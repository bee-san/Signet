from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import signet.db as db_module
from signet.app import main
from signet.credential_broker import CredentialError, SQLiteTokenRegistry, TokenRegistry
from signet.db import Database, DatabaseError, IntegrityError
from signet.deployment import (
    DISABLED_CONFIG_ENV,
    DeploymentError,
    DisabledDeploymentConfig,
    HumanAuthContext,
    create_mcp_app,
    create_mcp_runtime,
    create_web_app,
    create_web_app_from_config,
    load_disabled_config,
)
from signet.gateway_tools import GATEWAY_TOOL_DEFINITIONS

TOKEN_PATTERN = re.compile(r"^sgt_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}$")


@pytest.mark.parametrize(
    ("public_origin", "rp_id", "accepted"),
    [
        ("https://signet.example.test:8443", "signet.example.test", True),
        ("https://127.0.0.1", "127.0.0.1", False),
        ("https://[::1]", "::1", False),
    ],
)
def test_human_auth_context_requires_dns_rp_id(
    public_origin: str,
    rp_id: str,
    accepted: bool,
) -> None:
    if accepted:
        assert (
            HumanAuthContext(user_id="owner", public_origin=public_origin, rp_id=rp_id).rp_id
            == rp_id
        )
        return

    with pytest.raises(ValueError, match="matching RP ID"):
        HumanAuthContext(user_id="owner", public_origin=public_origin, rp_id=rp_id)


def initialized_config(tmp_path: Path) -> tuple[Path, DisabledDeploymentConfig]:
    config_path = tmp_path / "config.json"
    data_dir = tmp_path / "data"
    main(
        [
            "deployment",
            "init",
            "--config",
            str(config_path),
            "--data-dir",
            str(data_dir),
            "--namespace",
            "profile:hermes",
        ]
    )
    return config_path, load_disabled_config(config_path)


@asynccontextmanager
async def mcp_client(config: DisabledDeploymentConfig, token: str) -> AsyncIterator[ClientSession]:
    runtime = create_mcp_runtime(config)
    async with (
        runtime.app.router.lifespan_context(runtime.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=runtime.app),
            base_url="http://localhost:8789",
            headers={"Authorization": f"Bearer {token}"},
        ) as client,
        streamable_http_client("http://localhost:8789/mcp/approvals", http_client=client) as (
            read_stream,
            write_stream,
            _,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


def test_init_creates_only_private_disabled_state_and_cli_never_reprints_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, config = initialized_config(tmp_path)
    initialized = json.loads(capsys.readouterr().out)
    assert initialized == {
        "config_created": True,
        "database_initialized": True,
        "downstream_aliases": [],
        "human_credentials_enrolled": False,
        "mcp_aliases": ["approvals"],
        "mode": "disabled",
    }
    assert stat_mode(config_path) == 0o600
    assert stat_mode(config.data_dir) == 0o700
    assert stat_mode(config.database_path) == 0o600

    main(
        [
            "deployment",
            "token",
            "issue",
            "--config",
            str(config_path),
            "--namespace",
            "profile:hermes",
        ]
    )
    issue_output = capsys.readouterr()
    raw_token = issue_output.out.strip()
    assert TOKEN_PATTERN.fullmatch(raw_token)
    assert issue_output.err == ""

    main(["deployment", "token", "list", "--config", str(config_path)])
    list_output = capsys.readouterr()
    metadata = json.loads(list_output.out)
    assert raw_token not in list_output.out
    assert "sha256$" not in list_output.out
    assert metadata[0]["namespace"] == "profile:hermes"
    assert metadata[0]["allowed_aliases"] == ["approvals"]

    token_id = metadata[0]["token_id"]
    assert token_id[0].isalnum()
    main(
        [
            "deployment",
            "token",
            "rotate",
            "--config",
            str(config_path),
            "--token-id",
            token_id,
        ]
    )
    rotate_output = capsys.readouterr()
    assert re.fullmatch(TOKEN_PATTERN.pattern + "\n", rotate_output.out)
    assert rotate_output.err == ""
    assert raw_token not in rotate_output.out
    main(["deployment", "token", "list", "--config", str(config_path)])
    after_rotate = json.loads(capsys.readouterr().out)
    original = next(item for item in after_rotate if item["token_id"] == token_id)
    replacement = next(item for item in after_rotate if item["rotation_of_token_id"] == token_id)
    assert original["revoked_at"] is None
    assert replacement["revoked_at"] is None
    main(
        [
            "deployment",
            "token",
            "revoke",
            "--config",
            str(config_path),
            "--token-id",
            token_id,
        ]
    )
    assert json.loads(capsys.readouterr().out)["revoked_at"] is not None

    second_config = tmp_path / "second.json"
    with pytest.raises(SystemExit):
        main(
            [
                "deployment",
                "init",
                "--config",
                str(second_config),
                "--data-dir",
                str(config.data_dir),
                "--namespace",
                "profile:hermes",
            ]
        )
    assert not second_config.exists()


def test_persistent_authentication_revalidates_a_concurrent_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, config = initialized_config(tmp_path)
    registry = SQLiteTokenRegistry(
        Database(config.database_path),
        allowed_principals=config.allowed_principals,
        clock=lambda: 100,
    )
    issued = registry.issue("profile:hermes", {"approvals"})
    authenticate_snapshot = TokenRegistry.authenticate

    def revoke_after_snapshot(
        in_memory: TokenRegistry,
        authorization_header: str | None,
        *,
        alias: str,
    ) -> Any:
        principal = authenticate_snapshot(
            in_memory,
            authorization_header,
            alias=alias,
        )
        registry.revoke(issued.token_id)
        return principal

    monkeypatch.setattr(TokenRegistry, "authenticate", revoke_after_snapshot)

    with pytest.raises(CredentialError, match="invalid bearer token"):
        registry.authenticate(f"Bearer {issued.token}", alias="approvals")


def test_persistent_registry_revocation_and_rotation_are_immediate(tmp_path: Path) -> None:
    _, config = initialized_config(tmp_path)
    registry = SQLiteTokenRegistry(
        Database(config.database_path),
        allowed_principals=config.allowed_principals,
        clock=lambda: 100,
    )
    issued = registry.issue("profile:hermes", {"approvals"})
    restarted = SQLiteTokenRegistry(
        Database(config.database_path),
        allowed_principals=config.allowed_principals,
        clock=lambda: 101,
    )
    assert (
        restarted.authenticate(f"Bearer {issued.token}", alias="approvals").namespace
        == "profile:hermes"
    )

    replacement = restarted.rotate(issued.token_id)
    assert (
        registry.authenticate(f"Bearer {issued.token}", alias="approvals").token_id
        == issued.token_id
    )
    assert (
        registry.authenticate(f"Bearer {replacement.token}", alias="approvals").token_id
        == replacement.token_id
    )
    replacement_metadata = registry.metadata(replacement.token_id)
    assert replacement_metadata is not None
    assert replacement_metadata.rotation_of_token_id == issued.token_id
    assert replacement_metadata.revoked_at is None
    with pytest.raises(CredentialError, match="active replacement"):
        restarted.rotate(issued.token_id)

    restarted.revoke(issued.token_id)
    with pytest.raises(CredentialError, match="invalid"):
        restarted.authenticate(f"Bearer {issued.token}", alias="approvals")
    restarted.revoke(replacement.token_id)
    with pytest.raises(CredentialError, match="invalid"):
        restarted.authenticate(f"Bearer {replacement.token}", alias="approvals")


def test_rotation_stdout_failure_preserves_old_token_and_recoverable_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path, config = initialized_config(tmp_path)
    registry = SQLiteTokenRegistry(
        Database(config.database_path), allowed_principals=config.allowed_principals
    )
    issued = registry.issue("profile:hermes", {"approvals"})
    capsys.readouterr()

    def fail_stdout(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise BrokenPipeError("closed token sink")

    with monkeypatch.context() as patch:
        patch.setattr("builtins.print", fail_stdout)
        with pytest.raises(SystemExit):
            main(
                [
                    "deployment",
                    "token",
                    "rotate",
                    "--config",
                    str(config_path),
                    "--token-id",
                    issued.token_id,
                ]
            )
    failure = capsys.readouterr()
    assert failure.out == ""
    assert "stdout delivery failed" in failure.err
    assert "Traceback" not in failure.err

    restarted = SQLiteTokenRegistry(
        Database(config.database_path), allowed_principals=config.allowed_principals
    )
    assert (
        restarted.authenticate(f"Bearer {issued.token}", alias="approvals").token_id
        == issued.token_id
    )
    linked = [
        item
        for item in restarted.list_metadata()
        if item.rotation_of_token_id == issued.token_id and item.revoked_at is None
    ]
    assert len(linked) == 1
    restarted.revoke(linked[0].token_id)
    retry = restarted.rotate(issued.token_id)
    assert retry.token_id != linked[0].token_id
    assert (
        restarted.authenticate(f"Bearer {issued.token}", alias="approvals").token_id
        == issued.token_id
    )


def test_token_transitions_tolerate_wall_clock_rollback(tmp_path: Path) -> None:
    _, config = initialized_config(tmp_path)
    issued = SQLiteTokenRegistry(
        Database(config.database_path),
        allowed_principals=config.allowed_principals,
        clock=lambda: 500,
    ).issue("profile:hermes", {"approvals"})
    rollback_clock = SQLiteTokenRegistry(
        Database(config.database_path),
        allowed_principals=config.allowed_principals,
        clock=lambda: 400,
    )
    replacement = rollback_clock.rotate(issued.token_id)
    rollback_clock.revoke(replacement.token_id)
    replacement_metadata = rollback_clock.metadata(replacement.token_id)
    assert replacement_metadata is not None
    assert replacement_metadata.created_at == replacement_metadata.revoked_at == 500
    assert replacement_metadata.rotation_of_token_id == issued.token_id


def test_registry_rejects_unconfigured_namespaces_and_alias_sets(tmp_path: Path) -> None:
    _, config = initialized_config(tmp_path)
    registry = SQLiteTokenRegistry(
        Database(config.database_path), allowed_principals=config.allowed_principals
    )
    with pytest.raises(CredentialError, match="deployment config"):
        registry.issue("profile:other", {"approvals"})
    with pytest.raises(CredentialError, match="deployment config"):
        registry.issue("profile:hermes", {"fastmail"})
    with pytest.raises(CredentialError, match="duplicate"):
        registry.issue("profile:hermes", ["approvals", "approvals"])


def test_explicit_empty_principal_policy_denies_all_and_verifiers_cannot_be_exported(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "data" / "signet.sqlite3")
    database.initialize()
    unrestricted = SQLiteTokenRegistry(database)
    issued = unrestricted.issue("profile:test", {"approvals"})
    with pytest.raises(CredentialError, match="not exportable"):
        unrestricted.export_records()

    deny_all = SQLiteTokenRegistry(database, allowed_principals={})
    with pytest.raises(CredentialError, match="deployment config"):
        deny_all.issue("profile:test", {"approvals"})
    with pytest.raises(CredentialError, match="invalid bearer token"):
        deny_all.authenticate(f"Bearer {issued.token}", alias="approvals")


@pytest.mark.asyncio
async def test_disabled_mcp_exposes_exact_gateway_schemas_and_every_call_denies(
    tmp_path: Path,
) -> None:
    _, config = initialized_config(tmp_path)
    registry = SQLiteTokenRegistry(
        Database(config.database_path), allowed_principals=config.allowed_principals
    )
    token = registry.issue("profile:hermes", {"approvals"})
    async with mcp_client(config, token.token) as session:
        listed = await session.list_tools()
        assert [tool.model_dump(by_alias=True, exclude_none=True) for tool in listed.tools] == (
            GATEWAY_TOOL_DEFINITIONS
        )
        for definition in GATEWAY_TOOL_DEFINITIONS:
            result = await session.call_tool(definition["name"], {})
            assert result.isError is True
            assert result.structuredContent == {
                "error": {
                    "code": "deployment_disabled",
                    "message": (
                        "This Signet deployment is downstream-disabled. "
                        "No request or external action was performed."
                    ),
                }
            }

    runtime = create_mcp_runtime(config)
    async with (
        runtime.app.router.lifespan_context(runtime.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=runtime.app),
            base_url="http://localhost:8789",
        ) as client,
    ):
        assert (await client.get("/mcp/fastmail")).status_code == 404
        assert (await client.get("/mcp/whatsapp")).status_code == 404
        assert (await client.get("/healthz")).json() == {"status": "ok"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=runtime.app, client=("192.0.2.1", 1234)),
        base_url="http://localhost:8789",
    ) as remote:
        assert (await remote.get("/healthz")).status_code == 403


@pytest.mark.asyncio
async def test_disabled_web_is_loopback_host_guarded_and_has_no_auth_or_action_routes(
    tmp_path: Path,
) -> None:
    _, config = initialized_config(tmp_path)
    app = create_web_app_from_config(config)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost:8790"
    ) as client:
        status = await client.get("/")
        assert status.status_code == 503
        assert "downstream-disabled" in status.text
        assert status.headers["content-security-policy"] == (
            "default-src 'none'; frame-ancestors 'none'"
        )
        assert (await client.get("/healthz")).json() == {
            "status": "ok",
            "service": "signet",
            "mode": "disabled",
        }
        assert (await client.get("/login")).status_code == 404
        assert (await client.post("/requests/req_A/approve")).status_code == 404
        assert (await client.get("/", headers={"Host": "attacker.example"})).status_code == 421
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.1", 1234)),
        base_url="http://localhost:8790",
    ) as remote:
        assert (await remote.get("/healthz")).status_code == 403


def test_factories_require_private_environment_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path, _ = initialized_config(tmp_path)
    monkeypatch.delenv(DISABLED_CONFIG_ENV, raising=False)
    with pytest.raises(DeploymentError, match=DISABLED_CONFIG_ENV):
        create_mcp_app()
    monkeypatch.setenv(DISABLED_CONFIG_ENV, str(config_path))
    assert create_mcp_app().debug is False
    assert create_web_app().debug is False


def test_config_rejects_nonprivate_duplicate_symlink_and_hardlink_inputs(tmp_path: Path) -> None:
    config_path, _ = initialized_config(tmp_path)
    os.chmod(config_path, 0o644)
    with pytest.raises(DeploymentError, match="0600"):
        load_disabled_config(config_path)
    os.chmod(config_path, 0o600)

    hardlink = tmp_path / "hardlink.json"
    os.link(config_path, hardlink)
    with pytest.raises(DeploymentError, match="0600"):
        load_disabled_config(config_path)
    hardlink.unlink()

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(config_path)
    with pytest.raises(DeploymentError):
        load_disabled_config(symlink)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"version":1,"version":1}\n', encoding="utf-8")
    os.chmod(duplicate, 0o600)
    with pytest.raises(DeploymentError, match="invalid"):
        load_disabled_config(duplicate)


@pytest.mark.parametrize(
    "reserved_name",
    [
        "signet.sqlite3",
        "signet.sqlite3-wal",
        "signet.sqlite3-shm",
        "signet.sqlite3-journal",
        ".signet.sqlite3.maintenance.lock",
    ],
)
def test_init_rejects_reserved_state_path_collisions_without_partial_files(
    tmp_path: Path,
    reserved_name: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_dir = tmp_path / "data"
    config_path = data_dir / reserved_name
    with pytest.raises(SystemExit):
        main(
            [
                "deployment",
                "init",
                "--config",
                str(config_path),
                "--data-dir",
                str(data_dir),
                "--namespace",
                "profile:collision",
            ]
        )
    assert not data_dir.exists()
    assert "Traceback" not in capsys.readouterr().err


def test_init_reports_unsafe_data_directory_without_deleting_existing_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "unsafe-data"
    data_dir.mkdir(mode=0o755)
    os.chmod(data_dir, 0o755)
    marker = data_dir / "keep.txt"
    marker.write_text("operator-owned\n", encoding="utf-8")
    config_path = tmp_path / "config.json"
    with pytest.raises(SystemExit):
        main(
            [
                "deployment",
                "init",
                "--config",
                str(config_path),
                "--data-dir",
                str(data_dir),
                "--namespace",
                "profile:unsafe",
            ]
        )
    assert marker.read_text(encoding="utf-8") == "operator-owned\n"
    assert not config_path.exists()
    assert "Traceback" not in capsys.readouterr().err


def test_init_partial_database_failure_rolls_back_and_same_command_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "config.json"
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    marker = data_dir / "operator-owned.txt"
    marker.write_text("keep\n", encoding="utf-8")
    arguments = [
        "deployment",
        "init",
        "--config",
        str(config_path),
        "--data-dir",
        str(data_dir),
        "--namespace",
        "profile:retry",
    ]
    original_initialize = Database.initialize
    injected = False

    def fail_first_initialization(self: Database, **kwargs: Any) -> None:
        nonlocal injected
        if not injected:
            injected = True

            def fail_after_partial_creation(stage: str) -> None:
                if stage == "migration:1:statement:8":
                    raise RuntimeError("injected deployment init failure")

            original_initialize(self, fault_injector=fail_after_partial_creation)
            return
        original_initialize(self, **kwargs)

    monkeypatch.setattr(Database, "initialize", fail_first_initialization)
    with pytest.raises(SystemExit):
        main(arguments)
    failed = capsys.readouterr()
    assert "could not be initialized" in failed.err
    assert "Traceback" not in failed.err
    assert not config_path.exists()
    assert {path.name for path in data_dir.iterdir()} == {marker.name}
    assert marker.read_text(encoding="utf-8") == "keep\n"

    main(arguments)
    initialized = json.loads(capsys.readouterr().out)
    assert initialized["database_initialized"] is True
    assert load_disabled_config(config_path).database_path.exists()
    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_init_preserves_state_if_database_inode_changes_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "config.json"
    data_dir = tmp_path / "data"
    database_path = data_dir / "signet.sqlite3"
    replacement_path = data_dir / "replacement.sqlite3"
    replacement = b"replacement requiring manual review\n"

    def replace_database_then_fail(self: Database, **kwargs: Any) -> None:
        del kwargs
        replacement_path.write_bytes(replacement)
        os.chmod(replacement_path, 0o600)
        replacement_path.replace(self.path)
        raise DatabaseError("injected database replacement")

    monkeypatch.setattr(Database, "initialize", replace_database_then_fail)
    with pytest.raises(SystemExit):
        main(
            [
                "deployment",
                "init",
                "--config",
                str(config_path),
                "--data-dir",
                str(data_dir),
                "--namespace",
                "profile:changed-inode",
            ]
        )
    error = capsys.readouterr().err
    assert "preserved it for manual review" in error
    assert "Traceback" not in error
    assert config_path.exists()
    assert database_path.read_bytes() == replacement


def test_auth_status_is_metadata_only_and_context_validation_is_honest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = tmp_path / "config.json"
    main(
        [
            "deployment",
            "init",
            "--config",
            str(config_path),
            "--data-dir",
            str(tmp_path / "data"),
            "--namespace",
            "profile:hermes",
            "--human-user-id",
            "owner",
            "--public-origin",
            "https://signet.example.test:8443",
            "--rp-id",
            "signet.example.test",
        ]
    )
    capsys.readouterr()
    main(["deployment", "auth-status", "--config", str(config_path)])
    status = json.loads(capsys.readouterr().out)
    assert status == {
        "active_credentials": {"password": 0, "totp": 0, "webauthn": 0},
        "authenticated_web_enabled": False,
        "authorizes_live_actions": False,
        "context_configured": True,
        "enrollment_performed": False,
        "passkey_browser_ceremony_required": True,
        "secrets_read": False,
    }


def test_serve_command_uses_only_configured_loopback_listener(
    tmp_path: Path,
) -> None:
    config_path, _ = initialized_config(tmp_path)
    calls: list[tuple[Any, dict[str, Any]]] = []

    def runner(app: Any, **kwargs: Any) -> None:
        calls.append((app, kwargs))

    main(
        ["deployment", "serve-mcp", "--config", str(config_path)],
        runner=runner,
    )
    assert len(calls) == 1
    assert calls[0][1] == {
        "host": "127.0.0.1",
        "port": 8789,
        "server_header": False,
        "limit_concurrency": 64,
    }


def test_disabled_processes_start_stop_and_restart_without_releasing_state(
    tmp_path: Path,
) -> None:
    mcp_port = reserve_port()
    web_port = reserve_port()
    config_path = tmp_path / "config.json"
    main(
        [
            "deployment",
            "init",
            "--config",
            str(config_path),
            "--data-dir",
            str(tmp_path / "data"),
            "--namespace",
            "profile:process-test",
            "--mcp-port",
            str(mcp_port),
            "--web-port",
            str(web_port),
        ]
    )

    mcp = start_process("serve-mcp", config_path)
    web = start_process("serve-web", config_path)
    try:
        assert wait_for_json(f"http://127.0.0.1:{mcp_port}/healthz") == {"status": "ok"}
        assert wait_for_json(f"http://127.0.0.1:{web_port}/healthz") == {
            "status": "ok",
            "service": "signet",
            "mode": "disabled",
        }
    finally:
        try:
            terminate_process(mcp)
        finally:
            terminate_process(web)
    assert_port_available(mcp_port)
    assert_port_available(web_port)

    restarted = start_process("serve-mcp", config_path)
    try:
        assert wait_for_json(f"http://127.0.0.1:{mcp_port}/healthz") == {"status": "ok"}
    finally:
        terminate_process(restarted)
    assert_port_available(mcp_port)


def test_schema_12_enforces_token_shape_and_retains_records(tmp_path: Path) -> None:
    database = Database(tmp_path / "data" / "signet.sqlite3")
    database.initialize()
    with (
        pytest.raises(IntegrityError, match="CHECK constraint|invalid MCP"),
        database.transaction() as connection,
    ):
        connection.execute(
            """
            INSERT INTO mcp_caller_tokens(
                token_id, origin_namespace, verifier, allowed_aliases_json, created_at
            ) VALUES ('short', 'profile:test', ?, '["approvals"]', 1)
            """,
            ("sha256$" + "a" * 64,),
        )

    registry = SQLiteTokenRegistry(database, clock=lambda: 2)
    issued = registry.issue("profile:test", {"approvals"})
    with (
        pytest.raises(IntegrityError, match="retained"),
        database.transaction() as connection,
    ):
        connection.execute("DELETE FROM mcp_caller_tokens WHERE token_id = ?", (issued.token_id,))


@pytest.mark.parametrize(
    ("token_id", "namespace", "aliases", "created_at"),
    [
        ("AAAAAAAAAAAAAAAA", "profile:other", '["approvals"]', 2),
        ("BBBBBBBBBBBBBBBB", "profile:test", '["other"]', 2),
        ("CCCCCCCCCCCCCCCC", "profile:test", '["approvals"]', 1),
    ],
)
def test_schema_12_rejects_rotation_context_divergence(
    tmp_path: Path,
    token_id: str,
    namespace: str,
    aliases: str,
    created_at: int,
) -> None:
    database = Database(tmp_path / "data" / "signet.sqlite3")
    database.initialize()
    parent = SQLiteTokenRegistry(database, clock=lambda: 2).issue("profile:test", {"approvals"})
    with (
        pytest.raises(IntegrityError, match="rotation context"),
        database.transaction() as connection,
    ):
        connection.execute(
            """
            INSERT INTO mcp_caller_tokens(
                token_id, origin_namespace, verifier, allowed_aliases_json,
                created_at, rotation_of_token_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                token_id,
                namespace,
                "sha256$" + "a" * 64,
                aliases,
                created_at,
                parent.token_id,
            ),
        )


def test_schema_11_upgrade_requires_and_streams_private_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    database_path = data_dir / "signet.sqlite3"
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 11)
    Database(database_path).initialize()
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 12)

    config_path = tmp_path / "disabled.json"
    config_path.write_text(
        json.dumps(
            {
                "version": 1,
                "mode": "disabled",
                "data_dir": str(data_dir),
                "mcp": {"host": "127.0.0.1", "port": 8789, "limit_concurrency": 64},
                "web": {"host": "127.0.0.1", "port": 8790, "limit_concurrency": 64},
                "principals": [
                    {"namespace": "profile:migration", "allowed_aliases": ["approvals"]}
                ],
                "human_auth": None,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(config_path, 0o600)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    snapshot = backup_dir / "pre-schema-12.sqlite3"
    original_read_bytes = Path.read_bytes

    def reject_snapshot_whole_file_read(path: Path) -> bytes:
        if path == snapshot:
            raise AssertionError("deployment migration must stream the snapshot digest")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", reject_snapshot_whole_file_read)
    main(
        [
            "deployment",
            "migrate",
            "--config",
            str(config_path),
            "--backup-snapshot",
            str(snapshot),
        ]
    )
    assert json.loads(capsys.readouterr().out) == {
        "backup_snapshot_created": True,
        "migrated": True,
    }
    assert stat_mode(snapshot) == 0o600
    with Database(snapshot).read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11
    with Database(database_path).read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 12


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def start_process(command: str, config_path: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from signet.app import main; main()",
            "deployment",
            command,
            "--config",
            str(config_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )


def wait_for_json(url: str) -> Any:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=0.25)
            if response.status_code == 200:
                return response.json()
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"service did not become healthy: {url}")


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        return_code = process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
        raise AssertionError("disabled deployment did not stop after SIGTERM") from None
    # Current Uvicorn re-raises the captured signal after completing its shutdown.
    assert return_code in {0, -signal.SIGTERM}


def assert_port_available(port: int) -> None:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
