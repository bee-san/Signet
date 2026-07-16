from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Barrier, Event, Timer
from typing import Any

import httpx
import pytest
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError

import signet.backup as backup_module
import signet.demo as demo_module
from signet.app import main
from signet.backup import BackupError
from signet.credential_broker import CredentialError
from signet.db import Database, DatabaseError, DatabaseFinalizationStateUnknown
from signet.demo import (
    DEMO_ACTION_PROOF,
    DEMO_GRACEFUL_SHUTDOWN_SECONDS,
    DEMO_LOGIN_PROOF,
    DEMO_NAMESPACE,
    DemoAssembly,
    DemoError,
    backup_demo,
    build_demo,
    credential_value,
    hermes_config,
    initialize_demo,
    live_smoke,
    offline_smoke,
    restore_demo,
)
from signet.private_paths import PrivatePathError
from signet.retention import BackupPins

FASTMAIL_ARGUMENTS = {
    "from": "fake-sender@demo.invalid",
    "to": ["fake-recipient@demo.invalid"],
    "cc": [],
    "bcc": [],
    "subject": "Signet fake-only demo",
    "body": "This is a fake-only approval test.",
    "attachments": [],
}
WHATSAPP_ARGUMENTS = {
    "to": "15555550123@s.whatsapp.net",
    "message": "This is a fake-only approval test.",
}


def new_demo(tmp_path: Path, name: str = "demo") -> Path:
    root = tmp_path / name
    initialize_demo(root, now=1_800_000_000)
    return root


@asynccontextmanager
async def mcp_client(assembly: DemoAssembly) -> AsyncIterator[httpx.AsyncClient]:
    token = credential_value(assembly.root, "mcp-token")
    async with (
        assembly.mcp.app.router.lifespan_context(assembly.mcp.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=assembly.mcp.app),
            base_url="http://localhost:8789",
            headers={"Authorization": f"Bearer {token}"},
        ) as client,
    ):
        yield client


@asynccontextmanager
async def mcp_session(
    client: httpx.AsyncClient,
    alias: str,
) -> AsyncIterator[ClientSession]:
    async with (
        streamable_http_client(
            f"http://localhost:8789/mcp/{alias}",
            http_client=client,
        ) as (read_stream, write_stream, _get_session_id),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


async def enqueue(
    client: httpx.AsyncClient,
    alias: str,
    tool: str,
    arguments: dict[str, Any],
) -> str:
    async with mcp_session(client, alias) as session:
        result = await session.call_tool(tool, arguments)
    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["status"] == "pending_approval"
    return str(result.structuredContent["request_id"])


def exhausted_fake_unknown(root: Path) -> tuple[DemoAssembly, str, str]:
    assembly = build_demo(root)

    async def create_request() -> str:
        async with mcp_client(assembly) as client:
            return await enqueue(client, "fastmail", "send_email", FASTMAIL_ARGUMENTS)

    request_id = asyncio.run(create_request())
    request = assembly.state_machine.get_request(request_id)
    payload_hash = str(request["current_payload_hash"])
    with assembly.database.transaction() as connection:
        connection.execute(
            """
            UPDATE approval_requests
            SET state = 'outcome_unknown', safe_outcome_json = ?
            WHERE request_id = ?
            """,
            ('{"provider_candidate":"fake:private"}', request_id),
        )
        connection.execute(
            """
            INSERT INTO execution_attempts(
                attempt_id, request_id, version, payload_hash, fencing_token,
                worker_id, worker_generation, phase, claimed_at,
                dispatch_started_at, reconciliation_attempt_count,
                reconciliation_resolution, reconciliation_exhausted_at,
                reconciliation_notification_required, safe_completion_json,
                outcome_classification
            ) VALUES (?, ?, 1, ?, ?, 'fake:worker', 1, 'outcome_unknown', ?,
                      ?, 2, 'exhausted', ?, 1, ?, 'outcome_unknown')
            """,
            (
                f"attempt:{request_id}",
                request_id,
                payload_hash,
                f"fence:{request_id}",
                int(request["created_at"]),
                int(request["created_at"]) + 1,
                int(request["created_at"]) + 2,
                '{"provider_candidate":"fake:private"}',
            ),
        )
    return assembly, request_id, payload_hash


def hidden_values(document: str, name: str) -> list[str]:
    return re.findall(rf'name="{re.escape(name)}" value="([^"]+)"', document)


async def web_action(
    assembly: DemoAssembly,
    request_id: str,
    action: str,
) -> httpx.Response:
    origin = "http://127.0.0.1:8790"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=assembly.web),
        base_url=origin,
        follow_redirects=False,
    ) as client:
        login = await client.get("/login")
        assert login.status_code == 200
        assert "Fake-only demo" in login.text
        assert "Fake demo credentials" in login.text
        assert ">Fake user<" in login.text
        assert ">Fake password<" in login.text
        assert ">Fake login proof<" in login.text
        assert "Enter fake demo" in login.text
        assert 'id="password" name="password" type="text"' in login.text
        assert 'inputmode="text" autocomplete="off"' in login.text
        assert '<details class="fallback-login" open>' in login.text
        assert "data-passkey-login" not in login.text
        assert "Use passkey" not in login.text
        login_csrf = hidden_values(login.text, "csrf_token")[-1]
        authenticated = await client.post(
            "/login/password",
            data={
                "user_id": credential_value(assembly.root, "web-user"),
                "password": credential_value(assembly.root, "web-password"),
                "totp_proof": DEMO_LOGIN_PROOF,
                "csrf_token": login_csrf,
            },
            headers={"Origin": origin},
        )
        assert authenticated.status_code == 303

        detail = await client.get(f"/requests/{request_id}")
        assert detail.status_code == 200
        assert "Fake-only demo" in detail.text
        assert "Use fake action proof" in detail.text
        assert ">Fake action proof<" in detail.text
        assert 'inputmode="text" autocomplete="off"' in detail.text
        assert '<details class="authenticator-fallback" open>' in detail.text
        assert 'class="totp-action"' in detail.text
        assert "data-passkey-action" not in detail.text
        assert "Use passkey" not in detail.text
        assert "Always allow" not in detail.text
        response = await client.post(
            f"/requests/{request_id}/actions/totp",
            data={
                "action": action,
                "decision_note": {
                    "approve": "exact_request_approved",
                    "deny": "request_no_longer_needed",
                }.get(action, ""),
                "expected_version": hidden_values(detail.text, "expected_version")[-1],
                "expected_payload_hash": hidden_values(detail.text, "expected_payload_hash")[-1],
                "totp_proof": DEMO_ACTION_PROOF,
                "csrf_token": hidden_values(detail.text, "csrf_token")[-1],
            },
            headers={"Origin": origin},
        )
    return response


def request_state(assembly: DemoAssembly, request_id: str) -> str:
    return str(assembly.state_machine.get_request(request_id)["state"])


def test_cli_initializes_private_state_and_prints_only_selected_credentials(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "demo"
    main(["demo", "init", "--data-dir", str(root)])
    assert "fake-only" in capsys.readouterr().out
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for name in ("demo-state.json", "demo-secrets.json", "policy.yaml", "approvals.sqlite3"):
        assert stat.S_IMODE((root / name).stat().st_mode) == 0o600

    main(
        [
            "demo",
            "credentials",
            "--data-dir",
            str(root),
            "--field",
            "web-login-proof",
        ]
    )
    captured = capsys.readouterr()
    assert captured.out == "fake:login\n"
    assert captured.err == ""
    assert credential_value(root, "web-action-proof") == "fake:approve"
    assert credential_value(root, "mcp-token").startswith("fake:sgt_")

    with pytest.raises(SystemExit):
        main(["demo", "init", "--data-dir", str(root)])
    assert offline_smoke(root)["network_provider_calls"] == 0


@pytest.mark.parametrize(
    "operator_message",
    [
        (
            "database maintenance completed, but the SQLite connection close outcome could not "
            "be confirmed; stop Signet processes and verify the database before retrying"
        ),
        (
            "database maintenance completed, but the maintenance-lock release outcome could not "
            "be confirmed; stop Signet processes and inspect the private maintenance lock before "
            "retrying"
        ),
    ],
)
def test_demo_cli_preserves_bounded_database_finalization_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operator_message: str,
) -> None:
    root = new_demo(tmp_path, "database-finalization-message")

    def report_finalization_state(_root: Path) -> dict[str, object]:
        raise DatabaseFinalizationStateUnknown(operator_message) from OSError(
            "injected raw finalizer detail"
        )

    monkeypatch.setattr(demo_module, "offline_smoke", report_finalization_state)

    with pytest.raises(SystemExit) as caught:
        main(["demo", "smoke", "--data-dir", str(root)])

    assert caught.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert operator_message in output.err
    assert "demo smoke failed safely" not in output.err
    assert "injected raw" not in output.err


def test_demo_cli_preserves_combined_backup_and_database_lock_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import signet.db as db_module

    root = new_demo(tmp_path, "combined-database-lock-recovery")
    database = Database(root / "approvals.sqlite3")
    with database.transaction() as connection:
        connection.execute(f"PRAGMA user_version={db_module.LATEST_SCHEMA_VERSION - 1}")

    real_flock = db_module.fcntl.flock

    def fail_maintenance_unlock(descriptor: int, operation: int) -> None:
        if operation == db_module.fcntl.LOCK_UN:
            raise OSError("injected raw maintenance unlock failure")
        real_flock(descriptor, operation)

    def fail_pre_migration_backup(*_args: object) -> None:
        raise BackupError("injected raw pre-migration backup failure")

    monkeypatch.setattr(db_module.fcntl, "flock", fail_maintenance_unlock)
    monkeypatch.setattr(backup_module, "_archive_workspace", fail_pre_migration_backup)

    with pytest.raises(SystemExit) as caught:
        main(["demo", "smoke", "--data-dir", str(root)])

    assert caught.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "maintenance-lock finalization could not be confirmed" in output.err
    assert "stop Signet processes and inspect the private maintenance lock" in output.err
    assert "demo smoke failed safely" not in output.err
    assert "injected raw" not in output.err


def test_seed_request_cli_uses_gateway_is_repeatable_and_prints_safe_metadata(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path, "seed-request")
    calls: list[tuple[str, str, dict[str, Any], str, Any]] = []
    original_handle_call = demo_module.GatewayCallPipeline.handle_call

    async def observed_handle_call(
        pipeline: Any,
        alias: str,
        tool: str,
        arguments: dict[str, Any],
        namespace: str,
        identity: Any,
    ) -> dict[str, Any]:
        calls.append((alias, tool, dict(arguments), namespace, identity))
        return await original_handle_call(
            pipeline,
            alias,
            tool,
            arguments,
            namespace,
            identity,
        )

    async def reject_provider_call(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("seed request must not invoke a provider")

    monkeypatch.setattr(
        demo_module.GatewayCallPipeline,
        "handle_call",
        observed_handle_call,
    )
    monkeypatch.setattr(
        demo_module.FakeOnlyProviderClient,
        "call_tool_raw",
        reject_provider_call,
    )
    monkeypatch.setattr(
        demo_module.FakeOnlyProviderClient,
        "call_tool",
        reject_provider_call,
    )

    command = ["demo", "seed-request", "--data-dir", str(root)]
    main(command)
    first_raw = capsys.readouterr().out
    first = json.loads(first_raw)
    assert first == {
        "created": True,
        "request_id": first["request_id"],
        "service": "fastmail",
        "state": "pending_approval",
        "status": "ready_for_review",
        "tool": "send_email",
    }
    assert str(root) not in first_raw
    assert credential_value(root, "mcp-token") not in first_raw
    assert "fake-customer-success@demo.invalid" not in first_raw
    assert "Fake onboarding status follow-up" not in first_raw
    assert "Reason for sending" not in first_raw
    assert "payload" not in first_raw

    assert len(calls) == 1
    alias, tool, arguments, namespace, identity = calls[0]
    assert (alias, tool, namespace) == ("fastmail", "send_email", DEMO_NAMESPACE)
    assert arguments["to"] == ["fake-customer-success@demo.invalid"]
    assert arguments["subject"] == "Fake onboarding status follow-up"
    assert "Reason for sending" in arguments["body"]
    assert identity.source == "explicit"

    assembly = build_demo(root)
    request_id = str(first["request_id"])
    stored = assembly.state_machine.get_request(request_id)
    assert stored["state"] == "pending_approval"
    assert stored["downstream_alias"] == "fastmail"
    assert stored["tool_name"] == "send_email"
    assert stored["origin_namespace"] == DEMO_NAMESPACE
    with assembly.database.read() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM payload_versions WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                """
                SELECT count(*) FROM request_events
                WHERE request_id = ? AND action = 'pending_enqueued'
                """,
                (request_id,),
            ).fetchone()[0]
            == 1
        )

    main(command)
    replay = json.loads(capsys.readouterr().out)
    assert replay == {**first, "created": False}
    with assembly.database.read() as connection:
        assert connection.execute("SELECT count(*) FROM approval_requests").fetchone()[0] == 1

    denied = asyncio.run(web_action(assembly, request_id, "deny"))
    assert denied.status_code == 303
    main(command)
    next_request = json.loads(capsys.readouterr().out)
    assert next_request["created"] is True
    assert next_request["request_id"] != request_id
    assert next_request["state"] == "pending_approval"
    with assembly.database.read() as connection:
        assert connection.execute("SELECT count(*) FROM approval_requests").fetchone()[0] == 2
    assert len(calls) == 3


def test_seed_request_cli_requires_valid_marker_and_stopped_server(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "guarded-seed")
    command = ["demo", "seed-request", "--data-dir", str(root)]
    marker = root / "demo-state.json"
    original_marker = marker.read_text(encoding="utf-8")
    invalid_marker = json.loads(original_marker)
    invalid_marker["mode"] = "not-fake"
    marker.write_text(json.dumps(invalid_marker), encoding="utf-8")

    with pytest.raises(SystemExit) as marker_exit:
        main(command)
    assert marker_exit.value.code == 2
    marker_failure = capsys.readouterr()
    assert marker_failure.out == ""
    assert "fake-only marker is invalid" in marker_failure.err
    assert "Traceback" not in marker_failure.err

    marker.write_text(original_marker, encoding="utf-8")
    with demo_module._demo_server_lock(root), pytest.raises(SystemExit) as lock_exit:
        main(command)
    assert lock_exit.value.code == 2
    lock_failure = capsys.readouterr()
    assert lock_failure.out == ""
    assert "already being served" in lock_failure.err
    assert "Traceback" not in lock_failure.err
    with build_demo(root).database.read() as connection:
        assert connection.execute("SELECT count(*) FROM approval_requests").fetchone()[0] == 0


def test_seed_request_cli_sanitizes_gateway_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path, "failed-seed")

    async def fail_admission(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("private fake-customer-success@demo.invalid payload")

    monkeypatch.setattr(demo_module.GatewayCallPipeline, "handle_call", fail_admission)
    with pytest.raises(SystemExit) as failure:
        main(["demo", "seed-request", "--data-dir", str(root)])
    assert failure.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "could not be admitted safely" in captured.err
    assert "fake-customer-success" not in captured.err
    assert "payload" not in captured.err
    assert "Traceback" not in captured.err
    with build_demo(root).database.read() as connection:
        assert connection.execute("SELECT count(*) FROM approval_requests").fetchone()[0] == 0


def test_demo_paths_reject_symlinked_ancestors_before_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = tmp_path.resolve(strict=True)
    direct_target = base / "direct-target"
    direct_target.mkdir(mode=0o700)
    direct_destination = base / "direct-demo"
    direct_destination.symlink_to(direct_target, target_is_directory=True)
    with pytest.raises(DemoError, match="must not already exist"):
        initialize_demo(direct_destination)
    assert direct_destination.is_symlink()
    assert tuple(direct_target.iterdir()) == ()

    physical_parent = base / "physical"
    physical_parent.mkdir(mode=0o700)
    linked_parent = base / "linked"
    linked_parent.symlink_to(physical_parent, target_is_directory=True)

    linked_destination = linked_parent / "new-demo"
    with pytest.raises(DemoError, match="parent is unavailable or unsafe"):
        initialize_demo(linked_destination)
    assert not (physical_parent / "new-demo").exists()

    nested_destination = linked_parent / "missing" / "new-demo"
    with pytest.raises(DemoError, match="parent is unavailable or unsafe"):
        initialize_demo(nested_destination)
    assert not (physical_parent / "missing").exists()

    missing_parent = base / "missing-parent"
    with pytest.raises(DemoError, match="parent is unavailable or unsafe"):
        initialize_demo(missing_parent / "new-demo")
    assert not missing_parent.exists()

    unsafe_parent = base / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o777)
    with pytest.raises(DemoError, match="parent is unavailable or unsafe"):
        initialize_demo(unsafe_parent / "new-demo")
    assert stat.S_IMODE(unsafe_parent.stat().st_mode) == 0o777
    assert tuple(unsafe_parent.iterdir()) == ()

    physical_root = physical_parent / "existing-demo"
    initialize_demo(physical_root)
    direct_root = base / "direct-root"
    direct_root.symlink_to(physical_root, target_is_directory=True)
    for selected in (direct_root, linked_parent / "existing-demo"):
        with pytest.raises(DemoError, match="data directory is unavailable or unsafe"):
            credential_value(selected, "mcp-token")

    def fail_identity_verification(_path: Path) -> Path:
        raise PrivatePathError("injected identity race")

    with monkeypatch.context() as scoped:
        scoped.setattr(demo_module, "require_private_directory", fail_identity_verification)
        with pytest.raises(DemoError, match="data directory is unavailable or unsafe"):
            credential_value(physical_root, "mcp-token")


def test_demo_init_rejects_parent_traversal_without_creating_state(tmp_path: Path) -> None:
    base = tmp_path.resolve(strict=True)
    outside = base / "outside"
    nested = outside / "nested"
    nested.mkdir(parents=True, mode=0o700)
    linked = base / "linked"
    linked.symlink_to(nested, target_is_directory=True)

    for destination in (
        linked / ".." / "demo",
        base / "missing" / ".." / "demo",
    ):
        with pytest.raises(DemoError, match="parent is unavailable or unsafe"):
            initialize_demo(destination)

    assert not (base / "demo").exists()
    assert not (outside / "demo").exists()
    assert not (base / "missing").exists()


def test_demo_init_never_replaces_destination_created_at_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path.resolve(strict=True)
    destination = parent / "publication-race"
    real_rename = demo_module._rename_directory_no_replace
    raced_inode: int | None = None

    def create_destination_then_rename(source: Path, target: Path) -> None:
        nonlocal raced_inode
        target.mkdir(mode=0o700)
        raced_inode = target.stat().st_ino
        real_rename(source, target)

    monkeypatch.setattr(
        demo_module,
        "_rename_directory_no_replace",
        create_destination_then_rename,
    )
    with pytest.raises(DemoError, match="must not already exist"):
        initialize_demo(destination)

    assert raced_inode is not None
    assert destination.is_dir()
    assert destination.stat().st_ino == raced_inode
    assert tuple(destination.iterdir()) == ()
    assert not any(path.name.startswith(".publication-race.init-") for path in parent.iterdir())


def test_demo_paths_map_unexpandable_home_to_controlled_error() -> None:
    selected = Path("~signet-user-that-must-not-exist-7f43d5/demo")

    with pytest.raises(DemoError, match="path is unavailable or unsafe"):
        initialize_demo(selected)

    with pytest.raises(DemoError, match="path is unavailable or unsafe"):
        initialize_demo(Path("invalid\ud800demo"))
    with pytest.raises(DemoError, match="path is unavailable or unsafe"):
        credential_value(selected, "mcp-token")


def test_demo_created_files_are_rejected_when_acl_inspection_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "acl-rejected-demo"

    def reject_acl(_descriptor: int) -> None:
        raise PrivatePathError("injected unsafe granting ACL")

    monkeypatch.setattr(demo_module, "require_no_acl_grants", reject_acl)

    with pytest.raises(DemoError, match="inherited an unsafe granting ACL"):
        initialize_demo(destination)

    assert not destination.exists()
    assert not any(path.name.startswith(".acl-rejected-demo.init-") for path in tmp_path.iterdir())


def test_demo_init_failure_removes_only_its_temporary_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path.resolve(strict=True)
    marker = parent / "keep"
    marker.write_text("keep\n", encoding="utf-8")

    def fail_initialization(self: Database, **kwargs: Any) -> None:
        del self, kwargs
        raise DatabaseError("injected demo initialization failure")

    monkeypatch.setattr(Database, "initialize", fail_initialization)
    previous_umask = os.umask(0o777)
    try:
        with pytest.raises(DatabaseError, match="injected demo initialization failure"):
            initialize_demo(parent / "failed-demo")
    finally:
        os.umask(previous_umask)

    assert {path.name for path in parent.iterdir()} == {marker.name}
    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_demo_init_retains_uncaptured_tree_when_mkdir_outcome_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path.resolve(strict=True)
    destination = parent / "interrupted-create"
    real_mkdir = Path.mkdir

    def mkdir_then_interrupt(path: Path, *args: Any, **kwargs: Any) -> None:
        real_mkdir(path, *args, **kwargs)
        if path.name.startswith(".interrupted-create.init-"):
            raise KeyboardInterrupt

    monkeypatch.setattr(Path, "mkdir", mkdir_then_interrupt)
    previous_umask = os.umask(0o777)
    try:
        with pytest.raises(
            DemoError,
            match="creation cleanup could not be confirmed.*inspect the demo parent",
        ):
            initialize_demo(destination)
    finally:
        os.umask(previous_umask)

    assert not destination.exists()
    retained = tuple(
        path for path in parent.iterdir() if path.name.startswith(".interrupted-create.init-")
    )
    assert len(retained) == 1
    retained[0].rmdir()


def test_demo_init_preserves_replacement_when_mkdir_outcome_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path.resolve(strict=True)
    destination = parent / "uncaptured-replacement"
    displaced = parent / "demo-created-before-interrupt"
    replacement: Path | None = None
    real_mkdir = Path.mkdir

    def replace_then_interrupt(path: Path, *args: Any, **kwargs: Any) -> None:
        nonlocal replacement
        real_mkdir(path, *args, **kwargs)
        if path.name.startswith(".uncaptured-replacement.init-"):
            path.rename(displaced)
            real_mkdir(path, mode=0o700)
            (path / "replacement-marker").write_text("preserve\n", encoding="utf-8")
            path.chmod(0o500)
            replacement = path
            raise KeyboardInterrupt

    monkeypatch.setattr(Path, "mkdir", replace_then_interrupt)

    with pytest.raises(
        DemoError,
        match="creation cleanup could not be confirmed.*inspect the demo parent",
    ):
        initialize_demo(destination)

    assert replacement is not None
    assert (replacement / "replacement-marker").read_text(encoding="utf-8") == "preserve\n"
    assert stat.S_IMODE(replacement.stat().st_mode) == 0o500
    replacement.chmod(0o700)
    backup_module.shutil.rmtree(replacement)
    displaced.rmdir()


def test_demo_init_cleans_up_restrictive_nested_directory_after_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path.resolve(strict=True)
    destination = parent / "interrupted-imports"
    real_mkdir = Path.mkdir

    def mkdir_then_interrupt(path: Path, *args: Any, **kwargs: Any) -> None:
        real_mkdir(path, *args, **kwargs)
        if path.name == "imports":
            raise KeyboardInterrupt

    monkeypatch.setattr(Path, "mkdir", mkdir_then_interrupt)
    previous_umask = os.umask(0o777)
    try:
        with pytest.raises(KeyboardInterrupt):
            initialize_demo(destination)
    finally:
        os.umask(previous_umask)

    assert not destination.exists()
    assert not any(path.name.startswith(".interrupted-imports.init-") for path in parent.iterdir())


def test_demo_init_cli_reports_unconfirmed_private_secret_tree_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "retained-initialization"
    original_rmtree = backup_module.shutil.rmtree

    def fail_before_publish(_source: Path, _destination: Path) -> None:
        raise DemoError("injected private initialization failure")

    def retain_initialization_tree(path: Path) -> None:
        if path.name.startswith(".retained-initialization.init-"):
            raise OSError("injected private cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(demo_module, "_rename_directory_no_replace", fail_before_publish)
    monkeypatch.setattr(backup_module.shutil, "rmtree", retain_initialization_tree)

    with pytest.raises(SystemExit):
        main(["demo", "init", "--data-dir", str(destination)])

    failure = capsys.readouterr().err
    assert "initialization did not complete" in failure
    assert "cleanup could not be confirmed" in failure
    assert "injected" not in failure
    assert str(destination) not in failure
    assert "Traceback" not in failure
    retained = tuple(tmp_path.glob(".retained-initialization.init-*"))
    assert len(retained) == 1
    secret_document = json.loads((retained[0] / "demo-secrets.json").read_text(encoding="utf-8"))
    assert secret_document["mcp_token"] not in failure
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(retained[0])


def test_demo_init_hardens_every_artifact_against_restrictive_umask(
    tmp_path: Path,
) -> None:
    parent = tmp_path.resolve(strict=True)
    destination = parent / "restrictive-umask-demo"

    previous_umask = os.umask(0o777)
    try:
        initialized = initialize_demo(destination, now=1_800_000_000)
    finally:
        os.umask(previous_umask)

    assert initialized == destination
    for path in (destination, *destination.rglob("*")):
        expected_mode = 0o700 if path.is_dir() else 0o600
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode, path
    assert not any(
        path.name.startswith(".restrictive-umask-demo.init-") for path in parent.iterdir()
    )


def test_demo_init_detects_same_path_parent_replacement_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = tmp_path.resolve(strict=True)
    parent = base / "parent"
    parent.mkdir(mode=0o700)
    replacement = base / "replacement"
    replacement.mkdir(mode=0o700)
    replacement_marker = replacement / "keep"
    replacement_marker.write_text("replacement\n", encoding="utf-8")
    displaced = base / "displaced"
    real_fsync_directory = demo_module._fsync_directory
    swapped = False

    def swap_parent_after_temporary_fsync(path: Path) -> None:
        nonlocal swapped
        real_fsync_directory(path)
        if not swapped:
            parent.rename(displaced)
            replacement.rename(parent)
            swapped = True

    monkeypatch.setattr(demo_module, "_fsync_directory", swap_parent_after_temporary_fsync)
    with pytest.raises(
        DemoError,
        match="initialization did not complete.*cleanup could not be confirmed",
    ):
        initialize_demo(parent / "demo")

    assert swapped
    assert (parent / replacement_marker.name).read_text(encoding="utf-8") == "replacement\n"
    assert not (parent / "demo").exists()
    assert not (displaced / "demo").exists()
    temporary_trees = tuple(displaced.glob(".demo.init-*"))
    assert len(temporary_trees) == 1
    assert stat.S_IMODE(temporary_trees[0].stat().st_mode) == 0o700


def test_demo_init_reports_unknown_outcome_and_preserves_publish_on_parent_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path.resolve(strict=True)
    destination = parent / "published-before-fsync-failure"
    real_fsync_directory = demo_module._fsync_directory
    calls = 0

    def fail_second_directory_fsync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected parent fsync failure")
        real_fsync_directory(path)

    monkeypatch.setattr(demo_module, "_fsync_directory", fail_second_directory_fsync)
    with pytest.raises(DemoError, match="outcome is unknown.*durable publication"):
        initialize_demo(destination, now=1_800_000_000)

    assert calls == 2
    assert destination.is_dir()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert credential_value(destination, "web-login-proof") == "fake:login"
    assert not any(
        path.name.startswith(".published-before-fsync-failure.init-") for path in parent.iterdir()
    )


def test_demo_init_reports_unknown_outcome_when_interrupted_immediately_after_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path.resolve(strict=True)
    destination = parent / "interrupted-publication"
    real_rename = demo_module._rename_directory_no_replace

    def rename_then_interrupt(source: Path, target: Path) -> None:
        real_rename(source, target)
        raise KeyboardInterrupt

    monkeypatch.setattr(demo_module, "_rename_directory_no_replace", rename_then_interrupt)
    with pytest.raises(DemoError, match="outcome is unknown.*durable publication"):
        initialize_demo(destination, now=1_800_000_000)

    assert destination.is_dir()
    assert credential_value(destination, "web-login-proof") == "fake:login"
    assert not any(
        path.name.startswith(".interrupted-publication.init-") for path in parent.iterdir()
    )


def test_cli_fake_unknown_purge_preserves_uncertainty_and_redacts_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = new_demo(tmp_path, "unknown-purge")
    assembly, request_id, payload_hash = exhausted_fake_unknown(root)

    main(
        [
            "demo",
            "purge-unknown",
            "--data-dir",
            str(root),
            "--request-id",
            request_id,
            "--expected-version",
            "1",
            "--expected-payload-hash",
            payload_hash,
            "--acknowledge-possible-delivery",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "claimed": 2,
        "completed": 2,
        "failed": 0,
        "scheduled": 2,
        "state": "outcome_unknown",
        "status": "fake_only_content_purged",
        "uncertainty_preserved": True,
    }
    main(
        [
            "demo",
            "purge-unknown",
            "--data-dir",
            str(root),
            "--request-id",
            request_id,
            "--expected-version",
            "1",
            "--expected-payload-hash",
            payload_hash,
            "--acknowledge-possible-delivery",
        ]
    )
    replay = json.loads(capsys.readouterr().out)
    assert replay["scheduled"] == replay["claimed"] == replay["completed"] == 0
    assert replay["failed"] == 0
    assert replay["state"] == "outcome_unknown"
    restarted = build_demo(root)
    with restarted.database.read() as connection:
        stored = connection.execute(
            """
            SELECT request.state, request.safe_outcome_json,
                   payload.encrypted_payload, payload.payload_hash, payload.purge_reason,
                   attempt.safe_completion_json, attempt.reconciliation_resolution
            FROM approval_requests AS request
            JOIN payload_versions AS payload
              ON payload.request_id = request.request_id
             AND payload.version = request.current_version
            JOIN execution_attempts AS attempt
              ON attempt.request_id = request.request_id
             AND attempt.version = request.current_version
            WHERE request.request_id = ?
            """,
            (request_id,),
        ).fetchone()
        actions = connection.execute(
            """
            SELECT action FROM request_events
            WHERE request_id = ? AND action LIKE 'fake_only_unknown_content_purge_%'
            ORDER BY event_id
            """,
            (request_id,),
        ).fetchall()
    assert tuple(stored) == (
        "outcome_unknown",
        None,
        None,
        payload_hash,
        "fake_only_unknown_content",
        None,
        "exhausted",
    )
    assert [row["action"] for row in actions] == [
        "fake_only_unknown_content_purge_authorized",
        "fake_only_unknown_content_purge_completed",
    ]
    assert assembly.provider_clients["fastmail"].mutation_calls == 0


def test_fake_unknown_purge_cli_help_and_required_acknowledgement(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as help_exit:
        main(["demo", "purge-unknown", "--help"])
    assert help_exit.value.code == 0
    help_output = capsys.readouterr()
    assert help_output.err == ""
    normalized_help = " ".join(help_output.out.split())
    for phrase in (
        "FAKE-ONLY destructive logical redaction",
        "Stop the demo server first",
        "does not erase SQLite free pages",
        "authenticated expanded review",
        "full lowercase SHA-256 payload hash",
        "delivery remains possible",
    ):
        assert phrase in normalized_help

    with pytest.raises(SystemExit) as missing_ack:
        main(
            [
                "demo",
                "purge-unknown",
                "--data-dir",
                "/private/path-marker",
                "--request-id",
                "request-secret-marker",
                "--expected-version",
                "1",
                "--expected-payload-hash",
                "a" * 64,
            ]
        )
    assert missing_ack.value.code == 2
    failure = capsys.readouterr()
    assert "--acknowledge-possible-delivery" in failure.err
    assert "request-secret-marker" not in failure.err
    assert "/private/path-marker" not in failure.err
    assert "Traceback" not in failure.err


def test_abandoned_pin_release_cli_help_and_required_acknowledgement(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as help_exit:
        main(["demo", "release-abandoned-pins", "--help"])
    assert help_exit.value.code == 0
    help_output = capsys.readouterr()
    assert help_output.err == ""
    normalized_help = " ".join(help_output.out.split())
    for phrase in (
        "FAKE-ONLY recovery",
        "terminated demo backup",
        "Stop the demo server",
        "backup, restore, or snapshot process",
        "inclusive cutoff",
        "Unix timestamp",
    ):
        assert phrase in normalized_help

    with pytest.raises(SystemExit) as missing_ack:
        main(
            [
                "demo",
                "release-abandoned-pins",
                "--data-dir",
                "/private/demo-marker",
                "--created-at-or-before",
                "1234",
            ]
        )
    assert missing_ack.value.code == 2
    failure = capsys.readouterr()
    assert "--acknowledge-no-backup-active" in failure.err
    assert "/private/demo-marker" not in failure.err
    assert "Traceback" not in failure.err


def test_abandoned_pin_release_cli_is_marker_lock_and_cutoff_guarded(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "abandoned-pin-cli")
    assembly, request_id, payload_hash = exhausted_fake_unknown(root)
    selected_now = int(time.time())
    old = BackupPins(assembly.database).acquire(now=selected_now - 20)
    recent = BackupPins(assembly.database).acquire(now=selected_now - 5)
    args = [
        "demo",
        "release-abandoned-pins",
        "--data-dir",
        str(root),
        "--created-at-or-before",
        str(selected_now - 10),
        "--acknowledge-no-backup-active",
    ]

    with pytest.raises(DemoError, match="explicit no-backup acknowledgement"):
        demo_module.release_abandoned_demo_backup_pins(
            root,
            created_at_or_before=selected_now - 10,
            acknowledge_no_backup_active=False,
            now=selected_now,
        )
    with pytest.raises(DemoError, match="cutoff cannot be in the future"):
        demo_module.release_abandoned_demo_backup_pins(
            root,
            created_at_or_before=selected_now + 1,
            acknowledge_no_backup_active=True,
            now=selected_now,
        )

    marker = root / "demo-state.json"
    original_marker = marker.read_text(encoding="utf-8")
    invalid_marker = json.loads(original_marker)
    invalid_marker["mode"] = "not-fake"
    marker.write_text(json.dumps(invalid_marker), encoding="utf-8")
    with pytest.raises(SystemExit) as marker_exit:
        main(args)
    assert marker_exit.value.code == 2
    marker_failure = capsys.readouterr()
    assert "fake-only marker is invalid" in marker_failure.err
    assert request_id not in marker_failure.err
    assert payload_hash not in marker_failure.err
    marker.write_text(original_marker, encoding="utf-8")

    main(args)
    released = json.loads(capsys.readouterr().out)
    assert released == {
        "created_at_or_before": selected_now - 10,
        "released_pin_rows": len(old.purge_job_ids),
        "remaining_active_pin_rows": len(recent.purge_job_ids),
        "scope": "fake_only_downstream_disabled",
        "status": "abandoned_backup_pins_released",
    }
    assert request_id not in json.dumps(released)
    assert payload_hash not in json.dumps(released)
    assert str(root) not in json.dumps(released)

    recent_args = list(args)
    recent_args[recent_args.index(str(selected_now - 10))] = str(selected_now - 5)
    with demo_module._demo_server_lock(root), pytest.raises(SystemExit) as locked_exit:
        main(recent_args)
    assert locked_exit.value.code == 2
    lock_failure = capsys.readouterr()
    assert "already being served" in lock_failure.err
    assert request_id not in lock_failure.err
    assert payload_hash not in lock_failure.err

    main(recent_args)
    final_release = json.loads(capsys.readouterr().out)
    assert final_release["released_pin_rows"] == len(recent.purge_job_ids)
    assert final_release["remaining_active_pin_rows"] == 0

    main(
        [
            "demo",
            "purge-unknown",
            "--data-dir",
            str(root),
            "--request-id",
            request_id,
            "--expected-version",
            "1",
            "--expected-payload-hash",
            payload_hash,
            "--acknowledge-possible-delivery",
        ]
    )
    purged = json.loads(capsys.readouterr().out)
    assert purged["status"] == "fake_only_content_purged"


def test_fake_unknown_purge_reports_failure_backoff_and_due_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path, "purge-retry-report")
    _assembly, request_id, payload_hash = exhausted_fake_unknown(root)
    selected_now = 1_800_000_100
    original_process = demo_module.RetentionManager.process
    failed_once = False

    def fail_first_attachment(
        manager: Any,
        claim: Any,
        *,
        now: int,
    ) -> bool:
        nonlocal failed_once
        if claim.intent.value == "attachments" and not failed_once:
            failed_once = True
            manager._record_failure(claim, now=now, error_code="worker_failure")
            return False
        return bool(original_process(manager, claim, now=now))

    monkeypatch.setattr(demo_module.RetentionManager, "process", fail_first_attachment)
    call = {
        "request_id": request_id,
        "expected_version": 1,
        "expected_payload_hash": payload_hash,
        "acknowledge_possible_delivery": True,
    }
    with pytest.raises(DemoError) as failed:
        demo_module.purge_fake_unknown_content(root, **call, now=selected_now)
    assert json.loads(str(failed.value)) == {
        "failed": 1,
        "reason": "worker_failure",
        "retry_after": 60,
        "status": "fake_only_content_purge_incomplete",
    }

    with pytest.raises(DemoError) as early:
        demo_module.purge_fake_unknown_content(root, **call, now=selected_now + 59)
    assert json.loads(str(early.value)) == {
        "failed": 0,
        "reason": "worker_failure",
        "retry_after": 1,
        "status": "fake_only_content_purge_incomplete",
    }

    monkeypatch.setattr(demo_module.RetentionManager, "process", original_process)
    replay = demo_module.purge_fake_unknown_content(root, **call, now=selected_now + 60)
    assert replay["claimed"] == replay["completed"] == 1
    assert replay["failed"] == 0
    assert replay["status"] == "fake_only_content_purged"


def test_fake_unknown_purge_reports_abandoned_claim_lease_boundary(tmp_path: Path) -> None:
    root = new_demo(tmp_path, "purge-claim-report")
    assembly, request_id, payload_hash = exhausted_fake_unknown(root)
    selected_now = 1_800_000_100
    retention = assembly.workers.retention
    assert (
        retention.authorize_fake_only_exhausted_unknown_purge(
            request_id=request_id,
            expected_version=1,
            expected_payload_hash=payload_hash,
            acknowledge_possible_external_effect=True,
            now=selected_now,
        )
        == 2
    )
    assert retention.claim_due(now=selected_now, request_id=request_id) is not None
    call = {
        "request_id": request_id,
        "expected_version": 1,
        "expected_payload_hash": payload_hash,
        "acknowledge_possible_delivery": True,
    }

    with pytest.raises(DemoError) as active:
        demo_module.purge_fake_unknown_content(root, **call, now=selected_now)
    assert json.loads(str(active.value)) == {
        "failed": 0,
        "reason": "claim_lease_active",
        "retry_after": 301,
        "status": "fake_only_content_purge_incomplete",
    }
    with pytest.raises(DemoError) as boundary:
        demo_module.purge_fake_unknown_content(root, **call, now=selected_now + 300)
    assert json.loads(str(boundary.value))["retry_after"] == 1
    replay = demo_module.purge_fake_unknown_content(root, **call, now=selected_now + 301)
    assert replay["claimed"] == replay["completed"] == 2
    assert replay["status"] == "fake_only_content_purged"


def test_fake_unknown_purge_cli_pin_lock_and_stale_binding_fail_without_authorizing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = new_demo(tmp_path, "unknown-purge-guards")
    assembly, request_id, payload_hash = exhausted_fake_unknown(root)
    args = [
        "demo",
        "purge-unknown",
        "--data-dir",
        str(root),
        "--request-id",
        request_id,
        "--expected-version",
        "1",
        "--expected-payload-hash",
        payload_hash,
        "--acknowledge-possible-delivery",
    ]

    pins = BackupPins(assembly.database)
    lease = pins.acquire(now=1_800_000_100)
    with pytest.raises(SystemExit) as pinned_exit:
        main(args)
    assert pinned_exit.value.code == 2
    pinned = capsys.readouterr()
    assert "backup is active" in pinned.err
    assert request_id not in pinned.err
    assert payload_hash not in pinned.err
    assert str(root) not in pinned.err
    assert "Traceback" not in pinned.err
    with assembly.database.read() as connection:
        assert (
            connection.execute(
                """
                SELECT count(*) FROM request_events
                WHERE request_id = ?
                  AND action = 'fake_only_unknown_content_purge_authorized'
                """,
                (request_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """
                SELECT count(*) FROM purge_jobs
                WHERE request_id = ? AND intent != 'backup_pin'
                """,
                (request_id,),
            ).fetchone()[0]
            == 0
        )
    pins.release(lease, now=1_800_000_101)

    stale_args = list(args)
    stale_args[stale_args.index(payload_hash)] = "b" * 64
    with pytest.raises(SystemExit) as stale_exit:
        main(stale_args)
    assert stale_exit.value.code == 2
    stale = capsys.readouterr()
    assert "revision is not the current unknown outcome" in stale.err
    assert request_id not in stale.err
    assert payload_hash not in stale.err
    assert "b" * 64 not in stale.err
    assert "Traceback" not in stale.err

    with demo_module._demo_server_lock(root), pytest.raises(SystemExit) as locked_exit:
        main(args)
    assert locked_exit.value.code == 2
    locked = capsys.readouterr()
    assert "already being served" in locked.err
    assert request_id not in locked.err
    assert payload_hash not in locked.err
    assert "Traceback" not in locked.err


def test_marker_permissions_policy_and_production_shaped_tokens_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path)
    assembly = build_demo(root)
    fake_token = credential_value(root, "mcp-token")
    with pytest.raises(CredentialError):
        assembly.token_registry.authenticate(
            f"Bearer {fake_token.removeprefix('fake:')}",
            alias="fastmail",
        )

    os.chmod(root / "demo-secrets.json", 0o644)
    with pytest.raises(DemoError, match="unsafe"):
        build_demo(root)
    os.chmod(root / "demo-secrets.json", 0o600)

    with monkeypatch.context() as scoped:
        scoped.setattr("signet.demo.os.geteuid", lambda: root.stat().st_uid + 1)
        with pytest.raises(DemoError, match="private mode 0700"):
            build_demo(root)

    private_target = tmp_path / "private-target"
    private_target.mkdir(mode=0o700)
    private_link = tmp_path / "private-link"
    private_link.symlink_to(private_target, target_is_directory=True)
    with pytest.raises(DemoError, match="private directory"):
        backup_demo(root, private_link / "backup.signet-backup")

    policy_path = root / "policy.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy["downstreams"]["fastmail"]["url"] = "https://api.fastmail.com/mcp"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(DemoError, match="non-fake"):
        build_demo(root)


@pytest.mark.asyncio
async def test_mcp_fake_read_approval_deny_and_web_only_approval_surface(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        async with mcp_session(client, "fastmail") as session:
            listed = await session.list_tools()
            assert [tool.name for tool in listed.tools] == [
                "list_identities",
                "search_email",
                "send_email",
                "delete_email",
            ]
            read = await session.call_tool("list_identities", {})
            assert read.isError is False
            assert read.structuredContent == {
                "identities": [
                    {
                        "id": "fake:identity:primary",
                        "email": "fake-sender@demo.invalid",
                        "name": "Fake Demo Sender",
                    }
                ]
            }
            denied = await session.call_tool(
                "delete_email", {"message_id": "fake:message:never-delete"}
            )
            assert denied.isError is True
            assert denied.structuredContent["error"]["code"] == "policy_denied"
            denied_replay = await session.call_tool(
                "delete_email", {"message_id": "fake:message:different-private-value"}
            )
            assert denied_replay.structuredContent["error"]["code"] == "policy_denied"
            pending_fastmail = await session.call_tool("send_email", FASTMAIL_ARGUMENTS)
            assert pending_fastmail.isError is False
            fastmail_request_id = str(pending_fastmail.structuredContent["request_id"])

        async with mcp_session(client, "whatsapp") as session:
            read = await session.call_tool("list_chats", {})
            assert read.structuredContent["chats"][0]["label"] == "fake:demo-chat"
            denied = await session.call_tool("delete_chat", {"jid": "15555550123@s.whatsapp.net"})
            assert denied.isError is True
            pending = await session.call_tool("send_text", WHATSAPP_ARGUMENTS)
            assert pending.structuredContent["status"] == "pending_approval"
            whatsapp_request_id = str(pending.structuredContent["request_id"])

        async with mcp_session(client, "approvals") as session:
            listed = await session.list_tools()
            names = [tool.name for tool in listed.tools]
            assert "approve_request" not in names
            assert names == [
                "check_approval_status",
                "list_pending_approvals",
                "cancel_request",
                "request_tool_access",
            ]
            pending = await session.call_tool("list_pending_approvals", {})
            assert pending.isError is False
            serialized = json.dumps(pending.structuredContent)
            assert FASTMAIL_ARGUMENTS["to"][0] not in serialized
            assert WHATSAPP_ARGUMENTS["to"] not in serialized
            summaries = {
                str(item["request_id"]): str(item["destination_summary"])
                for item in pending.structuredContent["requests"]
            }
            assert summaries[fastmail_request_id] == "f*** at demo.invalid"
            assert summaries[whatsapp_request_id] == "*******0123@s.whatsapp.net"
            for request_id, raw_destination in (
                (fastmail_request_id, FASTMAIL_ARGUMENTS["to"][0]),
                (whatsapp_request_id, WHATSAPP_ARGUMENTS["to"]),
            ):
                status = await session.call_tool(
                    "check_approval_status", {"request_id": request_id}
                )
                assert status.isError is False
                status_json = json.dumps(status.structuredContent)
                assert raw_destination not in status_json
                assert status.structuredContent["summary_available"] is True
            with pytest.raises(McpError):
                await session.call_tool(
                    "approve_request",
                    {
                        "request_id": "req_fake",
                        "totp_code": "000000",
                        "expected_version_hash": "a" * 8,
                    },
                )
    assert assembly.provider_clients["fastmail"].mutation_calls == 0
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0
    with assembly.database.read() as connection:
        denied_events = connection.execute(
            """
            SELECT request.request_id, request.origin_namespace,
                   payload.encrypted_payload
            FROM approval_requests AS request
            JOIN payload_versions AS payload
              ON payload.request_id = request.request_id
             AND payload.version = request.current_version
            WHERE request.gateway_internal = 1
              AND request.tool_name = 'request_tool_access'
            ORDER BY request.request_id
            """
        ).fetchall()
        denied_idempotency = connection.execute(
            """
            SELECT count(*) FROM idempotency_records AS idempotency
            JOIN approval_requests AS request USING(request_id)
            WHERE request.gateway_internal = 1
              AND request.tool_name = 'request_tool_access'
            """
        ).fetchone()[0]
    assert len(denied_events) == 2
    assert denied_idempotency == 2
    assert {row["origin_namespace"] for row in denied_events} == {DEMO_NAMESPACE}
    for row in denied_events:
        ciphertext = bytes(row["encrypted_payload"])
        assert b"never-delete" not in ciphertext
        assert b"different-private-value" not in ciphertext
        assert b"15555550123" not in ciphertext


@pytest.mark.asyncio
async def test_immediate_browser_deny_then_approve_has_zero_then_one_provider_call(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        denied_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Deny this fake request"},
        )
        approved_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Approve this fake request"},
        )

    denied = await web_action(assembly, denied_id, "deny")
    assert denied.status_code == 303
    assert request_state(assembly, denied_id) == "denied"
    denied_delivery, _notifications = await assembly.workers.run_once()
    assert denied_delivery == 0
    assert assembly.provider_clients["fastmail"].mutation_calls == 0

    approved = await web_action(assembly, approved_id, "approve")
    assert approved.status_code == 303
    delivered, _notifications = await assembly.workers.run_once()
    assert delivered == 1
    assert request_state(assembly, approved_id) == "succeeded"
    assert assembly.provider_clients["fastmail"].mutation_calls == 1
    safe = assembly.state_machine.get_request(approved_id)["safe_outcome_json"]
    assert "fake:message" not in str(safe)
    assert "sgref_" in str(safe)

    restarted = build_demo(assembly.root)
    assert request_state(restarted, approved_id) == "succeeded"
    assert (await restarted.workers.run_once())[0] == 0
    assert restarted.provider_clients["fastmail"].mutation_calls == 0


@pytest.mark.asyncio
async def test_workers_reclaim_only_pre_dispatch_and_reconcile_abandoned_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        reclaimable_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Reclaim before fake dispatch"},
        )
        unknown_id = await enqueue(
            client,
            "whatsapp",
            "send_text",
            {**WHATSAPP_ARGUMENTS, "message": "Recover after fake dispatch boundary"},
        )
    assert (await web_action(assembly, reclaimable_id, "approve")).status_code == 303
    assert (await web_action(assembly, unknown_id, "approve")).status_code == 303

    started_at = int(time.time())
    assembly.state_machine.claim_execution(
        reclaimable_id,
        worker_id="fake:crashed-before-dispatch",
        now=started_at,
        lease_seconds=1,
    )
    unknown_lease = assembly.state_machine.claim_execution(
        unknown_id,
        worker_id="fake:crashed-after-dispatch",
        now=started_at,
        lease_seconds=1,
    )
    assembly.state_machine.mark_dispatch_started(unknown_lease, now=started_at)
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE execution_attempts SET lease_expires_at = ? WHERE request_id IN (?, ?)",
            (started_at - 1, reclaimable_id, unknown_id),
        )

    stop = asyncio.Event()
    result: tuple[int, int] | None = None
    original_run_once = assembly.workers.run_once

    async def run_one_supervised_cycle(*, now: int | None = None) -> tuple[int, int]:
        nonlocal result
        result = await original_run_once(now=now)
        stop.set()
        return result

    monkeypatch.setattr(assembly.workers, "run_once", run_one_supervised_cycle)
    await assembly.workers.serve(stop)
    monkeypatch.setattr(assembly.workers, "run_once", original_run_once)
    assert result is not None
    delivered, _notifications = result
    assert delivered == 1
    assert request_state(assembly, reclaimable_id) == "succeeded"
    assert request_state(assembly, unknown_id) == "outcome_unknown"
    assert assembly.provider_clients["fastmail"].mutation_calls == 1
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0
    with assembly.database.read() as connection:
        reclaimed = connection.execute(
            "SELECT worker_generation, phase FROM execution_attempts WHERE request_id = ?",
            (reclaimable_id,),
        ).fetchone()
        unknown = connection.execute(
            """
            SELECT reconciliation_attempt_count, reconciliation_next_at,
                   reconciliation_resolution
            FROM execution_attempts WHERE request_id = ?
            """,
            (unknown_id,),
        ).fetchone()
    assert tuple(reclaimed) == (2, "succeeded")
    assert unknown["reconciliation_attempt_count"] == 1
    assert unknown["reconciliation_resolution"] == "inconclusive"

    while unknown["reconciliation_resolution"] != "exhausted":
        next_at = int(unknown["reconciliation_next_at"])
        await assembly.workers.run_once(now=next_at)
        with assembly.database.read() as connection:
            unknown = connection.execute(
                """
                SELECT reconciliation_attempt_count, reconciliation_next_at,
                       reconciliation_resolution
                FROM execution_attempts WHERE request_id = ?
                """,
                (unknown_id,),
            ).fetchone()
    assert unknown["reconciliation_attempt_count"] == 5
    assert unknown["reconciliation_next_at"] is None
    assert assembly.provider_clients["fastmail"].mutation_calls == 1
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0


@pytest.mark.asyncio
async def test_fake_fastmail_ambiguous_result_is_resolved_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        request_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {**FASTMAIL_ARGUMENTS, "subject": "Reconcile this fake send"},
        )
    assert (await web_action(assembly, request_id, "approve")).status_code == 303

    provider = assembly.provider_clients["fastmail"]
    original_call = provider.call_tool

    async def ambiguous_result(
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        result = await original_call(tool_name, arguments)
        if tool_name == "send_email":
            result["status"] = "ambiguous"
        return result

    monkeypatch.setattr(provider, "call_tool", ambiguous_result)
    now = int(time.time())
    delivered, _notifications = await assembly.workers.run_once(now=now)
    assert delivered == 1
    assert request_state(assembly, request_id) == "outcome_unknown"
    assert provider.mutation_calls == 1

    await assembly.workers.run_once(now=now + 60)
    assert request_state(assembly, request_id) == "succeeded"
    assert provider.mutation_calls == 1
    with assembly.database.read() as connection:
        attempt = connection.execute(
            """
            SELECT reconciliation_attempt_count, reconciliation_resolution
            FROM execution_attempts WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
    assert tuple(attempt) == (1, "confirmed_effect")


@pytest.mark.asyncio
async def test_workers_schedule_private_notifications_and_retention_once(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        request_id = await enqueue(client, "whatsapp", "send_text", WHATSAPP_ARGUMENTS)

    now = int(time.time())
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE approval_requests SET expires_at = ? WHERE request_id = ?",
            (now + 60, request_id),
        )
    _delivered, notifications = await assembly.workers.run_once(now=now)
    assert notifications == 3
    with assembly.database.read() as connection:
        kinds = [
            str(row["kind"])
            for row in connection.execute(
                "SELECT kind FROM notification_outbox ORDER BY kind"
            ).fetchall()
        ]
    assert kinds == ["approaching_expiry", "daily_digest", "new_pending"]
    assert (await assembly.workers.run_once(now=now))[1] == 0

    await assembly.workers.run_once(now=now + 61)
    assert request_state(assembly, request_id) == "expired"
    with assembly.database.read() as connection:
        payload = connection.execute(
            "SELECT encrypted_payload, purged_at FROM payload_versions WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        retention = connection.execute(
            """
            SELECT intent, completed_at FROM purge_jobs
            WHERE request_id = ? ORDER BY intent
            """,
            (request_id,),
        ).fetchall()
    assert payload["encrypted_payload"] is not None
    assert payload["purged_at"] is None
    assert [tuple(row) for row in retention] == [("sensitive_rows", None)]


@pytest.mark.asyncio
async def test_worker_supervision_retries_and_health_reports_persistent_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    stop = asyncio.Event()
    third_failure = asyncio.Event()
    calls = 0

    original_sweep = assembly.state_machine.sweep_expired

    def flaky_expiry_sweep(*, now: int, limit: int) -> int:
        nonlocal calls
        calls += 1
        if calls <= 3:
            if calls == 3:
                third_failure.set()
            raise RuntimeError("private fake expiry failure")
        stop.set()
        return original_sweep(now=now, limit=limit)

    assembly.workers.interval_seconds = 0.05
    monkeypatch.setattr(assembly.state_machine, "sweep_expired", flaky_expiry_sweep)
    task = asyncio.create_task(assembly.workers.serve(stop))
    await asyncio.wait_for(third_failure.wait(), timeout=2)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=assembly.web),
        base_url="http://127.0.0.1:8790",
    ) as client:
        for _ in range(20):
            health = await client.get("/healthz")
            if health.status_code == 503:
                break
            await asyncio.sleep(0.01)
    assert health.status_code == 503
    assert health.json() == {"status": "unavailable", "service": "signet-web"}

    await asyncio.wait_for(task, timeout=2)
    assert calls == 4


@pytest.mark.asyncio
async def test_assembled_worker_lifespan_keeps_web_responsive_during_blocking_sweep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    started = Event()
    release = Event()
    original_sweep = assembly.state_machine.sweep_expired

    def blocking_sweep(*, now: int, limit: int) -> int:
        started.set()
        if not release.wait(timeout=5):
            raise AssertionError("blocking demo sweep was not released")
        return original_sweep(now=now, limit=limit)

    monkeypatch.setattr(assembly.state_machine, "sweep_expired", blocking_sweep)
    safety_release = Timer(3, release.set)
    safety_release.start()
    try:
        async with assembly.web.router.lifespan_context(assembly.web):
            waiting_started_at = time.monotonic()
            assert await asyncio.to_thread(started.wait, 1)
            assert time.monotonic() - waiting_started_at < 2
            assert not release.is_set()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=assembly.web),
                base_url="http://127.0.0.1:8790",
            ) as client:
                health = await asyncio.wait_for(client.get("/healthz"), timeout=1)
            assert health.status_code == 200
            release.set()
    finally:
        release.set()
        safety_release.cancel()


@pytest.mark.asyncio
async def test_offline_operations_under_serve_lock_never_recover_execution(
    tmp_path: Path,
) -> None:
    root = new_demo(tmp_path, "live-source")
    assembly = build_demo(root)
    async with mcp_client(assembly) as client:
        request_id = await enqueue(client, "whatsapp", "send_text", WHATSAPP_ARGUMENTS)
    assert (await web_action(assembly, request_id, "approve")).status_code == 303

    now = int(time.time())
    lease = assembly.state_machine.claim_execution(
        request_id,
        worker_id="fake:live-dispatch",
        now=now,
        lease_seconds=30,
    )
    assembly.state_machine.mark_dispatch_started(lease, now=now)
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE execution_attempts SET lease_expires_at = ? WHERE request_id = ?",
            (now - 1, request_id),
        )

    private = tmp_path / "offline-artifacts"
    private.mkdir(mode=0o700)
    with demo_module._demo_server_lock(root):
        assert request_state(build_demo(root), request_id) == "executing"
        assert offline_smoke(root)["status"] == "ok"
        assert request_state(assembly, request_id) == "executing"
        bundle = backup_demo(root, private / "concurrent.signet-backup")
        assert request_state(assembly, request_id) == "executing"
        restored = restore_demo(root, bundle, private / "restored")
        assert request_state(build_demo(restored.root), request_id) == "executing"
        assert request_state(assembly, request_id) == "executing"

    recovered = assembly.state_machine.recover_startup(now=now)
    assert recovered.routed_to_reconciliation == (request_id,)
    assert request_state(assembly, request_id) == "outcome_unknown"


def test_demo_serve_lock_rejects_links_and_reuses_stale_regular_file(tmp_path: Path) -> None:
    root = new_demo(tmp_path)
    lock_path = root / ".serve.lock"
    outside = tmp_path / "outside-lock"
    outside.write_text("not a lock\n", encoding="utf-8")
    os.chmod(outside, 0o600)

    lock_path.symlink_to(outside)
    with (
        pytest.raises(DemoError, match="unavailable or unsafe"),
        demo_module._demo_server_lock(root),
    ):
        pass
    lock_path.unlink()

    os.link(outside, lock_path)
    with (
        pytest.raises(DemoError, match="unavailable or unsafe"),
        demo_module._demo_server_lock(root),
    ):
        pass
    lock_path.unlink()

    lock_path.write_text("stale owner metadata is ignored\n", encoding="utf-8")
    os.chmod(lock_path, 0o600)
    with (
        demo_module._demo_server_lock(root),
        pytest.raises(DemoError, match="already being served"),
        demo_module._demo_server_lock(root),
    ):
        pass
    with demo_module._demo_server_lock(root):
        pass


def test_demo_backup_maintenance_lock_is_marker_guarded_safe_and_reusable(
    tmp_path: Path,
) -> None:
    root = new_demo(tmp_path, "backup-maintenance-lock")
    lock_path = root / ".backup-maintenance.lock"
    outside = tmp_path / "outside-backup-lock"
    outside.write_text("not a lock\n", encoding="utf-8")
    os.chmod(outside, 0o600)

    lock_path.symlink_to(outside)
    with (
        pytest.raises(DemoError, match="maintenance lock is unavailable or unsafe"),
        demo_module._demo_backup_maintenance_lock(root),
    ):
        pass
    lock_path.unlink()

    os.link(outside, lock_path)
    with (
        pytest.raises(DemoError, match="maintenance lock is unavailable or unsafe"),
        demo_module._demo_backup_maintenance_lock(root),
    ):
        pass
    lock_path.unlink()

    lock_path.write_text("stale owner metadata is ignored\n", encoding="utf-8")
    os.chmod(lock_path, 0o600)
    with (
        demo_module._demo_backup_maintenance_lock(root),
        demo_module._demo_server_lock(root),
        pytest.raises(DemoError, match="backup maintenance is already active"),
        demo_module._demo_backup_maintenance_lock(root),
    ):
        pass
    with demo_module._demo_backup_maintenance_lock(root):
        pass


def test_demo_lock_setup_failure_reports_unconfirmed_post_acquire_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path, "lock-setup-finalization")
    original_open = demo_module.os.open
    original_fstat = demo_module.os.fstat
    original_close = demo_module.os.close
    original_flock = demo_module.fcntl.flock
    lock_descriptor: int | None = None
    lock_fstats = 0
    close_attempted = False
    unlock_attempted = False

    def capture_lock_open(path: Path, *args: Any, **kwargs: Any) -> int:
        nonlocal lock_descriptor
        descriptor = original_open(path, *args, **kwargs)
        if Path(path).name == ".serve.lock":
            lock_descriptor = descriptor
        return descriptor

    def fail_post_acquire_fstat(descriptor: int) -> os.stat_result:
        nonlocal lock_fstats
        if descriptor == lock_descriptor:
            lock_fstats += 1
            if lock_fstats == 3:
                raise OSError("injected private post-acquire verification failure")
        return original_fstat(descriptor)

    def record_unlock(descriptor: int, operation: int) -> None:
        nonlocal unlock_attempted
        if descriptor == lock_descriptor and operation == demo_module.fcntl.LOCK_UN:
            unlock_attempted = True
        original_flock(descriptor, operation)

    def fail_lock_close_once(descriptor: int) -> None:
        nonlocal close_attempted
        if descriptor == lock_descriptor and not close_attempted:
            close_attempted = True
            raise OSError("injected private lock close failure")
        original_close(descriptor)

    monkeypatch.setattr(demo_module.os, "open", capture_lock_open)
    monkeypatch.setattr(demo_module.os, "fstat", fail_post_acquire_fstat)
    monkeypatch.setattr(demo_module.fcntl, "flock", record_unlock)
    monkeypatch.setattr(demo_module.os, "close", fail_lock_close_once)

    with (
        pytest.raises(
            DemoError,
            match=(
                "lock setup failed.*lock release could not be confirmed.*stop all demo processes"
            ),
        ) as caught,
        demo_module._demo_server_lock(root),
    ):
        pytest.fail("lock setup unexpectedly reached the protected operation")

    assert "injected" not in str(caught.value)
    assert unlock_attempted
    assert close_attempted
    assert lock_descriptor is not None
    original_flock(lock_descriptor, demo_module.fcntl.LOCK_UN)
    original_close(lock_descriptor)

    private = tmp_path / "backup-lock-output"
    private.mkdir(mode=0o700)
    blocked_destination = private / "blocked.signet-backup"
    with (
        demo_module._demo_backup_maintenance_lock(root),
        pytest.raises(DemoError, match="backup maintenance is already active"),
    ):
        backup_demo(root, blocked_destination)
    assert not blocked_destination.exists()

    assembly = build_demo(root)
    pre_migration = assembly.backups.create_pre_migration_callback(private / "pre-migration")
    with (
        demo_module._demo_backup_maintenance_lock(root),
        pytest.raises(DemoError, match="backup maintenance is already active"),
    ):
        pre_migration(assembly.database, 1)

    marker = root / "demo-state.json"
    original_marker = marker.read_text(encoding="utf-8")
    invalid_marker = json.loads(original_marker)
    invalid_marker["mode"] = "not-fake"
    marker.write_text(json.dumps(invalid_marker), encoding="utf-8")
    with (
        pytest.raises(DemoError, match="fake-only marker is invalid"),
        demo_module._demo_backup_maintenance_lock(root),
    ):
        pass
    marker.write_text(original_marker, encoding="utf-8")
    with demo_module._demo_backup_maintenance_lock(root):
        pass


def test_demo_backup_lock_release_failure_preserves_durable_success_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path, "backup-lock-finalization-success")
    assembly = build_demo(root)
    private = tmp_path / "backup-lock-finalization-output"
    private.mkdir(mode=0o700)
    destination = private / "durable.signet-backup"
    original_flock = demo_module.fcntl.flock

    class UnlockFailure:
        LOCK_EX = demo_module.fcntl.LOCK_EX
        LOCK_NB = demo_module.fcntl.LOCK_NB
        LOCK_UN = demo_module.fcntl.LOCK_UN

        @staticmethod
        def flock(descriptor: int, operation: int) -> None:
            if operation == UnlockFailure.LOCK_UN:
                raise OSError("injected private unlock failure")
            original_flock(descriptor, operation)

    monkeypatch.setattr(demo_module, "fcntl", UnlockFailure)

    with pytest.raises(
        DemoError,
        match="operation completed.*lock release could not be confirmed.*destination result",
    ) as caught:
        assembly.backups.create(destination)

    assert "injected" not in str(caught.value)
    assert destination.is_file()


def test_demo_backup_lock_release_failure_preserves_unknown_publication_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path, "backup-lock-finalization-unknown")
    assembly = build_demo(root)
    private = tmp_path / "backup-lock-unknown-output"
    private.mkdir(mode=0o700)
    destination = private / "unknown.signet-backup"
    original_flock = demo_module.fcntl.flock
    original_fsync = backup_module._fsync_directory

    class UnlockFailure:
        LOCK_EX = demo_module.fcntl.LOCK_EX
        LOCK_NB = demo_module.fcntl.LOCK_NB
        LOCK_UN = demo_module.fcntl.LOCK_UN

        @staticmethod
        def flock(descriptor: int, operation: int) -> None:
            if operation == UnlockFailure.LOCK_UN:
                raise OSError("injected private unlock failure")
            original_flock(descriptor, operation)

    def fail_publication_fsync(path: Path) -> None:
        if path == private and destination.exists():
            raise OSError("injected private fsync failure")
        original_fsync(path)

    monkeypatch.setattr(demo_module, "fcntl", UnlockFailure)
    monkeypatch.setattr(backup_module, "_fsync_directory", fail_publication_fsync)

    with pytest.raises(DemoError) as caught:
        assembly.backups.create(destination)

    message = str(caught.value)
    assert "outcome is unknown" in message
    assert "additionally, lock release could not be confirmed" in message
    assert "injected" not in message
    assert destination.is_file()


def test_active_backup_lock_blocks_abandoned_pin_release_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path, "backup-release-race")
    assembly, request_id, payload_hash = exhausted_fake_unknown(root)
    private = tmp_path / "backup-release-race-output"
    private.mkdir(mode=0o700)
    destination = private / "concurrent.signet-backup"
    backup_service = build_demo(root).backups
    original_acquire = BackupPins.acquire
    pin_created = Barrier(2)
    allow_backup = Event()
    pin_times: list[int] = []
    leases: list[Any] = []

    def acquire_then_pause(pins: BackupPins, *, now: int) -> Any:
        lease = original_acquire(pins, now=now)
        pin_times.append(now)
        leases.append(lease)
        pin_created.wait(timeout=10)
        if not allow_backup.wait(timeout=10):
            raise AssertionError("backup release race did not unblock")
        return lease

    monkeypatch.setattr(BackupPins, "acquire", acquire_then_pause)
    with ThreadPoolExecutor(max_workers=1) as pool:
        backup = pool.submit(backup_service.create, destination)
        pin_created.wait(timeout=10)
        try:
            assert len(pin_times) == len(leases) == 1
            pin_time = pin_times[0]
            with pytest.raises(DemoError, match="backup maintenance is already active") as blocked:
                demo_module.release_abandoned_demo_backup_pins(
                    root,
                    created_at_or_before=pin_time,
                    acknowledge_no_backup_active=True,
                    now=pin_time,
                )
            assert request_id not in str(blocked.value)
            assert payload_hash not in str(blocked.value)
            assert str(root) not in str(blocked.value)
            with assembly.database.read() as connection:
                active = connection.execute(
                    """
                    SELECT count(*) FROM purge_jobs
                    WHERE intent = 'backup_pin' AND completed_at IS NULL
                    """
                ).fetchone()[0]
            assert active == len(leases[0].purge_job_ids)
            assert active > 0
        finally:
            allow_backup.set()
        assert backup.result(timeout=10) == destination

    assert destination.is_file()
    assert stat.S_IMODE((root / ".backup-maintenance.lock").stat().st_mode) == 0o600
    with assembly.database.read() as connection:
        remaining = connection.execute(
            """
            SELECT count(*) FROM purge_jobs
            WHERE intent = 'backup_pin' AND completed_at IS NULL
            """
        ).fetchone()[0]
    assert remaining == 0


@pytest.mark.asyncio
async def test_direct_workers_serve_cannot_recover_while_lifespan_holds_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = new_demo(tmp_path)
    holder = build_demo(root)
    contender = build_demo(root)
    recovery_calls = 0

    def unexpected_recovery(*, now: int) -> Any:
        nonlocal recovery_calls
        del now
        recovery_calls += 1
        raise AssertionError("unlocked recovery ran")

    monkeypatch.setattr(contender.state_machine, "recover_startup", unexpected_recovery)
    async with holder.web.router.lifespan_context(holder.web):
        with pytest.raises(DemoError, match="already being served"):
            await contender.workers.serve(asyncio.Event())
        assert recovery_calls == 0
        assert contender.provider_clients["fastmail"].mutation_calls == 0
        assert contender.provider_clients["whatsapp"].mutation_calls == 0


@pytest.mark.asyncio
async def test_corrupt_approved_payload_fails_before_fake_provider_call(
    tmp_path: Path,
) -> None:
    assembly = build_demo(new_demo(tmp_path))
    async with mcp_client(assembly) as client:
        request_id = await enqueue(client, "whatsapp", "send_text", WHATSAPP_ARGUMENTS)
    assert (await web_action(assembly, request_id, "approve")).status_code == 303
    with assembly.database.transaction() as connection:
        connection.execute(
            """
            UPDATE payload_versions
            SET encrypted_payload = NULL, purged_at = ?
            WHERE request_id = ?
            """,
            (1_800_000_001, request_id),
        )
    delivered, _notifications = await assembly.workers.run_once()
    assert delivered == 0
    assert request_state(assembly, request_id) == "failed"
    assert assembly.provider_clients["whatsapp"].mutation_calls == 0


@pytest.mark.asyncio
async def test_encrypted_backup_restore_preserves_pending_request_and_attachment(
    tmp_path: Path,
) -> None:
    root = new_demo(tmp_path, "source")
    assembly = build_demo(root)
    content = b"fake pending attachment content\n"
    source = root / "imports" / "pending.txt"
    source.write_bytes(content)
    os.chmod(source, 0o600)
    staged = assembly.staging.stage_path(
        source,
        adapter="fastmail",
        account="fake:fastmail-account",
        filename="pending.txt",
        declared_mime="text/plain",
    )
    attachment = {
        "staged_id": staged.opaque_id,
        "filename": staged.filename,
        "mime_type": staged.declared_mime,
        "detected_mime": staged.detected_mime,
        "detection_source": staged.detection_source,
        "size": staged.size,
        "sha256": staged.sha256,
    }
    async with mcp_client(assembly) as client:
        request_id = await enqueue(
            client,
            "fastmail",
            "send_email",
            {
                **FASTMAIL_ARGUMENTS,
                "subject": "Back up this pending fake request",
                "attachments": [attachment],
            },
        )
    assert request_state(assembly, request_id) == "pending_approval"

    old_token = credential_value(root, "mcp-token")
    old_password = credential_value(root, "web-password")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    bundle = backup_demo(root, private / "demo.signet-backup")
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    encrypted = bundle.read_bytes()
    assert old_token.encode() not in encrypted
    assert old_password.encode() not in encrypted
    assert content not in encrypted

    destination = private / "restored"
    restored = restore_demo(root, bundle, destination)
    assert restored.root == destination
    assert [item["attachment_id"] for item in restored.manifest["attachments"]] == [
        staged.opaque_id
    ]
    assert credential_value(destination, "mcp-token") != old_token
    assert credential_value(destination, "web-password") != old_password
    assert credential_value(destination, "mcp-token").startswith("fake:sgt_")
    assert offline_smoke(destination)["status"] == "ok"
    restarted = build_demo(destination)
    assert request_state(restarted, request_id) == "pending_approval"
    restored_record, restored_content = restarted.staging.read_verified(
        staged.opaque_id,
        adapter="fastmail",
        account="fake:fastmail-account",
    )
    assert restored_content == content
    assert restored_record.path.parent == destination / "attachments"

    existing = private / "existing"
    existing.mkdir(mode=0o700)
    with pytest.raises(BackupError, match="must not already exist"):
        restore_demo(root, bundle, existing)
    assert existing.is_dir()

    bad_bundle = private / "bad.signet-backup"
    bad_bundle.write_bytes(b"not-a-signet-backup")
    os.chmod(bad_bundle, 0o600)
    failed_destination = private / "failed-restore"
    with pytest.raises(BackupError):
        restore_demo(root, bad_bundle, failed_destination)
    assert not failed_destination.exists()


def test_demo_backup_restore_hardens_imports_and_secrets_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    root = new_demo(tmp_path, "restrictive-restore-source")
    artifacts = tmp_path / "restrictive-restore-artifacts"
    artifacts.mkdir(mode=0o700)
    bundle = backup_demo(root, artifacts / "source.signet-backup")
    destination = artifacts / "restored"
    previous_umask = os.umask(0o777)
    try:
        restore_demo(root, bundle, destination)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE((destination / "imports").stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "demo-secrets.json").stat().st_mode) == 0o600
    assert offline_smoke(destination)["status"] == "ok"


def test_cli_backup_errors_are_bounded_and_hermes_shape_is_restrictive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path)
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                str(public_parent / "backup.signet-backup"),
            ]
        )
    error = capsys.readouterr().err
    assert "Traceback" not in error
    assert credential_value(root, "mcp-token") not in error
    assert "private directory" in error

    document = yaml.safe_load(hermes_config(mcp_port=18789))
    assert set(document["mcp_servers"]) == {
        "signet_demo_fastmail",
        "signet_demo_whatsapp",
        "signet_demo_approvals",
    }
    for server in document["mcp_servers"].values():
        assert server == {
            "url": server["url"],
            "headers": {"Authorization": "Bearer ${SIGNET_DEMO_MCP_CALLER_TOKEN}"},
            "enabled": True,
            "connect_timeout": 10,
            "timeout": 120,
            "supports_parallel_tool_calls": False,
            "tools": {"resources": False, "prompts": False},
            "sampling": {"enabled": False},
        }
        assert server["url"].startswith("http://127.0.0.1:18789/mcp/")


def test_cli_backup_reports_unknown_publication_before_operator_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "cli-backup-unknown")
    output_parent = tmp_path / "private-unknown-output"
    output_parent.mkdir(mode=0o700)
    destination = output_parent / "unknown.signet-backup"
    original_fsync = backup_module._fsync_directory

    def fail_destination_parent_fsync(path: Path) -> None:
        if path == output_parent and destination.exists():
            raise OSError("injected parent fsync failure")
        original_fsync(path)

    monkeypatch.setattr(backup_module, "_fsync_directory", fail_destination_parent_fsync)

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                str(destination),
            ]
        )

    error = capsys.readouterr().err
    assert "outcome is unknown" in error
    assert "inspect the destination before retrying" in error
    assert "failed safely" not in error
    assert "Traceback" not in error
    assert credential_value(root, "mcp-token") not in error
    assert destination.is_file()


def test_demo_backup_and_restore_cli_paths_are_bounded(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "bounded-artifact-paths")
    selected = "~signet-user-that-must-not-exist-7f43d5/private.signet"

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                selected,
            ]
        )
    backup_error = capsys.readouterr().err
    assert "backup destination path is unavailable or unsafe" in backup_error
    assert selected not in backup_error
    assert "Traceback" not in backup_error

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "restore",
                "--data-dir",
                str(root),
                "--bundle",
                selected,
                "--destination",
                str(tmp_path / "unused-restore"),
            ]
        )
    restore_error = capsys.readouterr().err
    assert "backup bundle path is unavailable or unsafe" in restore_error
    assert selected not in restore_error
    assert "Traceback" not in restore_error


def test_cli_reports_combined_pin_release_and_private_cleanup_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "combined-backup-recovery")
    private = tmp_path / "combined-backup-recovery-output"
    private.mkdir(mode=0o700)
    destination = private / "not-published.signet-backup"
    original_rmtree = backup_module.shutil.rmtree

    def fail_construction(*_args: object) -> None:
        raise BackupError("injected private construction failure")

    def fail_pin_release(_self: object, _pins: object, *, now: int) -> None:
        del now
        raise sqlite3.OperationalError("injected private pin release failure")

    def retain_workspace(path: Path) -> None:
        if path.name.startswith(".signet-backup-"):
            raise OSError("injected private cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(backup_module, "_archive_workspace", fail_construction)
    monkeypatch.setattr(backup_module.BackupPins, "release", fail_pin_release)
    monkeypatch.setattr(backup_module.shutil, "rmtree", retain_workspace)

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                str(destination),
            ]
        )

    failure = capsys.readouterr().err
    assert "retention pin release could not be confirmed" in failure
    assert "private backup artifacts could not be removed safely" in failure.lower()
    assert "injected" not in failure
    assert credential_value(root, "mcp-token") not in failure
    assert not destination.exists()
    workspaces = tuple(private.glob(".signet-backup-*"))
    assert len(workspaces) == 1
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(workspaces[0])


def test_cli_backup_pin_release_uncertainty_is_prepublication_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "cli-backup-pin-release")
    output_parent = tmp_path / "private-pin-output"
    output_parent.mkdir(mode=0o700)
    destination = output_parent / "not-published.signet-backup"

    def fail_pin_release(_self: object, _pins: object, *, now: int) -> None:
        del now
        raise sqlite3.OperationalError("injected sqlite pin release failure")

    monkeypatch.setattr(backup_module.BackupPins, "release", fail_pin_release)

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                str(destination),
            ]
        )

    error = capsys.readouterr().err
    assert "was not published" in error
    assert "retention pin release could not be confirmed" in error
    assert "inspect retention state before retrying" in error
    assert "injected sqlite" not in error
    assert "Traceback" not in error
    assert credential_value(root, "mcp-token") not in error
    assert not destination.exists()
    assert tuple(output_parent.glob(".not-published.signet-backup.partial-*")) == ()
    assert tuple(output_parent.glob(".signet-backup-*")) == ()


def test_cli_backup_reports_retained_private_workspace_without_leaking_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "cli-backup-workspace-cleanup")
    output_parent = tmp_path / "private-workspace-output"
    output_parent.mkdir(mode=0o700)
    destination = output_parent / "not-published.signet-backup"
    original_rmtree = backup_module.shutil.rmtree

    def fail_archive_after_plaintext_workspace(*_args: object) -> None:
        raise BackupError("injected archive construction failure")

    def retain_backup_workspace(path: Path) -> None:
        if path.name.startswith(".signet-backup-"):
            raise OSError("injected private workspace cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(backup_module, "_archive_workspace", fail_archive_after_plaintext_workspace)
    monkeypatch.setattr(backup_module.shutil, "rmtree", retain_backup_workspace)

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                str(destination),
            ]
        )

    error = capsys.readouterr().err
    assert "was not published" in error
    assert "private backup artifact cleanup could not be confirmed" in error
    assert "inspect the backup parent before continuing" in error
    assert "injected" not in error
    assert str(output_parent) not in error
    assert "Traceback" not in error
    assert credential_value(root, "mcp-token") not in error
    assert not destination.exists()
    workspaces = tuple(output_parent.glob(".signet-backup-*"))
    assert len(workspaces) == 1
    assert (workspaces[0] / "approvals.sqlite3").is_file()
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(workspaces[0])


def test_cli_backup_reports_durable_publish_with_private_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "cli-backup-cleanup")
    output_parent = tmp_path / "private-cleanup-output"
    output_parent.mkdir(mode=0o700)
    destination = output_parent / "published.signet-backup"
    original_rmtree = backup_module.shutil.rmtree
    leaked_workspaces: list[Path] = []

    def fail_backup_workspace_cleanup(path: Path) -> None:
        if path.name.startswith(".signet-backup-"):
            leaked_workspaces.append(path)
            raise OSError("injected workspace cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(backup_module.shutil, "rmtree", fail_backup_workspace_cleanup)

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "backup",
                "--data-dir",
                str(root),
                "--output",
                str(destination),
            ]
        )

    error = capsys.readouterr().err
    assert "published durably" in error
    assert "private backup artifacts could not be removed" in error
    assert "inspect the backup parent before continuing" in error
    assert "failed safely" not in error
    assert "Traceback" not in error
    assert credential_value(root, "mcp-token") not in error
    assert destination.is_file()
    assert len(leaked_workspaces) == 1 and leaked_workspaces[0].is_dir()
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(leaked_workspaces[0])


def test_cli_demo_restore_reports_retained_rotated_secret_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = new_demo(tmp_path, "cli-restore-cleanup")
    artifacts = tmp_path / "private-restore-artifacts"
    artifacts.mkdir(mode=0o700)
    bundle = backup_demo(root, artifacts / "source.signet-backup")
    destination = artifacts / "retained-restore"
    original_demo_fsync = demo_module._fsync_directory
    original_rmtree = backup_module.shutil.rmtree

    def fail_after_rotated_secrets(path: Path) -> None:
        if path == destination and (destination / "demo-secrets.json").is_file():
            raise OSError("injected post-secret restore failure")
        original_demo_fsync(path)

    def retain_restore_tree(path: Path) -> None:
        if path == destination:
            raise OSError("injected restore cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(demo_module, "_fsync_directory", fail_after_rotated_secrets)
    monkeypatch.setattr(backup_module.shutil, "rmtree", retain_restore_tree)

    with pytest.raises(SystemExit):
        main(
            [
                "demo",
                "restore",
                "--data-dir",
                str(root),
                "--bundle",
                str(bundle),
                "--destination",
                str(destination),
            ]
        )

    error = capsys.readouterr().err
    assert "demo restore did not complete" in error
    assert "private restore tree could not be removed" in error
    assert "do not start that tree" in error
    assert "injected" not in error
    assert str(destination) not in error
    assert "Traceback" not in error
    assert credential_value(root, "mcp-token") not in error
    assert (destination / "demo-secrets.json").is_file()
    monkeypatch.setattr(backup_module.shutil, "rmtree", original_rmtree)
    original_rmtree(destination)


@pytest.mark.parametrize(
    "stop_signal",
    (signal.SIGINT, signal.SIGTERM),
    ids=("sigint", "sigterm"),
)
def test_demo_serve_stops_both_listeners_within_bound(
    tmp_path: Path,
    stop_signal: signal.Signals,
) -> None:
    root = new_demo(tmp_path)
    ports = _available_ports()
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and in-repo entry point
        [
            sys.executable,
            "-c",
            "from signet.app import main; main()",
            "demo",
            "serve",
            "--data-dir",
            str(root),
            "--mcp-port",
            str(ports[0]),
            "--web-port",
            str(ports[1]),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_listener(process, ports[1])
        assert live_smoke(mcp_port=ports[0], web_port=ports[1]) == {
            "status": "ok",
            "mode": "fake-only",
            "services": ["mcp", "web"],
        }
        contender_ports = _available_ports()
        contender = subprocess.run(  # noqa: S603 - fixed interpreter and entry point
            [
                sys.executable,
                "-c",
                "from signet.app import main; main()",
                "demo",
                "serve",
                "--data-dir",
                str(root),
                "--mcp-port",
                str(contender_ports[0]),
                "--web-port",
                str(contender_ports[1]),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert contender.returncode != 0
        assert "already being served" in contender.stderr
        assert "Traceback" not in contender.stderr
        assert stat.S_IMODE((root / ".serve.lock").stat().st_mode) == 0o600
        started_shutdown = time.monotonic()
        process.send_signal(stop_signal)
        stdout, stderr = process.communicate(timeout=DEMO_GRACEFUL_SHUTDOWN_SECONDS + 5)
        shutdown_elapsed = time.monotonic() - started_shutdown
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    combined = stdout + stderr
    assert process.returncode == 0
    assert "Signet fake-only demo MCP:" in stdout
    assert "Signet fake-only demo web:" in stdout
    assert "Traceback" not in combined
    assert "CancelledError" not in combined
    assert "ERROR" not in combined
    assert shutdown_elapsed < DEMO_GRACEFUL_SHUTDOWN_SECONDS + 3
    with pytest.raises(DemoError, match="live mcp health check failed"):
        live_smoke(mcp_port=ports[0], web_port=ports[1])
    for port in ports:
        with socket.socket() as candidate:
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            candidate.bind(("127.0.0.1", port))


def test_live_smoke_rejects_oversized_health_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OversizedResponse:
        status = 200

        @staticmethod
        def read(_maximum: int) -> bytes:
            return b"x" * 4097

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        @staticmethod
        def request(_method: str, _path: str) -> None:
            pass

        @staticmethod
        def getresponse() -> OversizedResponse:
            return OversizedResponse()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr("signet.demo.http.client.HTTPConnection", FakeConnection)
    with pytest.raises(DemoError, match="live mcp health check failed"):
        live_smoke(mcp_port=18789, web_port=18790)


def test_forced_request_cancellation_is_bounded_sanitized_error(tmp_path: Path) -> None:
    root = new_demo(tmp_path)
    token = credential_value(root, "mcp-token")
    ports = _available_ports()
    script = """
import asyncio
import signet.demo as demo

original_build_demo = demo.build_demo

def instrumented_build_demo(*args, **kwargs):
    assembly = original_build_demo(*args, **kwargs)

    async def stuck_request():
        await asyncio.Event().wait()

    assembly.web.add_api_route('/_test_stuck', stuck_request, methods=['GET'])
    return assembly

demo.build_demo = instrumented_build_demo
from signet.app import main
main()
"""
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and test script
        [
            sys.executable,
            "-c",
            script,
            "demo",
            "serve",
            "--data-dir",
            str(root),
            "--mcp-port",
            str(ports[0]),
            "--web-port",
            str(ports[1]),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    connection: socket.socket | None = None
    try:
        _wait_for_listener(process, ports[1])
        connection = socket.create_connection(("127.0.0.1", ports[1]), timeout=2)
        connection.sendall(
            b"GET /_test_stuck HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        time.sleep(0.2)
        started_shutdown = time.monotonic()
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=DEMO_GRACEFUL_SHUTDOWN_SECONDS + 5)
        shutdown_elapsed = time.monotonic() - started_shutdown
    finally:
        if connection is not None:
            connection.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    combined = stdout + stderr
    assert process.returncode == 2
    assert "demo shutdown exceeded its graceful safety deadline" in stderr
    assert token not in combined
    assert "Traceback" not in combined
    assert "CancelledError" not in combined
    assert shutdown_elapsed < DEMO_GRACEFUL_SHUTDOWN_SECONDS + 3


def _available_ports() -> list[int]:
    ports: list[int] = []
    while len(ports) < 2:
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            selected = int(candidate.getsockname()[1])
            if selected not in ports:
                ports.append(selected)
    return ports


def _wait_for_listener(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("demo listener did not become ready")
