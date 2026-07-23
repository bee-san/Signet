from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import signet.provider_setup as provider_setup_module
from signet.config import DownstreamConfig, ProductionConfig
from signet.credential_broker import MemorySecretStore
from signet.db import Database
from signet.mcp_mirror import tool_schema_digest
from signet.policy import PolicyMode, dump_policy, parse_policy
from signet.provider_setup import (
    ProviderSetupOperations,
    _extract_wacli,
    _provider_policy,
    _store_reviewed_schemas,
    _whatsapp_tools,
)
from signet.setup_platform import render_production_config
from signet.setup_state import SetupError, SetupSpec

NOW = 1_800_000_000

FASTMAIL_TOOLS: list[dict[str, Any]] = [
    {
        "name": "send_email",
        "description": "Send an email.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["from", "to", "subject", "body"],
            "properties": {
                "from": {"type": "string"},
                "to": {"type": "array", "items": {"type": "string"}},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
        },
        "outputSchema": {"type": "object"},
    },
    {
        "name": "search_email",
        "description": "Search email.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
        },
        "outputSchema": {"type": "object"},
    },
]


class RecordingPlatform:
    def __init__(self) -> None:
        self.events: list[str] = []

    def manage_services(self, spec: object, action: str) -> None:
        del spec
        self.events.append(action)

    def verify_service_health(self, spec: object) -> None:
        del spec
        self.events.append("verify")


def _base_policy() -> Any:
    return parse_policy(
        {
            "version": 1,
            "default_mode": "deny",
            "downstreams": {},
        }
    )


def _fastmail_connector(root: Path, *, identity: str = "a" * 64) -> DownstreamConfig:
    return DownstreamConfig(
        transport="http",
        credential_ref="keychain://Signet-Setup/setup-fastmail",
        credential_identity_digest=identity,
        server_identity_digest="b" * 64,
        url="https://api.fastmail.com/mcp",
        tls_server_certificate=root / "fastmail.pem",
        tls_server_certificate_sha256="c" * 64,
    )


def _config(
    root: Path,
    *,
    connectors: dict[str, DownstreamConfig] | None = None,
) -> ProductionConfig:
    selected = SetupSpec(
        root=root,
        public_origin="https://signet.example.test",
        owner_user_id="user:owner",
        hermes_profiles=("personal",),
        executable=Path("/opt/signet/bin/signet"),
    )
    document = render_production_config(
        selected,
        setup_id="setup_0123456789abcdef",
    )
    document["connectors"] = {
        alias: connector.model_dump(mode="json") for alias, connector in (connectors or {}).items()
    }
    return ProductionConfig.model_validate(document)


def _write_config(root: Path, config: ProductionConfig) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / "production.json"
    path.write_text(
        json.dumps(
            config.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _wacli_archive(payload: bytes = b"\x7fELFtest-wacli") -> bytes:
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w:gz") as archive:
        member = tarfile.TarInfo("release/wacli")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return target.getvalue()


def test_generated_fastmail_policy_is_idempotent_and_schemas_are_reviewed(
    tmp_path: Path,
) -> None:
    connector = _fastmail_connector(tmp_path)
    generated = _provider_policy(
        _base_policy(),
        alias="fastmail",
        connector=connector,
        tools=FASTMAIL_TOOLS,
        account="account:fastmail",
    )

    assert generated.version == 2
    assert generated.resolve("fastmail", "send_email") is PolicyMode.APPROVAL
    assert generated.resolve("fastmail", "search_email") is PolicyMode.PASSTHROUGH
    assert generated.configured("fastmail", "send_email").schema_digest == (
        tool_schema_digest(FASTMAIL_TOOLS[0])
    )
    assert (
        _provider_policy(
            generated,
            alias="fastmail",
            connector=connector,
            tools=FASTMAIL_TOOLS,
            account="account:fastmail",
        )
        is generated
    )

    database = Database(tmp_path / "schemas.sqlite3")
    database.initialize()
    _store_reviewed_schemas(
        database,
        generated,
        alias="fastmail",
        tools=FASTMAIL_TOOLS,
        now=NOW,
    )
    with database.read() as connection:
        rows = connection.execute(
            """
            SELECT tool_name, review_state, reviewed_at, present
            FROM schema_cache ORDER BY tool_name
            """
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("search_email", "approved", NOW, 1),
        ("send_email", "approved", NOW, 1),
    ]


def test_changed_provider_schema_creates_one_new_policy_version(tmp_path: Path) -> None:
    connector = _fastmail_connector(tmp_path)
    current = _provider_policy(
        _base_policy(),
        alias="fastmail",
        connector=connector,
        tools=FASTMAIL_TOOLS,
        account="account:fastmail",
    )
    changed = [dict(tool) for tool in FASTMAIL_TOOLS]
    changed[1] = {
        **changed[1],
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
    }

    updated = _provider_policy(
        current,
        alias="fastmail",
        connector=connector,
        tools=changed,
        account="account:fastmail",
    )

    assert updated.version == current.version + 1
    assert updated.configured("fastmail", "search_email").schema_digest == (
        tool_schema_digest(changed[1])
    )


def test_generated_whatsapp_policy_and_schemas_enable_both_send_tools(
    tmp_path: Path,
) -> None:
    tools = _whatsapp_tools()
    connector = DownstreamConfig(
        transport="stdio",
        credential_ref="keychain://Signet-Setup/setup-capability",
        credential_identity_digest="a" * 64,
        command=(str(tmp_path / "tools" / "wacli"),),
        working_directory=tmp_path / "runtime",
        executable_sha256="b" * 64,
        execution_snapshot_root=tmp_path / "snapshots",
        output_limit_bytes=256 * 1024,
    )
    generated = _provider_policy(
        _base_policy(),
        alias="whatsapp",
        connector=connector,
        tools=tools,
        account="account:signet",
    )

    assert generated.version == 2
    for tool in tools:
        configured = generated.configured("whatsapp", str(tool["name"]))
        assert configured is not None
        assert configured.mode is PolicyMode.APPROVAL
        assert configured.adapter == f"whatsapp.{tool['name']}"
        assert configured.communication_send
        assert configured.schema_digest == tool_schema_digest(tool)

    database = Database(tmp_path / "whatsapp-schemas.sqlite3")
    database.initialize()
    _store_reviewed_schemas(
        database,
        generated,
        alias="whatsapp",
        tools=tools,
        now=NOW,
    )
    with database.read() as connection:
        rows = connection.execute(
            """
            SELECT tool_name, review_state, present
            FROM schema_cache ORDER BY tool_name
            """
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("send_file", "approved", 1),
        ("send_text", "approved", 1),
    ]


def test_provider_status_reports_support_configuration_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _fastmail_connector(tmp_path)
    config = _config(tmp_path, connectors={"fastmail": connector})
    store = MemorySecretStore(
        {
            ("Signet-Setup", "setup-fastmail"): "fastmail-token",
        }
    )
    operations = ProviderSetupOperations(tmp_path)
    monkeypatch.setattr(operations, "_require_installed_config", lambda: config)
    monkeypatch.setattr(provider_setup_module, "KeychainSecretStore", lambda: store)
    monkeypatch.setattr(provider_setup_module.sys, "platform", "darwin")
    monkeypatch.setattr(provider_setup_module.host_platform, "machine", lambda: "arm64")

    status = operations.status()

    assert status == {
        "rollout": "disabled",
        "providers": {
            "fastmail": {
                "supported": True,
                "configured": True,
                "credential_ready": True,
                "enabled": False,
            },
            "whatsapp": {
                "supported": False,
                "configured": False,
                "credential_ready": False,
                "enabled": False,
            },
        },
    }


def test_whatsapp_setup_is_rejected_outside_linux_x86_64(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provider_setup_module.sys, "platform", "darwin")
    monkeypatch.setattr(provider_setup_module.host_platform, "machine", lambda: "arm64")

    with pytest.raises(SetupError, match="unsupported"):
        ProviderSetupOperations(tmp_path).setup_whatsapp(
            recipient="+447700900123",
            install_wacli=False,
        )


def test_verified_wacli_archive_is_extracted_and_installed_privately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _wacli_archive()
    executable = tmp_path / "tools" / "wacli"
    monkeypatch.setattr(provider_setup_module, "_download_bounded", lambda _url: archive)
    monkeypatch.setattr(
        provider_setup_module,
        "WACLI_ARCHIVE_SHA256",
        hashlib.sha256(archive).hexdigest(),
    )

    ProviderSetupOperations(tmp_path)._install_wacli(executable)

    assert executable.read_bytes() == b"\x7fELFtest-wacli"
    assert stat.S_IMODE(executable.stat().st_mode) == 0o500

    monkeypatch.setattr(provider_setup_module, "WACLI_ARCHIVE_SHA256", "0" * 64)
    with pytest.raises(SetupError, match="digest"):
        ProviderSetupOperations(tmp_path)._install_wacli(tmp_path / "other-wacli")


def test_wacli_archive_rejects_non_linux_payload() -> None:
    with pytest.raises(SetupError, match="expected Linux executable"):
        _extract_wacli(_wacli_archive(b"not-elf"))


def test_schema_failure_after_policy_commit_keeps_retryable_disabled_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    current = _config(root)
    connector = _fastmail_connector(root)
    configured = _config(root, connectors={"fastmail": connector})
    policy_path = current.policy_path
    root.mkdir(mode=0o700)
    policy_path.write_bytes(dump_policy(_base_policy()))
    policy_path.chmod(0o600)
    _write_config(root, current)
    platform = RecordingPlatform()
    operations = ProviderSetupOperations(root, platform=platform)
    monkeypatch.setattr(
        operations.setup,
        "spec",
        lambda: SimpleNamespace(root=root),
    )
    policy = _provider_policy(
        _base_policy(),
        alias="fastmail",
        connector=connector,
        tools=FASTMAIL_TOOLS,
        account="account:fastmail",
    )

    class State:
        def __init__(self) -> None:
            self.transitions: list[tuple[ProductionConfig, ProductionConfig]] = []

        def configure_provider(
            self,
            *,
            current_config: ProductionConfig,
            next_config: ProductionConfig,
            alias: str,
            now: int,
        ) -> None:
            del alias, now
            self.transitions.append((current_config, next_config))

    class Boundary:
        def __init__(self) -> None:
            self.ready = True
            self.current = _base_policy()

        def install_provider_setup(self, snapshot: Any, *, alias: str, now: int) -> None:
            del alias, now
            self.current = snapshot

        def recover(self, *, now: int) -> None:
            del now
            self.ready = True

    state = State()
    boundary = Boundary()

    class Assembly:
        def __init__(self) -> None:
            self.database = object()
            self.policy_promotions = boundary
            self.state = state

        @property
        def policy(self) -> Any:
            return boundary.current

    monkeypatch.setattr(
        provider_setup_module,
        "create_production_assembly",
        lambda *_args, **_kwargs: Assembly(),
    )

    def fail_schema_capture(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("schema capture failed")

    monkeypatch.setattr(
        provider_setup_module,
        "_store_reviewed_schemas",
        fail_schema_capture,
    )

    with pytest.raises(RuntimeError, match="schema capture failed"):
        operations._install_provider(
            current=current,
            configured=configured,
            policy=policy,
            alias="fastmail",
            tools=FASTMAIL_TOOLS,
        )

    persisted = ProductionConfig.model_validate_json(
        (root / "production.json").read_text(encoding="utf-8")
    )
    assert persisted == configured
    assert state.transitions == [(current, configured)]
    assert platform.events == ["stop", "start", "verify"]


def test_failed_live_rollout_restores_disabled_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    config = _config(
        root,
        connectors={"fastmail": _fastmail_connector(root)},
    )
    _write_config(root, config)
    platform = RecordingPlatform()
    operations = ProviderSetupOperations(root, platform=platform)
    monkeypatch.setattr(
        operations.setup,
        "spec",
        lambda: SimpleNamespace(root=root),
    )
    attempts = 0

    def assemble(*_args: Any, **_kwargs: Any) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("startup failed")
        return object()

    monkeypatch.setattr(provider_setup_module, "create_production_assembly", assemble)

    with pytest.raises(SetupError, match="failed and was restored"):
        operations._switch_rollout(config, enabled=True)

    persisted = ProductionConfig.model_validate_json(
        (root / "production.json").read_text(encoding="utf-8")
    )
    assert persisted == config
    assert attempts == 2
    assert platform.events == ["stop", "stop", "start", "verify"]
