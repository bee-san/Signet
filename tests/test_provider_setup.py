from __future__ import annotations

import asyncio
import hashlib
import io
import json
import stat
import subprocess
import tarfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

import signet.provider_setup as provider_setup_module
from signet.canonical import canonical_json, sha256_hex
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


def test_guided_fastmail_setup_persists_the_reviewed_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "fastmail"
    current = _config(root)
    root.mkdir(mode=0o700)
    current.policy_path.write_bytes(dump_policy(_base_policy()))
    current.policy_path.chmod(0o600)
    operations = ProviderSetupOperations(root)
    captured: dict[str, Any] = {}

    monkeypatch.setattr(operations.setup, "lifecycle_lock", lambda: nullcontext())
    monkeypatch.setattr(
        operations.setup.store,
        "load",
        lambda: SimpleNamespace(setup_id="setup_0123456789abcdef"),
    )
    monkeypatch.setattr(operations, "_require_installed_config", lambda: current)
    monkeypatch.setattr(
        operations,
        "_store_fastmail_token",
        lambda reference, token: captured.update(reference=reference, token=token),
    )
    monkeypatch.setattr(operations, "_capability_key", lambda _config: b"k" * 32)
    monkeypatch.setattr(
        provider_setup_module,
        "_fetch_fastmail_certificate",
        lambda _url: (b"reviewed certificate", "c" * 64),
    )

    async def probe(
        connector: DownstreamConfig,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        captured.update(probe_connector=connector, probe_arguments=kwargs)
        return FASTMAIL_TOOLS, {"protocolVersion": "2025-06-18"}

    monkeypatch.setattr(provider_setup_module, "_probe_fastmail", probe)

    def install_provider(**kwargs: Any) -> ProductionConfig:
        captured.update(install=kwargs)
        configured = kwargs["configured"]
        return configured.model_copy(
            update={
                "provider_rollout": configured.provider_rollout.model_copy(
                    update={"state": "enabled"}
                )
            }
        )

    monkeypatch.setattr(operations, "_install_provider", install_provider)

    result = operations.setup_fastmail(
        token="fastmail-token",
        sender="sender@example.test",
        recipient="recipient@example.test",
    )

    assert result == {
        "provider": "fastmail",
        "configured": True,
        "test_send": "succeeded",
        "enabled": True,
    }
    assert captured["reference"].endswith("/setup_0123456789abcdef-fastmail")
    assert captured["token"] == "fastmail-token"
    assert captured["install"]["alias"] == "fastmail"
    assert captured["install"]["tools"] == FASTMAIL_TOOLS
    connector = captured["install"]["configured"].connectors["fastmail"]
    assert connector.server_identity_digest == sha256_hex(
        canonical_json({"protocolVersion": "2025-06-18"})
    )
    assert connector.tls_server_certificate.read_bytes() == b"reviewed certificate"


@pytest.mark.parametrize(
    ("token", "sender", "recipient", "message"),
    (
        ("", "sender@example.test", "recipient@example.test", "token"),
        ("token\n", "sender@example.test", "recipient@example.test", "token"),
        ("token", "", "recipient@example.test", "sender"),
        ("token", "sender@example.test", "", "recipient"),
    ),
)
def test_guided_fastmail_setup_rejects_incomplete_inputs(
    tmp_path: Path,
    token: str,
    sender: str,
    recipient: str,
    message: str,
) -> None:
    with pytest.raises(SetupError, match=message):
        ProviderSetupOperations(tmp_path).setup_fastmail(
            token=token,
            sender=sender,
            recipient=recipient,
        )


def test_guided_whatsapp_setup_installs_pairs_and_tests_wacli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "whatsapp"
    current = _config(root)
    root.mkdir(mode=0o700)
    current.policy_path.write_bytes(dump_policy(_base_policy()))
    current.policy_path.chmod(0o600)
    operations = ProviderSetupOperations(root)
    captured: dict[str, Any] = {}

    monkeypatch.setattr(provider_setup_module.sys, "platform", "linux")
    monkeypatch.setattr(provider_setup_module.host_platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(operations.setup, "lifecycle_lock", lambda: nullcontext())
    monkeypatch.setattr(operations, "_require_installed_config", lambda: current)

    def install_wacli(path: Path) -> None:
        provider_setup_module._write_private_resource(path, b"\x7fELFreviewed-wacli")
        path.chmod(0o500)

    monkeypatch.setattr(operations, "_install_wacli", install_wacli)
    monkeypatch.setattr(
        operations,
        "_pair_wacli",
        lambda executable, **kwargs: captured.update(pair=(executable, kwargs)),
    )
    monkeypatch.setattr(
        operations,
        "_wacli_linked_jid",
        lambda executable, **kwargs: "447700900123@s.whatsapp.net",
    )

    class Wrapper:
        def __init__(self, config: Any) -> None:
            captured["wrapper_config"] = config

        async def send_text(self, arguments: dict[str, str]) -> dict[str, Any]:
            captured["send"] = arguments
            return {"sent": True, "message_id": "setup-test"}

    monkeypatch.setattr(provider_setup_module, "WacliWrapper", Wrapper)

    def install_provider(**kwargs: Any) -> ProductionConfig:
        captured.update(install=kwargs)
        configured = kwargs["configured"]
        return configured.model_copy(
            update={
                "provider_rollout": configured.provider_rollout.model_copy(
                    update={"state": "enabled"}
                )
            }
        )

    monkeypatch.setattr(operations, "_install_provider", install_provider)

    result = operations.setup_whatsapp(
        recipient="+447700900123",
        install_wacli=True,
    )

    assert result == {
        "provider": "whatsapp",
        "configured": True,
        "test_send": "succeeded",
        "enabled": True,
    }
    executable = operations._managed_wacli_path()
    assert executable.read_bytes() == b"\x7fELFreviewed-wacli"
    assert captured["send"] == {
        "to": "+447700900123",
        "message": "Signet setup test",
    }
    assert captured["wrapper_config"].expected_linked_jid == "447700900123@s.whatsapp.net"
    configured = captured["install"]["configured"]
    assert configured.connectors["whatsapp"].command == (str(executable),)
    assert configured.provider_rollout.wacli is not None
    assert configured.provider_rollout.wacli.account == "signet"
    account_config = root / "wacli-runtime" / "home" / ".local" / "state" / "wacli" / "config.yaml"
    assert yaml.safe_load(account_config.read_text(encoding="utf-8"))["default_account"] == "signet"


def test_provider_controls_validate_setup_and_switch_the_shared_rollout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "controls"
    connector = _fastmail_connector(root)
    config = _config(root, connectors={"fastmail": connector})
    _write_config(root, config)
    platform = RecordingPlatform()
    operations = ProviderSetupOperations(root, platform=platform)
    monkeypatch.setattr(operations.setup, "spec", lambda: SimpleNamespace(root=root))
    monkeypatch.setattr(operations.setup, "lifecycle_lock", lambda: nullcontext())
    monkeypatch.setattr(
        provider_setup_module,
        "create_production_assembly",
        lambda *_args, **_kwargs: object(),
    )

    enabled = operations._switch_rollout(config, enabled=True)
    assert enabled.provider_rollout.state == "enabled"
    assert enabled.capabilities.live_providers_ready
    assert platform.events == ["stop", "start", "verify"]

    switched: list[bool] = []
    monkeypatch.setattr(operations, "_require_installed_config", lambda: config)
    monkeypatch.setattr(
        operations,
        "_switch_rollout",
        lambda selected, *, enabled: (
            switched.append(enabled)
            or selected.model_copy(
                update={
                    "provider_rollout": selected.provider_rollout.model_copy(
                        update={"state": "enabled" if enabled else "disabled"}
                    )
                }
            )
        ),
    )
    assert operations.enable("fastmail") == {
        "provider": "fastmail",
        "rollout": "enabled",
        "affected": ["fastmail"],
    }
    assert operations.disable("fastmail") == {
        "provider": "fastmail",
        "rollout": "disabled",
        "affected": ["fastmail"],
    }
    assert switched == [True, False]

    with pytest.raises(SetupError, match="not configured"):
        operations._require_provider(config, "whatsapp")
    monkeypatch.setattr(provider_setup_module, "_whatsapp_supported", lambda: False)
    whatsapp = config.model_copy(
        update={"connectors": {**config.connectors, "whatsapp": connector}}
    )
    with pytest.raises(SetupError, match="unsupported"):
        operations._require_provider(whatsapp, "whatsapp")

    empty = _config(tmp_path / "empty")
    with pytest.raises(SetupError, match="no provider"):
        ProviderSetupOperations(tmp_path / "empty")._switch_rollout(empty, enabled=True)


def test_installed_config_and_disabled_rollout_preconditions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    operations = ProviderSetupOperations(tmp_path)
    monkeypatch.setattr(
        operations.setup.store,
        "load",
        lambda: SimpleNamespace(status="failed"),
    )
    with pytest.raises(SetupError, match="complete signet setup"):
        operations._require_installed_config()

    monkeypatch.setattr(
        operations.setup.store,
        "load",
        lambda: SimpleNamespace(status="completed"),
    )
    monkeypatch.setattr(
        provider_setup_module,
        "load_production_config",
        lambda _path: config,
    )
    assert operations._require_installed_config() is config
    assert operations._disable_for_setup(config) is config

    enabled = config.model_copy(
        update={"provider_rollout": config.provider_rollout.model_copy(update={"state": "enabled"})}
    )
    monkeypatch.setattr(
        operations,
        "_switch_rollout",
        lambda selected, *, enabled: config,
    )
    assert operations._disable_for_setup(enabled) is config


def test_fastmail_probe_validates_tools_sends_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _fastmail_connector(tmp_path)
    selected: list[Any] = []

    class Client:
        def __init__(
            self,
            tools: list[dict[str, Any]],
            *,
            result: dict[str, Any] | None = None,
            initialization: dict[str, Any] | None = None,
        ) -> None:
            self.tools = tools
            self.result = result or {"content": [{"type": "text", "text": "sent"}]}
            self.initialization_identity = initialization
            self.closed = False
            self.call: tuple[str, dict[str, Any]] | None = None

        async def start(self) -> None:
            return None

        async def discover_all_tools(self) -> list[dict[str, Any]]:
            return self.tools

        async def call_tool_raw(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            self.call = (name, arguments)
            return self.result

        async def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(
        provider_setup_module,
        "pinned_tls_http_connector",
        lambda *_args: object(),
    )
    monkeypatch.setattr(
        provider_setup_module,
        "DownstreamClient",
        lambda *_args, **_kwargs: selected[-1],
    )

    client = Client(
        FASTMAIL_TOOLS,
        initialization={"protocolVersion": "2025-06-18"},
    )
    selected.append(client)
    tools, initialization = asyncio.run(
        provider_setup_module._probe_fastmail(
            connector,
            certificate_pem=b"certificate",
            certificate_digest="c" * 64,
            sender="sender@example.test",
            recipient="recipient@example.test",
        )
    )
    assert tools == FASTMAIL_TOOLS
    assert initialization == {"protocolVersion": "2025-06-18"}
    assert client.call == (
        "send_email",
        {
            "from": "sender@example.test",
            "to": ["recipient@example.test"],
            "subject": "Signet setup test",
            "body": "Signet successfully connected to Fastmail.",
        },
    )
    assert client.closed

    invalid_cases = (
        (
            Client([FASTMAIL_TOOLS[0]], initialization={"protocolVersion": "test"}),
            "required tools",
        ),
        (
            Client(
                [
                    {
                        **FASTMAIL_TOOLS[0],
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    FASTMAIL_TOOLS[1],
                ],
                initialization={"protocolVersion": "test"},
            ),
            "unsupported",
        ),
        (
            Client(
                FASTMAIL_TOOLS,
                result={"isError": True},
                initialization={"protocolVersion": "test"},
            ),
            "test email failed",
        ),
        (Client(FASTMAIL_TOOLS), "identity is unavailable"),
    )
    for invalid, message in invalid_cases:
        selected.append(invalid)
        with pytest.raises(SetupError, match=message):
            asyncio.run(
                provider_setup_module._probe_fastmail(
                    connector,
                    certificate_pem=b"certificate",
                    certificate_digest="c" * 64,
                    sender="sender@example.test",
                    recipient="recipient@example.test",
                )
            )
        assert invalid.closed


def test_keychain_and_wacli_command_helpers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        provider_setup_module.keyring,
        "set_password",
        lambda service, account, token: stored.__setitem__((service, account), token),
    )
    monkeypatch.setattr(
        provider_setup_module.keyring,
        "get_password",
        lambda service, account: stored.get((service, account)),
    )
    ProviderSetupOperations._store_fastmail_token(
        "keychain://Signet-Setup/setup-fastmail",
        "token",
    )
    assert stored == {("Signet-Setup", "setup-fastmail"): "token"}

    monkeypatch.setattr(provider_setup_module.keyring, "get_password", lambda *_args: "changed")
    with pytest.raises(SetupError, match="could not be verified"):
        ProviderSetupOperations._store_fastmail_token(
            "keychain://Signet-Setup/setup-fastmail",
            "token",
        )
    monkeypatch.setattr(
        provider_setup_module.keyring,
        "set_password",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("unavailable")),
    )
    with pytest.raises(SetupError, match="could not be stored"):
        ProviderSetupOperations._store_fastmail_token(
            "keychain://Signet-Setup/setup-fastmail",
            "token",
        )

    executable = tmp_path / "wacli"
    home = tmp_path / "home"
    store = tmp_path / "store"
    responses = iter(
        (
            subprocess.CompletedProcess([], 0, '{"authenticated":false}', ""),
            subprocess.CompletedProcess([], 0, "", ""),
        )
    )
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return next(responses)

    operations = ProviderSetupOperations(tmp_path, command_runner=runner)
    operations._pair_wacli(executable, home=home, store=store)
    assert calls[0][-3:] == ["auth", "status", "--read-only"]
    assert calls[1][-3:] == ["auth", "--idle-exit", "30s"]

    operations.command_runner = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [], 0, '{"authenticated":true,"linked_jid":"447700900123@s.whatsapp.net"}', ""
    )
    operations._pair_wacli(executable, home=home, store=store)
    assert (
        operations._wacli_linked_jid(executable, home=home, store=store)
        == "447700900123@s.whatsapp.net"
    )

    operations.command_runner = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [], 0, "not-json", ""
    )
    assert operations._wacli_status(executable, home=home, store=store) == {}
    with pytest.raises(SetupError, match="not authenticated"):
        operations._wacli_linked_jid(executable, home=home, store=store)

    responses = iter(
        (
            subprocess.CompletedProcess([], 1, "", ""),
            subprocess.CompletedProcess([], 1, "", ""),
        )
    )
    operations.command_runner = lambda *_args, **_kwargs: next(responses)
    with pytest.raises(SetupError, match="pairing did not complete"):
        operations._pair_wacli(executable, home=home, store=store)


def test_bounded_download_archive_and_private_file_helpers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return self.payload

    monkeypatch.setattr(
        provider_setup_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(b"archive"),
    )
    assert (
        provider_setup_module._download_bounded(provider_setup_module.WACLI_ARCHIVE_URL)
        == b"archive"
    )
    with pytest.raises(SetupError, match="URL is not reviewed"):
        provider_setup_module._download_bounded("https://example.test/wacli")

    monkeypatch.setattr(provider_setup_module, "_DOWNLOAD_LIMIT", 4)
    with pytest.raises(SetupError, match="size limit"):
        provider_setup_module._download_bounded(provider_setup_module.WACLI_ARCHIVE_URL)
    monkeypatch.setattr(
        provider_setup_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    with pytest.raises(SetupError, match="download failed"):
        provider_setup_module._download_bounded(provider_setup_module.WACLI_ARCHIVE_URL)

    with pytest.raises(SetupError, match="archive is invalid"):
        _extract_wacli(b"not-a-tarball")
    empty_archive = io.BytesIO()
    with tarfile.open(fileobj=empty_archive, mode="w:gz"):
        pass
    with pytest.raises(SetupError, match="layout is invalid"):
        _extract_wacli(empty_archive.getvalue())

    home = tmp_path / "wacli-home"
    store = tmp_path / "wacli-store"
    provider_setup_module._write_wacli_account_config(home, store)
    assert provider_setup_module._wacli_environment(home) == {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }

    resource = tmp_path / "private" / "resource"
    provider_setup_module._write_private_resource(resource, b"one")
    provider_setup_module._write_private_resource(resource, b"two")
    assert resource.read_bytes() == b"two"
    assert provider_setup_module._file_sha256(resource) == hashlib.sha256(b"two").hexdigest()
    with pytest.raises(SetupError, match="could not be read"):
        provider_setup_module._file_sha256(tmp_path / "missing")
