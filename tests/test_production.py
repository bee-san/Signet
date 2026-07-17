from __future__ import annotations

import asyncio
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import signet.db as db_module
from signet.config import ProductionConfig
from signet.credential_broker import MemorySecretStore
from signet.db import Database
from signet.production import (
    ProductionAssemblyError,
    ProductionDisabledProviderClient,
    build_production_runtime,
    create_production_assembly,
    create_production_mcp_app_from_environment,
    create_production_web_app_from_environment,
    load_production_config,
)


def _production_payload(tmp_path: Path) -> dict[str, Any]:
    data = tmp_path / "data"
    policy_path = data / "policy.yaml"
    data.mkdir(mode=0o700)
    policy_path.write_text(
        """
version: 1
default_mode: deny
downstreams:
  mail:
    transport: http
    url: https://mail.example.test/mcp
    credential_ref: keychain://signet/mail
    tools: {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    os.chmod(policy_path, 0o600)
    return {
        "version": 1,
        "mode": "production",
        "owner_user_id": "user:owner",
        "public_origin": "https://signet.example.test",
        "rp_id": "signet.example.test",
        "allowed_hosts": ["signet.example.test", "127.0.0.1", "localhost"],
        "mcp_host": "127.0.0.1",
        "mcp_port": 8789,
        "web_host": "127.0.0.1",
        "web_port": 8790,
        "policy_path": str(policy_path),
        "storage": {
            "data_dir": str(data),
            "backup_dir": str(tmp_path / "backups"),
            "restore_dir": str(tmp_path / "restore"),
        },
        "secrets": {
            "session_secret_ref": "keychain://signet/session",
            "csrf_secret_ref": "keychain://signet/csrf",
            "capability_key_ref": "keychain://signet/capability",
            "payload_key_ref": "keychain://signet/payload",
            "totp_secret_ref": "keychain://signet/totp",
            "vapid_private_key_ref": None,
        },
        "capabilities": {
            "storage_ready": True,
            "secret_broker_ready": True,
            "mcp_ready": True,
            "web_ready": True,
            "workers_ready": True,
            "policy_ready": True,
            "live_providers_ready": False,
        },
        "connectors": {
            "mail": {
                "transport": "http",
                "credential_ref": "keychain://signet/mail",
                "credential_identity_digest": "a" * 64,
                "url": "https://mail.example.test/mcp",
            }
        },
    }


def _secret_store() -> MemorySecretStore:
    return MemorySecretStore(
        {
            ("signet", "session"): "session-secret-" * 3,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): "totp-secret-value",
            ("signet", "mail"): "mail-secret-value",
        }
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: payload.update(version=2), "version"),
        (
            lambda payload: payload.update(public_origin="http://signet.example.test"),
            "public_origin",
        ),
        (lambda payload: payload.update(mcp_host="0.0.0.0"), "loopback"),
        (lambda payload: payload.update(mcp_host="localhost"), "numeric loopback"),
        (lambda payload: payload.update(web_port=8789), "ports must differ"),
        (lambda payload: payload.update(allowed_hosts=["*"]), "allowed_hosts"),
        (
            lambda payload: payload["capabilities"].update(live_providers_ready=True),
            "live provider cutover",
        ),
        (
            lambda payload: payload["storage"].update(data_dir="relative"),
            "absolute lexical",
        ),
        (lambda payload: payload.update(rp_id="other.example.test"), "rp_id"),
        (
            lambda payload: payload["connectors"]["mail"].update(
                url="https://mail.example.test/mcp?token=forbidden"
            ),
            "HTTP connector",
        ),
        (
            lambda payload: payload["storage"].update(
                backup_dir=str(Path(payload["storage"]["data_dir"]) / "nested")
            ),
            "must not overlap",
        ),
    ],
)
def test_production_config_rejects_unsafe_or_ambiguous_values(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    payload = _production_payload(tmp_path)
    mutate(payload)

    with pytest.raises(ValidationError, match=message):
        ProductionConfig.model_validate(payload)


def test_production_config_rejects_mixed_connector_transport_fields(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    payload["connectors"]["mail"]["command"] = ["/usr/bin/false"]

    with pytest.raises(ValidationError, match="mixed"):
        ProductionConfig.model_validate(payload)


def test_build_production_runtime_stages_durable_provider_free_assembly(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))

    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)
    status = assembly.status()

    assert status.schema_version == 16
    assert status.setup_status == "staged"
    assert status.ready is False
    assert status.missing_prerequisites == ("live_providers_ready",)
    assert status.services["mcp"].host == "127.0.0.1"
    assert status.services["mcp"].port == 8789
    assert status.services["delivery"].state == "blocked"
    health = TestClient(
        assembly.web,
        base_url="https://signet.example.test",
    ).get("/healthz")
    assert health.status_code == 503
    assert health.json() == {"status": "unavailable", "service": "signet-web"}
    assert assembly.workers.running is False
    assert assembly.workers.healthy is True
    assert set(assembly.provider_clients) == {"mail"}
    assert isinstance(assembly.provider_clients["mail"], ProductionDisabledProviderClient)
    assert assembly.mcp.allowed_hosts == frozenset(
        {"127.0.0.1", "127.0.0.1:8789", "localhost", "localhost:8789"}
    )

    for path in (config.storage.data_dir, config.storage.backup_dir, config.storage.restore_dir):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert stat.S_IMODE(config.storage.database_path.stat().st_mode) == 0o600

    expected_counts = {
        "production_setup_state": 1,
        "production_users": 1,
        "production_user_factors": 2,
        "production_connectors": 1,
        "production_policies": 1,
        "production_secret_references": 5,
        "production_secret_generations": 5,
        "production_services": 7,
    }
    with assembly.database.read() as connection:
        for table, expected in expected_counts.items():
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == expected

    durable_bytes = b"".join(
        path.read_bytes()
        for path in config.storage.data_dir.iterdir()
        if path.is_file()
    )
    for secret in (
        b"capability-secret-",
        b"payload-secret-",
        b"session-secret-",
        b"csrf-secret-",
        b"totp-secret-value",
        b"mail-secret-value",
    ):
        assert secret not in durable_bytes

    second = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 124)
    with second.database.read() as connection:
        for table, expected in expected_counts.items():
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == expected


@pytest.mark.asyncio
async def test_production_maintenance_worker_has_explicit_lifecycle(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)

    await assembly.workers.run_once(now=124)
    stop = asyncio.Event()
    stop.set()
    await assembly.workers.serve(stop)

    assert assembly.workers.running is False
    assert assembly.workers.healthy is True


def test_build_fails_closed_before_database_creation_when_secret_is_missing(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    secrets = MemorySecretStore(
        {
            ("signet", "session"): "session-secret-" * 3,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): "totp-secret-value",
        }
    )

    with pytest.raises(ProductionAssemblyError, match="could not be resolved"):
        build_production_runtime(config, secret_store=secrets)

    assert not config.storage.database_path.exists()


def test_build_rejects_short_cryptographic_secret_before_database_creation(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    secrets = MemorySecretStore(
        {
            ("signet", "session"): "too-short",
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): "totp-secret-value",
            ("signet", "mail"): "mail-secret-value",
        }
    )

    with pytest.raises(ProductionAssemblyError, match="32 to 4096"):
        build_production_runtime(config, secret_store=secrets)

    assert not config.storage.database_path.exists()


def test_build_rejects_non_private_policy_before_database_creation(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    config.policy_path.chmod(0o644)

    with pytest.raises(ProductionAssemblyError, match="production policy"):
        build_production_runtime(config, secret_store=_secret_store())

    assert not config.storage.database_path.exists()


def test_build_rejects_policy_connector_drift_before_database_creation(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    payload["connectors"]["mail"]["url"] = "https://other.example.test/mcp"
    config = ProductionConfig.model_validate(payload)

    with pytest.raises(ProductionAssemblyError, match="differs from its policy binding"):
        build_production_runtime(config, secret_store=_secret_store())

    assert not config.storage.database_path.exists()


def test_private_config_loader_and_factory_use_versioned_json(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    config_path = tmp_path / "production.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(config_path, 0o600)

    loaded = load_production_config(config_path)
    assembly = create_production_assembly(config_path, secret_store=_secret_store())

    assert loaded.version == 1
    assert assembly.config == loaded

    os.chmod(config_path, 0o644)
    with pytest.raises(ProductionAssemblyError, match="mode-0600"):
        load_production_config(config_path)

    os.chmod(config_path, 0o600)
    symlink = tmp_path / "production-link.json"
    symlink.symlink_to(config_path)
    with pytest.raises(ProductionAssemblyError, match="opened safely"):
        load_production_config(symlink)


def test_environment_asgi_factories_use_only_the_private_config_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _production_payload(tmp_path)
    config_path = tmp_path / "production.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)
    monkeypatch.setenv("SIGNET_PRODUCTION_CONFIG", str(config_path))

    mcp_app = create_production_mcp_app_from_environment(secret_store=_secret_store())
    web_app = create_production_web_app_from_environment(secret_store=_secret_store())

    assert mcp_app is not None
    assert web_app is not None


def test_build_fails_closed_on_corrupt_durable_schema_cache(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    database = Database(config.storage.database_path)
    database.initialize()
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO schema_cache (
                downstream_alias,
                tool_name,
                schema_digest,
                tool_schema_json,
                discovered_at,
                review_state,
                reviewed_at,
                present
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("mail", "search", "a" * 64, b"not-json", 1, "unreviewed", None, 1),
        )

    with pytest.raises(ProductionAssemblyError, match="schema cache failed closed"):
        build_production_runtime(config, secret_store=_secret_store())

    with database.read() as connection:
        staged = connection.execute(
            "SELECT COUNT(*) AS count FROM production_setup_state"
        ).fetchone()
    assert staged is not None
    assert staged["count"] == 0


def test_schema_15_upgrades_to_production_schema_with_verified_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "data" / "signet.db")
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 15)
    database.initialize()
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 16)
    backups: list[int] = []

    database.initialize(pre_migration_backup=lambda _database, version: backups.append(version))

    assert backups == [15]
    with database.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 16
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'production_%'"
            ).fetchall()
        }
    assert tables == {
        "production_setup_state",
        "production_services",
        "production_users",
        "production_user_factors",
        "production_connectors",
        "production_policies",
        "production_secret_references",
        "production_secret_generations",
    }
