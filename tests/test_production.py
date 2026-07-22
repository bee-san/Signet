from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import time
import traceback
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pyotp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import ValidationError

import signet.db as db_module
import signet.production as production_module
import signet.production_connectors as production_connectors_module
from signet.adapters.whatsapp import WhatsAppAdapter
from signet.app import main as run_cli
from signet.auth import SessionManager, SQLiteSessionRepository
from signet.browser_auth import BootstrapService
from signet.canonical import canonical_json
from signet.config import ProductionConfig, production_health_proof, production_instance_identity
from signet.credential_broker import MemorySecretStore, Secret, SecretReference
from signet.db import Database
from signet.downstream import DownstreamClient
from signet.policy import parse_policy_yaml
from signet.production import (
    ProductionAssemblyError,
    ProductionDisabledProviderClient,
    build_production_runtime,
    create_production_assembly,
    create_production_mcp_app_from_environment,
    create_production_mcp_runtime,
    create_production_web_app,
    create_production_web_app_from_environment,
    load_production_config,
)
from signet.production_connectors import (
    CredentialBoundClient,
    ProductionConnectorError,
    ProviderSessionPool,
    provider_execution_identity_digest,
)
from signet.production_state import ProductionStateError, production_config_digest
from signet.totp_enrollment import (
    InvalidTotpEnrollment,
    IssuedTotpEnrollment,
    TotpEnrollmentService,
)
from signet.wacli_wrapper import WacliConfig
from tests.migration_helpers import verified_backup_callback


def _write_reviewed_server_certificate(tmp_path: Path) -> tuple[Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "fastmail-server-certificate.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    return path, digest


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


def _secret_store(
    *,
    session_secret: str = "session-secret-" * 3,
    totp_secret: str = "totp-secret-value",
) -> MemorySecretStore:
    return MemorySecretStore(
        {
            ("signet", "session"): session_secret,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): totp_secret,
            ("signet", "mail"): "mail-secret-value",
        }
    )


def test_production_config_digest_migrates_only_the_empty_caller_principal_predecessor(
    tmp_path: Path,
) -> None:
    payload = _production_payload(tmp_path)
    without_principal = ProductionConfig.model_validate(payload)
    predecessor_document = without_principal.model_dump(mode="json")
    predecessor_document.pop("caller_principals")
    predecessor_digest = hashlib.sha256(canonical_json(predecessor_document)).hexdigest()
    expected_digest = production_config_digest(without_principal)
    assembly = build_production_runtime(
        without_principal,
        secret_store=_secret_store(),
        components=frozenset(),
    )
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE production_setup_state SET config_digest = ? WHERE state_id = 1",
            (predecessor_digest,),
        )
        connection.execute(
            "UPDATE production_services SET config_digest = ?",
            (predecessor_digest,),
        )

    migrated = build_production_runtime(
        without_principal,
        secret_store=_secret_store(),
        components=frozenset(),
    )
    with migrated.database.read() as connection:
        assert (
            connection.execute(
                "SELECT config_digest FROM production_setup_state WHERE state_id = 1"
            ).fetchone()["config_digest"]
            == expected_digest
        )

    payload["caller_principals"] = [{"namespace": "profile:work", "allowed_aliases": ["approvals"]}]
    with_principal = ProductionConfig.model_validate(payload)
    assert expected_digest != production_config_digest(with_principal)
    with migrated.database.transaction() as connection:
        connection.execute(
            "UPDATE production_setup_state SET config_digest = ? WHERE state_id = 1",
            (predecessor_digest,),
        )
        connection.execute(
            "UPDATE production_services SET config_digest = ?",
            (predecessor_digest,),
        )
    with pytest.raises(ProductionAssemblyError, match="differs from durable state"):
        build_production_runtime(
            with_principal,
            secret_store=_secret_store(),
            components=frozenset(),
        )


def test_production_config_digest_composes_empty_callers_with_legacy_predecessor(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(
        config,
        secret_store=_secret_store(),
        components=frozenset(),
    )
    predecessor = config.model_dump(mode="json")
    predecessor.pop("caller_principals")
    predecessor["storage"].pop("attachment_staging_dir")
    predecessor["storage"].pop("attachment_source_roots")
    predecessor["secrets"].pop("attachment_key_ref")
    predecessor["capabilities"]["live_providers_ready"] = False
    predecessor.pop("provider_rollout")
    for connector in predecessor["connectors"].values():
        connector.pop("server_identity_digest")
        connector.pop("tls_server_certificate")
        connector.pop("tls_server_certificate_sha256")
    predecessor_digest = hashlib.sha256(canonical_json(predecessor)).hexdigest()
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE production_setup_state SET config_digest = ? WHERE state_id = 1",
            (predecessor_digest,),
        )
        connection.execute(
            "UPDATE production_services SET config_digest = ?",
            (predecessor_digest,),
        )

    migrated = build_production_runtime(
        config,
        secret_store=_secret_store(),
        components=frozenset(),
    )

    with migrated.database.read() as connection:
        assert {
            row["config_digest"]
            for row in connection.execute(
                "SELECT config_digest FROM production_services"
            ).fetchall()
        } == {production_config_digest(config)}


def test_config_digest_migration_never_erases_a_divergent_service_digest(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(
        config,
        secret_store=_secret_store(),
        components=frozenset(),
    )
    predecessor = config.model_dump(mode="json")
    predecessor.pop("caller_principals")
    predecessor_digest = hashlib.sha256(canonical_json(predecessor)).hexdigest()
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE production_setup_state SET config_digest = ? WHERE state_id = 1",
            (predecessor_digest,),
        )
        connection.execute(
            "UPDATE production_services SET config_digest = ?",
            ("0" * 64,),
        )

    with pytest.raises(ProductionAssemblyError, match="service config has diverged"):
        build_production_runtime(
            config,
            secret_store=_secret_store(),
            components=frozenset(),
        )


def _provider_credential_identity(
    *,
    reference: str,
    secret: str,
    identity_key: str = "capability-secret-" * 3,
) -> str:
    return hmac.new(
        identity_key.encode("utf-8"),
        b"provider_credential\x00" + reference.encode("utf-8") + b"\x00" + secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class _RecordingSecretStore:
    def __init__(self) -> None:
        self._delegate = _secret_store()
        self.accounts: list[str] = []

    def get(self, reference: SecretReference) -> Secret:
        self.accounts.append(reference.account)
        return self._delegate.get(reference)


class _ProvisioningSecretStore:
    def __init__(self) -> None:
        self.values = {
            ("signet", "session"): "session-secret-" * 3,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): "JBSWY3DPEHPK3PXP",
            ("signet", "mail"): "mail-secret-value",
        }

    def get(self, reference: SecretReference) -> Secret:
        return MemorySecretStore(self.values).get(reference)


class _FixedTotpProvisioner:
    def __init__(self, store: _ProvisioningSecretStore) -> None:
        self.store = store

    def create(self, factor_id: str) -> str:
        self.store.values[("Signet", factor_id)] = "JBSWY3DPEHPK3PXP"
        return f"keychain://Signet/{factor_id}"

    def delete(self, secret_reference: str) -> None:
        reference = SecretReference.parse(secret_reference)
        self.store.values.pop((reference.service, reference.account), None)


class _FailOnCallProvider:
    calls: list[tuple[str, str]] = []

    def __init__(self, alias: str, *, credential_identity_digest: str) -> None:
        self.alias = alias
        self.credential_identity_digest = credential_identity_digest

    async def call_tool(self, tool_name: str, arguments: object) -> object:
        del arguments
        type(self).calls.append((self.alias, tool_name))
        raise AssertionError("browser authentication reached a production provider")

    async def call_tool_raw(self, tool_name: str, arguments: object) -> object:
        return await self.call_tool(tool_name, arguments)


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


@pytest.mark.parametrize(
    "origin",
    (
        "https://signet.example.test:bad",
        "https://signet.example.test:99999",
        "https://Signet.example.test",
    ),
)
def test_noncanonical_public_origin_is_rejected_before_database_initialization(
    tmp_path: Path,
    origin: str,
) -> None:
    config_path = tmp_path / "production.json"
    payload = _production_payload(tmp_path)
    payload["public_origin"] = origin
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)

    with pytest.raises(ProductionAssemblyError, match="configuration is invalid"):
        create_production_assembly(config_path, secret_store=_secret_store())

    assert not (Path(payload["storage"]["data_dir"]) / "signet.db").exists()


@pytest.mark.parametrize(
    "allowed_hosts",
    (
        ["signet.example.test", "bad host"],
        ["signet.example.test", "host:8790"],
        ["signet.example.test", "fe80::1%*"],
        ["signet.example.test", "localhost", "LOCALHOST"],
    ),
)
def test_invalid_allowed_hosts_are_rejected_before_database_initialization(
    tmp_path: Path,
    allowed_hosts: list[str],
) -> None:
    config_path = tmp_path / "production.json"
    payload = _production_payload(tmp_path)
    payload["allowed_hosts"] = allowed_hosts
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)

    with pytest.raises(ProductionAssemblyError, match="configuration is invalid"):
        create_production_assembly(config_path, secret_store=_secret_store())

    assert not (Path(payload["storage"]["data_dir"]) / "signet.db").exists()


def test_production_config_rejects_mixed_connector_transport_fields(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    payload["connectors"]["mail"]["command"] = ["/usr/bin/false"]

    with pytest.raises(ValidationError, match="mixed"):
        ProductionConfig.model_validate(payload)


def test_live_provider_rollout_is_explicit_and_disabled_by_default(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))

    assert config.provider_rollout.state == "disabled"
    assert config.safe_dump()["provider_rollout"] == {
        "state": "disabled",
        "wacli": None,
    }


def test_disabled_production_connector_example_matches_strict_config_schema() -> None:
    example = Path("deploy/config/production.example.json").read_text(encoding="utf-8")

    config = ProductionConfig.model_validate_json(example)

    assert config.provider_rollout.state == "disabled"
    assert config.capabilities.live_providers_ready is False


def test_live_provider_rollout_requires_attachment_and_readiness_records(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    payload["provider_rollout"] = {"state": "enabled"}

    with pytest.raises(ValidationError, match="live provider readiness"):
        ProductionConfig.model_validate(payload)

    payload["capabilities"]["live_providers_ready"] = True
    with pytest.raises(ValidationError, match="attachment staging"):
        ProductionConfig.model_validate(payload)


def test_live_fastmail_rollout_builds_hardened_client_adapter_and_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _production_payload(tmp_path)
    source_root = tmp_path / "attachment-imports"
    source_root.mkdir(mode=0o700)
    Path(payload["policy_path"]).write_text(
        """
version: 1
default_mode: deny
downstreams:
  fastmail:
    transport: http
    url: https://mail.example.test/mcp
    credential_ref: keychain://signet/mail
    account_ref: account:fastmail-primary
    tools:
      send_email:
        mode: approval
        adapter: fastmail.send
        communication_send: true
        account_ref: account:fastmail-primary
        schema_digest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      search_email:
        mode: passthrough
        reviewed_read_only: true
        account_ref: account:fastmail-primary
        schema_digest: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
""".strip()
        + "\n",
        encoding="utf-8",
    )
    server_certificate, server_certificate_sha256 = _write_reviewed_server_certificate(tmp_path)
    identity_digest = _provider_credential_identity(
        reference="keychain://signet/mail",
        secret="mail-secret-value",
    )
    payload["connectors"] = {
        "fastmail": {
            "transport": "http",
            "credential_ref": "keychain://signet/mail",
            "credential_identity_digest": identity_digest,
            "server_identity_digest": "f" * 64,
            "url": "https://mail.example.test/mcp",
            "tls_server_certificate": str(server_certificate),
            "tls_server_certificate_sha256": server_certificate_sha256,
        }
    }
    payload["storage"].update(
        attachment_staging_dir=str(tmp_path / "attachment-staging"),
        attachment_source_roots=[str(source_root)],
    )
    payload["secrets"]["attachment_key_ref"] = "keychain://signet/attachment"
    payload["capabilities"]["live_providers_ready"] = True
    payload["provider_rollout"] = {"state": "enabled"}
    config = ProductionConfig.model_validate(payload)
    secret_store = MemorySecretStore(
        {
            ("signet", "session"): "session-secret-" * 3,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): "totp-secret-value",
            ("signet", "mail"): "mail-secret-value",
            ("signet", "attachment"): "attachment-key-material-" * 3,
        }
    )
    captured_server_identities: dict[str, str] = {}
    captured_reviewer_staging: list[object] = []
    captured_reviewer_adapters: list[dict[tuple[str, str], object]] = []
    original_reviewer = production_module.EncryptedPayloadReviewer

    def capturing_reviewer(*args: Any, **kwargs: Any):
        captured_reviewer_adapters.append(dict(cast(Mapping[tuple[str, str], object], args[2])))
        captured_reviewer_staging.append(kwargs.get("staging"))
        return original_reviewer(*args, **kwargs)

    class CapturingProviderSessionPool(production_connectors_module.ProviderSessionPool):
        def __init__(
            self,
            clients: Mapping[str, object],
            *,
            expected_schema_digests: Mapping[str, Mapping[str, str]] | None = None,
            expected_server_identity_digests: Mapping[str, str] | None = None,
        ) -> None:
            captured_server_identities.update(expected_server_identity_digests or {})
            super().__init__(
                clients,
                expected_schema_digests=expected_schema_digests,
                expected_server_identity_digests=expected_server_identity_digests,
            )

    monkeypatch.setattr(
        production_connectors_module,
        "ProviderSessionPool",
        CapturingProviderSessionPool,
    )
    monkeypatch.setattr(production_module, "EncryptedPayloadReviewer", capturing_reviewer)

    disabled_config = config.model_copy(
        update={
            "capabilities": config.capabilities.model_copy(update={"live_providers_ready": False}),
            "provider_rollout": config.provider_rollout.model_copy(update={"state": "disabled"}),
        }
    )
    staged = build_production_runtime(disabled_config, secret_store=secret_store)
    assert staged.provider_sessions is None
    assert staged.adapters == {}
    assert tuple(captured_reviewer_adapters[-1]) == (
        ("fastmail", "send_email"),
        ("gateway", "request_tool_access"),
    )
    disabled_fastmail = captured_reviewer_adapters[-1][("fastmail", "send_email")]
    assert cast(Any, disabled_fastmail).reviewed_dispatch_enabled is False
    assert staged.retention is not None

    mismatched_pin = config.connectors["fastmail"].model_copy(
        update={"tls_server_certificate_sha256": "0" * 64}
    )
    mismatched_pin_config = config.model_copy(update={"connectors": {"fastmail": mismatched_pin}})
    with pytest.raises(ProductionAssemblyError, match="TLS server certificate"):
        build_production_runtime(mismatched_pin_config, secret_store=secret_store)

    assembly = build_production_runtime(config, secret_store=secret_store)

    assert isinstance(assembly.provider_clients["fastmail"], DownstreamClient)
    assert assembly.provider_clients["fastmail"].credential_identity_digest == (
        provider_execution_identity_digest(config, "fastmail")
    )
    assert assembly.provider_clients["fastmail"].credential_identity_digest != identity_digest
    assert tuple(assembly.adapters) == (("fastmail", "send_email"),)
    assert assembly.adapters[("fastmail", "send_email")].reviewed_dispatch_enabled is True
    assert assembly.staging is not None
    assert captured_reviewer_staging[-1] is assembly.staging
    assert assembly.retention is not None
    assert assembly.provider_sessions is not None
    assert captured_server_identities == {"fastmail": "f" * 64}

    transport_calls: list[str] = []

    @asynccontextmanager
    async def forbidden_transport(*_args: Any, **_kwargs: Any):
        transport_calls.append("opened")
        yield object(), object(), lambda: None

    live_client = cast(DownstreamClient, assembly.provider_clients["fastmail"])
    monkeypatch.setattr(live_client, "_http_connector", forbidden_transport)
    secret_store._values[("signet", "mail")] = "rotated-after-assembly"

    async def start_rotated_provider() -> None:
        assert assembly.provider_sessions is not None
        async with assembly.provider_sessions.run():
            pytest.fail("rotated provider credential must not become ready")

    with pytest.raises(ProductionConnectorError, match="startup failed"):
        asyncio.run(start_rotated_provider())
    assert transport_calls == []
    secret_store._values[("signet", "mail")] = "mail-secret-value"

    rotated_secret_store = MemorySecretStore(
        {
            ("signet", "session"): "session-secret-" * 3,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): "totp-secret-value",
            ("signet", "mail"): "rotated-mail-secret-value",
            ("signet", "attachment"): "attachment-key-material-" * 3,
        }
    )
    with pytest.raises(ProductionAssemblyError, match="credential identity"):
        build_production_runtime(config, secret_store=rotated_secret_store)

    active_now = int(time.time())
    assembly.state.record_provider_state("active", ready=True, now=active_now)
    restarted = build_production_runtime(
        config,
        secret_store=secret_store,
        clock=lambda: active_now,
    )
    assert restarted.state.status().live_providers_ready is True
    assert restarted.status().live_providers_ready is False
    assert "live_providers_ready" in restarted.status().missing_prerequisites
    with assembly.database.read() as connection:
        assert (
            connection.execute(
                "SELECT state FROM production_connectors WHERE connector_alias = 'fastmail'"
            ).fetchone()["state"]
            == "active"
        )

    lifecycle_now = int(time.time())
    recovered_at: list[int] = []

    class DelayedProviderContext:
        async def __aenter__(self) -> None:
            nonlocal lifecycle_now
            lifecycle_now += 10

        async def __aexit__(self, *_: Any) -> None:
            return None

    def observe_recovery(*, now: int) -> None:
        recovered_at.append(now)

    monkeypatch.setattr(assembly.workers, "_clock", lambda: lifecycle_now)
    monkeypatch.setattr(assembly.provider_sessions, "run", DelayedProviderContext)
    monkeypatch.setattr(assembly.workers._approvals, "recover_startup", observe_recovery)
    stopped = asyncio.Event()
    stopped.set()
    asyncio.run(assembly.workers.serve(stopped))
    assert recovered_at == [lifecycle_now]

    dispatched: list[str] = []
    reconciled: list[str] = []
    retained: list[bool] = []
    stop = asyncio.Event()

    async def stop_after_first_dispatch(request_id: str, **_: Any) -> None:
        dispatched.append(request_id)
        stop.set()

    async def stop_after_first_reconciliation(request_id: str, **_: Any) -> None:
        reconciled.append(request_id)
        stop.set()

    def observe_retention(**_: Any) -> None:
        retained.append(True)

    monkeypatch.setattr(
        assembly.workers,
        "_due_delivery_request_ids",
        lambda _now: ("request:first", "request:second"),
    )
    monkeypatch.setattr(assembly.workers._delivery, "dispatch", stop_after_first_dispatch)
    monkeypatch.setattr(
        assembly.workers._reconciliation,
        "due_request_ids",
        lambda **_: ("reconcile:first", "reconcile:second"),
    )
    monkeypatch.setattr(
        assembly.workers._reconciliation,
        "reconcile_once",
        stop_after_first_reconciliation,
    )
    monkeypatch.setattr(assembly.retention, "run_due", observe_retention)
    asyncio.run(assembly.workers.run_once(now=int(time.time()), stop=stop))
    assert dispatched == ["request:first"]
    assert reconciled == []
    assert retained == []

    stop.clear()
    monkeypatch.setattr(
        assembly.workers,
        "_due_delivery_request_ids",
        lambda _now: (),
    )
    asyncio.run(assembly.workers.run_once(now=int(time.time()), stop=stop))
    assert reconciled == ["reconcile:first"]
    assert retained == []

    stop.clear()
    monkeypatch.setattr(
        assembly.workers._reconciliation,
        "due_request_ids",
        lambda **_: (),
    )
    asyncio.run(assembly.workers.run_once(now=int(time.time()), stop=stop))
    assert retained == [True]

    rolled_back = build_production_runtime(
        disabled_config,
        secret_store=secret_store,
        clock=lambda: lifecycle_now,
    )
    assert rolled_back.retention is not None
    with rolled_back.database.read() as connection:
        assert (
            connection.execute(
                "SELECT state FROM production_connectors WHERE connector_alias = 'fastmail'"
            ).fetchone()["state"]
            == "disabled"
        )
    rolled_back.state.record_provider_state("active", ready=True, now=lifecycle_now + 1)
    assert rolled_back.status().live_providers_ready is False

    missing_identity = config.connectors["fastmail"].model_copy(
        update={"server_identity_digest": None}
    )
    missing_identity_config = config.model_copy(
        update={"connectors": {"fastmail": missing_identity}}
    )
    with pytest.raises(ProductionAssemblyError, match="initialization identity"):
        build_production_runtime(missing_identity_config, secret_store=secret_store)

    policy_path = Path(payload["policy_path"])
    reviewed_policy = policy_path.read_text(encoding="utf-8")
    policy_path.write_text(
        reviewed_policy.replace(
            "        schema_digest: "
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            "",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProductionAssemblyError, match="schema digest"):
        build_production_runtime(config, secret_store=secret_store)


def test_production_connector_rejects_invalid_server_identity_digest(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    payload["connectors"]["mail"]["server_identity_digest"] = "not-a-digest"

    with pytest.raises(ValidationError, match="server identity"):
        ProductionConfig.model_validate(payload)


def test_live_whatsapp_rollout_uses_owned_isolated_wacli_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _production_payload(tmp_path)
    source_root = tmp_path / "attachment-imports"
    source_root.mkdir(mode=0o700)
    runtime_root = tmp_path / "wacli-runtime"
    runtime_root.mkdir(mode=0o700)
    home = runtime_root / "home"
    store = runtime_root / "store"
    home.mkdir(mode=0o700)
    store.mkdir(mode=0o700)
    snapshot_root = tmp_path / "wacli-execution-snapshots"
    snapshot_root.mkdir(mode=0o700)
    executable_path = runtime_root / "wacli"
    executable_path.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable_path.chmod(0o700)
    executable = str(executable_path)
    digest = hashlib.sha256(executable_path.read_bytes()).hexdigest()
    Path(payload["policy_path"]).write_text(
        """
version: 1
default_mode: deny
downstreams:
  whatsapp:
    transport: stdio
    command_ref: connector:whatsapp
    credential_ref: keychain://signet/whatsapp
    account_ref: account:whatsapp-primary
    tools:
      send_text:
        mode: approval
        adapter: whatsapp.send_text
        communication_send: true
        account_ref: account:whatsapp-primary
        schema_digest: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
      send_file:
        mode: approval
        adapter: whatsapp.send_file
        communication_send: true
        account_ref: account:whatsapp-primary
        schema_digest: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
""".strip()
        + "\n",
        encoding="utf-8",
    )
    payload["connectors"] = {
        "whatsapp": {
            "transport": "stdio",
            "credential_ref": "keychain://signet/whatsapp",
            "credential_identity_digest": "b" * 64,
            "command": [executable],
            "working_directory": str(runtime_root),
            "execution_snapshot_root": str(snapshot_root),
            "executable_sha256": digest,
            "output_limit_bytes": 256 * 1024,
        }
    }
    payload["storage"].update(
        attachment_staging_dir=str(tmp_path / "attachment-staging"),
        attachment_source_roots=[str(source_root)],
    )
    payload["secrets"]["attachment_key_ref"] = "keychain://signet/attachment"
    payload["capabilities"]["live_providers_ready"] = True
    payload["provider_rollout"] = {
        "state": "enabled",
        "wacli": {
            "account": "whatsapp-primary",
            "linked_jid": "15551234567@s.whatsapp.net",
            "home": str(home),
            "store": str(store),
            "expected_version": "0.1.0",
        },
    }
    captured: list[object] = []

    class CapturingWacli:
        def __init__(self, config: object, *, staging_store: object) -> None:
            captured.extend((config, staging_store))

        async def verify_version(self) -> str:
            return "0.1.0"

        async def call_tool(
            self,
            tool_name: str,
            arguments: Mapping[str, object],
        ) -> Mapping[str, object]:
            del tool_name, arguments
            return {"status": "sent", "message_id": "provider-message-id"}

    monkeypatch.setattr(production_connectors_module, "WacliWrapper", CapturingWacli)
    config = ProductionConfig.model_validate(payload)
    secrets = MemorySecretStore(
        {
            ("signet", "session"): "session-secret-" * 3,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "payload"): "payload-secret-" * 3,
            ("signet", "totp"): "totp-secret-value",
            ("signet", "attachment"): "attachment-key-material-" * 3,
        }
    )
    assembly = build_production_runtime(config, secret_store=secrets)

    predecessor_document = config.model_dump(mode="json")
    predecessor_document["provider_rollout"]["wacli"].pop("linked_jid")
    for connector_document in predecessor_document["connectors"].values():
        connector_document.pop("tls_server_certificate")
        connector_document.pop("tls_server_certificate_sha256")
    predecessor_digest = hashlib.sha256(canonical_json(predecessor_document)).hexdigest()
    predecessor_connector = config.connectors["whatsapp"].model_dump(mode="json")
    predecessor_connector.pop("tls_server_certificate")
    predecessor_connector.pop("tls_server_certificate_sha256")
    predecessor_connector_digest = hashlib.sha256(canonical_json(predecessor_connector)).hexdigest()
    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE production_setup_state SET config_digest = ? WHERE state_id = 1",
            (predecessor_digest,),
        )
        connection.execute(
            "UPDATE production_services SET config_digest = ?",
            (predecessor_digest,),
        )
        connection.execute(
            "UPDATE production_connectors SET config_digest = ? WHERE connector_alias = ?",
            (predecessor_connector_digest, "whatsapp"),
        )
    upgraded = build_production_runtime(config, secret_store=secrets)
    with upgraded.database.read() as connection:
        assert (
            connection.execute(
                "SELECT config_digest FROM production_setup_state WHERE state_id = 1"
            ).fetchone()["config_digest"]
            == hashlib.sha256(canonical_json(config.model_dump(mode="json"))).hexdigest()
        )

    client = assembly.provider_clients["whatsapp"]
    assert isinstance(client, CredentialBoundClient)
    wrapper_config = cast(WacliConfig, captured[0])
    assert client.credential_identity_digest == provider_execution_identity_digest(
        config, "whatsapp"
    )
    assert client.credential_identity_digest != "b" * 64
    linked_rotation = config.model_copy(
        update={
            "provider_rollout": config.provider_rollout.model_copy(
                update={
                    "wacli": cast(Any, config.provider_rollout.wacli).model_copy(
                        update={"linked_jid": "15557654321@s.whatsapp.net"}
                    )
                }
            )
        }
    )
    assert provider_execution_identity_digest(linked_rotation, "whatsapp") != (
        client.credential_identity_digest
    )
    assert "redacted" in repr(client)
    assert wrapper_config.reviewed_dispatch_enabled is True
    assert wrapper_config.home == home
    assert wrapper_config.store == store
    assert wrapper_config.execution_snapshot_root == snapshot_root
    assert tuple(assembly.adapters) == (
        ("whatsapp", "send_text"),
        ("whatsapp", "send_file"),
    )
    file_adapter = cast(WhatsAppAdapter, assembly.adapters[("whatsapp", "send_file")])
    assert file_adapter.staging_store is assembly.staging

    for connector_override in (
        {"command": (executable, "ignored-argument")},
        {"working_directory": tmp_path / "different-runtime"},
        {"output_limit_bytes": config.connectors["whatsapp"].output_limit_bytes + 1},
    ):
        misbound_connector = config.connectors["whatsapp"].model_copy(update=connector_override)
        misbound_config = config.model_copy(update={"connectors": {"whatsapp": misbound_connector}})
        with pytest.raises(ProductionAssemblyError, match="wacli process boundary"):
            build_production_runtime(misbound_config, secret_store=secrets)

    policy_path = Path(payload["policy_path"])
    reviewed_policy = policy_path.read_text(encoding="utf-8")
    policy_path.write_text(
        reviewed_policy.replace(
            "        mode: approval\n"
            "        adapter: whatsapp.send_text\n"
            "        communication_send: true\n",
            "        mode: passthrough\n        reviewed_read_only: true\n",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProductionAssemblyError, match="approval-bound"):
        build_production_runtime(config, secret_store=secrets)
    policy_path.write_text(reviewed_policy, encoding="utf-8")

    class FailingWacli:
        def __init__(self, config: object, *, staging_store: object) -> None:
            del config, staging_store
            raise RuntimeError("never-leak-provider-secret")

    monkeypatch.setattr(production_connectors_module, "WacliWrapper", FailingWacli)
    with pytest.raises(ProductionAssemblyError) as failure:
        build_production_runtime(config, secret_store=secrets)
    assert "never-leak-provider-secret" not in str(failure.value)


def test_production_browser_ceremony_isolation_never_calls_providers_or_mutates_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [int(time.time())]
    secret = "JBSWY3DPEHPK3PXP"
    store = _ProvisioningSecretStore()
    provisioner = _FixedTotpProvisioner(store)
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    _FailOnCallProvider.calls.clear()
    monkeypatch.setattr(
        production_module,
        "ProductionDisabledProviderClient",
        _FailOnCallProvider,
    )
    assembly = build_production_runtime(
        config,
        secret_store=store,
        totp_provisioner=provisioner,
        clock=lambda: now[0],
    )
    enrollments = TotpEnrollmentService(
        assembly.database,
        provisioner=provisioner,
        secret_store=store,
    )
    bootstrap = BootstrapService(
        assembly.database,
        owner_user_id=config.owner_user_id,
        totp_enrollments=enrollments,
    )
    claimant = "production-browser-claimant-token-long-enough"
    capability = bootstrap.issue_capability(now=now[0], lifetime=3600)
    bootstrap.claim(capability, claimant, now=now[0])
    bootstrap.enroll_password(
        "correct horse battery staple",
        claimant_token=claimant,
        now=now[0],
    )
    initial = enrollments.begin(
        config.owner_user_id,
        "Primary TOTP",
        flow="bootstrap",
        session_id=None,
        now=now[0],
    )
    verified = enrollments.verify(
        initial.enrollment.enrollment_id,
        pyotp.TOTP(secret).at(now[0]),
        user_id=config.owner_user_id,
        session_id=None,
        now=now[0],
    )
    bootstrap.enroll_totp(verified, claimant_token=claimant, now=now[0])
    assert bootstrap.complete(claimant_token=claimant, now=now[0]).complete

    sessions = SessionManager(
        SQLiteSessionRepository(assembly.database),
        signing_key=("session-secret-" * 3).encode(),
    )
    owner_token = sessions.create_session(
        config.owner_user_id,
        auth_method="totp",
        now=now[0],
    )
    owner = sessions.authenticate(owner_token, now=now[0])
    actor_factor_id = assembly.authenticators.list_factors(config.owner_user_id)[0].factor_id

    def pending(label: str) -> IssuedTotpEnrollment:
        slug = label.lower().replace(" ", "-")
        authorization_id = f"authorization-{slug}"
        operation_id = f"browser-operation-{slug}"
        with assembly.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO browser_enrollment_authorizations(
                    authorization_id, user_id, session_id, action, factor_label,
                    operation_id, actor_factor_id, created_at, expires_at, claimed_at
                ) VALUES (?, ?, ?, 'add_totp', ?, ?, ?, ?, ?, ?)
                """,
                (
                    authorization_id,
                    config.owner_user_id,
                    owner.session_id,
                    label,
                    operation_id,
                    actor_factor_id,
                    now[0],
                    now[0] + 900,
                    now[0],
                ),
            )
        return enrollments.begin(
            config.owner_user_id,
            label,
            flow="management",
            session_id=owner.session_id,
            authorization_id=authorization_id,
            operation_id=operation_id,
            now=now[0],
        )

    def durable_effects() -> tuple[tuple[tuple[Any, ...], ...], tuple[tuple[Any, ...], ...]]:
        with assembly.database.read() as connection:
            return (
                tuple(
                    tuple(row)
                    for row in connection.execute(
                        "SELECT * FROM approval_requests ORDER BY request_id"
                    )
                ),
                tuple(
                    tuple(row)
                    for row in connection.execute(
                        "SELECT * FROM notification_outbox ORDER BY outbox_id"
                    )
                ),
            )

    def authenticated_client(token: str) -> tuple[TestClient, str]:
        client = TestClient(assembly.web, base_url=config.public_origin)
        client.cookies.set(
            "__Host-signet_session",
            token,
            domain="signet.example.test",
            path="/",
        )
        page = client.get("/authenticators")
        assert page.status_code == 200
        match = re.search(r'<meta name="csrf-token" content="([^"]+)">', page.text)
        assert match is not None
        return client, match.group(1)

    baseline = durable_effects()
    assert baseline == ((), ())

    owner_client, owner_csrf = authenticated_client(owner_token)
    stale_proof = owner_client.post(
        "/authenticators/enroll/totp",
        json={
            "action": "add_totp",
            "label": "Rejected stale proof",
            "operation_id": "browser-operation-rejected-stale-proof",
            "totp_proof": pyotp.TOTP(secret).at(now[0] - 90),
            "totp_credential_id": "totp-bootstrap",
        },
        headers={"Origin": config.public_origin, "X-CSRF-Token": owner_csrf},
    )
    assert stale_proof.status_code == 400
    assert durable_effects() == baseline

    issued = pending("Bound enrollment")
    assert durable_effects() == baseline
    enrollment_id = issued.enrollment.enrollment_id

    other_owner_token = sessions.create_session(
        config.owner_user_id,
        auth_method="totp",
        now=now[0],
    )
    other_owner, other_owner_csrf = authenticated_client(other_owner_token)
    wrong_session = other_owner.post(
        "/authenticators/enroll/resume",
        json={"kind": "totp", "enrollment_id": enrollment_id},
        headers={"Origin": config.public_origin, "X-CSRF-Token": other_owner_csrf},
    )
    assert wrong_session.status_code == 400
    assert durable_effects() == baseline

    other_user_token = sessions.create_session(
        "user:other",
        auth_method="totp",
        now=now[0],
    )
    foreign_user = TestClient(assembly.web, base_url=config.public_origin)
    foreign_user.cookies.set(
        "__Host-signet_session",
        other_user_token,
        domain="signet.example.test",
        path="/",
    )
    assert foreign_user.get("/authenticators").status_code == 401
    assert durable_effects() == baseline

    with pytest.raises(InvalidTotpEnrollment):
        enrollments.resume(
            enrollment_id,
            user_id="user:other",
            session_id=owner.session_id,
            now=now[0],
        )
    assert durable_effects() == baseline

    resumed = owner_client.post(
        "/authenticators/enroll/resume",
        json={"kind": "totp", "enrollment_id": enrollment_id},
        headers={"Origin": config.public_origin, "X-CSRF-Token": owner_csrf},
    )
    assert resumed.status_code == 200
    enrollments.verify(
        enrollment_id,
        pyotp.TOTP(secret).at(now[0]),
        user_id=config.owner_user_id,
        session_id=owner.session_id,
        now=now[0],
    )
    enrollments.consume(
        enrollment_id,
        user_id=config.owner_user_id,
        session_id=owner.session_id,
        now=now[0],
    )
    replay = owner_client.post(
        "/authenticators/enroll/resume",
        json={"kind": "totp", "enrollment_id": enrollment_id},
        headers={"Origin": config.public_origin, "X-CSRF-Token": owner_csrf},
    )
    assert replay.status_code == 400
    assert durable_effects() == baseline

    stale = pending("Stale enrollment")
    stale_id = stale.enrollment.enrollment_id
    with assembly.database.transaction() as connection:
        connection.execute(
            """
            UPDATE browser_totp_enrollments
            SET created_at = ?, expires_at = ?
            WHERE enrollment_id = ?
            """,
            (now[0] - 10, now[0] - 1, stale_id),
        )
    stale_response = owner_client.post(
        "/authenticators/enroll/resume",
        json={"kind": "totp", "enrollment_id": stale_id},
        headers={"Origin": config.public_origin, "X-CSRF-Token": owner_csrf},
    )
    assert stale_response.status_code == 400
    assert durable_effects() == baseline

    expired_authorization = pending("Expired authorization")
    expired_id = expired_authorization.enrollment.enrollment_id
    assert expired_authorization.enrollment.authorization_id is not None
    with assembly.database.transaction() as connection:
        connection.execute(
            """
            UPDATE browser_enrollment_authorizations
            SET expires_at = ?
            WHERE authorization_id = ?
            """,
            (now[0] + 1, expired_authorization.enrollment.authorization_id),
        )
    now[0] += 2
    expired_status = owner_client.post(
        "/authenticators/enroll/status",
        json={"kind": "totp", "registration_id": expired_id},
        headers={"Origin": config.public_origin, "X-CSRF-Token": owner_csrf},
    )
    assert expired_status.status_code == 400
    expired_resume = owner_client.post(
        "/authenticators/enroll/resume",
        json={"kind": "totp", "enrollment_id": expired_id},
        headers={"Origin": config.public_origin, "X-CSRF-Token": owner_csrf},
    )
    assert expired_resume.status_code == 400
    expired_verify = owner_client.post(
        "/authenticators/totp/verify",
        json={"enrollment_id": expired_id, "proof": pyotp.TOTP(secret).at(now[0])},
        headers={"Origin": config.public_origin, "X-CSRF-Token": owner_csrf},
    )
    assert expired_verify.status_code == 400
    assert durable_effects() == baseline
    assert _FailOnCallProvider.calls == []


@pytest.mark.parametrize("installation", ("source", "wheel"))
def test_bootstrap_issue_runs_from_source_and_installed_wheel(
    tmp_path: Path,
    installation: str,
) -> None:
    root = Path(__file__).resolve().parents[1]
    payload = _production_payload(tmp_path)
    config_path = tmp_path / "production.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)

    if installation == "source":
        command = [
            "uv",
            "run",
            "signet",
            "bootstrap",
            "issue",
            "--config",
            str(config_path),
            "--lifetime",
            "60",
        ]
        environment = os.environ.copy()
    else:
        dist = tmp_path / "dist"
        built = subprocess.run(
            ["uv", "build", "--wheel", "--out-dir", str(dist)],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert built.returncode == 0, built.stderr
        wheels = tuple(dist.glob("*.whl"))
        assert len(wheels) == 1
        command = [
            "uv",
            "run",
            "--quiet",
            "--isolated",
            "--no-project",
            "--with",
            str(wheels[0]),
            "signet",
            "bootstrap",
            "issue",
            "--config",
            str(config_path),
            "--lifetime",
            "60",
        ]
        environment = os.environ.copy()

    issued = subprocess.run(
        command,
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert issued.returncode == 0, issued.stderr
    assert re.fullmatch(r"sbc1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\n", issued.stdout)
    assert issued.stderr == ""
    database = Database(Path(payload["storage"]["data_dir"]) / "signet.db")
    with database.read() as connection:
        row = connection.execute(
            "SELECT status, capability_verifier FROM browser_bootstrap_state WHERE state_id = 1"
        ).fetchone()
    assert row is not None
    assert tuple(row) == ("pending", row["capability_verifier"])
    assert bytes(row["capability_verifier"])
    assert issued.stdout.strip().encode() not in database.path.read_bytes()


def test_build_production_runtime_stages_durable_provider_free_assembly(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    secret_store = _secret_store()
    health_identity = production_instance_identity(config.storage.data_dir.parent)
    health_secret = secret_store.get(
        SecretReference.parse(config.secrets.session_secret_ref)
    ).reveal()
    health_challenge = "test-health-challenge-value-0123456789"

    assembly = build_production_runtime(config, secret_store=secret_store, clock=lambda: 123)
    status = assembly.status()

    assert status.schema_version == 19
    assert assembly.authenticators.list_factors(config.owner_user_id) == ()
    assert status.setup_status == "staged"
    assert status.ready is False
    assert status.missing_prerequisites == (
        "mcp_ready",
        "web_ready",
        "workers_ready",
        "live_providers_ready",
    )
    assert status.services["mcp"].host == "127.0.0.1"
    assert status.services["mcp"].port == 8789
    assert status.services["delivery"].state == "blocked"
    health = TestClient(
        assembly.web,
        base_url="https://signet.example.test",
    ).get("/healthz", headers={"X-Signet-Health-Challenge": health_challenge})
    assert health.status_code == 503
    assert health.json() == {"status": "unavailable", "service": "signet-web"}
    assert health.headers["X-Signet-Instance"] == health_identity
    assert health.headers["X-Signet-Health-Proof"] == production_health_proof(
        health_secret,
        identity=health_identity,
        component="web",
        challenge=health_challenge,
    )
    mcp_client = TestClient(assembly.mcp.app, base_url="http://127.0.0.1:8789")
    mcp_health = mcp_client.get("/healthz", headers={"X-Signet-Health-Challenge": health_challenge})
    assert mcp_health.status_code == 503
    assert mcp_health.json() == {"status": "unavailable"}
    assert mcp_health.headers["X-Signet-Instance"] == health_identity
    assert mcp_health.headers["X-Signet-Health-Proof"] == production_health_proof(
        health_secret,
        identity=health_identity,
        component="mcp",
        challenge=health_challenge,
    )
    readiness = mcp_client.get("/readyz")
    assert readiness.status_code == 503
    assert readiness.json() == {"status": "unavailable"}
    with TestClient(assembly.mcp.app, base_url="http://127.0.0.1:8789") as running_mcp:
        assert running_mcp.get("/healthz").json() == {"status": "ok"}
        readiness = running_mcp.get("/readyz")
        assert readiness.status_code == 200
        assert readiness.json() == {"status": "ready"}
        assert assembly.status().services["mcp"].state == "ready"
    assert assembly.status().services["mcp"].state == "stopped"
    assert assembly.workers.running is False
    assert assembly.workers.healthy is False
    assert set(assembly.provider_clients) == {"mail"}
    assert isinstance(assembly.provider_clients["mail"], ProductionDisabledProviderClient)


def test_disabled_runtime_requires_atomic_reviewed_connector_identity_rotation(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)
    previous_execution_identity = assembly.provider_clients["mail"].credential_identity_digest
    current_connector = config.connectors["mail"]
    rotated_connector = current_connector.model_copy(
        update={
            "credential_identity_digest": "b" * 64,
            "server_identity_digest": "c" * 64,
            "tls_server_certificate": tmp_path / "reviewed-next-server.pem",
            "tls_server_certificate_sha256": "d" * 64,
        }
    )
    rotated = config.model_copy(update={"connectors": {"mail": rotated_connector}})

    with pytest.raises(ProductionAssemblyError, match="differs from durable state"):
        build_production_runtime(rotated, secret_store=_secret_store(), clock=lambda: 124)

    changed_endpoint = rotated_connector.model_copy(
        update={"url": "https://other.example.test/mcp"}
    )
    with pytest.raises(ProductionStateError, match="only change reviewed identity fields"):
        assembly.state.rotate_connector_identity(
            current_config=config,
            next_config=rotated.model_copy(update={"connectors": {"mail": changed_endpoint}}),
            alias="mail",
            now=124,
        )

    assembly.state.rotate_connector_identity(
        current_config=config,
        next_config=rotated,
        alias="mail",
        now=124,
    )
    restarted = build_production_runtime(rotated, secret_store=_secret_store(), clock=lambda: 125)
    assert (
        restarted.provider_clients["mail"].credential_identity_digest != previous_execution_identity
    )
    with restarted.database.read() as connection:
        setup_digest = connection.execute(
            "SELECT config_digest FROM production_setup_state WHERE state_id = 1"
        ).fetchone()["config_digest"]
        connector_row = connection.execute(
            """
            SELECT config_digest, credential_identity_digest, state
            FROM production_connectors WHERE connector_alias = 'mail'
            """
        ).fetchone()
    assert (
        setup_digest == hashlib.sha256(canonical_json(rotated.model_dump(mode="json"))).hexdigest()
    )
    assert tuple(connector_row) == (
        hashlib.sha256(canonical_json(rotated_connector.model_dump(mode="json"))).hexdigest(),
        "b" * 64,
        "disabled",
    )


def test_web_health_uses_durable_maintenance_state_from_a_separate_worker(
    tmp_path: Path,
) -> None:
    current_time = 123
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(
        config,
        secret_store=_secret_store(),
        clock=lambda: current_time,
    )
    client = TestClient(assembly.web, base_url="https://signet.example.test")

    assert assembly.workers.running is False
    assert client.get("/healthz").status_code == 503

    assembly.state.record_worker_state("ready", ready=True, now=current_time)
    assert assembly.workers.running is False
    assert client.get("/healthz").status_code == 200

    current_time += 1
    assembly.state.record_worker_state("blocked", ready=False, now=current_time)
    assert client.get("/healthz").status_code == 503


def test_worker_state_rejects_readiness_that_contradicts_lifecycle_state(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)
    staged_status = assembly.status()

    with pytest.raises(ValueError, match="worker readiness does not match lifecycle state"):
        assembly.state.record_worker_state("blocked", ready=True, now=124)

    assert assembly.status() == staged_status


def test_web_health_expires_stale_durable_worker_readiness(tmp_path: Path) -> None:
    current_time = 123
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(
        config,
        secret_store=_secret_store(),
        clock=lambda: current_time,
    )
    client = TestClient(assembly.web, base_url="https://signet.example.test")

    assembly.state.record_worker_state("ready", ready=True, now=current_time)
    assert client.get("/healthz").status_code == 200

    current_time += assembly.workers.heartbeat_lease_seconds
    assert client.get("/healthz").status_code == 200

    current_time += 1
    assert client.get("/healthz").status_code == 503


def test_production_http_surfaces_reject_non_loopback_transport_peers(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store())

    remote_web = TestClient(
        assembly.web,
        base_url="https://signet.example.test",
        client=("203.0.113.10", 50000),
    )
    remote_mcp = TestClient(
        assembly.mcp.app,
        base_url="http://127.0.0.1:8789",
        client=("203.0.113.10", 50001),
    )

    assert remote_web.get("/healthz").status_code == 403
    assert remote_mcp.get("/healthz").status_code == 403
    assert assembly.mcp.allowed_hosts == frozenset(
        {"127.0.0.1", "127.0.0.1:8789", "localhost", "localhost:8789"}
    )

    for path in (config.storage.data_dir, config.storage.backup_dir, config.storage.restore_dir):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert stat.S_IMODE(config.storage.database_path.stat().st_mode) == 0o600

    expected_counts = {
        "production_setup_state": 1,
        "production_users": 1,
        "production_connectors": 1,
        "production_secret_references": 5,
        "production_services": 7,
    }
    with assembly.database.read() as connection:
        for table, expected in expected_counts.items():
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == expected

        legacy_document = config.model_dump(mode="json")
        legacy_document["storage"].pop("attachment_staging_dir")
        legacy_document["storage"].pop("attachment_source_roots")
        legacy_document["secrets"].pop("attachment_key_ref")
        legacy_document.pop("provider_rollout")
        legacy_document["connectors"]["mail"].pop("server_identity_digest")
        legacy_document["connectors"]["mail"].pop("tls_server_certificate")
        legacy_document["connectors"]["mail"].pop("tls_server_certificate_sha256")
        legacy_digest = hashlib.sha256(canonical_json(legacy_document)).hexdigest()

        legacy_connector = config.connectors["mail"].model_dump(mode="json")
        legacy_connector.pop("server_identity_digest")
        legacy_connector.pop("tls_server_certificate")
        legacy_connector.pop("tls_server_certificate_sha256")
        legacy_connector_digest = hashlib.sha256(canonical_json(legacy_connector)).hexdigest()

    with assembly.database.transaction() as connection:
        connection.execute(
            "UPDATE production_setup_state SET config_digest = ? WHERE state_id = 1",
            (legacy_digest,),
        )
        connection.execute(
            "UPDATE production_services SET config_digest = ?",
            (legacy_digest,),
        )
        connection.execute(
            """
            UPDATE production_connectors SET config_digest = ?
            WHERE connector_alias = 'mail'
            """,
            (legacy_connector_digest,),
        )

    durable_bytes = b"".join(
        path.read_bytes() for path in config.storage.data_dir.iterdir() if path.is_file()
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
        expected_current_digest = hashlib.sha256(
            canonical_json(config.model_dump(mode="json"))
        ).hexdigest()
        assert (
            connection.execute(
                "SELECT config_digest FROM production_setup_state WHERE state_id = 1"
            ).fetchone()["config_digest"]
            == expected_current_digest
        )


@pytest.mark.asyncio
async def test_production_maintenance_worker_has_explicit_lifecycle(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)

    await assembly.workers.run_once(now=124)
    stop = asyncio.Event()
    stop.set()
    await assembly.workers.serve(stop)

    assert assembly.workers.running is False
    assert assembly.workers.healthy is False


@pytest.mark.asyncio
async def test_worker_heartbeat_uses_maintenance_completion_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = 123
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(
        config,
        secret_store=_secret_store(),
        clock=lambda: current_time,
    )
    stop = asyncio.Event()
    recorded_states: list[tuple[str, int]] = []
    expected_ready_timestamps: list[int] = []
    record_worker_state = assembly.state.record_worker_state

    def record_state(state: Any, *, ready: bool, now: int) -> None:
        recorded_states.append((state, now))
        record_worker_state(state, ready=ready, now=now)

    def delayed_recovery(*, now: int) -> None:
        nonlocal current_time
        assert now == current_time
        current_time += assembly.workers.heartbeat_lease_seconds + 1
        expected_ready_timestamps.append(current_time)

    async def delayed_publish(*, now: int | None = None) -> bool:
        nonlocal current_time
        assert now == current_time
        current_time += assembly.workers.heartbeat_lease_seconds + 1
        expected_ready_timestamps.append(current_time)
        stop.set()
        return False

    monkeypatch.setattr(assembly.state, "record_worker_state", record_state)
    monkeypatch.setattr(assembly.workers._approvals, "recover_startup", delayed_recovery)
    monkeypatch.setattr(assembly.workers._policy_promotions, "publish_pending", delayed_publish)

    await assembly.workers.serve(stop)

    ready_timestamps = [now for state, now in recorded_states if state == "ready"]
    assert ready_timestamps == expected_ready_timestamps


def test_build_fails_closed_before_database_creation_when_secret_is_missing(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    secrets = MemorySecretStore(
        {
            ("signet", "session"): "session-secret-" * 3,
            ("signet", "csrf"): "csrf-secret-" * 4,
            ("signet", "capability"): "capability-secret-" * 3,
            ("signet", "totp"): "totp-secret-value",
            ("signet", "mail"): "mail-secret-value",
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


@pytest.mark.parametrize(
    ("command", "factory", "host", "port"),
    (
        (
            "serve-mcp",
            "signet.production:create_production_mcp_app_from_environment",
            "127.0.0.2",
            9000,
        ),
        (
            "serve-web",
            "signet.production:create_production_web_app_from_environment",
            "127.0.0.3",
            9001,
        ),
    ),
)
def test_environment_factories_require_the_configured_listener_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    factory: str,
    host: str,
    port: int,
) -> None:
    payload = _production_payload(tmp_path)
    service = command.removeprefix("serve-")
    payload[f"{service}_host"] = host
    payload[f"{service}_port"] = port
    config_path = tmp_path / "production.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)
    monkeypatch.setenv("SIGNET_PRODUCTION_CONFIG", str(config_path))
    calls: list[dict[str, Any]] = []

    def runner(_app: str, **kwargs: Any) -> None:
        calls.append(kwargs)

    with pytest.raises(SystemExit):
        run_cli([command, "--factory", factory], runner=runner)
    assert calls == []

    run_cli(
        [command, "--factory", factory, "--host", host, "--port", str(port)],
        runner=runner,
    )
    assert calls == [
        {
            "factory": True,
            "host": host,
            "port": port,
            "server_header": False,
            "limit_concurrency": 64,
            "proxy_headers": False,
        }
    ]


def test_service_specific_factories_do_not_construct_unused_sibling_apps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "production.json"
    config_path.write_text(json.dumps(_production_payload(tmp_path)), encoding="utf-8")
    config_path.chmod(0o600)
    original_web_factory = production_module.create_web_app

    def unexpected_web_factory(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the MCP factory constructed the web sibling")

    monkeypatch.setattr(production_module, "create_web_app", unexpected_web_factory)
    runtime = create_production_mcp_runtime(config_path, secret_store=_secret_store())
    assert runtime.app is not None

    monkeypatch.setattr(production_module, "create_web_app", original_web_factory)

    def unexpected_mcp_factory(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the web factory constructed the MCP sibling")

    monkeypatch.setattr(production_module, "assemble_mcp_runtime", unexpected_mcp_factory)
    app = create_production_web_app(config_path, secret_store=_secret_store())
    assert app is not None


def test_standard_factory_creates_and_verifies_required_upgrade_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "production.json"
    payload = _production_payload(tmp_path)
    config = ProductionConfig.model_validate(payload)
    config.prepare_directories()
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 15)
    legacy_database = Database(config.storage.database_path)
    legacy_database.initialize()
    with legacy_database.transaction() as connection:
        connection.execute("DROP INDEX auth_credentials_one_active_totp")
        connection.executemany(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, public_material,
                secret_reference, enrolled_at, disabled_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (
                (
                    "x" * 47 + " " + "tail",
                    config.owner_user_id,
                    "totp",
                    None,
                    "keychain://signet/totp",
                    2,
                ),
                (
                    "shared-passkey-prefix-" * 3 + "one",
                    config.owner_user_id,
                    "webauthn",
                    b"first-public-key",
                    None,
                    None,
                ),
                (
                    "shared-passkey-prefix-" * 3 + "two",
                    config.owner_user_id,
                    "webauthn",
                    b"second-public-key",
                    None,
                    None,
                ),
            ),
        )
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 16)
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path.parent == config.storage.backup_dir:
            raise AssertionError("production backup digest loaded the complete snapshot")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    runtime = create_production_mcp_runtime(config_path, secret_store=_secret_store())

    assert runtime.app is not None
    with Database(config.storage.database_path).read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 16
        labels = tuple(
            row[0]
            for row in connection.execute(
                "SELECT factor_label FROM auth_credentials ORDER BY credential_id"
            )
        )
    assert len(labels) == len(set(labels)) == 3
    assert all(label == label.strip() for label in labels)
    backups = tuple(config.storage.backup_dir.glob("signet-pre-migration-v15-*.sqlite3"))
    assert len(backups) == 1
    Database.verify_snapshot(backups[0])


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

    database.initialize(
        pre_migration_backup=verified_backup_callback(tmp_path / "backups", backups)
    )

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
        "production_connectors",
        "production_secret_references",
    }


def test_production_refuses_schema_upgrade_without_verified_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    database = Database(config.storage.database_path)
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 15)
    database.initialize()
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 16)

    with pytest.raises(ProductionAssemblyError, match="migration was not started"):
        build_production_runtime(config, secret_store=_secret_store())

    with database.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 15
        production_tables = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'production_%'"
        ).fetchone()[0]
    assert production_tables == 0


def test_post_migration_startup_failure_names_verified_restore_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    database = Database(config.storage.database_path)
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 15)
    database.initialize()
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO schema_cache (
                downstream_alias, tool_name, schema_digest, tool_schema_json,
                discovered_at, review_state, reviewed_at, present
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("mail", "search", "a" * 64, b"not-json", 1, "unreviewed", None, 1),
        )
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 16)
    backups: list[int] = []

    with pytest.raises(ProductionAssemblyError, match="restore the verified pre-migration backup"):
        build_production_runtime(
            config,
            secret_store=_secret_store(),
            pre_migration_backup=verified_backup_callback(tmp_path / "backups", backups),
        )

    assert backups == [15]
    with database.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 16
        assert connection.execute("SELECT count(*) FROM production_setup_state").fetchone()[0] == 0


def test_production_assembly_policy_tracks_recovered_engine_snapshot(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store())
    recovered = parse_policy_yaml(
        b"""
version: 2
default_mode: deny
downstreams:
  mail:
    transport: http
    url: https://mail.example.test/mcp
    credential_ref: keychain://signet/mail
    tools: {}
"""
    )

    assembly.policy_engine.restore_durable_snapshot(recovered)

    assert assembly.policy is recovered


def test_production_does_not_fetch_unused_or_connector_secrets_during_assembly(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    secrets = _RecordingSecretStore()

    build_production_runtime(config, secret_store=secrets)

    assert secrets.accounts == ["session", "csrf", "capability", "payload"]


def test_production_config_validation_does_not_chain_raw_secret_input(tmp_path: Path) -> None:
    marker = "raw-reference-must-not-appear"
    payload = _production_payload(tmp_path)
    payload["secrets"]["session_secret_ref"] = marker
    config_path = tmp_path / "production.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)

    with pytest.raises(ProductionAssemblyError) as caught:
        load_production_config(config_path)

    rendered = "".join(traceback.format_exception(caught.value))
    assert caught.value.__cause__ is None
    assert marker not in rendered


def test_private_config_loader_rejects_symlinked_ancestors_and_hard_links(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    config_path = real / "production.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config_path.chmod(0o600)

    linked_ancestor = tmp_path / "linked"
    linked_ancestor.symlink_to(real, target_is_directory=True)
    with pytest.raises(ProductionAssemblyError, match="opened safely"):
        load_production_config(linked_ancestor / config_path.name)

    hard_link = tmp_path / "production-hardlink.json"
    os.link(config_path, hard_link)
    with pytest.raises(ProductionAssemblyError, match="opened safely"):
        load_production_config(hard_link)


def test_private_policy_loader_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    payload = _production_payload(tmp_path)
    policy_path = Path(payload["policy_path"])
    linked_data = tmp_path / "linked-data"
    linked_data.symlink_to(policy_path.parent, target_is_directory=True)
    payload["policy_path"] = str(linked_data / policy_path.name)
    config = ProductionConfig.model_validate(payload)

    with pytest.raises(ProductionAssemblyError, match="opened safely"):
        build_production_runtime(config, secret_store=_secret_store())

    assert not config.storage.database_path.exists()


def test_production_state_derives_independent_factor_inventory_from_auth_credentials(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store())
    with assembly.database.transaction() as connection:
        connection.execute(
            "INSERT INTO auth_users(user_id, created_at) VALUES (?, ?)",
            (config.owner_user_id, 123),
        )
        for credential_id, kind in (
            ("totp-primary", "totp"),
            ("totp-backup", "totp"),
            ("webauthn-laptop", "webauthn"),
            ("webauthn-phone", "webauthn"),
        ):
            connection.execute(
                """
                INSERT INTO auth_credentials(
                    credential_id, user_id, kind, public_material,
                    secret_reference, enrolled_at, factor_label
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    credential_id,
                    config.owner_user_id,
                    kind,
                    b"public" if kind == "webauthn" else None,
                    "keychain://signet/totp" if kind == "totp" else None,
                    123,
                    credential_id,
                ),
            )
        connection.execute(
            "UPDATE auth_credentials SET disabled_at = ? WHERE credential_id = ?",
            (124, "totp-primary"),
        )

    factors = assembly.status().factors

    assert factors["totp-primary"].state == "disabled"
    assert factors["totp-backup"].state == "active"
    assert factors["webauthn-laptop"].state == "active"
    assert factors["webauthn-phone"].state == "active"


def test_production_persists_observed_capabilities_and_secret_material_identity(
    tmp_path: Path,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store())

    with assembly.database.read() as connection:
        setup = connection.execute(
            "SELECT capability_status_json FROM production_setup_state"
        ).fetchone()
        references = connection.execute(
            """
            SELECT purpose, state, current_generation, material_identity_digest
            FROM production_secret_references ORDER BY purpose
            """
        ).fetchall()

    assert setup is not None
    assert json.loads(setup["capability_status_json"]) == {
        "storage_ready": True,
        "secret_broker_ready": True,
        "mcp_ready": False,
        "web_ready": False,
        "workers_ready": False,
        "policy_ready": True,
        "live_providers_ready": False,
    }
    by_purpose = {row["purpose"]: row for row in references}
    for purpose in (
        "session_secret_ref",
        "csrf_secret_ref",
        "capability_key_ref",
        "payload_key_ref",
    ):
        assert by_purpose[purpose]["state"] == "present"
        assert by_purpose[purpose]["current_generation"] == 1
        assert len(by_purpose[purpose]["material_identity_digest"]) == 64
    assert by_purpose["totp_secret_ref"]["state"] == "required"
    assert by_purpose["totp_secret_ref"]["current_generation"] is None


def test_secret_material_change_requires_explicit_generation_rotation(tmp_path: Path) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)
    changed_session = "changed-session-secret-" * 2
    changed_store = _secret_store(session_secret=changed_session)

    with pytest.raises(ProductionAssemblyError, match="explicit generation rotation"):
        build_production_runtime(config, secret_store=changed_store, clock=lambda: 124)

    with assembly.database.read() as connection:
        current_identity = str(
            connection.execute(
                """
                SELECT material_identity_digest FROM production_secret_references
                WHERE purpose = 'session_secret_ref'
                """
            ).fetchone()[0]
        )
    identity_key = ("capability-secret-" * 3).encode()
    new_identity = hmac.new(
        identity_key,
        b"session_secret_ref\x00" + changed_session.encode(),
        hashlib.sha256,
    ).hexdigest()
    assembly.state.rotate_secret(
        "session_secret_ref",
        reference="keychain://signet/session",
        current_identity=current_identity,
        new_identity=new_identity,
        now=124,
    )

    restarted = build_production_runtime(config, secret_store=changed_store, clock=lambda: 125)
    with restarted.database.read() as connection:
        generation = connection.execute(
            """
            SELECT current_generation FROM production_secret_references
            WHERE purpose = 'session_secret_ref'
            """
        ).fetchone()[0]
    assert generation == 2


@pytest.mark.asyncio
async def test_worker_startup_failure_is_unhealthy_and_persisted_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ProductionConfig.model_validate(_production_payload(tmp_path))
    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)

    def fail_recovery(*, now: int) -> None:
        del now
        raise RuntimeError("injected startup recovery failure")

    monkeypatch.setattr(assembly.workers._approvals, "recover_startup", fail_recovery)

    serving = asyncio.create_task(assembly.workers.serve(asyncio.Event()))
    with pytest.raises(RuntimeError, match="startup recovery"):
        await assembly.workers.wait_started()
    with pytest.raises(RuntimeError, match="startup recovery"):
        await serving

    status = assembly.status()
    assert assembly.workers.running is False
    assert assembly.workers.healthy is False
    assert status.services["maintenance"].state == "blocked"
    assert "workers_ready" in status.missing_prerequisites


@pytest.mark.asyncio
async def test_provider_lifespan_starts_before_apps_and_stops_after_them() -> None:
    events: list[str] = []

    @asynccontextmanager
    async def original_lifespan(_app: object):
        events.append("app:start")
        yield
        events.append("app:stop")

    class Sessions:
        active = False

        def run(self):
            @asynccontextmanager
            async def provider_session():
                self.active = True
                events.append("provider:start")
                yield
                events.append("provider:stop")
                self.active = False

            return provider_session()

    class State:
        def record_provider_state(self, state: str, *, ready: bool, now: int) -> None:
            events.append(f"state:{state}:{ready}:{now}")

    app = SimpleNamespace(router=SimpleNamespace(lifespan_context=original_lifespan))
    production_module._attach_provider_lifespan(
        app,
        cast(Any, Sessions()),
        cast(Any, State()),
        lambda: 123,
    )

    async with app.router.lifespan_context(app):
        assert events == ["provider:start", "state:active:True:123", "app:start"]

    assert events == [
        "provider:start",
        "state:active:True:123",
        "app:start",
        "app:stop",
        "provider:stop",
        "state:blocked:False:123",
    ]


@pytest.mark.asyncio
async def test_provider_runtime_failure_cancels_service_and_records_blocked_state() -> None:
    events: list[str] = []
    entered = asyncio.Event()

    class Client:
        is_running = False

        async def start(self) -> None:
            self.is_running = True
            events.append("provider:start")

        async def close(self) -> None:
            self.is_running = False
            events.append("provider:stop")

    @asynccontextmanager
    async def original_lifespan(_app: object):
        events.append("app:start")
        try:
            yield
        finally:
            events.append("app:stop")

    class State:
        def record_provider_state(self, state: str, *, ready: bool, now: int) -> None:
            events.append(f"state:{state}:{ready}:{now}")

    client = Client()
    sessions = ProviderSessionPool({"fastmail": cast(Any, client)})
    app = SimpleNamespace(router=SimpleNamespace(lifespan_context=original_lifespan))
    production_module._attach_provider_lifespan(
        app,
        sessions,
        cast(Any, State()),
        lambda: 123,
    )

    async def serve() -> None:
        async with app.router.lifespan_context(app):
            entered.set()
            await asyncio.Event().wait()

    serving = asyncio.create_task(serve())
    await entered.wait()
    client.is_running = False
    await asyncio.sleep(0.1)

    assert serving.done() is True
    with pytest.raises(asyncio.CancelledError):
        await serving
    assert sessions.active is False
    assert events[:3] == ["provider:start", "state:active:True:123", "app:start"]
    assert "app:stop" in events
    assert "provider:stop" in events
    assert events[-1] == "state:blocked:False:123"


@pytest.mark.asyncio
async def test_worker_lifespan_cancellation_stops_background_task() -> None:
    @asynccontextmanager
    async def original_lifespan(_app: object):
        yield

    class Workers:
        def __init__(self) -> None:
            self.serve_entered = asyncio.Event()
            self.serve_exited = asyncio.Event()
            self.wait_forever = asyncio.Event()
            self.stop_was_set = False

        async def serve(self, stop: asyncio.Event) -> None:
            self.serve_entered.set()
            try:
                for _ in range(20):
                    if stop.is_set():
                        self.stop_was_set = True
                        return
                    await asyncio.sleep(0.01)
            finally:
                self.serve_exited.set()

        async def wait_started(self) -> None:
            await self.wait_forever.wait()

    workers = Workers()
    app = SimpleNamespace(router=SimpleNamespace(lifespan_context=original_lifespan))
    production_module._attach_production_worker_lifespan(app, cast(Any, workers))
    entering = asyncio.create_task(app.router.lifespan_context(app).__aenter__())
    await workers.serve_entered.wait()
    entering.cancel()
    await asyncio.sleep(0)
    entering.cancel()
    with pytest.raises(asyncio.CancelledError):
        await entering

    assert workers.stop_was_set is True
    assert workers.serve_exited.is_set() is True
