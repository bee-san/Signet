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
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pyotp
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import signet.db as db_module
import signet.production as production_module
from signet.app import main as run_cli
from signet.auth import SessionManager, SQLiteSessionRepository
from signet.browser_auth import BootstrapService
from signet.config import ProductionConfig
from signet.credential_broker import MemorySecretStore, Secret, SecretReference
from signet.db import Database
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
from signet.totp_enrollment import (
    InvalidTotpEnrollment,
    IssuedTotpEnrollment,
    TotpEnrollmentService,
)
from tests.migration_helpers import verified_backup_callback


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

    assembly = build_production_runtime(config, secret_store=_secret_store(), clock=lambda: 123)
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
    ).get("/healthz")
    assert health.status_code == 503
    assert health.json() == {"status": "unavailable", "service": "signet-web"}
    mcp_client = TestClient(assembly.mcp.app, base_url="http://127.0.0.1:8789")
    mcp_health = mcp_client.get("/healthz")
    assert mcp_health.status_code == 503
    assert mcp_health.json() == {"status": "unavailable"}
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

    with pytest.raises(RuntimeError, match="startup recovery"):
        await assembly.workers.serve(asyncio.Event())

    status = assembly.status()
    assert assembly.workers.running is False
    assert assembly.workers.healthy is False
    assert status.services["maintenance"].state == "blocked"
    assert "workers_ready" in status.missing_prerequisites
