from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

import pyotp
import pytest

from signet.auth import SQLitePasswordCredentialRepository
from signet.browser_auth import (
    BootstrapAlreadyComplete,
    BootstrapIncomplete,
    BootstrapService,
)
from signet.credential_broker import Secret, SecretReference
from signet.db import Database
from signet.totp_enrollment import InvalidTotpEnrollment, TotpEnrollmentService
from signet.webauthn import SQLiteWebAuthnRepository, WebAuthnCredential
from signet.webauthn_registration import (
    InvalidRegistrationChallenge,
    PasskeyRegistrationService,
    RegistrationResult,
)

USER_ID = "owner"
OTHER_USER_ID = "other"
ORIGIN = "https://approval.example.test"
RP_ID = "approval.example.test"
SESSION_ID = "session-id-long-enough-for-binding"
OTHER_SESSION_ID = "other-session-id-long-enough-binding"


class FastPasswordEnroller:
    def hash(self, password: str) -> str:
        if len(password) < 12:
            raise ValueError("password must contain at least 12 characters")
        return "$argon2id$fake$" + password[::-1]


class RecordingRegistrationProvider:
    test_only = True

    def __init__(self) -> None:
        self.expected: list[tuple[bytes, str, str]] = []

    def verify(
        self,
        credential: dict[str, Any],
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> RegistrationResult:
        self.expected.append((expected_challenge, expected_rp_id, expected_origin))
        if credential.get("challenge") != expected_challenge.hex():
            raise ValueError("challenge mismatch")
        return RegistrationResult(
            credential_id=str(credential["id"]),
            public_key=b"public-key",
            sign_count=0,
            device_type="multi_device",
            backed_up=True,
            transports=("internal",),
            discoverable=True,
        )


@pytest.fixture
def database(tmp_path: Path) -> Database:
    selected = Database(tmp_path / "signet.sqlite3")
    selected.initialize()
    return selected


def encoded_credential_id(identifier: str) -> str:
    return base64.urlsafe_b64encode(identifier.encode()).rstrip(b"=").decode()


def credential(identifier: str = "credential-one") -> WebAuthnCredential:
    return WebAuthnCredential(
        credential_id=encoded_credential_id(identifier),
        user_id=USER_ID,
        public_key=b"public-key",
        sign_count=0,
        user_handle=hashlib.sha256(b"signet-webauthn-user-v1\x00" + USER_ID.encode()).digest(),
        device_type="multi_device",
        backed_up=True,
        transports=("internal",),
        discoverable=True,
    )


def bootstrap(database: Database) -> BootstrapService:
    return BootstrapService(
        database,
        owner_user_id=USER_ID,
        password_enroller=FastPasswordEnroller(),
    )


def test_bootstrap_resumes_after_restart_and_finalizes_only_once(database: Database) -> None:
    first = bootstrap(database)
    initial = first.status(now=100)
    assert initial.complete is False
    assert initial.has_password is False
    assert initial.has_authenticator is False

    first.enroll_password("a sufficiently long password", now=101)
    restarted = bootstrap(database)
    assert restarted.status(now=102).has_password is True

    restarted.enroll_passkey("MacBook Touch ID", credential(), now=103)
    ready = first.status(now=104)
    assert ready.has_authenticator is True
    assert ready.factor_labels == ("MacBook Touch ID",)

    completed = first.complete(now=105)
    assert completed.complete is True
    with pytest.raises(BootstrapAlreadyComplete):
        restarted.complete(now=106)
    with pytest.raises(BootstrapAlreadyComplete):
        restarted.enroll_password("another sufficiently long password", now=107)

    stored = SQLitePasswordCredentialRepository(database).find_password(USER_ID)
    assert stored is not None
    assert "sufficiently long password" not in repr(stored)
    assert len(SQLiteWebAuthnRepository(database).credentials_for_user(USER_ID)) == 1


def test_bootstrap_requires_password_and_non_password_authenticator(database: Database) -> None:
    service = bootstrap(database)
    service.enroll_password("a sufficiently long password", now=100)

    with pytest.raises(BootstrapIncomplete):
        service.complete(now=101)


def test_concurrent_bootstrap_completion_has_one_winner(database: Database) -> None:
    service = bootstrap(database)
    service.enroll_password("a sufficiently long password", now=100)
    service.enroll_passkey("Primary passkey", credential(), now=101)
    barrier = Barrier(2)

    def complete() -> str:
        barrier.wait()
        try:
            bootstrap(database).complete(now=102)
        except BootstrapAlreadyComplete:
            return "rejected"
        return "completed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: complete(), range(2)))
    assert sorted(outcomes) == ["completed", "rejected"]


def test_passkey_registration_is_origin_session_account_and_replay_bound(
    database: Database,
) -> None:
    provider = RecordingRegistrationProvider()
    service = PasskeyRegistrationService(
        database,
        rp_id=RP_ID,
        origin=ORIGIN,
        provider=provider,
        lifetime=120,
    )
    issued = service.begin(
        USER_ID,
        "Travel key",
        flow="management",
        session_id=SESSION_ID,
        existing_credential_ids=(),
        now=100,
    )
    options = json.loads(issued.options_json)
    challenge = service.repository.find(issued.challenge_id)
    assert challenge is not None
    assert options["rp"]["id"] == RP_ID
    assert options["authenticatorSelection"]["userVerification"] == "required"
    submitted = {
        "id": encoded_credential_id("credential-two"),
        "challenge": challenge.challenge.hex(),
    }

    with pytest.raises(InvalidRegistrationChallenge):
        service.complete(
            issued.challenge_id,
            submitted,
            user_id=OTHER_USER_ID,
            session_id=SESSION_ID,
            now=101,
        )
    with pytest.raises(InvalidRegistrationChallenge):
        service.complete(
            issued.challenge_id,
            submitted,
            user_id=USER_ID,
            session_id=OTHER_SESSION_ID,
            now=101,
        )

    pending = service.complete(
        issued.challenge_id,
        submitted,
        user_id=USER_ID,
        session_id=SESSION_ID,
        now=101,
    )
    assert pending.label == "Travel key"
    assert pending.credential.user_id == USER_ID
    assert provider.expected == [(challenge.challenge, RP_ID, ORIGIN)]

    with pytest.raises(InvalidRegistrationChallenge):
        service.complete(
            issued.challenge_id,
            submitted,
            user_id=USER_ID,
            session_id=SESSION_ID,
            now=102,
        )


def test_passkey_registration_rejects_expired_and_cross_flow_claims(database: Database) -> None:
    provider = RecordingRegistrationProvider()
    service = PasskeyRegistrationService(
        database,
        rp_id=RP_ID,
        origin=ORIGIN,
        provider=provider,
        lifetime=10,
    )
    issued = service.begin(
        USER_ID,
        "Stale key",
        flow="bootstrap",
        session_id=None,
        existing_credential_ids=(),
        now=100,
    )
    challenge = service.repository.find(issued.challenge_id)
    assert challenge is not None

    with pytest.raises(InvalidRegistrationChallenge):
        service.complete(
            issued.challenge_id,
            {"id": "stale", "challenge": challenge.challenge.hex()},
            user_id=USER_ID,
            session_id=None,
            now=110,
        )


class _TotpSecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, reference: SecretReference) -> Secret:
        return Secret(self.values[(reference.service, reference.account)])


class _TotpProvisioner:
    def __init__(self, store: _TotpSecrets, secret: str) -> None:
        self.store = store
        self.secret = secret

    def create(self, factor_id: str) -> str:
        reference = f"keychain://test-signet/{factor_id}"
        self.store.values[("test-signet", factor_id)] = self.secret
        return reference

    def delete(self, secret_reference: str) -> None:
        reference = SecretReference.parse(secret_reference)
        self.store.values.pop((reference.service, reference.account), None)


def test_totp_bootstrap_enrollment_is_verified_bound_and_seed_is_not_persisted(
    database: Database,
) -> None:
    secret = "JBSWY3DPEHPK3PXP"
    store = _TotpSecrets()
    enrollments = TotpEnrollmentService(
        database,
        provisioner=_TotpProvisioner(store, secret),
        secret_store=store,
        lifetime=120,
    )
    bootstrap = BootstrapService(
        database,
        owner_user_id=USER_ID,
        password_enroller=FastPasswordEnroller(),
    )
    bootstrap.enroll_password("correct horse battery staple", now=100)

    issued = enrollments.begin(
        USER_ID,
        "Phone app",
        flow="bootstrap",
        session_id=None,
        now=100,
    )
    assert secret not in repr(issued)
    assert issued.manual_key == secret
    with pytest.raises(InvalidTotpEnrollment):
        enrollments.resume(
            issued.enrollment.enrollment_id,
            user_id=OTHER_USER_ID,
            session_id=None,
            now=101,
        )

    proof = pyotp.TOTP(secret).at(120)
    verified = enrollments.verify(
        issued.enrollment.enrollment_id,
        proof,
        user_id=USER_ID,
        session_id=None,
        now=120,
    )
    status = bootstrap.enroll_totp(verified, now=121)
    assert status.factor_labels == ("Phone app",)
    enrollments.consume(
        issued.enrollment.enrollment_id,
        user_id=USER_ID,
        session_id=None,
        now=121,
    )
    assert bootstrap.complete(now=122).complete
    assert secret.encode() not in database.path.read_bytes()
