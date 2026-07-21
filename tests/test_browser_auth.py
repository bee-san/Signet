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

import signet.db as db_module
from signet.auth import (
    SQLitePasswordCredentialRepository,
    _ensure_auth_user,
    _register_auth_factor,
)
from signet.browser_auth import (
    BootstrapAlreadyComplete,
    BootstrapClaimRequired,
    BootstrapError,
    BootstrapIncomplete,
    BootstrapService,
)
from signet.credential_broker import CredentialError, Secret, SecretReference
from signet.db import Database
from signet.totp_enrollment import InvalidTotpEnrollment, TotpEnrollmentService
from signet.webauthn import SQLiteWebAuthnRepository, WebAuthnCredential
from signet.webauthn_registration import (
    InvalidRegistrationChallenge,
    PasskeyRegistrationService,
    RegistrationResult,
)
from tests.migration_helpers import verified_backup_callback

USER_ID = "owner"
OTHER_USER_ID = "other"
ORIGIN = "https://approval.example.test"
RP_ID = "approval.example.test"
SESSION_ID = "session-id-long-enough-for-binding"
OTHER_SESSION_ID = "other-session-id-long-enough-binding"
CLAIMANT_TOKEN = "claimant-token-long-enough-for-bootstrap-binding"


class FastPasswordEnroller:
    def hash(self, password: str) -> str:
        if len(password) < 12:
            raise ValueError("password must contain at least 12 characters")
        return "$argon2id$fake$" + password[::-1]


class RecordingPasswordEnroller(FastPasswordEnroller):
    def __init__(self) -> None:
        self.passwords: list[str] = []

    def hash(self, password: str) -> str:
        self.passwords.append(password)
        return super().hash(password)


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


def test_operator_can_rotate_an_abandoned_bootstrap_capability(database: Database) -> None:
    service = bootstrap(database)
    abandoned = service.issue_capability(now=100, lifetime=600)
    assert service.capability_is_current(abandoned, now=101) is True
    assert service.capability_is_recorded(abandoned) is True
    assert service.capability_is_current(abandoned, now=700) is False
    assert service.capability_is_recorded(abandoned) is True

    replacement = service.issue_capability(now=700, lifetime=600, replace_existing=True)

    assert replacement != abandoned
    assert service.capability_is_recorded(abandoned) is False
    assert service.capability_is_current(replacement, now=701) is True
    with pytest.raises(BootstrapClaimRequired):
        service.claim(abandoned, CLAIMANT_TOKEN, now=702)
    status = service.claim(replacement, CLAIMANT_TOKEN, now=702)
    assert status.claimed is True


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


def claimed_bootstrap(database: Database, *, now: int = 90) -> BootstrapService:
    service = bootstrap(database)
    capability = service.issue_capability(now=now, lifetime=60)
    service.claim(capability, CLAIMANT_TOKEN, now=now + 1)
    return service


def test_bootstrap_resumes_after_restart_and_finalizes_only_once(database: Database) -> None:
    first = claimed_bootstrap(database)
    initial = first.status(now=100, claimant_token=CLAIMANT_TOKEN)
    assert initial.complete is False
    assert initial.has_password is False
    assert initial.has_authenticator is False

    first.enroll_password("a sufficiently long password", claimant_token=CLAIMANT_TOKEN, now=101)
    restarted = bootstrap(database)
    assert restarted.status(now=102, claimant_token=CLAIMANT_TOKEN).has_password is True

    restarted.enroll_passkey(
        "MacBook Touch ID", credential(), claimant_token=CLAIMANT_TOKEN, now=103
    )
    ready = first.status(now=104, claimant_token=CLAIMANT_TOKEN)
    assert ready.has_authenticator is True
    assert ready.factor_labels == ("MacBook Touch ID",)
    assert SQLitePasswordCredentialRepository(database).find_password(USER_ID) is None
    assert SQLiteWebAuthnRepository(database).credentials_for_user(USER_ID) == ()

    completed = first.complete(claimant_token=CLAIMANT_TOKEN, now=105)
    assert completed.complete is True
    with pytest.raises(BootstrapAlreadyComplete):
        restarted.complete(claimant_token=CLAIMANT_TOKEN, now=106)
    with pytest.raises(BootstrapAlreadyComplete):
        restarted.enroll_password(
            "another sufficiently long password", claimant_token=CLAIMANT_TOKEN, now=107
        )

    stored = SQLitePasswordCredentialRepository(database).find_password(USER_ID)
    assert stored is not None
    assert "sufficiently long password" not in repr(stored)
    assert len(SQLiteWebAuthnRepository(database).credentials_for_user(USER_ID)) == 1


def test_bootstrap_reconciles_a_missing_complete_state_for_the_configured_owner(
    database: Database,
) -> None:
    service = claimed_bootstrap(database)
    service.enroll_password(
        "a sufficiently long password",
        claimant_token=CLAIMANT_TOKEN,
        now=100,
    )
    service.enroll_passkey(
        "Primary passkey",
        credential(),
        claimant_token=CLAIMANT_TOKEN,
        now=101,
    )
    service.complete(claimant_token=CLAIMANT_TOKEN, now=102)
    with database.transaction() as connection:
        owner_created_at = int(
            connection.execute(
                "SELECT created_at FROM auth_users WHERE user_id = ?",
                (USER_ID,),
            ).fetchone()[0]
        )
        connection.execute("DELETE FROM browser_bootstrap_state")

    assert bootstrap(database).status(now=103).complete is True
    with database.read() as connection:
        row = connection.execute(
            "SELECT user_id, status, created_at FROM browser_bootstrap_state WHERE state_id = 1"
        ).fetchone()
    assert dict(row) == {
        "user_id": USER_ID,
        "status": "complete",
        "created_at": owner_created_at,
    }


def test_bootstrap_requires_password_and_non_password_authenticator(database: Database) -> None:
    service = claimed_bootstrap(database)
    service.enroll_password("a sufficiently long password", claimant_token=CLAIMANT_TOKEN, now=100)

    with pytest.raises(BootstrapIncomplete):
        service.complete(claimant_token=CLAIMANT_TOKEN, now=101)


def test_bootstrap_credential_publication_rolls_back_as_one_database_transaction(
    database: Database,
) -> None:
    service = claimed_bootstrap(database)
    service.enroll_password(
        "a sufficiently long password",
        claimant_token=CLAIMANT_TOKEN,
        now=100,
    )
    service.enroll_passkey(
        "Primary passkey",
        credential(),
        claimant_token=CLAIMANT_TOKEN,
        now=101,
    )
    with database.transaction() as connection:
        connection.execute(
            """
            CREATE TRIGGER inject_bootstrap_completion_failure
            BEFORE UPDATE OF status ON browser_bootstrap_state
            WHEN NEW.status = 'complete'
            BEGIN SELECT RAISE(ABORT, 'injected bootstrap completion failure'); END
            """
        )

    with pytest.raises(BootstrapError, match="published atomically"):
        service.complete(claimant_token=CLAIMANT_TOKEN, now=102)

    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_credentials").fetchone()[0] == 0
        state = connection.execute(
            "SELECT status, staged_password_verifier FROM browser_bootstrap_state"
        ).fetchone()
        assert state["status"] == "pending"
        assert state["staged_password_verifier"] is not None
    with database.transaction() as connection:
        connection.execute("DROP TRIGGER inject_bootstrap_completion_failure")
    status = service.status(now=103, claimant_token=CLAIMANT_TOKEN)
    assert status.can_complete is True


def test_concurrent_bootstrap_completion_has_one_winner(database: Database) -> None:
    service = claimed_bootstrap(database)
    service.enroll_password("a sufficiently long password", claimant_token=CLAIMANT_TOKEN, now=100)
    service.enroll_passkey("Primary passkey", credential(), claimant_token=CLAIMANT_TOKEN, now=101)
    barrier = Barrier(2)

    def complete() -> str:
        barrier.wait()
        try:
            bootstrap(database).complete(claimant_token=CLAIMANT_TOKEN, now=102)
        except BootstrapAlreadyComplete:
            return "rejected"
        return "completed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: complete(), range(2)))
    assert sorted(outcomes) == ["completed", "rejected"]


def test_bootstrap_requires_one_use_local_capability_and_one_atomic_claimant(
    database: Database,
) -> None:
    password_enroller = RecordingPasswordEnroller()
    service = BootstrapService(
        database,
        owner_user_id=USER_ID,
        password_enroller=password_enroller,
    )
    assert service.status(now=100).has_password is False
    with pytest.raises(BootstrapClaimRequired):
        service.enroll_password(
            "a sufficiently long password",
            claimant_token="unclaimed-browser-token-long-enough",
            now=101,
        )
    assert password_enroller.passwords == []

    capability = service.issue_capability(now=102, lifetime=60)
    barrier = Barrier(2)

    def claim(index: int) -> str:
        barrier.wait()
        token = f"claimant-token-long-enough-for-race-{index}"
        try:
            bootstrap(database).claim(capability, token, now=103)
        except BootstrapClaimRequired:
            return "rejected"
        return token

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(claim, range(2)))
    assert sum(outcome != "rejected" for outcome in outcomes) == 1
    winner = next(outcome for outcome in outcomes if outcome != "rejected")

    with pytest.raises(BootstrapClaimRequired):
        service.claim(capability, "third-claimant-token-long-enough", now=104)
    with pytest.raises(BootstrapClaimRequired):
        service.enroll_password(
            "a sufficiently long password",
            claimant_token="losing-claimant-token-long-enough",
            now=104,
        )

    service.enroll_password("a sufficiently long password", claimant_token=winner, now=104)
    assert service.status(now=105, claimant_token=winner).has_password is True


def test_reissued_bootstrap_capability_discards_expired_claimant_staging(
    database: Database,
) -> None:
    secret = "JBSWY3DPEHPK3PXP"
    store = _TotpSecrets()
    enrollments = TotpEnrollmentService(
        database,
        provisioner=_TotpProvisioner(store, secret),
        secret_store=store,
        lifetime=15 * 60,
    )
    service = BootstrapService(
        database,
        owner_user_id=USER_ID,
        password_enroller=FastPasswordEnroller(),
        totp_enrollments=enrollments,
    )
    capability = service.issue_capability(now=100, lifetime=60)
    service.claim(capability, CLAIMANT_TOKEN, now=101)
    service.enroll_password(
        "a sufficiently long password",
        claimant_token=CLAIMANT_TOKEN,
        now=102,
    )
    service.enroll_passkey(
        "Prior passkey",
        credential(),
        claimant_token=CLAIMANT_TOKEN,
        now=103,
    )
    issued = enrollments.begin(
        USER_ID,
        "Prior phone",
        flow="bootstrap",
        session_id=None,
        now=104,
    )
    verified = enrollments.verify(
        issued.enrollment.enrollment_id,
        pyotp.TOTP(secret).at(120),
        user_id=USER_ID,
        session_id=None,
        now=120,
    )
    service.enroll_totp(verified, claimant_token=CLAIMANT_TOKEN, now=121)

    replacement = service.issue_capability(now=160, lifetime=60)
    with pytest.raises(InvalidTotpEnrollment):
        enrollments.resume(
            issued.enrollment.enrollment_id,
            user_id=USER_ID,
            session_id=None,
            now=160,
        )
    new_claimant = "replacement-claimant-token-long-enough"
    service.claim(replacement, new_claimant, now=161)
    replacement_enrollment = enrollments.begin(
        USER_ID,
        "Replacement phone",
        flow="bootstrap",
        session_id=None,
        now=162,
    )

    assert enrollments.invalidate_bootstrap(USER_ID, before=160, now=163) == 0

    status = service.status(now=161, claimant_token=new_claimant)
    assert status.has_password is False
    assert status.has_authenticator is False
    assert status.factor_labels == ()
    with database.read() as connection:
        state = connection.execute(
            "SELECT staged_password_verifier FROM browser_bootstrap_state WHERE state_id = 1"
        ).fetchone()
        passkey = connection.execute(
            "SELECT invalidated_at FROM auth_registration_challenges WHERE flow = 'bootstrap'"
        ).fetchone()
        totps = connection.execute(
            """
            SELECT invalidated_at, cleanup_completed_at
            FROM browser_totp_enrollments WHERE flow = 'bootstrap'
            ORDER BY created_at, enrollment_id
            """
        ).fetchall()
    assert state["staged_password_verifier"] is None
    assert passkey["invalidated_at"] == 160
    assert totps[0]["invalidated_at"] == 160
    assert totps[0]["cleanup_completed_at"] == 160
    assert totps[1]["invalidated_at"] is None
    assert totps[1]["cleanup_completed_at"] is None
    replacement_reference = SecretReference.parse(
        replacement_enrollment.enrollment.secret_reference
    )
    assert (replacement_reference.service, replacement_reference.account) in store.values


def test_schema_18_upgrade_backfills_existing_valid_owner_as_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "schema-18-owner.db"
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 18)
    database = Database(path)
    database.initialize()
    with database.transaction() as connection:
        _ensure_auth_user(connection, USER_ID, created_at=50)
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, public_material, enrolled_at, factor_label
            ) VALUES ('password_existing_owner', ?, 'password', ?, 50, 'Password')
            """,
            (USER_ID, b"$argon2id$existing"),
        )
        _register_auth_factor(
            connection,
            credential_id="password_existing_owner",
            user_id=USER_ID,
            kind="password",
            label="Password",
            now=50,
        )
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, public_material, enrolled_at,
                sign_count, backup_eligible, backup_state, user_handle,
                factor_label, transports_json, discoverable
            ) VALUES (?, ?, 'webauthn', ?, 50, 0, 1, 1, ?, 'Existing passkey', '[]', 1)
            """,
            (
                encoded_credential_id("existing-owner-passkey"),
                USER_ID,
                b"existing-public-key",
                hashlib.sha256(b"signet-webauthn-user-v1\x00" + USER_ID.encode()).digest(),
            ),
        )
        _register_auth_factor(
            connection,
            credential_id=encoded_credential_id("existing-owner-passkey"),
            user_id=USER_ID,
            kind="webauthn",
            label="Existing passkey",
            now=50,
        )
        connection.execute(
            """
            INSERT INTO browser_bootstrap_state(
                state_id, user_id, status, created_at, updated_at
            ) VALUES (1, ?, 'pending', 50, 50)
            """,
            (USER_ID,),
        )

    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 19)
    versions: list[int] = []
    database.initialize(
        pre_migration_backup=verified_backup_callback(tmp_path / "backups", versions)
    )

    service = bootstrap(database)
    status = service.status(now=100)
    assert status.complete is True
    assert status.has_password is True
    assert status.factor_labels == ("Existing passkey",)
    assert versions == [18]
    with pytest.raises(BootstrapAlreadyComplete):
        service.issue_capability(now=101)


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


def test_passkey_registration_resumes_after_restart_only_for_bound_session(
    database: Database,
) -> None:
    provider = RecordingRegistrationProvider()
    first = PasskeyRegistrationService(
        database,
        rp_id=RP_ID,
        origin=ORIGIN,
        provider=provider,
        lifetime=120,
    )
    issued = first.begin(
        USER_ID,
        "Restart-safe key",
        flow="management",
        session_id=SESSION_ID,
        existing_credential_ids=(),
        now=100,
    )
    original_options = json.loads(issued.options_json)
    restarted = PasskeyRegistrationService(
        database,
        rp_id=RP_ID,
        origin=ORIGIN,
        provider=provider,
        lifetime=120,
    )

    resumed = restarted.resume(
        issued.challenge_id,
        user_id=USER_ID,
        session_id=SESSION_ID,
        existing_credential_ids=(),
        now=101,
    )

    resumed_options = json.loads(resumed.options_json)
    assert original_options["timeout"] == 120_000
    assert resumed_options["timeout"] == 119_000
    assert {key: value for key, value in resumed_options.items() if key != "timeout"} == {
        key: value for key, value in original_options.items() if key != "timeout"
    }
    assert resumed.challenge_id == issued.challenge_id
    with pytest.raises(InvalidRegistrationChallenge):
        restarted.resume(
            issued.challenge_id,
            user_id=OTHER_USER_ID,
            session_id=SESSION_ID,
            existing_credential_ids=(),
            now=101,
        )
    with pytest.raises(InvalidRegistrationChallenge):
        restarted.resume(
            issued.challenge_id,
            user_id=USER_ID,
            session_id=OTHER_SESSION_ID,
            existing_credential_ids=(),
            now=101,
        )
    assert provider.expected == []


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
        try:
            return Secret(self.values[(reference.service, reference.account)])
        except KeyError:
            raise CredentialError("secret does not exist") from None


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
    bootstrap = claimed_bootstrap(database)
    bootstrap.enroll_password(
        "correct horse battery staple", claimant_token=CLAIMANT_TOKEN, now=100
    )

    issued = enrollments.begin(
        USER_ID,
        "Phone app",
        flow="bootstrap",
        session_id=None,
        now=100,
    )
    assert secret not in repr(issued)
    assert issued.manual_key == secret
    restarted = TotpEnrollmentService(
        database,
        provisioner=_TotpProvisioner(store, secret),
        secret_store=store,
        lifetime=120,
    )
    resumed = restarted.resume(
        issued.enrollment.enrollment_id,
        user_id=USER_ID,
        session_id=None,
        now=101,
    )
    assert resumed.manual_key == secret
    assert resumed.enrollment.enrollment_id == issued.enrollment.enrollment_id
    with pytest.raises(InvalidTotpEnrollment):
        restarted.resume(
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
    with pytest.raises(InvalidTotpEnrollment):
        restarted.resume(
            issued.enrollment.enrollment_id,
            user_id=USER_ID,
            session_id=None,
            now=120,
        )
    status = bootstrap.enroll_totp(verified, claimant_token=CLAIMANT_TOKEN, now=121)
    assert status.factor_labels == ("Phone app",)
    assert bootstrap.complete(claimant_token=CLAIMANT_TOKEN, now=122).complete
    assert secret.encode() not in database.path.read_bytes()
