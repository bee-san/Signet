from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from typing import Any

import pyotp
import pytest

from signet.auth import (
    AuthenticationRateLimited,
    InMemoryAttemptLimiter,
    PasswordCredential,
    ProofCapability,
    SessionManager,
    SQLitePasswordCredentialRepository,
    SQLiteSessionRepository,
    totp_factor_rate_limit_key,
)
from signet.authenticator_management import (
    AuthenticatorManager,
    FactorManagementError,
    FactorProofInvalid,
    FactorReplay,
    FactorUnavailable,
    LastAuthenticatorError,
    RecoveryPolicy,
)
from signet.browser_auth import (
    BootstrapClaimRequired,
    BootstrapError,
    BootstrapService,
    BrowserAuthController,
    ManagementIntent,
)
from signet.credential_broker import CredentialError, Secret, SecretReference
from signet.db import Database, IntegrityError
from signet.totp import (
    InvalidTotp,
    SQLiteTotpCredentialRepository,
    TotpCredential,
    TotpVerifier,
)
from signet.totp_enrollment import (
    TotpEnrollmentCleanupError,
    TotpEnrollmentRateLimited,
    TotpEnrollmentService,
)
from signet.webauthn import (
    FakeAssertion,
    FakeWebAuthnProvider,
    SQLiteWebAuthnRepository,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnChallengeUnavailable,
    WebAuthnCredential,
)
from signet.webauthn_registration import PasskeyRegistrationService, RegistrationResult

USER_ID = "human"
OTHER_USER_ID = "other"
SESSION_KEY = b"authenticator-management-session-key"
CAPABILITY_KEY = b"authenticator-management-proof-key"
CAPABILITIES = ProofCapability(CAPABILITY_KEY)
RP_ID = "approval.example.test"
ORIGIN = f"https://{RP_ID}"
CLAIMANT_TOKEN = "bootstrap-claimant-token-long-enough"


class RecordingProvisioner:
    """Test-only provisioning boundary that never returns seed material."""

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], str] = {
            ("Signet", "bootstrap"): "bootstrap-seed",
            ("Signet", "second-bootstrap"): "second-bootstrap-seed",
        }
        self.created_references: list[str] = []
        self.deleted_references: list[str] = []

    def create(self, factor_id: str) -> str:
        account = f"managed-{len(self.created_references) + 1}-{factor_id}"
        reference = f"keychain://Signet/{account}"
        self._values[("Signet", account)] = f"unique-seed-{len(self.created_references) + 1}"
        self.created_references.append(reference)
        return reference

    def delete(self, reference: str) -> None:
        selected = SecretReference.parse(reference)
        self._values.pop((selected.service, selected.account), None)
        self.deleted_references.append(reference)

    def get(self, reference: SecretReference) -> Secret:
        try:
            return Secret(self._values[(reference.service, reference.account)])
        except KeyError as exc:
            raise CredentialError("test secret is unavailable") from exc


class FailingCleanupProvisioner(RecordingProvisioner):
    def __init__(self) -> None:
        super().__init__()
        self.fail_cleanup = True

    def delete(self, reference: str) -> None:
        if self.fail_cleanup:
            raise CredentialError("injected Keychain cleanup failure")
        super().delete(reference)


class AlreadyMissingCleanupProvisioner(RecordingProvisioner):
    def delete(self, reference: str) -> None:
        super().delete(reference)
        raise CredentialError("test backend reports an already-missing secret")


class SecretBoundTotpProvider:
    test_only = True

    def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None:
        del now
        return 77 if proof == f"fake:{secret.reveal()}" else None


class CountingRegistrationProvider:
    test_only = True

    def __init__(self) -> None:
        self.verify_calls = 0

    def verify(self, *args: object, **kwargs: object) -> RegistrationResult:
        del args, kwargs
        self.verify_calls += 1
        raise AssertionError("registration verification was not expected")


class SuccessfulRegistrationProvider:
    test_only = True

    def __init__(self) -> None:
        self.credential_id = (
            base64.urlsafe_b64encode(b"atomic-passkey-credential").rstrip(b"=").decode("ascii")
        )

    def verify(self, *args: object, **kwargs: object) -> RegistrationResult:
        del args, kwargs
        return RegistrationResult(
            credential_id=self.credential_id,
            public_key=b"atomic-passkey-public-key",
            sign_count=0,
            device_type="single_device",
            backed_up=False,
            transports=("internal",),
            discoverable=True,
        )


@pytest.fixture
def database(tmp_path: Path) -> Database:
    selected = Database(tmp_path / "signet.sqlite3")
    selected.initialize()
    return selected


def session(database: Database, user_id: str = USER_ID, *, now: int = 100) -> tuple[str, str]:
    manager = SessionManager(
        SQLiteSessionRepository(database),
        signing_key=SESSION_KEY,
        idle_timeout=300,
        absolute_timeout=1_000,
    )
    token = manager.create_session(user_id, auth_method="preauth", now=now)
    return token, manager.authenticate(token, now=now).session_id


def bootstrap_totp(
    database: Database,
    *,
    credential_id: str = "totp-bootstrap",
    reference: str = "keychain://Signet/bootstrap",
    now: int = 10,
) -> None:
    SQLiteTotpCredentialRepository(database).add_totp(
        TotpCredential(credential_id, USER_ID, reference),
        now=now,
    )


def manager(database: Database, provisioner: RecordingProvisioner) -> AuthenticatorManager:
    return AuthenticatorManager(
        database,
        provisioner=provisioner,
        capabilities=CAPABILITIES,
        web_session_idle_timeout=300,
    )


def totp_verifier(
    database: Database,
    provisioner: RecordingProvisioner,
    *,
    limiter: InMemoryAttemptLimiter | None = None,
) -> TotpVerifier:
    return TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        provisioner,
        limiter or InMemoryAttemptLimiter(),
        capabilities=CAPABILITIES,
        provider=SecretBoundTotpProvider(),
        allow_test_provider=True,
    )


def browser_controller(
    database: Database,
    provisioner: RecordingProvisioner,
    *,
    registration_provider: (
        CountingRegistrationProvider | SuccessfulRegistrationProvider | None
    ) = None,
) -> BrowserAuthController:
    webauthn_repository = SQLiteWebAuthnRepository(database)
    return BrowserAuthController(
        bootstrap=BootstrapService(database, owner_user_id=USER_ID),
        registrations=PasskeyRegistrationService(
            database,
            provider=registration_provider or CountingRegistrationProvider(),
            rp_id=RP_ID,
            origin=ORIGIN,
            allow_test_provider=True,
        ),
        manager=manager(database, provisioner),
        totp_verifier=totp_verifier(database, provisioner),
        webauthn_issuer=WebAuthnChallengeIssuer(
            webauthn_repository,
            rp_id=RP_ID,
            origin=ORIGIN,
        ),
        webauthn_verifier=WebAuthnAssertionVerifier(
            webauthn_repository,
            rp_id=RP_ID,
            origin=ORIGIN,
            capabilities=CAPABILITIES,
            provider=FakeWebAuthnProvider(),
            allow_test_provider=True,
        ),
        webauthn_repository=webauthn_repository,
        totp_enrollments=TotpEnrollmentService(
            database,
            provisioner=provisioner,
            secret_store=provisioner,
        ),
    )


def test_bootstrap_reissue_serializes_with_passkey_enrollment_start(
    database: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioner = RecordingProvisioner()
    controller = browser_controller(database, provisioner)
    capability = controller.bootstrap.issue_capability(now=100, lifetime=60)
    controller.bootstrap.claim(capability, CLAIMANT_TOKEN, now=101)
    original_begin = controller.registrations.begin

    def begin_after_reissue(*args: Any, **kwargs: Any) -> Any:
        replacement = controller.bootstrap.issue_capability(now=160, lifetime=60)
        controller.bootstrap.claim(replacement, CLAIMANT_TOKEN, now=161)
        return original_begin(*args, **kwargs)

    monkeypatch.setattr(controller.registrations, "begin", begin_after_reissue)

    with pytest.raises(BootstrapClaimRequired):
        controller.begin_registration(
            USER_ID,
            "Stale passkey",
            flow="bootstrap",
            session_id=None,
            claimant_token=CLAIMANT_TOKEN,
            now=159,
        )

    with database.read() as connection:
        count = connection.execute(
            "SELECT count(*) FROM auth_registration_challenges WHERE flow = 'bootstrap'"
        ).fetchone()[0]
    assert count == 0


def test_bootstrap_reissue_serializes_with_totp_enrollment_start(
    database: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioner = RecordingProvisioner()
    controller = browser_controller(database, provisioner)
    capability = controller.bootstrap.issue_capability(now=100, lifetime=60)
    controller.bootstrap.claim(capability, CLAIMANT_TOKEN, now=101)
    assert controller.totp_enrollments is not None
    original_begin = controller.totp_enrollments.begin

    def begin_after_reissue(*args: Any, **kwargs: Any) -> Any:
        replacement = controller.bootstrap.issue_capability(now=160, lifetime=60)
        controller.bootstrap.claim(replacement, CLAIMANT_TOKEN, now=161)
        return original_begin(*args, **kwargs)

    monkeypatch.setattr(controller.totp_enrollments, "begin", begin_after_reissue)

    with pytest.raises(BootstrapClaimRequired):
        controller.begin_totp_enrollment(
            USER_ID,
            "Stale TOTP",
            flow="bootstrap",
            session_id=None,
            claimant_token=CLAIMANT_TOKEN,
            now=159,
        )

    with database.read() as connection:
        count = connection.execute(
            "SELECT count(*) FROM browser_totp_enrollments WHERE flow = 'bootstrap'"
        ).fetchone()[0]
    assert count == 0
    assert provisioner.created_references == []


def confirm_totp(
    selected: AuthenticatorManager,
    verifier: TotpVerifier,
    *,
    binding: object,
    credential_id: str,
    proof: str,
    session_id: str,
    now: int,
):
    return verifier.verify(
        USER_ID,
        proof,
        binding=binding,  # type: ignore[arg-type]
        credential_id=credential_id,
        session_id=session_id,
        http_method="POST",
        now=now,
    )


def web_credential(credential_id: str, *, sign_count: int = 7) -> WebAuthnCredential:
    return WebAuthnCredential(
        credential_id=credential_id,
        user_id=USER_ID,
        user_handle=b"factor-management-user-handle",
        public_key=b"explicit-fake-public-key",
        sign_count=sign_count,
        device_type="single_device",
        backed_up=False,
        transports=("internal", "hybrid"),
        discoverable=True,
    )


def test_multiple_totps_are_independent_and_listing_never_exposes_secrets(
    database: Database,
) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    selected = manager(database, provisioner)
    verifier = totp_verifier(database, provisioner)
    _, session_id = session(database)

    binding = selected.binding_for_add_totp(USER_ID, "Travel phone", operation_id="op-add-1")
    confirmation = confirm_totp(
        selected,
        verifier,
        binding=binding,
        credential_id="totp-bootstrap",
        proof="fake:bootstrap-seed",
        session_id=session_id,
        now=101,
    )
    added = selected.add_totp(
        USER_ID,
        "Travel phone",
        operation_id="op-add-1",
        confirmation=confirmation,
        now=101,
    )

    factors = selected.list_factors(USER_ID)
    assert len(factors) == 2
    assert len({factor.factor_id for factor in factors}) == 2
    assert len({factor.credential_id for factor in factors}) == 2
    assert added.label == "Travel phone"
    assert added.kind == "totp"
    assert added.state == "active"
    assert added.created_audit_ref is not None
    serialized = repr(factors)
    assert "bootstrap-seed" not in serialized
    assert "unique-seed" not in serialized
    assert "secret_reference" not in serialized
    with database.read() as connection:
        secret_reference = connection.execute(
            "SELECT secret_reference FROM auth_credentials WHERE credential_id = ?",
            (added.credential_id,),
        ).fetchone()[0]
    assert provisioner.created_references == [secret_reference]

    verified_added = verifier.verify(
        USER_ID,
        "fake:unique-seed-1",
        binding=selected.binding_for_rename(
            USER_ID,
            added.factor_id,
            "Renamed phone",
            operation_id="op-rename-1",
        ),
        credential_id=added.credential_id,
        session_id=session(database, now=110)[1],
        http_method="POST",
        now=111,
    )
    assert verified_added.credential_id == added.credential_id
    with pytest.raises(InvalidTotp):
        verifier.verify(
            USER_ID,
            "fake:bootstrap-seed",
            binding=verified_added.binding,
            credential_id=added.credential_id,
            session_id=verified_added.session_id,
            http_method="POST",
            now=111,
        )


def test_totp_selected_factor_also_consumes_the_aggregate_user_limit(
    database: Database,
) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    bootstrap_totp(
        database,
        credential_id="totp-second",
        reference="keychain://Signet/second-bootstrap",
        now=11,
    )
    limiter = InMemoryAttemptLimiter(lock_schedule=((2, 60),))
    verifier = totp_verifier(database, provisioner, limiter=limiter)
    binding = manager(database, provisioner).binding_for_rename(
        USER_ID,
        manager(database, provisioner).list_factors(USER_ID)[0].factor_id,
        "Any label",
        operation_id="op-rate-limit",
    )
    _, session_id = session(database)

    for timestamp in (101, 102):
        with pytest.raises(InvalidTotp):
            verifier.verify(
                USER_ID,
                "fake:wrong",
                binding=binding,
                credential_id="totp-bootstrap",
                source_id=f"source-{timestamp}",
                session_id=session_id,
                http_method="POST",
                now=timestamp,
            )
    assert limiter.state(totp_factor_rate_limit_key(USER_ID, "totp-bootstrap")).failures == 2
    assert limiter.state(totp_factor_rate_limit_key(USER_ID, "totp-second")).failures == 0
    with pytest.raises(AuthenticationRateLimited):
        verifier.verify(
            USER_ID,
            "fake:second-bootstrap-seed",
            binding=binding,
            credential_id="totp-second",
            source_id="unlocked-source",
            session_id=session_id,
            http_method="POST",
            now=103,
        )


def test_management_enrollment_has_zero_side_effects_until_fresh_factor_authorization(
    database: Database,
) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    _, session_id = session(database)
    registration_provider = CountingRegistrationProvider()
    controller = browser_controller(
        database,
        provisioner,
        registration_provider=registration_provider,
    )

    with pytest.raises(BootstrapError, match="issued authorization"):
        controller.apply_with_totp(
            USER_ID,
            session_id,
            ManagementIntent(
                action="add_totp",
                label="New phone",
                operation_id="operation-bypass-enrollment-001",
                registration_id="attacker-controlled-registration",
            ),
            "fake:bootstrap-seed",
            source_id="test-source",
            credential_id="totp-bootstrap",
            now=101,
        )
    with pytest.raises(BootstrapClaimRequired):
        controller.begin_registration(
            USER_ID,
            "New passkey",
            flow="management",
            session_id=session_id,
            now=101,
        )
    with pytest.raises(BootstrapClaimRequired):
        controller.begin_totp_enrollment(
            USER_ID,
            "New phone",
            flow="management",
            session_id=session_id,
            now=101,
        )
    intent = ManagementIntent(
        action="add_totp",
        label="New phone",
        operation_id="operation-add-totp-001",
    )
    with pytest.raises(InvalidTotp):
        controller.authorize_enrollment_with_totp(
            USER_ID,
            session_id,
            intent,
            "fake:wrong",
            source_id="test-source",
            credential_id="totp-bootstrap",
            now=102,
        )

    with database.read() as connection:
        assert (
            connection.execute("SELECT count(*) FROM auth_registration_challenges").fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT count(*) FROM browser_totp_enrollments").fetchone()[0] == 0
        )
        assert (
            connection.execute("SELECT count(*) FROM browser_enrollment_authorizations").fetchone()[
                0
            ]
            == 0
        )
    assert provisioner.created_references == []
    assert registration_provider.verify_calls == 0

    issued = controller.authorize_enrollment_with_totp(
        USER_ID,
        session_id,
        intent,
        "fake:bootstrap-seed",
        source_id="test-source",
        credential_id="totp-bootstrap",
        now=103,
    )
    assert issued.enrollment.authorization_id is not None
    assert issued.enrollment.operation_id == intent.operation_id
    assert len(provisioner.created_references) == 1
    with database.read() as connection:
        assert (
            connection.execute("SELECT count(*) FROM browser_totp_enrollments").fetchone()[0] == 1
        )
        assert (
            connection.execute("SELECT count(*) FROM browser_enrollment_authorizations").fetchone()[
                0
            ]
            == 1
        )


def test_totp_publication_and_pending_enrollment_consumption_are_atomic(
    database: Database,
) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    _, session_id = session(database)
    controller = browser_controller(database, provisioner)
    intent = ManagementIntent(
        action="add_totp",
        label="New phone",
        operation_id="operation-add-totp-atomic-001",
    )
    issued = controller.authorize_enrollment_with_totp(
        USER_ID,
        session_id,
        intent,
        "fake:bootstrap-seed",
        source_id="test-source",
        credential_id="totp-bootstrap",
        now=101,
    )
    enrollment = issued.enrollment
    reference = SecretReference.parse(enrollment.secret_reference)
    valid_seed = "JBSWY3DPEHPK3PXP"
    provisioner._values[(reference.service, reference.account)] = valid_seed
    verified = controller.verify_totp_enrollment(
        enrollment.enrollment_id,
        pyotp.TOTP(valid_seed).at(102),
        user_id=USER_ID,
        session_id=session_id,
        now=102,
    )
    assert verified.authorization_id is not None
    with database.transaction() as connection:
        connection.execute(
            """
            CREATE TRIGGER inject_totp_enrollment_consume_failure
            BEFORE UPDATE OF consumed_at ON browser_totp_enrollments
            WHEN NEW.consumed_at IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'injected enrollment consume failure'); END
            """
        )

    with pytest.raises(IntegrityError, match="injected enrollment consume failure"):
        controller.complete_authorized_enrollment(
            USER_ID,
            session_id,
            ManagementIntent(
                action="add_totp",
                operation_id=intent.operation_id,
                registration_id=enrollment.enrollment_id,
                authorization_id=verified.authorization_id,
            ),
            now=103,
        )

    with database.read() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM auth_credentials WHERE credential_id = ?",
                (enrollment.credential_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """
            SELECT consumed_at FROM browser_enrollment_authorizations
            WHERE authorization_id = ?
            """,
                (verified.authorization_id,),
            ).fetchone()[0]
            is None
        )
        assert (
            connection.execute(
                "SELECT consumed_at FROM browser_totp_enrollments WHERE enrollment_id = ?",
                (enrollment.enrollment_id,),
            ).fetchone()[0]
            is None
        )
    assert provisioner.get(reference).reveal() == valid_seed


def test_passkey_publication_and_registration_consumption_are_atomic(
    database: Database,
) -> None:
    provisioner = RecordingProvisioner()
    provider = SuccessfulRegistrationProvider()
    bootstrap_totp(database)
    _, session_id = session(database)
    controller = browser_controller(
        database,
        provisioner,
        registration_provider=provider,
    )
    intent = ManagementIntent(
        action="add_passkey",
        label="New passkey",
        operation_id="operation-add-passkey-atomic-001",
    )
    issued = controller.authorize_enrollment_with_totp(
        USER_ID,
        session_id,
        intent,
        "fake:bootstrap-seed",
        source_id="test-source",
        credential_id="totp-bootstrap",
        now=101,
    )
    challenge_id = issued.challenge_id  # type: ignore[union-attr]
    pending = controller.complete_registration(
        challenge_id,
        {},
        user_id=USER_ID,
        session_id=session_id,
        now=102,
    )
    assert pending.authorization_id is not None
    with database.transaction() as connection:
        connection.execute(
            """
            CREATE TRIGGER inject_passkey_registration_consume_failure
            BEFORE UPDATE OF consumed_at ON auth_registration_challenges
            WHEN NEW.consumed_at IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'injected registration consume failure'); END
            """
        )

    with pytest.raises(IntegrityError, match="injected registration consume failure"):
        controller.complete_authorized_enrollment(
            USER_ID,
            session_id,
            ManagementIntent(
                action="add_passkey",
                operation_id=intent.operation_id,
                registration_id=challenge_id,
                authorization_id=pending.authorization_id,
            ),
            now=103,
        )

    with database.read() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM auth_credentials WHERE credential_id = ?",
                (provider.credential_id,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """
            SELECT consumed_at FROM browser_enrollment_authorizations
            WHERE authorization_id = ?
            """,
                (pending.authorization_id,),
            ).fetchone()[0]
            is None
        )
        assert (
            connection.execute(
                "SELECT consumed_at FROM auth_registration_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()[0]
            is None
        )


def test_totp_enrollment_caps_precede_provisioning_and_cleanup_failures_are_retryable(
    database: Database,
) -> None:
    provisioner = FailingCleanupProvisioner()
    service = TotpEnrollmentService(
        database,
        provisioner=provisioner,
        secret_store=provisioner,
        lifetime=10,
        max_active_per_user=1,
        max_active_per_session=1,
    )
    issued = service.begin(
        USER_ID,
        "Phone",
        flow="bootstrap",
        session_id=None,
        now=100,
    )
    with pytest.raises(TotpEnrollmentRateLimited):
        service.begin(
            USER_ID,
            "Second phone",
            flow="bootstrap",
            session_id=None,
            now=101,
        )
    assert len(provisioner.created_references) == 1

    with pytest.raises(TotpEnrollmentCleanupError):
        service.cleanup_expired(now=110)
    with database.read() as connection:
        row = connection.execute(
            """
            SELECT invalidated_at, cleanup_completed_at
            FROM browser_totp_enrollments WHERE enrollment_id = ?
            """,
            (issued.enrollment.enrollment_id,),
        ).fetchone()
    assert row is not None
    assert row["invalidated_at"] == 110
    assert row["cleanup_completed_at"] is None

    provisioner.fail_cleanup = False
    assert service.cleanup_expired(now=111) == 1
    assert issued.enrollment.secret_reference in provisioner.deleted_references
    replacement = service.begin(
        USER_ID,
        "Replacement phone",
        flow="bootstrap",
        session_id=None,
        now=112,
    )
    assert replacement.enrollment.enrollment_id != issued.enrollment.enrollment_id
    assert len(provisioner.created_references) == 2


def test_totp_cleanup_accepts_delete_error_only_after_absence_is_verified(
    database: Database,
) -> None:
    provisioner = AlreadyMissingCleanupProvisioner()
    service = TotpEnrollmentService(
        database,
        provisioner=provisioner,
        secret_store=provisioner,
        lifetime=10,
    )
    issued = service.begin(
        USER_ID,
        "Phone",
        flow="bootstrap",
        session_id=None,
        now=100,
    )

    assert service.cleanup_expired(now=110) == 1
    assert issued.enrollment.secret_reference in provisioner.deleted_references


def test_failed_totp_enrollment_insert_retains_retryable_cleanup_debt(
    database: Database,
) -> None:
    provisioner = FailingCleanupProvisioner()
    service = TotpEnrollmentService(
        database,
        provisioner=provisioner,
        secret_store=provisioner,
    )
    with database.transaction() as connection:
        connection.execute(
            """
            CREATE TRIGGER inject_active_totp_enrollment_insert_failure
            BEFORE INSERT ON browser_totp_enrollments
            WHEN NEW.invalidated_at IS NULL
            BEGIN SELECT RAISE(ABORT, 'injected active enrollment insert failure'); END
            """
        )

    with pytest.raises(TotpEnrollmentCleanupError, match="cleanup"):
        service.begin(
            USER_ID,
            "Phone",
            flow="bootstrap",
            session_id=None,
            now=100,
        )

    with database.read() as connection:
        row = connection.execute(
            """
            SELECT invalidated_at, cleanup_completed_at
            FROM browser_totp_enrollments
            """
        ).fetchone()
    assert row is not None
    assert row["invalidated_at"] == 100
    assert row["cleanup_completed_at"] is None
    provisioner.fail_cleanup = False
    assert service.cleanup_expired(now=101) == 1
    assert len(provisioner.deleted_references) == 1


def test_management_proofs_are_action_bound_fresh_and_single_use(database: Database) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    selected = manager(database, provisioner)
    existing = selected.list_factors(USER_ID)[0]
    _, session_id = session(database)
    verifier = totp_verifier(database, provisioner)
    rename_binding = selected.binding_for_rename(
        USER_ID,
        existing.factor_id,
        "Laptop authenticator",
        operation_id="op-rename",
    )
    proof = confirm_totp(
        selected,
        verifier,
        binding=rename_binding,
        credential_id=existing.credential_id,
        proof="fake:bootstrap-seed",
        session_id=session_id,
        now=101,
    )

    with pytest.raises(FactorProofInvalid, match="binding"):
        selected.rename_factor(
            USER_ID,
            existing.factor_id,
            "Different label",
            operation_id="op-rename",
            confirmation=proof,
            now=101,
        )
    renamed = selected.rename_factor(
        USER_ID,
        existing.factor_id,
        "Laptop authenticator",
        operation_id="op-rename",
        confirmation=proof,
        now=101,
    )
    assert renamed.label == "Laptop authenticator"
    with pytest.raises(FactorReplay):
        selected.rename_factor(
            USER_ID,
            existing.factor_id,
            "Laptop authenticator",
            operation_id="op-rename",
            confirmation=proof,
            now=101,
        )

    _, new_session_id = session(database, now=110)
    stale_binding = selected.binding_for_rename(
        USER_ID,
        existing.factor_id,
        "Too late",
        operation_id="op-stale",
    )
    stale = confirm_totp(
        selected,
        verifier,
        binding=stale_binding,
        credential_id=existing.credential_id,
        proof="fake:bootstrap-seed",
        session_id=new_session_id,
        now=111,
    )
    with pytest.raises(FactorProofInvalid, match="fresh"):
        selected.rename_factor(
            USER_ID,
            existing.factor_id,
            "Too late",
            operation_id="op-stale",
            confirmation=stale,
            now=111 + selected.proof_lifetime,
        )


def test_totp_replacement_can_reuse_the_existing_factor_label(database: Database) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    selected = manager(database, provisioner)
    existing = selected.list_factors(USER_ID)[0]
    _, session_id = session(database)
    binding = selected.binding_for_replace_totp(
        USER_ID,
        existing.factor_id,
        existing.label,
        operation_id="op-replace-same-label",
    )
    proof = confirm_totp(
        selected,
        totp_verifier(database, provisioner),
        binding=binding,
        credential_id=existing.credential_id,
        proof="fake:bootstrap-seed",
        session_id=session_id,
        now=101,
    )

    replacement = selected.replace_totp(
        USER_ID,
        existing.factor_id,
        existing.label,
        operation_id="op-replace-same-label",
        confirmation=proof,
        now=101,
    )

    assert replacement.factor_id != existing.factor_id
    assert replacement.label == existing.label
    assert tuple(
        factor.factor_id for factor in selected.list_factors(USER_ID, include_inactive=False)
    ) == (replacement.factor_id,)
    replaced = selected.get_factor(USER_ID, existing.factor_id)
    assert replaced is not None and replaced.state == "revoked"


def test_lost_factor_can_be_revoked_by_another_but_never_leaves_zero_factors(
    database: Database,
) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    bootstrap_totp(
        database,
        credential_id="totp-second",
        reference="keychain://Signet/second-bootstrap",
        now=11,
    )
    selected = manager(database, provisioner)
    first, second = selected.list_factors(USER_ID)
    _, session_id = session(database)
    binding = selected.binding_for_revoke(
        USER_ID,
        first.factor_id,
        compromised=True,
        operation_id="op-lost",
    )
    proof = confirm_totp(
        selected,
        totp_verifier(database, provisioner),
        binding=binding,
        credential_id=second.credential_id,
        proof="fake:second-bootstrap-seed",
        session_id=session_id,
        now=101,
    )
    revoked = selected.revoke_factor(
        USER_ID,
        first.factor_id,
        compromised=True,
        operation_id="op-lost",
        confirmation=proof,
        now=101,
    )
    assert revoked.state == "compromised"
    assert tuple(
        factor.factor_id for factor in selected.list_factors(USER_ID, include_inactive=False)
    ) == (second.factor_id,)
    assert tuple(
        factor.factor_id
        for factor in browser_controller(database, provisioner).list_factors(USER_ID)
    ) == (second.factor_id,)

    _, new_session_id = session(database, now=110)
    last_binding = selected.binding_for_revoke(
        USER_ID,
        second.factor_id,
        compromised=False,
        operation_id="op-last",
    )
    last_proof = confirm_totp(
        selected,
        totp_verifier(database, provisioner),
        binding=last_binding,
        credential_id=second.credential_id,
        proof="fake:second-bootstrap-seed",
        session_id=new_session_id,
        now=111,
    )
    with pytest.raises(LastAuthenticatorError):
        selected.revoke_factor(
            USER_ID,
            second.factor_id,
            compromised=False,
            operation_id="op-last",
            confirmation=last_proof,
            now=111,
        )


def test_passkey_has_distinct_factor_and_credential_ids_and_can_confirm_management(
    database: Database,
) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    selected = manager(database, provisioner)
    _, session_id = session(database)
    passkey_id = base64.urlsafe_b64encode(b"new-management-passkey").rstrip(b"=").decode()
    binding = selected.binding_for_add_passkey(
        USER_ID,
        "Hardware passkey",
        web_credential(passkey_id),
        operation_id="op-add-passkey",
    )
    proof = confirm_totp(
        selected,
        totp_verifier(database, provisioner),
        binding=binding,
        credential_id="totp-bootstrap",
        proof="fake:bootstrap-seed",
        session_id=session_id,
        now=101,
    )
    passkey = selected.add_passkey(
        USER_ID,
        "Hardware passkey",
        web_credential(passkey_id),
        operation_id="op-add-passkey",
        confirmation=proof,
        now=101,
    )
    assert passkey.factor_id != passkey.credential_id
    assert passkey.credential_id == passkey_id
    assert passkey.transports == ("internal", "hybrid")
    assert passkey.discoverable is True
    assert passkey.device_type == "single_device"
    assert passkey.backed_up is False
    assert "public" not in repr(passkey).lower()

    _, next_session_id = session(database, now=110)
    rename_binding = selected.binding_for_rename(
        USER_ID,
        passkey.factor_id,
        "Desk passkey",
        operation_id="op-passkey-rename",
    )
    repository = SQLiteWebAuthnRepository(database)
    issued = WebAuthnChallengeIssuer(repository, rp_id=RP_ID, origin=ORIGIN).issue(
        USER_ID,
        rename_binding,
        session_id=next_session_id,
        http_method="POST",
        now=111,
    )
    stored = repository.find_challenge(issued.challenge_id)
    assert stored is not None
    with pytest.raises(WebAuthnChallengeUnavailable):
        WebAuthnAssertionVerifier(
            repository,
            rp_id="alternate.example",
            origin="https://alternate.example",
            capabilities=CAPABILITIES,
            provider=FakeWebAuthnProvider(),
            allow_test_provider=True,
        ).verify(
            FakeAssertion(
                credential_id=passkey_id,
                user_handle=b"factor-management-user-handle",
                challenge=stored.challenge,
                origin="https://alternate.example",
                rp_id="alternate.example",
                new_sign_count=8,
            ),
            challenge_id=issued.challenge_id,
            user_id=USER_ID,
            binding=rename_binding,
            session_id=next_session_id,
            http_method="POST",
            now=112,
        )
    verified = WebAuthnAssertionVerifier(
        repository,
        rp_id=RP_ID,
        origin=ORIGIN,
        capabilities=CAPABILITIES,
        provider=FakeWebAuthnProvider(),
        allow_test_provider=True,
    ).verify(
        FakeAssertion(
            credential_id=passkey_id,
            user_handle=b"factor-management-user-handle",
            challenge=stored.challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
            new_sign_count=8,
        ),
        challenge_id=issued.challenge_id,
        user_id=USER_ID,
        binding=rename_binding,
        session_id=next_session_id,
        http_method="POST",
        now=112,
    )
    assert (
        selected.rename_factor(
            USER_ID,
            passkey.factor_id,
            "Desk passkey",
            operation_id="op-passkey-rename",
            confirmation=verified,
            now=112,
        ).label
        == "Desk passkey"
    )
    with pytest.raises(FactorReplay):
        selected.rename_factor(
            USER_ID,
            passkey.factor_id,
            "Desk passkey",
            operation_id="op-passkey-rename",
            confirmation=verified,
            now=112,
        )


def test_add_passkey_proof_binds_complete_credential(database: Database) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    selected = manager(database, provisioner)
    _, session_id = session(database)
    passkey_id = base64.urlsafe_b64encode(b"bound-management-passkey").rstrip(b"=").decode()
    credential = web_credential(passkey_id)
    binding = selected.binding_for_add_passkey(
        USER_ID,
        "Bound passkey",
        credential,
        operation_id="op-bound-passkey",
    )
    proof = confirm_totp(
        selected,
        totp_verifier(database, provisioner),
        binding=binding,
        credential_id="totp-bootstrap",
        proof="fake:bootstrap-seed",
        session_id=session_id,
        now=101,
    )

    with pytest.raises(FactorProofInvalid, match="binding"):
        selected.add_passkey(
            USER_ID,
            "Bound passkey",
            replace(credential, public_key=b"substituted-public-key"),
            operation_id="op-bound-passkey",
            confirmation=proof,
            now=101,
        )


def test_password_record_does_not_bypass_last_authenticator_guard(database: Database) -> None:
    provisioner = RecordingProvisioner()
    SQLitePasswordCredentialRepository(database).replace_password(
        PasswordCredential("password-main", USER_ID, "$argon2id$test-verifier"),
        now=9,
    )
    bootstrap_totp(database)
    selected = manager(database, provisioner)
    totp_factor = next(factor for factor in selected.list_factors(USER_ID) if factor.kind == "totp")
    _, session_id = session(database)
    binding = selected.binding_for_revoke(
        USER_ID,
        totp_factor.factor_id,
        compromised=False,
        operation_id="op-password-is-not-an-authenticator",
    )
    proof = confirm_totp(
        selected,
        totp_verifier(database, provisioner),
        binding=binding,
        credential_id=totp_factor.credential_id,
        proof="fake:bootstrap-seed",
        session_id=session_id,
        now=101,
    )

    with pytest.raises(LastAuthenticatorError):
        selected.revoke_factor(
            USER_ID,
            totp_factor.factor_id,
            compromised=False,
            operation_id="op-password-is-not-an-authenticator",
            confirmation=proof,
            now=101,
        )

    password_factor = next(
        factor for factor in selected.list_factors(USER_ID) if factor.kind == "password"
    )
    password_binding = selected.binding_for_revoke(
        USER_ID,
        password_factor.factor_id,
        compromised=False,
        operation_id="op-password-revoke",
    )
    password_proof = confirm_totp(
        selected,
        totp_verifier(database, provisioner),
        binding=password_binding,
        credential_id=totp_factor.credential_id,
        proof="fake:bootstrap-seed",
        session_id=session_id,
        now=102,
    )
    with pytest.raises(FactorUnavailable, match="password"):
        selected.revoke_factor(
            USER_ID,
            password_factor.factor_id,
            compromised=False,
            operation_id="op-password-revoke",
            confirmation=password_proof,
            now=102,
        )


def test_concurrent_revocations_cannot_bypass_last_factor_guard(database: Database) -> None:
    provisioner = RecordingProvisioner()
    bootstrap_totp(database)
    bootstrap_totp(
        database,
        credential_id="totp-second",
        reference="keychain://Signet/second-bootstrap",
        now=11,
    )
    selected = manager(database, provisioner)
    first, second = selected.list_factors(USER_ID)
    first_session = session(database, now=100)[1]
    second_session = session(database, now=100)[1]
    verifier = totp_verifier(database, provisioner)
    first_binding = selected.binding_for_revoke(
        USER_ID, first.factor_id, compromised=False, operation_id="op-race-first"
    )
    second_binding = selected.binding_for_revoke(
        USER_ID, second.factor_id, compromised=False, operation_id="op-race-second"
    )
    first_proof = confirm_totp(
        selected,
        verifier,
        binding=first_binding,
        credential_id=second.credential_id,
        proof="fake:second-bootstrap-seed",
        session_id=first_session,
        now=101,
    )
    second_proof = confirm_totp(
        selected,
        verifier,
        binding=second_binding,
        credential_id=first.credential_id,
        proof="fake:bootstrap-seed",
        session_id=second_session,
        now=101,
    )
    barrier = Barrier(2)

    def revoke(factor_id: str, operation_id: str, confirmation: object) -> str:
        barrier.wait()
        try:
            selected.revoke_factor(
                USER_ID,
                factor_id,
                compromised=False,
                operation_id=operation_id,
                confirmation=confirmation,  # type: ignore[arg-type]
                now=102,
            )
        except FactorManagementError as exc:
            return type(exc).__name__
        return "revoked"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(
            pool.map(
                lambda arguments: revoke(*arguments),
                (
                    (first.factor_id, "op-race-first", first_proof),
                    (second.factor_id, "op-race-second", second_proof),
                ),
            )
        )
    assert results.count("revoked") == 1
    assert len(selected.list_factors(USER_ID, include_inactive=False)) == 1


def test_recovery_policy_is_explicit_and_fail_closed(database: Database) -> None:
    provisioner = RecordingProvisioner()
    selected = AuthenticatorManager(
        database,
        provisioner=provisioner,
        capabilities=CAPABILITIES,
        recovery_policy=RecoveryPolicy(),
    )
    with pytest.raises(LastAuthenticatorError, match="recovery"):
        selected.recover_totp(
            OTHER_USER_ID,
            "Recovery phone",
            operation_id="op-recovery",
            now=100,
        )

    enabled = AuthenticatorManager(
        database,
        provisioner=provisioner,
        capabilities=CAPABILITIES,
        recovery_policy=RecoveryPolicy(allow_bootstrap_without_factor=True),
    )
    recovered = enabled.recover_totp(
        OTHER_USER_ID,
        "Recovery phone",
        operation_id="op-recovery",
        now=100,
    )
    assert recovered.user_id == OTHER_USER_ID
    assert recovered.state == "active"
