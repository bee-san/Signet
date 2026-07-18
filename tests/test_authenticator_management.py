from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from signet.auth import (
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
from signet.credential_broker import CredentialError, Secret, SecretReference
from signet.db import Database
from signet.totp import (
    InvalidTotp,
    SQLiteTotpCredentialRepository,
    TotpCredential,
    TotpVerifier,
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

USER_ID = "human"
OTHER_USER_ID = "other"
SESSION_KEY = b"authenticator-management-session-key"
CAPABILITY_KEY = b"authenticator-management-proof-key"
CAPABILITIES = ProofCapability(CAPABILITY_KEY)
RP_ID = "approval.example.test"
ORIGIN = f"https://{RP_ID}"


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


class SecretBoundTotpProvider:
    test_only = True

    def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None:
        del now
        return 77 if proof == f"fake:{secret.reveal()}" else None


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


def test_totp_selected_factor_has_an_independent_rate_limit(database: Database) -> None:
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
    assert (
        verifier.verify(
            USER_ID,
            "fake:second-bootstrap-seed",
            binding=binding,
            credential_id="totp-second",
            source_id="unlocked-source",
            session_id=session_id,
            http_method="POST",
            now=103,
        ).credential_id
        == "totp-second"
    )


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
