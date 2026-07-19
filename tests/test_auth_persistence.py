from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest
from argon2 import PasswordHasher

from signet.auth import (
    TOTP_PROOF_DOMAIN,
    ActionBinding,
    Argon2PasswordVerifier,
    AuthenticationError,
    AuthenticationRateLimited,
    InvalidCredentials,
    InvalidSession,
    PasswordAuthenticator,
    PasswordCredential,
    ProofCapability,
    SessionManager,
    SQLiteAttemptLimiter,
    SQLiteAuthenticationTransactions,
    SQLitePasswordCredentialRepository,
    SQLiteSessionRepository,
    source_rate_limit_key,
    totp_rate_limit_key,
)
from signet.credential_broker import MemorySecretStore
from signet.db import Database
from signet.models import (
    ApprovalConfirmation,
    ConfirmationKind,
    ConfirmationReplay,
    EnqueueRequest,
    InvalidConfirmation,
)
from signet.state_machine import ApprovalStateMachine
from signet.totp import (
    FakeTotpProvider,
    SQLiteTotpCredentialRepository,
    TotpCredential,
    TotpVerifier,
    VerifiedTotp,
)
from signet.webauthn import (
    FakeAssertion,
    FakeWebAuthnProvider,
    InvalidWebAuthnAssertion,
    SQLiteWebAuthnRepository,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnChallengeUnavailable,
    WebAuthnCredential,
)

SIGNING_KEY = b"persistent-session-signing-key-0001"
CAPABILITY_KEY = b"persistent-proof-capability-key-0001"
TEST_CAPABILITIES = ProofCapability(CAPABILITY_KEY)
RP_ID = "approval.example.test"
ORIGIN = f"https://{RP_ID}"
USER_ID = "human"
TOTP_REFERENCE = "keychain://Signet/persistent-totp"
WEB_CREDENTIAL_ID = base64.urlsafe_b64encode(b"persistent-credential-one").rstrip(b"=").decode()
SECOND_WEB_CREDENTIAL_ID = (
    base64.urlsafe_b64encode(b"persistent-credential-two").rstrip(b"=").decode()
)


@pytest.fixture
def database(tmp_path: Path) -> Database:
    value = Database(tmp_path / "approvals.sqlite3")
    value.initialize()
    return value


def restarted(database: Database) -> Database:
    value = Database(database.path)
    value.initialize()
    return value


def password_verifier() -> Argon2PasswordVerifier:
    return Argon2PasswordVerifier(
        PasswordHasher(
            time_cost=1,
            memory_cost=8_192,
            parallelism=1,
            hash_len=16,
            salt_len=16,
        )
    )


def web_credential(
    credential_id: str = WEB_CREDENTIAL_ID,
    *,
    sign_count: int = 7,
) -> WebAuthnCredential:
    return WebAuthnCredential(
        credential_id=credential_id,
        user_id=USER_ID,
        user_handle=b"persistent-user-handle",
        public_key=b"explicit-fake-public-key",
        sign_count=sign_count,
        device_type="single_device",
        backed_up=False,
    )


def preauth_session(database: Database, *, now: int) -> tuple[SessionManager, str, str]:
    manager = SessionManager(
        SQLiteSessionRepository(database),
        signing_key=SIGNING_KEY,
        idle_timeout=300,
        absolute_timeout=1_000,
    )
    token = manager.create_session(USER_ID, auth_method="preauth", now=now)
    principal = manager.authenticate(token, now=now)
    return manager, token, principal.session_id


def fake_assertion(
    challenge: bytes,
    *,
    credential_id: str = WEB_CREDENTIAL_ID,
    new_sign_count: int = 8,
) -> FakeAssertion:
    return FakeAssertion(
        credential_id=credential_id,
        user_handle=b"persistent-user-handle",
        challenge=challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
        new_sign_count=new_sign_count,
    )


def fake_webauthn_verifier(database: Database) -> WebAuthnAssertionVerifier:
    return WebAuthnAssertionVerifier(
        SQLiteWebAuthnRepository(database),
        rp_id=RP_ID,
        origin=ORIGIN,
        capabilities=TEST_CAPABILITIES,
        provider=FakeWebAuthnProvider(),
        allow_test_provider=True,
    )


def approval_request(request_id: str, *, now: int) -> EnqueueRequest:
    payload_hash = hashlib.sha256(b"approval-body").hexdigest()
    return EnqueueRequest(
        request_id=request_id,
        downstream_alias="test",
        tool_name="mutate",
        policy_mode="approval",
        origin_namespace="profile:test",
        encrypted_payload=b"encrypted",
        payload_hash=payload_hash,
        payload_fingerprint=hashlib.sha256(b"fingerprint").hexdigest(),
        pending_result=b"{}",
        created_at=now,
        expires_at=now + 600,
        policy_version="policy-1",
        adapter_version="adapter-1",
        schema_version="schema-1",
        editor_actor="caller:profile:test",
    )


def confirmation_from_totp(proof: VerifiedTotp) -> ApprovalConfirmation:
    binding = proof.binding
    reservation = proof.attempt_reservation
    return ApprovalConfirmation(
        kind=ConfirmationKind.TOTP,
        use_id=proof.use_id,
        path=("web" if proof.http_method == "POST" else "mcp"),
        capability=proof.capability,
        user_id=proof.user_id,
        action=binding.action,
        bound_request_id=binding.request_id,
        bound_version=binding.version,
        bound_payload_hash=binding.payload_hash,
        prospective_payload_hash=binding.prospective_payload_hash,
        session_id=proof.session_id,
        http_method=proof.http_method,
        attempt_id=reservation.attempt_id,
        attempt_scope_keys=reservation.scope_keys,
        rate_limit_key=proof.rate_limit_key,
        credential_id=proof.credential_id,
        credential_user_id=proof.user_id,
    )


def test_password_and_sessions_survive_restart_and_password_change_revokes(
    database: Database,
) -> None:
    verifier = password_verifier()
    passwords = SQLitePasswordCredentialRepository(database)
    passwords.replace_password(
        PasswordCredential("password-one", USER_ID, verifier._hasher.hash("correct horse")),
        now=10,
    )
    manager, token, _ = preauth_session(database, now=20)

    after_restart = restarted(database)
    restarted_manager = SessionManager(
        SQLiteSessionRepository(after_restart),
        signing_key=SIGNING_KEY,
        idle_timeout=300,
        absolute_timeout=1_000,
    )
    assert restarted_manager.authenticate(token, now=30).user_id == USER_ID
    authenticator = PasswordAuthenticator(
        SQLitePasswordCredentialRepository(after_restart),
        SQLiteAttemptLimiter(after_restart, lock_schedule=((10, 60),)),
        capabilities=TEST_CAPABILITIES,
        verifier=verifier,
    )
    assert (
        authenticator.authenticate(
            USER_ID,
            "correct horse",
            source_id="restart-test",
            now=31,
        ).credential_id
        == "password-one"
    )

    SQLitePasswordCredentialRepository(after_restart).replace_password(
        PasswordCredential("password-two", USER_ID, verifier._hasher.hash("new password")),
        now=40,
    )
    with pytest.raises(InvalidSession):
        manager.authenticate(token, now=41)
    with pytest.raises(InvalidCredentials):
        authenticator.authenticate(
            USER_ID,
            "correct horse",
            source_id="restart-test",
            now=42,
        )
    assert (
        authenticator.authenticate(
            USER_ID,
            "new password",
            source_id="restart-test",
            now=43,
        ).credential_id
        == "password-two"
    )
    with after_restart.read() as connection:
        factor_label = connection.execute(
            "SELECT factor_label FROM auth_credentials WHERE credential_id = 'password-two'"
        ).fetchone()[0]
    assert factor_label.startswith("Password ")


def test_persistent_session_clock_rollback_fails_closed(database: Database) -> None:
    manager, token, session_id = preauth_session(database, now=100)

    with pytest.raises(InvalidSession):
        manager.authenticate(token, now=99)
    with database.read() as connection:
        assert (
            connection.execute(
                "SELECT revoked_at FROM web_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]
            == 100
        )


def test_totp_and_webauthn_credential_changes_revoke_user_sessions(
    database: Database,
) -> None:
    totp = SQLiteTotpCredentialRepository(database)
    totp.replace_totp(TotpCredential("totp-one", USER_ID, TOTP_REFERENCE), now=10)
    manager, first_token, _ = preauth_session(database, now=20)

    restarted_totp = SQLiteTotpCredentialRepository(restarted(database))
    assert restarted_totp.find_totp(USER_ID) == TotpCredential("totp-one", USER_ID, TOTP_REFERENCE)
    restarted_totp.replace_totp(
        TotpCredential("totp-two", USER_ID, TOTP_REFERENCE),
        now=30,
    )
    with pytest.raises(InvalidSession):
        manager.authenticate(first_token, now=31)

    manager, second_token, _ = preauth_session(database, now=40)
    webauthn = SQLiteWebAuthnRepository(database)
    webauthn.add_credential(web_credential(), now=50)
    with pytest.raises(InvalidSession):
        manager.authenticate(second_token, now=51)
    assert SQLiteWebAuthnRepository(restarted(database)).credentials_for_user(USER_ID) == (
        web_credential(),
    )


def test_multiple_active_totp_factors_persist_and_can_be_disabled_independently(
    database: Database,
) -> None:
    repository = SQLiteTotpCredentialRepository(database)
    first = TotpCredential("totp-first", USER_ID, "keychain://Signet/totp-first")
    second = TotpCredential("totp-second", USER_ID, "keychain://Signet/totp-second")

    repository.add_totp(first, now=10)
    repository.add_totp(second, now=11)

    restarted_repository = SQLiteTotpCredentialRepository(restarted(database))
    assert restarted_repository.active_totps(USER_ID) == (first, second)
    assert restarted_repository.disable_totp("totp-first", USER_ID, now=12)
    assert restarted_repository.active_totps(USER_ID) == (second,)


def test_sqlite_rate_limit_reservations_are_atomic_and_durable(database: Database) -> None:
    barrier = Barrier(8)

    def reserve(index: int) -> bool:
        limiter = SQLiteAttemptLimiter(
            Database(database.path),
            lock_schedule=((3, 60),),
        )
        barrier.wait()
        try:
            limiter.reserve(
                "account:shared",
                source_key=f"source:{index}",
                now=100,
            )
        except AuthenticationRateLimited:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(8)))

    assert results.count(True) == 3
    limiter = SQLiteAttemptLimiter(restarted(database), lock_schedule=((3, 60),))
    state = limiter.state("account:shared")
    assert state.failures == 3
    assert state.locked_until == 160
    with pytest.raises(AuthenticationRateLimited) as locked:
        limiter.reserve("account:shared", source_key="source:late", now=159)
    assert locked.value.retry_after == 1
    assert limiter.reserve("account:shared", source_key="source:late", now=160)

    first = limiter.reserve("account:success", source_key="source:success", now=200)
    second = limiter.reserve("account:success", source_key="source:success", now=201)
    limiter.record_success(first, now=202)
    assert limiter.state("account:success").failures == 2
    SQLiteAttemptLimiter(Database(database.path)).record_success(second, now=203)
    assert limiter.state("account:success").failures == 0
    assert limiter.state("source:success").failures == 0


def test_sqlite_rate_limit_reservations_enforce_aggregate_scope_atomically(
    database: Database,
) -> None:
    limiter = SQLiteAttemptLimiter(database, lock_schedule=((2, 60),))
    first = limiter.reserve(
        "totp-factor:human:first",
        additional_scope_keys=("totp:human",),
        source_key="source:first",
        now=100,
    )
    limiter.record_failure(first, now=100)
    second = limiter.reserve(
        "totp-factor:human:second",
        additional_scope_keys=("totp:human",),
        source_key="source:second",
        now=101,
    )
    limiter.record_failure(second, now=101)

    restarted = SQLiteAttemptLimiter(Database(database.path), lock_schedule=((2, 60),))
    with pytest.raises(AuthenticationRateLimited):
        restarted.reserve(
            "totp-factor:human:third",
            additional_scope_keys=("totp:human",),
            source_key="source:third",
            now=102,
        )

    assert restarted.state("totp:human").failures == 2
    assert restarted.state("totp-factor:human:first").failures == 1
    assert restarted.state("totp-factor:human:second").failures == 1
    assert restarted.state("totp-factor:human:third").failures == 0
    assert restarted.state("source:third").failures == 0


def test_sqlite_rate_limiter_bounds_distributed_scope_storage(database: Database) -> None:
    limiter = SQLiteAttemptLimiter(
        database,
        lock_schedule=((10, 60),),
        global_window_seconds=60,
        global_attempt_limit=20,
        scope_retention_seconds=60,
        maximum_scope_rows=50,
    )
    for window in range(12):
        now = 1_000 + window * 60
        for index in range(20):
            limiter.reserve(
                f"account:{window}:{index}",
                source_key=f"source:{window}:{index}",
                now=now,
            )
        with pytest.raises(AuthenticationRateLimited):
            limiter.reserve(
                f"account:{window}:blocked",
                source_key=f"source:{window}:blocked",
                now=now,
            )

    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_attempts").fetchone()[0] <= 40
        global_row = connection.execute(
            "SELECT attempts, blocked_until FROM auth_rate_windows WHERE scope_key = 'auth:global'"
        ).fetchone()
    assert global_row is not None
    assert tuple(global_row) == (20, 1_720)


def test_persistent_webauthn_challenge_binds_session_method_action_and_offered_set(
    database: Database,
) -> None:
    repository = SQLiteWebAuthnRepository(database)
    repository.add_credential(web_credential(), now=10)
    _, _, session_id = preauth_session(database, now=20)
    binding = ActionBinding("login")
    issued = WebAuthnChallengeIssuer(repository, rp_id=RP_ID).issue(
        USER_ID,
        binding,
        session_id=session_id,
        http_method="POST",
        now=21,
    )

    after_restart = restarted(database)
    stored = SQLiteWebAuthnRepository(after_restart).find_challenge(issued.challenge_id)
    assert stored is not None
    assertion = fake_assertion(stored.challenge)
    proof = fake_webauthn_verifier(after_restart).verify(
        assertion,
        challenge_id=issued.challenge_id,
        user_id=USER_ID,
        binding=binding,
        session_id=session_id,
        http_method="POST",
        now=22,
    )
    assert proof.binding == binding

    verifier = fake_webauthn_verifier(after_restart)
    for changes in (
        {"binding": ActionBinding("approve", "different-request", 1, "a" * 64)},
        {"session_id": "different-session-id-opaque"},
        {"http_method": "GET"},
    ):
        arguments = {
            "challenge_id": issued.challenge_id,
            "user_id": USER_ID,
            "binding": binding,
            "session_id": session_id,
            "http_method": "POST",
            "now": 22,
        }
        arguments.update(changes)
        with pytest.raises(WebAuthnChallengeUnavailable):
            verifier.verify(assertion, **arguments)  # type: ignore[arg-type]

    repository = SQLiteWebAuthnRepository(after_restart)
    repository.add_credential(web_credential(SECOND_WEB_CREDENTIAL_ID), now=23)
    with pytest.raises(InvalidWebAuthnAssertion):
        verifier.verify(
            fake_assertion(stored.challenge, credential_id=SECOND_WEB_CREDENTIAL_ID),
            challenge_id=issued.challenge_id,
            user_id=USER_ID,
            binding=binding,
            session_id=session_id,
            http_method="POST",
            now=24,
        )


def test_webauthn_login_completion_rotates_session_and_consumes_atomically(
    database: Database,
) -> None:
    repository = SQLiteWebAuthnRepository(database)
    repository.add_credential(web_credential(), now=10)
    manager, old_token, session_id = preauth_session(database, now=20)
    issued = WebAuthnChallengeIssuer(repository, rp_id=RP_ID).issue(
        USER_ID,
        ActionBinding("login"),
        session_id=session_id,
        http_method="POST",
        now=21,
    )
    challenge = repository.find_challenge(issued.challenge_id)
    assert challenge is not None
    proof = fake_webauthn_verifier(database).verify(
        fake_assertion(challenge.challenge),
        challenge_id=issued.challenge_id,
        user_id=USER_ID,
        binding=ActionBinding("login"),
        session_id=session_id,
        http_method="POST",
        now=22,
    )

    transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=SIGNING_KEY,
        capabilities=TEST_CAPABILITIES,
    )
    new_token = transactions.complete_webauthn_login(proof, now=23)
    assert manager.authenticate(new_token, now=24).auth_method == "webauthn"
    with pytest.raises(InvalidSession):
        manager.authenticate(old_token, now=24)
    with pytest.raises(AuthenticationError):
        transactions.complete_webauthn_login(proof, now=25)

    stored = repository.find_challenge(issued.challenge_id)
    credential = repository.find_credential(WEB_CREDENTIAL_ID)
    assert stored is not None and stored.consumed_at == 23
    assert credential is not None and credential.sign_count == 8
    with database.read() as connection:
        assert (
            connection.execute(
                "SELECT last_used_at FROM auth_factors WHERE credential_id = ?",
                (WEB_CREDENTIAL_ID,),
            ).fetchone()[0]
            == 23
        )


def test_webauthn_login_fault_rolls_back_every_auth_record(database: Database) -> None:
    repository = SQLiteWebAuthnRepository(database)
    repository.add_credential(web_credential(), now=10)
    manager, old_token, session_id = preauth_session(database, now=20)
    issued = WebAuthnChallengeIssuer(repository, rp_id=RP_ID).issue(
        USER_ID,
        ActionBinding("login"),
        session_id=session_id,
        http_method="POST",
        now=21,
    )
    challenge = repository.find_challenge(issued.challenge_id)
    assert challenge is not None
    proof = fake_webauthn_verifier(database).verify(
        fake_assertion(challenge.challenge),
        challenge_id=issued.challenge_id,
        user_id=USER_ID,
        binding=ActionBinding("login"),
        session_id=session_id,
        http_method="POST",
        now=22,
    )

    cross_domain = TEST_CAPABILITIES.seal(
        TOTP_PROOF_DOMAIN,
        {"cross_domain": "webauthn"},
    )
    variants = (
        replace(proof, capability="pc1.forged"),
        replace(proof, capability=cross_domain),
        replace(proof, credential_id=SECOND_WEB_CREDENTIAL_ID),
        replace(proof, user_id="other-user"),
        replace(proof, challenge_id="different-challenge-opaque"),
        replace(proof, use_id="different-webauthn-use"),
        replace(proof, binding=ActionBinding("approve", "request-a", 1, "a" * 64)),
        replace(proof, session_id="different-session-id-opaque-000001"),
        replace(proof, http_method="GET"),
        replace(proof, expected_counter=6),
        replace(proof, new_counter=9),
        replace(proof, device_type="multi_device"),
        replace(proof, expected_backup_eligible=True),
        replace(proof, new_backup_eligible=True),
        replace(proof, previous_backed_up=True),
        replace(proof, new_backed_up=True),
    )
    verifier_transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=SIGNING_KEY,
        capabilities=TEST_CAPABILITIES,
    )
    for variant in variants:
        with pytest.raises(InvalidCredentials):
            verifier_transactions.complete_webauthn_login(variant, now=23)
    with pytest.raises(InvalidCredentials):
        SQLiteAuthenticationTransactions(
            database,
            signing_key=SIGNING_KEY,
            capabilities=ProofCapability(b"rotated-proof-capability-key-00001"),
        ).complete_webauthn_login(proof, now=23)

    def fail_before_commit(stage: str) -> None:
        assert stage == "login:before_commit"
        raise RuntimeError("injected login failure")

    faulty = SQLiteAuthenticationTransactions(
        database,
        signing_key=SIGNING_KEY,
        capabilities=TEST_CAPABILITIES,
        fault_injector=fail_before_commit,
    )
    with pytest.raises(RuntimeError, match="injected login failure"):
        faulty.complete_webauthn_login(proof, now=23)

    assert manager.authenticate(old_token, now=24).user_id == USER_ID
    stored = repository.find_challenge(issued.challenge_id)
    credential = repository.find_credential(WEB_CREDENTIAL_ID)
    assert stored is not None and stored.consumed_at is None
    assert credential is not None and credential.sign_count == 7
    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM web_sessions").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM auth_login_consumptions").fetchone()[0] == 0

    token = SQLiteAuthenticationTransactions(
        restarted(database),
        signing_key=SIGNING_KEY,
        capabilities=ProofCapability(CAPABILITY_KEY),
    ).complete_webauthn_login(proof, now=25)
    assert manager.authenticate(token, now=26).user_id == USER_ID


def test_totp_login_completion_is_durable_single_use_and_clears_attempts(
    database: Database,
) -> None:
    verifier = password_verifier()
    SQLitePasswordCredentialRepository(database).replace_password(
        PasswordCredential("password-main", USER_ID, verifier._hasher.hash("correct horse")),
        now=10,
    )
    SQLiteTotpCredentialRepository(database).replace_totp(
        TotpCredential("totp-main", USER_ID, TOTP_REFERENCE),
        now=11,
    )
    manager, old_token, session_id = preauth_session(database, now=20)
    password_user = PasswordAuthenticator(
        SQLitePasswordCredentialRepository(database),
        SQLiteAttemptLimiter(database, lock_schedule=((10, 60),)),
        capabilities=TEST_CAPABILITIES,
        verifier=verifier,
    ).authenticate(USER_ID, "correct horse", source_id="login-test", now=21)
    totp = TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        MemorySecretStore({("Signet", "persistent-totp"): "fake-secret-material"}),
        SQLiteAttemptLimiter(database, lock_schedule=((10, 60),)),
        capabilities=TEST_CAPABILITIES,
        provider=FakeTotpProvider("fake:persistent-login", step=77),
        allow_test_provider=True,
    )
    proof = totp.verify(
        USER_ID,
        "fake:persistent-login",
        binding=ActionBinding("login"),
        session_id=session_id,
        http_method="POST",
        source_id="login-test",
        now=22,
    )
    tampered_attempt = replace(
        proof.attempt_reservation,
        attempt_id="different-attempt-id-opaque",
    )
    tampered_attempt_source = replace(
        proof.attempt_reservation,
        scope_keys=(
            proof.rate_limit_key,
            source_rate_limit_key("different-source"),
        ),
    )
    variants = (
        (replace(password_user, capability="pc1.forged"), proof),
        (replace(password_user, credential_id="password-other"), proof),
        (password_user, replace(proof, capability="pc1.forged")),
        (password_user, replace(proof, capability=password_user.capability)),
        (password_user, replace(proof, credential_id="totp-other")),
        (password_user, replace(proof, user_id="other-user")),
        (password_user, replace(proof, use_id="different-totp-use")),
        (
            password_user,
            replace(
                proof,
                binding=ActionBinding("approve", "request-a", 1, "a" * 64),
            ),
        ),
        (password_user, replace(proof, session_id="different-session-id-opaque-000001")),
        (password_user, replace(proof, http_method="MCP")),
        (password_user, replace(proof, rate_limit_key=totp_rate_limit_key("other-user"))),
        (password_user, replace(proof, attempt_reservation=tampered_attempt)),
        (
            password_user,
            replace(proof, attempt_reservation=tampered_attempt_source),
        ),
    )
    verifier_transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=SIGNING_KEY,
        capabilities=TEST_CAPABILITIES,
    )
    for password_variant, totp_variant in variants:
        with pytest.raises(InvalidCredentials):
            verifier_transactions.complete_totp_login(
                password_variant,
                totp_variant,
                now=23,
            )
    with pytest.raises(InvalidCredentials):
        SQLiteAuthenticationTransactions(
            database,
            signing_key=SIGNING_KEY,
            capabilities=ProofCapability(b"rotated-proof-capability-key-00001"),
        ).complete_totp_login(password_user, proof, now=23)
    with pytest.raises(TypeError):
        SQLiteAuthenticationTransactions(  # type: ignore[call-arg]
            database,
            signing_key=SIGNING_KEY,
        )
    transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=SIGNING_KEY,
        capabilities=ProofCapability(CAPABILITY_KEY),
    )
    new_token = transactions.complete_totp_login(password_user, proof, now=23)
    totp.record_consumed_success(proof, now=23)

    assert manager.authenticate(new_token, now=24).auth_method == "password+totp"
    with pytest.raises(InvalidSession):
        manager.authenticate(old_token, now=24)
    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_attempts").fetchone()[0] == 0
        factor_usage = {
            row["credential_id"]: row["last_used_at"]
            for row in connection.execute(
                """
                SELECT credential_id, last_used_at FROM auth_factors
                WHERE credential_id IN ('password-main', 'totp-main')
                """
            ).fetchall()
        }
        assert factor_usage == {"password-main": 23, "totp-main": 23}

    candidate = approval_request("login-then-approval-replay", now=24)
    machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
    machine.enqueue(candidate)
    approval_proof = totp.verify(
        USER_ID,
        "fake:persistent-login",
        binding=ActionBinding(
            "approve",
            candidate.request_id,
            1,
            candidate.payload_hash,
        ),
        session_id=None,
        http_method="MCP",
        source_id="login-test",
        now=25,
    )
    assert approval_proof.use_id == proof.use_id
    with pytest.raises(ConfirmationReplay):
        machine.approve(
            candidate.request_id,
            expected_version=1,
            expected_payload_hash=candidate.payload_hash,
            confirmation=confirmation_from_totp(approval_proof),
            actor="human:mcp",
            now=25,
        )
    assert machine.get_request(candidate.request_id)["state"] == "pending_approval"
    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_attempts").fetchone()[0] == 2
        assert (
            connection.execute(
                """
            SELECT last_used_at FROM auth_credentials
            WHERE credential_id = 'totp-main'
            """
            ).fetchone()[0]
            == 23
        )

    _, replay_token, replay_session_id = preauth_session(database, now=30)
    replay = totp.verify(
        USER_ID,
        "fake:persistent-login",
        binding=ActionBinding("login"),
        session_id=replay_session_id,
        http_method="POST",
        source_id="login-test",
        now=30,
    )
    assert replay.use_id == proof.use_id
    with pytest.raises(InvalidCredentials, match="replayed"):
        SQLiteAuthenticationTransactions(
            restarted(database),
            signing_key=SIGNING_KEY,
            capabilities=TEST_CAPABILITIES,
        ).complete_totp_login(password_user, replay, now=31)
    assert manager.authenticate(replay_token, now=32).auth_method == "preauth"


def test_approval_consumption_blocks_same_totp_step_from_login(database: Database) -> None:
    verifier = password_verifier()
    SQLitePasswordCredentialRepository(database).replace_password(
        PasswordCredential("password-main", USER_ID, verifier._hasher.hash("correct horse")),
        now=10,
    )
    SQLiteTotpCredentialRepository(database).replace_totp(
        TotpCredential("totp-main", USER_ID, TOTP_REFERENCE),
        now=11,
    )
    manager, preauth_token, session_id = preauth_session(database, now=20)
    password_user = PasswordAuthenticator(
        SQLitePasswordCredentialRepository(database),
        SQLiteAttemptLimiter(database, lock_schedule=((10, 60),)),
        capabilities=TEST_CAPABILITIES,
        verifier=verifier,
    ).authenticate(USER_ID, "correct horse", source_id="reverse-replay", now=21)
    totp = TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        MemorySecretStore({("Signet", "persistent-totp"): "fake-secret-material"}),
        SQLiteAttemptLimiter(database, lock_schedule=((10, 60),)),
        capabilities=TEST_CAPABILITIES,
        provider=FakeTotpProvider("fake:reverse-replay", step=91),
        allow_test_provider=True,
    )
    candidate = approval_request("approval-then-login-replay", now=20)
    machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
    machine.enqueue(candidate)
    approval_proof = totp.verify(
        USER_ID,
        "fake:reverse-replay",
        binding=ActionBinding(
            "approve",
            candidate.request_id,
            1,
            candidate.payload_hash,
        ),
        session_id=None,
        http_method="MCP",
        source_id="reverse-replay",
        now=22,
    )
    machine.approve(
        candidate.request_id,
        expected_version=1,
        expected_payload_hash=candidate.payload_hash,
        confirmation=confirmation_from_totp(approval_proof),
        actor="human:mcp",
        now=22,
    )
    with database.read() as connection:
        assert (
            connection.execute(
                "SELECT last_used_at FROM auth_factors WHERE credential_id = 'totp-main'"
            ).fetchone()[0]
            == 22
        )

    login_proof = totp.verify(
        USER_ID,
        "fake:reverse-replay",
        binding=ActionBinding("login"),
        session_id=session_id,
        http_method="POST",
        source_id="reverse-replay",
        now=23,
    )
    assert login_proof.use_id == approval_proof.use_id
    with pytest.raises(InvalidCredentials, match="replayed"):
        SQLiteAuthenticationTransactions(
            database,
            signing_key=SIGNING_KEY,
            capabilities=TEST_CAPABILITIES,
        ).complete_totp_login(password_user, login_proof, now=23)
    assert manager.authenticate(preauth_token, now=24).auth_method == "preauth"


def test_totp_replacement_invalidates_verified_mutation_proof(database: Database) -> None:
    credentials = SQLiteTotpCredentialRepository(database)
    credentials.replace_totp(
        TotpCredential("totp-old", USER_ID, TOTP_REFERENCE),
        now=10,
    )
    totp = TotpVerifier(
        credentials,
        MemorySecretStore({("Signet", "persistent-totp"): "fake-secret-material"}),
        SQLiteAttemptLimiter(database, lock_schedule=((10, 60),)),
        capabilities=TEST_CAPABILITIES,
        provider=FakeTotpProvider("fake:before-replacement", step=101),
        allow_test_provider=True,
    )
    candidate = approval_request("credential-replacement", now=20)
    machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
    machine.enqueue(candidate)
    proof = totp.verify(
        USER_ID,
        "fake:before-replacement",
        binding=ActionBinding(
            "approve",
            candidate.request_id,
            1,
            candidate.payload_hash,
        ),
        session_id=None,
        http_method="MCP",
        source_id="replacement-test",
        now=20,
    )
    credentials.replace_totp(
        TotpCredential("totp-new", USER_ID, TOTP_REFERENCE),
        now=21,
    )

    with pytest.raises(InvalidConfirmation, match="stale or unavailable"):
        machine.approve(
            candidate.request_id,
            expected_version=1,
            expected_payload_hash=candidate.payload_hash,
            confirmation=confirmation_from_totp(proof),
            actor="human:mcp",
            now=22,
        )
    assert machine.get_request(candidate.request_id)["state"] == "pending_approval"
    with database.read() as connection:
        assert connection.execute("SELECT count(*) FROM auth_proof_consumptions").fetchone()[0] == 0
