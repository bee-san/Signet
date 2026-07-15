from __future__ import annotations

from dataclasses import dataclass

import pytest
from argon2 import PasswordHasher

from signet.auth import (
    PASSWORD_PROOF_DOMAIN,
    TOTP_PROOF_DOMAIN,
    ActionBinding,
    Argon2PasswordVerifier,
    AuthenticationRateLimited,
    InMemoryAttemptLimiter,
    InMemorySessionRepository,
    InvalidCredentials,
    InvalidSession,
    PasswordAuthenticator,
    PasswordCredential,
    ProofCapability,
    SessionCookieSettings,
    SessionManager,
    password_proof_claims,
    password_rate_limit_key,
)

SESSION_KEY = b"test-only-session-signing-material!"
TEST_CAPABILITIES = ProofCapability(b"test-only-proof-capability-key-0001")


def session_manager(
    repository: InMemorySessionRepository | None = None,
    *,
    idle_timeout: int = 10,
    absolute_timeout: int = 30,
) -> SessionManager:
    return SessionManager(
        repository or InMemorySessionRepository(),
        signing_key=SESSION_KEY,
        idle_timeout=idle_timeout,
        absolute_timeout=absolute_timeout,
    )


def test_session_cookie_is_signed_opaque_and_has_host_cookie_controls() -> None:
    repository = InMemorySessionRepository()
    manager = session_manager(repository)
    token = manager.create_session("human:autumn", auth_method="webauthn", now=1_000)

    assert "human:autumn" not in token
    principal = manager.authenticate(token, now=1_001)
    assert principal.user_id == "human:autumn"
    assert principal.session_id not in repr(principal)
    record = repository.get(principal.session_id)
    assert record is not None
    assert principal.session_id not in repr(record)
    replacement = "A" if token[-1] != "A" else "B"
    with pytest.raises(InvalidSession, match="invalid or expired"):
        manager.authenticate(f"{token[:-1]}{replacement}", now=1_001)

    settings = SessionCookieSettings()
    assert settings.name.startswith("__Host-")
    assert settings.as_response_kwargs() == {
        "path": "/",
        "secure": True,
        "httponly": True,
        "samesite": "strict",
    }


def test_login_rotates_and_revokes_the_pre_login_session() -> None:
    manager = session_manager()
    fixed = manager.create_session("human:autumn", auth_method="pre-auth", now=1_000)
    authenticated = manager.create_session(
        "human:autumn",
        auth_method="password+totp",
        now=1_001,
        previous_token=fixed,
    )

    assert authenticated != fixed
    with pytest.raises(InvalidSession):
        manager.authenticate(fixed, now=1_002)
    assert manager.authenticate(authenticated, now=1_002).auth_method == "password+totp"


def test_idle_and_absolute_expiry_are_both_enforced() -> None:
    idle_manager = session_manager(idle_timeout=5, absolute_timeout=20)
    idle_token = idle_manager.create_session("human", auth_method="passkey", now=1_000)
    idle_manager.authenticate(idle_token, now=1_004)
    with pytest.raises(InvalidSession):
        idle_manager.authenticate(idle_token, now=1_009)

    absolute_manager = session_manager(idle_timeout=8, absolute_timeout=10)
    absolute_token = absolute_manager.create_session("human", auth_method="passkey", now=2_000)
    absolute_manager.authenticate(absolute_token, now=2_007)
    absolute_manager.authenticate(absolute_token, now=2_009)
    with pytest.raises(InvalidSession):
        absolute_manager.authenticate(absolute_token, now=2_010)

    future_token = absolute_manager.create_session("human", auth_method="passkey", now=3_000)
    with pytest.raises(InvalidSession):
        absolute_manager.authenticate(future_token, now=2_999)


def test_logout_is_idempotent_and_logged_out_cookie_cannot_be_replayed() -> None:
    manager = session_manager()
    token = manager.create_session("human", auth_method="passkey", now=1_000)

    assert manager.logout(token, now=1_001)
    assert not manager.logout(token, now=1_002)
    assert not manager.logout("not-a-session", now=1_002)
    with pytest.raises(InvalidSession):
        manager.authenticate(token, now=1_003)


@dataclass
class PasswordRepository:
    credentials: dict[str, PasswordCredential]

    def find_password(self, user_id: str) -> PasswordCredential | None:
        return self.credentials.get(user_id)


def password_verifier() -> tuple[Argon2PasswordVerifier, PasswordHasher]:
    hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1_024,
        parallelism=1,
        hash_len=16,
        salt_len=8,
    )
    return Argon2PasswordVerifier(hasher), hasher


def test_password_authentication_uses_argon2_and_generic_failures() -> None:
    verifier, hasher = password_verifier()
    repository = PasswordRepository(
        {
            "human": PasswordCredential(
                credential_id="password-main",
                user_id="human",
                verifier=hasher.hash("correct horse battery staple"),
            )
        }
    )
    authenticator = PasswordAuthenticator(
        repository,
        InMemoryAttemptLimiter(),
        capabilities=TEST_CAPABILITIES,
        verifier=verifier,
    )

    principal = authenticator.authenticate(
        "human",
        "correct horse battery staple",
        now=1_000,
    )
    assert principal.user_id == "human"
    assert principal.method == "password"
    assert repository.credentials["human"].verifier not in repr(repository.credentials["human"])
    with pytest.raises(InvalidCredentials, match="invalid credentials"):
        authenticator.authenticate("human", "wrong", now=1_001)
    with pytest.raises(InvalidCredentials, match="invalid credentials"):
        authenticator.authenticate("unknown", "wrong", now=1_001)


def test_password_attempts_escalate_lockout_and_success_resets_it() -> None:
    verifier, hasher = password_verifier()
    limiter = InMemoryAttemptLimiter(lock_schedule=((2, 4), (3, 20)))
    authenticator = PasswordAuthenticator(
        PasswordRepository(
            {
                "human": PasswordCredential(
                    credential_id="password-main",
                    user_id="human",
                    verifier=hasher.hash("valid password"),
                )
            }
        ),
        limiter,
        capabilities=TEST_CAPABILITIES,
        verifier=verifier,
    )

    for now in (1_000, 1_001):
        with pytest.raises(InvalidCredentials):
            authenticator.authenticate("human", "wrong", now=now)
    with pytest.raises(AuthenticationRateLimited) as locked:
        authenticator.authenticate("human", "valid password", now=1_002)
    assert locked.value.retry_after == 3

    authenticator.authenticate("human", "valid password", now=1_005)
    assert limiter.state(password_rate_limit_key("human")).failures == 0


def test_password_repository_cannot_return_another_users_credential() -> None:
    verifier, hasher = password_verifier()
    authenticator = PasswordAuthenticator(
        PasswordRepository(
            {
                "human": PasswordCredential(
                    credential_id="password-other",
                    user_id="other",
                    verifier=hasher.hash("valid password"),
                )
            }
        ),
        InMemoryAttemptLimiter(),
        capabilities=TEST_CAPABILITIES,
        verifier=verifier,
    )
    with pytest.raises(InvalidCredentials):
        authenticator.authenticate("human", "valid password", now=1_000)


def test_invalid_session_configuration_fails_closed() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        SessionManager(InMemorySessionRepository(), signing_key=b"short")
    with pytest.raises(ValueError, match="cannot exceed"):
        session_manager(idle_timeout=31, absolute_timeout=30)


def test_action_binding_requires_complete_canonical_request_hashes() -> None:
    with pytest.raises(ValueError, match="request ID"):
        ActionBinding("edit", prospective_payload_hash="a" * 64)
    with pytest.raises(ValueError, match="lowercase"):
        ActionBinding("approve", "request-a", 1, "A" * 64)
    with pytest.raises(ValueError, match="login cannot"):
        ActionBinding("login", "request-a", 1, "a" * 64)
    with pytest.raises(ValueError, match="prospective"):
        ActionBinding("edit", "request-a", 1, "a" * 64)
    with pytest.raises(ValueError, match="only for edits"):
        ActionBinding("approve", "request-a", 1, "a" * 64, "b" * 64)


def test_authentication_identifiers_are_bounded_and_canonical() -> None:
    manager = session_manager()
    with pytest.raises(InvalidCredentials):
        manager.create_session("x" * 257, auth_method="webauthn", now=1_000)
    with pytest.raises(InvalidCredentials):
        manager.create_session("\u0065\u0301", auth_method="webauthn", now=1_000)
    with pytest.raises(ValueError, match="bounded"):
        manager.create_session("human", auth_method="x" * 65, now=1_000)
    with pytest.raises(ValueError, match="bounded action"):
        ActionBinding("x" * 65)
    with pytest.raises(ValueError, match="request ID"):
        ActionBinding("approve", "x" * 257, 1, "a" * 64)


def test_proof_capabilities_are_canonical_domain_separated_and_key_scoped() -> None:
    key = b"capability-test-key-material-000001"
    capabilities = ProofCapability(key)
    claims = password_proof_claims(
        user_id="human",
        credential_id="password-main",
        method="password",
    )
    capability = capabilities.seal(PASSWORD_PROOF_DOMAIN, claims)

    assert capabilities.verify(
        capability,
        domain=PASSWORD_PROOF_DOMAIN,
        claims=dict(reversed(tuple(claims.items()))),
    )
    assert ProofCapability(bytes(key)).verify(
        capability,
        domain=PASSWORD_PROOF_DOMAIN,
        claims=claims,
    )
    assert not capabilities.verify(
        capability,
        domain=TOTP_PROOF_DOMAIN,
        claims=claims,
    )
    assert not capabilities.verify(
        capability,
        domain=PASSWORD_PROOF_DOMAIN,
        claims={**claims, "credential_id": "password-other"},
    )
    assert not ProofCapability(b"rotated-capability-test-key-00001").verify(
        capability,
        domain=PASSWORD_PROOF_DOMAIN,
        claims=claims,
    )
    assert not capabilities.verify("forged", domain=PASSWORD_PROOF_DOMAIN, claims=claims)
    assert key.decode() not in repr(capabilities)
    with pytest.raises(ValueError, match="32 bytes"):
        ProofCapability(b"short")


def test_password_authenticator_requires_explicit_capabilities() -> None:
    verifier, _ = password_verifier()
    with pytest.raises(TypeError):
        PasswordAuthenticator(  # type: ignore[call-arg]
            PasswordRepository({}),
            InMemoryAttemptLimiter(),
            verifier=verifier,
        )
