"""Single-use, action-bound TOTP confirmation support.

Code verification proves possession only.  The returned ``use_id`` identifies
the credential time-step without retaining the submitted code.  The approval
state machine must insert that ID into its shared confirmation-consumption
ledger in the same transaction as the bound state transition.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

import pyotp

from signet.auth import (
    TOTP_PROOF_DOMAIN,
    ActionBinding,
    AttemptLimiter,
    AttemptReservation,
    ProofCapability,
    _bounded_identifier,
    _ensure_auth_user,
    _revoke_user_sessions,
    canonical_user_id,
    source_rate_limit_key,
    totp_proof_claims,
    totp_rate_limit_key,
)
from signet.credential_broker import CredentialError, Secret, SecretReference, SecretStore
from signet.db import Database


class TotpError(RuntimeError):
    pass


class TotpNotEnrolled(TotpError):
    pass


class InvalidTotp(TotpError):
    pass


class TotpUnavailable(TotpError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class TotpCredential:
    credential_id: str
    user_id: str
    secret_reference: str
    disabled: bool = False

    def __repr__(self) -> str:
        return (
            "TotpCredential("
            f"credential_id={self.credential_id!r}, user_id={self.user_id!r}, "
            "secret_reference=<redacted>, "
            f"disabled={self.disabled!r})"
        )


class TotpCredentialRepository(Protocol):
    def find_totp(self, user_id: str) -> TotpCredential | None: ...


class SQLiteTotpCredentialRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def find_totp(self, user_id: str) -> TotpCredential | None:
        user_id = canonical_user_id(user_id)
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT credential_id, user_id, secret_reference, disabled_at
                FROM auth_credentials
                WHERE user_id = ? AND kind = 'totp' AND disabled_at IS NULL
                """,
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return TotpCredential(
            credential_id=str(row["credential_id"]),
            user_id=str(row["user_id"]),
            secret_reference=str(row["secret_reference"]),
            disabled=row["disabled_at"] is not None,
        )

    def replace_totp(self, credential: TotpCredential, *, now: int) -> None:
        user_id = canonical_user_id(credential.user_id)
        if credential.disabled:
            raise ValueError("an active TOTP credential is required")
        _bounded_identifier(credential.credential_id, name="credential ID", maximum=256)
        SecretReference.parse(credential.secret_reference)
        with self.database.transaction() as connection:
            _ensure_auth_user(connection, user_id, created_at=now)
            connection.execute(
                """
                UPDATE auth_credentials SET disabled_at = ?
                WHERE user_id = ? AND kind = 'totp' AND disabled_at IS NULL
                """,
                (now, user_id),
            )
            connection.execute(
                """
                INSERT INTO auth_credentials(
                    credential_id, user_id, kind, secret_reference, enrolled_at
                ) VALUES (?, ?, 'totp', ?, ?)
                """,
                (credential.credential_id, user_id, credential.secret_reference, now),
            )
            _revoke_user_sessions(connection, user_id, revoked_at=now)


class TotpCodeProvider(Protocol):
    test_only: bool

    def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None: ...


class PyotpTotpProvider:
    """Production RFC 6238 provider backed by PyOTP."""

    test_only = False

    def __init__(
        self,
        *,
        interval: int = 30,
        valid_window: int = 1,
        digits: int = 6,
    ) -> None:
        if interval <= 0 or valid_window < 0 or valid_window > 2 or digits not in {6, 8}:
            raise ValueError("invalid TOTP timing parameters")
        self.interval = interval
        self.valid_window = valid_window
        self.digits = digits

    def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None:
        if len(proof) != self.digits or not proof.isascii() or not proof.isdigit() or now < 0:
            return None
        try:
            totp = pyotp.TOTP(secret.reveal(), digits=self.digits, interval=self.interval)
            current_step = now // self.interval
            # Prefer the current time-step when a rare adjacent-step collision occurs.
            offsets = [0]
            offsets.extend(range(-1, -self.valid_window - 1, -1))
            offsets.extend(range(1, self.valid_window + 1))
            for offset in offsets:
                step = current_step + offset
                if step < 0:
                    continue
                candidate = totp.generate_otp(step)
                if hmac.compare_digest(candidate, proof):
                    return step
        except Exception as exc:
            # PyOTP may surface malformed Base32 material through several stdlib
            # exception types.  Do not reflect secret details to the caller.
            raise TotpUnavailable("TOTP credential material is unavailable") from exc
        return None


class FakeTotpProvider:
    """Explicit fake for tests; it refuses values shaped like authenticator codes."""

    test_only = True

    def __init__(self, accepted_proof: str = "fake:valid-proof", *, step: int = 42) -> None:
        if _looks_like_authenticator_code(accepted_proof):
            raise ValueError("fake proof must not resemble an authenticator code")
        if not accepted_proof.startswith("fake:") or step < 0:
            raise ValueError("an explicit fake proof and non-negative step are required")
        self._accepted_proof = accepted_proof
        self._step = step

    def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None:
        del secret, now
        if hmac.compare_digest(self._accepted_proof, proof):
            return self._step
        return None

    def __repr__(self) -> str:
        return "FakeTotpProvider(accepted_proof=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedTotp:
    credential_id: str
    user_id: str
    use_id: str
    binding: ActionBinding
    session_id: str | None
    http_method: str
    rate_limit_key: str
    attempt_reservation: AttemptReservation
    capability: str

    def __repr__(self) -> str:
        return (
            "VerifiedTotp(credential_id=<redacted>, use_id=<redacted>, "
            f"user_id={self.user_id!r}, binding={self.binding!r}, "
            "session_id=<redacted>, "
            f"http_method={self.http_method!r}, "
            "rate_limit_key=<redacted>, attempt_reservation=<redacted>, "
            "capability=<redacted>)"
        )


class TotpVerifier:
    """Resolve an enrolled secret reference and verify a bound TOTP proof."""

    def __init__(
        self,
        credentials: TotpCredentialRepository,
        secret_store: SecretStore,
        limiter: AttemptLimiter,
        *,
        capabilities: ProofCapability,
        provider: TotpCodeProvider | None = None,
        allow_test_provider: bool = False,
    ) -> None:
        selected_provider = provider or PyotpTotpProvider()
        if selected_provider.test_only and not allow_test_provider:
            raise ValueError("a fake TOTP provider requires explicit test opt-in")
        self._credentials = credentials
        self._secret_store = secret_store
        self._limiter = limiter
        self._provider = selected_provider
        self._capabilities = capabilities

    def verify(
        self,
        user_id: str,
        proof: str,
        *,
        binding: ActionBinding,
        now: int,
        source_id: str = "local-web",
        session_id: str | None = None,
        http_method: str = "MCP",
    ) -> VerifiedTotp:
        user_id = canonical_user_id(user_id)
        if http_method == "POST":
            if session_id is None or len(session_id) < 16:
                raise ValueError("web TOTP verification requires a bound session")
            _bounded_identifier(session_id, name="session ID", maximum=128)
        elif http_method != "MCP" or session_id is not None or binding.action != "approve":
            raise ValueError("TOTP confirmation context is invalid")
        rate_key = totp_rate_limit_key(user_id)
        reservation = self._limiter.reserve(
            rate_key,
            source_key=source_rate_limit_key(source_id),
            now=now,
        )
        credential = self._credentials.find_totp(user_id)
        if credential is None or credential.user_id != user_id or credential.disabled:
            raise TotpNotEnrolled("TOTP is not enrolled; use the authenticated web app")
        if not proof or len(proof) > 128:
            self._limiter.record_failure(reservation, now=now)
            raise InvalidTotp("invalid or consumed TOTP proof")
        try:
            reference = SecretReference.parse(credential.secret_reference)
            secret = self._secret_store.get(reference)
        except CredentialError as exc:
            raise TotpUnavailable("TOTP credential material is unavailable") from exc

        step = self._provider.verify_step(secret, proof, now=now)
        if step is None:
            self._limiter.record_failure(reservation, now=now)
            raise InvalidTotp("invalid or consumed TOTP proof")
        use_id = _use_id(credential.credential_id, step)
        path = "web" if http_method == "POST" else "mcp"
        capability = self._capabilities.seal(
            TOTP_PROOF_DOMAIN,
            totp_proof_claims(
                credential_id=credential.credential_id,
                credential_user_id=credential.user_id,
                user_id=credential.user_id,
                use_id=use_id,
                binding=binding,
                path=path,
                session_id=session_id,
                http_method=http_method,
                rate_limit_key=rate_key,
                attempt_id=reservation.attempt_id,
                attempt_scope_keys=reservation.scope_keys,
            ),
        )
        return VerifiedTotp(
            credential_id=credential.credential_id,
            user_id=credential.user_id,
            use_id=use_id,
            binding=binding,
            session_id=session_id,
            http_method=http_method,
            rate_limit_key=rate_key,
            attempt_reservation=reservation,
            capability=capability,
        )

    def record_consumed_success(self, proof: VerifiedTotp, *, now: int) -> None:
        """Clear failures only after the proof's use ID is atomically consumed."""

        if proof.rate_limit_key != totp_rate_limit_key(proof.user_id):
            raise ValueError("TOTP proof has an invalid rate-limit binding")
        self._limiter.record_success(proof.attempt_reservation, now=now)


def _use_id(credential_id: str, step: int) -> str:
    value = f"totp-use\x00{credential_id}\x00{step}".encode()
    return hashlib.sha256(value).hexdigest()


def _looks_like_authenticator_code(value: str) -> bool:
    return len(value) == 6 and value.isascii() and value.isdigit()
