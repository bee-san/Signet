"""Web sessions and password authentication primitives.

The web session cookie contains only a random identifier and an HMAC.  All
authorization state remains in the injected repository.  In particular,
``use_and_touch`` is deliberately one repository operation so a persistent
implementation can enforce idle expiry and update activity atomically.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from signet.db import Database, IntegrityError

PASSWORD_PROOF_DOMAIN = "signet.password-authenticated.v1"
TOTP_PROOF_DOMAIN = "signet.totp-verified.v1"
WEBAUTHN_PROOF_DOMAIN = "signet.webauthn-verified.v1"
_PROOF_DOMAINS = frozenset({PASSWORD_PROOF_DOMAIN, TOTP_PROOF_DOMAIN, WEBAUTHN_PROOF_DOMAIN})


@dataclass(frozen=True, slots=True)
class ActionBinding:
    """The exact browser action and immutable request revision being confirmed."""

    action: str
    request_id: str | None = None
    version: int | None = None
    payload_hash: str | None = None
    prospective_payload_hash: str | None = None

    def __post_init__(self) -> None:
        if self.action not in {
            "login",
            "approve",
            "edit",
            "deny",
            "human_cancel",
            "promote_approval",
            "promote_passthrough",
        }:
            raise ValueError("a supported bounded action is required")
        request_fields = (self.request_id, self.version, self.payload_hash)
        if self.action == "login" and any(
            field is not None for field in (*request_fields, self.prospective_payload_hash)
        ):
            raise ValueError("login cannot carry a request binding")
        if self.action != "login" and not all(field is not None for field in request_fields):
            raise ValueError("request ID, version, and payload hash must be bound together")
        if self.request_id is not None and (not self.request_id or len(self.request_id) > 256):
            raise ValueError("invalid request ID")
        if self.version is not None and self.version < 1:
            raise ValueError("request version must be positive")
        for value in (self.payload_hash, self.prospective_payload_hash):
            if value is not None and not _is_sha256(value):
                raise ValueError("payload hashes must be lowercase SHA-256 values")
        if (self.prospective_payload_hash is not None) != (self.action == "edit"):
            raise ValueError("a prospective hash is required only for edits")


class ProofCapability:
    """Issue and verify process-internal, domain-separated proof capabilities."""

    _VERSION = "pc1"

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("proof capability key must contain at least 32 bytes")
        self._key = bytes(key)

    def seal(self, domain: str, claims: Mapping[str, object]) -> str:
        payload = _proof_capability_payload(domain, claims)
        signature = hmac.new(self._key, payload, hashlib.sha256).digest()
        return f"{self._VERSION}.{_base64url_encode(signature)}"

    def verify(
        self,
        capability: str,
        *,
        domain: str,
        claims: Mapping[str, object],
    ) -> bool:
        try:
            version, encoded_signature = capability.split(".")
            signature = _base64url_decode(encoded_signature)
            if (
                version != self._VERSION
                or len(signature) != hashlib.sha256().digest_size
                or _base64url_encode(signature) != encoded_signature
            ):
                return False
            expected = hmac.new(
                self._key,
                _proof_capability_payload(domain, claims),
                hashlib.sha256,
            ).digest()
        except (AttributeError, TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, signature)

    def __repr__(self) -> str:
        return "ProofCapability(key=<redacted>)"


def password_proof_claims(
    *,
    user_id: str,
    credential_id: str,
    method: str,
) -> dict[str, object]:
    return {
        "credential_id": credential_id,
        "method": method,
        "user_id": user_id,
    }


def totp_proof_claims(
    *,
    credential_id: str,
    credential_user_id: str,
    user_id: str,
    use_id: str,
    binding: ActionBinding,
    path: str,
    session_id: str | None,
    http_method: str,
    rate_limit_key: str,
    attempt_id: str,
    attempt_scope_keys: Sequence[str],
) -> dict[str, object]:
    return {
        **_binding_claims(binding),
        "attempt_id": attempt_id,
        "attempt_scope_keys": list(attempt_scope_keys),
        "credential_id": credential_id,
        "credential_user_id": credential_user_id,
        "http_method": http_method,
        "path": path,
        "rate_limit_key": rate_limit_key,
        "session_id": session_id,
        "use_id": use_id,
        "user_id": user_id,
    }


def webauthn_proof_claims(
    *,
    credential_id: str,
    credential_user_id: str,
    user_id: str,
    challenge_id: str,
    use_id: str,
    binding: ActionBinding,
    path: str,
    session_id: str,
    http_method: str,
    expected_counter: int,
    new_counter: int,
    device_type: str,
    expected_backup_eligible: bool,
    new_backup_eligible: bool,
    previous_backed_up: bool,
    new_backed_up: bool,
) -> dict[str, object]:
    return {
        **_binding_claims(binding),
        "challenge_id": challenge_id,
        "credential_id": credential_id,
        "credential_user_id": credential_user_id,
        "device_type": device_type,
        "expected_backup_eligible": expected_backup_eligible,
        "expected_counter": expected_counter,
        "http_method": http_method,
        "new_backed_up": new_backed_up,
        "new_backup_eligible": new_backup_eligible,
        "new_counter": new_counter,
        "path": path,
        "previous_backed_up": previous_backed_up,
        "session_id": session_id,
        "use_id": use_id,
        "user_id": user_id,
    }


class AuthenticationError(RuntimeError):
    """Base class for deliberately non-specific authentication failures."""


class InvalidSession(AuthenticationError):
    pass


class InvalidCredentials(AuthenticationError):
    pass


class AuthenticationRateLimited(AuthenticationError):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = max(1, retry_after)
        super().__init__("authentication is temporarily locked")


@dataclass(frozen=True, slots=True, repr=False)
class SessionRecord:
    session_id: str
    user_id: str
    auth_method: str
    created_at: int
    last_seen_at: int
    absolute_expires_at: int
    credential_id: str | None = None
    auth_generation: int = 0
    revoked_at: int | None = None

    def __repr__(self) -> str:
        return (
            "SessionRecord(session_id=<redacted>, "
            f"user_id={self.user_id!r}, auth_method={self.auth_method!r}, "
            f"created_at={self.created_at!r}, last_seen_at={self.last_seen_at!r}, "
            f"absolute_expires_at={self.absolute_expires_at!r}, "
            "credential_id=<redacted>, "
            f"auth_generation={self.auth_generation!r}, "
            f"revoked_at={self.revoked_at!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SessionPrincipal:
    user_id: str
    session_id: str
    auth_method: str
    created_at: int
    absolute_expires_at: int

    def __repr__(self) -> str:
        return (
            "SessionPrincipal("
            f"user_id={self.user_id!r}, session_id=<redacted>, "
            f"auth_method={self.auth_method!r}, created_at={self.created_at!r}, "
            f"absolute_expires_at={self.absolute_expires_at!r})"
        )


class SessionRepository(Protocol):
    """Persistence boundary for server-side sessions.

    Implementations must make ``use_and_touch`` atomic.  It may return a record
    only when it is unrevoked and both expiry checks pass at ``now``.
    """

    def create(self, record: SessionRecord) -> bool:
        """Insert a record, returning ``False`` on an identifier collision."""

        ...

    def use_and_touch(
        self,
        session_id: str,
        *,
        now: int,
        idle_timeout: int,
    ) -> SessionRecord | None: ...

    def revoke(self, session_id: str, *, revoked_at: int) -> bool: ...

    def revoke_user(self, user_id: str, *, revoked_at: int) -> int: ...


class InMemorySessionRepository:
    """Thread-safe repository for tests and single-process development."""

    def __init__(self) -> None:
        self._records: dict[str, SessionRecord] = {}
        self._user_generations: dict[str, int] = {}
        self._lock = threading.Lock()

    def create(self, record: SessionRecord) -> bool:
        with self._lock:
            if record.session_id in self._records:
                return False
            generation = self._user_generations.setdefault(record.user_id, 0)
            self._records[record.session_id] = replace(record, auth_generation=generation)
            return True

    def use_and_touch(
        self,
        session_id: str,
        *,
        now: int,
        idle_timeout: int,
    ) -> SessionRecord | None:
        with self._lock:
            record = self._records.get(session_id)
            if record is None or record.revoked_at is not None:
                return None
            if record.auth_generation != self._user_generations.get(record.user_id, 0):
                self._records[session_id] = replace(record, revoked_at=now)
                return None
            idle_expires_at = record.last_seen_at + idle_timeout
            if (
                now < record.created_at
                or now >= idle_expires_at
                or now >= record.absolute_expires_at
            ):
                self._records[session_id] = replace(
                    record,
                    revoked_at=max(now, record.created_at),
                )
                return None
            touched = replace(record, last_seen_at=max(now, record.last_seen_at))
            self._records[session_id] = touched
            return touched

    def revoke(self, session_id: str, *, revoked_at: int) -> bool:
        with self._lock:
            record = self._records.get(session_id)
            if record is None or record.revoked_at is not None:
                return False
            self._records[session_id] = replace(
                record,
                revoked_at=max(revoked_at, record.created_at),
            )
            return True

    def revoke_user(self, user_id: str, *, revoked_at: int) -> int:
        user_id = canonical_user_id(user_id)
        with self._lock:
            self._user_generations[user_id] = self._user_generations.get(user_id, 0) + 1
            revoked = 0
            for session_id, record in tuple(self._records.items()):
                if record.user_id == user_id and record.revoked_at is None:
                    self._records[session_id] = replace(
                        record,
                        revoked_at=max(revoked_at, record.created_at),
                    )
                    revoked += 1
            return revoked

    def get(self, session_id: str) -> SessionRecord | None:
        """Return a snapshot for assertions in tests."""

        with self._lock:
            return self._records.get(session_id)


class SQLiteSessionRepository:
    """Durable session repository with atomic expiry and auth-generation checks."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, record: SessionRecord) -> bool:
        user_id = canonical_user_id(record.user_id)
        with self.database.transaction() as connection:
            _ensure_auth_user(connection, user_id, created_at=record.created_at)
            generation = int(
                connection.execute(
                    "SELECT auth_generation FROM auth_users WHERE user_id = ?",
                    (user_id,),
                ).fetchone()[0]
            )
            inserted = connection.execute(
                """
                    INSERT INTO web_sessions(
                        session_id, user_id, auth_method, credential_id,
                        auth_generation, created_at, last_seen_at,
                        absolute_expires_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id) DO NOTHING
                """,
                (
                    record.session_id,
                    user_id,
                    record.auth_method,
                    record.credential_id,
                    generation,
                    record.created_at,
                    record.last_seen_at,
                    record.absolute_expires_at,
                    record.revoked_at,
                ),
            ).rowcount
            inserted = int(inserted)
        return inserted == 1

    def use_and_touch(
        self,
        session_id: str,
        *,
        now: int,
        idle_timeout: int,
    ) -> SessionRecord | None:
        with self.database.transaction() as connection:
            row = connection.execute(
                """
                UPDATE web_sessions
                SET last_seen_at = max(last_seen_at, ?)
                WHERE session_id = ? AND revoked_at IS NULL
                  AND created_at <= ?
                  AND last_seen_at + ? > ?
                  AND absolute_expires_at > ?
                  AND auth_generation = (
                      SELECT auth_generation FROM auth_users
                      WHERE auth_users.user_id = web_sessions.user_id
                  )
                RETURNING *
                """,
                (now, session_id, now, idle_timeout, now, now),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    UPDATE web_sessions SET revoked_at = max(?, created_at)
                    WHERE session_id = ? AND revoked_at IS NULL
                    """,
                    (now, session_id),
                )
                return None
        return _session_record(row)

    def revoke(self, session_id: str, *, revoked_at: int) -> bool:
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE web_sessions SET revoked_at = max(?, created_at)
                WHERE session_id = ? AND revoked_at IS NULL
                """,
                (revoked_at, session_id),
            ).rowcount
            updated = int(updated)
        return updated == 1

    def revoke_user(self, user_id: str, *, revoked_at: int) -> int:
        user_id = canonical_user_id(user_id)
        with self.database.transaction() as connection:
            _ensure_auth_user(connection, user_id, created_at=revoked_at)
            connection.execute(
                """
                UPDATE auth_users
                SET auth_generation = auth_generation + 1,
                    credentials_changed_at = ?
                WHERE user_id = ?
                """,
                (revoked_at, user_id),
            )
            updated = connection.execute(
                """
                UPDATE web_sessions SET revoked_at = max(?, created_at)
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (revoked_at, user_id),
            ).rowcount
        return int(updated)


@dataclass(frozen=True, slots=True)
class SessionCookieSettings:
    name: str = "__Host-signet_session"
    path: str = "/"
    secure: bool = True
    http_only: bool = True
    same_site: str = "strict"

    def as_response_kwargs(self) -> dict[str, str | bool]:
        return {
            "path": self.path,
            "secure": self.secure,
            "httponly": self.http_only,
            "samesite": self.same_site,
        }


class SessionManager:
    """Issue, validate, rotate, and revoke signed opaque web sessions."""

    _VERSION = "s1"
    _MAX_TOKEN_LENGTH = 192

    def __init__(
        self,
        repository: SessionRepository,
        *,
        signing_key: bytes,
        idle_timeout: int = 30 * 60,
        absolute_timeout: int = 12 * 60 * 60,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("session signing key must contain at least 32 bytes")
        if idle_timeout <= 0 or absolute_timeout <= 0:
            raise ValueError("session timeouts must be positive")
        if idle_timeout > absolute_timeout:
            raise ValueError("idle timeout cannot exceed absolute timeout")
        self._repository = repository
        self._signing_key = bytes(signing_key)
        self.idle_timeout = idle_timeout
        self.absolute_timeout = absolute_timeout

    def create_session(
        self,
        user_id: str,
        *,
        auth_method: str,
        now: int,
        previous_token: str | None = None,
    ) -> str:
        """Create a new session and revoke any valid pre-login session.

        Always issuing a fresh random identifier prevents session fixation.  A
        valid previous cookie is revoked even if creating the replacement later
        fails because of an improbable identifier collision.
        """

        user_id = canonical_user_id(user_id)
        if (
            not auth_method
            or len(auth_method.encode("ascii", errors="ignore")) != len(auth_method)
            or len(auth_method) > 64
        ):
            raise ValueError("a bounded user and authentication method are required")
        if previous_token is not None:
            self.logout(previous_token, now=now)

        for _ in range(4):
            session_id = _base64url_encode(secrets.token_bytes(32))
            record = SessionRecord(
                session_id=session_id,
                user_id=user_id,
                auth_method=auth_method,
                created_at=now,
                last_seen_at=now,
                absolute_expires_at=now + self.absolute_timeout,
            )
            if self._repository.create(record):
                return self._encode(session_id)
        raise AuthenticationError("could not allocate a session")

    def authenticate(self, token: str | None, *, now: int) -> SessionPrincipal:
        session_id = self._decode(token)
        record = self._repository.use_and_touch(
            session_id,
            now=now,
            idle_timeout=self.idle_timeout,
        )
        if record is None:
            raise InvalidSession("invalid or expired session")
        return SessionPrincipal(
            user_id=record.user_id,
            session_id=record.session_id,
            auth_method=record.auth_method,
            created_at=record.created_at,
            absolute_expires_at=record.absolute_expires_at,
        )

    def logout(self, token: str | None, *, now: int) -> bool:
        try:
            session_id = self._decode(token)
        except InvalidSession:
            return False
        return self._repository.revoke(session_id, revoked_at=now)

    def _encode(self, session_id: str) -> str:
        return _encode_session_token(session_id, self._signing_key)

    def _decode(self, token: str | None) -> str:
        if token is None or not token or len(token) > self._MAX_TOKEN_LENGTH:
            raise InvalidSession("invalid or expired session")
        try:
            version, session_id, supplied_signature = token.split(".")
            if version != self._VERSION or not session_id or not supplied_signature:
                raise ValueError
            raw_id = _base64url_decode(session_id)
            raw_signature = _base64url_decode(supplied_signature)
            if len(raw_id) != 32 or len(raw_signature) != hashlib.sha256().digest_size:
                raise ValueError
            if _base64url_encode(raw_id) != session_id:
                raise ValueError
            payload = f"{version}.{session_id}".encode("ascii")
        except (UnicodeError, ValueError):
            raise InvalidSession("invalid or expired session") from None
        expected_signature = hmac.new(self._signing_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_signature, raw_signature):
            raise InvalidSession("invalid or expired session")
        return session_id


@dataclass(frozen=True, slots=True, repr=False)
class PasswordCredential:
    credential_id: str
    user_id: str
    verifier: str
    disabled: bool = False

    def __repr__(self) -> str:
        return (
            "PasswordCredential("
            f"credential_id={self.credential_id!r}, user_id={self.user_id!r}, "
            f"verifier=<redacted>, disabled={self.disabled!r})"
        )


class PasswordCredentialRepository(Protocol):
    def find_password(self, user_id: str) -> PasswordCredential | None: ...


class SQLitePasswordCredentialRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def find_password(self, user_id: str) -> PasswordCredential | None:
        user_id = canonical_user_id(user_id)
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT credential_id, user_id, public_material, disabled_at
                FROM auth_credentials
                WHERE user_id = ? AND kind = 'password' AND disabled_at IS NULL
                """,
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        material = row["public_material"]
        verifier = bytes(material).decode("utf-8") if not isinstance(material, str) else material
        return PasswordCredential(
            credential_id=str(row["credential_id"]),
            user_id=str(row["user_id"]),
            verifier=verifier,
            disabled=row["disabled_at"] is not None,
        )

    def replace_password(self, credential: PasswordCredential, *, now: int) -> None:
        user_id = canonical_user_id(credential.user_id)
        if credential.disabled or not credential.verifier.startswith("$argon2id$"):
            raise ValueError("an active Argon2id verifier is required")
        _bounded_identifier(credential.credential_id, name="credential ID", maximum=256)
        with self.database.transaction() as connection:
            _ensure_auth_user(connection, user_id, created_at=now)
            connection.execute(
                """
                UPDATE auth_credentials SET disabled_at = ?
                WHERE user_id = ? AND kind = 'password' AND disabled_at IS NULL
                """,
                (now, user_id),
            )
            connection.execute(
                """
                INSERT INTO auth_credentials(
                    credential_id, user_id, kind, public_material, enrolled_at
                ) VALUES (?, ?, 'password', ?, ?)
                """,
                (credential.credential_id, user_id, credential.verifier.encode(), now),
            )
            _revoke_user_sessions(connection, user_id, revoked_at=now)


class PasswordVerifier(Protocol):
    def verify(self, password: str, encoded_verifier: str) -> bool: ...

    def create_dummy_verifier(self) -> str: ...


class Argon2PasswordVerifier:
    """Production Argon2id verifier; password enrolment is intentionally elsewhere."""

    def __init__(self, password_hasher: PasswordHasher | None = None) -> None:
        self._hasher = password_hasher or PasswordHasher(
            time_cost=3,
            memory_cost=65_536,
            parallelism=1,
            hash_len=32,
            salt_len=16,
        )

    def verify(self, password: str, encoded_verifier: str) -> bool:
        if (
            not password
            or len(password.encode("utf-8")) > 1_024
            or not encoded_verifier.startswith("$argon2id$")
        ):
            return False
        try:
            return bool(self._hasher.verify(encoded_verifier, password))
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            return False

    def create_dummy_verifier(self) -> str:
        return self._hasher.hash(secrets.token_urlsafe(32))


class AttemptLimiter(Protocol):
    """Shared rate-limit boundary used independently of the transport path."""

    def reserve(
        self,
        key: str,
        *,
        source_key: str,
        now: int,
    ) -> AttemptReservation: ...

    def record_failure(self, reservation: AttemptReservation, *, now: int) -> None: ...

    def record_success(self, reservation: AttemptReservation, *, now: int) -> None: ...


@dataclass(frozen=True, slots=True)
class AttemptState:
    failures: int = 0
    locked_until: int | None = None
    last_attempt_id: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class AttemptReservation:
    attempt_id: str
    scope_keys: tuple[str, ...]

    def __repr__(self) -> str:
        return "AttemptReservation(attempt_id=<redacted>, scopes=<redacted>)"


class InMemoryAttemptLimiter:
    """Thread-safe escalating limiter for tests and single-process development."""

    def __init__(
        self,
        *,
        lock_schedule: tuple[tuple[int, int], ...] = (
            (3, 5),
            (5, 30),
            (7, 5 * 60),
            (10, 60 * 60),
        ),
    ) -> None:
        if not lock_schedule or any(
            failures <= 0 or seconds <= 0 for failures, seconds in lock_schedule
        ):
            raise ValueError("lock schedule must contain positive thresholds")
        if tuple(sorted(lock_schedule)) != lock_schedule:
            raise ValueError("lock schedule thresholds must be ordered")
        self._schedule = lock_schedule
        self._states: dict[str, AttemptState] = {}
        self._lock = threading.Lock()

    def reserve(
        self,
        key: str,
        *,
        source_key: str,
        now: int,
    ) -> AttemptReservation:
        scopes = tuple(dict.fromkeys((key, source_key)))
        attempt_id = secrets.token_urlsafe(18)
        with self._lock:
            retry_after = max(
                (
                    state.locked_until - now
                    for scope in scopes
                    if (state := self._states.get(scope, AttemptState())).locked_until is not None
                    and now < state.locked_until
                ),
                default=0,
            )
            if retry_after:
                raise AuthenticationRateLimited(retry_after)
            for scope in scopes:
                previous = self._states.get(scope, AttemptState())
                failures = previous.failures + 1
                lock_seconds = _lock_seconds(self._schedule, failures)
                self._states[scope] = AttemptState(
                    failures=failures,
                    locked_until=now + lock_seconds if lock_seconds else None,
                    last_attempt_id=attempt_id,
                )
        return AttemptReservation(attempt_id=attempt_id, scope_keys=scopes)

    def record_failure(self, reservation: AttemptReservation, *, now: int) -> None:
        del reservation, now

    def record_success(self, reservation: AttemptReservation, *, now: int) -> None:
        del now
        with self._lock:
            for scope in reservation.scope_keys:
                state = self._states.get(scope)
                if state is not None and hmac.compare_digest(
                    state.last_attempt_id or "",
                    reservation.attempt_id,
                ):
                    self._states.pop(scope, None)

    def state(self, key: str) -> AttemptState:
        with self._lock:
            return self._states.get(key, AttemptState())


class SQLiteAttemptLimiter:
    """Durable limiter that reserves account and source attempts atomically."""

    def __init__(
        self,
        database: Database,
        *,
        lock_schedule: tuple[tuple[int, int], ...] = (
            (3, 5),
            (5, 30),
            (7, 5 * 60),
            (10, 60 * 60),
        ),
        global_window_seconds: int = 10 * 60,
        global_attempt_limit: int = 200,
        scope_retention_seconds: int = 10 * 60,
        maximum_scope_rows: int = 1_000,
    ) -> None:
        _validate_lock_schedule(lock_schedule)
        if (
            global_window_seconds < 60
            or global_window_seconds > 60 * 60
            or global_attempt_limit < 1
            or global_attempt_limit > 100_000
            or scope_retention_seconds < global_window_seconds
            or scope_retention_seconds > 30 * 24 * 60 * 60
            or maximum_scope_rows < global_attempt_limit * 2 + 1
            or maximum_scope_rows > 1_000_000
        ):
            raise ValueError("durable rate-limiter bounds are invalid")
        self.database = database
        self._schedule = lock_schedule
        self._global_window_seconds = global_window_seconds
        self._global_attempt_limit = global_attempt_limit
        self._scope_retention_seconds = scope_retention_seconds
        self._maximum_scope_rows = maximum_scope_rows

    def reserve(
        self,
        key: str,
        *,
        source_key: str,
        now: int,
    ) -> AttemptReservation:
        scopes = tuple(dict.fromkeys((key, source_key)))
        for scope in scopes:
            _bounded_identifier(scope, name="rate-limit scope", maximum=128)
        attempt_id = secrets.token_urlsafe(18)
        with self.database.transaction() as connection:
            global_row = connection.execute(
                "SELECT * FROM auth_rate_windows WHERE scope_key = 'auth:global'"
            ).fetchone()
            if global_row is not None and now < int(global_row["window_start"]):
                raise AuthenticationRateLimited(self._global_window_seconds)
            window_start = int(global_row["window_start"]) if global_row is not None else now
            attempts = int(global_row["attempts"]) if global_row is not None else 0
            if now >= window_start + self._global_window_seconds:
                window_start = now
                attempts = 0
            blocked_until = (
                int(global_row["blocked_until"])
                if global_row is not None and global_row["blocked_until"] is not None
                else None
            )
            if blocked_until is not None and now < blocked_until:
                raise AuthenticationRateLimited(max(1, blocked_until - now))
            attempts += 1
            next_block = (
                window_start + self._global_window_seconds
                if attempts >= self._global_attempt_limit
                else None
            )
            connection.execute(
                """
                INSERT INTO auth_rate_windows(
                    scope_key, window_start, attempts, blocked_until, updated_at
                ) VALUES ('auth:global', ?, ?, ?, ?)
                ON CONFLICT(scope_key) DO UPDATE SET
                    window_start = excluded.window_start,
                    attempts = excluded.attempts,
                    blocked_until = excluded.blocked_until,
                    updated_at = excluded.updated_at
                """,
                (window_start, attempts, next_block, now),
            )
            connection.execute(
                """
                DELETE FROM auth_attempts WHERE rowid IN (
                    SELECT rowid FROM auth_attempts
                    WHERE updated_at <= ?
                      AND (locked_until IS NULL OR locked_until <= ?)
                    ORDER BY updated_at LIMIT 500
                )
                """,
                (max(0, now - self._scope_retention_seconds), now),
            )
            rows = {
                str(row["scope_key"]): row
                for row in connection.execute(
                    """
                    SELECT * FROM auth_attempts
                    WHERE scope_key IN (SELECT value FROM json_each(?))
                    """,
                    (json.dumps(scopes, separators=(",", ":")),),
                ).fetchall()
            }
            missing = sum(scope not in rows for scope in scopes)
            stored = int(connection.execute("SELECT count(*) FROM auth_attempts").fetchone()[0])
            if stored + missing > self._maximum_scope_rows:
                raise AuthenticationRateLimited(self._global_window_seconds)
            retry_after = max(
                (
                    int(row["locked_until"]) - now
                    for row in rows.values()
                    if row["locked_until"] is not None and now < int(row["locked_until"])
                ),
                default=0,
            )
            if retry_after:
                raise AuthenticationRateLimited(retry_after)
            for scope in scopes:
                row = rows.get(scope)
                failures = (int(row["failures"]) if row is not None else 0) + 1
                lock_seconds = _lock_seconds(self._schedule, failures)
                connection.execute(
                    """
                    INSERT INTO auth_attempts(
                        scope_key, failures, locked_until, last_attempt_id, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(scope_key) DO UPDATE SET
                        failures = excluded.failures,
                        locked_until = excluded.locked_until,
                        last_attempt_id = excluded.last_attempt_id,
                        updated_at = excluded.updated_at
                    """,
                    (
                        scope,
                        failures,
                        now + lock_seconds if lock_seconds else None,
                        attempt_id,
                        now,
                    ),
                )
        return AttemptReservation(attempt_id=attempt_id, scope_keys=scopes)

    def record_failure(self, reservation: AttemptReservation, *, now: int) -> None:
        del reservation, now

    def record_success(self, reservation: AttemptReservation, *, now: int) -> None:
        with self.database.transaction() as connection:
            for scope in reservation.scope_keys:
                connection.execute(
                    """
                    DELETE FROM auth_attempts
                    WHERE scope_key = ? AND last_attempt_id = ?
                    """,
                    (scope, reservation.attempt_id),
                )

    def state(self, key: str) -> AttemptState:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM auth_attempts WHERE scope_key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return AttemptState()
        return AttemptState(
            failures=int(row["failures"]),
            locked_until=(int(row["locked_until"]) if row["locked_until"] is not None else None),
            last_attempt_id=str(row["last_attempt_id"]),
        )


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedUser:
    user_id: str
    credential_id: str
    capability: str
    method: str = "password"

    def __repr__(self) -> str:
        return (
            "AuthenticatedUser("
            f"user_id={self.user_id!r}, credential_id=<redacted>, "
            f"method={self.method!r}, capability=<redacted>)"
        )


class TotpLoginProof(Protocol):
    credential_id: str
    user_id: str
    use_id: str
    binding: ActionBinding
    session_id: str | None
    http_method: str
    rate_limit_key: str
    attempt_reservation: AttemptReservation
    capability: str


class WebAuthnLoginProof(Protocol):
    credential_id: str
    user_id: str
    challenge_id: str
    use_id: str
    binding: ActionBinding
    session_id: str
    http_method: str
    expected_counter: int
    new_counter: int
    device_type: str
    expected_backup_eligible: bool
    new_backup_eligible: bool
    previous_backed_up: bool
    new_backed_up: bool
    capability: str


class SQLiteAuthenticationTransactions:
    """Complete login proofs and rotate sessions in one durable transaction."""

    def __init__(
        self,
        database: Database,
        *,
        signing_key: bytes,
        capabilities: ProofCapability,
        idle_timeout: int = 30 * 60,
        absolute_timeout: int = 12 * 60 * 60,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("session signing key must contain at least 32 bytes")
        if idle_timeout <= 0 or absolute_timeout <= 0 or idle_timeout > absolute_timeout:
            raise ValueError("invalid session timeouts")
        self.database = database
        self._signing_key = bytes(signing_key)
        self._capabilities = capabilities
        self.idle_timeout = idle_timeout
        self.absolute_timeout = absolute_timeout
        self._fault_injector = fault_injector

    def complete_totp_login(
        self,
        password_user: AuthenticatedUser,
        proof: TotpLoginProof,
        *,
        now: int,
    ) -> str:
        user_id = canonical_user_id(password_user.user_id)
        if (
            password_user.method != "password"
            or proof.user_id != user_id
            or proof.binding != ActionBinding("login")
            or proof.session_id is None
            or proof.http_method != "POST"
            or not self._capabilities.verify(
                password_user.capability,
                domain=PASSWORD_PROOF_DOMAIN,
                claims=password_proof_claims(
                    user_id=password_user.user_id,
                    credential_id=password_user.credential_id,
                    method=password_user.method,
                ),
            )
            or not self._capabilities.verify(
                proof.capability,
                domain=TOTP_PROOF_DOMAIN,
                claims=totp_proof_claims(
                    credential_id=proof.credential_id,
                    credential_user_id=proof.user_id,
                    user_id=proof.user_id,
                    use_id=proof.use_id,
                    binding=proof.binding,
                    path="web",
                    session_id=proof.session_id,
                    http_method=proof.http_method,
                    rate_limit_key=proof.rate_limit_key,
                    attempt_id=proof.attempt_reservation.attempt_id,
                    attempt_scope_keys=proof.attempt_reservation.scope_keys,
                ),
            )
        ):
            raise InvalidCredentials("invalid credentials")
        return self._complete_login(
            user_id=user_id,
            credential_id=proof.credential_id,
            previous_session_id=proof.session_id,
            auth_method="password+totp",
            kind="totp",
            use_id=proof.use_id,
            now=now,
            consume=lambda connection, session_id: self._consume_totp_login(
                connection,
                proof,
                password_credential_id=password_user.credential_id,
                session_id=session_id,
                now=now,
            ),
        )

    def complete_webauthn_login(self, proof: WebAuthnLoginProof, *, now: int) -> str:
        user_id = canonical_user_id(proof.user_id)
        if (
            proof.binding != ActionBinding("login")
            or proof.http_method != "POST"
            or not self._capabilities.verify(
                proof.capability,
                domain=WEBAUTHN_PROOF_DOMAIN,
                claims=webauthn_proof_claims(
                    credential_id=proof.credential_id,
                    credential_user_id=proof.user_id,
                    user_id=proof.user_id,
                    challenge_id=proof.challenge_id,
                    use_id=proof.use_id,
                    binding=proof.binding,
                    path="web",
                    session_id=proof.session_id,
                    http_method=proof.http_method,
                    expected_counter=proof.expected_counter,
                    new_counter=proof.new_counter,
                    device_type=proof.device_type,
                    expected_backup_eligible=proof.expected_backup_eligible,
                    new_backup_eligible=proof.new_backup_eligible,
                    previous_backed_up=proof.previous_backed_up,
                    new_backed_up=proof.new_backed_up,
                ),
            )
        ):
            raise InvalidCredentials("invalid credentials")
        return self._complete_login(
            user_id=user_id,
            credential_id=proof.credential_id,
            previous_session_id=proof.session_id,
            auth_method="webauthn",
            kind="webauthn",
            use_id=proof.use_id,
            now=now,
            consume=lambda connection, session_id: self._consume_webauthn_login(
                connection,
                proof,
                session_id=session_id,
                now=now,
            ),
        )

    def revoke_user_sessions(self, user_id: str, *, now: int) -> int:
        user_id = canonical_user_id(user_id)
        with self.database.transaction() as connection:
            return _revoke_user_sessions(connection, user_id, revoked_at=now)

    def _complete_login(
        self,
        *,
        user_id: str,
        credential_id: str,
        previous_session_id: str,
        auth_method: str,
        kind: str,
        use_id: str,
        now: int,
        consume: Callable[[object, str], None],
    ) -> str:
        _bounded_identifier(previous_session_id, name="session ID", maximum=128)
        _bounded_identifier(credential_id, name="credential ID", maximum=256)
        _bounded_identifier(use_id, name="confirmation use ID", maximum=256)
        for _ in range(4):
            session_id = _base64url_encode(secrets.token_bytes(32))
            try:
                with self.database.transaction() as connection:
                    _require_active_session(
                        connection,
                        previous_session_id,
                        user_id=user_id,
                        now=now,
                        idle_timeout=self.idle_timeout,
                    )
                    _ensure_auth_user(connection, user_id, created_at=now)
                    generation = int(
                        connection.execute(
                            "SELECT auth_generation FROM auth_users WHERE user_id = ?",
                            (user_id,),
                        ).fetchone()[0]
                    )
                    connection.execute(
                        """
                        INSERT INTO web_sessions(
                            session_id, user_id, auth_method, credential_id,
                            auth_generation, created_at, last_seen_at,
                            absolute_expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            user_id,
                            auth_method,
                            credential_id,
                            generation,
                            now,
                            now,
                            now + self.absolute_timeout,
                        ),
                    )
                    consume(connection, session_id)
                    connection.execute(
                        """
                        INSERT INTO auth_proof_consumptions(
                            kind, use_id, purpose, consumed_at
                        ) VALUES (?, ?, 'login', ?)
                        """,
                        (kind, use_id, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO auth_login_consumptions(
                            kind, use_id, user_id, session_id, consumed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (kind, use_id, user_id, session_id, now),
                    )
                    connection.execute(
                        """
                        UPDATE web_sessions SET revoked_at = ?
                        WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL
                        """,
                        (now, previous_session_id, user_id),
                    )
                    if self._fault_injector is not None:
                        self._fault_injector("login:before_commit")
            except IntegrityError as exc:
                if "web_sessions.session_id" in str(exc):
                    continue
                raise InvalidCredentials("invalid or replayed login proof") from exc
            return _encode_session_token(session_id, self._signing_key)
        raise AuthenticationError("could not allocate a session")

    @staticmethod
    def _consume_totp_login(
        connection: object,
        proof: TotpLoginProof,
        *,
        password_credential_id: str,
        session_id: str,
        now: int,
    ) -> None:
        password = connection.execute(  # type: ignore[attr-defined]
            """
            SELECT 1 FROM auth_credentials
            WHERE credential_id = ? AND user_id = ? AND kind = 'password'
              AND disabled_at IS NULL
            """,
            (password_credential_id, proof.user_id),
        ).fetchone()
        if password is None:
            raise InvalidCredentials("invalid credentials")
        credential = connection.execute(  # type: ignore[attr-defined]
            """
            UPDATE auth_credentials SET last_used_at = ?
            WHERE credential_id = ? AND user_id = ? AND kind = 'totp'
              AND disabled_at IS NULL
            RETURNING credential_id
            """,
            (now, proof.credential_id, proof.user_id),
        ).fetchone()
        if credential is None:
            raise InvalidCredentials("invalid credentials")
        del session_id
        _settle_attempt_success(connection, proof.attempt_reservation)

    @staticmethod
    def _consume_webauthn_login(
        connection: object,
        proof: WebAuthnLoginProof,
        *,
        session_id: str,
        now: int,
    ) -> None:
        del session_id
        _consume_webauthn_credential(connection, proof, now=now)
        consumed = connection.execute(  # type: ignore[attr-defined]
            """
            UPDATE auth_challenges SET consumed_at = ?
            WHERE challenge_id = ? AND user_id = ? AND action = 'login'
              AND request_id IS NULL AND session_id = ? AND http_method = 'POST'
              AND consumed_at IS NULL AND invalidated_at IS NULL
              AND created_at <= ? AND expires_at > ?
              AND EXISTS (
                  SELECT 1 FROM json_each(offered_credential_ids_json)
                  WHERE value = ?
              )
            """,
            (
                now,
                proof.challenge_id,
                proof.user_id,
                proof.session_id,
                now,
                now,
                proof.credential_id,
            ),
        ).rowcount
        if consumed != 1:
            raise InvalidCredentials("invalid or replayed login proof")


class PasswordAuthenticator:
    """Verify a stored password while keeping lookup failures indistinguishable."""

    def __init__(
        self,
        repository: PasswordCredentialRepository,
        limiter: AttemptLimiter,
        *,
        capabilities: ProofCapability,
        verifier: PasswordVerifier | None = None,
    ) -> None:
        self._repository = repository
        self._limiter = limiter
        self._verifier = verifier or Argon2PasswordVerifier()
        self._dummy_verifier = self._verifier.create_dummy_verifier()
        self._capabilities = capabilities

    def authenticate(
        self,
        user_id: str,
        password: str,
        *,
        now: int,
        source_id: str = "local-web",
    ) -> AuthenticatedUser:
        user_id = canonical_user_id(user_id)
        key = password_rate_limit_key(user_id)
        reservation = self._limiter.reserve(
            key,
            source_key=source_rate_limit_key(source_id),
            now=now,
        )
        credential = self._repository.find_password(user_id)
        encoded = (
            credential.verifier
            if credential is not None and credential.user_id == user_id and not credential.disabled
            else self._dummy_verifier
        )
        valid = self._verifier.verify(password, encoded)
        if not valid or credential is None or credential.user_id != user_id or credential.disabled:
            self._limiter.record_failure(reservation, now=now)
            raise InvalidCredentials("invalid credentials")
        self._limiter.record_success(reservation, now=now)
        method = "password"
        capability = self._capabilities.seal(
            PASSWORD_PROOF_DOMAIN,
            password_proof_claims(
                user_id=credential.user_id,
                credential_id=credential.credential_id,
                method=method,
            ),
        )
        return AuthenticatedUser(
            user_id=credential.user_id,
            credential_id=credential.credential_id,
            capability=capability,
            method=method,
        )


def password_rate_limit_key(user_id: str) -> str:
    return f"password:{hashlib.sha256(canonical_user_id(user_id).encode()).hexdigest()}"


def totp_rate_limit_key(user_id: str) -> str:
    return f"totp:{hashlib.sha256(canonical_user_id(user_id).encode()).hexdigest()}"


def source_rate_limit_key(source_id: str) -> str:
    source_id = _bounded_identifier(source_id, name="authentication source", maximum=256)
    return f"auth-source:{hashlib.sha256(source_id.encode()).hexdigest()}"


def canonical_user_id(user_id: str) -> str:
    if not isinstance(user_id, str):
        raise InvalidCredentials("invalid credentials")
    normalized = unicodedata.normalize("NFC", user_id)
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeError:
        raise InvalidCredentials("invalid credentials") from None
    if (
        normalized != user_id
        or not encoded
        or len(encoded) > 256
        or any(unicodedata.category(character).startswith("C") for character in normalized)
    ):
        raise InvalidCredentials("invalid credentials")
    return normalized


def _bounded_identifier(value: str, *, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{name} is invalid") from None
    if not encoded or len(encoded) > maximum or any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} is invalid")
    return value


def _validate_lock_schedule(lock_schedule: tuple[tuple[int, int], ...]) -> None:
    if not lock_schedule or any(
        failures <= 0 or seconds <= 0 for failures, seconds in lock_schedule
    ):
        raise ValueError("lock schedule must contain positive thresholds")
    if tuple(sorted(lock_schedule)) != lock_schedule:
        raise ValueError("lock schedule thresholds must be ordered")


def _lock_seconds(schedule: tuple[tuple[int, int], ...], failures: int) -> int:
    seconds = 0
    for threshold, duration in schedule:
        if failures >= threshold:
            seconds = duration
    return seconds


def _ensure_auth_user(connection: object, user_id: str, *, created_at: int) -> None:
    connection.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO auth_users(user_id, created_at) VALUES (?, ?)
        ON CONFLICT(user_id) DO NOTHING
        """,
        (user_id, created_at),
    )


def _revoke_user_sessions(connection: object, user_id: str, *, revoked_at: int) -> int:
    _ensure_auth_user(connection, user_id, created_at=revoked_at)
    connection.execute(  # type: ignore[attr-defined]
        """
        UPDATE auth_users
        SET auth_generation = auth_generation + 1, credentials_changed_at = ?
        WHERE user_id = ?
        """,
        (revoked_at, user_id),
    )
    return int(
        connection.execute(  # type: ignore[attr-defined]
            """
            UPDATE web_sessions SET revoked_at = max(?, created_at)
            WHERE user_id = ? AND revoked_at IS NULL
            """,
            (revoked_at, user_id),
        ).rowcount
    )


def _session_record(row: object) -> SessionRecord:
    return SessionRecord(
        session_id=str(row["session_id"]),  # type: ignore[index]
        user_id=str(row["user_id"]),  # type: ignore[index]
        auth_method=str(row["auth_method"]),  # type: ignore[index]
        credential_id=(
            str(row["credential_id"])  # type: ignore[index]
            if row["credential_id"] is not None  # type: ignore[index]
            else None
        ),
        auth_generation=int(row["auth_generation"]),  # type: ignore[index]
        created_at=int(row["created_at"]),  # type: ignore[index]
        last_seen_at=int(row["last_seen_at"]),  # type: ignore[index]
        absolute_expires_at=int(row["absolute_expires_at"]),  # type: ignore[index]
        revoked_at=(
            int(row["revoked_at"])  # type: ignore[index]
            if row["revoked_at"] is not None  # type: ignore[index]
            else None
        ),
    )


def _encode_session_token(session_id: str, signing_key: bytes) -> str:
    payload = f"{SessionManager._VERSION}.{session_id}"
    signature = hmac.new(signing_key, payload.encode("ascii"), hashlib.sha256).digest()
    return f"{payload}.{_base64url_encode(signature)}"


def _require_active_session(
    connection: object,
    session_id: str,
    *,
    user_id: str,
    now: int,
    idle_timeout: int,
) -> None:
    row = connection.execute(  # type: ignore[attr-defined]
        """
        SELECT 1 FROM web_sessions AS session
        JOIN auth_users AS user ON user.user_id = session.user_id
        WHERE session.session_id = ? AND session.user_id = ?
          AND session.revoked_at IS NULL AND session.created_at <= ?
          AND session.last_seen_at + ? > ?
          AND session.absolute_expires_at > ?
          AND session.auth_generation = user.auth_generation
        """,
        (session_id, user_id, now, idle_timeout, now, now),
    ).fetchone()
    if row is None:
        raise InvalidSession("invalid or expired session")


def _settle_attempt_success(connection: object, reservation: AttemptReservation) -> None:
    for scope in reservation.scope_keys:
        connection.execute(  # type: ignore[attr-defined]
            """
            DELETE FROM auth_attempts
            WHERE scope_key = ? AND last_attempt_id = ?
            """,
            (scope, reservation.attempt_id),
        )


def _consume_webauthn_credential(
    connection: object,
    proof: WebAuthnLoginProof,
    *,
    now: int,
) -> None:
    if proof.expected_counter < 0 or not (
        proof.expected_counter == proof.new_counter == 0
        or proof.new_counter > proof.expected_counter
    ):
        raise InvalidCredentials("invalid WebAuthn credential state")
    if (
        proof.expected_backup_eligible != proof.new_backup_eligible
        or (not proof.new_backup_eligible and proof.new_backed_up)
        or (proof.previous_backed_up and not proof.new_backed_up)
    ):
        raise InvalidCredentials("invalid WebAuthn credential state")
    updated = connection.execute(  # type: ignore[attr-defined]
        """
        UPDATE auth_credentials
        SET sign_count = ?, backup_eligible = ?, backup_state = ?, last_used_at = ?
        WHERE credential_id = ? AND user_id = ? AND kind = 'webauthn'
          AND disabled_at IS NULL AND sign_count = ?
          AND backup_eligible = ? AND backup_state = ?
        """,
        (
            proof.new_counter,
            int(proof.new_backup_eligible),
            int(proof.new_backed_up),
            now,
            proof.credential_id,
            proof.user_id,
            proof.expected_counter,
            int(proof.expected_backup_eligible),
            int(proof.previous_backed_up),
        ),
    ).rowcount
    if updated != 1:
        raise InvalidCredentials("invalid WebAuthn credential state")


def _binding_claims(binding: ActionBinding) -> dict[str, object]:
    return {
        "action": binding.action,
        "payload_hash": binding.payload_hash,
        "prospective_payload_hash": binding.prospective_payload_hash,
        "request_id": binding.request_id,
        "version": binding.version,
    }


def _proof_capability_payload(domain: str, claims: Mapping[str, object]) -> bytes:
    if domain not in _PROOF_DOMAINS or not claims:
        raise ValueError("invalid proof capability domain or claims")
    normalized: dict[str, object] = {}
    for key, value in claims.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            raise ValueError("invalid proof capability claim")
        if isinstance(value, list):
            if len(value) > 16 or not all(
                isinstance(item, str) and len(item.encode("utf-8")) <= 256 for item in value
            ):
                raise ValueError("invalid proof capability claim")
            normalized[key] = list(value)
        elif value is None or isinstance(value, bool | int | str):
            if isinstance(value, str) and len(value.encode("utf-8")) > 4_096:
                raise ValueError("invalid proof capability claim")
            normalized[key] = value
        else:
            raise ValueError("invalid proof capability claim")
    encoded = json.dumps(
        {"claims": normalized, "v": 1},
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(encoded) > 32_768:
        raise ValueError("proof capability claims are too large")
    return b"signet-auth-proof-v1\x00" + domain.encode("ascii") + b"\x00" + encoded


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if not value or any(character not in _BASE64URL_ALPHABET for character in value):
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if _base64url_encode(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
