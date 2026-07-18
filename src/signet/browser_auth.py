"""Durable browser-only initial-owner bootstrap state machine."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from argon2 import PasswordHasher

from signet.auth import (
    ActionBinding,
    _disable_auth_factors,
    _ensure_auth_user,
    _register_auth_factor,
    _revoke_user_sessions,
    canonical_user_id,
)
from signet.authenticator_management import AuthenticatorManager, FactorMetadata
from signet.db import Database, IntegrityError
from signet.totp import TotpVerifier, VerifiedTotp
from signet.totp_enrollment import (
    IssuedTotpEnrollment,
    TotpEnrollment,
    TotpEnrollmentService,
)
from signet.webauthn import (
    IssuedWebAuthnChallenge,
    SQLiteWebAuthnRepository,
    VerifiedWebAuthn,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnCredential,
)
from signet.webauthn_registration import (
    IssuedRegistration,
    PasskeyRegistrationService,
    PendingRegistration,
)


class BootstrapError(RuntimeError):
    pass


class BootstrapAlreadyComplete(BootstrapError):
    pass


class BootstrapIncomplete(BootstrapError):
    pass


class BootstrapOwnerMismatch(BootstrapError):
    pass


class PasswordEnroller(Protocol):
    def hash(self, password: str) -> str: ...


class Argon2PasswordEnroller:
    """Create the same bounded Argon2id verifier accepted by login."""

    def __init__(self, password_hasher: PasswordHasher | None = None) -> None:
        self._hasher = password_hasher or PasswordHasher(
            time_cost=3,
            memory_cost=65_536,
            parallelism=1,
            hash_len=32,
            salt_len=16,
        )

    def hash(self, password: str) -> str:
        encoded = password.encode("utf-8")
        if len(encoded) < 12 or len(encoded) > 1_024:
            raise ValueError("password must contain between 12 and 1024 UTF-8 bytes")
        return self._hasher.hash(password)


@dataclass(frozen=True, slots=True)
class BootstrapStatus:
    user_id: str
    complete: bool
    has_password: bool
    has_authenticator: bool
    factor_labels: tuple[str, ...]
    updated_at: int

    @property
    def can_complete(self) -> bool:
        return self.has_password and self.has_authenticator and not self.complete


class BootstrapService:
    """One-time durable bootstrap for the production owner account."""

    def __init__(
        self,
        database: Database,
        *,
        owner_user_id: str,
        password_enroller: PasswordEnroller | None = None,
    ) -> None:
        self.database = database
        self.owner_user_id = canonical_user_id(owner_user_id)
        self.password_enroller = password_enroller or Argon2PasswordEnroller()

    def status(self, *, now: int) -> BootstrapStatus:
        self._ensure_state(now=now)
        with self.database.read() as connection:
            state = connection.execute(
                "SELECT * FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT f.kind, f.label
                FROM auth_factors AS f
                JOIN auth_credentials AS c ON c.credential_id = f.credential_id
                WHERE f.user_id = ? AND f.state = 'active'
                  AND c.user_id = f.user_id AND c.kind = f.kind
                  AND c.disabled_at IS NULL
                ORDER BY f.created_at, f.factor_id
                """,
                (self.owner_user_id,),
            ).fetchall()
        assert state is not None
        kinds = tuple(str(row["kind"]) for row in rows)
        return BootstrapStatus(
            user_id=self.owner_user_id,
            complete=str(state["status"]) == "complete",
            has_password="password" in kinds,
            has_authenticator=any(kind in {"totp", "webauthn"} for kind in kinds),
            factor_labels=tuple(
                str(row["label"]) for row in rows if str(row["kind"]) in {"totp", "webauthn"}
            ),
            updated_at=int(state["updated_at"]),
        )

    def enroll_password(self, password: str, *, now: int) -> BootstrapStatus:
        self._ensure_pending(now=now)
        verifier = self.password_enroller.hash(password)
        if not verifier.startswith("$argon2id$"):
            raise ValueError("password enroller must return an Argon2id verifier")
        credential_id = f"password_{secrets.token_urlsafe(24)}"
        label = "Password"
        with self.database.transaction() as connection:
            self._require_pending(connection)
            _ensure_auth_user(connection, self.owner_user_id, created_at=now)
            connection.execute(
                """
                UPDATE auth_credentials SET disabled_at = ?
                WHERE user_id = ? AND kind = 'password' AND disabled_at IS NULL
                """,
                (now, self.owner_user_id),
            )
            _disable_auth_factors(
                connection,
                user_id=self.owner_user_id,
                kind="password",
                now=now,
            )
            connection.execute(
                """
                INSERT INTO auth_credentials(
                    credential_id, user_id, kind, public_material, enrolled_at, factor_label
                ) VALUES (?, ?, 'password', ?, ?, ?)
                """,
                (credential_id, self.owner_user_id, verifier.encode(), now, label),
            )
            _register_auth_factor(
                connection,
                credential_id=credential_id,
                user_id=self.owner_user_id,
                kind="password",
                label=label,
                now=now,
                operation_id="browser-bootstrap-password",
            )
            _revoke_user_sessions(connection, self.owner_user_id, revoked_at=now)
            connection.execute(
                """
                    UPDATE browser_bootstrap_state
                    SET updated_at = max(updated_at, ?)
                    WHERE state_id = 1
                    """,
                (now,),
            )
        return self.status(now=now)

    def enroll_passkey(
        self,
        label: str,
        credential: WebAuthnCredential,
        *,
        now: int,
    ) -> BootstrapStatus:
        selected_label = _label(label)
        if credential.user_id != self.owner_user_id or credential.disabled:
            raise ValueError("an active owner passkey credential is required")
        if credential.user_handle != _user_handle(self.owner_user_id):
            raise ValueError("passkey user handle does not match the bootstrap owner")
        self._ensure_pending(now=now)
        try:
            with self.database.transaction() as connection:
                self._require_pending(connection)
                _ensure_auth_user(connection, self.owner_user_id, created_at=now)
                connection.execute(
                    """
                    INSERT INTO auth_credentials(
                        credential_id, user_id, kind, public_material, enrolled_at,
                        sign_count, backup_eligible, backup_state, user_handle,
                        factor_label, transports_json, discoverable
                    ) VALUES (?, ?, 'webauthn', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential.credential_id,
                        self.owner_user_id,
                        credential.public_key,
                        now,
                        credential.sign_count,
                        int(credential.device_type == "multi_device"),
                        int(credential.backed_up),
                        credential.user_handle,
                        selected_label,
                        _json_transports(credential.transports),
                        int(credential.discoverable),
                    ),
                )
                _register_auth_factor(
                    connection,
                    credential_id=credential.credential_id,
                    user_id=self.owner_user_id,
                    kind="webauthn",
                    label=selected_label,
                    now=now,
                    operation_id="browser-bootstrap-passkey",
                )
                _revoke_user_sessions(connection, self.owner_user_id, revoked_at=now)
                connection.execute(
                    """
                    UPDATE browser_bootstrap_state
                    SET updated_at = max(updated_at, ?) WHERE state_id = 1
                    """,
                    (now,),
                )
        except IntegrityError:
            raise BootstrapError("passkey is already enrolled or unavailable") from None
        return self.status(now=now)

    def enroll_totp(self, enrollment: TotpEnrollment, *, now: int) -> BootstrapStatus:
        if enrollment.user_id != self.owner_user_id or enrollment.verified_at is None:
            raise BootstrapError("verified owner TOTP enrollment is required")
        self._ensure_pending(now=now)
        try:
            with self.database.transaction() as connection:
                self._require_pending(connection)
                _ensure_auth_user(connection, self.owner_user_id, created_at=now)
                connection.execute(
                    """
                    INSERT INTO auth_credentials(
                        credential_id, user_id, kind, secret_reference, enrolled_at, factor_label
                    ) VALUES (?, ?, 'totp', ?, ?, ?)
                    """,
                    (
                        enrollment.credential_id,
                        self.owner_user_id,
                        enrollment.secret_reference,
                        now,
                        enrollment.label,
                    ),
                )
                _register_auth_factor(
                    connection,
                    credential_id=enrollment.credential_id,
                    user_id=self.owner_user_id,
                    kind="totp",
                    label=enrollment.label,
                    now=now,
                    operation_id="browser-bootstrap-totp",
                )
                _revoke_user_sessions(connection, self.owner_user_id, revoked_at=now)
                connection.execute(
                    """
                    UPDATE browser_bootstrap_state
                    SET updated_at = max(updated_at, ?)
                    WHERE state_id = 1
                    """,
                    (now,),
                )
        except IntegrityError:
            raise BootstrapError("TOTP authenticator is already enrolled or unavailable") from None
        return self.status(now=now)

    def complete(self, *, now: int) -> BootstrapStatus:
        self._ensure_state(now=now)
        with self.database.transaction() as connection:
            self._require_pending(connection)
            rows = connection.execute(
                """
                SELECT f.kind
                FROM auth_factors AS f
                JOIN auth_credentials AS c ON c.credential_id = f.credential_id
                WHERE f.user_id = ? AND f.state = 'active'
                  AND c.user_id = f.user_id AND c.kind = f.kind
                  AND c.disabled_at IS NULL
                """,
                (self.owner_user_id,),
            ).fetchall()
            kinds = {str(row["kind"]) for row in rows}
            if "password" not in kinds or not kinds.intersection({"totp", "webauthn"}):
                raise BootstrapIncomplete(
                    "setup requires a password and at least one passkey or TOTP authenticator"
                )
            updated = connection.execute(
                """
                UPDATE browser_bootstrap_state
                SET status = 'complete', updated_at = max(updated_at, ?), completed_at = ?
                WHERE state_id = 1 AND user_id = ? AND status = 'pending'
                """,
                (now, now, self.owner_user_id),
            ).rowcount
            if int(updated) != 1:
                raise BootstrapAlreadyComplete("initial owner setup is already complete")
        return self.status(now=now)

    def _ensure_pending(self, *, now: int) -> None:
        self._ensure_state(now=now)
        with self.database.read() as connection:
            self._require_pending(connection)

    def _ensure_state(self, *, now: int) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO browser_bootstrap_state(
                    state_id, user_id, status, created_at, updated_at
                ) VALUES (1, ?, 'pending', ?, ?)
                ON CONFLICT(state_id) DO NOTHING
                """,
                (self.owner_user_id, now, now),
            )
            row = connection.execute(
                "SELECT user_id FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
            if row is None or str(row["user_id"]) != self.owner_user_id:
                raise BootstrapOwnerMismatch("browser bootstrap is bound to another owner")

    def _require_pending(self, connection: object) -> None:
        row = connection.execute(  # type: ignore[attr-defined]
            "SELECT user_id, status FROM browser_bootstrap_state WHERE state_id = 1"
        ).fetchone()
        if row is None or str(row["user_id"]) != self.owner_user_id:
            raise BootstrapOwnerMismatch("browser bootstrap is bound to another owner")
        if str(row["status"]) != "pending":
            raise BootstrapAlreadyComplete("initial owner setup is already complete")


ManagementAction = Literal["add_passkey", "add_totp", "rename", "revoke"]


@dataclass(frozen=True, slots=True)
class ManagementIntent:
    action: ManagementAction
    operation_id: str
    factor_id: str | None = None
    label: str | None = None
    registration_id: str | None = None
    compromised: bool = False


class BrowserAuthController:
    """Transport-facing orchestration over registration and factor boundaries."""

    def __init__(
        self,
        *,
        bootstrap: BootstrapService,
        registrations: PasskeyRegistrationService,
        manager: AuthenticatorManager,
        totp_verifier: TotpVerifier,
        webauthn_issuer: WebAuthnChallengeIssuer,
        webauthn_verifier: WebAuthnAssertionVerifier,
        webauthn_repository: SQLiteWebAuthnRepository,
        totp_enrollments: TotpEnrollmentService | None = None,
    ) -> None:
        self.bootstrap = bootstrap
        self.registrations = registrations
        self.manager = manager
        self.totp_verifier = totp_verifier
        self.webauthn_issuer = webauthn_issuer
        self.webauthn_verifier = webauthn_verifier
        self.webauthn_repository = webauthn_repository
        self.totp_enrollments = totp_enrollments

    def list_factors(self, user_id: str) -> tuple[FactorMetadata, ...]:
        return tuple(
            factor
            for factor in self.manager.list_factors(user_id)
            if factor.kind in ("totp", "webauthn")
        )

    def begin_registration(
        self,
        user_id: str,
        label: str,
        *,
        flow: Literal["bootstrap", "management"],
        session_id: str | None,
        now: int,
    ) -> IssuedRegistration:
        existing = tuple(
            credential.credential_id
            for credential in self.webauthn_repository.credentials_for_user(user_id)
        )
        return self.registrations.begin(
            user_id,
            label,
            flow=flow,
            session_id=session_id,
            existing_credential_ids=existing,
            now=now,
        )

    def complete_registration(
        self,
        challenge_id: str,
        credential: Mapping[str, Any],
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> PendingRegistration:
        return self.registrations.complete(
            challenge_id,
            credential,
            user_id=user_id,
            session_id=session_id,
            now=now,
        )

    def commit_bootstrap_passkey(
        self,
        challenge_id: str,
        *,
        now: int,
    ) -> BootstrapStatus:
        pending = self.registrations.pending(
            challenge_id,
            user_id=self.bootstrap.owner_user_id,
            session_id=None,
            now=now,
        )
        status = self.bootstrap.enroll_passkey(pending.label, pending.credential, now=now)
        if not self.registrations.repository.consume(
            challenge_id,
            user_id=self.bootstrap.owner_user_id,
            session_id=None,
            now=now,
        ):
            raise BootstrapError("passkey registration could not be finalized")
        return status

    def begin_totp_enrollment(
        self,
        user_id: str,
        label: str,
        *,
        flow: Literal["bootstrap", "management"],
        session_id: str | None,
        now: int,
    ) -> IssuedTotpEnrollment:
        return self._totp_enrollments().begin(
            user_id,
            label,
            flow=flow,
            session_id=session_id,
            now=now,
        )

    def verify_totp_enrollment(
        self,
        enrollment_id: str,
        proof: str,
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> TotpEnrollment:
        return self._totp_enrollments().verify(
            enrollment_id,
            proof,
            user_id=user_id,
            session_id=session_id,
            now=now,
        )

    def commit_bootstrap_totp(self, enrollment_id: str, *, now: int) -> BootstrapStatus:
        enrollments = self._totp_enrollments()
        pending = enrollments.pending(
            enrollment_id,
            user_id=self.bootstrap.owner_user_id,
            session_id=None,
            now=now,
        )
        status = self.bootstrap.enroll_totp(pending, now=now)
        enrollments.consume(
            enrollment_id,
            user_id=self.bootstrap.owner_user_id,
            session_id=None,
            now=now,
        )
        return status

    def binding_for(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        *,
        now: int,
    ) -> ActionBinding:
        if intent.action == "add_passkey":
            if intent.registration_id is None:
                raise ValueError("passkey registration ID is required")
            pending = self.registrations.pending(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            )
            return self.manager.binding_for_add_passkey(
                user_id,
                pending.label,
                pending.credential,
                intent.operation_id,
            )
        if intent.action == "add_totp":
            if intent.registration_id is None:
                raise ValueError("TOTP enrollment ID is required")
            pending_totp = self._totp_enrollments().pending(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            )
            return self.manager.binding_for_add_preprovisioned_totp(
                user_id,
                pending_totp.label,
                pending_totp.factor_id,
                pending_totp.credential_id,
                pending_totp.secret_reference,
                intent.operation_id,
            )
        if intent.action == "rename":
            if intent.factor_id is None or intent.label is None:
                raise ValueError("rename requires a factor and label")
            return self.manager.binding_for_rename(
                user_id,
                intent.factor_id,
                intent.label,
                intent.operation_id,
            )
        if intent.action == "revoke":
            if intent.factor_id is None:
                raise ValueError("revocation requires a factor")
            return self.manager.binding_for_revoke(
                user_id,
                intent.factor_id,
                intent.operation_id,
                compromised=intent.compromised,
            )
        raise ValueError("unsupported authenticator operation")

    def begin_webauthn_confirmation(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        *,
        now: int,
    ) -> IssuedWebAuthnChallenge:
        binding = self.binding_for(user_id, session_id, intent, now=now)
        return self.webauthn_issuer.issue(
            user_id,
            binding,
            session_id=session_id,
            http_method="POST",
            now=now,
        )

    def apply_with_totp(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        proof: str,
        *,
        source_id: str,
        credential_id: str | None,
        now: int,
    ) -> FactorMetadata:
        binding = self.binding_for(user_id, session_id, intent, now=now)
        verified = self.totp_verifier.verify(
            user_id,
            proof,
            binding=binding,
            now=now,
            source_id=source_id,
            session_id=session_id,
            http_method="POST",
            credential_id=credential_id,
        )
        factor = self._apply(user_id, session_id, intent, verified, now=now)
        self.totp_verifier.record_consumed_success(verified, now=now)
        return factor

    def apply_with_webauthn(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        *,
        challenge_id: str,
        assertion: Mapping[str, Any],
        now: int,
    ) -> FactorMetadata:
        binding = self.binding_for(user_id, session_id, intent, now=now)
        verified = self.webauthn_verifier.verify(
            dict(assertion),
            challenge_id=challenge_id,
            user_id=user_id,
            binding=binding,
            session_id=session_id,
            http_method="POST",
            now=now,
        )
        return self._apply(user_id, session_id, intent, verified, now=now)

    def _apply(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
    ) -> FactorMetadata:
        if intent.action == "add_passkey":
            assert intent.registration_id is not None
            pending = self.registrations.pending(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            )
            factor = self.manager.add_passkey(
                user_id,
                pending.label,
                pending.credential,
                intent.operation_id,
                confirmation,
                now=now,
            )
            if not self.registrations.repository.consume(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            ):
                raise BootstrapError("passkey registration could not be consumed")
            return factor
        if intent.action == "add_totp":
            assert intent.registration_id is not None
            enrollments = self._totp_enrollments()
            pending_totp = enrollments.pending(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            )
            factor = self.manager.add_preprovisioned_totp(
                user_id,
                pending_totp.label,
                pending_totp.factor_id,
                pending_totp.credential_id,
                pending_totp.secret_reference,
                intent.operation_id,
                confirmation,
                now=now,
            )
            enrollments.consume(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            )
            return factor
        if intent.action == "rename":
            assert intent.factor_id is not None and intent.label is not None
            return self.manager.rename_factor(
                user_id,
                intent.factor_id,
                intent.label,
                intent.operation_id,
                confirmation,
                now=now,
            )
        if intent.action == "revoke":
            assert intent.factor_id is not None
            return self.manager.revoke_factor(
                user_id,
                intent.factor_id,
                intent.operation_id,
                confirmation,
                now=now,
                compromised=intent.compromised,
            )
        raise ValueError("unsupported authenticator operation")

    def _totp_enrollments(self) -> TotpEnrollmentService:
        if self.totp_enrollments is None:
            raise BootstrapError("browser TOTP enrollment is unavailable")
        return self.totp_enrollments


def _label(label: str) -> str:
    normalized = " ".join(label.split())
    if not normalized or len(normalized.encode("utf-8")) > 64:
        raise ValueError("factor label must contain at most 64 bytes")
    return normalized


def _user_handle(user_id: str) -> bytes:
    return hashlib.sha256(b"signet-webauthn-user-v1\x00" + user_id.encode()).digest()


def _json_transports(transports: tuple[str, ...]) -> str:
    import json

    return json.dumps(list(transports), separators=(",", ":"))
