"""Durable browser-only initial-owner bootstrap state machine."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
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


class BootstrapClaimRequired(BootstrapError):
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
    claimed: bool = False

    @property
    def can_complete(self) -> bool:
        return self.has_password and self.has_authenticator and not self.complete


class BootstrapService:
    """One-time owner bootstrap claimed by a locally issued one-use capability."""

    def __init__(
        self,
        database: Database,
        *,
        owner_user_id: str,
        password_enroller: PasswordEnroller | None = None,
        totp_enrollments: TotpEnrollmentService | None = None,
    ) -> None:
        self.database = database
        self.owner_user_id = canonical_user_id(owner_user_id)
        self.password_enroller = password_enroller or Argon2PasswordEnroller()
        self.totp_enrollments = totp_enrollments
        self._reconcile_existing_owner()

    def issue_capability(self, *, now: int, lifetime: int = 10 * 60) -> str:
        if now < 0 or lifetime < 60 or lifetime > 60 * 60:
            raise ValueError("bootstrap capability lifetime is invalid")
        with self.database.read() as connection:
            existing = connection.execute(
                "SELECT * FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
            if existing is not None and str(existing["user_id"]) != self.owner_user_id:
                raise BootstrapOwnerMismatch("browser bootstrap is bound to another owner")
            if existing is not None and str(existing["status"]) == "complete":
                raise BootstrapAlreadyComplete("initial owner setup is already complete")
            if (
                existing is not None
                and existing["capability_expires_at"] is not None
                and now < int(existing["capability_expires_at"])
            ):
                raise BootstrapClaimRequired("an unexpired bootstrap ceremony already exists")
            pending_totp_cleanup = (
                int(
                    connection.execute(
                        """
                        SELECT count(*) FROM browser_totp_enrollments
                        WHERE user_id = ? AND flow = 'bootstrap' AND consumed_at IS NULL
                          AND cleanup_completed_at IS NULL
                        """,
                        (self.owner_user_id,),
                    ).fetchone()[0]
                )
                if existing is not None
                else 0
            )
        if pending_totp_cleanup:
            if self.totp_enrollments is None:
                raise BootstrapError("pending bootstrap TOTP cleanup is unavailable")
            self.totp_enrollments.invalidate_bootstrap(
                self.owner_user_id,
                before=now,
                now=now,
            )
        capability_id = secrets.token_urlsafe(18)
        capability = f"sbc1.{capability_id}.{secrets.token_urlsafe(32)}"
        verifier = _bootstrap_verifier(capability)
        expires_at = now + lifetime
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
            if row is not None and str(row["user_id"]) != self.owner_user_id:
                raise BootstrapOwnerMismatch("browser bootstrap is bound to another owner")
            if row is not None and str(row["status"]) == "complete":
                raise BootstrapAlreadyComplete("initial owner setup is already complete")
            if (
                row is not None
                and row["capability_expires_at"] is not None
                and now < int(row["capability_expires_at"])
            ):
                raise BootstrapClaimRequired("an unexpired bootstrap ceremony already exists")
            if row is None:
                connection.execute(
                    """
                    INSERT INTO browser_bootstrap_state(
                        state_id, user_id, status, created_at, updated_at,
                        capability_id, capability_verifier, capability_expires_at
                    ) VALUES (1, ?, 'pending', ?, ?, ?, ?, ?)
                    """,
                    (
                        self.owner_user_id,
                        now,
                        now,
                        capability_id,
                        verifier,
                        expires_at,
                    ),
                )
            else:
                remaining_totp_cleanup = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM browser_totp_enrollments
                        WHERE user_id = ? AND flow = 'bootstrap' AND consumed_at IS NULL
                          AND cleanup_completed_at IS NULL
                        """,
                        (self.owner_user_id,),
                    ).fetchone()[0]
                )
                if remaining_totp_cleanup:
                    raise BootstrapError("pending bootstrap TOTP cleanup did not complete")
                connection.execute(
                    """
                    UPDATE browser_bootstrap_state
                    SET capability_id = ?, capability_verifier = ?,
                        capability_expires_at = ?, claimant_verifier = NULL,
                        claimed_at = NULL, staged_password_verifier = NULL,
                        updated_at = max(updated_at, ?)
                    WHERE state_id = 1 AND status = 'pending'
                    """,
                    (capability_id, verifier, expires_at, now),
                )
                connection.execute(
                    """
                    UPDATE auth_registration_challenges SET invalidated_at = ?
                    WHERE user_id = ? AND flow = 'bootstrap'
                      AND consumed_at IS NULL AND invalidated_at IS NULL
                    """,
                    (now, self.owner_user_id),
                )
        return capability

    def claim(self, capability: str, claimant_token: str, *, now: int) -> BootstrapStatus:
        capability_id = _bootstrap_capability_id(capability)
        verifier = _bootstrap_verifier(capability)
        claimant_verifier = _claimant_verifier(claimant_token)
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
            if row is None or str(row["user_id"]) != self.owner_user_id:
                raise BootstrapClaimRequired("local bootstrap authorization is required")
            if str(row["status"]) == "complete":
                raise BootstrapAlreadyComplete("initial owner setup is already complete")
            stored = bytes(row["capability_verifier"] or b"")
            if (
                row["capability_id"] != capability_id
                or row["capability_expires_at"] is None
                or now >= int(row["capability_expires_at"])
                or row["claimed_at"] is not None
                or not hmac.compare_digest(stored, verifier)
            ):
                raise BootstrapClaimRequired("bootstrap authorization is invalid or consumed")
            updated = connection.execute(
                """
                UPDATE browser_bootstrap_state
                SET claimant_verifier = ?, claimed_at = ?, updated_at = max(updated_at, ?)
                WHERE state_id = 1 AND status = 'pending' AND claimed_at IS NULL
                """,
                (claimant_verifier, now, now),
            ).rowcount
            if int(updated) != 1:
                raise BootstrapClaimRequired("bootstrap authorization was already consumed")
        return self.status(now=now, claimant_token=claimant_token)

    def status(self, *, now: int, claimant_token: str | None = None) -> BootstrapStatus:
        with self.database.read() as connection:
            state = connection.execute(
                "SELECT * FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
            if state is None:
                return self._empty_status(updated_at=0)
            if str(state["user_id"]) != self.owner_user_id:
                raise BootstrapOwnerMismatch("browser bootstrap is bound to another owner")
            complete = str(state["status"]) == "complete"
            claimed = complete or self._claim_matches(state, claimant_token, now=now)
            if not claimed:
                return self._empty_status(updated_at=int(state["updated_at"]))
            active = self._active_factor_rows(connection)
            staged_passkeys = connection.execute(
                """
                SELECT factor_label AS label FROM auth_registration_challenges
                WHERE user_id = ? AND flow = 'bootstrap' AND verified_at IS NOT NULL
                  AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
                ORDER BY created_at, challenge_id
                """,
                (self.owner_user_id, now),
            ).fetchall()
            staged_totps = connection.execute(
                """
                SELECT factor_label AS label FROM browser_totp_enrollments
                WHERE user_id = ? AND flow = 'bootstrap' AND verified_at IS NOT NULL
                  AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
                ORDER BY created_at, enrollment_id
                """,
                (self.owner_user_id, now),
            ).fetchall()
        active_kinds = tuple(str(row["kind"]) for row in active)
        labels = tuple(
            str(row["label"]) for row in active if str(row["kind"]) in {"totp", "webauthn"}
        ) + tuple(str(row["label"]) for row in (*staged_passkeys, *staged_totps))
        return BootstrapStatus(
            user_id=self.owner_user_id,
            complete=complete,
            has_password=(
                "password" in active_kinds or state["staged_password_verifier"] is not None
            ),
            has_authenticator=bool(labels),
            factor_labels=labels,
            updated_at=int(state["updated_at"]),
            claimed=claimed,
        )

    def require_claim(self, claimant_token: str | None, *, now: int) -> None:
        with self.database.read() as connection:
            self._require_pending(connection, claimant_token, now=now)

    def claim_transaction_guard(
        self,
        claimant_token: str | None,
        *,
        now: int,
    ) -> Callable[[Any], None]:
        with self.database.read() as connection:
            state = self._require_pending(connection, claimant_token, now=now)
            capability_id = str(state["capability_id"])

        def require_same_claim(connection: Any) -> None:
            current = self._require_pending(connection, claimant_token, now=now)
            if not hmac.compare_digest(str(current["capability_id"]), capability_id):
                raise BootstrapClaimRequired("bootstrap claimant changed or expired")

        return require_same_claim

    def enroll_password(
        self,
        password: str,
        *,
        claimant_token: str | None,
        now: int,
    ) -> BootstrapStatus:
        self.require_claim(claimant_token, now=now)
        verifier = self.password_enroller.hash(password)
        if not verifier.startswith("$argon2id$"):
            raise ValueError("password enroller must return an Argon2id verifier")
        with self.database.transaction() as connection:
            self._require_pending(connection, claimant_token, now=now)
            connection.execute(
                """
                UPDATE browser_bootstrap_state
                SET staged_password_verifier = ?, updated_at = max(updated_at, ?)
                WHERE state_id = 1 AND status = 'pending'
                """,
                (verifier.encode(), now),
            )
        return self.status(now=now, claimant_token=claimant_token)

    def enroll_passkey(
        self,
        label: str,
        credential: WebAuthnCredential,
        *,
        claimant_token: str,
        now: int,
    ) -> BootstrapStatus:
        selected_label = _label(label)
        if credential.user_id != self.owner_user_id or credential.disabled:
            raise ValueError("an active owner passkey credential is required")
        if credential.user_handle != _user_handle(self.owner_user_id):
            raise ValueError("passkey user handle does not match the bootstrap owner")
        with self.database.transaction() as connection:
            state = self._require_pending(connection, claimant_token, now=now)
            expires_at = min(int(state["capability_expires_at"]), now + 15 * 60)
            connection.execute(
                """
                INSERT INTO auth_registration_challenges(
                    challenge_id, challenge, user_id, flow, session_id, factor_label,
                    created_at, expires_at, verified_at, credential_id, public_key,
                    sign_count, device_type, backed_up, transports_json, discoverable
                ) VALUES (?, ?, ?, 'bootstrap', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"reg_{secrets.token_urlsafe(24)}",
                    secrets.token_bytes(32),
                    self.owner_user_id,
                    selected_label,
                    now,
                    expires_at,
                    now,
                    credential.credential_id,
                    credential.public_key,
                    credential.sign_count,
                    credential.device_type,
                    int(credential.backed_up),
                    _json_transports(credential.transports),
                    int(credential.discoverable),
                ),
            )
            connection.execute(
                """
                UPDATE browser_bootstrap_state
                SET updated_at = max(updated_at, ?) WHERE state_id = 1
                """,
                (now,),
            )
        return self.status(now=now, claimant_token=claimant_token)

    def enroll_totp(
        self,
        enrollment: TotpEnrollment,
        *,
        claimant_token: str | None,
        now: int,
    ) -> BootstrapStatus:
        if enrollment.user_id != self.owner_user_id or enrollment.verified_at is None:
            raise BootstrapError("verified owner TOTP enrollment is required")
        self.require_claim(claimant_token, now=now)
        return self.status(now=now, claimant_token=claimant_token)

    def complete(self, *, claimant_token: str | None, now: int) -> BootstrapStatus:
        try:
            with self.database.transaction() as connection:
                state = self._require_pending(connection, claimant_token, now=now)
                active = self._active_factor_rows(connection)
                active_kinds = {str(row["kind"]) for row in active}
                passkeys = connection.execute(
                    """
                    SELECT * FROM auth_registration_challenges
                    WHERE user_id = ? AND flow = 'bootstrap' AND verified_at IS NOT NULL
                      AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
                    ORDER BY created_at, challenge_id
                    """,
                    (self.owner_user_id, now),
                ).fetchall()
                totps = connection.execute(
                    """
                    SELECT * FROM browser_totp_enrollments
                    WHERE user_id = ? AND flow = 'bootstrap' AND verified_at IS NOT NULL
                      AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
                    ORDER BY created_at, enrollment_id
                    """,
                    (self.owner_user_id, now),
                ).fetchall()
                staged_password = state["staged_password_verifier"]
                has_password = staged_password is not None or "password" in active_kinds
                has_authenticator = bool(
                    passkeys or totps or active_kinds.intersection({"totp", "webauthn"})
                )
                if not has_password or not has_authenticator:
                    raise BootstrapIncomplete(
                        "setup requires a password and at least one passkey or TOTP authenticator"
                    )
                _ensure_auth_user(connection, self.owner_user_id, created_at=now)
                if staged_password is not None:
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
                    password_id = f"password_{secrets.token_urlsafe(24)}"
                    connection.execute(
                        """
                        INSERT INTO auth_credentials(
                            credential_id, user_id, kind, public_material, enrolled_at, factor_label
                        ) VALUES (?, ?, 'password', ?, ?, 'Password')
                        """,
                        (password_id, self.owner_user_id, staged_password, now),
                    )
                    _register_auth_factor(
                        connection,
                        credential_id=password_id,
                        user_id=self.owner_user_id,
                        kind="password",
                        label="Password",
                        now=now,
                        operation_id="browser-bootstrap-password",
                    )
                for row in passkeys:
                    connection.execute(
                        """
                        INSERT INTO auth_credentials(
                            credential_id, user_id, kind, public_material, enrolled_at,
                            sign_count, backup_eligible, backup_state, user_handle,
                            factor_label, transports_json, discoverable
                        ) VALUES (?, ?, 'webauthn', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            row["credential_id"],
                            self.owner_user_id,
                            row["public_key"],
                            now,
                            row["sign_count"],
                            int(str(row["device_type"]) == "multi_device"),
                            row["backed_up"],
                            _user_handle(self.owner_user_id),
                            row["factor_label"],
                            row["transports_json"],
                            row["discoverable"],
                        ),
                    )
                    _register_auth_factor(
                        connection,
                        credential_id=str(row["credential_id"]),
                        user_id=self.owner_user_id,
                        kind="webauthn",
                        label=str(row["factor_label"]),
                        now=now,
                        operation_id=f"bootstrap-passkey:{row['challenge_id']}",
                    )
                for row in totps:
                    connection.execute(
                        """
                        INSERT INTO auth_credentials(
                            credential_id, user_id, kind, secret_reference,
                            enrolled_at, factor_label
                        ) VALUES (?, ?, 'totp', ?, ?, ?)
                        """,
                        (
                            row["credential_id"],
                            self.owner_user_id,
                            row["secret_reference"],
                            now,
                            row["factor_label"],
                        ),
                    )
                    _register_auth_factor(
                        connection,
                        credential_id=str(row["credential_id"]),
                        user_id=self.owner_user_id,
                        kind="totp",
                        label=str(row["factor_label"]),
                        now=now,
                        operation_id=f"bootstrap-totp:{row['enrollment_id']}",
                    )
                connection.execute(
                    """
                    UPDATE auth_registration_challenges SET consumed_at = ?
                    WHERE user_id = ? AND flow = 'bootstrap' AND verified_at IS NOT NULL
                      AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
                    """,
                    (now, self.owner_user_id, now),
                )
                connection.execute(
                    """
                    UPDATE browser_totp_enrollments SET consumed_at = ?
                    WHERE user_id = ? AND flow = 'bootstrap' AND verified_at IS NOT NULL
                      AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > ?
                    """,
                    (now, self.owner_user_id, now),
                )
                _revoke_user_sessions(connection, self.owner_user_id, revoked_at=now)
                updated = connection.execute(
                    """
                    UPDATE browser_bootstrap_state
                    SET status = 'complete', updated_at = max(updated_at, ?), completed_at = ?,
                        capability_id = NULL, capability_verifier = NULL,
                        capability_expires_at = NULL, claimant_verifier = NULL,
                        claimed_at = NULL, staged_password_verifier = NULL
                    WHERE state_id = 1 AND user_id = ? AND status = 'pending'
                    """,
                    (now, now, self.owner_user_id),
                ).rowcount
                if int(updated) != 1:
                    raise BootstrapAlreadyComplete("initial owner setup is already complete")
        except IntegrityError:
            raise BootstrapError(
                "bootstrap credentials could not be published atomically"
            ) from None
        return self.status(now=now, claimant_token=claimant_token)

    def _reconcile_existing_owner(self) -> None:
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
            if row is not None and str(row["user_id"]) != self.owner_user_id:
                raise BootstrapOwnerMismatch("browser bootstrap is bound to another owner")
            kinds = {str(item["kind"]) for item in self._active_factor_rows(connection)}
            if "password" not in kinds or not kinds.intersection({"totp", "webauthn"}):
                return
            created_at = int(row["created_at"]) if row is not None else 0
            if row is None:
                connection.execute(
                    """
                    INSERT INTO browser_bootstrap_state(
                        state_id, user_id, status, created_at, updated_at, completed_at
                    ) VALUES (1, ?, 'complete', ?, ?, ?)
                    """,
                    (self.owner_user_id, created_at, created_at, created_at),
                )
            elif str(row["status"]) == "pending":
                connection.execute(
                    """
                    UPDATE browser_bootstrap_state
                    SET status = 'complete', completed_at = max(updated_at, created_at),
                        capability_id = NULL, capability_verifier = NULL,
                        capability_expires_at = NULL, claimant_verifier = NULL, claimed_at = NULL
                    WHERE state_id = 1
                    """
                )

    def _active_factor_rows(self, connection: object) -> list[Any]:
        return list(
            connection.execute(  # type: ignore[attr-defined]
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
        )

    def _empty_status(self, *, updated_at: int) -> BootstrapStatus:
        return BootstrapStatus(
            user_id=self.owner_user_id,
            complete=False,
            has_password=False,
            has_authenticator=False,
            factor_labels=(),
            updated_at=updated_at,
            claimed=False,
        )

    def _require_pending(
        self,
        connection: object,
        claimant_token: str | None,
        *,
        now: int,
    ) -> Any:
        row = connection.execute(  # type: ignore[attr-defined]
            "SELECT * FROM browser_bootstrap_state WHERE state_id = 1"
        ).fetchone()
        if row is None:
            raise BootstrapClaimRequired("local bootstrap authorization is required")
        if str(row["user_id"]) != self.owner_user_id:
            raise BootstrapOwnerMismatch("browser bootstrap is bound to another owner")
        if str(row["status"]) != "pending":
            raise BootstrapAlreadyComplete("initial owner setup is already complete")
        if not self._claim_matches(row, claimant_token, now=now):
            raise BootstrapClaimRequired("bootstrap claimant is invalid or expired")
        return row

    @staticmethod
    def _claim_matches(row: Any, claimant_token: str | None, *, now: int) -> bool:
        if claimant_token is None or row["claimant_verifier"] is None:
            return False
        if row["capability_expires_at"] is None or now >= int(row["capability_expires_at"]):
            return False
        try:
            supplied = _claimant_verifier(claimant_token)
        except ValueError:
            return False
        return hmac.compare_digest(bytes(row["claimant_verifier"]), supplied)


ManagementAction = Literal["add_passkey", "add_totp", "rename", "revoke"]


@dataclass(frozen=True, slots=True)
class ManagementIntent:
    action: ManagementAction
    operation_id: str
    factor_id: str | None = None
    label: str | None = None
    registration_id: str | None = None
    authorization_id: str | None = None
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
            for factor in self.manager.list_factors(user_id, include_inactive=False)
            if factor.kind in ("totp", "webauthn")
        )

    def begin_registration(
        self,
        user_id: str,
        label: str,
        *,
        flow: Literal["bootstrap", "management"],
        session_id: str | None,
        claimant_token: str | None = None,
        authorization_id: str | None = None,
        operation_id: str | None = None,
        now: int,
    ) -> IssuedRegistration:
        transaction_guard: Callable[[Any], None] | None = None
        if flow == "bootstrap":
            transaction_guard = self.bootstrap.claim_transaction_guard(
                claimant_token,
                now=now,
            )
        elif authorization_id is None or operation_id is None:
            raise BootstrapClaimRequired("fresh factor authorization is required")
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
            authorization_id=authorization_id,
            operation_id=operation_id,
            now=now,
            transaction_guard=transaction_guard,
        )

    def resume_registration(
        self,
        challenge_id: str,
        *,
        user_id: str,
        session_id: str | None,
        claimant_token: str | None = None,
        now: int,
    ) -> IssuedRegistration:
        if session_id is None:
            self.bootstrap.require_claim(claimant_token, now=now)
        existing = tuple(
            credential.credential_id
            for credential in self.webauthn_repository.credentials_for_user(user_id)
        )
        return self.registrations.resume(
            challenge_id,
            user_id=user_id,
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
        claimant_token: str | None = None,
        now: int,
    ) -> PendingRegistration:
        if session_id is None:
            self.bootstrap.require_claim(claimant_token, now=now)
        return self.registrations.complete(
            challenge_id,
            credential,
            user_id=user_id,
            session_id=session_id,
            now=now,
        )

    def pending_registration(
        self,
        challenge_id: str,
        *,
        user_id: str,
        session_id: str | None,
        claimant_token: str | None = None,
        now: int,
    ) -> PendingRegistration:
        if session_id is None:
            self.bootstrap.require_claim(claimant_token, now=now)
        return self.registrations.pending(
            challenge_id,
            user_id=user_id,
            session_id=session_id,
            now=now,
        )

    def commit_bootstrap_passkey(
        self,
        challenge_id: str,
        *,
        claimant_token: str | None,
        now: int,
    ) -> BootstrapStatus:
        self.bootstrap.require_claim(claimant_token, now=now)
        self.registrations.pending(
            challenge_id,
            user_id=self.bootstrap.owner_user_id,
            session_id=None,
            now=now,
        )
        return self.bootstrap.status(now=now, claimant_token=claimant_token)

    def begin_totp_enrollment(
        self,
        user_id: str,
        label: str,
        *,
        flow: Literal["bootstrap", "management"],
        session_id: str | None,
        claimant_token: str | None = None,
        authorization_id: str | None = None,
        operation_id: str | None = None,
        now: int,
    ) -> IssuedTotpEnrollment:
        transaction_guard: Callable[[Any], None] | None = None
        if flow == "bootstrap":
            transaction_guard = self.bootstrap.claim_transaction_guard(
                claimant_token,
                now=now,
            )
        elif authorization_id is None or operation_id is None:
            raise BootstrapClaimRequired("fresh factor authorization is required")
        return self._totp_enrollments().begin(
            user_id,
            label,
            flow=flow,
            session_id=session_id,
            authorization_id=authorization_id,
            operation_id=operation_id,
            now=now,
            transaction_guard=transaction_guard,
        )

    def verify_totp_enrollment(
        self,
        enrollment_id: str,
        proof: str,
        *,
        user_id: str,
        session_id: str | None,
        claimant_token: str | None = None,
        now: int,
    ) -> TotpEnrollment:
        if session_id is None:
            self.bootstrap.require_claim(claimant_token, now=now)
        return self._totp_enrollments().verify(
            enrollment_id,
            proof,
            user_id=user_id,
            session_id=session_id,
            now=now,
        )

    def resume_totp_enrollment(
        self,
        enrollment_id: str,
        *,
        user_id: str,
        session_id: str | None,
        claimant_token: str | None = None,
        now: int,
    ) -> IssuedTotpEnrollment:
        if session_id is None:
            self.bootstrap.require_claim(claimant_token, now=now)
        return self._totp_enrollments().resume(
            enrollment_id,
            user_id=user_id,
            session_id=session_id,
            now=now,
        )

    def pending_totp_enrollment(
        self,
        enrollment_id: str,
        *,
        user_id: str,
        session_id: str | None,
        claimant_token: str | None = None,
        now: int,
    ) -> TotpEnrollment:
        if session_id is None:
            self.bootstrap.require_claim(claimant_token, now=now)
        return self._totp_enrollments().pending(
            enrollment_id,
            user_id=user_id,
            session_id=session_id,
            now=now,
        )

    def commit_bootstrap_totp(
        self,
        enrollment_id: str,
        *,
        claimant_token: str | None,
        now: int,
    ) -> BootstrapStatus:
        enrollments = self._totp_enrollments()
        pending = enrollments.pending(
            enrollment_id,
            user_id=self.bootstrap.owner_user_id,
            session_id=None,
            now=now,
        )
        return self.bootstrap.enroll_totp(
            pending,
            claimant_token=claimant_token,
            now=now,
        )

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
                if intent.label is None:
                    raise ValueError("passkey label is required")
                return self.manager.binding_for_enrollment_authorization(
                    user_id,
                    session_id,
                    "add_passkey",
                    intent.label,
                    intent.operation_id,
                )
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
                if intent.label is None:
                    raise ValueError("TOTP label is required")
                return self.manager.binding_for_enrollment_authorization(
                    user_id,
                    session_id,
                    "add_totp",
                    intent.label,
                    intent.operation_id,
                )
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

    def authorize_enrollment_with_totp(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        proof: str,
        *,
        source_id: str,
        credential_id: str | None,
        now: int,
    ) -> IssuedRegistration | IssuedTotpEnrollment:
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
        issued = self._authorize_and_begin_enrollment(
            user_id,
            session_id,
            intent,
            verified,
            now=now,
        )
        self.totp_verifier.record_consumed_success(verified, now=now)
        return issued

    def authorize_enrollment_with_webauthn(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        *,
        challenge_id: str,
        assertion: Mapping[str, Any],
        now: int,
    ) -> IssuedRegistration | IssuedTotpEnrollment:
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
        return self._authorize_and_begin_enrollment(
            user_id,
            session_id,
            intent,
            verified,
            now=now,
        )

    def _authorize_and_begin_enrollment(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
    ) -> IssuedRegistration | IssuedTotpEnrollment:
        if (
            intent.action not in {"add_passkey", "add_totp"}
            or intent.label is None
            or intent.registration_id is not None
        ):
            raise ValueError("an unstarted enrollment intent is required")
        authorization_id = self.manager.authorize_enrollment(
            user_id,
            session_id,
            intent.action,
            intent.label,
            intent.operation_id,
            confirmation,
            now=now,
        )
        if intent.action == "add_passkey":
            return self.begin_registration(
                user_id,
                intent.label,
                flow="management",
                session_id=session_id,
                authorization_id=authorization_id,
                operation_id=intent.operation_id,
                now=now,
            )
        return self.begin_totp_enrollment(
            user_id,
            intent.label,
            flow="management",
            session_id=session_id,
            authorization_id=authorization_id,
            operation_id=intent.operation_id,
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
        if intent.action in {"add_passkey", "add_totp"}:
            raise BootstrapError("authenticator enrollment requires its issued authorization")
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
        if intent.action in {"add_passkey", "add_totp"}:
            raise BootstrapError("authenticator enrollment requires its issued authorization")
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

    def complete_authorized_enrollment(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        *,
        now: int,
    ) -> FactorMetadata:
        if intent.registration_id is None or intent.authorization_id is None:
            raise ValueError("authorized enrollment identifiers are required")
        if intent.action == "add_passkey":
            pending = self.registrations.pending(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            )
            if (
                pending.authorization_id != intent.authorization_id
                or pending.operation_id != intent.operation_id
            ):
                raise BootstrapClaimRequired("passkey enrollment authorization is invalid")
            factor = self.manager.add_authorized_passkey(
                user_id,
                session_id,
                intent.registration_id,
                pending.label,
                pending.credential,
                intent.operation_id,
                intent.authorization_id,
                now=now,
            )
            return factor
        if intent.action == "add_totp":
            enrollments = self._totp_enrollments()
            pending_totp = enrollments.pending(
                intent.registration_id,
                user_id=user_id,
                session_id=session_id,
                now=now,
            )
            if (
                pending_totp.authorization_id != intent.authorization_id
                or pending_totp.operation_id != intent.operation_id
            ):
                raise BootstrapClaimRequired("TOTP enrollment authorization is invalid")
            factor = self.manager.add_authorized_preprovisioned_totp(
                user_id,
                session_id,
                intent.registration_id,
                pending_totp.label,
                pending_totp.factor_id,
                pending_totp.credential_id,
                pending_totp.secret_reference,
                intent.operation_id,
                intent.authorization_id,
                now=now,
            )
            return factor
        raise ValueError("authorized enrollment action is invalid")

    def _apply(
        self,
        user_id: str,
        session_id: str,
        intent: ManagementIntent,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
    ) -> FactorMetadata:
        if intent.action == "rename":
            if intent.factor_id is None or intent.label is None:
                raise ValueError("rename intent is incomplete")
            return self.manager.rename_factor(
                user_id,
                intent.factor_id,
                intent.label,
                intent.operation_id,
                confirmation,
                now=now,
            )
        if intent.action == "revoke":
            if intent.factor_id is None:
                raise ValueError("revoke intent is incomplete")
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


def _bootstrap_capability_id(capability: str) -> str:
    try:
        version, capability_id, secret = capability.split(".")
    except (AttributeError, ValueError):
        raise BootstrapClaimRequired("bootstrap authorization is invalid or consumed") from None
    if (
        version != "sbc1"
        or len(capability_id) < 16
        or len(capability_id) > 128
        or len(secret) < 32
        or len(secret) > 128
    ):
        raise BootstrapClaimRequired("bootstrap authorization is invalid or consumed")
    return capability_id


def _bootstrap_verifier(capability: str) -> bytes:
    _bootstrap_capability_id(capability)
    return hashlib.sha256(b"signet-bootstrap-capability-v1\x00" + capability.encode()).digest()


def _claimant_verifier(claimant_token: str) -> bytes:
    if not isinstance(claimant_token, str):
        raise ValueError("bootstrap claimant token is invalid")
    encoded = claimant_token.encode("utf-8")
    if len(encoded) < 16 or len(encoded) > 256:
        raise ValueError("bootstrap claimant token is invalid")
    return hashlib.sha256(b"signet-bootstrap-claimant-v1\x00" + encoded).digest()


def _user_handle(user_id: str) -> bytes:
    return hashlib.sha256(b"signet-webauthn-user-v1\x00" + user_id.encode()).digest()


def _json_transports(transports: tuple[str, ...]) -> str:
    import json

    return json.dumps(list(transports), separators=(",", ":"))
