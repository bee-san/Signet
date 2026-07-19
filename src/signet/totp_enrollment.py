"""Durable browser TOTP enrollment without storing seeds in SQLite."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

import pyotp
import segno

from signet.auth import canonical_user_id
from signet.authenticator_management import TotpSecretProvisioner
from signet.credential_broker import CredentialError, SecretReference, SecretStore
from signet.db import Database

TotpEnrollmentFlow = Literal["bootstrap", "management"]


class TotpEnrollmentError(RuntimeError):
    pass


class InvalidTotpEnrollment(TotpEnrollmentError):
    pass


class TotpEnrollmentRateLimited(TotpEnrollmentError):
    pass


class TotpEnrollmentCleanupError(TotpEnrollmentError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class TotpEnrollment:
    enrollment_id: str
    user_id: str
    flow: TotpEnrollmentFlow
    session_id: str | None
    factor_id: str
    credential_id: str
    label: str
    secret_reference: str
    created_at: int
    expires_at: int
    authorization_id: str | None = None
    operation_id: str | None = None
    verified_at: int | None = None

    def __repr__(self) -> str:
        return (
            "TotpEnrollment(enrollment_id=<redacted>, user_id=<redacted>, "
            f"flow={self.flow!r}, secret=<redacted>, verified={self.verified_at is not None})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class IssuedTotpEnrollment:
    enrollment: TotpEnrollment
    provisioning_uri: str
    qr_code_data_uri: str
    manual_key: str

    def __repr__(self) -> str:
        return "IssuedTotpEnrollment(enrollment=<redacted>, provisioning=<redacted>)"


class TotpEnrollmentService:
    def __init__(
        self,
        database: Database,
        *,
        provisioner: TotpSecretProvisioner,
        secret_store: SecretStore,
        lifetime: int = 15 * 60,
        max_active_per_user: int = 3,
        max_active_per_session: int = 2,
    ) -> None:
        if (
            lifetime <= 0
            or lifetime > 60 * 60
            or max_active_per_user <= 0
            or max_active_per_session <= 0
        ):
            raise ValueError("invalid TOTP enrollment lifetime")
        self.database = database
        self.provisioner = provisioner
        self.secret_store = secret_store
        self.lifetime = lifetime
        self.max_active_per_user = max_active_per_user
        self.max_active_per_session = max_active_per_session

    def begin(
        self,
        user_id: str,
        label: str,
        *,
        flow: TotpEnrollmentFlow,
        session_id: str | None,
        authorization_id: str | None = None,
        operation_id: str | None = None,
        now: int,
    ) -> IssuedTotpEnrollment:
        user = canonical_user_id(user_id)
        selected_label = _label(label)
        selected_session = _session_for_flow(flow, session_id)
        selected_authorization, selected_operation = _authorization_for_flow(
            flow,
            authorization_id,
            operation_id,
        )
        self.cleanup_expired(now=now)
        secret_reference: str | None = None
        enrollment: TotpEnrollment | None = None
        try:
            with self.database.transaction() as connection:
                active_for_user = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM browser_totp_enrollments
                        WHERE user_id = ? AND consumed_at IS NULL AND invalidated_at IS NULL
                          AND expires_at > ?
                        """,
                        (user, now),
                    ).fetchone()[0]
                )
                active_for_session = (
                    int(
                        connection.execute(
                            """
                            SELECT count(*) FROM browser_totp_enrollments
                            WHERE user_id = ? AND session_id = ? AND consumed_at IS NULL
                              AND invalidated_at IS NULL AND expires_at > ?
                            """,
                            (user, selected_session, now),
                        ).fetchone()[0]
                    )
                    if selected_session is not None
                    else 0
                )
                if active_for_user >= self.max_active_per_user or (
                    selected_session is not None
                    and active_for_session >= self.max_active_per_session
                ):
                    raise TotpEnrollmentRateLimited("too many active TOTP enrollments")
                enrollment_id = secrets.token_urlsafe(24)
                factor_id = f"fac_{secrets.token_urlsafe(24)}"
                credential_id = f"totp_{secrets.token_urlsafe(24)}"
                secret_reference = self.provisioner.create(factor_id)
                SecretReference.parse(secret_reference)
                enrollment = TotpEnrollment(
                    enrollment_id=enrollment_id,
                    user_id=user,
                    flow=flow,
                    session_id=selected_session,
                    factor_id=factor_id,
                    credential_id=credential_id,
                    label=selected_label,
                    secret_reference=secret_reference,
                    created_at=now,
                    expires_at=now + self.lifetime,
                    authorization_id=selected_authorization,
                    operation_id=selected_operation,
                )
                connection.execute(
                    """
                    INSERT INTO browser_totp_enrollments(
                        enrollment_id, user_id, flow, session_id, factor_id,
                        credential_id, factor_label, secret_reference, created_at, expires_at,
                        authorization_id, operation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        enrollment.enrollment_id,
                        enrollment.user_id,
                        enrollment.flow,
                        enrollment.session_id,
                        enrollment.factor_id,
                        enrollment.credential_id,
                        enrollment.label,
                        enrollment.secret_reference,
                        enrollment.created_at,
                        enrollment.expires_at,
                        enrollment.authorization_id,
                        enrollment.operation_id,
                    ),
                )
        except Exception as enrollment_error:
            if secret_reference is not None:
                try:
                    self._delete_secret_verified(secret_reference)
                except TotpEnrollmentCleanupError as cleanup_error:
                    if enrollment is not None:
                        self._record_cleanup_debt(enrollment, now=now)
                    raise cleanup_error from enrollment_error
            raise
        if enrollment is None:  # pragma: no cover - local assignment invariant
            raise TotpEnrollmentError("TOTP enrollment was not created")
        return self._issued(enrollment)

    def resume(
        self,
        enrollment_id: str,
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> IssuedTotpEnrollment:
        enrollment = self.pending(
            enrollment_id,
            user_id=user_id,
            session_id=session_id,
            now=now,
            require_verified=False,
        )
        return self._issued(enrollment)

    def verify(
        self,
        enrollment_id: str,
        proof: str,
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> TotpEnrollment:
        enrollment = self.pending(
            enrollment_id,
            user_id=user_id,
            session_id=session_id,
            now=now,
            require_verified=False,
        )
        selected_proof = "".join(proof.split())
        if len(selected_proof) != 6 or not selected_proof.isascii() or not selected_proof.isdigit():
            raise InvalidTotpEnrollment("TOTP proof is invalid")
        reference = SecretReference.parse(enrollment.secret_reference)
        secret = self.secret_store.get(reference).reveal()
        try:
            valid = pyotp.TOTP(secret).verify(
                selected_proof,
                for_time=datetime.fromtimestamp(now, UTC),
                valid_window=1,
            )
        finally:
            secret = ""
        if not valid:
            raise InvalidTotpEnrollment("TOTP proof is invalid")
        with self.database.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE browser_totp_enrollments
                SET verified_at = ?
                WHERE enrollment_id = ? AND user_id = ?
                  AND verified_at IS NULL AND consumed_at IS NULL AND invalidated_at IS NULL
                  AND expires_at >= ?
                """,
                (now, enrollment.enrollment_id, enrollment.user_id, now),
            ).rowcount
        if changed != 1:
            raise InvalidTotpEnrollment("TOTP enrollment was already verified or expired")
        return self.pending(
            enrollment_id,
            user_id=user_id,
            session_id=session_id,
            now=now,
            require_verified=True,
        )

    def pending(
        self,
        enrollment_id: str,
        *,
        user_id: str,
        session_id: str | None,
        now: int,
        require_verified: bool = True,
    ) -> TotpEnrollment:
        user = canonical_user_id(user_id)
        selected_id = _identifier(enrollment_id)
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT enrollment_id, user_id, flow, session_id, factor_id,
                       credential_id, factor_label, secret_reference, created_at,
                       expires_at, authorization_id, operation_id,
                       verified_at, consumed_at, invalidated_at
                FROM browser_totp_enrollments
                WHERE enrollment_id = ?
                """,
                (selected_id,),
            ).fetchone()
        if (
            row is None
            or str(row["user_id"]) != user
            or (str(row["session_id"]) if row["session_id"] is not None else None) != session_id
            or row["consumed_at"] is not None
            or row["invalidated_at"] is not None
            or int(row["expires_at"]) < now
            or (require_verified and row["verified_at"] is None)
        ):
            raise InvalidTotpEnrollment("TOTP enrollment is unavailable")
        return _from_row(row)

    def consume(
        self,
        enrollment_id: str,
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> None:
        user = canonical_user_id(user_id)
        selected_id = _identifier(enrollment_id)
        selected_session = (
            None if session_id is None else _session_for_flow("management", session_id)
        )
        with self.database.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE browser_totp_enrollments
                SET consumed_at = ?
                WHERE enrollment_id = ? AND user_id = ? AND session_id IS ?
                  AND verified_at IS NOT NULL
                  AND consumed_at IS NULL AND invalidated_at IS NULL
                """,
                (now, selected_id, user, selected_session),
            ).rowcount
        if changed != 1:
            raise InvalidTotpEnrollment("TOTP enrollment cannot be consumed")

    def cleanup_expired(self, *, now: int) -> int:
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE browser_totp_enrollments
                SET invalidated_at = ?
                WHERE consumed_at IS NULL AND invalidated_at IS NULL AND expires_at <= ?
                """,
                (now, now),
            )
            rows = connection.execute(
                """
                SELECT enrollment_id, secret_reference
                FROM browser_totp_enrollments
                WHERE consumed_at IS NULL AND invalidated_at IS NOT NULL
                  AND cleanup_completed_at IS NULL
                ORDER BY invalidated_at, enrollment_id
                """
            ).fetchall()
        cleaned = 0
        for row in rows:
            self._delete_secret_verified(str(row["secret_reference"]))
            with self.database.transaction() as connection:
                updated = connection.execute(
                    """
                    UPDATE browser_totp_enrollments SET cleanup_completed_at = ?
                    WHERE enrollment_id = ? AND consumed_at IS NULL
                      AND invalidated_at IS NOT NULL AND cleanup_completed_at IS NULL
                    """,
                    (now, row["enrollment_id"]),
                ).rowcount
            cleaned += int(updated)
        return cleaned

    def invalidate(
        self,
        enrollment_id: str,
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> None:
        user = canonical_user_id(user_id)
        selected_id = _identifier(enrollment_id)
        with self.database.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE browser_totp_enrollments SET invalidated_at = ?
                WHERE enrollment_id = ? AND user_id = ? AND session_id IS ?
                  AND consumed_at IS NULL AND invalidated_at IS NULL
                """,
                (now, selected_id, user, session_id),
            ).rowcount
        if int(changed) != 1:
            raise InvalidTotpEnrollment("TOTP enrollment cannot be invalidated")
        self.cleanup_expired(now=now)

    def _delete_secret_verified(self, secret_reference: str) -> None:
        reference = SecretReference.parse(secret_reference)
        delete_error: Exception | None = None
        try:
            self.provisioner.delete(secret_reference)
        except Exception as exc:
            delete_error = exc
        try:
            self.secret_store.get(reference)
        except CredentialError:
            return
        except Exception as exc:
            raise TotpEnrollmentCleanupError("TOTP secret cleanup could not be verified") from exc
        if delete_error is not None:
            raise TotpEnrollmentCleanupError("TOTP secret cleanup failed") from delete_error
        raise TotpEnrollmentCleanupError("TOTP secret still exists after cleanup")

    def _record_cleanup_debt(self, enrollment: TotpEnrollment, *, now: int) -> None:
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO browser_totp_enrollments(
                        enrollment_id, user_id, flow, session_id, factor_id,
                        credential_id, factor_label, secret_reference, created_at, expires_at,
                        invalidated_at, authorization_id, operation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        enrollment.enrollment_id,
                        enrollment.user_id,
                        enrollment.flow,
                        enrollment.session_id,
                        enrollment.factor_id,
                        enrollment.credential_id,
                        enrollment.label,
                        enrollment.secret_reference,
                        enrollment.created_at,
                        enrollment.expires_at,
                        now,
                        enrollment.authorization_id,
                        enrollment.operation_id,
                    ),
                )
        except Exception as exc:
            raise TotpEnrollmentCleanupError(
                "TOTP cleanup debt could not be recorded"
            ) from exc

    def _issued(self, enrollment: TotpEnrollment) -> IssuedTotpEnrollment:
        reference = SecretReference.parse(enrollment.secret_reference)
        secret = self.secret_store.get(reference).reveal()
        try:
            uri = pyotp.TOTP(secret).provisioning_uri(
                name=enrollment.user_id,
                issuer_name="Signet",
            )
            return IssuedTotpEnrollment(
                enrollment=enrollment,
                provisioning_uri=uri,
                qr_code_data_uri=segno.make_qr(uri, error="m").svg_data_uri(scale=4),
                manual_key=secret,
            )
        finally:
            secret = ""


def _from_row(row: Any) -> TotpEnrollment:
    selected = row
    return TotpEnrollment(
        enrollment_id=str(selected["enrollment_id"]),
        user_id=str(selected["user_id"]),
        flow=cast(TotpEnrollmentFlow, str(selected["flow"])),
        session_id=(str(selected["session_id"]) if selected["session_id"] is not None else None),
        factor_id=str(selected["factor_id"]),
        credential_id=str(selected["credential_id"]),
        label=str(selected["factor_label"]),
        secret_reference=str(selected["secret_reference"]),
        created_at=int(selected["created_at"]),
        expires_at=int(selected["expires_at"]),
        authorization_id=(
            str(selected["authorization_id"])
            if selected["authorization_id"] is not None
            else None
        ),
        operation_id=(
            str(selected["operation_id"]) if selected["operation_id"] is not None else None
        ),
        verified_at=(int(selected["verified_at"]) if selected["verified_at"] is not None else None),
    )


def _label(label: str) -> str:
    selected = " ".join(label.split())
    if not selected or len(selected.encode("utf-8")) > 64:
        raise ValueError("TOTP label must contain at most 64 bytes")
    return selected


def _identifier(value: str) -> str:
    if not isinstance(value, str) or len(value) < 16 or len(value) > 128:
        raise InvalidTotpEnrollment("TOTP enrollment ID is invalid")
    if not all(
        character.isascii() and (character.isalnum() or character in "-_") for character in value
    ):
        raise InvalidTotpEnrollment("TOTP enrollment ID is invalid")
    return value


def _authorization_for_flow(
    flow: TotpEnrollmentFlow,
    authorization_id: str | None,
    operation_id: str | None,
) -> tuple[str | None, str | None]:
    if flow == "bootstrap":
        if authorization_id is not None or operation_id is not None:
            raise ValueError("bootstrap enrollment cannot use management authorization")
        return None, None
    if authorization_id is None and operation_id is None:
        return None, None
    if (
        authorization_id is None
        or operation_id is None
        or not 16 <= len(authorization_id) <= 128
        or not 16 <= len(operation_id) <= 128
    ):
        raise ValueError("management enrollment authorization is invalid")
    return authorization_id, operation_id


def _session_for_flow(flow: TotpEnrollmentFlow, session_id: str | None) -> str | None:
    if flow == "bootstrap":
        if session_id is not None:
            raise ValueError("bootstrap TOTP enrollment cannot use an authenticated session")
        return None
    if flow != "management" or session_id is None or len(session_id) < 16 or len(session_id) > 128:
        raise ValueError("management TOTP enrollment requires a valid session")
    return session_id
