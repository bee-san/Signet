"""Durable, exact-origin WebAuthn passkey registration ceremonies."""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from signet.auth import canonical_user_id
from signet.db import Database, IntegrityError
from signet.webauthn import WebAuthnCredential

RegistrationFlow = Literal["bootstrap", "management"]
DeviceType = Literal["single_device", "multi_device"]
_ALLOWED_TRANSPORTS = frozenset({"ble", "hybrid", "internal", "nfc", "usb"})


class PasskeyRegistrationError(RuntimeError):
    pass


class InvalidRegistrationChallenge(PasskeyRegistrationError):
    pass


class RegistrationRateLimited(PasskeyRegistrationError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class RegistrationResult:
    credential_id: str
    public_key: bytes
    sign_count: int
    device_type: DeviceType
    backed_up: bool
    transports: tuple[str, ...]
    discoverable: bool

    def __repr__(self) -> str:
        return "RegistrationResult(credential/public-key=<redacted>, result=<verified>)"


class RegistrationProvider(Protocol):
    test_only: bool

    def verify(
        self,
        credential: Mapping[str, Any],
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> RegistrationResult: ...


class OfficialRegistrationProvider:
    """Production registration verifier backed by the official WebAuthn package."""

    test_only = False

    def verify(
        self,
        credential: Mapping[str, Any],
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
    ) -> RegistrationResult:
        try:
            verified = verify_registration_response(
                credential=dict(credential),
                expected_challenge=expected_challenge,
                expected_rp_id=expected_rp_id,
                expected_origin=expected_origin,
                require_user_verification=True,
            )
            response = credential.get("response")
            transports_value = (
                response.get("transports", []) if isinstance(response, Mapping) else []
            )
            if not isinstance(transports_value, list) or not all(
                isinstance(item, str) and item in _ALLOWED_TRANSPORTS for item in transports_value
            ):
                raise ValueError
            transports = tuple(dict.fromkeys(cast(list[str], transports_value)))
            credential_id = _base64url_encode(verified.credential_id)
            outer_id = credential.get("id")
            if not isinstance(outer_id, str) or outer_id != credential_id:
                raise ValueError
            device_type_value = verified.credential_device_type.value
            if device_type_value == "single_device":
                device_type: DeviceType = "single_device"
            elif device_type_value == "multi_device":
                device_type = "multi_device"
            else:
                raise ValueError
        except (KeyError, TypeError, ValueError, WebAuthnException):
            raise InvalidRegistrationChallenge("invalid passkey registration") from None
        return RegistrationResult(
            credential_id=credential_id,
            public_key=bytes(verified.credential_public_key),
            sign_count=int(verified.sign_count),
            device_type=device_type,
            backed_up=bool(verified.credential_backed_up),
            transports=transports,
            discoverable=True,
        )


@dataclass(frozen=True, slots=True, repr=False)
class RegistrationChallenge:
    challenge_id: str
    challenge: bytes
    user_id: str
    flow: RegistrationFlow
    session_id: str | None
    label: str
    created_at: int
    expires_at: int
    verified_at: int | None = None
    consumed_at: int | None = None
    invalidated_at: int | None = None
    result: RegistrationResult | None = None

    def __repr__(self) -> str:
        return (
            "RegistrationChallenge(challenge_id=<redacted>, challenge=<redacted>, "
            f"user_id={self.user_id!r}, flow={self.flow!r}, expires_at={self.expires_at!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class IssuedRegistration:
    challenge_id: str
    options_json: str
    expires_at: int

    def __repr__(self) -> str:
        return "IssuedRegistration(challenge/options=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PendingRegistration:
    challenge_id: str
    label: str
    credential: WebAuthnCredential

    def __repr__(self) -> str:
        return (
            "PendingRegistration(challenge_id=<redacted>, "
            f"label={self.label!r}, credential=<redacted>)"
        )


class SQLiteRegistrationRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, challenge: RegistrationChallenge, *, now: int, max_active: int) -> bool:
        with self.database.transaction() as connection:
            active = int(
                connection.execute(
                    """
                    SELECT count(*) FROM auth_registration_challenges
                    WHERE user_id = ? AND consumed_at IS NULL AND invalidated_at IS NULL
                      AND expires_at > ?
                    """,
                    (challenge.user_id, now),
                ).fetchone()[0]
            )
            if active >= max_active:
                return False
            try:
                connection.execute(
                    """
                    INSERT INTO auth_registration_challenges(
                        challenge_id, challenge, user_id, flow, session_id,
                        factor_label, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        challenge.challenge_id,
                        challenge.challenge,
                        challenge.user_id,
                        challenge.flow,
                        challenge.session_id,
                        challenge.label,
                        challenge.created_at,
                        challenge.expires_at,
                    ),
                )
            except IntegrityError:
                return False
        return True

    def find(self, challenge_id: str) -> RegistrationChallenge | None:
        if not isinstance(challenge_id, str) or not 16 <= len(challenge_id) <= 128:
            return None
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM auth_registration_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            return None
        result = None
        if row["verified_at"] is not None:
            try:
                transports = json.loads(str(row["transports_json"]))
            except (TypeError, ValueError):
                raise PasskeyRegistrationError("stored registration metadata is invalid") from None
            if not isinstance(transports, list) or not all(
                isinstance(item, str) and item in _ALLOWED_TRANSPORTS for item in transports
            ):
                raise PasskeyRegistrationError("stored registration metadata is invalid")
            result = RegistrationResult(
                credential_id=str(row["credential_id"]),
                public_key=bytes(row["public_key"]),
                sign_count=int(row["sign_count"]),
                device_type=cast(DeviceType, str(row["device_type"])),
                backed_up=bool(row["backed_up"]),
                transports=tuple(transports),
                discoverable=bool(row["discoverable"]),
            )
        return RegistrationChallenge(
            challenge_id=str(row["challenge_id"]),
            challenge=bytes(row["challenge"]),
            user_id=str(row["user_id"]),
            flow=cast(RegistrationFlow, str(row["flow"])),
            session_id=(str(row["session_id"]) if row["session_id"] is not None else None),
            label=str(row["factor_label"]),
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
            verified_at=(int(row["verified_at"]) if row["verified_at"] is not None else None),
            consumed_at=(int(row["consumed_at"]) if row["consumed_at"] is not None else None),
            invalidated_at=(
                int(row["invalidated_at"]) if row["invalidated_at"] is not None else None
            ),
            result=result,
        )

    def store_result(self, challenge_id: str, result: RegistrationResult, *, now: int) -> bool:
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE auth_registration_challenges
                SET verified_at = ?, credential_id = ?, public_key = ?, sign_count = ?,
                    device_type = ?, backed_up = ?, transports_json = ?, discoverable = ?
                WHERE challenge_id = ? AND verified_at IS NULL AND consumed_at IS NULL
                  AND invalidated_at IS NULL AND created_at <= ? AND expires_at > ?
                """,
                (
                    now,
                    result.credential_id,
                    result.public_key,
                    result.sign_count,
                    result.device_type,
                    int(result.backed_up),
                    json.dumps(list(result.transports), separators=(",", ":")),
                    int(result.discoverable),
                    challenge_id,
                    now,
                    now,
                ),
            ).rowcount
        return int(updated) == 1

    def consume(self, challenge_id: str, *, user_id: str, session_id: str | None, now: int) -> bool:
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE auth_registration_challenges SET consumed_at = ?
                WHERE challenge_id = ? AND user_id = ? AND session_id IS ?
                  AND verified_at IS NOT NULL AND consumed_at IS NULL
                  AND invalidated_at IS NULL AND created_at <= ? AND expires_at > ?
                """,
                (now, challenge_id, user_id, session_id, now, now),
            ).rowcount
        return int(updated) == 1

    def invalidate(self, challenge_id: str, *, now: int) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE auth_registration_challenges SET invalidated_at = ?
                WHERE challenge_id = ? AND verified_at IS NULL AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, challenge_id),
            )


class PasskeyRegistrationService:
    def __init__(
        self,
        database: Database,
        *,
        rp_id: str,
        origin: str,
        provider: RegistrationProvider,
        lifetime: int = 5 * 60,
        max_active_per_user: int = 5,
        allow_test_provider: bool = False,
    ) -> None:
        from signet.webauthn import _normalize_rp_id, _validate_origin_and_rp

        self.rp_id = _normalize_rp_id(rp_id)
        self.origin = origin
        _validate_origin_and_rp(self.origin, self.rp_id)
        if provider.test_only and not (
            allow_test_provider or provider.__class__.__module__.startswith("tests")
        ):
            raise ValueError("test-only registration provider requires explicit opt-in")
        if lifetime <= 0 or lifetime > 10 * 60 or max_active_per_user <= 0:
            raise ValueError("invalid registration challenge limits")
        self.repository = SQLiteRegistrationRepository(database)
        self.provider = provider
        self.lifetime = lifetime
        self.max_active_per_user = max_active_per_user

    def begin(
        self,
        user_id: str,
        label: str,
        *,
        flow: RegistrationFlow,
        session_id: str | None,
        existing_credential_ids: tuple[str, ...],
        now: int,
    ) -> IssuedRegistration:
        selected_user = canonical_user_id(user_id)
        selected_label = _label(label)
        selected_session = _session_for_flow(flow, session_id)
        challenge_bytes = secrets.token_bytes(32)
        challenge_id = _base64url_encode(secrets.token_bytes(24))
        challenge = RegistrationChallenge(
            challenge_id=challenge_id,
            challenge=challenge_bytes,
            user_id=selected_user,
            flow=flow,
            session_id=selected_session,
            label=selected_label,
            created_at=now,
            expires_at=now + self.lifetime,
        )
        if not self.repository.create(
            challenge,
            now=now,
            max_active=self.max_active_per_user,
        ):
            raise RegistrationRateLimited("too many active passkey registrations")
        try:
            excluded = [
                PublicKeyCredentialDescriptor(id=_base64url_decode(identifier))
                for identifier in existing_credential_ids
            ]
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name="Signet",
                user_name=selected_user,
                user_display_name=selected_user,
                user_id=_user_handle(selected_user),
                challenge=challenge_bytes,
                timeout=self.lifetime * 1_000,
                exclude_credentials=excluded,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
            )
        except ValueError:
            self.repository.invalidate(challenge_id, now=now)
            raise InvalidRegistrationChallenge("stored passkey credential ID is invalid") from None
        return IssuedRegistration(
            challenge_id=challenge_id,
            options_json=options_to_json(options),
            expires_at=challenge.expires_at,
        )

    def complete(
        self,
        challenge_id: str,
        credential: Mapping[str, Any],
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> PendingRegistration:
        selected_user = canonical_user_id(user_id)
        challenge = self.repository.find(challenge_id)
        if (
            challenge is None
            or challenge.user_id != selected_user
            or challenge.session_id != session_id
            or challenge.verified_at is not None
            or challenge.consumed_at is not None
            or challenge.invalidated_at is not None
            or challenge.created_at > now
            or challenge.expires_at <= now
        ):
            raise InvalidRegistrationChallenge("passkey registration is stale or unavailable")
        try:
            result = self.provider.verify(
                credential,
                expected_challenge=challenge.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
            )
        except (InvalidRegistrationChallenge, TypeError, ValueError):
            self.repository.invalidate(challenge_id, now=now)
            raise InvalidRegistrationChallenge("invalid passkey registration") from None
        if not self.repository.store_result(challenge_id, result, now=now):
            raise InvalidRegistrationChallenge("passkey registration is stale or unavailable")
        return PendingRegistration(
            challenge_id=challenge_id,
            label=challenge.label,
            credential=WebAuthnCredential(
                credential_id=result.credential_id,
                user_id=selected_user,
                public_key=result.public_key,
                sign_count=result.sign_count,
                user_handle=_user_handle(selected_user),
                device_type=result.device_type,
                backed_up=result.backed_up,
                transports=result.transports,
                discoverable=result.discoverable,
            ),
        )

    def pending(
        self,
        challenge_id: str,
        *,
        user_id: str,
        session_id: str | None,
        now: int,
    ) -> PendingRegistration:
        selected_user = canonical_user_id(user_id)
        challenge = self.repository.find(challenge_id)
        if (
            challenge is None
            or challenge.user_id != selected_user
            or challenge.session_id != session_id
            or challenge.result is None
            or challenge.consumed_at is not None
            or challenge.invalidated_at is not None
            or challenge.created_at > now
            or challenge.expires_at <= now
        ):
            raise InvalidRegistrationChallenge("passkey registration is stale or unavailable")
        result = challenge.result
        return PendingRegistration(
            challenge_id=challenge.challenge_id,
            label=challenge.label,
            credential=WebAuthnCredential(
                credential_id=result.credential_id,
                user_id=selected_user,
                public_key=result.public_key,
                sign_count=result.sign_count,
                user_handle=_user_handle(selected_user),
                device_type=result.device_type,
                backed_up=result.backed_up,
                transports=result.transports,
                discoverable=result.discoverable,
            ),
        )


def _session_for_flow(flow: RegistrationFlow, session_id: str | None) -> str | None:
    if flow == "bootstrap":
        if session_id is not None:
            raise ValueError("bootstrap registrations are not session-bound")
        return None
    if flow != "management" or session_id is None or not 16 <= len(session_id) <= 128:
        raise ValueError("management registrations require a bound session")
    return session_id


def _label(label: str) -> str:
    normalized = " ".join(label.split())
    if not normalized or len(normalized.encode("utf-8")) > 64:
        raise ValueError("factor label must contain at most 64 bytes")
    return normalized


def _user_handle(user_id: str) -> bytes:
    import hashlib

    return hashlib.sha256(b"signet-webauthn-user-v1\x00" + user_id.encode()).digest()


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if not value or any(character not in _BASE64URL_ALPHABET for character in value):
        raise ValueError("invalid base64url")
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if _base64url_encode(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
