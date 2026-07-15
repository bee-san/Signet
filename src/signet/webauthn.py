"""Action-bound WebAuthn challenge and assertion verification.

Verification intentionally does not consume the challenge or update the
credential counter.  The returned proof contains every value a persistence
layer needs to compare-and-swap those records in the same transaction as the
authorized action.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
from dataclasses import dataclass, replace
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from webauthn import (
    generate_authentication_options,
    options_to_json,
    verify_authentication_response,
)
from webauthn.helpers import parse_authentication_credential_json
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    UserVerificationRequirement,
)

from signet.auth import (
    WEBAUTHN_PROOF_DOMAIN,
    ActionBinding,
    ProofCapability,
    _bounded_identifier,
    _ensure_auth_user,
    _revoke_user_sessions,
    canonical_user_id,
    webauthn_proof_claims,
)
from signet.db import Database, IntegrityError


class WebAuthnError(RuntimeError):
    pass


class InvalidWebAuthnAssertion(WebAuthnError):
    pass


class WebAuthnChallengeUnavailable(WebAuthnError):
    pass


class WebAuthnCredentialUnavailable(WebAuthnError):
    pass


class WebAuthnChallengeRateLimited(WebAuthnError):
    pass


type DeviceType = Literal["single_device", "multi_device"]


@dataclass(frozen=True, slots=True, repr=False)
class FakeAssertion:
    """An explicitly non-WebAuthn assertion used only by ``FakeWebAuthnProvider``."""

    credential_id: str
    user_handle: bytes | None
    challenge: bytes
    origin: str
    rp_id: str
    new_sign_count: int
    outer_type: str = "public-key"
    client_type: str = "webauthn.get"
    cross_origin: bool = False
    user_present: bool = True
    user_verified: bool = True
    device_type: DeviceType = "single_device"
    backed_up: bool = False
    signature_valid: bool = True

    def __repr__(self) -> str:
        return "FakeAssertion(challenge=<redacted>, response=<explicit-fake>)"


type AssertionInput = str | dict[str, Any] | AuthenticationCredential | FakeAssertion


@dataclass(frozen=True, slots=True, repr=False)
class WebAuthnCredential:
    credential_id: str
    user_id: str
    user_handle: bytes
    public_key: bytes
    sign_count: int
    device_type: DeviceType
    backed_up: bool
    disabled: bool = False

    def __post_init__(self) -> None:
        if (
            not self.credential_id
            or not self.user_id
            or not self.user_handle
            or not self.public_key
        ):
            raise ValueError("WebAuthn credential fields must not be empty")
        if self.sign_count < 0:
            raise ValueError("credential counter cannot be negative")
        if self.device_type == "single_device" and self.backed_up:
            raise ValueError("a single-device credential cannot be backed up")
        try:
            raw_id = _base64url_decode(self.credential_id)
        except ValueError:
            raise ValueError("credential ID must be canonical base64url") from None
        if not raw_id or _base64url_encode(raw_id) != self.credential_id:
            raise ValueError("credential ID must be canonical base64url")

    @property
    def raw_id(self) -> bytes:
        return _base64url_decode(self.credential_id)

    def __repr__(self) -> str:
        return (
            "WebAuthnCredential("
            f"credential_id=<redacted>, user_id={self.user_id!r}, "
            "user_handle=<redacted>, public_key=<redacted>, "
            f"sign_count={self.sign_count!r}, device_type={self.device_type!r}, "
            f"backed_up={self.backed_up!r}, disabled={self.disabled!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class WebAuthnChallenge:
    challenge_id: str
    challenge: bytes
    user_id: str
    binding: ActionBinding
    session_id: str
    http_method: str
    offered_credential_ids: tuple[str, ...]
    created_at: int
    expires_at: int
    consumed_at: int | None = None
    invalidated_at: int | None = None

    def __repr__(self) -> str:
        return (
            "WebAuthnChallenge("
            f"challenge_id=<redacted>, challenge=<redacted>, "
            f"user_id={self.user_id!r}, binding={self.binding!r}, "
            "session_id=<redacted>, "
            f"http_method={self.http_method!r}, offered_credentials=<redacted>, "
            f"created_at={self.created_at!r}, expires_at={self.expires_at!r}, "
            f"consumed_at={self.consumed_at!r}, invalidated_at={self.invalidated_at!r})"
        )


class WebAuthnRepository(Protocol):
    """Repository reads used during verification and atomic challenge issuance."""

    def create_challenge(
        self,
        challenge: WebAuthnChallenge,
        *,
        now: int,
        max_active: int,
    ) -> bool: ...

    def find_challenge(self, challenge_id: str) -> WebAuthnChallenge | None: ...

    def invalidate_challenge(self, challenge_id: str, *, now: int) -> bool: ...

    def find_credential(self, credential_id: str) -> WebAuthnCredential | None: ...

    def credentials_for_user(self, user_id: str) -> tuple[WebAuthnCredential, ...]: ...


class InMemoryWebAuthnRepository:
    """Thread-safe fake persistence for unit tests."""

    def __init__(self, credentials: tuple[WebAuthnCredential, ...] = ()) -> None:
        self._credentials = {credential.credential_id: credential for credential in credentials}
        self._challenges: dict[str, WebAuthnChallenge] = {}
        self._lock = threading.Lock()

    def create_challenge(
        self,
        challenge: WebAuthnChallenge,
        *,
        now: int,
        max_active: int,
    ) -> bool:
        with self._lock:
            active_count = sum(
                item.user_id == challenge.user_id
                and item.consumed_at is None
                and item.invalidated_at is None
                and item.expires_at > now
                for item in self._challenges.values()
            )
            if challenge.challenge_id in self._challenges or active_count >= max_active:
                return False
            self._challenges[challenge.challenge_id] = challenge
            return True

    def find_challenge(self, challenge_id: str) -> WebAuthnChallenge | None:
        with self._lock:
            return self._challenges.get(challenge_id)

    def invalidate_challenge(self, challenge_id: str, *, now: int) -> bool:
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if (
                challenge is None
                or challenge.consumed_at is not None
                or challenge.invalidated_at is not None
            ):
                return False
            self._challenges[challenge_id] = replace(challenge, invalidated_at=now)
            return True

    def find_credential(self, credential_id: str) -> WebAuthnCredential | None:
        with self._lock:
            return self._credentials.get(credential_id)

    def credentials_for_user(self, user_id: str) -> tuple[WebAuthnCredential, ...]:
        with self._lock:
            return tuple(
                credential
                for credential in self._credentials.values()
                if credential.user_id == user_id and not credential.disabled
            )

    def consume_challenge(self, challenge_id: str, *, now: int) -> bool:
        """Test helper modelling the transaction performed by the state machine."""

        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if (
                challenge is None
                or challenge.consumed_at is not None
                or challenge.invalidated_at is not None
                or challenge.expires_at <= now
            ):
                return False
            self._challenges[challenge_id] = replace(challenge, consumed_at=now)
            return True

    def update_credential(
        self,
        credential_id: str,
        *,
        expected_sign_count: int,
        new_sign_count: int,
        backed_up: bool,
    ) -> bool:
        """Test helper modelling the credential compare-and-swap."""

        with self._lock:
            credential = self._credentials.get(credential_id)
            if (
                credential is None
                or credential.disabled
                or credential.sign_count != expected_sign_count
            ):
                return False
            self._credentials[credential_id] = replace(
                credential,
                sign_count=new_sign_count,
                backed_up=backed_up,
            )
            return True

    def replace_challenge(self, challenge: WebAuthnChallenge) -> None:
        """Test helper for expiry, invalidation, and replay fixtures."""

        with self._lock:
            self._challenges[challenge.challenge_id] = challenge

    def replace_credential(self, credential: WebAuthnCredential) -> None:
        """Test helper for revocation and counter-race fixtures."""

        with self._lock:
            self._credentials[credential.credential_id] = credential


class SQLiteWebAuthnRepository:
    """Durable credentials and complete action-bound challenge records."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create_challenge(
        self,
        challenge: WebAuthnChallenge,
        *,
        now: int,
        max_active: int,
    ) -> bool:
        offered_json = json.dumps(
            list(challenge.offered_credential_ids),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        with self.database.transaction() as connection:
            active = int(
                connection.execute(
                    """
                    SELECT count(*) FROM auth_challenges
                    WHERE user_id = ? AND consumed_at IS NULL
                      AND invalidated_at IS NULL AND expires_at > ?
                    """,
                    (challenge.user_id, now),
                ).fetchone()[0]
            )
            if active >= max_active:
                return False
            try:
                connection.execute(
                    """
                    INSERT INTO auth_challenges(
                        challenge_id, challenge, user_id, action, request_id,
                        version, current_payload_hash, prospective_payload_hash,
                        session_id, http_method, offered_credential_ids_json,
                        created_at, expires_at, consumed_at, invalidated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        challenge.challenge_id,
                        challenge.challenge,
                        challenge.user_id,
                        challenge.binding.action,
                        challenge.binding.request_id,
                        challenge.binding.version,
                        challenge.binding.payload_hash,
                        challenge.binding.prospective_payload_hash,
                        challenge.session_id,
                        challenge.http_method,
                        offered_json,
                        challenge.created_at,
                        challenge.expires_at,
                        challenge.consumed_at,
                        challenge.invalidated_at,
                    ),
                )
            except IntegrityError:
                return False
        return True

    def find_challenge(self, challenge_id: str) -> WebAuthnChallenge | None:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM auth_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            return None
        offered = json.loads(str(row["offered_credential_ids_json"]))
        if not isinstance(offered, list) or not all(isinstance(item, str) for item in offered):
            raise WebAuthnError("stored WebAuthn challenge is invalid")
        return WebAuthnChallenge(
            challenge_id=str(row["challenge_id"]),
            challenge=bytes(row["challenge"]),
            user_id=str(row["user_id"]),
            binding=ActionBinding(
                action=str(row["action"]),
                request_id=(str(row["request_id"]) if row["request_id"] is not None else None),
                version=(int(row["version"]) if row["version"] is not None else None),
                payload_hash=(
                    str(row["current_payload_hash"])
                    if row["current_payload_hash"] is not None
                    else None
                ),
                prospective_payload_hash=(
                    str(row["prospective_payload_hash"])
                    if row["prospective_payload_hash"] is not None
                    else None
                ),
            ),
            session_id=str(row["session_id"]),
            http_method=str(row["http_method"]),
            offered_credential_ids=tuple(offered),
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
            consumed_at=(
                int(row["consumed_at"]) if row["consumed_at"] is not None else None
            ),
            invalidated_at=(
                int(row["invalidated_at"]) if row["invalidated_at"] is not None else None
            ),
        )

    def invalidate_challenge(self, challenge_id: str, *, now: int) -> bool:
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE auth_challenges SET invalidated_at = ?
                WHERE challenge_id = ? AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """,
                (now, challenge_id),
            ).rowcount
        return int(updated) == 1

    def find_credential(self, credential_id: str) -> WebAuthnCredential | None:
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT * FROM auth_credentials
                WHERE credential_id = ? AND kind = 'webauthn'
                """,
                (credential_id,),
            ).fetchone()
        return _credential_from_row(row) if row is not None else None

    def credentials_for_user(self, user_id: str) -> tuple[WebAuthnCredential, ...]:
        user_id = canonical_user_id(user_id)
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM auth_credentials
                WHERE user_id = ? AND kind = 'webauthn' AND disabled_at IS NULL
                ORDER BY credential_id
                """,
                (user_id,),
            ).fetchall()
        return tuple(_credential_from_row(row) for row in rows)

    def add_credential(self, credential: WebAuthnCredential, *, now: int) -> None:
        user_id = canonical_user_id(credential.user_id)
        with self.database.transaction() as connection:
            _ensure_auth_user(connection, user_id, created_at=now)
            connection.execute(
                """
                INSERT INTO auth_credentials(
                    credential_id, user_id, kind, public_material, enrolled_at,
                    sign_count, backup_eligible, backup_state, user_handle
                ) VALUES (?, ?, 'webauthn', ?, ?, ?, ?, ?, ?)
                """,
                (
                    credential.credential_id,
                    user_id,
                    credential.public_key,
                    now,
                    credential.sign_count,
                    int(credential.device_type == "multi_device"),
                    int(credential.backed_up),
                    credential.user_handle,
                ),
            )
            _revoke_user_sessions(connection, user_id, revoked_at=now)

    def disable_credential(self, credential_id: str, user_id: str, *, now: int) -> bool:
        user_id = canonical_user_id(user_id)
        with self.database.transaction() as connection:
            updated = int(
                connection.execute(
                    """
                    UPDATE auth_credentials SET disabled_at = ?
                    WHERE credential_id = ? AND user_id = ? AND kind = 'webauthn'
                      AND disabled_at IS NULL
                    """,
                    (now, credential_id, user_id),
                ).rowcount
            )
            if updated:
                _revoke_user_sessions(connection, user_id, revoked_at=now)
        return updated == 1


@dataclass(frozen=True, slots=True, repr=False)
class IssuedWebAuthnChallenge:
    challenge_id: str
    binding: ActionBinding
    options_json: str
    expires_at: int

    def __repr__(self) -> str:
        return (
            "IssuedWebAuthnChallenge("
            f"challenge_id=<redacted>, binding={self.binding!r}, "
            f"options_json=<redacted>, expires_at={self.expires_at!r})"
        )


class WebAuthnChallengeIssuer:
    """Create fresh user-verification-required request options."""

    def __init__(
        self,
        repository: WebAuthnRepository,
        *,
        rp_id: str,
        lifetime: int = 2 * 60,
        max_active_per_user: int = 5,
    ) -> None:
        normalized_rp = _normalize_rp_id(rp_id)
        if lifetime <= 0 or lifetime > 10 * 60 or max_active_per_user <= 0:
            raise ValueError("invalid WebAuthn challenge limits")
        self._repository = repository
        self.rp_id = normalized_rp
        self.lifetime = lifetime
        self.max_active_per_user = max_active_per_user

    def issue(
        self,
        user_id: str,
        binding: ActionBinding,
        *,
        session_id: str,
        http_method: str,
        now: int,
    ) -> IssuedWebAuthnChallenge:
        user_id = canonical_user_id(user_id)
        _bounded_identifier(session_id, name="session ID", maximum=128)
        if len(session_id) < 16 or http_method != "POST":
            raise ValueError("WebAuthn challenges require a bound session and POST method")
        credentials = self._repository.credentials_for_user(user_id)
        if not credentials:
            raise WebAuthnCredentialUnavailable("no active WebAuthn credential")
        challenge_bytes = secrets.token_bytes(32)
        challenge_id = _base64url_encode(secrets.token_bytes(24))
        challenge = WebAuthnChallenge(
            challenge_id=challenge_id,
            challenge=challenge_bytes,
            user_id=user_id,
            binding=binding,
            session_id=session_id,
            http_method=http_method,
            offered_credential_ids=tuple(
                credential.credential_id for credential in credentials
            ),
            created_at=now,
            expires_at=now + self.lifetime,
        )
        created = self._repository.create_challenge(
            challenge,
            now=now,
            max_active=self.max_active_per_user,
        )
        if not created:
            raise WebAuthnChallengeRateLimited("too many active WebAuthn challenges")
        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge_bytes,
            timeout=self.lifetime * 1_000,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=credential.raw_id)
                for credential in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return IssuedWebAuthnChallenge(
            challenge_id=challenge_id,
            binding=binding,
            options_json=options_to_json(options),
            expires_at=challenge.expires_at,
        )


@dataclass(frozen=True, slots=True, repr=False)
class AssertionInspection:
    credential_id: str
    user_handle: bytes | None
    challenge: bytes
    origin: str
    outer_type: str
    client_type: str
    cross_origin: bool

    def __repr__(self) -> str:
        return "AssertionInspection(credential/challenge/user_handle=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ProviderVerification:
    credential_id: str
    new_sign_count: int
    user_present: bool
    user_verified: bool
    device_type: DeviceType
    backed_up: bool

    def __repr__(self) -> str:
        return "ProviderVerification(credential_id=<redacted>, result=<verified>)"


class WebAuthnProvider(Protocol):
    test_only: bool

    def inspect(self, assertion: AssertionInput) -> AssertionInspection: ...

    def verify(
        self,
        assertion: AssertionInput,
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
        credential_public_key: bytes,
        credential_current_sign_count: int,
    ) -> ProviderVerification: ...


class OfficialWebAuthnProvider:
    """Production provider using the official ``webauthn`` package."""

    test_only = False

    def inspect(self, assertion: AssertionInput) -> AssertionInspection:
        credential = _parse_official_credential(assertion)
        try:
            client_data = _strict_json_object(bytes(credential.response.client_data_json))
            challenge_value = client_data["challenge"]
            origin = client_data["origin"]
            client_type = client_data["type"]
            cross_origin_value = client_data.get("crossOrigin", False)
            if not isinstance(challenge_value, str):
                raise ValueError
            if not isinstance(origin, str) or not isinstance(client_type, str):
                raise ValueError
            if not isinstance(cross_origin_value, bool):
                raise ValueError
            challenge = _base64url_decode(challenge_value)
            outer_type = (
                credential.type.value
                if isinstance(credential.type, PublicKeyCredentialType)
                else str(credential.type)
            )
        except (KeyError, TypeError, UnicodeError, ValueError):
            raise InvalidWebAuthnAssertion("invalid WebAuthn assertion") from None
        return AssertionInspection(
            credential_id=credential.id,
            user_handle=(
                bytes(credential.response.user_handle)
                if credential.response.user_handle is not None
                else None
            ),
            challenge=challenge,
            origin=origin,
            outer_type=outer_type,
            client_type=client_type,
            cross_origin=cross_origin_value,
        )

    def verify(
        self,
        assertion: AssertionInput,
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
        credential_public_key: bytes,
        credential_current_sign_count: int,
    ) -> ProviderVerification:
        credential = _parse_official_credential(assertion)
        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=expected_rp_id,
                expected_origin=expected_origin,
                credential_public_key=credential_public_key,
                credential_current_sign_count=credential_current_sign_count,
                require_user_verification=True,
            )
        except (WebAuthnException, TypeError, ValueError):
            raise InvalidWebAuthnAssertion("invalid WebAuthn assertion") from None
        return ProviderVerification(
            credential_id=_base64url_encode(verified.credential_id),
            new_sign_count=verified.new_sign_count,
            user_present=True,
            user_verified=verified.user_verified,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
        )


class FakeWebAuthnProvider:
    """Explicit fake provider.  Construction of the verifier requires test opt-in."""

    test_only = True

    def inspect(self, assertion: AssertionInput) -> AssertionInspection:
        fake = _require_fake(assertion)
        return AssertionInspection(
            credential_id=fake.credential_id,
            user_handle=fake.user_handle,
            challenge=fake.challenge,
            origin=fake.origin,
            outer_type=fake.outer_type,
            client_type=fake.client_type,
            cross_origin=fake.cross_origin,
        )

    def verify(
        self,
        assertion: AssertionInput,
        *,
        expected_challenge: bytes,
        expected_rp_id: str,
        expected_origin: str,
        credential_public_key: bytes,
        credential_current_sign_count: int,
    ) -> ProviderVerification:
        del credential_public_key
        fake = _require_fake(assertion)
        counter_valid = (
            fake.new_sign_count == 0 == credential_current_sign_count
            or fake.new_sign_count > credential_current_sign_count
        )
        if (
            not fake.signature_valid
            or fake.challenge != expected_challenge
            or fake.rp_id != expected_rp_id
            or fake.origin != expected_origin
            or not fake.user_present
            or not fake.user_verified
            or not counter_valid
        ):
            raise InvalidWebAuthnAssertion("invalid fake WebAuthn assertion")
        return ProviderVerification(
            credential_id=fake.credential_id,
            new_sign_count=fake.new_sign_count,
            user_present=fake.user_present,
            user_verified=fake.user_verified,
            device_type=fake.device_type,
            backed_up=fake.backed_up,
        )


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedWebAuthn:
    credential_id: str
    user_id: str
    challenge_id: str
    use_id: str
    binding: ActionBinding
    session_id: str
    http_method: str
    expected_counter: int
    new_counter: int
    device_type: DeviceType
    expected_backup_eligible: bool
    new_backup_eligible: bool
    previous_backed_up: bool
    new_backed_up: bool
    capability: str

    def __repr__(self) -> str:
        return (
            "VerifiedWebAuthn(credential_id=<redacted>, challenge_id=<redacted>, "
            f"user_id={self.user_id!r}, binding={self.binding!r}, result=<verified>)"
        )


class WebAuthnAssertionVerifier:
    """Strictly validate a user-owned assertion against an action challenge."""

    def __init__(
        self,
        repository: WebAuthnRepository,
        *,
        rp_id: str,
        origin: str,
        provider: WebAuthnProvider | None = None,
        capabilities: ProofCapability,
        allow_test_provider: bool = False,
    ) -> None:
        _validate_origin_and_rp(origin, rp_id)
        selected_provider = provider or OfficialWebAuthnProvider()
        if selected_provider.test_only and not allow_test_provider:
            raise ValueError("a fake WebAuthn provider requires explicit test opt-in")
        self._repository = repository
        self.rp_id = _normalize_rp_id(rp_id)
        self.origin = origin
        self._provider = selected_provider
        self._capabilities = capabilities

    def verify(
        self,
        assertion: AssertionInput,
        *,
        challenge_id: str,
        user_id: str,
        binding: ActionBinding,
        session_id: str,
        http_method: str,
        now: int,
    ) -> VerifiedWebAuthn:
        user_id = canonical_user_id(user_id)
        challenge = self._repository.find_challenge(challenge_id)
        if (
            challenge is None
            or challenge.user_id != user_id
            or challenge.binding != binding
            or challenge.session_id != session_id
            or challenge.http_method != http_method
            or challenge.consumed_at is not None
            or challenge.invalidated_at is not None
            or now >= challenge.expires_at
            or now < challenge.created_at
        ):
            raise WebAuthnChallengeUnavailable("challenge is stale, expired, or consumed")

        inspection = self._provider.inspect(assertion)
        if (
            inspection.outer_type != "public-key"
            or inspection.client_type != "webauthn.get"
            or inspection.cross_origin
            or inspection.origin != self.origin
            or inspection.challenge != challenge.challenge
            or inspection.user_handle is None
            or inspection.credential_id not in challenge.offered_credential_ids
        ):
            raise InvalidWebAuthnAssertion("invalid WebAuthn assertion")

        credential = self._repository.find_credential(inspection.credential_id)
        if (
            credential is None
            or credential.disabled
            or credential.user_id != user_id
            or not hmac_compare(credential.user_handle, inspection.user_handle)
        ):
            raise WebAuthnCredentialUnavailable("credential is unavailable")

        verified = self._provider.verify(
            assertion,
            expected_challenge=challenge.challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
        )
        counter_valid = (
            verified.new_sign_count == 0 == credential.sign_count
            or verified.new_sign_count > credential.sign_count
        )
        backup_valid = (
            verified.device_type == credential.device_type
            and not (credential.backed_up and not verified.backed_up)
            and not (verified.device_type == "single_device" and verified.backed_up)
        )
        if (
            verified.credential_id != credential.credential_id
            or not verified.user_present
            or not verified.user_verified
            or not counter_valid
            or not backup_valid
        ):
            raise InvalidWebAuthnAssertion("invalid WebAuthn assertion")

        use_id = _assertion_use_id(challenge.challenge_id, credential.credential_id)
        expected_backup_eligible = credential.device_type == "multi_device"
        new_backup_eligible = verified.device_type == "multi_device"
        capability = self._capabilities.seal(
            WEBAUTHN_PROOF_DOMAIN,
            webauthn_proof_claims(
                credential_id=credential.credential_id,
                credential_user_id=credential.user_id,
                user_id=credential.user_id,
                challenge_id=challenge.challenge_id,
                use_id=use_id,
                binding=binding,
                path="web",
                session_id=session_id,
                http_method=http_method,
                expected_counter=credential.sign_count,
                new_counter=verified.new_sign_count,
                device_type=verified.device_type,
                expected_backup_eligible=expected_backup_eligible,
                new_backup_eligible=new_backup_eligible,
                previous_backed_up=credential.backed_up,
                new_backed_up=verified.backed_up,
            ),
        )
        return VerifiedWebAuthn(
            credential_id=credential.credential_id,
            user_id=credential.user_id,
            challenge_id=challenge.challenge_id,
            use_id=use_id,
            binding=binding,
            session_id=session_id,
            http_method=http_method,
            expected_counter=credential.sign_count,
            new_counter=verified.new_sign_count,
            device_type=verified.device_type,
            expected_backup_eligible=expected_backup_eligible,
            new_backup_eligible=new_backup_eligible,
            previous_backed_up=credential.backed_up,
            new_backed_up=verified.backed_up,
            capability=capability,
        )


def _parse_official_credential(assertion: AssertionInput) -> AuthenticationCredential:
    try:
        if isinstance(assertion, AuthenticationCredential):
            return assertion
        if isinstance(assertion, str):
            return parse_authentication_credential_json(assertion)
        if isinstance(assertion, dict) and "__fake__" not in assertion:
            return parse_authentication_credential_json(assertion)
    except (WebAuthnException, KeyError, TypeError, ValueError):
        pass
    raise InvalidWebAuthnAssertion("invalid WebAuthn assertion")


def _require_fake(assertion: AssertionInput) -> FakeAssertion:
    if not isinstance(assertion, FakeAssertion):
        raise InvalidWebAuthnAssertion("fake provider requires a fake assertion")
    return assertion


def _strict_json_object(value: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = item
        return result

    parsed = json.loads(value.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(parsed, dict):
        raise ValueError("client data must be an object")
    return parsed


def _validate_origin_and_rp(origin: str, rp_id: str) -> None:
    parsed = urlsplit(origin)
    normalized_rp = _normalize_rp_id(rp_id)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("WebAuthn requires an HTTPS origin and hostname RP ID") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("WebAuthn requires an HTTPS origin and hostname RP ID")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("WebAuthn origin hostname is invalid") from None
    canonical_origin = f"https://{hostname}"
    if port is not None and port != 443:
        canonical_origin = f"{canonical_origin}:{port}"
    if origin != canonical_origin:
        raise ValueError("WebAuthn origin must use its canonical HTTPS serialization")
    if hostname != normalized_rp:
        raise ValueError("RP ID must exactly match the origin host")


def _normalize_rp_id(rp_id: str) -> str:
    try:
        normalized = rp_id.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("RP ID must be a hostname") from None
    if (
        not normalized
        or len(normalized) > 253
        or normalized.endswith(".")
        or normalized != rp_id
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or _HOST_LABEL.fullmatch(label) is None
            for label in normalized.split(".")
        )
    ):
        raise ValueError("RP ID must be a canonical hostname")
    return normalized


def _assertion_use_id(challenge_id: str, credential_id: str) -> str:
    value = f"webauthn-use\x00{challenge_id}\x00{credential_id}".encode()
    return hashlib.sha256(value).hexdigest()


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not value or any(character not in alphabet for character in value):
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


def hmac_compare(left: bytes, right: bytes) -> bool:
    """Keep user-handle comparisons constant-time and easy to audit."""

    return hmac.compare_digest(left, right)


_HOST_LABEL = re.compile(r"[a-z0-9-]+")


def _credential_from_row(row: Any) -> WebAuthnCredential:
    if row["user_handle"] is None or row["backup_eligible"] is None:
        raise WebAuthnError("stored WebAuthn credential is incomplete")
    return WebAuthnCredential(
        credential_id=str(row["credential_id"]),
        user_id=str(row["user_id"]),
        user_handle=bytes(row["user_handle"]),
        public_key=bytes(row["public_material"]),
        sign_count=int(row["sign_count"]),
        device_type=("multi_device" if bool(row["backup_eligible"]) else "single_device"),
        backed_up=bool(row["backup_state"]),
        disabled=row["disabled_at"] is not None,
    )
