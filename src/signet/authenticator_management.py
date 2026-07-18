"""Persistent multi-authenticator management with action-bound proof consumption.

This module owns safe factor metadata and guarded mutations. Secret provisioning is
kept behind ``TotpSecretProvisioner``; list/read APIs never load credential material.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

import keyring
import pyotp

from signet.auth import (
    TOTP_PROOF_DOMAIN,
    WEBAUTHN_PROOF_DOMAIN,
    ActionBinding,
    ProofCapability,
    _bounded_identifier,
    _ensure_auth_user,
    _require_active_session,
    _revoke_user_sessions,
    canonical_user_id,
    totp_factor_rate_limit_key,
    totp_proof_claims,
    totp_rate_limit_key,
    webauthn_proof_claims,
)
from signet.credential_broker import CredentialError, SecretReference
from signet.db import Database, IntegrityError
from signet.totp import VerifiedTotp
from signet.webauthn import VerifiedWebAuthn, WebAuthnCredential

FactorKind = Literal["password", "totp", "webauthn"]
FactorState = Literal["active", "revoked", "compromised"]
ManagementAction = Literal[
    "add_authenticator",
    "rename_authenticator",
    "revoke_authenticator",
    "replace_authenticator",
]


class AuthenticatorManagementError(RuntimeError):
    pass


# Backwards-compatible concise public name used by backend callers.
FactorManagementError = AuthenticatorManagementError


class InvalidFactorProof(AuthenticatorManagementError):
    pass


FactorProofInvalid = InvalidFactorProof


class FactorProofReplay(InvalidFactorProof):
    pass


FactorReplay = FactorProofReplay


class FactorUnavailable(AuthenticatorManagementError):
    pass


class LastAuthenticatorRemovalDenied(AuthenticatorManagementError):
    pass


LastAuthenticatorError = LastAuthenticatorRemovalDenied


class SecretProvisioningError(AuthenticatorManagementError):
    pass


class TotpSecretProvisioner(Protocol):
    """Generate/provision TOTP material without returning the seed to callers."""

    def create(self, factor_id: str) -> str: ...

    def delete(self, secret_reference: str) -> None: ...


class KeychainTotpSecretProvisioner:
    """Generate a unique RFC 6238 seed and place it directly in the OS keychain."""

    def __init__(self, *, service: str = "Signet") -> None:
        self.service = _bounded_identifier(service, name="keychain service", maximum=128)

    def create(self, factor_id: str) -> str:
        _factor_id(factor_id)
        seed = pyotp.random_base32(length=32)
        try:
            keyring.set_password(self.service, factor_id, seed)
        except Exception as exc:  # keyring backends intentionally vary by platform
            raise SecretProvisioningError("TOTP provisioning failed") from exc
        return f"keychain://{self.service}/{factor_id}"

    def delete(self, secret_reference: str) -> None:
        reference = SecretReference.parse(secret_reference)
        if reference.service != self.service:
            raise SecretProvisioningError("TOTP secret reference is outside this provisioner")
        try:
            keyring.delete_password(reference.service, reference.account)
        except Exception as exc:  # keyring backends intentionally vary by platform
            raise SecretProvisioningError("TOTP secret cleanup failed") from exc

    def __repr__(self) -> str:
        return f"KeychainTotpSecretProvisioner(service={self.service!r})"


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    """Explicit operator policy; strict denial is the default."""

    allow_last_factor_revocation: bool = False
    allow_last_admin_factor_revocation: bool = False
    allow_bootstrap_without_factor: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class FactorMetadata:
    factor_id: str
    credential_id: str
    user_id: str
    kind: FactorKind
    label: str
    state: FactorState
    created_at: int
    updated_at: int
    last_used_at: int | None
    revoked_at: int | None
    compromised_at: int | None
    created_audit_ref: str
    state_audit_ref: str | None
    transports: tuple[str, ...] = ()
    discoverable: bool = False
    device_type: Literal["single_device", "multi_device"] | None = None
    backed_up: bool | None = None

    def __repr__(self) -> str:
        return (
            "FactorMetadata("
            f"factor_id={self.factor_id!r}, credential_id={self.credential_id!r}, "
            f"user_id={self.user_id!r}, kind={self.kind!r}, label={self.label!r}, "
            f"state={self.state!r}, created_at={self.created_at!r}, "
            f"updated_at={self.updated_at!r}, last_used_at={self.last_used_at!r}, "
            f"transports={self.transports!r}, discoverable={self.discoverable!r}, "
            f"device_type={self.device_type!r}, backed_up={self.backed_up!r})"
        )


class AuthenticatorManager:
    """Manage persistent factors using fresh, single-use existing-factor proofs."""

    def __init__(
        self,
        database: Database,
        *,
        capabilities: ProofCapability,
        provisioner: TotpSecretProvisioner,
        recovery_policy: RecoveryPolicy | None = None,
        web_session_idle_timeout: int = 30 * 60,
        maximum_proof_lifetime: int = 5 * 60,
    ) -> None:
        if web_session_idle_timeout < 1 or maximum_proof_lifetime < 1:
            raise ValueError("factor-management timeouts must be positive")
        self.database = database
        self._capabilities = capabilities
        self._totp_provisioner = provisioner
        self.recovery_policy = recovery_policy or RecoveryPolicy()
        self.session_idle_timeout = web_session_idle_timeout
        self.maximum_proof_lifetime = maximum_proof_lifetime
        self.proof_lifetime = maximum_proof_lifetime

    def list_factors(
        self, user_id: str, *, include_inactive: bool = True
    ) -> tuple[FactorMetadata, ...]:
        selected_user = canonical_user_id(user_id)
        with self.database.read() as connection:
            if include_inactive:
                rows = connection.execute(
                    """
                    SELECT f.factor_id, f.credential_id, f.user_id, f.kind, f.label,
                           f.state, f.created_at, f.updated_at, f.last_used_at,
                           f.revoked_at, f.compromised_at, f.created_audit_ref,
                           f.state_audit_ref, c.transports_json, c.backup_eligible,
                           c.backup_state, c.discoverable
                    FROM auth_factors AS f
                    JOIN auth_credentials AS c ON c.credential_id = f.credential_id
                    WHERE f.user_id = ?
                    ORDER BY f.created_at, f.factor_id
                    """,
                    (selected_user,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT f.factor_id, f.credential_id, f.user_id, f.kind, f.label,
                           f.state, f.created_at, f.updated_at, f.last_used_at,
                           f.revoked_at, f.compromised_at, f.created_audit_ref,
                           f.state_audit_ref, c.transports_json, c.backup_eligible,
                           c.backup_state, c.discoverable
                    FROM auth_factors AS f
                    JOIN auth_credentials AS c ON c.credential_id = f.credential_id
                    WHERE f.user_id = ? AND f.state = 'active'
                    ORDER BY f.created_at, f.factor_id
                    """,
                    (selected_user,),
                ).fetchall()
        return tuple(_metadata(row) for row in rows)

    def get_factor(self, user_id: str, factor_id: str) -> FactorMetadata | None:
        selected_user = canonical_user_id(user_id)
        selected_factor = _factor_id(factor_id)
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT f.factor_id, f.credential_id, f.user_id, f.kind, f.label,
                       f.state, f.created_at, f.updated_at, f.last_used_at,
                       f.revoked_at, f.compromised_at, f.created_audit_ref,
                       f.state_audit_ref, c.transports_json, c.backup_eligible,
                       c.backup_state, c.discoverable
                FROM auth_factors AS f
                JOIN auth_credentials AS c ON c.credential_id = f.credential_id
                WHERE f.factor_id = ? AND f.user_id = ?
                """,
                (selected_factor, selected_user),
            ).fetchone()
        return _metadata(row) if row is not None else None

    def binding_for_add_totp(self, user_id: str, label: str, operation_id: str) -> ActionBinding:
        return self._binding(
            "add_authenticator",
            user_id,
            operation_id,
            {"kind": "totp", "label": _label(label)},
        )

    def binding_for_add_passkey(
        self,
        user_id: str,
        label: str,
        credential: WebAuthnCredential,
        operation_id: str,
    ) -> ActionBinding:
        selected_user = canonical_user_id(user_id)
        if credential.user_id != selected_user or credential.disabled:
            raise ValueError("an active user-owned passkey credential is required")
        return self._binding(
            "add_authenticator",
            selected_user,
            operation_id,
            {
                "credential_id": credential.credential_id,
                "kind": "webauthn",
                "label": _label(label),
                "public_key_sha256": hashlib.sha256(credential.public_key).hexdigest(),
                "user_handle_sha256": hashlib.sha256(credential.user_handle).hexdigest(),
                "sign_count": credential.sign_count,
                "device_type": credential.device_type,
                "backed_up": credential.backed_up,
                "transports": list(credential.transports),
                "discoverable": credential.discoverable,
            },
        )

    def binding_for_rename(
        self,
        user_id: str,
        factor_id: str,
        label: str,
        operation_id: str,
    ) -> ActionBinding:
        return self._binding(
            "rename_authenticator",
            user_id,
            operation_id,
            {"factor_id": _factor_id(factor_id), "label": _label(label)},
        )

    def binding_for_revoke(
        self,
        user_id: str,
        factor_id: str,
        operation_id: str,
        *,
        compromised: bool,
    ) -> ActionBinding:
        return self._binding(
            "revoke_authenticator",
            user_id,
            operation_id,
            {"compromised": compromised, "factor_id": _factor_id(factor_id)},
        )

    def binding_for_replace_totp(
        self,
        user_id: str,
        factor_id: str,
        label: str,
        operation_id: str,
    ) -> ActionBinding:
        return self._binding(
            "replace_authenticator",
            user_id,
            operation_id,
            {"factor_id": _factor_id(factor_id), "kind": "totp", "label": _label(label)},
        )

    def add_totp(
        self,
        user_id: str,
        label: str,
        operation_id: str,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
    ) -> FactorMetadata:
        selected_user = canonical_user_id(user_id)
        selected_label = _label(label)
        binding = self.binding_for_add_totp(selected_user, selected_label, operation_id)
        self._validate_proof_envelope(confirmation, user_id=selected_user, binding=binding, now=now)
        factor_id = _new_factor_id()
        credential_id = _new_credential_id("totp")
        secret_reference = self._totp_provisioner.create(factor_id)
        try:
            SecretReference.parse(secret_reference)
            with self.database.transaction() as connection:
                actor_factor_id = self._consume_proof(
                    connection,
                    confirmation,
                    user_id=selected_user,
                    binding=binding,
                    now=now,
                )
                _ensure_auth_user(connection, selected_user, created_at=now)
                connection.execute(
                    """
                    INSERT INTO auth_credentials(
                        credential_id, user_id, kind, secret_reference, enrolled_at, factor_label
                    ) VALUES (?, ?, 'totp', ?, ?, ?)
                    """,
                    (credential_id, selected_user, secret_reference, now, selected_label),
                )
                self._insert_factor(
                    connection,
                    factor_id=factor_id,
                    credential_id=credential_id,
                    user_id=selected_user,
                    kind="totp",
                    label=selected_label,
                    action="added",
                    actor_factor_id=actor_factor_id,
                    operation_id=operation_id,
                    payload_hash=binding.payload_hash or "",
                    now=now,
                )
                _revoke_user_sessions(connection, selected_user, revoked_at=now)
        except Exception:
            with suppress(CredentialError, SecretProvisioningError):
                self._totp_provisioner.delete(secret_reference)
            raise
        factor = self.get_factor(selected_user, factor_id)
        if factor is None:  # pragma: no cover - committed invariant
            raise AuthenticatorManagementError("new TOTP factor was not persisted")
        return factor

    def add_passkey(
        self,
        user_id: str,
        label: str,
        credential: WebAuthnCredential,
        operation_id: str,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
    ) -> FactorMetadata:
        selected_user = canonical_user_id(user_id)
        selected_label = _label(label)
        if credential.user_id != selected_user or credential.disabled:
            raise ValueError("an active user-owned passkey credential is required")
        binding = self.binding_for_add_passkey(
            selected_user, selected_label, credential, operation_id
        )
        factor_id = _new_factor_id()
        with self.database.transaction() as connection:
            actor_factor_id = self._consume_proof(
                connection,
                confirmation,
                user_id=selected_user,
                binding=binding,
                now=now,
            )
            connection.execute(
                """
                INSERT INTO auth_credentials(
                    credential_id, user_id, kind, public_material, sign_count,
                    enrolled_at, backup_eligible, backup_state, user_handle, factor_label,
                    transports_json, discoverable
                ) VALUES (?, ?, 'webauthn', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    credential.credential_id,
                    selected_user,
                    credential.public_key,
                    credential.sign_count,
                    now,
                    int(credential.device_type == "multi_device"),
                    int(credential.backed_up),
                    credential.user_handle,
                    selected_label,
                    json.dumps(list(credential.transports), separators=(",", ":")),
                    int(credential.discoverable),
                ),
            )
            self._insert_factor(
                connection,
                factor_id=factor_id,
                credential_id=credential.credential_id,
                user_id=selected_user,
                kind="webauthn",
                label=selected_label,
                action="added",
                actor_factor_id=actor_factor_id,
                operation_id=operation_id,
                payload_hash=binding.payload_hash or "",
                now=now,
            )
            _revoke_user_sessions(connection, selected_user, revoked_at=now)
        factor = self.get_factor(selected_user, factor_id)
        if factor is None:  # pragma: no cover - committed invariant
            raise AuthenticatorManagementError("new passkey factor was not persisted")
        return factor

    def rename_factor(
        self,
        user_id: str,
        factor_id: str,
        label: str,
        operation_id: str,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
    ) -> FactorMetadata:
        selected_user = canonical_user_id(user_id)
        selected_factor = _factor_id(factor_id)
        selected_label = _label(label)
        binding = self.binding_for_rename(
            selected_user, selected_factor, selected_label, operation_id
        )
        with self.database.transaction() as connection:
            actor_factor_id = self._consume_proof(
                connection,
                confirmation,
                user_id=selected_user,
                binding=binding,
                now=now,
            )
            row = self._active_factor_for_update(connection, selected_user, selected_factor)
            if str(row["kind"]) == "password":
                raise FactorUnavailable("password factors use the password-management boundary")
            event_id = self._insert_event(
                connection,
                factor_id=selected_factor,
                user_id=selected_user,
                action="renamed",
                actor_factor_id=actor_factor_id,
                operation_id=operation_id,
                payload_hash=binding.payload_hash or "",
                now=now,
                details={"label": selected_label},
            )
            connection.execute(
                """
                UPDATE auth_factors
                SET label = ?, updated_at = ?, state_audit_ref = ?
                WHERE factor_id = ? AND state = 'active'
                """,
                (selected_label, now, event_id, selected_factor),
            )
            connection.execute(
                "UPDATE auth_credentials SET factor_label = ? WHERE credential_id = ?",
                (selected_label, row["credential_id"]),
            )
            _revoke_user_sessions(connection, selected_user, revoked_at=now)
        factor = self.get_factor(selected_user, selected_factor)
        if factor is None:  # pragma: no cover
            raise AuthenticatorManagementError("renamed factor disappeared")
        return factor

    def revoke_factor(
        self,
        user_id: str,
        factor_id: str,
        operation_id: str,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
        compromised: bool = False,
    ) -> FactorMetadata:
        selected_user = canonical_user_id(user_id)
        selected_factor = _factor_id(factor_id)
        binding = self.binding_for_revoke(
            selected_user,
            selected_factor,
            operation_id,
            compromised=compromised,
        )
        state: FactorState = "compromised" if compromised else "revoked"
        with self.database.transaction() as connection:
            row = self._active_factor_for_update(connection, selected_user, selected_factor)
            if str(row["kind"]) == "password":
                raise FactorUnavailable("password factors use the password-management boundary")
            self._enforce_removal_guard(connection, selected_user, selected_factor)
            actor_factor_id = self._consume_proof(
                connection,
                confirmation,
                user_id=selected_user,
                binding=binding,
                now=now,
            )
            event_id = self._insert_event(
                connection,
                factor_id=selected_factor,
                user_id=selected_user,
                action="compromised" if compromised else "revoked",
                actor_factor_id=actor_factor_id,
                operation_id=operation_id,
                payload_hash=binding.payload_hash or "",
                now=now,
                details={"state": state},
            )
            connection.execute(
                """
                UPDATE auth_factors
                SET state = ?, updated_at = ?, revoked_at = ?, compromised_at = ?,
                    state_audit_ref = ?
                WHERE factor_id = ? AND state = 'active'
                """,
                (
                    state,
                    now,
                    now,
                    now if compromised else None,
                    event_id,
                    selected_factor,
                ),
            )
            connection.execute(
                "UPDATE auth_credentials SET disabled_at = ? WHERE credential_id = ?",
                (now, row["credential_id"]),
            )
            _revoke_user_sessions(connection, selected_user, revoked_at=now)
        factor = self.get_factor(selected_user, selected_factor)
        if factor is None:  # pragma: no cover
            raise AuthenticatorManagementError("revoked factor disappeared")
        return factor

    def replace_totp(
        self,
        user_id: str,
        factor_id: str,
        label: str,
        operation_id: str,
        confirmation: VerifiedTotp | VerifiedWebAuthn,
        *,
        now: int,
    ) -> FactorMetadata:
        selected_user = canonical_user_id(user_id)
        selected_factor = _factor_id(factor_id)
        selected_label = _label(label)
        binding = self.binding_for_replace_totp(
            selected_user, selected_factor, selected_label, operation_id
        )
        self._validate_proof_envelope(confirmation, user_id=selected_user, binding=binding, now=now)
        new_factor_id = _new_factor_id()
        new_credential_id = _new_credential_id("totp")
        secret_reference = self._totp_provisioner.create(new_factor_id)
        try:
            SecretReference.parse(secret_reference)
            with self.database.transaction() as connection:
                old = self._active_factor_for_update(connection, selected_user, selected_factor)
                if str(old["kind"]) != "totp":
                    raise FactorUnavailable("replacement target is not an active TOTP factor")
                actor_factor_id = self._consume_proof(
                    connection,
                    confirmation,
                    user_id=selected_user,
                    binding=binding,
                    now=now,
                )
                connection.execute(
                    """
                    INSERT INTO auth_credentials(
                        credential_id, user_id, kind, secret_reference, enrolled_at, factor_label
                    ) VALUES (?, ?, 'totp', ?, ?, ?)
                    """,
                    (new_credential_id, selected_user, secret_reference, now, selected_label),
                )
                self._insert_factor(
                    connection,
                    factor_id=new_factor_id,
                    credential_id=new_credential_id,
                    user_id=selected_user,
                    kind="totp",
                    label=selected_label,
                    action="added",
                    actor_factor_id=actor_factor_id,
                    operation_id=operation_id,
                    payload_hash=binding.payload_hash or "",
                    now=now,
                )
                event_id = self._insert_event(
                    connection,
                    factor_id=selected_factor,
                    user_id=selected_user,
                    action="replaced",
                    actor_factor_id=actor_factor_id,
                    operation_id=operation_id,
                    payload_hash=binding.payload_hash or "",
                    now=now,
                    details={"replacement_factor_id": new_factor_id},
                )
                connection.execute(
                    """
                    UPDATE auth_factors
                    SET state = 'revoked', updated_at = ?, revoked_at = ?, state_audit_ref = ?
                    WHERE factor_id = ? AND state = 'active'
                    """,
                    (now, now, event_id, selected_factor),
                )
                connection.execute(
                    "UPDATE auth_credentials SET disabled_at = ? WHERE credential_id = ?",
                    (now, old["credential_id"]),
                )
                _revoke_user_sessions(connection, selected_user, revoked_at=now)
        except Exception:
            with suppress(CredentialError, SecretProvisioningError):
                self._totp_provisioner.delete(secret_reference)
            raise
        factor = self.get_factor(selected_user, new_factor_id)
        if factor is None:  # pragma: no cover
            raise AuthenticatorManagementError("replacement factor was not persisted")
        return factor

    def recover_totp(
        self,
        user_id: str,
        label: str,
        operation_id: str,
        *,
        now: int,
    ) -> FactorMetadata:
        """Use an explicitly enabled operator recovery path for a factorless account."""

        selected_user = canonical_user_id(user_id)
        selected_label = _label(label)
        selected_operation = _bounded_identifier(
            operation_id, name="factor operation ID", maximum=128
        )
        if not self.recovery_policy.allow_bootstrap_without_factor:
            raise LastAuthenticatorRemovalDenied("factorless recovery is not explicitly enabled")
        factor_id = _new_factor_id()
        credential_id = _new_credential_id("totp")
        payload_hash = _operation_hash(
            selected_user,
            "recovery_bootstrap",
            selected_operation,
            {"kind": "totp", "label": selected_label},
        )
        secret_reference = self._totp_provisioner.create(factor_id)
        try:
            SecretReference.parse(secret_reference)
            with self.database.transaction() as connection:
                active = int(
                    connection.execute(
                        """
                        SELECT count(*)
                        FROM auth_factors AS f
                        JOIN auth_credentials AS c ON c.credential_id = f.credential_id
                        WHERE f.user_id = ? AND f.state = 'active'
                          AND f.kind IN ('totp', 'webauthn')
                          AND c.user_id = f.user_id AND c.kind = f.kind
                          AND c.disabled_at IS NULL
                        """,
                        (selected_user,),
                    ).fetchone()[0]
                )
                if active:
                    raise LastAuthenticatorRemovalDenied(
                        "factorless recovery is unavailable while an authenticator is active"
                    )
                _ensure_auth_user(connection, selected_user, created_at=now)
                connection.execute(
                    """
                    INSERT INTO auth_credentials(
                        credential_id, user_id, kind, secret_reference, enrolled_at, factor_label
                    ) VALUES (?, ?, 'totp', ?, ?, ?)
                    """,
                    (credential_id, selected_user, secret_reference, now, selected_label),
                )
                self._insert_factor(
                    connection,
                    factor_id=factor_id,
                    credential_id=credential_id,
                    user_id=selected_user,
                    kind="totp",
                    label=selected_label,
                    action="recovered",
                    actor_factor_id=None,
                    operation_id=selected_operation,
                    payload_hash=payload_hash,
                    now=now,
                )
                _revoke_user_sessions(connection, selected_user, revoked_at=now)
        except Exception:
            with suppress(CredentialError, SecretProvisioningError):
                self._totp_provisioner.delete(secret_reference)
            raise
        factor = self.get_factor(selected_user, factor_id)
        if factor is None:  # pragma: no cover
            raise AuthenticatorManagementError("recovery factor was not persisted")
        return factor

    def _binding(
        self,
        action: ManagementAction,
        user_id: str,
        operation_id: str,
        payload: Mapping[str, object],
    ) -> ActionBinding:
        selected_user = canonical_user_id(user_id)
        selected_operation = _bounded_identifier(
            operation_id, name="factor operation ID", maximum=128
        )
        payload_hash = _operation_hash(selected_user, action, selected_operation, payload)
        return ActionBinding(action, selected_operation, 1, payload_hash)

    def _validate_proof_envelope(
        self,
        proof: VerifiedTotp | VerifiedWebAuthn,
        *,
        user_id: str,
        binding: ActionBinding,
        now: int,
    ) -> None:
        if proof.user_id != user_id or proof.binding != binding:
            raise InvalidFactorProof("factor proof binding does not match this operation")
        if (
            proof.http_method != "POST"
            or proof.session_id is None
            or proof.verified_at is None
            or proof.expires_at is None
            or proof.verified_at > now
            or now >= proof.expires_at
            or proof.expires_at - proof.verified_at > self.maximum_proof_lifetime
        ):
            raise InvalidFactorProof("factor proof is not fresh or has an invalid context")
        domain, claims = self._proof_claims(proof)
        if not self._capabilities.verify(proof.capability, domain=domain, claims=claims):
            raise InvalidFactorProof("factor proof capability is invalid")

    def _consume_proof(
        self,
        connection: object,
        proof: VerifiedTotp | VerifiedWebAuthn,
        *,
        user_id: str,
        binding: ActionBinding,
        now: int,
    ) -> str:
        self._validate_proof_envelope(proof, user_id=user_id, binding=binding, now=now)
        assert proof.session_id is not None
        try:
            connection.execute(  # type: ignore[attr-defined]
                """
                INSERT INTO auth_proof_consumptions(kind, use_id, purpose, consumed_at)
                VALUES (?, ?, 'mutation', ?)
                """,
                ("totp" if isinstance(proof, VerifiedTotp) else "webauthn", proof.use_id, now),
            )
        except IntegrityError as exc:
            raise FactorProofReplay("factor proof was already consumed") from exc
        try:
            _require_active_session(
                connection,
                proof.session_id,
                user_id=user_id,
                now=now,
                idle_timeout=self.session_idle_timeout,
            )
        except Exception as exc:
            raise InvalidFactorProof("factor proof session is unavailable") from exc
        actor = connection.execute(  # type: ignore[attr-defined]
            """
            SELECT f.factor_id, f.state, c.disabled_at
            FROM auth_factors AS f
            JOIN auth_credentials AS c ON c.credential_id = f.credential_id
            WHERE f.user_id = ? AND f.credential_id = ?
            """,
            (user_id, proof.credential_id),
        ).fetchone()
        if actor is None or actor["state"] != "active" or actor["disabled_at"] is not None:
            raise InvalidFactorProof("confirming factor is unavailable")

        if isinstance(proof, VerifiedTotp):
            updated = connection.execute(  # type: ignore[attr-defined]
                """
                UPDATE auth_credentials SET last_used_at = ?
                WHERE credential_id = ? AND user_id = ? AND kind = 'totp'
                  AND disabled_at IS NULL
                """,
                (now, proof.credential_id, user_id),
            ).rowcount
            if updated != 1:
                raise InvalidFactorProof("confirming TOTP factor is unavailable")
            for scope in proof.attempt_reservation.scope_keys:
                connection.execute(  # type: ignore[attr-defined]
                    """
                    DELETE FROM auth_attempts
                    WHERE scope_key = ? AND last_attempt_id = ?
                    """,
                    (scope, proof.attempt_reservation.attempt_id),
                )
        else:
            self._consume_webauthn(connection, proof, now=now)

        connection.execute(  # type: ignore[attr-defined]
            """
            UPDATE auth_factors
            SET last_used_at = ?, updated_at = max(updated_at, ?)
            WHERE factor_id = ?
            """,
            (now, now, actor["factor_id"]),
        )
        return str(actor["factor_id"])

    def _proof_claims(
        self, proof: VerifiedTotp | VerifiedWebAuthn
    ) -> tuple[str, dict[str, object]]:
        if isinstance(proof, VerifiedTotp):
            valid_rate_keys = {
                totp_rate_limit_key(proof.user_id),
                totp_factor_rate_limit_key(proof.user_id, proof.credential_id),
            }
            if proof.rate_limit_key not in valid_rate_keys:
                raise InvalidFactorProof("TOTP factor rate-limit binding is invalid")
            return (
                TOTP_PROOF_DOMAIN,
                totp_proof_claims(
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
                    verified_at=proof.verified_at,
                    expires_at=proof.expires_at,
                ),
            )
        return (
            WEBAUTHN_PROOF_DOMAIN,
            webauthn_proof_claims(
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
                verified_at=proof.verified_at,
                expires_at=proof.expires_at,
            ),
        )

    @staticmethod
    def _consume_webauthn(connection: object, proof: VerifiedWebAuthn, *, now: int) -> None:
        if proof.expected_counter < 0 or not (
            proof.expected_counter == proof.new_counter == 0
            or proof.new_counter > proof.expected_counter
        ):
            raise InvalidFactorProof("WebAuthn counter transition is invalid")
        if (
            proof.expected_backup_eligible != proof.new_backup_eligible
            or proof.device_type
            != ("multi_device" if proof.new_backup_eligible else "single_device")
            or (not proof.new_backup_eligible and proof.new_backed_up)
            or (proof.previous_backed_up and not proof.new_backed_up)
        ):
            raise InvalidFactorProof("WebAuthn backup transition is invalid")
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
        consumed = connection.execute(  # type: ignore[attr-defined]
            """
            UPDATE auth_factor_challenges SET consumed_at = ?
            WHERE challenge_id = ? AND user_id = ? AND operation_id = ?
              AND payload_hash = ? AND session_id = ? AND consumed_at IS NULL
              AND invalidated_at IS NULL AND expires_at > ? AND created_at <= ?
            """,
            (
                now,
                proof.challenge_id,
                proof.user_id,
                proof.binding.request_id,
                proof.binding.payload_hash,
                proof.session_id,
                now,
                now,
            ),
        ).rowcount
        if updated != 1 or consumed != 1:
            raise InvalidFactorProof("WebAuthn factor proof is stale or unavailable")

    def _active_factor_for_update(self, connection: object, user_id: str, factor_id: str) -> Any:
        row = connection.execute(  # type: ignore[attr-defined]
            "SELECT * FROM auth_factors WHERE factor_id = ? AND user_id = ? AND state = 'active'",
            (factor_id, user_id),
        ).fetchone()
        if row is None:
            raise FactorUnavailable("authenticator factor is unavailable")
        return row

    def _enforce_removal_guard(self, connection: object, user_id: str, factor_id: str) -> None:
        remaining = int(
            connection.execute(  # type: ignore[attr-defined]
                """
                SELECT count(*)
                FROM auth_factors AS f
                JOIN auth_credentials AS c ON c.credential_id = f.credential_id
                WHERE f.user_id = ? AND f.state = 'active' AND f.factor_id <> ?
                  AND f.kind IN ('totp', 'webauthn')
                  AND c.user_id = f.user_id AND c.kind = f.kind
                  AND c.disabled_at IS NULL
                """,
                (user_id, factor_id),
            ).fetchone()[0]
        )
        is_admin = (
            connection.execute(  # type: ignore[attr-defined]
                """
                SELECT 1 FROM production_users
                WHERE user_id = ? AND state IN ('staged', 'active')
                """,
                (user_id,),
            ).fetchone()
            is not None
        )
        if remaining == 0 and (
            not self.recovery_policy.allow_last_factor_revocation
            or (is_admin and not self.recovery_policy.allow_last_admin_factor_revocation)
        ):
            raise LastAuthenticatorRemovalDenied(
                "the last usable authenticator cannot be revoked without explicit recovery policy"
            )

    def _insert_factor(
        self,
        connection: object,
        *,
        factor_id: str,
        credential_id: str,
        user_id: str,
        kind: FactorKind,
        label: str,
        action: str,
        actor_factor_id: str | None,
        operation_id: str,
        payload_hash: str,
        now: int,
    ) -> None:
        event_id = _new_event_id()
        connection.execute(  # type: ignore[attr-defined]
            """
            INSERT INTO auth_factors(
                factor_id, credential_id, user_id, kind, label, state,
                created_at, updated_at, created_audit_ref
            ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (factor_id, credential_id, user_id, kind, label, now, now, event_id),
        )
        connection.execute(  # type: ignore[attr-defined]
            """
            INSERT INTO auth_factor_events(
                event_id, factor_id, user_id, action, actor_factor_id,
                operation_id, payload_hash, created_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                factor_id,
                user_id,
                action,
                actor_factor_id,
                operation_id,
                payload_hash,
                now,
                json.dumps({"kind": kind, "label": label}, sort_keys=True, separators=(",", ":")),
            ),
        )

    @staticmethod
    def _insert_event(
        connection: object,
        *,
        factor_id: str,
        user_id: str,
        action: str,
        actor_factor_id: str,
        operation_id: str,
        payload_hash: str,
        now: int,
        details: Mapping[str, object],
    ) -> str:
        event_id = _new_event_id()
        connection.execute(  # type: ignore[attr-defined]
            """
            INSERT INTO auth_factor_events(
                event_id, factor_id, user_id, action, actor_factor_id,
                operation_id, payload_hash, created_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                factor_id,
                user_id,
                action,
                actor_factor_id,
                operation_id,
                payload_hash,
                now,
                json.dumps(dict(details), sort_keys=True, separators=(",", ":")),
            ),
        )
        return event_id


def _metadata(row: Any) -> FactorMetadata:
    kind = str(row["kind"])
    transports: tuple[str, ...] = ()
    device_type: Literal["single_device", "multi_device"] | None = None
    backed_up: bool | None = None
    if kind == "webauthn":
        try:
            stored_transports = json.loads(str(row["transports_json"]))
        except (TypeError, ValueError):
            raise AuthenticatorManagementError("stored passkey metadata is invalid") from None
        if not isinstance(stored_transports, list) or not all(
            isinstance(transport, str) for transport in stored_transports
        ):
            raise AuthenticatorManagementError("stored passkey metadata is invalid")
        transports = tuple(stored_transports)
        device_type = "multi_device" if bool(row["backup_eligible"]) else "single_device"
        backed_up = bool(row["backup_state"])
    return FactorMetadata(
        factor_id=str(row["factor_id"]),
        credential_id=str(row["credential_id"]),
        user_id=str(row["user_id"]),
        kind=cast(FactorKind, kind),
        label=str(row["label"]),
        state=cast(FactorState, str(row["state"])),
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
        last_used_at=(int(row["last_used_at"]) if row["last_used_at"] is not None else None),
        revoked_at=(int(row["revoked_at"]) if row["revoked_at"] is not None else None),
        compromised_at=(int(row["compromised_at"]) if row["compromised_at"] is not None else None),
        created_audit_ref=str(row["created_audit_ref"]),
        state_audit_ref=(
            str(row["state_audit_ref"]) if row["state_audit_ref"] is not None else None
        ),
        transports=transports,
        discoverable=bool(row["discoverable"]) if kind == "webauthn" else False,
        device_type=device_type,
        backed_up=backed_up,
    )


def _operation_hash(
    user_id: str,
    action: str,
    operation_id: str,
    payload: Mapping[str, object],
) -> str:
    encoded = json.dumps(
        {
            "action": action,
            "operation_id": operation_id,
            "payload": dict(payload),
            "user_id": user_id,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _label(label: str) -> str:
    normalized = " ".join(label.split())
    if not normalized or len(normalized.encode("utf-8")) > 64:
        raise ValueError("factor label must contain at most 64 bytes")
    return normalized


def _factor_id(factor_id: str) -> str:
    selected = _bounded_identifier(factor_id, name="factor ID", maximum=64)
    if len(selected) < 20 or not selected.startswith("fac_"):
        raise ValueError("factor ID is invalid")
    return selected


def _new_factor_id() -> str:
    return f"fac_{secrets.token_urlsafe(24)}"


def _new_credential_id(kind: str) -> str:
    return f"{kind}_{secrets.token_urlsafe(24)}"


def _new_event_id() -> str:
    return f"evt_{secrets.token_urlsafe(24)}"
