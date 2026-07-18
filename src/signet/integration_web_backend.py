"""Authenticated, staged-only integration review orchestration.

This module can discover and review immutable MCP tool definitions, but it has
no downstream client and no dispatch operation.  A final effect profile is
appended only in the same transaction that consumes a fresh TOTP or WebAuthn
proof bound to the exact plugin, connector, server, tool, schema, and evidence
snapshot shown to the reviewer.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, cast

from signet.auth import (
    TOTP_PROOF_DOMAIN,
    WEBAUTHN_PROOF_DOMAIN,
    ActionBinding,
    AuthenticationRateLimited,
    InvalidCredentials,
    InvalidSession,
    ProofCapability,
    SessionManager,
    SessionPrincipal,
    _require_active_session,
    canonical_user_id,
    totp_proof_claims,
    webauthn_proof_claims,
)
from signet.canonical import canonical_json, sha256_hex
from signet.db import Database, IntegrityError
from signet.effects import (
    EffectEvidence,
    EffectProfile,
    EvidenceSource,
    evidence_bundle_digest,
    evidence_disagreements,
    recommend_policy,
)
from signet.integration_store import (
    MAX_ACTIVE_PLUGIN_IDS,
    MAX_CONNECTOR_ALIASES,
    MAX_RETAINED_TOOL_NAMES_PER_ALIAS,
    ConnectorRecord,
    CurrentToolRecord,
    EffectReviewRecord,
    EffectReviewTarget,
    IntegrationStoreError,
    PluginIdentity,
    SQLiteIntegrationStore,
)
from signet.totp import InvalidTotp, TotpError, TotpVerifier, VerifiedTotp
from signet.web import (
    EffectReviewResult,
    EffectReviewView,
    IntegrationConnectorSummary,
    IntegrationPasskeyOptions,
    IntegrationPluginSummary,
    IntegrationsPage,
    IntegrationToolDetail,
    IntegrationToolSummary,
    WebConflict,
    WebForbidden,
    WebRateLimited,
    WebUnauthorized,
)
from signet.webauthn import (
    AssertionInput,
    VerifiedWebAuthn,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
    WebAuthnChallengeRateLimited,
    WebAuthnChallengeUnavailable,
    WebAuthnCredentialUnavailable,
    WebAuthnError,
    WebAuthnRepository,
)

_REVIEW_DOMAIN = "signet.effect-mapping-review.v1"
_OPAQUE_DOMAIN = b"signet.integration-tool-id.v1\x00"
_PREAUTH_PREFIX = "preauth:"
_MAX_PLUGIN_SUMMARIES = MAX_ACTIVE_PLUGIN_IDS + MAX_CONNECTOR_ALIASES
_MAX_TOOLS = MAX_RETAINED_TOOL_NAMES_PER_ALIAS


@dataclass(frozen=True, slots=True)
class _ToolLocation:
    connector: ConnectorRecord
    tool_name: str


@dataclass(frozen=True, slots=True)
class _EffectDraft:
    challenge_id: str
    opaque_id: str
    alias: str
    tool_name: str
    target_snapshot_digest: str
    effect_mapping_key: str
    effect_review_digest: str
    profile: EffectProfile
    user_id: str
    session_id: str
    created_at: int
    expires_at: int


class SQLiteIntegrationWebBackend:
    """Render staged integrations and atomically append authenticated reviews."""

    def __init__(
        self,
        database: Database,
        *,
        authorized_user_id: str,
        sessions: SessionManager,
        store: SQLiteIntegrationStore,
        totp: TotpVerifier,
        capabilities: ProofCapability,
        webauthn_repository: WebAuthnRepository,
        webauthn_issuer: WebAuthnChallengeIssuer,
        webauthn_verifier: WebAuthnAssertionVerifier,
        opaque_id_key: bytes,
        clock: Callable[[], int] | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        try:
            selected_user = canonical_user_id(authorized_user_id)
        except (InvalidCredentials, TypeError, ValueError):
            raise ValueError("authorized integration reviewer is invalid") from None
        if len(f"web:{selected_user}".encode()) > 256:
            raise ValueError("authorized integration reviewer is too long for audit history")
        if store.database is not database:
            raise ValueError("integration store must share the authentication database")
        if not isinstance(opaque_id_key, bytes) or len(opaque_id_key) < 32:
            raise ValueError("integration opaque-ID key must contain at least 32 bytes")
        if clock is not None and not callable(clock):
            raise ValueError("integration review clock is invalid")
        self._database = database
        self._authorized_user_id = selected_user
        self._idle_timeout = sessions.idle_timeout
        self._store = store
        self._totp = totp
        self._capabilities = capabilities
        self._webauthn_repository = webauthn_repository
        self._webauthn_issuer = webauthn_issuer
        self._webauthn_verifier = webauthn_verifier
        self._opaque_id_key = bytes(opaque_id_key)
        self._clock = clock
        self._fault_injector = fault_injector

    def list_integrations(
        self,
        principal: SessionPrincipal,
        *,
        now: int,
    ) -> IntegrationsPage:
        self._require_principal(principal)
        self._validate_now(now)
        plugins = self._store.list_plugins(limit=MAX_ACTIVE_PLUGIN_IDS + 1)
        connectors = self._store.list_connectors(limit=MAX_CONNECTOR_ALIASES + 1)
        if len(plugins) > MAX_ACTIVE_PLUGIN_IDS or len(connectors) > MAX_CONNECTOR_ALIASES:
            raise IntegrationStoreError("integration workspace exceeds its durable bounds")
        generations = {record.plugin: record.disabled_at is None for record in plugins}
        for connector in connectors:
            generations.setdefault(connector.plugin, False)
        if len(generations) > _MAX_PLUGIN_SUMMARIES:
            raise IntegrationStoreError("integration workspace exceeds its generation bound")
        summaries: list[IntegrationPluginSummary] = []
        for identity, enabled in sorted(
            generations.items(),
            key=lambda item: (
                item[0].plugin_id,
                item[0].plugin_version,
                item[0].manifest_sha256,
            ),
        ):
            manifest = self._manifest(identity)
            connector_summaries = tuple(
                self._connector_summary(connector, manifest)
                for connector in connectors
                if connector.plugin == identity
            )
            summaries.append(
                IntegrationPluginSummary(
                    plugin_id=identity.plugin_id,
                    plugin_version=identity.plugin_version,
                    manifest_sha256=identity.manifest_sha256,
                    display_name=_manifest_text(manifest, "display_name"),
                    enabled=enabled,
                    connectors=connector_summaries,
                )
            )
        return IntegrationsPage(tuple(summaries))

    def get_integration_tool(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        *,
        now: int,
    ) -> IntegrationToolDetail:
        self._require_principal(principal)
        self._validate_now(now)
        location = self._resolve_opaque_id(opaque_id)
        if location is None:
            raise WebConflict("integration tool is stale or unavailable")
        connector = location.connector
        manifest = self._manifest(connector.plugin)
        mapping = _mapping_for(manifest, connector.connector_id, location.tool_name)
        connector_template = _connector_template(manifest, connector.connector_id)
        detail = self._store.tool_detail(connector.alias, location.tool_name)
        if detail is None or detail.definition is None or detail.definition_run_id is None:
            raise WebConflict("integration tool definition is unavailable")
        evidence = _parse_evidence(detail.evidence)
        bundle_digest = evidence_bundle_digest(evidence)
        discovery = self._store.discovery_detail(
            connector.alias,
            run_id=detail.definition_run_id,
            max_tools=_MAX_TOOLS,
        )
        if (
            discovery is None
            or discovery.discovery.status != "succeeded"
            or discovery.discovery.server_identity_digest is None
            or discovery.discovery.source not in {"fixture", "live"}
        ):
            raise WebConflict("integration discovery identity is unavailable")
        target = self._store.current_review_target(connector.alias, location.tool_name)
        reviewable = (
            mapping is not None
            and detail.current.present
            and connector.is_active
            and target is not None
        )
        if reviewable:
            assert target is not None
            if not hmac.compare_digest(target.evidence_bundle_digest, bundle_digest):
                raise WebConflict("integration evidence changed after discovery")
            snapshot_digest = target.snapshot_digest
        else:
            snapshot_digest = _unreviewable_snapshot(
                connector=connector,
                tool_name=location.tool_name,
                schema_digest=detail.current.schema_digest,
                run_id=detail.current.run_id,
                evidence_digest=bundle_digest,
                present=detail.current.present,
            )
        reviews = self._review_views(connector.alias, location.tool_name)
        valid = self._store.current_valid_review(connector.alias, location.tool_name)
        return IntegrationToolDetail(
            opaque_id=opaque_id,
            plugin_id=connector.plugin.plugin_id,
            plugin_version=connector.plugin.plugin_version,
            plugin_display_name=_manifest_text(manifest, "display_name"),
            manifest_sha256=connector.plugin.manifest_sha256,
            connector_id=connector.connector_id,
            connector_alias=connector.alias,
            connector_display_name=_manifest_text(connector_template, "display_name"),
            connector_config_digest=connector.config_digest,
            discovery_status=discovery.discovery.status,
            discovery_source=discovery.discovery.source,
            discovered_at=discovery.discovery.discovered_at,
            server_identity_digest=discovery.discovery.server_identity_digest,
            tool_name=location.tool_name,
            display_label=(
                _manifest_text(mapping, "display_label")
                if mapping is not None
                else f"{location.tool_name} (unmapped)"
            ),
            action_id=(_manifest_text(mapping, "action_id") if mapping is not None else "unmapped"),
            schema_digest=detail.current.schema_digest,
            target_snapshot_digest=snapshot_digest,
            evidence_bundle_digest=bundle_digest,
            canonical_tool_json=canonical_json(detail.definition).decode("utf-8"),
            sensitive_json_paths=(
                _string_tuple(mapping, "sensitive_json_paths") if mapping is not None else ()
            ),
            safe_result_fields=(
                _string_tuple(mapping, "safe_result_fields") if mapping is not None else ()
            ),
            evidence=evidence,
            disagreements=evidence_disagreements(evidence),
            reviews=tuple(
                EffectReviewView(
                    review_id=item.review_id,
                    profile=item.profile,
                    recommended_mode=item.recommended_mode,
                    actor=item.actor,
                    auth_kind=item.auth_kind,
                    reviewed_at=item.reviewed_at,
                    current=(valid is not None and item.review_id == valid.review_id),
                )
                for item in reviews
            ),
            reviewable=reviewable,
            unavailable_reason=(
                None
                if reviewable
                else _unavailable_reason(
                    mapping=mapping,
                    present=detail.current.present,
                    connector_active=connector.is_active,
                )
            ),
        )

    def complete_totp_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        profile: EffectProfile,
        totp_proof: str,
        *,
        expected_snapshot_digest: str,
        now: int,
        credential_id: str | None = None,
    ) -> EffectReviewResult:
        self._require_principal(principal)
        self._validate_now(now)
        target, binding = self._require_review_target(
            opaque_id,
            profile,
            expected_snapshot_digest=expected_snapshot_digest,
        )
        try:
            proof = self._totp.verify(
                principal.user_id,
                totp_proof,
                binding=binding,
                source_id=f"integration-review:{principal.session_id}",
                session_id=principal.session_id,
                http_method="POST",
                now=now,
                credential_id=credential_id,
            )
        except AuthenticationRateLimited as exc:
            raise WebRateLimited(str(exc)) from None
        except (InvalidTotp, TotpError, InvalidCredentials, ValueError) as exc:
            raise WebForbidden("TOTP confirmation is invalid") from exc
        try:
            review_id = self._commit_totp_review(
                principal,
                opaque_id=opaque_id,
                profile=profile,
                expected_target=target,
                binding=binding,
                proof=proof,
                now=now,
            )
        except IntegrityError as exc:
            raise WebConflict("confirmation was already used") from exc
        except IntegrationStoreError as exc:
            raise WebConflict("integration changed after review") from exc
        # The SQLite limiter was settled inside the review transaction.  This
        # also clears an injected in-memory limiter without turning cleanup
        # failure after commit into an ambiguous review failure.
        with suppress(Exception):
            self._totp.record_consumed_success(proof, now=now)
        return EffectReviewResult(
            opaque_id=opaque_id,
            review_id=review_id,
            recommended_mode=recommend_policy(profile),
        )

    def begin_passkey_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        profile: EffectProfile,
        *,
        expected_snapshot_digest: str,
        http_method: str,
        now: int,
    ) -> IntegrationPasskeyOptions:
        self._require_principal(principal)
        self._validate_now(now)
        target, binding = self._require_review_target(
            opaque_id,
            profile,
            expected_snapshot_digest=expected_snapshot_digest,
        )
        self._prune_effect_ephemera(now=now)
        try:
            issued = self._webauthn_issuer.issue(
                principal.user_id,
                binding,
                session_id=principal.session_id,
                http_method=http_method,
                now=now,
            )
        except WebAuthnChallengeRateLimited as exc:
            raise WebRateLimited(str(exc)) from None
        except (WebAuthnCredentialUnavailable, WebAuthnError, ValueError) as exc:
            raise WebForbidden("passkey confirmation is unavailable") from exc
        try:
            with self._database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO connector_effect_review_drafts(
                        challenge_id, opaque_id, alias, tool_name,
                        target_snapshot_digest, effect_mapping_key,
                        effect_review_digest, mutation, external_communication,
                        code_execution, privilege_change, open_world, idempotent,
                        user_id, session_id, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        issued.challenge_id,
                        opaque_id,
                        target.alias,
                        target.tool_name,
                        target.snapshot_digest,
                        target.mapping_key,
                        cast(str, binding.effect_review_digest),
                        profile.mutation.value,
                        profile.external_communication.value,
                        profile.code_execution.value,
                        profile.privilege_change.value,
                        profile.open_world.value,
                        profile.idempotent.value,
                        principal.user_id,
                        principal.session_id,
                        now,
                        issued.expires_at,
                    ),
                )
        except Exception:
            self._webauthn_repository.invalidate_challenge(issued.challenge_id, now=now)
            raise WebConflict("passkey effect review could not be durably staged") from None
        return IntegrationPasskeyOptions(
            challenge_id=issued.challenge_id,
            public_key=_strict_json_object(issued.options_json),
            opaque_id=opaque_id,
            target_snapshot_digest=target.snapshot_digest,
            recommended_mode=recommend_policy(profile),
        )

    def complete_passkey_effect_review(
        self,
        principal: SessionPrincipal,
        opaque_id: str,
        challenge_id: str,
        assertion: Mapping[str, Any],
        *,
        expected_snapshot_digest: str,
        http_method: str,
        now: int,
    ) -> EffectReviewResult:
        self._require_principal(principal)
        self._validate_now(now)
        draft = self._find_draft(challenge_id)
        if not self._draft_matches(
            draft,
            principal=principal,
            opaque_id=opaque_id,
            expected_snapshot_digest=expected_snapshot_digest,
            now=now,
        ):
            raise WebConflict("passkey effect review is stale or unavailable")
        assert draft is not None
        binding = ActionBinding(
            "review_effect_mapping",
            effect_mapping_key=draft.effect_mapping_key,
            effect_review_digest=draft.effect_review_digest,
        )
        try:
            proof = self._webauthn_verifier.verify(
                cast(AssertionInput, assertion),
                challenge_id=challenge_id,
                user_id=principal.user_id,
                binding=binding,
                session_id=principal.session_id,
                http_method=http_method,
                now=now,
            )
        except WebAuthnChallengeUnavailable as exc:
            raise WebConflict("passkey effect review is stale or unavailable") from exc
        except WebAuthnError as exc:
            raise WebForbidden("passkey confirmation is invalid") from exc
        try:
            review_id = self._commit_passkey_review(
                principal,
                draft=draft,
                binding=binding,
                proof=proof,
                now=now,
            )
        except IntegrityError as exc:
            raise WebConflict("confirmation was already used") from exc
        except IntegrationStoreError as exc:
            raise WebConflict("integration changed after review") from exc
        return EffectReviewResult(
            opaque_id=opaque_id,
            review_id=review_id,
            recommended_mode=recommend_policy(draft.profile),
        )

    def _connector_summary(
        self,
        connector: ConnectorRecord,
        manifest: Mapping[str, Any],
    ) -> IntegrationConnectorSummary:
        template = _connector_template(manifest, connector.connector_id)
        discovery = self._store.discovery_detail(connector.alias, max_tools=_MAX_TOOLS)
        tools: list[IntegrationToolSummary] = []
        mappings = {
            _manifest_text(item, "tool_name"): item
            for item in _mapping_objects(manifest)
            if item.get("connector_id") == connector.connector_id
        }
        for current in self._bounded_current_tools(connector.alias):
            mapping = mappings.get(current.tool_name)
            valid = self._store.current_valid_review(connector.alias, current.tool_name)
            if not current.present:
                state = "removed — denied"
            elif not connector.is_active:
                state = "connector disabled — denied"
            elif mapping is None:
                state = "unmapped — denied"
            elif valid is None:
                state = "unreviewed — denied"
            else:
                state = f"reviewed: {valid.recommended_mode.value}"
            tools.append(
                IntegrationToolSummary(
                    opaque_id=self._opaque_id(connector.alias, current.tool_name),
                    tool_name=current.tool_name,
                    display_label=(
                        _manifest_text(mapping, "display_label")
                        if mapping is not None
                        else f"{current.tool_name} (unmapped)"
                    ),
                    schema_digest=current.schema_digest,
                    present=current.present,
                    review_state=state,
                    recommended_mode=(valid.recommended_mode if valid is not None else None),
                )
            )
        latest = discovery.discovery if discovery is not None else None
        return IntegrationConnectorSummary(
            alias=connector.alias,
            connector_id=connector.connector_id,
            display_name=_manifest_text(template, "display_name"),
            config_digest=connector.config_digest,
            enabled=connector.is_active,
            discovery_status=(latest.status if latest is not None else "not_discovered"),
            discovery_source=(latest.source if latest is not None else None),
            discovered_at=(latest.discovered_at if latest is not None else None),
            server_identity_digest=(latest.server_identity_digest if latest is not None else None),
            tools=tuple(tools),
        )

    def _commit_totp_review(
        self,
        principal: SessionPrincipal,
        *,
        opaque_id: str,
        profile: EffectProfile,
        expected_target: EffectReviewTarget,
        binding: ActionBinding,
        proof: VerifiedTotp,
        now: int,
    ) -> int:
        if (
            proof.user_id != principal.user_id
            or proof.binding != binding
            or proof.session_id != principal.session_id
            or proof.http_method != "POST"
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
            raise WebForbidden("TOTP confirmation is invalid")
        with self._database.transaction() as connection:
            self._require_active_session(connection, principal, now=now)
            target = self._store.current_review_target_in_transaction(
                connection,
                alias=expected_target.alias,
                tool_name=expected_target.tool_name,
            )
            if target != expected_target or not hmac.compare_digest(
                self._opaque_id(target.alias, target.tool_name) if target is not None else "",
                opaque_id,
            ):
                raise IntegrationStoreError("effect review target changed")
            credential = connection.execute(
                """
                UPDATE auth_credentials SET last_used_at = ?
                WHERE credential_id = ? AND user_id = ? AND kind = 'totp'
                  AND disabled_at IS NULL
                RETURNING credential_id
                """,
                (now, proof.credential_id, proof.user_id),
            ).fetchone()
            if credential is None:
                raise WebForbidden("TOTP confirmation is invalid")
            connection.execute(
                """
                INSERT INTO auth_proof_consumptions(kind, use_id, purpose, consumed_at)
                VALUES ('totp', ?, 'mutation', ?)
                """,
                (proof.use_id, now),
            )
            review_id = self._store._append_effect_review_in_transaction(
                connection,
                target=expected_target,
                profile=profile,
                actor=f"web:{principal.user_id}",
                auth_kind="totp",
                auth_use_id=proof.use_id,
                reviewed_at=now,
            )
            for scope in proof.attempt_reservation.scope_keys:
                connection.execute(
                    """
                    DELETE FROM auth_attempts
                    WHERE scope_key = ? AND last_attempt_id = ?
                    """,
                    (scope, proof.attempt_reservation.attempt_id),
                )
            if self._fault_injector is not None:
                self._fault_injector("totp:before_commit")
        return review_id

    def _commit_passkey_review(
        self,
        principal: SessionPrincipal,
        *,
        draft: _EffectDraft,
        binding: ActionBinding,
        proof: VerifiedWebAuthn,
        now: int,
    ) -> int:
        if (
            proof.user_id != principal.user_id
            or proof.challenge_id != draft.challenge_id
            or proof.binding != binding
            or proof.session_id != principal.session_id
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
            raise WebForbidden("passkey confirmation is invalid")
        with self._database.transaction() as connection:
            stored = self._find_draft_in_transaction(connection, draft.challenge_id)
            if stored != draft or now < draft.created_at or now >= draft.expires_at:
                raise IntegrationStoreError("effect review draft changed")
            self._require_active_session(connection, principal, now=now)
            target = self._store.current_review_target_in_transaction(
                connection,
                alias=draft.alias,
                tool_name=draft.tool_name,
            )
            if (
                target is None
                or not hmac.compare_digest(target.snapshot_digest, draft.target_snapshot_digest)
                or not hmac.compare_digest(target.mapping_key, draft.effect_mapping_key)
                or not hmac.compare_digest(
                    _review_digest(target, draft.profile),
                    draft.effect_review_digest,
                )
                or not hmac.compare_digest(
                    self._opaque_id(target.alias, target.tool_name),
                    draft.opaque_id,
                )
            ):
                raise IntegrationStoreError("effect review target changed")
            _consume_webauthn_credential(connection, proof, now=now)
            consumed = connection.execute(
                """
                UPDATE connector_effect_review_challenges SET consumed_at = ?
                WHERE challenge_id = ? AND user_id = ?
                  AND effect_mapping_key = ? AND effect_review_digest = ?
                  AND session_id = ? AND http_method = 'POST'
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
                    draft.effect_mapping_key,
                    draft.effect_review_digest,
                    proof.session_id,
                    now,
                    now,
                    proof.credential_id,
                ),
            ).rowcount
            if consumed != 1:
                raise IntegrationStoreError("passkey challenge was already consumed")
            connection.execute(
                """
                INSERT INTO auth_proof_consumptions(kind, use_id, purpose, consumed_at)
                VALUES ('webauthn', ?, 'mutation', ?)
                """,
                (proof.use_id, now),
            )
            review_id = self._store._append_effect_review_in_transaction(
                connection,
                target=target,
                profile=draft.profile,
                actor=f"web:{principal.user_id}",
                auth_kind="webauthn",
                auth_use_id=proof.use_id,
                reviewed_at=now,
            )
            connection.execute(
                "DELETE FROM connector_effect_review_drafts WHERE challenge_id = ?",
                (draft.challenge_id,),
            )
            if self._fault_injector is not None:
                self._fault_injector("passkey:before_commit")
        return review_id

    def _require_review_target(
        self,
        opaque_id: str,
        profile: EffectProfile,
        *,
        expected_snapshot_digest: str,
    ) -> tuple[EffectReviewTarget, ActionBinding]:
        if not isinstance(profile, EffectProfile):
            raise WebConflict("effect profile is invalid")
        location = self._resolve_opaque_id(opaque_id)
        if location is None:
            raise WebConflict("integration tool is stale or unavailable")
        target = self._store.current_review_target(location.connector.alias, location.tool_name)
        if (
            target is None
            or not hmac.compare_digest(target.snapshot_digest, expected_snapshot_digest)
            or not hmac.compare_digest(self._opaque_id(target.alias, target.tool_name), opaque_id)
        ):
            raise WebConflict("integration changed after review")
        review_digest = _review_digest(target, profile)
        return target, ActionBinding(
            "review_effect_mapping",
            effect_mapping_key=target.mapping_key,
            effect_review_digest=review_digest,
        )

    def _resolve_opaque_id(self, opaque_id: str) -> _ToolLocation | None:
        if not isinstance(opaque_id, str) or not 16 <= len(opaque_id) <= 128:
            return None
        match: _ToolLocation | None = None
        connectors = self._store.list_connectors(limit=MAX_CONNECTOR_ALIASES + 1)
        if len(connectors) > MAX_CONNECTOR_ALIASES:
            raise IntegrationStoreError("integration workspace exceeds its connector bound")
        for connector in connectors:
            for tool in self._bounded_current_tools(connector.alias):
                if hmac.compare_digest(self._opaque_id(connector.alias, tool.tool_name), opaque_id):
                    candidate = _ToolLocation(connector=connector, tool_name=tool.tool_name)
                    if match is not None and match != candidate:
                        raise IntegrationStoreError("integration tool identifier collision")
                    match = candidate
        return match

    def _bounded_current_tools(self, alias: str) -> tuple[CurrentToolRecord, ...]:
        tools = self._store.current_tools(alias, include_removed=True)
        if len(tools) > _MAX_TOOLS:
            raise IntegrationStoreError("connector retained tool history exceeds its bound")
        return tools

    def _opaque_id(self, alias: str, tool_name: str) -> str:
        return _opaque_id(self._opaque_id_key, alias, tool_name)

    def _review_views(
        self,
        alias: str,
        tool_name: str,
    ) -> tuple[EffectReviewRecord, ...]:
        return self._store.list_effect_reviews(alias, tool_name, limit=100)

    def _manifest(self, identity: PluginIdentity) -> dict[str, Any]:
        with self._database.read() as connection:
            row = connection.execute(
                """
                SELECT canonical_manifest FROM plugin_manifests
                WHERE plugin_id = ? AND plugin_version = ? AND manifest_sha256 = ?
                """,
                (identity.plugin_id, identity.plugin_version, identity.manifest_sha256),
            ).fetchone()
        if row is None:
            raise IntegrationStoreError("integration plugin manifest is unavailable")
        raw = bytes(row["canonical_manifest"])
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError, TypeError):
            raise IntegrationStoreError("stored integration plugin manifest is invalid") from None
        if (
            not isinstance(value, dict)
            or canonical_json(value) != raw
            or not hmac.compare_digest(sha256_hex(raw), identity.manifest_sha256)
        ):
            raise IntegrationStoreError("stored integration plugin manifest failed integrity")
        return value

    def _find_draft(self, challenge_id: str) -> _EffectDraft | None:
        with self._database.read() as connection:
            return self._find_draft_in_transaction(connection, challenge_id)

    @staticmethod
    def _find_draft_in_transaction(connection: Any, challenge_id: str) -> _EffectDraft | None:
        if not isinstance(challenge_id, str) or not 16 <= len(challenge_id) <= 128:
            return None
        row = connection.execute(
            "SELECT * FROM connector_effect_review_drafts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            profile = EffectProfile.from_mapping(
                {
                    "mutation": str(row["mutation"]),
                    "external_communication": str(row["external_communication"]),
                    "code_execution": str(row["code_execution"]),
                    "privilege_change": str(row["privilege_change"]),
                    "open_world": str(row["open_world"]),
                    "idempotent": str(row["idempotent"]),
                }
            )
        except ValueError:
            raise IntegrationStoreError("stored effect review draft is invalid") from None
        return _EffectDraft(
            challenge_id=str(row["challenge_id"]),
            opaque_id=str(row["opaque_id"]),
            alias=str(row["alias"]),
            tool_name=str(row["tool_name"]),
            target_snapshot_digest=str(row["target_snapshot_digest"]),
            effect_mapping_key=str(row["effect_mapping_key"]),
            effect_review_digest=str(row["effect_review_digest"]),
            profile=profile,
            user_id=str(row["user_id"]),
            session_id=str(row["session_id"]),
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
        )

    @staticmethod
    def _draft_matches(
        draft: _EffectDraft | None,
        *,
        principal: SessionPrincipal,
        opaque_id: str,
        expected_snapshot_digest: str,
        now: int,
    ) -> bool:
        return bool(
            draft is not None
            and hmac.compare_digest(draft.opaque_id, opaque_id)
            and hmac.compare_digest(draft.target_snapshot_digest, expected_snapshot_digest)
            and draft.user_id == principal.user_id
            and hmac.compare_digest(draft.session_id, principal.session_id)
            and draft.created_at <= now < draft.expires_at
        )

    def _require_principal(self, principal: SessionPrincipal) -> None:
        if (
            not isinstance(principal, SessionPrincipal)
            or principal.auth_method == "preauth"
            or principal.auth_method.startswith(_PREAUTH_PREFIX)
            or not hmac.compare_digest(principal.user_id, self._authorized_user_id)
        ):
            raise WebUnauthorized("a completed authorized human session is required")

    def _require_active_session(
        self,
        connection: Any,
        principal: SessionPrincipal,
        *,
        now: int,
    ) -> None:
        try:
            _require_active_session(
                connection,
                principal.session_id,
                user_id=principal.user_id,
                now=now,
                idle_timeout=self._idle_timeout,
            )
        except InvalidSession as exc:
            raise WebForbidden("authenticated session is no longer active") from exc

    def _prune_effect_ephemera(self, *, now: int) -> None:
        cutoff = max(0, now - 7 * 24 * 60 * 60)
        with self._database.transaction() as connection:
            connection.execute(
                """
                DELETE FROM connector_effect_review_drafts WHERE challenge_id IN (
                    SELECT challenge_id FROM connector_effect_review_drafts
                    WHERE expires_at <= ? ORDER BY expires_at LIMIT 500
                )
                """,
                (cutoff,),
            )
            connection.execute(
                """
                DELETE FROM connector_effect_review_challenges WHERE challenge_id IN (
                    SELECT challenge_id FROM connector_effect_review_challenges AS challenge
                    WHERE challenge.expires_at <= ?
                      AND NOT EXISTS (
                          SELECT 1 FROM connector_effect_review_drafts AS draft
                          WHERE draft.challenge_id = challenge.challenge_id
                      )
                    ORDER BY challenge.expires_at LIMIT 500
                )
                """,
                (cutoff,),
            )

    @staticmethod
    def _validate_now(now: int) -> None:
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise WebConflict("integration review time is invalid")


def _review_digest(target: EffectReviewTarget, profile: EffectProfile) -> str:
    return sha256_hex(
        canonical_json(
            {
                "domain": _REVIEW_DOMAIN,
                "profile": profile.as_dict(),
                "recommended_mode": recommend_policy(profile).value,
                "target_snapshot_digest": target.snapshot_digest,
            }
        )
    )


def _opaque_id(key: bytes, alias: str, tool_name: str) -> str:
    digest = hmac.new(
        key,
        _OPAQUE_DOMAIN + canonical_json({"alias": alias, "tool_name": tool_name}),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _unreviewable_snapshot(
    *,
    connector: ConnectorRecord,
    tool_name: str,
    schema_digest: str,
    run_id: str,
    evidence_digest: str,
    present: bool,
) -> str:
    return sha256_hex(
        canonical_json(
            {
                "config_digest": connector.config_digest,
                "connector_id": connector.connector_id,
                "evidence_bundle_digest": evidence_digest,
                "manifest_sha256": connector.plugin.manifest_sha256,
                "plugin_id": connector.plugin.plugin_id,
                "plugin_version": connector.plugin.plugin_version,
                "present": present,
                "run_id": run_id,
                "schema_digest": schema_digest,
                "tool_name": tool_name,
                "version": 1,
            }
        )
    )


def _consume_webauthn_credential(
    connection: Any,
    proof: VerifiedWebAuthn,
    *,
    now: int,
) -> None:
    if proof.expected_counter < 0 or not (
        proof.expected_counter == proof.new_counter == 0
        or proof.new_counter > proof.expected_counter
    ):
        raise WebForbidden("passkey confirmation is invalid")
    if (
        proof.expected_backup_eligible != proof.new_backup_eligible
        or (not proof.new_backup_eligible and proof.new_backed_up)
        or (proof.previous_backed_up and not proof.new_backed_up)
    ):
        raise WebForbidden("passkey confirmation is invalid")
    updated = connection.execute(
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
        raise WebForbidden("passkey confirmation is invalid")


def _parse_evidence(values: tuple[dict[str, Any], ...]) -> tuple[EffectEvidence, ...]:
    result: list[EffectEvidence] = []
    try:
        for value in values:
            if set(value) not in (
                {"source", "proposed_profile", "signals"},
                {"source", "proposed_profile", "signals", "action_id"},
            ):
                raise ValueError
            signals = value["signals"]
            if not isinstance(signals, list) or not all(isinstance(item, str) for item in signals):
                raise ValueError
            action_id = value.get("action_id")
            if action_id is not None and not isinstance(action_id, str):
                raise ValueError
            proposed = value["proposed_profile"]
            if not isinstance(proposed, dict):
                raise ValueError
            result.append(
                EffectEvidence(
                    source=EvidenceSource(value["source"]),
                    proposed_profile=EffectProfile.from_mapping(proposed),
                    signals=tuple(signals),
                    action_id=action_id,
                )
            )
    except (KeyError, TypeError, ValueError):
        raise IntegrationStoreError("stored integration evidence is invalid") from None
    return tuple(result)


def _strict_json_object(value: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = child
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, TypeError, UnicodeError, ValueError):
        raise WebConflict("passkey options are invalid") from None
    if not isinstance(parsed, dict):
        raise WebConflict("passkey options are invalid")
    return parsed


def _manifest_text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise IntegrationStoreError("stored plugin manifest is invalid")
    return selected


def _string_tuple(value: Mapping[str, Any], key: str) -> tuple[str, ...]:
    selected = value.get(key)
    if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected):
        raise IntegrationStoreError("stored plugin manifest is invalid")
    return tuple(selected)


def _mapping_objects(manifest: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    values = manifest.get("tool_mappings")
    if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
        raise IntegrationStoreError("stored plugin manifest is invalid")
    return tuple(values)


def _mapping_for(
    manifest: Mapping[str, Any],
    connector_id: str,
    tool_name: str,
) -> dict[str, Any] | None:
    matches = [
        item
        for item in _mapping_objects(manifest)
        if item.get("connector_id") == connector_id and item.get("tool_name") == tool_name
    ]
    if len(matches) > 1:
        raise IntegrationStoreError("stored plugin mappings are ambiguous")
    return matches[0] if matches else None


def _connector_template(
    manifest: Mapping[str, Any],
    connector_id: str,
) -> dict[str, Any]:
    values = manifest.get("connectors")
    if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
        raise IntegrationStoreError("stored plugin manifest is invalid")
    matches = [item for item in values if item.get("connector_id") == connector_id]
    if len(matches) != 1:
        raise IntegrationStoreError("stored plugin connector identity is invalid")
    return cast(dict[str, Any], matches[0])


def _unavailable_reason(
    *,
    mapping: Mapping[str, Any] | None,
    present: bool,
    connector_active: bool,
) -> str:
    if not connector_active:
        return "The exact connector generation is disabled or no longer selected."
    if not present:
        return "The server removed this exact tool; the prior definition is retained for audit."
    if mapping is None:
        return "No exact plugin mapping exists for this discovered tool, so it remains denied."
    return "The exact integration snapshot is stale or incomplete and cannot be reviewed."
