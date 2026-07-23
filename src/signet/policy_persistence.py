"""Durable web action drafts and crash-consistent policy promotion."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import inspect
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol, cast

import yaml

from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.auth import ActionBinding
from signet.db import Database, IntegrityError
from signet.decision_notes import normalize_decision_note, reason_for_action
from signet.models import (
    ApprovalConfirmation,
    InvalidConfirmation,
    InvalidTransition,
    RequestExpired,
    RequestNotFound,
    StaleVersion,
)
from signet.policy import (
    PolicyEngine,
    PolicyError,
    PolicyMode,
    PolicySnapshot,
    ToolPolicy,
    dump_policy,
    parse_policy_yaml,
    policy_config_hash,
    policy_document,
)
from signet.state_machine import ApprovalStateMachine
from signet.web import PolicyPromotionPreview
from signet.web_backend import (
    PolicyPromotionError,
    PreparedEdit,
    PrivatePayloadReviewer,
    WebActionDraft,
    WebPayloadError,
)

PolicyFaultInjector = Callable[[str], None]
PolicyApplyCallback = Callable[[PolicySnapshot], None]
ListChangedCallback = Callable[[frozenset[str]], Awaitable[None] | None]
_POLICY_ACTIONS = frozenset({"promote_approval", "promote_passthrough"})
_MAX_POLICY_BYTES = 4 * 1024 * 1024
_DEFAULT_MAX_POLICY_VERSIONS = 10_000
_DEFAULT_MAX_POLICY_HISTORY_BYTES = 256 * 1024 * 1024
_SQLITE_MAX_INTEGER = (2**63) - 1

_INVALIDATE_APPROVAL_CHALLENGES = """
    UPDATE approval_challenges SET invalidated_at = ?
    WHERE request_id = ? AND invalidated_at IS NULL AND consumed_at IS NULL
"""
_INVALIDATE_AUTH_CHALLENGES = """
    UPDATE auth_challenges SET invalidated_at = ?
    WHERE request_id = ? AND invalidated_at IS NULL AND consumed_at IS NULL
"""
_INVALIDATE_BROWSER_VIEWS = """
    UPDATE browser_views SET invalidated_at = ?
    WHERE request_id = ? AND invalidated_at IS NULL
"""
_INVALIDATION_QUERIES = (
    _INVALIDATE_APPROVAL_CHALLENGES,
    _INVALIDATE_AUTH_CHALLENGES,
    _INVALIDATE_BROWSER_VIEWS,
)


class PolicyPersistenceError(PolicyPromotionError):
    """A durable policy operation could not be completed safely."""


class PolicyDivergenceError(PolicyPersistenceError):
    """The policy file and durable policy ledger disagree."""


class PolicyUnavailable(PolicyPersistenceError):
    """Policy mutation is disabled until durable recovery succeeds."""


class PolicyPublicationGate(Protocol):
    """Call-admission gate for aliases with an unpublished policy change."""

    def gate_publication(self, aliases: frozenset[str]) -> None: ...

    def ungate_publication(self, aliases: frozenset[str]) -> None: ...


class SQLiteActionDraftRepository:
    """Immutable restart-safe storage for passkey action drafts."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def save(self, draft: WebActionDraft) -> None:
        _validate_draft(draft)
        edit = draft.prepared_edit
        try:
            with self.database.transaction() as connection:
                cutoff = max(0, draft.created_at - 7 * 24 * 60 * 60)
                connection.execute(
                    """
                    DELETE FROM web_action_drafts WHERE rowid IN (
                        SELECT rowid FROM web_action_drafts
                        WHERE expires_at <= ? ORDER BY expires_at LIMIT 500
                    )
                    """,
                    (cutoff,),
                )
                connection.execute(
                    """
                    DELETE FROM auth_challenges WHERE rowid IN (
                        SELECT challenge.rowid FROM auth_challenges AS challenge
                        WHERE challenge.action != 'login' AND challenge.expires_at <= ?
                          AND NOT EXISTS (
                              SELECT 1 FROM web_action_drafts AS draft
                              WHERE draft.challenge_id = challenge.challenge_id
                          )
                        ORDER BY challenge.expires_at LIMIT 500
                    )
                    """,
                    (cutoff,),
                )
                connection.execute(
                    """
                    INSERT INTO web_action_drafts(
                        challenge_id, action, binding_action, request_id, version,
                        payload_hash, prospective_payload_hash, user_id, session_id,
                        policy_change, edit_encrypted_payload, edit_payload_hash,
                        edit_canonical_size, edit_policy_version, edit_adapter_version,
                        edit_schema_version, edit_encryption_key_ref, created_at, expires_at,
                        decision_note
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        draft.challenge_id,
                        draft.action,
                        draft.binding.action,
                        draft.binding.request_id,
                        draft.binding.version,
                        draft.binding.payload_hash,
                        draft.binding.prospective_payload_hash,
                        draft.user_id,
                        draft.session_id,
                        int(draft.policy_change),
                        edit.encrypted_payload if edit is not None else None,
                        edit.payload_hash if edit is not None else None,
                        edit.canonical_size if edit is not None else None,
                        edit.policy_version if edit is not None else None,
                        edit.adapter_version if edit is not None else None,
                        edit.schema_version if edit is not None else None,
                        edit.encryption_key_ref if edit is not None else None,
                        draft.created_at,
                        draft.expires_at,
                        draft.decision_note,
                    ),
                )
        except IntegrityError as exc:
            raise ValueError("action draft conflicts with durable state") from exc

    def find(self, challenge_id: str) -> WebActionDraft | None:
        if not isinstance(challenge_id, str) or not challenge_id or len(challenge_id) > 128:
            return None
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM web_action_drafts WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            return None
        prepared = None
        if row["edit_encrypted_payload"] is not None:
            prepared = PreparedEdit(
                encrypted_payload=bytes(row["edit_encrypted_payload"]),
                payload_hash=str(row["edit_payload_hash"]),
                canonical_size=int(row["edit_canonical_size"]),
                policy_version=str(row["edit_policy_version"]),
                adapter_version=str(row["edit_adapter_version"]),
                schema_version=str(row["edit_schema_version"]),
                encryption_key_ref=str(row["edit_encryption_key_ref"]),
            )
        draft = WebActionDraft(
            challenge_id=str(row["challenge_id"]),
            action=cast(Any, str(row["action"])),
            binding=ActionBinding(
                str(row["binding_action"]),
                str(row["request_id"]),
                int(row["version"]),
                str(row["payload_hash"]),
                (
                    str(row["prospective_payload_hash"])
                    if row["prospective_payload_hash"] is not None
                    else None
                ),
            ),
            user_id=str(row["user_id"]),
            session_id=str(row["session_id"]),
            policy_change=bool(row["policy_change"]),
            prepared_edit=prepared,
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
            decision_note=(str(row["decision_note"]) if row["decision_note"] is not None else None),
        )
        _validate_draft(draft)
        return draft


@dataclass(frozen=True, slots=True)
class _PromotionPlan:
    request_id: str
    version: int
    payload_hash: str
    alias: str
    tool: str
    mode: PolicyMode
    binding_action: str
    originating_event: str
    gateway_internal: bool
    previous: ToolPolicy
    updated: ToolPolicy
    snapshot: PolicySnapshot
    snapshot_yaml: bytes
    config_hash: str
    file_sha256: str
    previous_file_sha256: str


@dataclass(frozen=True, slots=True)
class _StoredPolicy:
    version: int
    config_hash: str
    file_sha256: str
    sync_state: str
    snapshot_yaml: bytes
    applied: bool
    publication_pending: bool
    previous_file_sha256: str | None


class SQLitePolicyPromotionBoundary:
    """Atomically consume a web proof and durably apply one policy mode change.

    SQLite and the policy file cannot share one physical transaction.  The
    boundary therefore stages and fsyncs the exact next file, commits a ledger
    row that marks it pending, then atomically renames and marks it synced.
    Startup recovery completes only a byte-identical committed pending write;
    every other mismatch fails closed.
    """

    def __init__(
        self,
        database: Database,
        state_machine: ApprovalStateMachine,
        payloads: PrivatePayloadReviewer,
        engine: PolicyEngine,
        policy_path: Path,
        *,
        apply_policy: PolicyApplyCallback | None = None,
        publication_gate: PolicyPublicationGate | None = None,
        notify_list_changed: ListChangedCallback | None = None,
        fault_injector: PolicyFaultInjector | None = None,
        clock: Callable[[], int] | None = None,
        max_policy_versions: int = _DEFAULT_MAX_POLICY_VERSIONS,
        max_policy_history_bytes: int = _DEFAULT_MAX_POLICY_HISTORY_BYTES,
    ) -> None:
        if (
            not isinstance(max_policy_versions, int)
            or isinstance(max_policy_versions, bool)
            or not 1 <= max_policy_versions <= 1_000_000
            or not isinstance(max_policy_history_bytes, int)
            or isinstance(max_policy_history_bytes, bool)
            or not 1 <= max_policy_history_bytes <= 8 * 1024 * 1024 * 1024
        ):
            raise ValueError("durable policy history limits are invalid")
        if apply_policy is not None and publication_gate is None:
            raise ValueError("policy application requires a publication gate")
        expanded = policy_path.expanduser()
        resolved_parent = expanded.parent.resolve(strict=True)
        _require_secure_directory(resolved_parent)
        if expanded.is_symlink():
            raise PolicyPersistenceError("policy path must be an existing regular file")
        resolved = resolved_parent / expanded.name
        try:
            _read_regular(resolved)
        except FileNotFoundError:
            with database.read() as connection:
                recoverable = connection.execute(
                    """
                    SELECT 1 FROM durable_policy_file_state
                    WHERE singleton = 1 AND sync_state = 'pending'
                    """
                ).fetchone()
            if recoverable is None:
                raise PolicyPersistenceError(
                    "missing policy file has no committed pending recovery"
                ) from None
        if database.path.expanduser().resolve() == resolved:
            raise PolicyPersistenceError("policy path cannot be the approval database")
        self.database = database
        self.state_machine = state_machine
        self.payloads = payloads
        self.engine = engine
        self.policy_path = resolved
        self.pending_path = resolved.with_name(f".{resolved.name}.pending")
        self.lock_path = resolved.with_name(f".{resolved.name}.lock")
        self._apply_policy = apply_policy
        self._publication_gate = publication_gate
        self._notify_list_changed = notify_list_changed
        self._fault_injector = fault_injector
        self._clock = clock or (lambda: int(time.time()))
        self._max_policy_versions = max_policy_versions
        self._max_policy_history_bytes = max_policy_history_bytes
        self._thread_lock = threading.RLock()
        self._publication_lock = asyncio.Lock()
        self._ready = False
        self.recover(now=self._clock())

    @property
    def ready(self) -> bool:
        return self._ready

    def install_provider_setup(
        self,
        snapshot: PolicySnapshot,
        *,
        alias: str,
        now: int,
    ) -> None:
        """Install one generated provider policy while services are stopped."""

        if alias not in {"fastmail", "whatsapp"}:
            raise ValueError("provider policy alias is unsupported")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise ValueError("provider policy time is invalid")
        if not isinstance(snapshot, PolicySnapshot):
            raise TypeError("provider policy snapshot is invalid")

        committed = False
        with self._locked():
            self._require_ready()
            stored = self._stored_policy(verify_history=True)
            if stored is None:
                raise PolicyUnavailable("durable policy state is unavailable")
            previous = self._validate_stored(stored)
            if (
                stored.sync_state != "synced"
                or stored.publication_pending
                or previous != self.engine.snapshot
            ):
                raise PolicyUnavailable("durable policy is stale or not fully synced")
            _validate_provider_setup_transition(previous, snapshot, alias)
            snapshot_yaml = dump_policy(snapshot)
            config_hash = policy_config_hash(snapshot)
            file_sha256 = hashlib.sha256(snapshot_yaml).hexdigest()
            current = _read_regular(self.policy_path)
            if not _same_digest(current, stored.file_sha256):
                raise PolicyDivergenceError("policy file changed before provider setup")

            self._write_pending(snapshot_yaml)
            try:
                with self.database.transaction() as connection:
                    self._require_history_capacity(
                        connection,
                        additional_bytes=len(snapshot_yaml),
                    )
                    row = connection.execute(
                        """
                        SELECT policy_version_id, config_hash, file_sha256,
                               sync_state, publication_pending
                        FROM durable_policy_file_state WHERE singleton = 1
                        """
                    ).fetchone()
                    if (
                        row is None
                        or int(row["policy_version_id"]) != previous.version
                        or not _same_text(str(row["config_hash"]), stored.config_hash)
                        or not _same_text(str(row["file_sha256"]), stored.file_sha256)
                        or row["sync_state"] != "synced"
                        or bool(row["publication_pending"])
                    ):
                        raise PolicyUnavailable("durable policy changed concurrently")
                    connection.execute(
                        """
                        INSERT INTO policy_versions(
                            policy_version_id, actor, created_at, mode_diffs_json,
                            originating_event, config_hash, applied
                        ) VALUES (?, 'gateway:provider-setup', ?, ?, 'file_change', ?, 1)
                        """,
                        (
                            snapshot.version,
                            now,
                            _canonical_json({"alias": alias, "operation": "provider_setup"}),
                            config_hash,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO durable_policy_snapshots(
                            policy_version_id, config_hash, prior_config_hash,
                            snapshot_yaml, file_sha256
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            snapshot.version,
                            config_hash,
                            stored.config_hash,
                            snapshot_yaml,
                            file_sha256,
                        ),
                    )
                    updated = connection.execute(
                        """
                        UPDATE durable_policy_file_state
                        SET policy_version_id = ?, config_hash = ?, file_sha256 = ?,
                            sync_state = 'pending', publication_pending = 0,
                            updated_at = ?
                        WHERE singleton = 1 AND policy_version_id = ?
                          AND config_hash = ? AND file_sha256 = ?
                          AND sync_state = 'synced' AND publication_pending = 0
                        """,
                        (
                            snapshot.version,
                            config_hash,
                            file_sha256,
                            now,
                            previous.version,
                            stored.config_hash,
                            stored.file_sha256,
                        ),
                    ).rowcount
                    if updated != 1:
                        raise PolicyUnavailable("durable policy changed concurrently")
                committed = True
                self._ready = False
                self._replace_pending(
                    expected_current_hash=stored.file_sha256,
                    expected_pending_hash=file_sha256,
                )
                published = _StoredPolicy(
                    snapshot.version,
                    config_hash,
                    file_sha256,
                    "pending",
                    snapshot_yaml,
                    True,
                    False,
                    stored.file_sha256,
                )
                self._mark_synced(published, now=now)
                self.engine.restore_durable_snapshot(snapshot)
                if self._apply_policy is not None:
                    self._apply_policy(snapshot)
                self._ready = True
            except BaseException:
                if not committed:
                    self._remove_untracked_pending()
                else:
                    self._ready = False
                raise

    async def publish_pending(self, *, now: int | None = None) -> bool:
        """Attempt one durable list-change publication and acknowledge it on success."""

        selected_now = self._clock() if now is None else now
        if not isinstance(selected_now, int) or isinstance(selected_now, bool) or selected_now < 0:
            raise ValueError("policy publication time is invalid")
        async with self._publication_lock:
            prepared = await _run_sync(self._prepare_pending_publication)
            if prepared is None:
                return False
            stored, aliases = prepared
            self._gate_publication(aliases)

            callback = self._notify_list_changed
            if callback is None:
                raise PolicyUnavailable("list-change publication callback is unavailable")
            result = callback(aliases)
            if inspect.isawaitable(result):
                await result
            elif result is not None:
                raise PolicyPersistenceError(
                    "list-change publication callback returned an invalid result"
                )
            self._fault("policy:published_callbacks")
            await _run_sync(
                self._acknowledge_publication,
                stored,
                aliases,
                now=selected_now,
            )
            return True

    def binding_action(
        self,
        request_id: str,
        action: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> str:
        self._require_ready()
        with self._locked():
            plan = self._build_plan(
                request_id,
                action,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
                now=now,
            )
            return plan.binding_action

    def preview(
        self,
        request_id: str,
        action: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> PolicyPromotionPreview:
        self._require_ready()
        with self._locked():
            request = self.state_machine.get_request(request_id)
            if int(request["current_version"]) != expected_version or not _same_text(
                str(request["current_payload_hash"]), expected_payload_hash
            ):
                raise StaleVersion(request_id)
            if (
                action != "approve"
                or not bool(request["gateway_internal"])
                or request["downstream_alias"] != "gateway"
                or request["tool_name"] != "request_tool_access"
            ):
                raise InvalidTransition("request is not a gateway policy proposal")
            try:
                reviewed = self.payloads.review(
                    request_id,
                    version=expected_version,
                    payload_hash=expected_payload_hash,
                )
            except WebPayloadError as exc:
                raise PolicyPersistenceError(
                    "gateway policy proposal content could not be authenticated"
                ) from exc
            alias = reviewed.arguments.get("alias")
            tool = reviewed.arguments.get("tool")
            if not isinstance(alias, str) or not alias or not isinstance(tool, str) or not tool:
                raise PolicyPersistenceError("gateway policy proposal target is invalid")
            historical, active_version, publication_pending = self._reviewed_policy_snapshot(
                reviewed.policy_version
            )
            current = historical.configured(alias, tool)
            if current is None:
                raise PolicyPersistenceError(
                    "gateway policy proposal target is absent from its reviewed policy"
                )
            mode = _gateway_promotion_mode(current)
            proposed_version = reviewed.policy_version + 1
            historical_change_valid = reviewed.policy_version < _SQLITE_MAX_INTEGER
            expected_snapshot: PolicySnapshot | None = None
            try:
                expected_snapshot, previous, updated = PolicyEngine(historical).preview_promotion(
                    alias, tool, mode
                )
            except PolicyError:
                historical_change_valid = False
                previous = current
                updated = replace(current, mode=mode)

            stale = reviewed.policy_version != active_version
            can_approve = (
                request["state"] == "pending_approval"
                and now < int(request["expires_at"])
                and not stale
                and not publication_pending
                and historical_change_valid
                and expected_snapshot is not None
            )
            if can_approve:
                try:
                    live_plan = self._build_plan(
                        request_id,
                        action,
                        expected_version=expected_version,
                        expected_payload_hash=expected_payload_hash,
                        now=now,
                    )
                except (
                    PolicyPromotionError,
                    RequestNotFound,
                    StaleVersion,
                    InvalidTransition,
                    RequestExpired,
                ):
                    can_approve = False
                else:
                    can_approve = (
                        live_plan.alias == alias
                        and live_plan.tool == tool
                        and live_plan.mode is mode
                        and live_plan.previous == previous
                        and live_plan.updated == updated
                        and live_plan.snapshot == expected_snapshot
                    )
            return PolicyPromotionPreview(
                target_alias=alias,
                target_tool=tool,
                current_mode=previous.mode.value,
                proposed_mode=updated.mode.value,
                reviewed_read_only=previous.reviewed_read_only,
                communication_send=previous.communication_send,
                reviewed_classification=previous.reviewed_classification,
                current_policy_version=reviewed.policy_version,
                proposed_policy_version=proposed_version,
                active_policy_version=active_version,
                can_approve=can_approve,
                stale=stale,
            )

    def promote(
        self,
        draft: WebActionDraft,
        confirmation: ApprovalConfirmation,
        *,
        actor: str,
        now: int,
    ) -> str:
        if not draft.policy_change or draft.prepared_edit is not None:
            raise InvalidConfirmation("policy action draft is invalid")
        return self._promote(
            draft.action,
            draft.binding,
            confirmation,
            actor=actor,
            now=now,
        )

    def promote_totp(
        self,
        action: str,
        binding: ActionBinding,
        confirmation: ApprovalConfirmation,
        *,
        actor: str,
        now: int,
    ) -> str:
        if confirmation.kind.value != "totp":
            raise InvalidConfirmation("TOTP policy boundary requires a TOTP proof")
        return self._promote(action, binding, confirmation, actor=actor, now=now)

    def recover(self, *, now: int) -> None:
        """Bootstrap or reconcile the durable ledger and exact policy file."""

        self._ready = False
        with self._locked():
            stored = self._stored_policy(verify_history=True)
            if stored is None:
                self._bootstrap(now=now)
                self._remove_untracked_pending()
                if self._apply_policy is not None:
                    self._apply_policy(self.engine.snapshot)
                self._ready = True
                return
            snapshot = self._validate_stored(stored)
            recovered_pending = stored.sync_state == "pending"
            if recovered_pending:
                self._recover_pending_file(stored)
                self._mark_synced(stored, now=now)
            else:
                current = _read_regular(self.policy_path)
                if not _same_digest(current, stored.file_sha256):
                    raise PolicyDivergenceError(
                        "policy file differs from the synced durable policy snapshot"
                    )
                if self.pending_path.exists() or self.pending_path.is_symlink():
                    self._remove_untracked_pending()
            aliases = (
                _changed_aliases_from_latest(self.database, stored.version)
                if stored.publication_pending
                else frozenset()
            )
            self._gate_publication(aliases)
            self.engine.restore_durable_snapshot(snapshot)
            if self._apply_policy is not None:
                self._apply_policy(snapshot)
            if stored.publication_pending:
                self._publish_synchronously_if_possible(stored, aliases=aliases, now=now)
            self._ready = True

    def _promote(
        self,
        action: str,
        binding: ActionBinding,
        confirmation: ApprovalConfirmation,
        *,
        actor: str,
        now: int,
    ) -> str:
        self._require_ready()
        request_id = binding.request_id
        version = binding.version
        payload_hash = binding.payload_hash
        if request_id is None or version is None or payload_hash is None:
            raise InvalidConfirmation("policy confirmation lacks an exact request revision")
        committed = False
        with self._locked():
            try:
                plan = self._build_plan(
                    request_id,
                    action,
                    expected_version=version,
                    expected_payload_hash=payload_hash,
                    now=now,
                )
                if binding.action != plan.binding_action:
                    raise InvalidConfirmation("policy confirmation mode binding does not match")
                self._write_pending(plan.snapshot_yaml)
                self._fault("policy:pending_fsynced")
                with self.database.transaction() as connection:
                    self._require_current_policy(connection, plan)
                    self._require_history_capacity(
                        connection,
                        additional_bytes=len(plan.snapshot_yaml),
                    )
                    request = connection.execute(
                        "SELECT * FROM approval_requests WHERE request_id = ?",
                        (request_id,),
                    ).fetchone()
                    if request is None:
                        raise RequestNotFound(request_id)
                    if (
                        request["state"] != "pending_approval"
                        or int(request["current_version"]) != version
                        or not _same_text(str(request["current_payload_hash"]), payload_hash)
                    ):
                        raise StaleVersion(request_id)
                    if now >= int(request["expires_at"]):
                        raise RequestExpired(request_id)
                    if bool(request["gateway_internal"]) != plan.gateway_internal:
                        raise InvalidTransition("policy proposal context changed")
                    if not plan.gateway_internal and (
                        request["downstream_alias"] != plan.alias
                        or request["tool_name"] != plan.tool
                    ):
                        raise InvalidTransition("policy promotion target changed")
                    self.state_machine.consume_policy_confirmation(
                        connection,
                        confirmation,
                        action=plan.binding_action,
                        request_id=request_id,
                        expected_version=version,
                        expected_payload_hash=payload_hash,
                        now=now,
                    )
                    diff = {
                        "alias": plan.alias,
                        "new_mode": plan.updated.mode.value,
                        "old_mode": plan.previous.mode.value,
                        "request_id": request_id,
                        "tool": plan.tool,
                    }
                    connection.execute(
                        """
                        INSERT INTO policy_versions(
                            policy_version_id, actor, created_at, mode_diffs_json,
                            originating_event, config_hash, applied
                        ) VALUES (?, ?, ?, ?, ?, ?, 1)
                        """,
                        (
                            plan.snapshot.version,
                            actor,
                            now,
                            _canonical_json(diff),
                            plan.originating_event,
                            plan.config_hash,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO durable_policy_snapshots(
                            policy_version_id, config_hash, prior_config_hash,
                            snapshot_yaml, file_sha256
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            plan.snapshot.version,
                            plan.config_hash,
                            policy_config_hash(self.engine.snapshot),
                            plan.snapshot_yaml,
                            plan.file_sha256,
                        ),
                    )
                    updated_state = connection.execute(
                        """
                        UPDATE durable_policy_file_state
                        SET policy_version_id = ?, config_hash = ?, file_sha256 = ?,
                            sync_state = 'pending', publication_pending = 1,
                            updated_at = ?
                        WHERE singleton = 1 AND policy_version_id = ?
                          AND config_hash = ? AND sync_state = 'synced'
                          AND publication_pending = 0
                        """,
                        (
                            plan.snapshot.version,
                            plan.config_hash,
                            plan.file_sha256,
                            now,
                            self.engine.snapshot.version,
                            policy_config_hash(self.engine.snapshot),
                        ),
                    ).rowcount
                    if updated_state != 1:
                        raise PolicyUnavailable("durable policy changed concurrently")
                    self._record_request_policy_event(connection, request, plan, actor, now)
                    self._fault("policy:before_db_commit")
                committed = True
                self._ready = False
                self._fault("policy:db_committed")
                self._fault("policy:before_rename")
                self._replace_pending(
                    expected_current_hash=plan.previous_file_sha256,
                    expected_pending_hash=plan.file_sha256,
                )
                self._fault("policy:renamed")
                self._fault("policy:before_sync_mark")
                self._mark_synced(
                    _StoredPolicy(
                        plan.snapshot.version,
                        plan.config_hash,
                        plan.file_sha256,
                        "pending",
                        plan.snapshot_yaml,
                        True,
                        True,
                        plan.previous_file_sha256,
                    ),
                    now=now,
                )
                self._fault("policy:synced")
                aliases = frozenset({plan.alias})
                self._gate_publication(aliases)
                self.engine.restore_durable_snapshot(plan.snapshot)
                if self._apply_policy is not None:
                    self._apply_policy(plan.snapshot)
                published = _StoredPolicy(
                    plan.snapshot.version,
                    plan.config_hash,
                    plan.file_sha256,
                    "synced",
                    plan.snapshot_yaml,
                    True,
                    True,
                    plan.previous_file_sha256,
                )
                self._publish_synchronously_if_possible(
                    published,
                    aliases=aliases,
                    now=now,
                )
                self._ready = True
                return "policy_updated"
            except BaseException:
                if not committed:
                    self._remove_untracked_pending()
                else:
                    self._ready = False
                raise

    def _build_plan(
        self,
        request_id: str,
        action: str,
        *,
        expected_version: int,
        expected_payload_hash: str,
        now: int,
    ) -> _PromotionPlan:
        request = self.state_machine.get_request(request_id)
        if (
            request["state"] != "pending_approval"
            or int(request["current_version"]) != expected_version
            or not _same_text(str(request["current_payload_hash"]), expected_payload_hash)
        ):
            raise StaleVersion(request_id)
        if now >= int(request["expires_at"]):
            raise RequestExpired(request_id)
        gateway_internal = bool(request["gateway_internal"])
        if gateway_internal:
            if (
                action != "approve"
                or request["downstream_alias"] != "gateway"
                or request["tool_name"] != "request_tool_access"
            ):
                raise InvalidTransition("gateway policy proposals cannot be retargeted")
            try:
                reviewed = self.payloads.review(
                    request_id,
                    version=expected_version,
                    payload_hash=expected_payload_hash,
                )
            except WebPayloadError as exc:
                raise PolicyPersistenceError(
                    "gateway policy proposal content could not be authenticated"
                ) from exc
            alias = reviewed.arguments.get("alias")
            tool = reviewed.arguments.get("tool")
            if not isinstance(alias, str) or not isinstance(tool, str):
                raise PolicyPersistenceError("gateway policy proposal target is invalid")
            if reviewed.policy_version != self.engine.snapshot.version:
                raise StaleVersion(request_id)
            current = self.engine.snapshot.configured(alias, tool)
            if current is None:
                raise PolicyPersistenceError("only a discovered, reviewed tool can be promoted")
            mode = _gateway_promotion_mode(current)
            origin = "request_tool_access"
        else:
            if action not in _POLICY_ACTIONS:
                raise InvalidTransition("request action is not a policy promotion")
            alias = str(request["downstream_alias"])
            tool = str(request["tool_name"])
            mode = PolicyMode.APPROVAL if action == "promote_approval" else PolicyMode.PASSTHROUGH
            origin = "one_click_promotion"
        binding_action = f"promote_{mode.value}"
        stored = self._stored_policy(verify_history=True)
        if stored is None:
            raise PolicyUnavailable("durable policy is not ready for promotion")
        self._require_active_policy(stored)
        if self.engine.snapshot.version >= _SQLITE_MAX_INTEGER:
            raise PolicyUnavailable("durable policy version space is exhausted")
        try:
            snapshot, previous, updated = self.engine.preview_promotion(alias, tool, mode)
        except PolicyError as exc:
            raise PolicyPersistenceError("reviewed policy promotion was refused") from exc
        serialized = dump_policy(snapshot)
        try:
            serialized_snapshot = _parse_snapshot(serialized)
        except PolicyDivergenceError as exc:
            raise PolicyPersistenceError(
                "reviewed policy promotion cannot be serialized safely"
            ) from exc
        if serialized_snapshot != snapshot or not _same_text(
            policy_config_hash(serialized_snapshot),
            policy_config_hash(snapshot),
        ):
            raise PolicyPersistenceError(
                "reviewed policy promotion changed during strict serialization"
            )
        with self.database.read() as connection:
            self._require_history_capacity(
                connection,
                additional_bytes=len(serialized),
            )
        return _PromotionPlan(
            request_id=request_id,
            version=expected_version,
            payload_hash=expected_payload_hash,
            alias=alias,
            tool=tool,
            mode=mode,
            binding_action=binding_action,
            originating_event=origin,
            gateway_internal=gateway_internal,
            previous=previous,
            updated=updated,
            snapshot=snapshot,
            snapshot_yaml=serialized,
            config_hash=policy_config_hash(snapshot),
            file_sha256=hashlib.sha256(serialized).hexdigest(),
            previous_file_sha256=stored.file_sha256,
        )

    def _reviewed_policy_snapshot(self, version: int) -> tuple[PolicySnapshot, int, bool]:
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or not 1 <= version <= _SQLITE_MAX_INTEGER
        ):
            raise PolicyDivergenceError("reviewed policy version is invalid")
        try:
            stored = self._stored_policy(verify_history=True)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PolicyDivergenceError("durable policy history metadata is invalid") from exc
        if stored is None:
            raise PolicyDivergenceError("durable policy history is unavailable")
        self._require_active_policy(stored, require_published=False)

        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT snapshot.policy_version_id, snapshot.config_hash,
                       snapshot.snapshot_yaml, snapshot.file_sha256,
                       version.config_hash AS version_config_hash,
                       version.applied
                FROM durable_policy_snapshots AS snapshot
                JOIN policy_versions AS version
                  ON version.policy_version_id = snapshot.policy_version_id
                WHERE snapshot.policy_version_id = ?
                """,
                (version,),
            ).fetchone()
        if row is None:
            raise PolicyDivergenceError("reviewed durable policy snapshot is unavailable")
        try:
            row_version = int(row["policy_version_id"])
            config_hash = str(row["config_hash"])
            snapshot_yaml = bytes(row["snapshot_yaml"])
            file_sha256 = str(row["file_sha256"])
            version_config_hash = str(row["version_config_hash"])
        except (TypeError, ValueError, OverflowError) as exc:
            raise PolicyDivergenceError("reviewed durable policy metadata is invalid") from exc
        snapshot = _parse_snapshot(snapshot_yaml)
        if (
            row_version != version
            or not bool(row["applied"])
            or not _same_text(config_hash, version_config_hash)
            or not _same_digest(snapshot_yaml, file_sha256)
            or snapshot.version != version
            or not _same_text(policy_config_hash(snapshot), config_hash)
        ):
            raise PolicyDivergenceError("reviewed durable policy failed integrity review")
        return snapshot, stored.version, stored.publication_pending

    def _require_active_policy(
        self,
        stored: _StoredPolicy,
        *,
        require_published: bool = True,
    ) -> PolicySnapshot:
        active = self._validate_stored(stored)
        if (
            stored.sync_state != "synced"
            or (require_published and stored.publication_pending)
            or not stored.applied
            or stored.version > _SQLITE_MAX_INTEGER
            or active != self.engine.snapshot
            or not _same_text(stored.config_hash, policy_config_hash(self.engine.snapshot))
        ):
            raise PolicyDivergenceError("active durable policy is not safely published")
        try:
            current_file = _read_regular(self.policy_path)
        except OSError as exc:
            raise PolicyDivergenceError("active durable policy file is unavailable") from exc
        if not _same_digest(current_file, stored.file_sha256):
            raise PolicyDivergenceError("active durable policy file failed integrity review")
        return active

    def _record_request_policy_event(
        self,
        connection: Any,
        request: Any,
        plan: _PromotionPlan,
        actor: str,
        now: int,
    ) -> None:
        if plan.gateway_internal:
            updated = connection.execute(
                """
                UPDATE approval_requests
                SET state = 'succeeded', completed_at = ?,
                    safe_outcome_json = ?, revision = revision + 1
                WHERE request_id = ? AND state = 'pending_approval'
                  AND current_version = ? AND current_payload_hash = ?
                """,
                (
                    now,
                    _canonical_json({"status": "policy_updated"}),
                    plan.request_id,
                    plan.version,
                    plan.payload_hash,
                ),
            ).rowcount
        else:
            updated = connection.execute(
                """
                UPDATE approval_requests SET revision = revision + 1
                WHERE request_id = ? AND state = 'pending_approval'
                  AND current_version = ? AND current_payload_hash = ?
                """,
                (plan.request_id, plan.version, plan.payload_hash),
            ).rowcount
        if updated != 1:
            raise StaleVersion(plan.request_id)
        for query in _INVALIDATION_QUERIES:
            connection.execute(query, (now, plan.request_id))
        connection.execute(
            """
            INSERT INTO request_events(
                request_id, actor, action, occurred_at,
                version, payload_hash, safe_details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                plan.request_id,
                actor,
                f"policy_promoted_to_{plan.mode.value}",
                now,
                plan.version,
                plan.payload_hash,
                _canonical_json(
                    {
                        "alias": plan.alias,
                        "config_hash": plan.config_hash,
                        "new_mode": plan.updated.mode.value,
                        "old_mode": plan.previous.mode.value,
                        "originating_event": plan.originating_event,
                        "policy_version": plan.snapshot.version,
                        "tool": plan.tool,
                    }
                ),
            ),
        )

    def _bootstrap(self, *, now: int) -> None:
        raw = _read_regular(self.policy_path)
        snapshot = _parse_snapshot(raw)
        if len(raw) > self._max_policy_history_bytes:
            raise PolicyUnavailable("initial policy exceeds the durable history limit")
        if snapshot.version > _SQLITE_MAX_INTEGER:
            raise PolicyDivergenceError("policy version exceeds SQLite's integer range")
        if snapshot.version != self.engine.snapshot.version or policy_config_hash(
            snapshot
        ) != policy_config_hash(self.engine.snapshot):
            raise PolicyDivergenceError(
                "runtime policy does not match the policy file during bootstrap"
            )
        config_hash = policy_config_hash(snapshot)
        file_hash = hashlib.sha256(raw).hexdigest()
        with self.database.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM durable_policy_file_state WHERE singleton = 1"
                ).fetchone()
                is not None
            ):
                raise PolicyUnavailable("durable policy was initialized concurrently")
            existing_versions = connection.execute(
                "SELECT policy_version_id, config_hash, applied FROM policy_versions"
            ).fetchall()
            if not existing_versions:
                connection.execute(
                    """
                    INSERT INTO policy_versions(
                        policy_version_id, actor, created_at, mode_diffs_json,
                        originating_event, config_hash, applied
                    ) VALUES (?, 'gateway:bootstrap', ?, '[]', 'file_change', ?, 1)
                    """,
                    (snapshot.version, now, config_hash),
                )
            elif (
                len(existing_versions) != 1
                or int(existing_versions[0]["policy_version_id"]) != snapshot.version
                or not bool(existing_versions[0]["applied"])
                or not _same_text(str(existing_versions[0]["config_hash"]), config_hash)
            ):
                raise PolicyDivergenceError(
                    "existing policy history cannot be reconciled during bootstrap"
                )
            connection.execute(
                """
                INSERT INTO durable_policy_snapshots(
                    policy_version_id, config_hash, prior_config_hash,
                    snapshot_yaml, file_sha256
                ) VALUES (?, ?, NULL, ?, ?)
                """,
                (snapshot.version, config_hash, raw, file_hash),
            )
            connection.execute(
                """
                INSERT INTO durable_policy_file_state(
                    singleton, policy_version_id, config_hash,
                    file_sha256, sync_state, publication_pending, updated_at
                ) VALUES (1, ?, ?, ?, 'synced', 0, ?)
                """,
                (snapshot.version, config_hash, file_hash, now),
            )
        current = _read_regular(self.policy_path)
        if not _same_digest(current, file_hash):
            raise PolicyDivergenceError(
                "policy file changed while its durable ledger was initialized"
            )

    def _stored_policy(self, *, verify_history: bool = False) -> _StoredPolicy | None:
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT state.policy_version_id, state.config_hash, state.file_sha256,
                       state.sync_state, state.publication_pending,
                       snapshot.snapshot_yaml, snapshot.prior_config_hash,
                       version.applied,
                       snapshot.config_hash AS snapshot_config_hash,
                       snapshot.file_sha256 AS snapshot_file_sha256,
                       version.config_hash AS version_config_hash,
                       prior.file_sha256 AS previous_file_sha256
                FROM durable_policy_file_state AS state
                JOIN durable_policy_snapshots AS snapshot
                  ON snapshot.policy_version_id = state.policy_version_id
                JOIN policy_versions AS version
                  ON version.policy_version_id = state.policy_version_id
                LEFT JOIN durable_policy_snapshots AS prior
                  ON prior.config_hash = snapshot.prior_config_hash
                WHERE state.singleton = 1
                """
            ).fetchone()
            if row is not None:
                self._validate_history_bounds(connection, latest_version=int(row[0]))
                if verify_history:
                    self._validate_policy_history(connection)
        if row is None:
            return None
        hashes = {
            str(row["config_hash"]),
            str(row["snapshot_config_hash"]),
            str(row["version_config_hash"]),
        }
        file_hashes = {str(row["file_sha256"]), str(row["snapshot_file_sha256"])}
        if len(hashes) != 1 or len(file_hashes) != 1:
            raise PolicyDivergenceError("durable policy ledger hashes disagree")
        return _StoredPolicy(
            version=int(row["policy_version_id"]),
            config_hash=str(row["config_hash"]),
            file_sha256=str(row["file_sha256"]),
            sync_state=str(row["sync_state"]),
            snapshot_yaml=bytes(row["snapshot_yaml"]),
            applied=bool(row["applied"]),
            publication_pending=bool(row["publication_pending"]),
            previous_file_sha256=(
                str(row["previous_file_sha256"])
                if row["previous_file_sha256"] is not None
                else None
            ),
        )

    def _validate_history_bounds(self, connection: Any, *, latest_version: int) -> None:
        statistics = connection.execute(
            """
            SELECT count(*) AS snapshot_count,
                   coalesce(sum(length(snapshot_yaml)), 0) AS aggregate_bytes,
                   min(policy_version_id) AS first_version,
                   max(policy_version_id) AS last_version
            FROM durable_policy_snapshots
            """
        ).fetchone()
        version_statistics = connection.execute(
            """
            SELECT count(*) AS version_count,
                   min(policy_version_id) AS first_version,
                   max(policy_version_id) AS last_version
            FROM policy_versions
            """
        ).fetchone()
        snapshot_count = int(statistics["snapshot_count"])
        version_count = int(version_statistics["version_count"])
        aggregate_bytes = int(statistics["aggregate_bytes"])
        first_version = statistics["first_version"]
        last_version = statistics["last_version"]
        if (
            snapshot_count < 1
            or snapshot_count != version_count
            or snapshot_count > self._max_policy_versions
            or aggregate_bytes > self._max_policy_history_bytes
            or first_version is None
            or last_version is None
            or int(last_version) != latest_version
            or int(version_statistics["last_version"]) != latest_version
            or int(first_version) != int(version_statistics["first_version"])
            or int(last_version) - int(first_version) + 1 != snapshot_count
        ):
            raise PolicyDivergenceError("durable policy history is incomplete or exceeds limits")

    def _validate_policy_history(self, connection: Any) -> None:
        rows = connection.execute(
            """
            SELECT snapshot.policy_version_id, snapshot.config_hash,
                   snapshot.prior_config_hash, snapshot.snapshot_yaml,
                   snapshot.file_sha256, version.config_hash AS version_config_hash,
                   version.applied, version.mode_diffs_json,
                   version.originating_event
            FROM durable_policy_snapshots AS snapshot
            JOIN policy_versions AS version
              ON version.policy_version_id = snapshot.policy_version_id
            ORDER BY snapshot.policy_version_id
            """
        )
        previous_version: int | None = None
        previous_hash: str | None = None
        previous_snapshot: PolicySnapshot | None = None
        for row in rows:
            version = int(row["policy_version_id"])
            config_hash = str(row["config_hash"])
            snapshot_yaml = bytes(row["snapshot_yaml"])
            snapshot = _parse_snapshot(snapshot_yaml)
            if (
                not bool(row["applied"])
                or not _same_text(config_hash, str(row["version_config_hash"]))
                or not _same_digest(snapshot_yaml, str(row["file_sha256"]))
                or snapshot.version != version
                or not _same_text(policy_config_hash(snapshot), config_hash)
                or (previous_version is None and row["prior_config_hash"] is not None)
                or (
                    previous_version is not None
                    and (
                        version != previous_version + 1
                        or row["prior_config_hash"] is None
                        or not _same_text(str(row["prior_config_hash"]), previous_hash or "")
                    )
                )
            ):
                raise PolicyDivergenceError("durable policy history failed integrity review")
            if previous_snapshot is not None:
                _validate_policy_transition(previous_snapshot, snapshot, row)
            previous_version = version
            previous_hash = config_hash
            previous_snapshot = snapshot

    def _require_history_capacity(
        self,
        connection: Any,
        *,
        additional_bytes: int,
    ) -> None:
        row = connection.execute(
            """
            SELECT count(*) AS snapshot_count,
                   coalesce(sum(length(snapshot_yaml)), 0) AS aggregate_bytes
            FROM durable_policy_snapshots
            """
        ).fetchone()
        if (
            int(row["snapshot_count"]) >= self._max_policy_versions
            or int(row["aggregate_bytes"]) + additional_bytes > self._max_policy_history_bytes
        ):
            raise PolicyUnavailable("durable policy history capacity is exhausted")

    def _validate_stored(self, stored: _StoredPolicy) -> PolicySnapshot:
        if (
            not stored.applied
            or stored.sync_state not in {"pending", "synced"}
            or (stored.sync_state == "pending" and not stored.publication_pending)
        ):
            raise PolicyDivergenceError("durable policy ledger state is invalid")
        if not _same_digest(stored.snapshot_yaml, stored.file_sha256):
            raise PolicyDivergenceError("durable policy snapshot bytes are corrupted")
        snapshot = _parse_snapshot(stored.snapshot_yaml)
        if snapshot.version != stored.version or not _same_text(
            policy_config_hash(snapshot), stored.config_hash
        ):
            raise PolicyDivergenceError("durable policy snapshot metadata is inconsistent")
        return snapshot

    def _recover_pending_file(self, stored: _StoredPolicy) -> None:
        current_missing = False
        try:
            current = _read_regular(self.policy_path)
        except FileNotFoundError:
            current_missing = True
            current = b""
        if _same_digest(current, stored.file_sha256):
            self._remove_untracked_pending()
            return
        if not current_missing and (
            stored.previous_file_sha256 is None
            or not _same_digest(current, stored.previous_file_sha256)
        ):
            raise PolicyDivergenceError("current policy file changed before pending recovery")
        if self.pending_path.exists() or self.pending_path.is_symlink():
            pending = _read_regular(self.pending_path)
            if not _same_digest(pending, stored.file_sha256):
                self._write_pending(stored.snapshot_yaml)
        else:
            self._write_pending(stored.snapshot_yaml)
        self._replace_pending(
            expected_current_hash=(None if current_missing else stored.previous_file_sha256),
            expected_pending_hash=stored.file_sha256,
        )

    def _require_current_policy(self, connection: Any, plan: _PromotionPlan) -> None:
        row = connection.execute(
            """
            SELECT policy_version_id, config_hash, file_sha256, sync_state,
                   publication_pending
            FROM durable_policy_file_state WHERE singleton = 1
            """
        ).fetchone()
        if (
            row is None
            or row["sync_state"] != "synced"
            or bool(row["publication_pending"])
            or int(row["policy_version_id"]) != self.engine.snapshot.version
            or not _same_text(str(row["config_hash"]), policy_config_hash(self.engine.snapshot))
            or plan.snapshot.version != self.engine.snapshot.version + 1
        ):
            raise PolicyUnavailable("durable policy is stale or not fully synced")
        current = _read_regular(self.policy_path)
        if not _same_digest(current, str(row["file_sha256"])):
            raise PolicyDivergenceError("policy file changed before promotion commit")

    def _mark_synced(self, stored: _StoredPolicy, *, now: int) -> None:
        current = _read_regular(self.policy_path)
        if not _same_digest(current, stored.file_sha256):
            raise PolicyDivergenceError("applied policy file does not match committed bytes")
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE durable_policy_file_state
                SET sync_state = 'synced', updated_at = ?
                WHERE singleton = 1 AND policy_version_id = ?
                  AND config_hash = ? AND file_sha256 = ? AND sync_state = 'pending'
                """,
                (now, stored.version, stored.config_hash, stored.file_sha256),
            ).rowcount
            if updated != 1:
                raise PolicyUnavailable("pending durable policy could not be marked synced")

    def _mark_published(self, stored: _StoredPolicy, *, now: int) -> None:
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE durable_policy_file_state
                SET publication_pending = 0, updated_at = ?
                WHERE singleton = 1 AND policy_version_id = ?
                  AND config_hash = ? AND file_sha256 = ?
                  AND sync_state = 'synced' AND publication_pending = 1
                """,
                (now, stored.version, stored.config_hash, stored.file_sha256),
            ).rowcount
            if updated != 1:
                raise PolicyUnavailable("applied policy publication marker changed")

    def _prepare_pending_publication(
        self,
    ) -> tuple[_StoredPolicy, frozenset[str]] | None:
        with self._locked():
            stored = self._stored_policy(verify_history=True)
            if stored is None:
                raise PolicyUnavailable("durable policy state is unavailable")
            self._validate_stored(stored)
            if stored.sync_state != "synced":
                raise PolicyUnavailable("durable policy file is not synchronized")
            if not stored.publication_pending:
                return None
            aliases = _changed_aliases_from_latest(self.database, stored.version)
            return stored, aliases

    def _acknowledge_publication(
        self,
        stored: _StoredPolicy,
        aliases: frozenset[str],
        *,
        now: int,
    ) -> None:
        with self._locked():
            current = self._stored_policy(verify_history=True)
            if current != stored:
                raise PolicyUnavailable("durable policy changed during publication")
            self._mark_published(stored, now=now)
        self._ungate_publication(aliases)

    def _publish_synchronously_if_possible(
        self,
        stored: _StoredPolicy,
        *,
        aliases: frozenset[str],
        now: int,
    ) -> bool:
        self._gate_publication(aliases)
        callback = self._notify_list_changed
        if callback is None or _is_async_callback(callback):
            return False
        result = callback(aliases)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise PolicyPersistenceError(
                "list-change publication callback must declare asynchronous execution"
            )
        if result is not None:
            raise PolicyPersistenceError(
                "list-change publication callback returned an invalid result"
            )
        self._fault("policy:published_callbacks")
        self._mark_published(stored, now=now)
        self._ungate_publication(aliases)
        return True

    def _gate_publication(self, aliases: frozenset[str]) -> None:
        if self._publication_gate is not None:
            self._publication_gate.gate_publication(aliases)

    def _ungate_publication(self, aliases: frozenset[str]) -> None:
        if self._publication_gate is not None:
            self._publication_gate.ungate_publication(aliases)

    def _write_pending(self, content: bytes) -> None:
        if len(content) > _MAX_POLICY_BYTES:
            raise PolicyPersistenceError("policy snapshot exceeds the writeback limit")
        parent_fd = _open_directory(self.policy_path.parent)
        temporary_name = f".{self.policy_path.name}.tmp.{secrets.token_hex(12)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
            _write_all(descriptor, content)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                self.pending_path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_fd)
            os.close(parent_fd)

    def _replace_pending(
        self,
        *,
        expected_current_hash: str | None = None,
        expected_pending_hash: str,
    ) -> None:
        if expected_current_hash is not None:
            current = _read_regular(self.policy_path)
            if not _same_digest(current, expected_current_hash):
                raise PolicyDivergenceError("policy file changed before atomic writeback")
        pending = _read_regular(self.pending_path)
        if not _same_digest(pending, expected_pending_hash):
            raise PolicyDivergenceError("pending policy changed before atomic writeback")
        parent_fd = _open_directory(self.policy_path.parent)
        try:
            os.replace(
                self.pending_path.name,
                self.policy_path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    def _remove_untracked_pending(self) -> None:
        parent_fd = _open_directory(self.policy_path.parent)
        try:
            try:
                os.unlink(self.pending_path.name, dir_fd=parent_fd)
            except FileNotFoundError:
                return
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    def _require_ready(self) -> None:
        if not self._ready:
            raise PolicyUnavailable("durable policy requires recovery before mutation")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._thread_lock:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            parent_fd = _open_directory(self.lock_path.parent)
            descriptor = -1
            acquired = False
            try:
                descriptor = os.open(
                    self.lock_path.name,
                    flags,
                    0o600,
                    dir_fd=parent_fd,
                )
                metadata = os.fstat(descriptor)
                _require_secure_regular_metadata(metadata, label="policy lock")
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                acquired = True
                path_metadata = os.stat(
                    self.lock_path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    path_metadata.st_dev != metadata.st_dev
                    or path_metadata.st_ino != metadata.st_ino
                ):
                    raise PolicyPersistenceError("policy lock changed while it was acquired")
                yield
            finally:
                if acquired:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(parent_fd)

    def _fault(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)


def _validate_draft(draft: WebActionDraft) -> None:
    binding = draft.binding
    edit = draft.prepared_edit
    try:
        normalized_note = normalize_decision_note(draft.decision_note)
    except ValueError:
        raise ValueError("action draft is invalid") from None
    if (
        not draft.challenge_id
        or len(draft.challenge_id) < 16
        or len(draft.challenge_id) > 128
        or binding.request_id is None
        or binding.version is None
        or binding.payload_hash is None
        or draft.expires_at <= draft.created_at
        or len(draft.user_id) > 256
        or len(draft.session_id) < 16
        or len(draft.session_id) > 128
        or draft.policy_change
        != (binding.action in _POLICY_ACTIONS or draft.action in _POLICY_ACTIONS)
        or (draft.action == "edit") != (edit is not None)
        or normalized_note != draft.decision_note
        or (
            normalized_note is not None
            and (draft.action not in {"approve", "deny"} or draft.policy_change)
        )
    ):
        raise ValueError("action draft is invalid")
    if draft.action in {"approve", "deny"} and not draft.policy_change:
        try:
            reason_for_action(draft.action, draft.decision_note)
        except ValueError:
            raise ValueError("action draft is invalid") from None
    elif normalized_note is not None:
        raise ValueError("action draft is invalid")
    if edit is not None and (
        not edit.encrypted_payload
        or edit.canonical_size < 0
        or not edit.policy_version
        or not edit.adapter_version
        or not edit.schema_version
        or not edit.encryption_key_ref
        or binding.prospective_payload_hash != edit.payload_hash
    ):
        raise ValueError("prepared edit draft is invalid")


def _parse_snapshot(document: bytes) -> PolicySnapshot:
    try:
        return parse_policy_yaml(document)
    except (PolicyError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyDivergenceError("durable policy snapshot is not valid strict YAML") from exc


def _read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        _require_secure_regular_metadata(metadata, label="policy storage")
        chunks: list[bytes] = []
        remaining = _MAX_POLICY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if not value or len(value) > _MAX_POLICY_BYTES:
            raise PolicyDivergenceError("policy file is empty or exceeds its size limit")
        return value
    finally:
        os.close(descriptor)


def _open_directory(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        _require_secure_directory_metadata(os.fstat(descriptor))
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _require_secure_directory(path: Path) -> None:
    descriptor = _open_directory(path)
    try:
        if not os.access(path, os.W_OK | os.X_OK):
            raise PolicyPersistenceError("policy directory is not writable by the gateway")
    finally:
        os.close(descriptor)


def _require_secure_directory_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise PolicyPersistenceError(
            "policy directory must be trusted and not group/world writable"
        )


def _require_secure_regular_metadata(
    metadata: os.stat_result,
    *,
    label: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise PolicyDivergenceError(f"{label} must be a trusted, single-link regular file")


def _fsync_directory(path: Path) -> None:
    descriptor = _open_directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("policy write made no progress")
        offset += written


def _same_text(first: str, second: str) -> bool:
    return secrets.compare_digest(first, second)


def _same_digest(content: bytes, expected: str) -> bool:
    return _same_text(hashlib.sha256(content).hexdigest(), expected)


def _is_async_callback(callback: ListChangedCallback) -> bool:
    return inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
        type(callback).__call__
    )


def _gateway_promotion_mode(current: ToolPolicy) -> PolicyMode:
    if (
        current.reviewed_read_only
        and not current.communication_send
        and current.reviewed_classification is None
    ):
        return PolicyMode.PASSTHROUGH
    return PolicyMode.APPROVAL


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _changed_aliases_from_latest(database: Database, version: int) -> frozenset[str]:
    with database.read() as connection:
        row = connection.execute(
            "SELECT mode_diffs_json FROM policy_versions WHERE policy_version_id = ?",
            (version,),
        ).fetchone()
    if row is None:
        raise PolicyDivergenceError("recovered policy version has no audit diff")
    try:
        value = json.loads(str(row["mode_diffs_json"]))
    except (TypeError, ValueError):
        raise PolicyDivergenceError("recovered policy audit diff is invalid") from None
    if not isinstance(value, dict) or not isinstance(value.get("alias"), str):
        raise PolicyDivergenceError("recovered policy audit diff lacks an alias")
    return frozenset({value["alias"]})


def _validate_policy_transition(
    previous: PolicySnapshot,
    current: PolicySnapshot,
    history_row: Any,
) -> None:
    try:
        audit = json.loads(str(history_row["mode_diffs_json"]))
    except (TypeError, ValueError):
        raise PolicyDivergenceError("durable policy audit history is invalid") from None
    if history_row["originating_event"] == "file_change":
        if (
            not isinstance(audit, dict)
            or set(audit) != {"alias", "operation"}
            or audit.get("operation") != "provider_setup"
            or audit.get("alias") not in {"fastmail", "whatsapp"}
        ):
            raise PolicyDivergenceError("durable provider policy audit is invalid")
        _validate_provider_setup_transition(previous, current, audit["alias"])
        return
    if (
        not isinstance(audit, dict)
        or set(audit) != {"alias", "new_mode", "old_mode", "request_id", "tool"}
        or not all(
            isinstance(audit.get(field), str) and bool(audit[field])
            for field in ("alias", "new_mode", "old_mode", "request_id", "tool")
        )
        or len(audit["request_id"]) > 256
        or history_row["originating_event"] not in {"one_click_promotion", "request_tool_access"}
    ):
        raise PolicyDivergenceError("durable policy audit history is invalid")
    alias = audit["alias"]
    tool = audit["tool"]
    previous_tool = previous.configured(alias, tool)
    current_tool = current.configured(alias, tool)
    if (
        current.version != previous.version + 1
        or previous_tool is None
        or current_tool is None
        or previous_tool.mode.value != audit["old_mode"]
        or current_tool.mode.value != audit["new_mode"]
        or previous_tool == current_tool
        or previous_tool != replace(current_tool, mode=previous_tool.mode)
    ):
        raise PolicyDivergenceError("durable policy transition does not match its audit record")
    previous_document = policy_document(previous)
    current_document = policy_document(current)
    current_document["version"] = previous.version
    current_document["downstreams"][alias]["tools"][tool]["mode"] = previous_tool.mode.value
    if current_document != previous_document:
        raise PolicyDivergenceError("durable policy transition changed unreviewed fields")


def _validate_provider_setup_transition(
    previous: PolicySnapshot,
    current: PolicySnapshot,
    alias: str,
) -> None:
    if current.version != previous.version + 1:
        raise PolicyDivergenceError("provider policy version is not consecutive")
    previous_document = policy_document(previous)
    current_document = policy_document(current)
    previous_document["version"] = current.version
    previous_downstreams = previous_document["downstreams"]
    current_downstreams = current_document["downstreams"]
    previous_provider = previous_downstreams.pop(alias, None)
    current_provider = current_downstreams.pop(alias, None)
    if (
        current_provider is None
        or current_provider == previous_provider
        or current_document != previous_document
    ):
        raise PolicyDivergenceError(
            "provider policy setup changed fields outside the selected provider"
        )
