"""Reviewed lifecycle plans and durable operation receipts.

Plans are read-only, deterministic snapshots. Applying a plan first records the
reviewed snapshot outside the setup root so interrupted uninstall/purge work can
resume without weakening setup ownership checks.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from signet.private_paths import PrivatePathError, ensure_private_directory, require_no_acl_grants
from signet.setup_platform import _replace_private_file
from signet.setup_state import SetupError, SetupJournalStore

LifecycleOperation = Literal["services", "backup", "restore", "upgrade", "uninstall"]
LifecycleStatus = Literal["applying", "failed", "completed", "rolling_back", "rolled_back"]


@contextmanager
def setup_lifecycle_lock(root_path: Path) -> Iterator[None]:
    descriptor = -1
    try:
        root = ensure_private_directory(root_path)
        descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        require_no_acl_grants(descriptor)
    except (OSError, PrivatePathError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise SetupError("setup lifecycle lock is unavailable or unsafe") from exc
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError("another setup lifecycle operation is in progress") from None
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


_PLAN_KEYS = {
    "version",
    "plan_id",
    "setup_id",
    "operation",
    "action",
    "observed",
    "steps",
    "automatic_safe_checks",
    "required_human_ceremonies",
    "deferred_live_provider_proof",
    "destructive_actions",
    "human_confirmation_required",
    "gateway_restart",
}
_RECORD_KEYS = {
    "version",
    "setup_id",
    "plan",
    "status",
    "phase",
    "revision",
    "attempts",
    "error_kind",
    "result",
}


@dataclass(frozen=True, slots=True)
class LifecyclePlan:
    setup_id: str
    operation: LifecycleOperation
    action: str
    observed: dict[str, Any]
    steps: tuple[str, ...]
    automatic_safe_checks: tuple[str, ...] = ()
    required_human_ceremonies: tuple[str, ...] = ()
    deferred_live_provider_proof: tuple[str, ...] = ()
    destructive_actions: tuple[str, ...] = ()
    human_confirmation_required: bool = True
    gateway_restart: bool = False

    @property
    def plan_id(self) -> str:
        return hashlib.sha256(_encoded(self._payload())).hexdigest()

    def _payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "setup_id": self.setup_id,
            "operation": self.operation,
            "action": self.action,
            "observed": self.observed,
            "steps": list(self.steps),
            "automatic_safe_checks": list(self.automatic_safe_checks),
            "required_human_ceremonies": list(self.required_human_ceremonies),
            "deferred_live_provider_proof": list(self.deferred_live_provider_proof),
            "destructive_actions": list(self.destructive_actions),
            "human_confirmation_required": self.human_confirmation_required,
            "gateway_restart": self.gateway_restart,
        }

    def document(self) -> dict[str, Any]:
        return {**self._payload(), "plan_id": self.plan_id}

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> LifecyclePlan:
        if set(document) != _PLAN_KEYS or document.get("version") != 1:
            raise SetupError("lifecycle plan receipt is invalid")
        operation = document.get("operation")
        if operation not in {"services", "backup", "restore", "upgrade", "uninstall"}:
            raise SetupError("lifecycle plan receipt operation is invalid")
        setup_id = document.get("setup_id")
        action = document.get("action")
        observed = document.get("observed")
        if not isinstance(setup_id, str) or not setup_id or not isinstance(action, str):
            raise SetupError("lifecycle plan receipt identity is invalid")
        if not isinstance(observed, dict):
            raise SetupError("lifecycle plan receipt observation is invalid")
        sequence_fields = (
            "steps",
            "automatic_safe_checks",
            "required_human_ceremonies",
            "deferred_live_provider_proof",
            "destructive_actions",
        )
        sequences: dict[str, tuple[str, ...]] = {}
        for name in sequence_fields:
            value = document.get(name)
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise SetupError("lifecycle plan receipt actions are invalid")
            sequences[name] = tuple(value)
        if not isinstance(document.get("human_confirmation_required"), bool) or not isinstance(
            document.get("gateway_restart"), bool
        ):
            raise SetupError("lifecycle plan receipt controls are invalid")
        plan = cls(
            setup_id=setup_id,
            operation=cast(LifecycleOperation, operation),
            action=action,
            observed=cast(dict[str, Any], observed),
            steps=sequences["steps"],
            automatic_safe_checks=sequences["automatic_safe_checks"],
            required_human_ceremonies=sequences["required_human_ceremonies"],
            deferred_live_provider_proof=sequences["deferred_live_provider_proof"],
            destructive_actions=sequences["destructive_actions"],
            human_confirmation_required=document["human_confirmation_required"],
            gateway_restart=document["gateway_restart"],
        )
        if document.get("plan_id") != plan.plan_id:
            raise SetupError("lifecycle plan receipt digest is invalid")
        return plan


@dataclass(slots=True)
class LifecycleOperationRecord:
    setup_id: str
    plan: LifecyclePlan
    status: LifecycleStatus
    phase: str
    revision: int = 0
    attempts: int = 0
    error_kind: str | None = None
    result: dict[str, Any] | None = None

    def document(self) -> dict[str, Any]:
        return {
            "version": 1,
            "setup_id": self.setup_id,
            "plan": self.plan.document(),
            "status": self.status,
            "phase": self.phase,
            "revision": self.revision,
            "attempts": self.attempts,
            "error_kind": self.error_kind,
            "result": self.result,
        }

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> LifecycleOperationRecord:
        if set(document) != _RECORD_KEYS or document.get("version") != 1:
            raise SetupError("lifecycle operation receipt is invalid")
        plan_document = document.get("plan")
        if not isinstance(plan_document, dict):
            raise SetupError("lifecycle operation receipt plan is invalid")
        plan = LifecyclePlan.from_document(cast(dict[str, Any], plan_document))
        status = document.get("status")
        if status not in {"applying", "failed", "completed", "rolling_back", "rolled_back"}:
            raise SetupError("lifecycle operation receipt status is invalid")
        setup_id = document.get("setup_id")
        phase = document.get("phase")
        revision = document.get("revision")
        attempts = document.get("attempts")
        error_kind = document.get("error_kind")
        result = document.get("result")
        if setup_id != plan.setup_id or not isinstance(phase, str) or not phase:
            raise SetupError("lifecycle operation receipt identity is invalid")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise SetupError("lifecycle operation receipt revision is invalid")
        if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
            raise SetupError("lifecycle operation receipt attempts are invalid")
        if error_kind is not None and not isinstance(error_kind, str):
            raise SetupError("lifecycle operation receipt error is invalid")
        if result is not None and not isinstance(result, dict):
            raise SetupError("lifecycle operation receipt result is invalid")
        return cls(
            setup_id=cast(str, setup_id),
            plan=plan,
            status=cast(LifecycleStatus, status),
            phase=phase,
            revision=revision,
            attempts=attempts,
            error_kind=error_kind,
            result=cast(dict[str, Any] | None, result),
        )


class LifecycleOperationStore:
    """CAS-style private receipt stored outside the purgeable setup root."""

    NAME = "lifecycle-operation.json"

    def __init__(self, root: Path) -> None:
        self.directory = root.parent / f"{root.name}-recovery"
        self.path = self.directory / self.NAME

    def load_optional(self) -> LifecycleOperationRecord | None:
        if not self.path.exists() and not self.path.is_symlink():
            return None
        document = SetupJournalStore._read_document(
            self.path,
            label="lifecycle operation receipt",
        )
        return LifecycleOperationRecord.from_document(document)

    def begin(self, plan: LifecyclePlan, *, phase: str) -> LifecycleOperationRecord:
        existing = self.load_optional()
        if existing is not None and existing.plan.plan_id == plan.plan_id:
            if existing.setup_id != plan.setup_id:
                raise SetupError("lifecycle operation receipt belongs to another setup")
            return existing
        if existing is not None and existing.status not in {"completed", "rolled_back"}:
            raise SetupError("another reviewed lifecycle plan is still incomplete")
        record = LifecycleOperationRecord(
            setup_id=plan.setup_id,
            plan=plan,
            status="applying",
            phase=phase,
        )
        self._write(record, previous=existing)
        return record

    def save(self, record: LifecycleOperationRecord) -> None:
        existing = self.load_optional()
        if (
            existing is None
            or existing.plan.plan_id != record.plan.plan_id
            or existing.revision != record.revision
        ):
            raise SetupError("lifecycle operation receipt changed before update")
        record.revision += 1
        try:
            self._write(record, previous=existing)
        except Exception:
            record.revision -= 1
            raise

    def _write(
        self,
        record: LifecycleOperationRecord,
        *,
        previous: LifecycleOperationRecord | None,
    ) -> None:
        if previous is None:
            self.directory.mkdir(mode=0o700, exist_ok=True)
            ensure_private_directory(self.directory)
            _fsync_directory(self.directory.parent)
            _replace_private_file(
                self.path,
                _encoded(record.document()),
                require_absent=True,
            )
            return
        _replace_private_file(
            self.path,
            _encoded(record.document()),
            expected_content=_encoded(previous.document()),
            require_present=True,
        )


def _encoded(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
