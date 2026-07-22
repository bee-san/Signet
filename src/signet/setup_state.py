"""Crash-safe, resumable setup journal and state machine."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from signet.auth import canonical_user_id
from signet.config import validate_public_origin
from signet.private_paths import (
    PrivatePathError,
    ensure_private_directory,
    require_no_acl_grants,
    require_private_directory_identity,
    revalidate_directory_identity,
)

SETUP_STEPS = (
    "preflight",
    "private_paths",
    "secrets",
    "configuration",
    "database",
    "services",
    "hermes_profiles",
    "owner_bootstrap",
)

JournalStatus = Literal[
    "planned",
    "applying",
    "failed",
    "completed",
    "rolling_back",
    "rolled_back",
    "rollback_failed",
    "uninstalled",
]
StepStatus = Literal[
    "pending",
    "applying",
    "completed",
    "failed",
    "rolling_back",
    "rolled_back",
    "rollback_failed",
]
PolicyMode = Literal["deny", "direct", "approval", "approval_with_edit"]


class SetupError(RuntimeError):
    """A setup operation was unsafe, invalid, or incomplete."""


@dataclass(frozen=True, slots=True)
class SetupSpec:
    root: Path
    public_origin: str
    owner_user_id: str
    hermes_profiles: tuple[str, ...]
    executable: Path
    open_browser: bool = True
    policy_mode: PolicyMode = "deny"

    def __post_init__(self) -> None:
        if not self.root.is_absolute() or ".." in self.root.parts:
            raise ValueError("setup root must be an absolute lexical path")
        if not self.executable.is_absolute() or ".." in self.executable.parts:
            raise ValueError("Signet executable must be an absolute lexical path")
        if canonical_user_id(self.owner_user_id) != self.owner_user_id:
            raise ValueError("setup owner must be a canonical user ID")
        try:
            validate_public_origin(self.public_origin)
        except ValueError as exc:
            raise ValueError("setup origin must be one canonical HTTPS origin") from exc
        if (
            not self.hermes_profiles
            or len(self.hermes_profiles) != len(set(self.hermes_profiles))
            or any(
                re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is None for name in self.hermes_profiles
            )
        ):
            raise ValueError("setup requires unique valid Hermes profile names")
        if self.policy_mode not in {"deny", "direct", "approval", "approval_with_edit"}:
            raise ValueError("unsupported setup policy mode")

    def document(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "public_origin": self.public_origin,
            "owner_user_id": self.owner_user_id,
            "hermes_profiles": list(self.hermes_profiles),
            "executable": str(self.executable),
            "open_browser": self.open_browser,
            "policy_mode": self.policy_mode,
        }

    @property
    def digest(self) -> str:
        document = self.document()
        # Browser launch is an operator preference, not an owned resource identity. A failed
        # browser handoff may therefore be resumed with --no-open-browser without adopting a
        # different installation.
        document.pop("open_browser")
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def legacy_deny_digest(self) -> str:
        document = self.document()
        document.pop("open_browser")
        document.pop("policy_mode")
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class SetupPlanStep:
    name: str
    status: Literal["planned"] = "planned"


@dataclass(frozen=True, slots=True)
class SetupPlan:
    setup_id: str
    spec: SetupSpec
    steps: tuple[SetupPlanStep, ...]
    provider_rollout: Literal["disabled"] = "disabled"


@dataclass(slots=True)
class SetupStepRecord:
    name: str
    status: StepStatus = "pending"
    attempts: int = 0
    error_kind: str | None = None

    def document(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "attempts": self.attempts,
            "error_kind": self.error_kind,
        }


@dataclass(slots=True)
class SetupJournal:
    version: int
    setup_id: str
    spec: dict[str, Any]
    spec_digest: str
    status: JournalStatus
    steps: list[SetupStepRecord]
    purge_backup: dict[str, Any] | None = None

    def step(self, name: str) -> SetupStepRecord:
        for step in self.steps:
            if step.name == name:
                return step
        raise SetupError(f"setup journal has no {name!r} step")

    def document(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "setup_id": self.setup_id,
            "spec": self.spec,
            "spec_digest": self.spec_digest,
            "status": self.status,
            "steps": [step.document() for step in self.steps],
            "purge_backup": self.purge_backup,
        }


class SetupPlatform(Protocol):
    def preflight(self, spec: SetupSpec) -> None: ...

    def validate_private_paths(self, spec: SetupSpec, setup_id: str) -> None: ...

    def apply(self, step: str, spec: SetupSpec, setup_id: str) -> None: ...

    def rollback(self, step: str, spec: SetupSpec, setup_id: str) -> None: ...


class SetupJournalStore:
    """Own one private setup root and atomically publish its non-secret journal."""

    OWNER_NAME = ".setup-owner.json"
    JOURNAL_NAME = ".setup-journal.json"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.owner_path = root / self.OWNER_NAME
        self.journal_path = root / self.JOURNAL_NAME

    def prepare(self, spec: SetupSpec, setup_id: str) -> None:
        if spec.root != self.root:
            raise SetupError("setup journal root does not match the setup specification")
        self._prepare_root()
        self._recover_owner_publication()
        if self.owner_path.exists():
            owner = self._read_document(self.owner_path, label="setup owner marker")
            accepted_digests = {spec.digest}
            if spec.policy_mode == "deny":
                accepted_digests.add(spec.legacy_deny_digest)
            expected_owners = (
                {"version": 1, "setup_id": setup_id, "spec_digest": digest}
                for digest in accepted_digests
            )
            if owner not in expected_owners:
                raise SetupError("setup root is owned by a different setup specification")
            return
        foreign = [
            child
            for child in self.root.iterdir()
            if child.name not in {self.OWNER_NAME, self.JOURNAL_NAME}
        ]
        if foreign or self.journal_path.exists():
            raise SetupError("setup root is not owned by Signet setup")
        self._write_document(
            self.owner_path,
            {"version": 1, "setup_id": setup_id, "spec_digest": spec.digest},
            replace=False,
        )

    def owned_setup_id(self, spec: SetupSpec) -> str | None:
        """Recover the durable setup ID without creating or replacing state."""

        self._recover_owner_publication()
        if not self.owner_path.exists():
            return None
        owner = self._read_document(self.owner_path, label="setup owner marker")
        accepted_digests = {spec.digest}
        if spec.policy_mode == "deny":
            accepted_digests.add(spec.legacy_deny_digest)
        setup_id = owner.get("setup_id")
        if (
            set(owner) != {"version", "setup_id", "spec_digest"}
            or owner.get("version") != 1
            or owner.get("spec_digest") not in accepted_digests
            or not isinstance(setup_id, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{16,64}", setup_id) is None
        ):
            raise SetupError("setup root is owned by a different setup specification")
        return setup_id

    def load_optional(self) -> SetupJournal | None:
        if not self.journal_path.exists():
            return None
        return self.load()

    def load(self) -> SetupJournal:
        document = self._read_document(self.journal_path, label="setup journal")
        try:
            steps = [
                SetupStepRecord(
                    name=str(item["name"]),
                    status=cast(StepStatus, item["status"]),
                    attempts=int(item["attempts"]),
                    error_kind=(
                        str(item["error_kind"]) if item["error_kind"] is not None else None
                    ),
                )
                for item in document["steps"]
            ]
            journal = SetupJournal(
                version=int(document["version"]),
                setup_id=str(document["setup_id"]),
                spec=dict(document["spec"]),
                spec_digest=str(document["spec_digest"]),
                status=cast(JournalStatus, document["status"]),
                steps=steps,
                purge_backup=(
                    dict(document["purge_backup"])
                    if document.get("purge_backup") is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError):
            raise SetupError("setup journal is invalid") from None
        if (
            journal.version != 1
            or [step.name for step in journal.steps] != list(SETUP_STEPS)
            or any(step.status not in _STEP_STATUSES for step in journal.steps)
            or journal.status not in _JOURNAL_STATUSES
            or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", journal.setup_id)
        ):
            raise SetupError("setup journal is invalid")
        return journal

    def save(self, journal: SetupJournal) -> None:
        self._write_document(self.journal_path, journal.document(), replace=True)

    def _prepare_root(self) -> None:
        if self.root.exists() and self.root.is_symlink():
            raise SetupError("setup root must not be a symbolic link")
        if self.root.exists() and not self.root.is_dir():
            raise SetupError("setup root must be a directory")
        if self.root.exists() and not self.owner_path.exists() and any(self.root.iterdir()):
            raise SetupError("setup root is not owned by Signet setup")
        try:
            resolved = ensure_private_directory(self.root)
        except PrivatePathError as exc:
            raise SetupError("setup root must be an owned mode-0700 directory") from exc
        if resolved != self.root:
            raise SetupError("setup root must be canonical and contain no symbolic links")

    def _recover_owner_publication(self) -> None:
        """Finish the recoverable hard-link publication boundary for the owner marker."""

        try:
            owner = self.owner_path.lstat()
        except FileNotFoundError:
            return
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if owner.st_nlink == 1:
            return
        if (
            not stat.S_ISREG(owner.st_mode)
            or owner.st_uid != current_uid
            or stat.S_IMODE(owner.st_mode) != 0o600
            or owner.st_nlink != 2
        ):
            raise SetupError("setup owner marker is not a private owned file")
        parent_identity = require_private_directory_identity(self.root)
        parent_descriptor = -1
        try:
            parent_descriptor = os.open(
                self.root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            prefix = f".{self.OWNER_NAME}."
            candidates: list[str] = []
            for name in os.listdir(parent_descriptor):
                if not name.startswith(prefix) or not name.endswith(".tmp"):
                    continue
                token = name[len(prefix) : -4]
                if not token or re.fullmatch(r"[A-Za-z0-9_-]+", token) is None:
                    continue
                candidate = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                if (candidate.st_dev, candidate.st_ino) == (owner.st_dev, owner.st_ino):
                    candidates.append(name)
            if len(candidates) != 1:
                raise SetupError("setup owner marker publication state is ambiguous")
            current = os.stat(
                self.OWNER_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (current.st_dev, current.st_ino) != (
                owner.st_dev,
                owner.st_ino,
            ) or current.st_nlink != 2:
                raise SetupError("setup owner marker changed during publication recovery")
            os.unlink(candidates[0], dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
            recovered = os.stat(
                self.OWNER_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (recovered.st_dev, recovered.st_ino) != (
                owner.st_dev,
                owner.st_ino,
            ) or recovered.st_nlink != 1:
                raise SetupError("setup owner marker recovery did not complete")
            revalidate_directory_identity(parent_identity, private=True)
        except SetupError:
            raise
        except (OSError, PrivatePathError) as exc:
            raise SetupError("setup owner marker publication could not be recovered") from exc
        finally:
            if parent_descriptor >= 0:
                os.close(parent_descriptor)

    @staticmethod
    def _read_document(path: Path, *, label: str) -> dict[str, Any]:
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            before = os.fstat(descriptor)
            require_no_acl_grants(descriptor)
            chunks: list[bytes] = []
            remaining = 1_048_577
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            encoded = b"".join(chunks)
            after = os.fstat(descriptor)
            current = path.lstat()
        except (OSError, PrivatePathError) as exc:
            raise SetupError(f"{label} is unavailable or unsafe") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(encoded) > 1_048_576:
            raise SetupError(f"{label} is too large")
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        stable_identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            stat.S_IMODE(before.st_mode),
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != current_uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise SetupError(f"{label} is not a private owned file")
        if stable_identity != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ) or stable_identity != (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
        ):
            raise SetupError(f"{label} changed during inspection")
        try:
            value = json.loads(encoded)
        except (UnicodeError, json.JSONDecodeError):
            raise SetupError(f"{label} is unavailable or invalid") from None
        if not isinstance(value, dict):
            raise SetupError(f"{label} is invalid")
        return cast(dict[str, Any], value)

    @staticmethod
    def _write_document(path: Path, document: dict[str, Any], *, replace: bool) -> None:
        encoded = (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(
            "utf-8"
        )
        temporary_name = f".{path.name}.{secrets.token_urlsafe(8)}.tmp"
        descriptor = -1
        parent_descriptor = -1
        try:
            parent_identity = require_private_directory_identity(path.parent)
            parent_descriptor = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            parent_metadata = os.fstat(parent_descriptor)
            require_no_acl_grants(parent_descriptor)
            if (
                parent_metadata.st_dev,
                parent_metadata.st_ino,
                parent_metadata.st_uid,
            ) != (
                parent_identity.device,
                parent_identity.inode,
                parent_identity.owner_uid,
            ):
                raise SetupError("setup state directory changed before publication")
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            os.fchmod(descriptor, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short journal write")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if replace:
                os.replace(
                    temporary_name,
                    path.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
            else:
                try:
                    os.link(
                        temporary_name,
                        path.name,
                        src_dir_fd=parent_descriptor,
                        dst_dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise SetupError("setup ownership marker already exists") from exc
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
            revalidate_directory_identity(parent_identity, private=True)
        except SetupError:
            raise
        except (OSError, PrivatePathError) as exc:
            raise SetupError("setup state could not be published durably") from exc
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            if parent_descriptor >= 0:
                with suppress(FileNotFoundError, OSError):
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                with suppress(OSError):
                    os.close(parent_descriptor)


class SetupEngine:
    def __init__(self, store: SetupJournalStore, platform: SetupPlatform) -> None:
        self.store = store
        self.platform = platform

    def plan(self, spec: SetupSpec) -> SetupPlan:
        return SetupPlan(
            setup_id=_new_setup_id(),
            spec=spec,
            steps=tuple(SetupPlanStep(name=name) for name in SETUP_STEPS),
        )

    def apply(self, spec: SetupSpec) -> SetupJournal:
        existing = self.store.load_optional()
        setup_id = (
            existing.setup_id
            if existing is not None
            else self.store.owned_setup_id(spec) or _new_setup_id()
        )
        self.store.prepare(spec, setup_id)
        journal = existing or SetupJournal(
            version=1,
            setup_id=setup_id,
            spec=spec.document(),
            spec_digest=spec.digest,
            status="planned",
            steps=[SetupStepRecord(name=name) for name in SETUP_STEPS],
        )
        self._require_spec(journal, spec)
        if journal.purge_backup is not None:
            durable_checkpoint = (
                isinstance(journal.purge_backup, dict)
                and set(journal.purge_backup)
                == {
                    "version",
                    "setup_id",
                    "recovery_directory",
                    "backup",
                    "recovery_receipt",
                    "backup_receipt",
                }
                and journal.purge_backup.get("version") == 1
                and journal.purge_backup.get("setup_id") == journal.setup_id
            )
            if durable_checkpoint or journal.status in {
                "rolling_back",
                "rolled_back",
                "rollback_failed",
                "uninstalled",
            }:
                raise SetupError(
                    "setup has a durable purge checkpoint; finish purge before applying again"
                )
        if journal.status in {"rolling_back", "rolled_back", "rollback_failed"}:
            raise SetupError("setup is in rollback state; finish rollback before applying again")
        if journal.purge_backup is not None:
            journal.purge_backup = None
            self.store.save(journal)
        self.validate_private_paths(spec, journal=journal)
        if journal.status == "completed":
            try:
                self.platform.apply("owner_bootstrap", spec, journal.setup_id)
            except Exception as exc:
                raise SetupError("completed setup owner reconciliation failed") from exc
            return journal
        integration_names = {"services", "hermes_profiles", "owner_bootstrap"}
        reinstalling_integrations = journal.status == "uninstalled" or (
            journal.status in {"applying", "failed"}
            and any(
                record.name in integration_names and record.status == "rolled_back"
                for record in journal.steps
            )
            and all(
                record.status == "completed"
                for record in journal.steps
                if record.name not in integration_names
            )
        )
        journal.status = "applying"
        self.store.save(journal)
        for record in journal.steps:
            if record.status == "completed":
                continue
            if record.status == "rolled_back" and reinstalling_integrations:
                pass
            elif record.status in {"rolling_back", "rolled_back", "rollback_failed"}:
                raise SetupError("setup journal contains an incompatible rollback step")
            record.status = "applying"
            record.attempts += 1
            record.error_kind = None
            self.store.save(journal)
            try:
                self.platform.apply(record.name, spec, journal.setup_id)
            except Exception as exc:
                record.status = "failed"
                record.error_kind = type(exc).__name__
                journal.status = "failed"
                self.store.save(journal)
                raise SetupError(f"setup step {record.name!r} failed") from exc
            record.status = "completed"
            self.store.save(journal)
        journal.status = "completed"
        self.store.save(journal)
        return journal

    def validate_private_paths(
        self,
        spec: SetupSpec,
        *,
        journal: SetupJournal | None = None,
    ) -> SetupJournal:
        selected = self.store.load() if journal is None else journal
        self._require_spec(selected, spec)
        if selected.step("private_paths").status == "completed":
            self.platform.validate_private_paths(spec, selected.setup_id)
        return selected

    def mark_pending_services_rolled_back_for_purge(self, spec: SetupSpec) -> SetupJournal:
        """Durably record that a never-applied service step needs no rollback."""

        journal = self.store.load()
        self._require_spec(journal, spec)
        self.validate_private_paths(spec, journal=journal)
        record = journal.step("services")
        if record.status == "rolled_back":
            return journal
        if record.status != "pending":
            raise SetupError("pending-service purge transition is no longer applicable")
        record.status = "rolled_back"
        record.error_kind = None
        journal.status = "rolling_back"
        try:
            self.store.save(journal)
        except Exception as exc:
            record.status = "pending"
            raise SetupError("could not durably quiesce a pending service step") from exc
        return journal

    def quiesce_services_for_purge(self, spec: SetupSpec) -> SetupJournal:
        """Durably stop managed writers while keeping ordinary setup resume possible."""

        journal = self.store.load()
        self._require_spec(journal, spec)
        self.validate_private_paths(spec, journal=journal)
        record = journal.step("services")
        if journal.status == "uninstalled" and record.status == "rolled_back":
            return journal
        other_steps_completed = all(
            candidate.status == "completed"
            for candidate in journal.steps
            if candidate.name != "services"
        )
        starting = (
            journal.status == "completed" and record.status == "completed" and other_steps_completed
        )
        retrying = (
            journal.status == "failed"
            and record.status
            in {"applying", "failed", "rolling_back", "rollback_failed", "rolled_back"}
            and other_steps_completed
        )
        if not starting and not retrying:
            raise SetupError("purge quiesce requires one completed service setup")
        if record.status == "rolled_back":
            return journal

        previous_status = journal.status
        previous_record_status = record.status
        previous_error_kind = record.error_kind
        record.status = "rolling_back"
        record.attempts += 1
        record.error_kind = None
        journal.status = "failed"
        try:
            self.store.save(journal)
        except Exception as exc:
            journal.status = previous_status
            record.status = previous_record_status
            record.error_kind = previous_error_kind
            record.attempts -= 1
            raise SetupError("could not durably begin purge quiesce") from exc

        try:
            self.platform.rollback("services", spec, journal.setup_id)
        except Exception as exc:
            record.status = "rollback_failed"
            record.error_kind = type(exc).__name__
            self.store.save(journal)
            raise SetupError("managed services could not be quiesced for purge") from exc

        record.status = "rolled_back"
        record.error_kind = None
        self.store.save(journal)
        return journal

    def rollback(self, spec: SetupSpec) -> SetupJournal:
        return self.rollback_steps(
            spec,
            reversed(SETUP_STEPS),
            final_status="rolled_back",
        )

    def rollback_steps(
        self,
        spec: SetupSpec,
        steps: Iterable[str],
        *,
        final_status: JournalStatus,
    ) -> SetupJournal:
        step_names = tuple(steps)
        unsupported = [name for name in step_names if name not in SETUP_STEPS]
        if unsupported:
            raise SetupError(f"unsupported setup step: {unsupported[0]}")
        journal = self.store.load()
        self._require_spec(journal, spec)
        self.validate_private_paths(spec, journal=journal)
        previous_status = journal.status
        journal.status = "rolling_back"
        try:
            self.store.save(journal)
        except Exception as exc:
            journal.status = previous_status
            raise SetupError("could not durably begin rollback") from exc
        failures: list[str] = []
        for name in step_names:
            record = journal.step(name)
            if record.status in {"pending", "rolled_back"}:
                continue
            if record.status not in {
                "applying",
                "completed",
                "failed",
                "rolling_back",
                "rollback_failed",
            }:
                continue
            record.status = "rolling_back"
            self.store.save(journal)
            try:
                self.platform.rollback(record.name, spec, journal.setup_id)
            except Exception as exc:
                record.status = "rollback_failed"
                record.error_kind = type(exc).__name__
                failures.append(record.name)
                self.store.save(journal)
                break
            else:
                record.status = "rolled_back"
                record.error_kind = None
                self.store.save(journal)
        journal.status = "rollback_failed" if failures else final_status
        self.store.save(journal)
        if failures:
            raise SetupError("setup rollback failed for: " + ", ".join(failures))
        return journal

    @staticmethod
    def _require_spec(journal: SetupJournal, spec: SetupSpec) -> None:
        persisted = dict(journal.spec)
        persisted.pop("open_browser", None)
        persisted.setdefault("policy_mode", "deny")
        requested = spec.document()
        requested.pop("open_browser")
        accepted_digests = {spec.digest}
        if spec.policy_mode == "deny":
            accepted_digests.add(spec.legacy_deny_digest)
        if journal.spec_digest not in accepted_digests or persisted != requested:
            raise SetupError("setup journal belongs to a different setup specification")


def _new_setup_id() -> str:
    return "setup_" + secrets.token_urlsafe(18)


_STEP_STATUSES = frozenset(
    {
        "pending",
        "applying",
        "completed",
        "failed",
        "rolling_back",
        "rolled_back",
        "rollback_failed",
    }
)
_JOURNAL_STATUSES = frozenset(
    {
        "planned",
        "applying",
        "failed",
        "completed",
        "rolling_back",
        "rolled_back",
        "rollback_failed",
        "uninstalled",
    }
)
