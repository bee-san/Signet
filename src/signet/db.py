"""SQLite connection and ordered migration management.

Every writer uses its own connection configured for WAL and FULL synchronous
commits.  SQLite serializes the short ``BEGIN IMMEDIATE`` transactions used by
the state machine, which gives compare-and-swap operations a process-safe
boundary without retaining a global Python lock.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from signet.private_paths import (
    PrivatePathError,
    ensure_owned_directory,
    ensure_private_directory,
    require_no_acl_grants,
)

try:  # pragma: no cover - selection depends on the runtime build
    import pysqlite3 as sqlite3  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - CPython's bundled driver is normal
    import sqlite3

IntegrityError = sqlite3.IntegrityError
LATEST_SCHEMA_VERSION = 19
MIN_SUPPORTED_SCHEMA_VERSION = 1
MINIMUM_SQLITE_VERSION = (3, 51, 3)
_MIGRATION_PATTERN = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
_CONNECTION_CLOSE_FAILURE_NOTE = (
    "The SQLite connection close outcome could not be confirmed; stop Signet processes and "
    "verify the database before retrying."
)
_LOCK_RELEASE_FAILURE_NOTE = (
    "The database maintenance-lock release outcome could not be confirmed; stop Signet "
    "processes and inspect the private maintenance lock before retrying."
)
_LOCK_CLOSE_FAILURE_NOTE = (
    "The database maintenance-lock descriptor close outcome could not be confirmed; stop "
    "Signet processes and inspect the private maintenance lock before retrying."
)
DATABASE_OPERATOR_RECOVERY_NOTES = frozenset(
    {
        _CONNECTION_CLOSE_FAILURE_NOTE,
        _LOCK_RELEASE_FAILURE_NOTE,
        _LOCK_CLOSE_FAILURE_NOTE,
    }
)
_BEGIN_STATEMENTS = {
    "DEFERRED": "BEGIN DEFERRED",
    "IMMEDIATE": "BEGIN IMMEDIATE",
    "EXCLUSIVE": "BEGIN EXCLUSIVE",
}
_USER_VERSION_STATEMENTS = {
    version: f"PRAGMA user_version={version}"
    for version in range(MIN_SUPPORTED_SCHEMA_VERSION, LATEST_SCHEMA_VERSION + 1)
}


class DatabaseError(RuntimeError):
    pass


class DatabaseRecoveryNoteCarrier:
    """Marker for bounded operator errors that safely surface database recovery notes."""


class DatabaseFinalizationStateUnknown(DatabaseError):
    """Database work completed or failed, but required finalization is uncertain."""

    def operator_message(self) -> str:
        return str(self)


class IncompatibleSchemaError(DatabaseError):
    pass


class MigrationIntegrityError(DatabaseError):
    pass


class PreMigrationBackupRequired(MigrationIntegrityError):
    pass


@dataclass(frozen=True, slots=True)
class MigrationBackupReceipt:
    database_path: Path
    source_schema_version: int
    artifact_path: Path
    artifact_sha256: str
    verified_restore_schema_version: int


MigrationFaultInjector = Callable[[str], None]
PreMigrationBackup = Callable[["Database", int], MigrationBackupReceipt]
_NETWORK_FILESYSTEMS = {
    "9p",
    "afs",
    "cifs",
    "fuse.sshfs",
    "nfs",
    "nfs4",
    "smbfs",
}


class Database:
    """A connection factory with strict durability and schema checks."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        timeout: float = 30.0,
    ):
        if timeout < 0.1 or timeout > 60:
            raise ValueError("SQLite timeout must be between 0.1 and 60 seconds")
        self.path = Path(path).expanduser().absolute()
        self.timeout = timeout

    @property
    def migrations_path(self) -> Path:
        return Path(__file__).with_name("migrations")

    def initialize(
        self,
        *,
        fault_injector: MigrationFaultInjector | None = None,
        pre_migration_backup: PreMigrationBackup | None = None,
    ) -> None:
        """Create or migrate the database and verify all applied checksums.

        The schema version is inspected before any migration is attempted.  A
        database created by newer code is refused rather than opened with a
        partially understood state machine.
        """

        try:
            parent = ensure_private_directory(self.path.parent)
        except PrivatePathError as exc:
            raise DatabaseError("the database parent must be an owned mode-0700 directory") from exc
        self.path = parent / self.path.name
        _require_local_filesystem(self.path.parent)
        if self.path.is_symlink():
            raise DatabaseError("the approval database may not be a symbolic link")
        if not self.path.exists():
            try:
                descriptor = os.open(
                    self.path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
            except FileExistsError:
                # Another initializer won the O_EXCL publication race.
                descriptor = None
            if descriptor is not None:
                creation_error: BaseException | None = None
                try:
                    os.fchmod(descriptor, 0o600)
                    require_no_acl_grants(descriptor)
                except BaseException as exc:
                    creation_error = exc
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    if creation_error is None:
                        creation_error = exc
                if creation_error is not None:
                    raise DatabaseFinalizationStateUnknown(
                        "the new approval database could not be secured and finalized; stop "
                        "Signet processes and inspect the database path before retrying"
                    ) from creation_error
        _require_private_file(self.path, label="approval database")

        with self._maintenance_lock():
            self._initialize_locked(
                fault_injector=fault_injector,
                pre_migration_backup=pre_migration_backup,
            )

        _require_private_file(self.path, label="approval database")

    def _initialize_locked(
        self,
        *,
        fault_injector: MigrationFaultInjector | None,
        pre_migration_backup: PreMigrationBackup | None,
    ) -> None:
        preflight_version = self._read_schema_version_read_only()
        if preflight_version > LATEST_SCHEMA_VERSION:
            raise IncompatibleSchemaError(
                f"database schema {preflight_version} is newer than supported "
                f"schema {LATEST_SCHEMA_VERSION}"
            )
        connection = self._connect()
        operation_error: BaseException | None = None
        try:
            journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise DatabaseError(f"SQLite refused WAL mode: {journal_mode!r}")
            connection.execute("PRAGMA synchronous=FULL")

            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current != preflight_version:
                raise MigrationIntegrityError("database schema changed during migration preflight")

            migrations = self._migration_files()
            if current and current not in migrations:
                raise IncompatibleSchemaError(
                    f"no migration definition is available for schema {current}"
                )

            if current:
                self._verify_applied_migrations(connection, migrations)
                self._verify_database_integrity(connection)

            if 0 < current < LATEST_SCHEMA_VERSION:
                if pre_migration_backup is None:
                    raise PreMigrationBackupRequired(
                        "a verified pre-migration backup callback is required"
                    )
                receipt = pre_migration_backup(self, current)
                self._verify_migration_backup_receipt(receipt, current)

            if current < LATEST_SCHEMA_VERSION:
                self._apply_migrations(
                    connection,
                    current,
                    migrations,
                    fault_injector=fault_injector,
                )

            self._complete_privacy_maintenance(connection, fault_injector=fault_injector)

            self._verify_applied_migrations(connection, migrations)
            self._verify_database_integrity(connection)
            if fault_injector is not None:
                fault_injector("migration:postcheck")
        except BaseException as exc:
            operation_error = exc

        close_error: BaseException | None = None
        try:
            connection.close()
        except BaseException as exc:
            close_error = exc

        if operation_error is not None:
            if close_error is not None:
                operation_error.add_note(_CONNECTION_CLOSE_FAILURE_NOTE)
                if not isinstance(operation_error, DatabaseRecoveryNoteCarrier):
                    raise DatabaseFinalizationStateUnknown(
                        "database maintenance failed, and the SQLite connection close outcome "
                        "could not be confirmed; stop Signet processes and verify the database "
                        "before retrying"
                    ) from operation_error
            raise operation_error.with_traceback(operation_error.__traceback__)
        if close_error is not None:
            raise DatabaseFinalizationStateUnknown(
                "database maintenance completed, but the SQLite connection close outcome "
                "could not be confirmed; stop Signet processes and verify the database "
                "before retrying"
            ) from close_error

    @staticmethod
    def _complete_privacy_maintenance(
        connection: Any,
        *,
        fault_injector: MigrationFaultInjector | None,
    ) -> None:
        tables = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'table' AND name IN (
                    'privacy_maintenance',
                    'attachment_metadata_privacy_maintenance'
                )
                """
            ).fetchall()
        }
        pending = False
        if "privacy_maintenance" in tables:
            row = connection.execute(
                """
                SELECT pending FROM privacy_maintenance
                WHERE maintenance_name = 'structured_decision_reasons'
                """
            ).fetchone()
            pending = row is not None and int(row[0]) != 0
        if "attachment_metadata_privacy_maintenance" in tables:
            row = connection.execute(
                """
                SELECT pending FROM attachment_metadata_privacy_maintenance
                WHERE singleton = 1
                """
            ).fetchone()
            pending = pending or (row is not None and int(row[0]) != 0)
        if not pending:
            return
        if fault_injector is not None:
            fault_injector("privacy-maintenance:before-vacuum")
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or int(checkpoint[0]) != 0:
            raise MigrationIntegrityError("privacy maintenance could not checkpoint the database")
        connection.execute("VACUUM")
        if fault_injector is not None:
            fault_injector("privacy-maintenance:after-vacuum")
        connection.execute("BEGIN IMMEDIATE")
        try:
            if "privacy_maintenance" in tables:
                connection.execute(
                    """
                    UPDATE privacy_maintenance SET pending = 0
                    WHERE maintenance_name = 'structured_decision_reasons' AND pending = 1
                    """
                )
            if "attachment_metadata_privacy_maintenance" in tables:
                connection.execute(
                    """
                    UPDATE attachment_metadata_privacy_maintenance SET pending = 0
                    WHERE singleton = 1 AND pending = 1
                    """
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or int(checkpoint[0]) != 0:
            raise MigrationIntegrityError("privacy maintenance could not finalize its checkpoint")
        if fault_injector is not None:
            fault_injector("privacy-maintenance:complete")

    @contextmanager
    def _maintenance_lock(self) -> Iterator[None]:
        lock_path = self.path.with_name(f".{self.path.name}.maintenance.lock")
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        lock_acquired = False
        operation_error: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != current_uid
                or metadata.st_nlink != 1
            ):
                raise DatabaseError("the database maintenance lock is unsafe")
            os.fchmod(descriptor, 0o600)
            try:
                require_no_acl_grants(descriptor)
            except PrivatePathError as exc:
                raise DatabaseError("the database maintenance lock is unsafe") from exc
            if not _private_file_metadata(os.fstat(descriptor)):
                raise DatabaseError("the database maintenance lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            lock_acquired = True
            yield
        except BaseException as exc:
            operation_error = exc

        unlock_error: BaseException | None = None
        if lock_acquired:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except BaseException as exc:
                unlock_error = exc

        close_error: BaseException | None = None
        try:
            os.close(descriptor)
        except BaseException as exc:
            close_error = exc

        if operation_error is not None:
            if unlock_error is not None:
                operation_error.add_note(_LOCK_RELEASE_FAILURE_NOTE)
            if close_error is not None:
                operation_error.add_note(_LOCK_CLOSE_FAILURE_NOTE)
            if (unlock_error is not None or close_error is not None) and not isinstance(
                operation_error, DatabaseRecoveryNoteCarrier
            ):
                primary = (
                    operation_error.operator_message()
                    if isinstance(operation_error, DatabaseFinalizationStateUnknown)
                    else "database operation failed"
                )
                raise DatabaseFinalizationStateUnknown(
                    f"{primary}; additionally, maintenance-lock finalization could not be "
                    "confirmed; stop Signet processes and inspect the private maintenance lock "
                    "before retrying"
                ) from operation_error
            raise operation_error.with_traceback(operation_error.__traceback__)

        if unlock_error is not None or close_error is not None:
            if unlock_error is not None and close_error is not None:
                detail = "maintenance-lock release and descriptor close"
                finalizer_error = unlock_error
            elif unlock_error is not None:
                detail = "maintenance-lock release"
                finalizer_error = unlock_error
            else:
                detail = "maintenance-lock descriptor close"
                assert close_error is not None
                finalizer_error = close_error
            raise DatabaseFinalizationStateUnknown(
                f"database maintenance completed, but the {detail} outcome could not be "
                "confirmed; stop Signet processes and inspect the private maintenance lock "
                "before retrying"
            ) from finalizer_error

    def connect(self) -> Any:
        """Return a configured caller-owned connection."""

        return self._connect()

    @contextmanager
    def read(self) -> Iterator[Any]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def read_only(self) -> Iterator[Any]:
        """Open one stable snapshot, including committed live-WAL frames when present."""

        if not self.path.is_absolute():
            raise DatabaseError("read-only database path must be absolute")
        snapshot_directory = Path(tempfile.mkdtemp(prefix="signet-read-only-"))
        try:
            snapshot_directory.chmod(0o700)
            _require_private_snapshot_directory(snapshot_directory)
            database_path = _copy_stable_database_snapshot(
                self.path,
                snapshot_directory,
            )
        except BaseException:
            _remove_read_only_snapshot(snapshot_directory)
            raise
        try:
            connection = sqlite3.connect(
                f"{database_path.as_uri()}?mode=ro",
                uri=True,
                timeout=self.timeout,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            _remove_read_only_snapshot(snapshot_directory)
            raise DatabaseError("database is unavailable for read-only inspection") from exc
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
            connection.execute("BEGIN")
            yield connection
        finally:
            _finalize_read_only_connection(connection, snapshot_directory)

    @contextmanager
    def transaction(self, *, mode: str = "IMMEDIATE") -> Iterator[Any]:
        begin = _BEGIN_STATEMENTS.get(mode)
        if begin is None:
            raise ValueError(f"unsupported SQLite transaction mode: {mode}")
        connection = self._connect()
        try:
            connection.execute(begin)
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def pragma_values(self) -> dict[str, int | str]:
        with self.read() as connection:
            return {
                "journal_mode": str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).lower(),
                "synchronous": int(connection.execute("PRAGMA synchronous").fetchone()[0]),
                "foreign_keys": int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
            }

    def integrity_check(self) -> tuple[str, tuple[Any, ...]]:
        with self.read() as connection:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_keys = tuple(
                tuple(row) for row in connection.execute("PRAGMA foreign_key_check")
            )
        return integrity, foreign_keys

    def create_snapshot(self, destination: str | os.PathLike[str]) -> Path:
        """Create and verify a mode-0600 SQLite backup at a separate path.

        Encryption and the attachment manifest are layered by the backup bundle
        service; this primitive never labels an unencrypted snapshot as a usable
        deployment backup.
        """

        destination_path = Path(destination).expanduser().absolute()
        if destination_path.resolve() == self.path.resolve():
            raise DatabaseError("a backup snapshot must use a separate path")
        try:
            ensure_owned_directory(destination_path.parent)
        except PrivatePathError as exc:
            raise DatabaseError(
                "backup snapshot parent must be owned and not writable by others"
            ) from exc
        if destination_path.exists() or destination_path.is_symlink():
            raise DatabaseError("backup snapshot destination already exists")
        temporary = destination_path.with_name(f".{destination_path.name}.partial")
        if temporary.exists() or temporary.is_symlink():
            raise DatabaseError("backup snapshot temporary path already exists")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)

        source = self._connect()
        target = sqlite3.connect(str(temporary), isolation_level=None)
        try:
            source.backup(target)
            target.execute("PRAGMA foreign_keys=ON")
            integrity = str(target.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_keys = tuple(target.execute("PRAGMA foreign_key_check"))
            if integrity != "ok" or foreign_keys:
                raise DatabaseError("backup snapshot failed integrity verification")
        except BaseException:
            target.close()
            temporary.unlink(missing_ok=True)
            raise
        else:
            target.close()
        finally:
            source.close()

        _require_private_file(temporary, label="backup snapshot")
        descriptor = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, destination_path)
        directory = os.open(destination_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return destination_path

    @staticmethod
    def verify_snapshot(path: str | os.PathLike[str]) -> None:
        snapshot = Path(path)
        if not snapshot.is_file() or snapshot.is_symlink():
            raise DatabaseError("backup snapshot is not a regular file")
        connection = sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_keys = tuple(connection.execute("PRAGMA foreign_key_check"))
        finally:
            connection.close()
        if integrity != "ok" or foreign_keys:
            raise DatabaseError("backup snapshot failed integrity verification")

    def _read_schema_version_read_only(self) -> int:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(self.path, flags)
        try:
            header = os.read(descriptor, 100)
        finally:
            os.close(descriptor)
        if not header:
            return 0
        if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
            raise MigrationIntegrityError("database header is missing or invalid")
        header_version = int.from_bytes(header[60:64], byteorder="big")
        if not Path(f"{self.path}-wal").exists():
            return header_version
        try:
            connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=ro",
                uri=True,
                timeout=self.timeout,
            )
            try:
                return int(connection.execute("PRAGMA user_version").fetchone()[0])
            finally:
                connection.close()
        except sqlite3.DatabaseError as exc:
            raise MigrationIntegrityError("database schema version could not be read") from exc

    def _verify_migration_backup_receipt(
        self,
        receipt: MigrationBackupReceipt,
        current_version: int,
    ) -> None:
        if not isinstance(receipt, MigrationBackupReceipt):
            raise MigrationIntegrityError("pre-migration backup did not return a verified receipt")
        if (
            receipt.database_path.resolve() != self.path.resolve()
            or receipt.source_schema_version != current_version
            or receipt.verified_restore_schema_version != current_version
            or not receipt.artifact_path.is_absolute()
        ):
            raise MigrationIntegrityError("pre-migration backup receipt is inconsistent")
        artifact_path = receipt.artifact_path.resolve()
        live_paths = tuple(
            candidate.resolve()
            for candidate in (
                self.path,
                Path(f"{self.path}-wal"),
                Path(f"{self.path}-shm"),
            )
        )
        if artifact_path in live_paths:
            raise MigrationIntegrityError("pre-migration backup receipt is inconsistent")
        _require_private_file(receipt.artifact_path, label="pre-migration backup artifact")
        if any(
            candidate.exists() and receipt.artifact_path.samefile(candidate)
            for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm"))
        ):
            raise MigrationIntegrityError("pre-migration backup receipt is inconsistent")
        if receipt.artifact_path.stat().st_size <= 0:
            raise MigrationIntegrityError("pre-migration backup artifact is empty")
        actual_digest = _file_sha256(receipt.artifact_path)
        if actual_digest != receipt.artifact_sha256:
            raise MigrationIntegrityError("pre-migration backup artifact digest is inconsistent")

    @staticmethod
    def _verify_database_integrity(connection: Any) -> None:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = tuple(connection.execute("PRAGMA foreign_key_check"))
        if integrity != "ok" or foreign_keys:
            raise MigrationIntegrityError("database integrity verification failed")

    def _connect(self) -> Any:
        current_version = tuple(int(part) for part in sqlite3.sqlite_version.split(".")[:3])
        if current_version < MINIMUM_SQLITE_VERSION:
            required = ".".join(str(part) for part in MINIMUM_SQLITE_VERSION)
            installed = ".".join(str(part) for part in current_version)
            raise DatabaseError(f"SQLite {required} or newer is required; found {installed}")
        connection = sqlite3.connect(
            str(self.path),
            timeout=self.timeout,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            connection.row_factory = sqlite3.Row
            expected_timeout = int(self.timeout * 1000)
            connection.execute("PRAGMA foreign_keys=ON")
            journal_mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            connection.execute("PRAGMA synchronous=FULL")
            if sys.platform == "darwin":
                connection.execute("PRAGMA fullfsync=ON")
            actual_timeout = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
            foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
            if (
                journal_mode != "wal"
                or synchronous != 2
                or foreign_keys != 1
                or actual_timeout != expected_timeout
            ):
                raise DatabaseError("SQLite refused required durability settings")
            if (
                sys.platform == "darwin"
                and int(connection.execute("PRAGMA fullfsync").fetchone()[0]) != 1
            ):
                raise DatabaseError("SQLite refused fullfsync on macOS")
            return connection
        except BaseException:
            connection.close()
            raise

    def _migration_files(self) -> dict[int, Path]:
        migrations: dict[int, Path] = {}
        if not self.migrations_path.is_dir():
            raise MigrationIntegrityError(f"migration directory is missing: {self.migrations_path}")
        for path in sorted(self.migrations_path.iterdir()):
            match = _MIGRATION_PATTERN.match(path.name)
            if match is None:
                continue
            version = int(match.group(1))
            if version in migrations:
                raise MigrationIntegrityError(f"duplicate migration version {version}: {path.name}")
            migrations[version] = path
        return migrations

    def _apply_migrations(
        self,
        connection: Any,
        current_version: int,
        migrations: dict[int, Path],
        *,
        fault_injector: MigrationFaultInjector | None,
    ) -> None:
        connection.execute("BEGIN EXCLUSIVE")
        try:
            for version in range(current_version + 1, LATEST_SCHEMA_VERSION + 1):
                path = migrations.get(version)
                if path is None:
                    raise MigrationIntegrityError(f"ordered migration {version:04d} is missing")
                script = path.read_text(encoding="utf-8")
                checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
                if fault_injector is not None:
                    fault_injector(f"migration:{version}:started")
                for index, statement in enumerate(_sql_statements(script), start=1):
                    connection.execute(statement)
                    if fault_injector is not None:
                        fault_injector(f"migration:{version}:statement:{index}")
                connection.execute(
                    """
                    INSERT INTO schema_meta(
                        migration_id, checksum, applied_at,
                        min_reader_version, max_reader_version
                    ) VALUES (?, ?, unixepoch(), ?, ?)
                    """,
                    (
                        version,
                        checksum,
                        MIN_SUPPORTED_SCHEMA_VERSION,
                        LATEST_SCHEMA_VERSION,
                    ),
                )
                connection.execute(_USER_VERSION_STATEMENTS[version])
                if fault_injector is not None:
                    fault_injector(f"migration:{version}:before_commit")
            self._verify_applied_migrations(connection, migrations)
            self._verify_database_integrity(connection)
            if fault_injector is not None:
                fault_injector("migration:transaction:postcheck")
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise

    def _verify_applied_migrations(
        self,
        connection: Any,
        migrations: dict[int, Path],
    ) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current == 0:
            raise MigrationIntegrityError("database has no applied schema")
        try:
            rows = connection.execute(
                "SELECT migration_id, checksum FROM schema_meta ORDER BY migration_id"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise MigrationIntegrityError("schema_meta is missing or unreadable") from exc

        expected_versions = list(range(1, current + 1))
        actual_versions = [int(row["migration_id"]) for row in rows]
        if actual_versions != expected_versions:
            raise MigrationIntegrityError(
                f"migration history is not contiguous: {actual_versions!r}"
            )
        for row in rows:
            version = int(row["migration_id"])
            path = migrations.get(version)
            if path is None:
                raise MigrationIntegrityError(
                    f"applied migration {version} has no local definition"
                )
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            if row["checksum"] != expected:
                raise MigrationIntegrityError(
                    f"migration {version} checksum does not match the database"
                )


def _require_private_file(path: Path, *, label: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise DatabaseError(f"the {label} is unavailable or unsafe") from exc
    try:
        if not _private_file_metadata(os.fstat(descriptor)):
            raise DatabaseError(f"the {label} must be an owned mode-0600 regular file")
    finally:
        os.close(descriptor)


def _require_private_snapshot_directory(directory: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink < 1
        ):
            raise DatabaseError("read-only snapshot directory is unsafe")
        require_no_acl_grants(descriptor)
    except (OSError, PrivatePathError) as exc:
        raise DatabaseError("read-only snapshot directory is unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _finalize_read_only_connection(connection: Any, snapshot_directory: Path) -> None:
    primary = sys.exception()
    failures: list[BaseException] = []
    try:
        if connection.in_transaction:
            connection.rollback()
    except BaseException as exc:
        failures.append(exc)
    try:
        connection.close()
    except BaseException as exc:
        failures.append(exc)
    try:
        _remove_read_only_snapshot(snapshot_directory)
    except BaseException as exc:
        failures.append(exc)
    if not failures:
        return
    note = "read-only database cleanup encountered: " + ", ".join(
        type(failure).__name__ for failure in failures
    )
    if primary is not None:
        primary.add_note(note)
        return
    error = DatabaseError("read-only database cleanup did not complete")
    for failure in failures[1:]:
        error.add_note(type(failure).__name__)
    raise error from failures[0]


def _remove_read_only_snapshot(directory: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != current_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise DatabaseError("read-only database snapshot directory changed during cleanup")
        for name in os.listdir(descriptor):
            entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(entry.st_mode)
                or entry.st_uid != current_uid
                or entry.st_nlink != 1
                or stat.S_IMODE(entry.st_mode) != 0o600
            ):
                raise DatabaseError("read-only database snapshot contains an unsafe artifact")
            os.unlink(name, dir_fd=descriptor)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DatabaseError("read-only database snapshot could not be removed safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        directory.rmdir()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DatabaseError("read-only database snapshot directory could not be removed") from exc


def _copy_stable_database_snapshot(source: Path, destination: Path) -> Path:
    snapshot = destination / source.name
    snapshot_wal = Path(f"{snapshot}-wal")
    source_wal = Path(f"{source}-wal")
    for _ in range(8):
        main_descriptor = -1
        wal_descriptor = -1
        try:
            opened_main = _open_snapshot_source(source, "database")
            if opened_main is None:  # pragma: no cover - required source invariant
                raise FileNotFoundError(source)
            main_descriptor, before_main = opened_main
            opened_wal = _open_snapshot_source(source_wal, "database WAL", optional=True)
            if opened_wal is None:
                before_wal = None
            else:
                wal_descriptor, before_wal = opened_wal

            copied_main_digest = _copy_descriptor_to_private_file(
                main_descriptor,
                snapshot,
            )
            copied_wal_digest = (
                _copy_descriptor_to_private_file(wal_descriptor, snapshot_wal)
                if before_wal is not None
                else None
            )
            after_main = os.fstat(main_descriptor)
            after_wal = os.fstat(wal_descriptor) if before_wal is not None else None
            stable = (
                _stable_copy_identity(before_main) == _stable_copy_identity(after_main)
                and _optional_stable_copy_identity(before_wal)
                == _optional_stable_copy_identity(after_wal)
                and copied_main_digest == _descriptor_sha256(main_descriptor)
                and copied_wal_digest
                == (_descriptor_sha256(wal_descriptor) if before_wal is not None else None)
                and _descriptor_still_names_path(source, main_descriptor)
                and (
                    _descriptor_still_names_path(source_wal, wal_descriptor)
                    if before_wal is not None
                    else not source_wal.exists() and not source_wal.is_symlink()
                )
            )
        except FileNotFoundError:
            stable = False
        finally:
            _close_snapshot_descriptors(wal_descriptor, main_descriptor)
        if stable:
            return snapshot
        else:
            snapshot.unlink(missing_ok=True)
            snapshot_wal.unlink(missing_ok=True)
    raise DatabaseError("database changed during read-only snapshot")


def _close_snapshot_descriptors(*descriptors: int) -> None:
    primary = sys.exception()
    failures: list[OSError] = []
    for descriptor in descriptors:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            failures.append(exc)
    if not failures:
        return
    if primary is not None:
        primary.add_note("one or more database snapshot descriptors could not be closed")
        return
    raise DatabaseError("database snapshot descriptor cleanup did not complete") from failures[0]


def _open_snapshot_source(
    path: Path,
    label: str,
    *,
    optional: bool = False,
) -> tuple[int, os.stat_result] | None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except FileNotFoundError:
        if optional:
            return None
        raise
    except OSError as exc:
        raise DatabaseError(f"the {label} snapshot source is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not _private_file_metadata(metadata) or not _descriptor_still_names_path(
            path,
            descriptor,
        ):
            raise DatabaseError(f"the {label} snapshot source is unavailable or unsafe")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def _copy_descriptor_to_private_file(descriptor: int, destination: Path) -> str:
    output = -1
    digest = hashlib.sha256()
    try:
        output = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(output, 0o600)
        require_no_acl_grants(output)
        os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise OSError("short database snapshot write")
                view = view[written:]
        os.fsync(output)
    except (OSError, PrivatePathError) as exc:
        destination.unlink(missing_ok=True)
        raise DatabaseError("database snapshot could not be copied safely") from exc
    finally:
        if output >= 0:
            os.close(output)
    return digest.hexdigest()


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _descriptor_still_names_path(path: Path, descriptor: int) -> bool:
    try:
        named = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    opened = os.fstat(descriptor)
    return (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino)


def _optional_stable_copy_identity(
    metadata: os.stat_result | None,
) -> tuple[int, ...] | None:
    return _stable_copy_identity(metadata) if metadata is not None else None


def _stable_copy_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _private_file_metadata(metadata: os.stat_result) -> bool:
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata.st_uid == current_uid
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sql_statements(script: str) -> Iterator[str]:
    """Yield complete SQLite statements, including multi-line triggers."""

    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                yield statement
            buffer = ""
    if buffer.strip():
        raise MigrationIntegrityError("migration ends with incomplete SQL")


def _require_local_filesystem(path: Path) -> None:
    """Reject known network filesystems; SQLite WAL requires local locking."""

    if sys.platform == "darwin" and hasattr(os, "ST_LOCAL"):
        if not os.statvfs(path).f_flag & os.ST_LOCAL:
            raise DatabaseError("the approval database requires a local filesystem")
        return
    mounts = Path("/proc/mounts")
    if not mounts.is_file():
        return
    resolved = path.resolve()
    selected_mount = Path("/")
    selected_type = ""
    for line in mounts.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        mount = Path(fields[1].replace("\\040", " ")).resolve()
        if (resolved == mount or mount in resolved.parents) and len(mount.parts) >= len(
            selected_mount.parts
        ):
            selected_mount = mount
            selected_type = fields[2]
    if selected_type in _NETWORK_FILESYSTEMS:
        raise DatabaseError("the approval database requires a local filesystem")
