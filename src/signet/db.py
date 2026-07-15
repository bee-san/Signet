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
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:  # pragma: no cover - selection depends on the runtime build
    import pysqlite3 as sqlite3  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - CPython's bundled driver is normal
    import sqlite3


IntegrityError = sqlite3.IntegrityError
LATEST_SCHEMA_VERSION = 6
MIN_SUPPORTED_SCHEMA_VERSION = 1
MINIMUM_SQLITE_VERSION = (3, 51, 3)
_MIGRATION_PATTERN = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


class DatabaseError(RuntimeError):
    pass


class IncompatibleSchemaError(DatabaseError):
    pass


class MigrationIntegrityError(DatabaseError):
    pass


MigrationFaultInjector = Callable[[str], None]
PreMigrationBackup = Callable[["Database", int], None]
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
        self.path = Path(path)
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

        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        _require_local_filesystem(self.path.parent)
        if self.path.is_symlink():
            raise DatabaseError("the approval database may not be a symbolic link")
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        os.chmod(self.path, 0o600)

        with self._maintenance_lock():
            self._initialize_locked(
                fault_injector=fault_injector,
                pre_migration_backup=pre_migration_backup,
            )

        os.chmod(self.path, 0o600)

    def _initialize_locked(
        self,
        *,
        fault_injector: MigrationFaultInjector | None,
        pre_migration_backup: PreMigrationBackup | None,
    ) -> None:
        connection = self._connect()
        try:
            journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise DatabaseError(f"SQLite refused WAL mode: {journal_mode!r}")
            connection.execute("PRAGMA synchronous=FULL")

            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current > LATEST_SCHEMA_VERSION:
                raise IncompatibleSchemaError(
                    f"database schema {current} is newer than supported "
                    f"schema {LATEST_SCHEMA_VERSION}"
                )

            migrations = self._migration_files()
            if current and current not in migrations:
                raise IncompatibleSchemaError(
                    f"no migration definition is available for schema {current}"
                )

            if 0 < current < LATEST_SCHEMA_VERSION:
                if pre_migration_backup is None:
                    raise MigrationIntegrityError(
                        "a verified pre-migration backup callback is required"
                    )
                pre_migration_backup(self, current)

            for version in range(current + 1, LATEST_SCHEMA_VERSION + 1):
                migration = migrations.get(version)
                if migration is None:
                    raise MigrationIntegrityError(f"ordered migration {version:04d} is missing")
                self._apply_migration(
                    connection,
                    version,
                    migration,
                    fault_injector=fault_injector,
                )

            self._verify_applied_migrations(connection, migrations)
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_keys = tuple(connection.execute("PRAGMA foreign_key_check"))
            if fault_injector is not None:
                fault_injector("migration:postcheck")
            if integrity != "ok" or foreign_keys:
                raise MigrationIntegrityError("post-migration database integrity check failed")
        finally:
            connection.close()

    @contextmanager
    def _maintenance_lock(self) -> Iterator[None]:
        lock_path = self.path.with_name(f".{self.path.name}.maintenance.lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

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
    def transaction(self, *, mode: str = "IMMEDIATE") -> Iterator[Any]:
        if mode not in {"DEFERRED", "IMMEDIATE", "EXCLUSIVE"}:
            raise ValueError(f"unsupported SQLite transaction mode: {mode}")
        connection = self._connect()
        try:
            connection.execute(f"BEGIN {mode}")
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

        destination_path = Path(destination)
        if destination_path.resolve() == self.path.resolve():
            raise DatabaseError("a backup snapshot must use a separate path")
        destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination_path.parent, 0o700)
        if destination_path.exists() or destination_path.is_symlink():
            raise DatabaseError("backup snapshot destination already exists")
        temporary = destination_path.with_name(f".{destination_path.name}.partial")
        if temporary.exists() or temporary.is_symlink():
            raise DatabaseError("backup snapshot temporary path already exists")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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

        os.chmod(temporary, 0o600)
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
            connection.execute(f"PRAGMA busy_timeout={expected_timeout}")
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

    def _apply_migration(
        self,
        connection: Any,
        version: int,
        path: Path,
        *,
        fault_injector: MigrationFaultInjector | None,
    ) -> None:
        script = path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
        connection.execute("BEGIN EXCLUSIVE")
        try:
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
            connection.execute(f"PRAGMA user_version={version}")
            if fault_injector is not None:
                fault_injector(f"migration:{version}:before_commit")
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
