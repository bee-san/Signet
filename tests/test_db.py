from __future__ import annotations

import hashlib
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

import signet.db as db_module
from signet.auth import (
    TOTP_PROOF_DOMAIN,
    ActionBinding,
    ProofCapability,
    source_rate_limit_key,
    totp_proof_claims,
    totp_rate_limit_key,
)
from signet.backup import BackupError, BackupPublishedWithWarnings
from signet.db import (
    LATEST_SCHEMA_VERSION,
    Database,
    DatabaseError,
    DatabaseFinalizationStateUnknown,
    IncompatibleSchemaError,
    MigrationBackupReceipt,
    MigrationIntegrityError,
)
from signet.models import (
    ApprovalConfirmation,
    ConfirmationKind,
    EnqueueRequest,
    OutcomeClassification,
    ResultAlias,
)
from signet.state_machine import ApprovalStateMachine
from tests.attachment_fixtures import register_catalog_attachment
from tests.migration_helpers import verified_backup_callback

TEST_CAPABILITIES = ProofCapability(b"test-only-proof-capability-key-0001")

CORE_TABLES = {
    "approval_requests",
    "payload_versions",
    "attachments",
    "staged_objects",
    "idempotency_records",
    "execution_attempts",
    "result_aliases",
    "request_events",
    "policy_versions",
    "push_subscriptions",
    "auth_credentials",
    "auth_rate_windows",
    "caller_tokens",
    "mcp_caller_tokens",
    "schema_cache",
    "purge_jobs",
    "schema_meta",
    "notification_outbox_deliveries",
    "plugin_manifests",
    "plugin_active",
    "plugin_tool_mappings",
    "connector_configurations",
    "connector_active",
    "connector_discovery_runs",
    "connector_discovered_tools",
    "connector_tool_state",
    "connector_effect_evidence",
    "connector_effect_review_challenges",
    "connector_effect_review_drafts",
    "connector_effect_reviews",
}


class CloseFailingConnection:
    def __init__(self, connection: Any, close_calls: list[None]):
        self._connection = connection
        self._close_calls = close_calls

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)

    def close(self) -> None:
        self._close_calls.append(None)
        self._connection.close()
        raise OSError("injected raw SQLite close failure")


def totp_confirmation(
    request_id: str,
    *,
    action: str,
    payload_hash: str,
    use_id: str,
    session_id: str,
) -> ApprovalConfirmation:
    binding = ActionBinding(action, request_id, 1, payload_hash)
    rate_key = totp_rate_limit_key("owner")
    source_key = source_rate_limit_key("database-test")
    attempt_id = "database-test-attempt-opaque"
    capability = TEST_CAPABILITIES.seal(
        TOTP_PROOF_DOMAIN,
        totp_proof_claims(
            credential_id="database-test-totp",
            credential_user_id="owner",
            user_id="owner",
            use_id=use_id,
            binding=binding,
            path="web",
            session_id=session_id,
            http_method="POST",
            rate_limit_key=rate_key,
            attempt_id=attempt_id,
            attempt_scope_keys=(rate_key, source_key),
        ),
    )
    return ApprovalConfirmation(
        kind=ConfirmationKind.TOTP,
        use_id=use_id,
        path="web",
        capability=capability,
        user_id="owner",
        action=action,
        bound_request_id=request_id,
        bound_version=1,
        bound_payload_hash=payload_hash,
        session_id=session_id,
        http_method="POST",
        attempt_id=attempt_id,
        attempt_scope_keys=(rate_key, source_key),
        rate_limit_key=rate_key,
        credential_id="database-test-totp",
        credential_user_id="owner",
    )


def test_database_uses_wal_full_sync_foreign_keys_and_private_mode(tmp_path: Path) -> None:
    path = tmp_path / "data" / "approvals.sqlite3"
    database = Database(path)
    database.initialize()

    assert database.pragma_values() == {
        "journal_mode": "wal",
        "synchronous": 2,
        "foreign_keys": 1,
    }
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700
    assert database.integrity_check() == ("ok", ())

    with database.read() as connection:
        tables = {
            row["name"]
            for row in connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
        }
        migrations = connection.execute(
            "SELECT * FROM schema_meta ORDER BY migration_id"
        ).fetchall()
    assert tables >= CORE_TABLES
    assert [migration["migration_id"] for migration in migrations] == list(
        range(1, LATEST_SCHEMA_VERSION + 1)
    )
    assert all(len(migration["checksum"]) == 64 for migration in migrations)


def test_database_refuses_unsafe_existing_parent_without_changing_mode(
    tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o1777)

    with pytest.raises(DatabaseError, match="mode-0700"):
        Database(shared / "approvals.sqlite3").initialize()

    assert os.stat(shared).st_mode & 0o7777 == 0o1777
    assert not (shared / "approvals.sqlite3").exists()


def test_database_refuses_unsafe_existing_file_without_changing_mode(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "data"
    parent.mkdir(mode=0o700)
    path = parent / "approvals.sqlite3"
    path.write_bytes(b"not a private database")
    path.chmod(0o640)

    with pytest.raises(DatabaseError, match="mode-0600"):
        Database(path).initialize()

    assert os.stat(path).st_mode & 0o777 == 0o640


def test_database_refuses_symlinked_parent(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)

    with pytest.raises(DatabaseError, match="mode-0700"):
        Database(linked / "approvals.sqlite3").initialize()

    assert not (target / "approvals.sqlite3").exists()


def test_runtime_refuses_an_unverified_sqlite_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("signet.db.sqlite3.sqlite_version", "3.50.0")
    database = Database(tmp_path / "approvals.sqlite3")
    with pytest.raises(DatabaseError, match="SQLite 3.51.3"):
        database.initialize()


@pytest.mark.parametrize("timeout", [0, 0.09, 61])
def test_database_rejects_unbounded_busy_timeouts(tmp_path: Path, timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        Database(tmp_path / "approvals.sqlite3", timeout=timeout)


def test_concurrent_initializers_share_a_single_maintenance_lock(tmp_path: Path) -> None:
    path = tmp_path / "approvals.sqlite3"
    barrier = Barrier(2)

    def initialize() -> tuple[str, tuple[object, ...]]:
        barrier.wait()
        database = Database(path)
        database.initialize()
        return database.integrity_check()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: initialize(), range(2)))
    assert results == [("ok", ()), ("ok", ())]


def test_backup_snapshot_restores_into_a_separate_verified_path(tmp_path: Path) -> None:
    database = Database(tmp_path / "live" / "approvals.sqlite3")
    database.initialize()
    ApprovalStateMachine(database).enqueue(
        EnqueueRequest(
            request_id="backup-fixture",
            downstream_alias="fastmail",
            tool_name="send_email",
            policy_mode="approval",
            origin_namespace="profile:test",
            encrypted_payload=b"encrypted",
            payload_hash="a" * 64,
            payload_fingerprint="fingerprint",
            pending_result=b'{"status":"pending_approval"}',
            created_at=100,
            expires_at=200,
            policy_version="policy-1",
            adapter_version="adapter-1",
            schema_version="schema-1",
            editor_actor="caller:profile:test",
        )
    )
    snapshot = database.create_snapshot(tmp_path / "backup" / "snapshot.sqlite3")
    assert os.stat(snapshot).st_mode & 0o777 == 0o600
    Database.verify_snapshot(snapshot)

    restored = Database(tmp_path / "restored" / "approvals.sqlite3")
    restored.path.parent.mkdir(parents=True, mode=0o700)
    snapshot.replace(restored.path)
    restored.initialize()
    assert ApprovalStateMachine(restored).get_request("backup-fixture")["state"] == (
        "pending_approval"
    )


def test_migration_failure_is_atomic_and_restartable(tmp_path: Path) -> None:
    path = tmp_path / "approvals.sqlite3"
    database = Database(path)

    def fail_mid_migration(stage: str) -> None:
        if stage == "migration:1:statement:8":
            raise RuntimeError("injected migration crash")

    with pytest.raises(RuntimeError, match="injected"):
        database.initialize(fault_injector=fail_mid_migration)

    connection = database.connect()
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'approval_requests'"
            ).fetchone()[0]
            == 0
        )
    finally:
        connection.close()

    database.initialize()
    assert database.integrity_check() == ("ok", ())


def test_every_initial_migration_statement_is_failure_injected_and_restartable(
    tmp_path: Path,
) -> None:
    from signet.db import _sql_statements

    migration = Database(tmp_path / "probe.sqlite3").migrations_path / "0001_initial.sql"
    statement_count = len(tuple(_sql_statements(migration.read_text(encoding="utf-8"))))
    stages = ["migration:1:started"] + [
        f"migration:1:statement:{index}" for index in range(1, statement_count + 1)
    ]
    stages.append("migration:1:before_commit")
    for index, target_stage in enumerate(stages):
        database = Database(tmp_path / f"fault-{index}" / "approvals.sqlite3")

        def fail(stage: str, target: str = target_stage) -> None:
            if stage == target:
                raise RuntimeError(target)

        with pytest.raises(RuntimeError, match="migration:1"):
            database.initialize(fault_injector=fail)
        database.initialize()
        assert database.integrity_check() == ("ok", ())


def test_retention_trigger_migration_is_atomic_and_restartable(tmp_path: Path) -> None:
    database = Database(tmp_path / "retention-migration" / "approvals.sqlite3")

    def fail_after_trigger_replacement(stage: str) -> None:
        if stage == "migration:4:statement:2":
            raise RuntimeError("injected retention migration crash")

    with pytest.raises(RuntimeError, match="retention migration"):
        database.initialize(fault_injector=fail_after_trigger_replacement)
    with database.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0

    database.initialize()
    with database.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == LATEST_SCHEMA_VERSION
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_schema
            WHERE type = 'trigger' AND name = 'payload_versions_immutable_fields'
            """
        ).fetchone()[0]
    assert "NEW.purged_at IS NOT NULL" in trigger
    assert "NEW.key_destroyed_at IS NOT NULL" in trigger


def test_upgrade_requires_and_runs_a_verified_pre_migration_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signet.db as db_module

    path = tmp_path / "approvals.sqlite3"
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    shutil.copy2(
        Database(path).migrations_path / "0001_initial.sql",
        migrations / "0001_initial.sql",
    )
    (migrations / "0002_upgrade_marker.sql").write_text(
        "CREATE TABLE upgrade_marker (id INTEGER PRIMARY KEY) STRICT;\n",
        encoding="utf-8",
    )

    class UpgradeDatabase(Database):
        @property
        def migrations_path(self) -> Path:
            return migrations

    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 1)
    UpgradeDatabase(path).initialize()
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 2)
    upgrading = UpgradeDatabase(path)
    with pytest.raises(MigrationIntegrityError, match="backup callback"):
        upgrading.initialize()

    backed_up_versions: list[int] = []
    upgrading.initialize(
        pre_migration_backup=verified_backup_callback(
            tmp_path / "pre-migration-backups",
            backed_up_versions,
        )
    )
    assert backed_up_versions == [1]
    with upgrading.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'upgrade_marker'"
            ).fetchone()[0]
            == 1
        )


def test_pre_migration_publication_warning_survives_connection_close_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    with database.transaction() as connection:
        connection.execute(f"PRAGMA user_version={LATEST_SCHEMA_VERSION - 1}")
        connection.execute(
            "DELETE FROM schema_meta WHERE migration_id = ?", (LATEST_SCHEMA_VERSION,)
        )

    original_connect = database._connect
    close_calls: list[None] = []

    monkeypatch.setattr(
        database,
        "_connect",
        lambda: CloseFailingConnection(original_connect(), close_calls),
    )
    warning = BackupPublishedWithWarnings(
        "backup published, but post-publication verification needs operator recovery"
    )

    def report_publication_warning(_database: Database, _version: int) -> None:
        raise warning

    with pytest.raises(BackupPublishedWithWarnings) as caught:
        database.initialize(pre_migration_backup=report_publication_warning)

    assert caught.value is warning
    operator_message = caught.value.operator_message()
    assert "backup published, but post-publication verification needs operator recovery" in (
        operator_message
    )
    assert "SQLite connection close outcome could not be confirmed" in operator_message
    assert "stop Signet processes and verify the database before retrying" in operator_message
    assert "raw SQLite close failure" not in operator_message
    assert len(close_calls) == 1
    assert getattr(caught.value, "__notes__", ()) == [
        "The SQLite connection close outcome could not be confirmed; stop Signet processes and "
        "verify the database before retrying.",
    ]


def test_generic_pre_migration_failure_combined_with_connection_close_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    with database.transaction() as connection:
        connection.execute(f"PRAGMA user_version={LATEST_SCHEMA_VERSION - 1}")
        connection.execute(
            "DELETE FROM schema_meta WHERE migration_id = ?", (LATEST_SCHEMA_VERSION,)
        )

    original_connect = database._connect
    close_calls: list[None] = []
    monkeypatch.setattr(
        database,
        "_connect",
        lambda: CloseFailingConnection(original_connect(), close_calls),
    )

    def fail_before_publication(_database: Database, _version: int) -> None:
        raise BackupError("injected raw pre-migration construction failure")

    with pytest.raises(DatabaseFinalizationStateUnknown) as caught:
        database.initialize(pre_migration_backup=fail_before_publication)

    message = caught.value.operator_message()
    assert "database maintenance failed" in message
    assert "SQLite connection close outcome could not be confirmed" in message
    assert "stop Signet processes and verify the database before retrying" in message
    assert "injected raw" not in message
    assert len(close_calls) == 1


def test_successful_database_maintenance_reports_bounded_connection_close_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    original_connect = database._connect
    close_calls: list[None] = []

    monkeypatch.setattr(
        database,
        "_connect",
        lambda: CloseFailingConnection(original_connect(), close_calls),
    )

    with pytest.raises(DatabaseFinalizationStateUnknown) as caught:
        database._initialize_locked(fault_injector=None, pre_migration_backup=None)

    message = str(caught.value)
    assert "database maintenance completed" in message
    assert "SQLite connection close outcome could not be confirmed" in message
    assert "stop Signet processes and verify the database before retrying" in message
    assert "raw SQLite close failure" not in message
    assert len(close_calls) == 1


def test_pre_migration_publication_warning_survives_all_database_finalizer_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signet.db as db_module

    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    with database.transaction() as connection:
        connection.execute(f"PRAGMA user_version={LATEST_SCHEMA_VERSION - 1}")
        connection.execute(
            "DELETE FROM schema_meta WHERE migration_id = ?", (LATEST_SCHEMA_VERSION,)
        )

    original_connect = database._connect
    real_flock = db_module.fcntl.flock
    real_close = db_module.os.close
    unlock_calls = 0
    connection_close_calls: list[None] = []
    lock_close_calls = 0
    maintenance_descriptor: int | None = None

    def failing_unlock(descriptor: int, operation: int) -> None:
        nonlocal maintenance_descriptor, unlock_calls
        if operation == db_module.fcntl.LOCK_EX:
            maintenance_descriptor = descriptor
        if operation == db_module.fcntl.LOCK_UN:
            unlock_calls += 1
            raise OSError("injected raw lock release failure")
        real_flock(descriptor, operation)

    def failing_close(descriptor: int) -> None:
        nonlocal lock_close_calls
        real_close(descriptor)
        if descriptor == maintenance_descriptor:
            lock_close_calls += 1
            raise OSError("injected raw lock descriptor close failure")

    monkeypatch.setattr(
        database,
        "_connect",
        lambda: CloseFailingConnection(original_connect(), connection_close_calls),
    )
    monkeypatch.setattr(db_module.fcntl, "flock", failing_unlock)
    monkeypatch.setattr(db_module.os, "close", failing_close)
    warning = BackupPublishedWithWarnings(
        "backup published, but post-publication verification needs operator recovery"
    )

    def report_publication_warning(_database: Database, _version: int) -> None:
        raise warning

    with pytest.raises(BackupPublishedWithWarnings) as caught:
        database.initialize(pre_migration_backup=report_publication_warning)

    assert caught.value is warning
    operator_message = caught.value.operator_message()
    assert "backup published, but post-publication verification needs operator recovery" in (
        operator_message
    )
    assert "SQLite connection close outcome could not be confirmed" in operator_message
    assert "maintenance-lock release outcome could not be confirmed" in operator_message
    assert "maintenance-lock descriptor close outcome could not be confirmed" in operator_message
    assert "injected raw" not in operator_message
    assert unlock_calls == 1
    assert len(connection_close_calls) == 1
    assert lock_close_calls == 1
    assert getattr(caught.value, "__notes__", ()) == [
        "The SQLite connection close outcome could not be confirmed; stop Signet processes and "
        "verify the database before retrying.",
        "The database maintenance-lock release outcome could not be confirmed; stop Signet "
        "processes and inspect the private maintenance lock before retrying.",
        "The database maintenance-lock descriptor close outcome could not be confirmed; stop "
        "Signet processes and inspect the private maintenance lock before retrying.",
    ]


@pytest.mark.parametrize(
    ("unlock_fails", "close_fails", "expected_detail"),
    [
        (True, False, "maintenance-lock release outcome"),
        (False, True, "maintenance-lock descriptor close outcome"),
        (True, True, "maintenance-lock release and descriptor close outcome"),
    ],
)
def test_successful_database_maintenance_reports_bounded_lock_finalizer_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unlock_fails: bool,
    close_fails: bool,
    expected_detail: str,
) -> None:
    import signet.db as db_module

    database = Database(tmp_path / "approvals.sqlite3")
    real_flock = db_module.fcntl.flock
    real_close = db_module.os.close
    unlock_calls = 0
    close_calls = 0

    def injected_unlock(descriptor: int, operation: int) -> None:
        nonlocal unlock_calls
        if operation == db_module.fcntl.LOCK_UN:
            unlock_calls += 1
            if unlock_fails:
                raise OSError("injected raw lock release failure")
        real_flock(descriptor, operation)

    def injected_close(descriptor: int) -> None:
        nonlocal close_calls
        close_calls += 1
        real_close(descriptor)
        if close_fails:
            raise OSError("injected raw lock descriptor close failure")

    monkeypatch.setattr(db_module.fcntl, "flock", injected_unlock)
    monkeypatch.setattr(db_module.os, "close", injected_close)

    with pytest.raises(DatabaseFinalizationStateUnknown) as caught, database._maintenance_lock():
        pass

    message = str(caught.value)
    assert "database maintenance completed" in message
    assert expected_detail in message
    assert "stop Signet processes and inspect the private maintenance lock" in message
    assert "injected raw" not in message
    assert unlock_calls == 1
    assert close_calls == 1


def test_generic_operation_failure_combined_with_lock_failure_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signet.db as db_module

    database = Database(tmp_path / "approvals.sqlite3")
    real_flock = db_module.fcntl.flock
    unlock_calls = 0

    def injected_unlock(descriptor: int, operation: int) -> None:
        nonlocal unlock_calls
        if operation == db_module.fcntl.LOCK_UN:
            unlock_calls += 1
            raise OSError("injected raw lock release failure")
        real_flock(descriptor, operation)

    monkeypatch.setattr(db_module.fcntl, "flock", injected_unlock)

    with pytest.raises(DatabaseFinalizationStateUnknown) as caught, database._maintenance_lock():
        raise BackupError("injected raw backup construction failure")

    message = caught.value.operator_message()
    assert "database operation failed" in message
    assert "maintenance-lock finalization could not be confirmed" in message
    assert "stop Signet processes and inspect the private maintenance lock" in message
    assert "injected raw" not in message
    assert unlock_calls == 1


def test_migration_backup_receipt_digest_is_verified_without_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    artifact = tmp_path / "large-backup.signet"
    content = b"x" * (2 * 1024 * 1024 + 1)
    artifact.write_bytes(content)
    artifact.chmod(0o600)
    receipt = MigrationBackupReceipt(
        database_path=database.path,
        source_schema_version=LATEST_SCHEMA_VERSION,
        artifact_path=artifact,
        artifact_sha256=hashlib.sha256(content).hexdigest(),
        verified_restore_schema_version=LATEST_SCHEMA_VERSION,
    )
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == artifact:
            raise AssertionError("migration receipt loaded the complete artifact")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    database._verify_migration_backup_receipt(receipt, LATEST_SCHEMA_VERSION)


def test_preflight_schema_version_reads_committed_wal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", LATEST_SCHEMA_VERSION - 1)
    database.initialize()
    reader = database.connect()
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM sqlite_schema").fetchone()
        monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", LATEST_SCHEMA_VERSION)
        database.initialize(
            pre_migration_backup=verified_backup_callback(tmp_path / "upgrade-backups", [])
        )

        with database.path.open("rb") as stream:
            stream.seek(60)
            main_file_version = int.from_bytes(stream.read(4), byteorder="big")
        assert main_file_version == LATEST_SCHEMA_VERSION - 1

        restarted = Database(database.path)
        restarted.initialize()
        with restarted.read() as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == LATEST_SCHEMA_VERSION
    finally:
        reader.rollback()
        reader.close()


def test_newer_schema_is_refused_before_application_work(tmp_path: Path) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    connection = database.connect()
    try:
        connection.execute("PRAGMA user_version=99")
    finally:
        connection.close()
    wal_path = Path(f"{database.path}-wal")
    shm_path = Path(f"{database.path}-shm")
    wal_path.unlink(missing_ok=True)
    shm_path.unlink(missing_ok=True)

    downstream_calls = 0
    with pytest.raises(IncompatibleSchemaError, match="newer"):
        database.initialize()
    assert downstream_calls == 0
    assert not wal_path.exists()
    assert not shm_path.exists()


def test_applied_migration_checksum_tampering_is_refused(tmp_path: Path) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    with database.transaction() as connection:
        connection.execute(
            "UPDATE schema_meta SET checksum = ? WHERE migration_id = 1",
            ("0" * 64,),
        )

    with pytest.raises(MigrationIntegrityError, match="checksum"):
        database.initialize()


def test_upgrade_validates_existing_migration_history_before_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    monkeypatch.setattr("signet.db.LATEST_SCHEMA_VERSION", 15)
    database.initialize()
    with database.transaction() as connection:
        connection.execute(
            "UPDATE schema_meta SET checksum = ? WHERE migration_id = 1",
            ("0" * 64,),
        )
    monkeypatch.setattr("signet.db.LATEST_SCHEMA_VERSION", 16)
    backups: list[int] = []

    with pytest.raises(MigrationIntegrityError, match="checksum"):
        database.initialize(
            pre_migration_backup=verified_backup_callback(tmp_path / "backups", backups)
        )

    assert backups == []
    with database.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 15


def test_upgrade_rejects_noop_backup_receipt_and_rolls_back_failed_postcheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    monkeypatch.setattr("signet.db.LATEST_SCHEMA_VERSION", 15)
    database.initialize()
    monkeypatch.setattr("signet.db.LATEST_SCHEMA_VERSION", 16)

    with pytest.raises(MigrationIntegrityError, match="receipt"):
        database.initialize(
            pre_migration_backup=lambda _database, _version: None  # type: ignore[arg-type,return-value]
        )

    backups: list[int] = []

    def fail_postcheck(event: str) -> None:
        if event == "migration:transaction:postcheck":
            raise RuntimeError("injected postcheck failure")

    with pytest.raises(RuntimeError, match="injected postcheck failure"):
        database.initialize(
            pre_migration_backup=verified_backup_callback(tmp_path / "backups", backups),
            fault_injector=fail_postcheck,
        )

    assert backups == [15]
    with database.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 15
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' "
                "AND name = 'production_setup_state'"
            ).fetchone()[0]
            == 0
        )


def test_migrated_operational_row_shapes_survive_restart(tmp_path: Path) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    payload_hash = "a" * 64
    machine = ApprovalStateMachine(database, capabilities=TEST_CAPABILITIES)
    machine.enqueue(
        EnqueueRequest(
            request_id="row-fixture",
            downstream_alias="fastmail",
            tool_name="send_email",
            policy_mode="approval",
            origin_namespace="profile:test",
            encrypted_payload=b"encrypted",
            payload_hash=payload_hash,
            payload_fingerprint="fingerprint",
            pending_result=b'{"status":"pending_approval"}',
            created_at=100,
            expires_at=200,
            policy_version="policy-1",
            adapter_version="adapter-1",
            schema_version="schema-1",
            editor_actor="caller:profile:test",
            idempotency_key="stable-call",
        )
    )
    attachment_id = "stg_" + "d" * 20
    storage_path = f"/private/staging/{attachment_id}"
    register_catalog_attachment(
        database,
        attachment_id=attachment_id,
        storage_path=storage_path,
        filename="review.txt",
        size_bytes=5,
    )
    machine.add_attachment(
        "row-fixture",
        version=1,
        payload_hash=payload_hash,
        attachment_id=attachment_id,
        filename="review.txt",
        mime_type="text/plain",
        size_bytes=5,
        sha256="b" * 64,
        storage_path=storage_path,
        created_at=101,
    )
    machine.enqueue(
        EnqueueRequest(
            request_id="terminal-fixture",
            downstream_alias="whatsapp",
            tool_name="send_text",
            policy_mode="approval",
            origin_namespace="profile:test",
            encrypted_payload=b"encrypted",
            payload_hash="d" * 64,
            payload_fingerprint="terminal-fingerprint",
            pending_result=b'{"status":"pending_approval"}',
            created_at=100,
            expires_at=200,
            policy_version="policy-1",
            adapter_version="adapter-1",
            schema_version="schema-1",
            editor_actor="caller:profile:test",
        )
    )
    with database.transaction() as connection:
        connection.execute("INSERT INTO auth_users(user_id, created_at) VALUES ('owner', 100)")
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, secret_reference, enrolled_at
            ) VALUES (
                'database-test-totp', 'owner', 'totp',
                'keychain://Signet/database-test', 100
            )
            """
        )
        connection.execute(
            """
            INSERT INTO web_sessions(
                session_id, user_id, auth_method, auth_generation,
                created_at, last_seen_at, absolute_expires_at
            ) VALUES (
                'terminal-web-session-opaque-00000001',
                'owner', 'totp', 0, 100, 100, 200
            )
            """
        )
    machine.deny(
        "terminal-fixture",
        expected_version=1,
        expected_payload_hash="d" * 64,
        confirmation=totp_confirmation(
            "terminal-fixture",
            action="deny",
            payload_hash="d" * 64,
            use_id="terminal-fixture-deny-proof",
            session_id="terminal-web-session-opaque-00000001",
        ),
        actor="human:web",
        now=102,
    )
    machine.enqueue(
        EnqueueRequest(
            request_id="execution-fixture",
            downstream_alias="fastmail",
            tool_name="send_email",
            policy_mode="approval",
            origin_namespace="profile:test",
            encrypted_payload=b"encrypted",
            payload_hash="e" * 64,
            payload_fingerprint="execution-fingerprint",
            pending_result=b'{"status":"pending_approval"}',
            created_at=100,
            expires_at=200,
            policy_version="policy-1",
            adapter_version="adapter-1",
            schema_version="schema-1",
            editor_actor="caller:profile:test",
        )
    )
    machine.approve(
        "execution-fixture",
        expected_version=1,
        expected_payload_hash="e" * 64,
        confirmation=totp_confirmation(
            "execution-fixture",
            action="approve",
            payload_hash="e" * 64,
            use_id="fixture-proof",
            session_id="terminal-web-session-opaque-00000001",
        ),
        actor="human:web",
        now=101,
    )
    lease = machine.claim_execution(
        "execution-fixture", worker_id="worker", now=102, lease_seconds=10
    )
    machine.mark_dispatch_started(lease, now=103)
    machine.record_outcome(
        lease,
        classification=OutcomeClassification.SUCCEEDED,
        now=104,
        safe_outcome={"provider_id": "provider-fixture"},
        result_aliases=(ResultAlias("primary", "message_id", "provider-fixture"),),
    )
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO policy_versions(
                actor, created_at, mode_diffs_json, originating_event,
                config_hash
            ) VALUES ('human:test', 101, '{}', 'file_change', ?)
            """,
            ("c" * 64,),
        )
        connection.execute(
            """
            INSERT INTO push_subscriptions(
                subscription_id, user_id, endpoint, p256dh_key, auth_key,
                device_label, categories_json, created_at
            ) VALUES (
                'push-1', 'user-1', 'https://push.example.test/device',
                x'01', x'02', 'phone', '["pending"]', 101
            )
            """
        )
        connection.execute(
            """
            INSERT INTO auth_credentials(
                credential_id, user_id, kind, public_material, enrolled_at
            ) VALUES ('credential-1', 'user-1', 'webauthn', x'01', 101)
            """
        )
        connection.execute(
            """
            INSERT INTO schema_cache(
                downstream_alias, tool_name, schema_digest, tool_schema_json,
                discovered_at, review_state
            ) VALUES ('fastmail', 'send_email', ?, x'7b7d', 101, 'approved')
            """,
            ("f" * 64,),
        )
        connection.execute(
            """
            INSERT INTO caller_tokens(
                token_id, origin_namespace, verifier, allowed_aliases_json, created_at
            ) VALUES ('token-1', 'profile:test', 'argon2-hash', '["approvals"]', 101)
            """
        )
        connection.execute(
            """
            INSERT INTO purge_jobs(
                purge_job_id, request_id, intent, idempotency_key, created_at
            ) VALUES (
                'purge-1', 'row-fixture', 'attachments', 'purge:row-fixture', 102
            )
            """
        )

    Database(database.path).initialize()
    with database.read() as connection:
        counts = {
            table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "approval_requests",
                "payload_versions",
                "attachments",
                "idempotency_records",
                "request_events",
                "policy_versions",
                "push_subscriptions",
                "purge_jobs",
            )
        }
    assert all(count >= 1 for count in counts.values())
    with database.read() as connection:
        states = {
            row["request_id"]: row["state"]
            for row in connection.execute("SELECT request_id, state FROM approval_requests")
        }
        assert connection.execute("SELECT count(*) FROM execution_attempts").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM result_aliases").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM auth_credentials").fetchone()[0] == 2
        assert connection.execute("SELECT count(*) FROM schema_cache").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM caller_tokens").fetchone()[0] == 1
    assert states["row-fixture"] == "pending_approval"
    assert states["terminal-fixture"] == "denied"
    assert states["execution-fixture"] == "succeeded"
    assert database.integrity_check() == ("ok", ())
