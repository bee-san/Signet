from __future__ import annotations

import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from signet.db import (
    Database,
    DatabaseError,
    IncompatibleSchemaError,
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

CORE_TABLES = {
    "approval_requests",
    "payload_versions",
    "attachments",
    "idempotency_records",
    "execution_attempts",
    "result_aliases",
    "request_events",
    "policy_versions",
    "push_subscriptions",
    "auth_credentials",
    "caller_tokens",
    "schema_cache",
    "purge_jobs",
    "schema_meta",
}


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
        migration = connection.execute("SELECT * FROM schema_meta").fetchone()
    assert tables >= CORE_TABLES
    assert migration["migration_id"] == 1
    assert len(migration["checksum"]) == 64


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
    restored.path.parent.mkdir(parents=True)
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


def test_upgrade_requires_and_runs_a_verified_pre_migration_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signet.db as db_module

    path = tmp_path / "approvals.sqlite3"
    Database(path).initialize()
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

    monkeypatch.setattr(db_module, "LATEST_SCHEMA_VERSION", 2)
    upgrading = UpgradeDatabase(path)
    with pytest.raises(MigrationIntegrityError, match="backup callback"):
        upgrading.initialize()

    snapshots: list[Path] = []

    def backup(database: Database, current_version: int) -> None:
        assert current_version == 1
        snapshot = database.create_snapshot(tmp_path / "pre-migration.sqlite3")
        Database.verify_snapshot(snapshot)
        snapshots.append(snapshot)

    upgrading.initialize(pre_migration_backup=backup)
    assert snapshots
    with upgrading.read() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'upgrade_marker'"
        ).fetchone()[0] == 1


def test_newer_schema_is_refused_before_application_work(tmp_path: Path) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    connection = database.connect()
    try:
        connection.execute("PRAGMA user_version=99")
    finally:
        connection.close()

    downstream_calls = 0
    with pytest.raises(IncompatibleSchemaError, match="newer"):
        database.initialize()
    assert downstream_calls == 0


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


def test_migrated_operational_row_shapes_survive_restart(tmp_path: Path) -> None:
    database = Database(tmp_path / "approvals.sqlite3")
    database.initialize()
    payload_hash = "a" * 64
    machine = ApprovalStateMachine(database)
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
    machine.add_attachment(
        "row-fixture",
        version=1,
        payload_hash=payload_hash,
        attachment_id="attachment-1",
        filename="review.txt",
        mime_type="text/plain",
        size_bytes=5,
        sha256="b" * 64,
        storage_path="/private/staging/attachment-1",
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
    machine.deny(
        "terminal-fixture",
        expected_version=1,
        expected_payload_hash="d" * 64,
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
        confirmation=ApprovalConfirmation(ConfirmationKind.TOTP, "fixture-proof", "web"),
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
            for row in connection.execute(
                "SELECT request_id, state FROM approval_requests"
            )
        }
        assert connection.execute("SELECT count(*) FROM execution_attempts").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM result_aliases").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM auth_credentials").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM schema_cache").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM caller_tokens").fetchone()[0] == 1
    assert states["row-fixture"] == "pending_approval"
    assert states["terminal-fixture"] == "denied"
    assert states["execution-fixture"] == "succeeded"
    assert database.integrity_check() == ("ok", ())
