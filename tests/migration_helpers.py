from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from signet.db import Database, MigrationBackupReceipt, PreMigrationBackup


def downgrade_auth_credentials_before_schema_17(connection: Any) -> None:
    """Restore the auth-credential shape owned by migration 17."""

    connection.execute("ALTER TABLE auth_credentials DROP COLUMN transports_json")
    connection.execute("ALTER TABLE auth_credentials DROP COLUMN discoverable")


def downgrade_auth_credentials_before_schema_16(connection: Any) -> None:
    """Restore the auth-credential shape owned by migration 16."""

    connection.execute("DROP INDEX IF EXISTS auth_credentials_active_factor_label")
    connection.execute("ALTER TABLE auth_credentials DROP COLUMN factor_label")
    connection.execute(
        """
        CREATE UNIQUE INDEX auth_credentials_one_active_totp
        ON auth_credentials(user_id) WHERE kind = 'totp' AND disabled_at IS NULL
        """
    )


def verified_backup_callback(
    directory: Path,
    versions: list[int],
) -> PreMigrationBackup:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def backup(database: Database, current_version: int) -> MigrationBackupReceipt:
        destination = directory / f"pre-migration-v{current_version}-{len(versions)}.sqlite3"
        snapshot = database.create_snapshot(destination)
        Database.verify_snapshot(snapshot)
        versions.append(current_version)
        return MigrationBackupReceipt(
            database_path=database.path,
            source_schema_version=current_version,
            artifact_path=snapshot.absolute(),
            artifact_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            verified_restore_schema_version=current_version,
        )

    return backup
