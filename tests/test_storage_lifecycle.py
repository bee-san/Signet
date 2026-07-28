from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import signet.setup_platform as setup_platform
from signet.setup_platform import storage_path_status
from signet.storage_lifecycle import StorageMaintenance, StoragePolicyError


def test_storage_path_status_can_skip_unrelated_usage_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_parent = tmp_path / "external"
    destination_parent.mkdir(mode=0o700)
    monkeypatch.setattr(
        setup_platform,
        "_tree_usage_bytes",
        lambda _path: pytest.fail("free-space checks must not traverse unrelated files"),
    )

    status = storage_path_status(
        destination_parent,
        disk_usage_provider=lambda _path: SimpleNamespace(free=2048, total=4096),
        include_usage=False,
    )

    assert status["usage_bytes"] == 0
    assert status["free_bytes"] == 2048


def test_storage_maintenance_rotates_logs_without_losing_concurrent_appends(
    tmp_path: Path,
) -> None:
    root = tmp_path / "signet"
    logs = root / "logs"
    cache = root / "cache"
    logs.mkdir(parents=True, mode=0o700)
    cache.mkdir(mode=0o700)
    active = logs / "workers.log"
    active.write_bytes(b"a" * 80)
    active.chmod(0o600)

    maintenance = StorageMaintenance(
        root,
        log_file_bytes=32,
        logs_hard_bytes=96,
        cache_hard_bytes=64,
    )
    with active.open("ab", buffering=0) as writer:
        report = maintenance.run_once()
        writer.write(b"concurrent")

    assert active.read_bytes() == b""
    assert (logs / "workers.log.1").read_bytes() == b"a" * 80 + b"concurrent"
    assert report["logs_bytes"] == 80
    assert report["rotated_logs"] == 1


def test_storage_maintenance_repeatedly_blocks_on_an_active_old_writer_archive(
    tmp_path: Path,
) -> None:
    root = tmp_path / "signet"
    logs = root / "logs"
    cache = root / "cache"
    logs.mkdir(parents=True, mode=0o700)
    cache.mkdir(mode=0o700)
    active = logs / "workers.log"
    active.write_bytes(b"a" * 80)
    active.chmod(0o600)
    maintenance = StorageMaintenance(
        root,
        log_file_bytes=32,
        logs_hard_bytes=96,
        cache_hard_bytes=64,
    )

    with active.open("ab", buffering=0) as writer:
        assert maintenance.run_once()["rotated_logs"] == 1
        writer.write(b"b" * 32)
        for _attempt in range(2):
            with pytest.raises(StoragePolicyError, match="logs exceed"):
                maintenance.run_once()
            assert active.read_bytes() == b""
            assert (logs / "workers.log.1").read_bytes() == b"a" * 80 + b"b" * 32

    (logs / "workers.log.1").unlink()
    recovered = maintenance.run_once()
    assert recovered["logs_bytes"] == 0
    assert recovered["rotated_logs"] == 0


def test_storage_maintenance_prunes_oldest_owned_cache_files(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    logs = root / "logs"
    cache = root / "cache"
    logs.mkdir(parents=True, mode=0o700)
    cache.mkdir(mode=0o700)
    oldest = cache / "old.cache"
    newest = cache / "new.cache"
    oldest.write_bytes(b"o" * 40)
    newest.write_bytes(b"n" * 40)
    oldest.chmod(0o600)
    newest.chmod(0o600)
    oldest.touch()
    newest.touch()
    oldest_mtime = newest.stat().st_mtime_ns - 1_000_000
    oldest.touch()
    import os

    os.utime(oldest, ns=(oldest_mtime, oldest_mtime))

    report = StorageMaintenance(
        root,
        log_file_bytes=32,
        logs_hard_bytes=96,
        cache_hard_bytes=40,
    ).run_once()

    assert not oldest.exists()
    assert newest.exists()
    assert report["cache_bytes"] == 40
    assert report["pruned_cache_files"] == 1


def test_storage_maintenance_refuses_symlinked_owned_entries(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    logs = root / "logs"
    cache = root / "cache"
    logs.mkdir(parents=True, mode=0o700)
    cache.mkdir(mode=0o700)
    target = tmp_path / "foreign"
    target.write_text("do not touch")
    (logs / "web.log").symlink_to(target)

    with pytest.raises(StoragePolicyError, match="symbolic link"):
        StorageMaintenance(root).run_once()

    assert target.read_text() == "do not touch"


def test_storage_maintenance_enforces_database_attachment_and_free_space_caps(
    tmp_path: Path,
) -> None:
    root = tmp_path / "signet"
    logs = root / "logs"
    cache = root / "cache"
    data = root / "data"
    attachments = root / "attachments"
    for path in (logs, cache, data, attachments):
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    database = data / "signet.db"
    database.write_bytes(b"d" * 65)
    database.chmod(0o600)
    attachment = attachments / "attachment.bin"
    attachment.write_bytes(b"a" * 32)
    attachment.chmod(0o600)

    with pytest.raises(StoragePolicyError, match="database"):
        StorageMaintenance(
            root,
            data_dir=data,
            attachment_roots=(attachments,),
            database_hard_bytes=64,
            attachments_hard_bytes=64,
            minimum_free_bytes=0,
        ).run_once()

    database.write_bytes(b"d" * 64)
    with pytest.raises(StoragePolicyError, match="attachment"):
        StorageMaintenance(
            root,
            data_dir=data,
            attachment_roots=(attachments,),
            database_hard_bytes=64,
            attachments_hard_bytes=31,
            minimum_free_bytes=0,
        ).run_once()

    attachment.write_bytes(b"a" * 31)
    with pytest.raises(StoragePolicyError, match="reserve"):
        StorageMaintenance(
            root,
            data_dir=data,
            attachment_roots=(attachments,),
            database_hard_bytes=64,
            attachments_hard_bytes=31,
            minimum_free_bytes=2,
            disk_usage_provider=lambda _path: type("Usage", (), {"free": 1})(),
        ).run_once()


def test_storage_maintenance_reports_enforced_runtime_budgets(tmp_path: Path) -> None:
    root = tmp_path / "signet"
    paths = {name: root / name for name in ("logs", "cache", "data", "attachments")}
    for path in paths.values():
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    for path, content in (
        (paths["data"] / "signet.db", b"database"),
        (paths["attachments"] / "item.bin", b"attachment"),
    ):
        path.write_bytes(content)
        path.chmod(0o600)

    report = StorageMaintenance(
        root,
        data_dir=paths["data"],
        attachment_roots=(paths["attachments"],),
        database_hard_bytes=64,
        attachments_hard_bytes=64,
        minimum_free_bytes=0,
    ).run_once()

    assert report["database_bytes"] == len(b"database")
    assert report["attachments_bytes"] == len(b"attachment")
