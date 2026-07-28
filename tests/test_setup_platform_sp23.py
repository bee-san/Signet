from __future__ import annotations

import hashlib
import plistlib
import shutil
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import signet.setup_platform as setup_platform
from signet.setup_platform import (
    ProductionSetupPlatform,
    render_launchd_services,
    render_production_config,
    render_systemd_services,
)
from signet.setup_state import ExecutableIdentity, SetupError, SetupSpec


def spec(root: Path, **changes: Any) -> SetupSpec:
    selected = SetupSpec(
        root=root,
        public_origin="https://signet.example.ts.net:8443",
        owner_user_id="user:owner",
        hermes_profiles=("work",),
        executable=Path("/opt/signet/bin/signet"),
        open_browser=False,
    )
    return replace(selected, **changes)


def test_service_renderers_bound_the_web_process_that_owns_workers(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")

    launchd = render_launchd_services(selected, active=True)
    systemd = render_systemd_services(selected, active=True)
    assert set(launchd) == {
        "ai.hermes.signet.mcp.plist",
        "ai.hermes.signet.web.plist",
    }
    web_plist = plistlib.loads(launchd["ai.hermes.signet.web.plist"])
    assert web_plist["ProgramArguments"] == [
        str(selected.executable),
        "production",
        "serve-web",
        "--config",
        str(selected.root / "production.json"),
    ]
    assert web_plist["ProcessType"] == "Background"
    assert web_plist["ThrottleInterval"] >= 5
    assert web_plist["HardResourceLimits"]["NumberOfFiles"] <= 4096
    assert set(systemd) == {
        "signet-mcp.service",
        "signet-web.service",
    }
    web_unit = systemd["signet-web.service"]
    assert "production serve-web" in web_unit
    assert "MemoryMax=" in web_unit
    assert "MemorySwapMax=0" in web_unit
    assert "TasksMax=" in web_unit
    assert "LimitNOFILE=" in web_unit


def test_explicit_external_data_root_requires_and_binds_device_identity(tmp_path: Path) -> None:
    external = tmp_path / "external-data"
    external.mkdir(mode=0o700)
    device = external.stat().st_dev

    with pytest.raises(ValueError, match="device identity"):
        spec(tmp_path / "missing-device", data_root=external)

    selected = spec(
        tmp_path / "signet",
        data_root=external,
        data_device=device,
    )
    rendered = render_production_config(selected, setup_id="setup_0123456789abcdef")

    assert rendered["instance_root"] == str(selected.root)
    assert rendered["storage"]["data_dir"] == str(external)
    assert selected.document()["data_device"] == device

    platform = ProductionSetupPlatform()
    platform._verify_configured_storage_roots(selected)

    with pytest.raises(SetupError, match="device identity"):
        platform._verify_configured_storage_roots(replace(selected, data_device=device + 1))


def test_external_storage_roots_are_marker_bound_and_data_rolls_back_safely(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "external-data"
    backup_root = tmp_path / "external-backups"
    data_root.mkdir(mode=0o700)
    backup_root.mkdir(mode=0o700)
    selected = spec(
        tmp_path / "signet",
        data_root=data_root,
        data_device=data_root.stat().st_dev,
        backup_root=backup_root,
    )
    platform = ProductionSetupPlatform()
    setup_id = "setup_0123456789abcdef"

    platform._apply_private_paths(selected, setup_id)
    platform.validate_private_paths(selected, setup_id)

    assert (data_root / ".signet-storage-owner.json").is_file()
    assert (backup_root / ".signet-storage-owner.json").is_file()
    assert (selected.root / ".signet-external-storage-data.json").is_file()
    assert (selected.root / ".signet-external-storage-backup.json").is_file()

    platform._rollback_private_paths(selected, setup_id)

    assert tuple(data_root.iterdir()) == ()
    assert (backup_root / ".signet-storage-owner.json").is_file()
    assert (selected.root / ".signet-external-storage-backup.json").is_file()


def test_external_data_root_database_lifecycle_preserves_the_storage_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "external-data"
    data_root.mkdir(mode=0o700)
    selected = spec(
        tmp_path / "signet",
        data_root=data_root,
        data_device=data_root.stat().st_dev,
    )
    platform = ProductionSetupPlatform()
    setup_id = "setup_0123456789abcdef"
    monkeypatch.setattr(
        setup_platform,
        "create_production_assembly",
        lambda *_args, **_kwargs: object(),
    )

    platform._apply_private_paths(selected, setup_id)
    platform._apply_configuration(selected, setup_id)
    platform._apply_database(selected, setup_id)

    assert (data_root / "signet.db").is_file()
    assert (data_root / ".signet-database-ownership.json").is_file()
    assert (data_root / ".signet-storage-owner.json").is_file()
    database_identity, lock_identity, parent_identity = (
        setup_platform.validate_active_database_runtime_ownership(
            data_root,
            setup_id=setup_id,
            instance_root=selected.root,
        )
    )
    assert database_identity == (
        (data_root / "signet.db").stat().st_dev,
        (data_root / "signet.db").stat().st_ino,
    )
    assert lock_identity == (
        (data_root / ".signet.db.maintenance.lock").stat().st_dev,
        (data_root / ".signet.db.maintenance.lock").stat().st_ino,
    )
    assert parent_identity.path == data_root

    receipt = selected.root / ".signet-external-storage-data.json"
    receipt_content = receipt.read_bytes()
    receipt.unlink()
    with pytest.raises(SetupError, match="ownership publication"):
        setup_platform.validate_active_database_runtime_ownership(
            data_root,
            setup_id=setup_id,
            instance_root=selected.root,
        )
    receipt.write_bytes(receipt_content)
    receipt.chmod(0o600)

    storage_marker = data_root / ".signet-storage-owner.json"
    marker_content = storage_marker.read_bytes()
    storage_marker.unlink()
    with pytest.raises(SetupError, match="ownership publication"):
        setup_platform.validate_active_database_runtime_ownership(
            data_root,
            setup_id=setup_id,
            instance_root=selected.root,
        )
    storage_marker.write_bytes(marker_content)
    storage_marker.chmod(0o600)

    receipt.unlink()
    storage_marker.unlink()
    with pytest.raises(SetupError, match="ownership publication"):
        setup_platform.validate_active_database_runtime_ownership(
            data_root,
            setup_id=setup_id,
            instance_root=selected.root,
            require_external_storage=True,
        )
    receipt.write_bytes(receipt_content)
    receipt.chmod(0o600)
    storage_marker.write_bytes(marker_content)
    storage_marker.chmod(0o600)

    platform._rollback_database(selected, setup_id)
    assert tuple(path.name for path in data_root.iterdir()) == (".signet-storage-owner.json",)
    platform._rollback_configuration(selected, setup_id)
    platform._rollback_private_paths(selected, setup_id)
    assert tuple(data_root.iterdir()) == ()


def test_external_backup_root_rechecks_local_filesystem_at_ownership_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_root = tmp_path / "external-backups"
    backup_root.mkdir(mode=0o700)
    selected = spec(tmp_path / "signet", backup_root=backup_root)

    def reject_non_local(path: Path) -> None:
        if path == backup_root:
            raise setup_platform.DatabaseError("injected non-local filesystem")

    monkeypatch.setattr(setup_platform, "require_local_filesystem", reject_non_local)

    with pytest.raises(SetupError, match="external backup root"):
        ProductionSetupPlatform()._apply_private_paths(
            selected,
            "setup_0123456789abcdef",
        )

    assert tuple(backup_root.iterdir()) == ()
    assert not (selected.root / ".signet-external-storage-backup.json").exists()


def test_service_install_revalidates_the_packaged_runtime_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = spec(tmp_path / "signet")
    platform = ProductionSetupPlatform()
    platform._apply_private_paths(selected, "setup_0123456789abcdef")

    def reject_replaced_runtime(_path: Path, _identity: ExecutableIdentity | None = None) -> None:
        raise SetupError("runtime changed after preflight")

    monkeypatch.setattr(setup_platform, "_require_packaged_runtime", reject_replaced_runtime)

    with pytest.raises(SetupError, match="runtime changed after preflight"):
        platform._apply_services(selected, "setup_0123456789abcdef")

    assert tuple((selected.root / "services").iterdir()) == ()


def test_storage_preflight_fails_before_the_reserve_is_exhausted(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    messages: list[str] = []
    platform = ProductionSetupPlatform(
        output=messages.append,
        disk_usage_provider=lambda path: shutil._ntuple_diskusage(  # type: ignore[attr-defined]
            100 * 1024**3,
            99 * 1024**3,
            1024**3,
        ),
    )

    with pytest.raises(SetupError, match="storage reserve"):
        platform._verify_storage_capacity(selected)


def test_storage_preflight_warns_below_percentage_without_mutating(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    messages: list[str] = []
    platform = ProductionSetupPlatform(
        output=messages.append,
        disk_usage_provider=lambda path: SimpleNamespace(
            total=100 * 1024**3,
            used=88 * 1024**3,
            free=12 * 1024**3,
        ),
    )

    report = platform._verify_storage_capacity(selected)

    assert report["warning"] is True
    assert report["free_bytes"] == 12 * 1024**3
    assert any("storage warning" in message.lower() for message in messages)
    assert not selected.root.exists()


def test_storage_status_reports_bounded_roots_without_secret_material(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    selected.root.mkdir(mode=0o700)
    for name in ("data", "backups", "logs", "cache", "staging"):
        (selected.root / name).mkdir(mode=0o700)
    (selected.root / "logs" / "web.log").write_bytes(b"safe metadata only")
    (selected.root / "logs" / "web.log").chmod(0o600)

    report = setup_platform.storage_status(selected)

    assert set(report["roots"]) == {
        "data",
        "attachments",
        "backups",
        "logs",
        "cache",
        "staging",
    }
    assert report["roots"]["logs"]["usage_bytes"] == len(b"safe metadata only")
    assert report["policy"]["logs_hard_bytes"] == 512 * 1024**2
    assert report["policy"]["database_hard_bytes"] == 1024**3
    assert report["policy"]["attachments_hard_bytes"] == 8 * 1024**3
    assert "safe metadata only" not in repr(report)
    assert stat.S_IMODE((selected.root / "logs").stat().st_mode) == 0o700


def test_storage_preflight_rejects_an_existing_hard_limit_breach(tmp_path: Path) -> None:
    selected = spec(tmp_path / "signet")
    logs = selected.root / "logs"
    logs.mkdir(parents=True, mode=0o700)
    oversized = logs / "signet-web.out.log"
    with oversized.open("wb") as stream:
        stream.truncate(512 * 1024**2 + 1)
    platform = ProductionSetupPlatform(
        disk_usage_provider=lambda _path: SimpleNamespace(
            total=100 * 1024**3,
            used=50 * 1024**3,
            free=50 * 1024**3,
        )
    )

    with pytest.raises(SetupError, match="hard storage limit"):
        platform._verify_storage_capacity(selected)


@pytest.mark.parametrize(
    ("root_name", "size"),
    (("data", 1024**3 + 1), ("attachments", 8 * 1024**3 + 1)),
)
def test_storage_preflight_rejects_database_and_attachment_hard_limit_breaches(
    tmp_path: Path,
    root_name: str,
    size: int,
) -> None:
    selected = spec(tmp_path / "signet")
    bounded_root = selected.root / root_name
    bounded_root.mkdir(parents=True, mode=0o700)
    oversized = bounded_root / ("signet.db" if root_name == "data" else "attachment.bin")
    with oversized.open("wb") as stream:
        stream.truncate(size)
    platform = ProductionSetupPlatform(
        disk_usage_provider=lambda _path: SimpleNamespace(
            total=100 * 1024**3,
            used=50 * 1024**3,
            free=50 * 1024**3,
        )
    )

    with pytest.raises(SetupError, match="hard storage limit"):
        platform._verify_storage_capacity(selected)


def test_preflight_rejects_an_editable_source_tree_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = tmp_path / "editable-environment"
    executable = environment / "bin" / "signet"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    site_packages = environment / "lib" / "python3.12" / "site-packages"
    site_packages.mkdir(parents=True)
    (site_packages / "_editable_impl_signet_gateway.pth").write_text(
        str(tmp_path / "source" / "src"),
        encoding="utf-8",
    )
    selected = spec(tmp_path / "signet", executable=executable)
    platform = ProductionSetupPlatform()
    monkeypatch.setattr(setup_platform.sys, "platform", "darwin")
    monkeypatch.setattr(platform, "_verify_configured_storage_roots", lambda _spec: None)
    monkeypatch.setattr(platform, "_verify_storage_capacity", lambda _spec: {})

    with pytest.raises(SetupError, match="editable or source-tree"):
        platform._apply_preflight(selected, "setup_0123456789abcdef")


def test_preflight_rejects_reviewed_executable_drift_and_symlinked_ancestors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_environment = tmp_path / "runtime"
    executable = real_environment / "bin" / "signet"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    metadata = executable.stat()
    identity = ExecutableIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    platform = ProductionSetupPlatform()
    monkeypatch.setattr(setup_platform.sys, "platform", "darwin")
    monkeypatch.setattr(platform, "_verify_configured_storage_roots", lambda _spec: None)
    monkeypatch.setattr(platform, "_verify_storage_capacity", lambda _spec: {})

    executable.write_bytes(b"#!/bin/sh\nexit 1\n")
    with pytest.raises(SetupError, match="identity changed after review"):
        platform._apply_preflight(
            spec(tmp_path / "drifted", executable=executable, executable_identity=identity),
            "setup_0123456789abcdef",
        )

    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    linked_environment = tmp_path / "linked-runtime"
    linked_environment.symlink_to(real_environment, target_is_directory=True)
    with pytest.raises(SetupError, match="symlinked ancestor"):
        platform._apply_preflight(
            spec(tmp_path / "linked", executable=linked_environment / "bin" / "signet"),
            "setup_0123456789abcdef",
        )


def test_preflight_rejects_runtime_below_a_nonsticky_world_writable_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writable = tmp_path / "writable"
    writable.mkdir(mode=0o700)
    writable.chmod(0o777)
    executable = writable / "runtime" / "bin" / "signet"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    platform = ProductionSetupPlatform()
    monkeypatch.setattr(setup_platform.sys, "platform", "darwin")
    monkeypatch.setattr(platform, "_verify_configured_storage_roots", lambda _spec: None)
    monkeypatch.setattr(platform, "_verify_storage_capacity", lambda _spec: {})

    with pytest.raises(SetupError, match="unsafe ancestry"):
        platform._apply_preflight(
            spec(tmp_path / "writable-runtime", executable=executable),
            "setup_0123456789abcdef",
        )
