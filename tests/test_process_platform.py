from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from signet import reviewed_process
from signet.config import DownstreamConfig
from signet.credential_broker import MemorySecretStore
from signet.downstream import (
    DownstreamClient,
    DownstreamConfigurationError,
    ReviewedStdioServerParameters,
    _official_stdio_connector,
)
from signet.reviewed_process import (
    _TEST_ONLY_SCRIPT_CAPABILITY,
    PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED,
    ReviewedProcessError,
    VerifiedPrivateDirectory,
    descriptor_path,
    descriptor_process_boundary_supported,
    open_verified_executable,
)
from signet.wacli_wrapper import WacliConfig, WacliError, WacliWrapper


def _write_script(path: Path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o700)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _disable_reviewed_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reviewed_process,
        "descriptor_process_boundary_supported",
        lambda: False,
    )


def test_process_boundary_capability_matches_reviewed_linux_contract() -> None:
    expected = (
        sys.platform == "linux"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and Path("/proc/self/fd").is_dir()
    )

    assert descriptor_process_boundary_supported() is expected


@pytest.mark.skipif(sys.platform != "darwin", reason="requires a real macOS host")
def test_macos_host_rejects_reviewed_descriptor_process_boundary() -> None:
    assert descriptor_process_boundary_supported() is False
    with pytest.raises(ReviewedProcessError) as captured:
        descriptor_path(3)
    assert captured.value.code == PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED


def test_unsupported_host_rejects_before_opening_directory_or_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "provider-mcp"
    digest = _write_script(executable)
    working_directory = _private_directory(tmp_path / "working")
    snapshot_root = tmp_path / "snapshots"
    _disable_reviewed_boundary(monkeypatch)

    for operation in (
        lambda: descriptor_path(3),
        lambda: VerifiedPrivateDirectory.open(working_directory),
        lambda: open_verified_executable(
            executable,
            expected_sha256=digest,
            snapshot_root=snapshot_root,
            _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY,
        ),
    ):
        with pytest.raises(ReviewedProcessError) as captured:
            operation()
        assert captured.value.code == PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED

    assert not snapshot_root.exists()


def test_stdio_configuration_reports_unsupported_process_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_directory = _private_directory(tmp_path / "working")
    _disable_reviewed_boundary(monkeypatch)
    config = DownstreamConfig(
        transport="stdio",
        credential_ref="keychain://Signet/example",
        credential_identity_digest="c" * 64,
        command=("/opt/signet/bin/provider-mcp",),
        working_directory=working_directory,
        executable_sha256="a" * 64,
        execution_snapshot_root=tmp_path / "snapshots",
        timeout_seconds=2,
    )

    with pytest.raises(DownstreamConfigurationError) as captured:
        DownstreamClient(
            "example",
            config,
            MemorySecretStore({("Signet", "example"): "unused-secret"}),
        )

    assert captured.value.code == PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED
    assert PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED in str(captured.value)


@pytest.mark.asyncio
@pytest.mark.skipif(
    not descriptor_process_boundary_supported(),
    reason="requires the reviewed Linux boundary before injecting a late failure",
)
async def test_stdio_connector_preserves_late_unsupported_process_boundary_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_directory = _private_directory(tmp_path / "working")
    with VerifiedPrivateDirectory.open(working_directory) as reviewed_directory:
        identity = reviewed_directory.identity
    parameters = ReviewedStdioServerParameters(
        command="/opt/signet/bin/provider-mcp",
        args=[],
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        cwd=working_directory,
        expected_sha256="a" * 64,
        execution_snapshot_root=tmp_path / "snapshots",
        working_directory_identity=identity,
        output_limit_bytes=1024,
    )

    def unsupported_executable(*args: object, **kwargs: object) -> int:
        del args, kwargs
        raise ReviewedProcessError(PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED)

    monkeypatch.setattr(
        "signet.downstream.open_verified_executable",
        unsupported_executable,
    )

    with pytest.raises(DownstreamConfigurationError) as captured:
        async with _official_stdio_connector(parameters):
            pytest.fail("unsupported stdio boundary started a process", pytrace=False)

    assert captured.value.code == PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED
    assert PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED in str(captured.value)
    assert not parameters.execution_snapshot_root.exists()


def test_wacli_reports_unsupported_process_boundary_before_process_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "wacli"
    digest = _write_script(executable)
    runtime_root = _private_directory(tmp_path / "runtime")
    home = _private_directory(runtime_root / "home")
    store = _private_directory(runtime_root / "store")
    snapshot_root = tmp_path / "snapshots"
    _disable_reviewed_boundary(monkeypatch)
    config = WacliConfig(
        account="personal",
        expected_linked_jid="15551234567@s.whatsapp.net",
        executable=executable,
        expected_sha256=digest,
        home=home,
        store=store,
        reviewed_dispatch_enabled=True,
        execution_snapshot_root=snapshot_root,
    )

    with pytest.raises(WacliError) as captured:
        WacliWrapper(config, _test_capability=_TEST_ONLY_SCRIPT_CAPABILITY)

    assert captured.value.code == PROCESS_BOUNDARY_PLATFORM_UNSUPPORTED
    assert captured.value.dispatch_may_have_occurred is False
    assert not snapshot_root.exists()
