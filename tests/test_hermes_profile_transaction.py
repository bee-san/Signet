from __future__ import annotations

import os
import runpy
import stat
from pathlib import Path
from typing import Any

import pytest

from signet.private_paths import PrivatePathError

ROOT = Path(__file__).resolve().parents[1]
HELPERS = (
    ROOT / "deploy" / "hermes" / "configure-demo-profile.py",
    ROOT / "deploy" / "hermes" / "configure-disabled-profile.py",
)
SECRET_CONTENT = (  # nosec B105
    b"SIGNET_TRANSACTION_SECRET=sgt_abcdefghijklmnop.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq\n"
)
CONFIG_CONTENT = b"mcp_servers:\n  configured: true\n"


def _transaction(tmp_path: Path, helper: Path) -> tuple[dict[str, Any], Any, Any, Path, Path]:
    namespace = runpy.run_path(str(helper))
    profile = tmp_path / helper.stem
    profile.mkdir(mode=0o700)
    config = profile / "config.yaml"
    env_file = profile / ".env"
    config.write_bytes(b"mcp_servers: {}\n")
    env_file.write_bytes(b"# empty profile environment\n")
    config.chmod(0o600)
    env_file.chmod(0o600)
    read_private_file = namespace["_read_private_file"]
    return (
        namespace,
        read_private_file(
            config,
            label="profile config",
            maximum=namespace["MAX_CONFIG_BYTES"],
        ),
        read_private_file(
            env_file,
            label="profile environment",
            maximum=namespace["MAX_ENV_BYTES"],
        ),
        config,
        env_file,
    )


def _commit(namespace: dict[str, Any], config_file: Any, env_file: Any) -> None:
    namespace["_commit_profile_files"](
        config_file=config_file,
        config_content=CONFIG_CONTENT,
        env_file=env_file,
        env_content=SECRET_CONTENT,
    )


def _assert_fixed_failure(error: BaseException, tmp_path: Path) -> str:
    message = str(error)
    assert "Traceback" not in message
    assert "injected" not in message
    assert str(tmp_path) not in message
    assert SECRET_CONTENT.decode("ascii").strip() not in message
    return message


@pytest.mark.parametrize("helper", HELPERS, ids=("demo", "disabled"))
@pytest.mark.parametrize(
    ("failed_fsync", "message", "env_published", "config_published"),
    (
        (3, "no profile file was published", False, False),
        (4, "environment may already contain the token", True, False),
        (5, "publication durability is unknown", True, True),
    ),
    ids=("before-publication", "after-environment-replace", "after-config-replace"),
)
def test_profile_transaction_classifies_each_directory_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: Path,
    failed_fsync: int,
    message: str,
    env_published: bool,
    config_published: bool,
) -> None:
    namespace, config_file, env_snapshot, config, env_file = _transaction(tmp_path, helper)
    original_config = config.read_bytes()
    original_env = env_file.read_bytes()
    real_fsync = os.fsync
    calls = 0

    def fail_selected_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == failed_fsync:
            raise OSError("injected fsync failure with a secret and path")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_selected_fsync)
    with pytest.raises(namespace["ConfigurationError"]) as captured:
        _commit(namespace, config_file, env_snapshot)

    assert message in _assert_fixed_failure(captured.value, tmp_path)
    assert env_file.read_bytes() == (SECRET_CONTENT if env_published else original_env)
    assert config.read_bytes() == (CONFIG_CONTENT if config_published else original_config)
    assert not tuple(config.parent.glob(".*.signet-demo-*"))


@pytest.mark.parametrize("helper", HELPERS, ids=("demo", "disabled"))
def test_profile_transaction_reports_retained_secret_when_checked_unlink_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: Path,
) -> None:
    namespace, config_file, env_snapshot, config, env_file = _transaction(tmp_path, helper)
    real_fsync = os.fsync
    real_unlink = os.unlink
    fsync_calls = 0
    unlink_calls = 0

    def fail_before_publish(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 3:
            raise OSError("injected pre-publication fsync failure")
        real_fsync(descriptor)

    def fail_first_unlink(path: str | bytes, *args: Any, **kwargs: Any) -> None:
        nonlocal unlink_calls
        unlink_calls += 1
        if unlink_calls == 1:
            raise OSError("injected unlink failure")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "fsync", fail_before_publish)
    monkeypatch.setattr(os, "unlink", fail_first_unlink)
    with pytest.raises(namespace["ConfigurationError"]) as captured:
        _commit(namespace, config_file, env_snapshot)

    message = _assert_fixed_failure(captured.value, tmp_path)
    assert "temporary cleanup could not be confirmed" in message
    assert config.read_bytes() == config_file.value
    assert env_file.read_bytes() == env_snapshot.value
    retained = tuple(config.parent.glob(".*.signet-demo-*"))
    assert len(retained) == 1
    assert retained[0].read_bytes() == SECRET_CONTENT
    assert stat.S_IMODE(retained[0].stat().st_mode) == 0o600


@pytest.mark.parametrize("helper", HELPERS, ids=("demo", "disabled"))
@pytest.mark.parametrize(
    ("empty_regular_fstat", "cleanup_confirmed"),
    ((2, False), (3, True)),
    ids=("before-identity", "after-identity"),
)
def test_profile_transaction_contains_temporary_fstat_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: Path,
    empty_regular_fstat: int,
    cleanup_confirmed: bool,
) -> None:
    namespace, config_file, env_snapshot, config, _env_file = _transaction(tmp_path, helper)
    real_fstat = os.fstat
    empty_regular_calls = 0

    def fail_selected_fstat(descriptor: int) -> os.stat_result:
        nonlocal empty_regular_calls
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size == 0:
            empty_regular_calls += 1
            if empty_regular_calls == empty_regular_fstat:
                raise OSError("injected fstat failure")
        return metadata

    monkeypatch.setattr(os, "fstat", fail_selected_fstat)
    with pytest.raises(namespace["ConfigurationError"]) as captured:
        _commit(namespace, config_file, env_snapshot)

    message = _assert_fixed_failure(captured.value, tmp_path)
    temporaries = tuple(config.parent.glob(".*.signet-demo-*"))
    if cleanup_confirmed:
        assert "no profile file was published" in message
        assert temporaries == ()
    else:
        assert "cleanup could not be confirmed" in message
        assert len(temporaries) == 1
        assert temporaries[0].read_bytes() == b""


@pytest.mark.parametrize("helper", HELPERS, ids=("demo", "disabled"))
def test_profile_transaction_cleans_identity_bound_file_after_fchmod_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: Path,
) -> None:
    namespace, config_file, env_snapshot, config, _env_file = _transaction(tmp_path, helper)

    def fail_fchmod(descriptor: int, mode: int) -> None:
        del descriptor, mode
        raise OSError("injected fchmod failure")

    monkeypatch.setattr(os, "fchmod", fail_fchmod)
    with pytest.raises(namespace["ConfigurationError"]) as captured:
        _commit(namespace, config_file, env_snapshot)

    assert "no profile file was published" in _assert_fixed_failure(captured.value, tmp_path)
    assert not tuple(config.parent.glob(".*.signet-demo-*"))


@pytest.mark.parametrize("helper", HELPERS, ids=("demo", "disabled"))
def test_profile_transaction_rejects_temporary_acl_grant_and_cleans_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: Path,
) -> None:
    namespace, config_file, env_snapshot, config, _env_file = _transaction(tmp_path, helper)
    commit = namespace["_commit_profile_files"]
    acl_checks = 0

    def fail_temporary_acl(descriptor: int) -> None:
        nonlocal acl_checks
        del descriptor
        acl_checks += 1
        if acl_checks == 5:
            raise PrivatePathError("injected granting ACL")

    monkeypatch.setitem(commit.__globals__, "require_no_acl_grants", fail_temporary_acl)
    with pytest.raises(namespace["ConfigurationError"]) as captured:
        _commit(namespace, config_file, env_snapshot)

    assert "no profile file was published" in _assert_fixed_failure(captured.value, tmp_path)
    assert not tuple(config.parent.glob(".*.signet-demo-*"))


@pytest.mark.parametrize("helper", HELPERS, ids=("demo", "disabled"))
@pytest.mark.parametrize(
    ("failed_close", "message", "published"),
    (
        (3, "temporary cleanup could not be confirmed", False),
        (8, "descriptor cleanup could not be confirmed", True),
    ),
    ids=("temporary-close", "final-lock-close"),
)
def test_profile_transaction_contains_close_failures_without_masking_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: Path,
    failed_close: int,
    message: str,
    published: bool,
) -> None:
    namespace, config_file, env_snapshot, config, env_file = _transaction(tmp_path, helper)
    real_close = os.close
    close_calls = 0

    def fail_selected_close(descriptor: int) -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == failed_close:
            real_close(descriptor)
            raise OSError("injected close failure")
        real_close(descriptor)

    monkeypatch.setattr(os, "close", fail_selected_close)
    with pytest.raises(namespace["ConfigurationError"]) as captured:
        _commit(namespace, config_file, env_snapshot)

    assert message in _assert_fixed_failure(captured.value, tmp_path)
    assert config.read_bytes() == (CONFIG_CONTENT if published else config_file.value)
    assert env_file.read_bytes() == (SECRET_CONTENT if published else env_snapshot.value)
    assert not tuple(config.parent.glob(".*.signet-demo-*"))
