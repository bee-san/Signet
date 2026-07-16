from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "validate-private-paths.py"
PREPARE_SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "prepare-owned-directory.py"


def run_validator(directory: Path, *private_files: Path) -> subprocess.CompletedProcess[str]:
    arguments = [sys.executable, str(SCRIPT), "--directory", str(directory)]
    for path in private_files:
        arguments.extend(("--private-file", str(path)))
    return subprocess.run(arguments, check=False, text=True, capture_output=True, timeout=5)


def run_tree_validator(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--directory",
            str(directory),
            "--private-tree",
        ],
        check=False,
        text=True,
        capture_output=True,
        timeout=5,
    )


def run_preparer(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PREPARE_SCRIPT), "--directory", str(directory)],
        check=False,
        text=True,
        capture_output=True,
        timeout=5,
    )


def test_validator_accepts_stable_ancestry_and_exact_private_files(tmp_path: Path) -> None:
    parent = tmp_path.resolve(strict=True) / "private"
    parent.mkdir(mode=0o700)
    first = parent / "first.plist"
    second = parent / "second.plist"
    for path in (first, second):
        path.write_text("reviewed\n", encoding="utf-8")
        path.chmod(0o600)

    result = run_validator(parent, first, second)

    assert result.returncode == 0, result
    assert result.stdout == ""
    assert result.stderr == ""


def test_validator_rejects_writable_ancestor_links_and_unsafe_files(tmp_path: Path) -> None:
    base = tmp_path.resolve(strict=True)
    writable = base / "writable"
    writable.mkdir(mode=0o700)
    writable.chmod(0o777)
    child = writable / "child"
    child.mkdir(mode=0o700)
    assert run_validator(child).returncode != 0

    target = base / "target"
    target.mkdir(mode=0o700)
    linked = base / "linked"
    linked.symlink_to(target, target_is_directory=True)
    assert run_validator(linked).returncode != 0

    unsafe_file = target / "unsafe.plist"
    unsafe_file.write_text("unsafe\n", encoding="utf-8")
    unsafe_file.chmod(0o644)
    assert run_validator(target, unsafe_file).returncode != 0

    safe_file = target / "safe.plist"
    safe_file.write_text("safe\n", encoding="utf-8")
    safe_file.chmod(0o600)
    alias = target / "alias.plist"
    os.link(safe_file, alias)
    assert run_validator(target, safe_file).returncode != 0

    fifo = target / "blocking.fifo"
    os.mkfifo(fifo, mode=0o600)
    assert run_validator(target, fifo).returncode != 0


def test_preparer_creates_private_components_and_rejects_unsafe_ancestry(
    tmp_path: Path,
) -> None:
    home = tmp_path.resolve(strict=True) / "home"
    home.mkdir(mode=0o700)
    profiles = home / ".hermes" / "profiles"

    prepared = run_preparer(profiles)

    assert prepared.returncode == 0, prepared
    for directory in (home / ".hermes", profiles):
        assert directory.stat().st_mode & 0o777 == 0o700

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    refused = run_preparer(unsafe / "profiles")
    assert refused.returncode != 0
    assert not (unsafe / "profiles").exists()

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    assert run_preparer(linked / "profiles").returncode != 0
    assert tuple(target.iterdir()) == ()


def test_validator_rejects_unencodable_directory_path_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("validate_private_paths", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    result: int | None = None
    with pytest.raises(SystemExit) as raised:
        result = module.main(["--directory", f"{tmp_path}/invalid\ud800path"])

    assert result is None
    assert raised.value.code == 1
    assert "Traceback" not in capsys.readouterr().err


def test_validator_rejects_unencodable_private_file_path_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from importlib.util import module_from_spec, spec_from_file_location

    parent = tmp_path.resolve(strict=True) / "private"
    parent.mkdir(mode=0o700)
    spec = spec_from_file_location("validate_private_files", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    result: int | None = None
    with pytest.raises(SystemExit) as raised:
        result = module.main(
            [
                "--directory",
                str(parent),
                "--private-file",
                f"{parent}/invalid\ud800file",
            ]
        )

    assert result is None
    assert raised.value.code == 1
    assert "Traceback" not in capsys.readouterr().err


def test_validator_refuses_special_file_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from importlib.util import module_from_spec, spec_from_file_location

    parent = tmp_path.resolve(strict=True) / "private"
    parent.mkdir(mode=0o700)
    selected = parent / "special.fifo"
    os.mkfifo(selected, mode=0o600)
    spec = spec_from_file_location("validate_special_file", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    real_open = os.open
    special_opened = False

    def guarded_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal special_opened
        if path == selected.name:
            special_opened = True
            raise AssertionError("special file must be rejected before open")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", guarded_open)
    try:
        with pytest.raises(module.ValidationError, match="type is unsafe"):
            module._validate_private_file(selected, parent=parent, parent_fd=parent_fd)
    finally:
        os.close(parent_fd)

    assert special_opened is False


def test_private_tree_validator_accepts_realistic_nested_state_and_rejects_unsafe_entries(
    tmp_path: Path,
) -> None:
    tree = tmp_path.resolve(strict=True) / "profile"
    tree.mkdir(mode=0o700)
    logs = tree / "logs"
    sessions = tree / "sessions" / "nested"
    logs.mkdir(mode=0o700)
    sessions.parent.mkdir(mode=0o700)
    sessions.mkdir(mode=0o700)
    for path, content in (
        (tree / ".env", "# private\n"),
        (tree / "config.yaml", "mcp_servers: {}\n"),
        (logs / "agent.log", ""),
        (sessions / "state.json", "{}\n"),
    ):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    accepted = run_tree_validator(tree)
    assert accepted.returncode == 0, accepted
    assert accepted.stdout == ""
    assert accepted.stderr == ""

    unsafe_mode = logs / "unsafe-mode"
    unsafe_mode.write_text("unsafe\n", encoding="utf-8")
    unsafe_mode.chmod(0o644)
    assert run_tree_validator(tree).returncode != 0
    unsafe_mode.unlink()

    linked = logs / "linked"
    linked.symlink_to(tree / ".env")
    assert run_tree_validator(tree).returncode != 0
    linked.unlink()

    hardlink = logs / "hardlink"
    os.link(tree / ".env", hardlink)
    assert run_tree_validator(tree).returncode != 0
    hardlink.unlink()

    fifo = logs / "special.fifo"
    os.mkfifo(fifo, mode=0o600)
    assert run_tree_validator(tree).returncode != 0


def test_private_tree_validator_enforces_root_mode_and_resource_bounds(tmp_path: Path) -> None:
    base = tmp_path.resolve(strict=True)

    public_root = base / "public-root"
    public_root.mkdir(mode=0o755)
    assert run_tree_validator(public_root).returncode != 0

    deep = base / "deep"
    deep.mkdir(mode=0o700)
    selected = deep
    for index in range(17):
        selected /= str(index)
        selected.mkdir(mode=0o700)
    assert run_tree_validator(deep).returncode != 0

    crowded = base / "crowded"
    crowded.mkdir(mode=0o700)
    for index in range(1025):
        selected_file = crowded / str(index)
        selected_file.touch(mode=0o600)
    assert run_tree_validator(crowded).returncode != 0

    oversized = base / "oversized"
    oversized.mkdir(mode=0o700)
    large_file = oversized / "large"
    with large_file.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024 + 1)
    large_file.chmod(0o600)
    assert run_tree_validator(oversized).returncode != 0


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_validator_accepts_deny_only_and_rejects_granting_darwin_file_acl(
    tmp_path: Path,
) -> None:
    parent = tmp_path.resolve(strict=True) / "private"
    parent.mkdir(mode=0o700)
    denied = parent / "deny-only.plist"
    allowed = parent / "granting.plist"
    for selected in (denied, allowed):
        selected.write_text("private\n", encoding="utf-8")
        selected.chmod(0o600)
    subprocess.run(
        ["chmod", "+a", "everyone deny delete", str(denied)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["chmod", "+a", "everyone allow read,write", str(allowed)],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        assert run_validator(parent, denied).returncode == 0
        assert run_validator(parent, allowed).returncode != 0
        assert run_tree_validator(parent).returncode != 0
        allowed.unlink()
        assert run_tree_validator(parent).returncode == 0
    finally:
        for selected in (denied, allowed):
            if not selected.exists():
                continue
            subprocess.run(
                ["chmod", "-N", str(selected)],
                check=True,
                capture_output=True,
                text=True,
            )
