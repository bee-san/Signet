from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import signet.private_paths as private_paths_module
from signet.private_paths import (
    PrivatePathError,
    capture_owned_directory_identity,
    ensure_owned_directory,
    ensure_private_directory,
    harden_private_directory_identity,
    require_no_acl_grants,
    require_owned_directory,
    require_owned_directory_identity,
    require_private_directory,
    revalidate_directory_identity,
)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_private_directory_is_created_with_exact_private_mode(tmp_path: Path) -> None:
    selected = tmp_path / "new" / "private"

    resolved = ensure_private_directory(selected)

    assert resolved == selected.resolve()
    assert mode(selected) == 0o700


def test_captured_mode_zero_directory_is_hardened_safely(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "captured-mode-zero"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)

    hardened = harden_private_directory_identity(identity)

    assert identity.same_object(hardened)
    assert mode(selected) == 0o700


def _emulate_darwin_private_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(private_paths_module, "_DARWIN", True)
    monkeypatch.setattr(private_paths_module, "_LINUX", False)
    monkeypatch.setattr(
        private_paths_module,
        "_darwin_descriptor_acl_grants_access",
        lambda _descriptor: False,
    )


def test_darwin_mode_zero_recovery_is_parent_anchored_and_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "captured-darwin-mode-zero"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)
    real_chmod = private_paths_module.os.chmod
    calls: list[tuple[Any, int, int | None, bool]] = []

    def track_chmod(
        path: Any,
        selected_mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        calls.append((path, selected_mode, dir_fd, follow_symlinks))
        real_chmod(
            path,
            selected_mode,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    _emulate_darwin_private_paths(monkeypatch)
    monkeypatch.setattr(private_paths_module.os, "chmod", track_chmod)

    hardened = harden_private_directory_identity(identity)

    assert identity.same_object(hardened)
    assert mode(selected) == 0o700
    assert len(calls) == 1
    component, selected_mode, parent_descriptor, follow_symlinks = calls[0]
    assert component == selected.name
    assert selected_mode == 0o700
    assert parent_descriptor is not None
    assert follow_symlinks is False


def test_darwin_mode_zero_recovery_fails_closed_without_fchmodat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "captured-darwin-unsupported"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)
    real_chmod = private_paths_module.os.chmod
    _emulate_darwin_private_paths(monkeypatch)
    monkeypatch.setattr(
        private_paths_module.os,
        "chmod",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(NotImplementedError),
    )

    try:
        with pytest.raises(PrivatePathError, match="descriptor-relative.*unavailable"):
            harden_private_directory_identity(identity)
        assert stat.S_IMODE(selected.lstat().st_mode) == 0o000
    finally:
        real_chmod(selected, 0o700)


def test_darwin_mode_zero_recovery_never_follows_a_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "captured-darwin-swap"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)
    displaced = tmp_path / "captured-darwin-displaced"
    outside = tmp_path / "captured-darwin-outside"
    outside.mkdir(mode=0o700)
    outside.chmod(0o500)
    real_chmod = private_paths_module.os.chmod
    swapped = False

    def swap_before_chmod(
        path: Any,
        selected_mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        assert path == selected.name
        assert dir_fd is not None
        assert follow_symlinks is False
        real_chmod(selected, 0o700)
        selected.rename(displaced)
        selected.symlink_to(outside, target_is_directory=True)
        swapped = True
        real_chmod(
            path,
            selected_mode,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    _emulate_darwin_private_paths(monkeypatch)
    monkeypatch.setattr(private_paths_module.os, "chmod", swap_before_chmod)

    with pytest.raises(PrivatePathError):
        harden_private_directory_identity(identity)

    assert swapped
    assert selected.is_symlink()
    assert stat.S_IMODE(outside.stat().st_mode) == 0o500
    selected.unlink()
    real_chmod(displaced, 0o700)
    displaced.rmdir()
    real_chmod(outside, 0o700)
    outside.rmdir()


def test_darwin_mode_zero_recovery_rejects_a_same_user_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "captured-darwin-directory-swap"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)
    displaced = tmp_path / "captured-darwin-original"
    real_chmod = private_paths_module.os.chmod
    swapped = False

    def swap_before_chmod(
        path: Any,
        selected_mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        assert path == selected.name
        assert dir_fd is not None
        assert follow_symlinks is False
        real_chmod(selected, 0o700)
        selected.rename(displaced)
        selected.mkdir(mode=0o700)
        (selected / "replacement-marker").write_text("preserve\n", encoding="utf-8")
        real_chmod(selected, 0o500)
        swapped = True
        real_chmod(
            path,
            selected_mode,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    _emulate_darwin_private_paths(monkeypatch)
    monkeypatch.setattr(private_paths_module.os, "chmod", swap_before_chmod)

    with pytest.raises(PrivatePathError, match="could not be confirmed"):
        harden_private_directory_identity(identity)

    assert swapped
    assert (selected / "replacement-marker").read_text(encoding="utf-8") == "preserve\n"
    assert mode(selected) == 0o700
    assert stat.S_IMODE(displaced.lstat().st_mode) == 0o700
    real_chmod(displaced, 0o700)


def test_darwin_mode_zero_recovery_rejects_an_unsafe_parent_before_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "darwin-unsafe-parent"
    parent.mkdir(mode=0o700)
    selected = parent / "captured"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)
    parent.chmod(0o777)
    real_chmod = private_paths_module.os.chmod
    _emulate_darwin_private_paths(monkeypatch)
    monkeypatch.setattr(
        private_paths_module.os,
        "chmod",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unsafe parent must be rejected before chmod")
        ),
    )

    try:
        with pytest.raises(PrivatePathError):
            harden_private_directory_identity(identity)
    finally:
        real_chmod(selected, 0o700)
        real_chmod(parent, 0o700)


def test_darwin_recursive_creation_is_parent_anchored_under_restrictive_umask(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "darwin-first" / "darwin-second" / "private"
    real_chmod = private_paths_module.os.chmod
    calls: list[tuple[Any, int | None, bool]] = []

    def track_chmod(
        path: Any,
        selected_mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        assert selected_mode == 0o700
        calls.append((path, dir_fd, follow_symlinks))
        real_chmod(
            path,
            selected_mode,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    _emulate_darwin_private_paths(monkeypatch)
    monkeypatch.setattr(private_paths_module.os, "chmod", track_chmod)
    previous_umask = os.umask(0o777)
    try:
        resolved = ensure_private_directory(selected)
    finally:
        os.umask(previous_umask)

    assert resolved == selected.resolve(strict=True)
    assert len(calls) == 3
    assert all(Path(component).name == component for component, _fd, _follow in calls)
    assert all(parent_descriptor is not None for _path, parent_descriptor, _follow in calls)
    assert all(follow_symlinks is False for _path, _fd, follow_symlinks in calls)
    for directory in (selected.parent.parent, selected.parent, selected):
        assert mode(directory) == 0o700


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux O_PATH regression")
def test_linux_mode_zero_hardening_fails_closed_without_proc_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "captured-no-fchmodat2"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)
    real_chmod = private_paths_module.os.chmod
    chmod_paths: list[Path] = []

    def reject_proc_chmod(path: object, *_args: object, **_kwargs: object) -> None:
        chmod_paths.append(Path(path))
        raise OSError("injected missing proc descriptor")

    monkeypatch.setattr(private_paths_module.os, "chmod", reject_proc_chmod)

    with pytest.raises(PrivatePathError, match="descriptor-bound.*unavailable"):
        harden_private_directory_identity(identity)

    assert len(chmod_paths) == 1
    assert chmod_paths[0].parent == Path("/proc/self/fd")
    assert chmod_paths[0] != selected
    real_chmod(selected, 0o700)


@pytest.mark.parametrize("unsafe_mode", [0o770, 0o777, 0o1777])
def test_existing_unsafe_directory_is_refused_without_chmod(
    tmp_path: Path,
    unsafe_mode: int,
) -> None:
    selected = tmp_path / "unsafe"
    selected.mkdir()
    selected.chmod(unsafe_mode)

    with pytest.raises(PrivatePathError, match="owned safe"):
        ensure_private_directory(selected)

    assert mode(selected) == unsafe_mode


def test_symlinked_directory_or_parent_is_refused(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    direct_link = tmp_path / "link"
    direct_link.symlink_to(private, target_is_directory=True)

    with pytest.raises(PrivatePathError):
        ensure_private_directory(direct_link)

    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(private, target_is_directory=True)
    with pytest.raises(PrivatePathError):
        ensure_private_directory(parent_link / "child")
    assert tuple(private.iterdir()) == ()


def test_recursive_directory_creation_is_descriptor_anchored_and_umask_proof(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "first" / "second" / "private"

    previous_umask = os.umask(0o777)
    try:
        resolved = ensure_private_directory(selected)
    finally:
        os.umask(previous_umask)

    assert resolved == selected.resolve(strict=True)
    for directory in (selected.parent.parent, selected.parent, selected):
        assert mode(directory) == 0o700


def test_owned_output_parent_keeps_existing_mode_and_refuses_writers(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "output"
    selected.mkdir(mode=0o755)
    os.chmod(selected, 0o755)

    assert ensure_owned_directory(selected) == selected.resolve()
    assert mode(selected) == 0o755

    os.chmod(selected, 0o775)
    with pytest.raises(PrivatePathError):
        ensure_owned_directory(selected)
    assert mode(selected) == 0o775


def test_required_owned_directory_never_creates_through_a_linked_ancestor(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)

    with pytest.raises(PrivatePathError, match="unavailable or unsafe"):
        require_owned_directory(linked / "missing")

    assert not (target / "missing").exists()


def test_parent_traversal_is_rejected_before_path_normalization(tmp_path: Path) -> None:
    base = tmp_path.resolve(strict=True)
    outside = base / "outside"
    nested = outside / "nested"
    nested.mkdir(parents=True, mode=0o700)
    linked = base / "linked"
    linked.symlink_to(nested, target_is_directory=True)

    for selected in (
        linked / ".." / "target",
        base / "missing" / ".." / "target",
    ):
        with pytest.raises(PrivatePathError, match="parent traversal"):
            ensure_private_directory(selected)

    assert not (base / "target").exists()
    assert not (outside / "target").exists()
    assert not (base / "missing").exists()

    with pytest.raises(PrivatePathError, match="invalid component"):
        ensure_private_directory(Path(f"{base}/invalid\x00component"))

    with pytest.raises(PrivatePathError, match="invalid component"):
        ensure_private_directory(base / "invalid\ud800component")


def test_required_private_directory_rejects_links_and_symlink_loops(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    assert require_private_directory(private) == private.resolve(strict=True)

    linked = tmp_path / "linked"
    linked.symlink_to(private, target_is_directory=True)
    with pytest.raises(PrivatePathError):
        require_private_directory(linked)

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(second, target_is_directory=True)
    second.symlink_to(first, target_is_directory=True)
    with pytest.raises(PrivatePathError, match="opened safely"):
        require_private_directory(first)


def test_directory_ancestry_rejects_unprotected_writers_but_allows_sticky_tmp(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable"
    writable.mkdir(mode=0o700)
    writable.chmod(0o777)
    unsafe_child = writable / "child"
    unsafe_child.mkdir(mode=0o700)

    with pytest.raises(PrivatePathError, match="opened safely"):
        require_owned_directory(unsafe_child)

    sticky = tmp_path / "sticky"
    sticky.mkdir(mode=0o700)
    sticky.chmod(0o1777)
    protected_child = sticky / "child"
    protected_child.mkdir(mode=0o700)

    assert require_owned_directory(protected_child) == protected_child.resolve(strict=True)


def test_directory_identity_detects_same_path_parent_replacement(tmp_path: Path) -> None:
    selected = tmp_path / "selected"
    selected.mkdir(mode=0o700)
    identity = require_owned_directory_identity(selected)

    displaced = tmp_path / "displaced"
    selected.rename(displaced)
    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)
    replacement.rename(selected)

    with pytest.raises(PrivatePathError, match="identity changed"):
        revalidate_directory_identity(identity, private=False)


def test_ancestry_edge_trusts_only_root_or_current_owned_parents() -> None:
    current_uid = 1_000
    current_child = os.stat_result((stat.S_IFDIR | 0o700, 2, 1, 1, current_uid, 0, 0, 0, 0, 0))

    for mode in (0o755, 0o555, 0o1777):
        foreign_parent = os.stat_result(
            (stat.S_IFDIR | mode, 1, 1, 1, current_uid + 1, 0, 0, 0, 0, 0)
        )
        assert not private_paths_module._ancestor_edge_is_stable(
            foreign_parent,
            current_child,
            current_uid,
        )

    for owner_uid in (0, current_uid):
        sticky_parent = os.stat_result((stat.S_IFDIR | 0o1777, 1, 1, 1, owner_uid, 0, 0, 0, 0, 0))
        assert private_paths_module._ancestor_edge_is_stable(
            sticky_parent,
            current_child,
            current_uid,
        )


def test_extended_acl_check_is_a_noop_off_darwin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "regular"
    selected.write_bytes(b"data")
    descriptor = os.open(selected, os.O_RDONLY)

    def unexpected_inspection(_descriptor: int) -> bool:
        raise AssertionError("native Darwin ACL API must not run on this platform")

    monkeypatch.setattr(private_paths_module, "_DARWIN", False)
    monkeypatch.setattr(
        private_paths_module,
        "_darwin_descriptor_acl_grants_access",
        unexpected_inspection,
    )
    try:
        require_no_acl_grants(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    ("inspection", "message"),
    [
        (lambda _descriptor: True, "granting ACL entries are not allowed"),
        (
            lambda _descriptor: (_ for _ in ()).throw(
                PrivatePathError("ACL inspection is unavailable")
            ),
            "inspection is unavailable",
        ),
    ],
)
def test_extended_acl_check_fails_closed_on_darwin(
    monkeypatch: pytest.MonkeyPatch,
    inspection: Callable[[int], bool],
    message: str,
) -> None:
    monkeypatch.setattr(private_paths_module, "_DARWIN", True)
    monkeypatch.setattr(
        private_paths_module,
        "_darwin_descriptor_acl_grants_access",
        inspection,
    )

    with pytest.raises(PrivatePathError, match=message):
        require_no_acl_grants(42)


class _NativeFunction:
    def __init__(self, callback: Callable[..., object]) -> None:
        self.callback = callback
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: object) -> object:
        return self.callback(*args)


@pytest.mark.parametrize(
    ("acl_present", "tags", "expected"),
    [
        (False, [], False),
        (True, [], False),
        (True, [2], False),
        (True, [2, 2], False),
        (True, [1], True),
        (True, [2, 1], True),
    ],
)
def test_native_darwin_acl_inspection_accepts_only_absent_or_deny_only_acl(
    monkeypatch: pytest.MonkeyPatch,
    acl_present: bool,
    tags: list[int],
    expected: bool,
) -> None:
    position = 0

    def get_acl(*_args: object) -> int | None:
        if acl_present:
            return 1234
        private_paths_module.ctypes.set_errno(private_paths_module.errno.ENOENT)
        return None

    def get_entry(*_args: object) -> int:
        if position < len(tags):
            return 0
        private_paths_module.ctypes.set_errno(private_paths_module.errno.EINVAL)
        return -1

    def get_tag(_entry: object, tag_pointer: object) -> int:
        nonlocal position
        pointer = private_paths_module.ctypes.cast(
            tag_pointer,
            private_paths_module.ctypes.POINTER(private_paths_module.ctypes.c_int),
        )
        pointer.contents.value = tags[position]
        position += 1
        return 0

    library = SimpleNamespace(
        acl_get_fd_np=_NativeFunction(get_acl),
        acl_valid=_NativeFunction(lambda *_args: 0),
        acl_get_entry=_NativeFunction(get_entry),
        acl_get_tag_type=_NativeFunction(get_tag),
        acl_free=_NativeFunction(lambda *_args: 0),
    )
    monkeypatch.setattr(
        private_paths_module.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: library,
    )

    assert private_paths_module._darwin_descriptor_acl_grants_access(42) is expected


@pytest.mark.parametrize(
    "missing_symbol",
    ["acl_get_fd_np", "acl_valid", "acl_get_entry", "acl_get_tag_type", "acl_free"],
)
def test_native_darwin_acl_inspection_rejects_unavailable_api(
    monkeypatch: pytest.MonkeyPatch,
    missing_symbol: str,
) -> None:
    functions: dict[str, Any] = {
        "acl_get_fd_np": _NativeFunction(lambda *_args: 1234),
        "acl_valid": _NativeFunction(lambda *_args: 0),
        "acl_get_entry": _NativeFunction(lambda *_args: -1),
        "acl_get_tag_type": _NativeFunction(lambda *_args: 0),
        "acl_free": _NativeFunction(lambda *_args: 0),
    }
    del functions[missing_symbol]
    monkeypatch.setattr(
        private_paths_module.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: SimpleNamespace(**functions),
    )

    with pytest.raises(PrivatePathError, match="inspection is unavailable"):
        private_paths_module._darwin_descriptor_acl_grants_access(42)


@pytest.mark.parametrize("operation", ["get", "validate", "entry", "tag", "free"])
def test_native_darwin_acl_inspection_rejects_api_errors(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    def get_acl(*_args: object) -> int | None:
        if operation == "get":
            private_paths_module.ctypes.set_errno(private_paths_module.errno.EIO)
            return None
        return 1234

    def free_acl(*_args: object) -> int:
        if operation == "free":
            private_paths_module.ctypes.set_errno(private_paths_module.errno.EIO)
            return -1
        return 0

    def native_result(selected_operation: str) -> int:
        if operation == selected_operation:
            private_paths_module.ctypes.set_errno(private_paths_module.errno.EIO)
            return -1
        return 0

    library = SimpleNamespace(
        acl_get_fd_np=_NativeFunction(get_acl),
        acl_valid=_NativeFunction(lambda *_args: native_result("validate")),
        acl_get_entry=_NativeFunction(lambda *_args: native_result("entry")),
        acl_get_tag_type=_NativeFunction(lambda *_args: native_result("tag")),
        acl_free=_NativeFunction(free_acl),
    )
    monkeypatch.setattr(
        private_paths_module.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: library,
    )

    with pytest.raises(PrivatePathError, match="ACL"):
        private_paths_module._darwin_descriptor_acl_grants_access(42)


def test_native_darwin_acl_inspection_rejects_unknown_entry_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def get_tag(_entry: object, tag_pointer: object) -> int:
        pointer = private_paths_module.ctypes.cast(
            tag_pointer,
            private_paths_module.ctypes.POINTER(private_paths_module.ctypes.c_int),
        )
        pointer.contents.value = 0
        return 0

    library = SimpleNamespace(
        acl_get_fd_np=_NativeFunction(lambda *_args: 1234),
        acl_valid=_NativeFunction(lambda *_args: 0),
        acl_get_entry=_NativeFunction(lambda *_args: 0),
        acl_get_tag_type=_NativeFunction(get_tag),
        acl_free=_NativeFunction(lambda *_args: 0),
    )
    monkeypatch.setattr(
        private_paths_module.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: library,
    )

    with pytest.raises(PrivatePathError, match="unknown entry type"):
        private_paths_module._darwin_descriptor_acl_grants_access(42)


def test_created_directory_rejected_for_inherited_acl_is_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_root = tmp_path.resolve(strict=True) / "created-root"
    selected = created_root / "nested" / "created"
    calls = 0

    def reject_new_component(_descriptor: int) -> bool:
        nonlocal calls
        calls += 1
        return calls == len(selected.parts)

    monkeypatch.setattr(private_paths_module, "_DARWIN", True)
    monkeypatch.setattr(
        private_paths_module,
        "_darwin_descriptor_acl_grants_access",
        reject_new_component,
    )

    with pytest.raises(PrivatePathError, match="opened safely"):
        ensure_private_directory(selected)

    assert not created_root.exists()


def test_created_directory_is_removed_when_descriptor_open_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_root = tmp_path.resolve(strict=True) / "created-root"
    selected = created_root / "nested" / "created"
    real_open = private_paths_module.os.open

    def fail_final_created_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == selected.name and dir_fd is not None:
            raise OSError("injected descriptor-open failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(private_paths_module.os, "open", fail_final_created_open)

    with pytest.raises(PrivatePathError, match="opened safely"):
        ensure_private_directory(selected)

    assert not created_root.exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_real_darwin_protective_deny_acl_is_accepted(tmp_path: Path) -> None:
    selected = tmp_path / "deny-only-acl"
    selected.mkdir(mode=0o700)
    subprocess.run(
        ["chmod", "+a", "everyone deny delete", str(selected)],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        assert require_private_directory(selected) == selected.resolve(strict=True)
    finally:
        subprocess.run(["chmod", "-N", str(selected)], check=True, capture_output=True, text=True)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_real_darwin_granting_acl_on_directory_is_rejected(tmp_path: Path) -> None:
    selected = tmp_path / "allow-acl"
    selected.mkdir(mode=0o700)
    subprocess.run(
        ["chmod", "+a", "everyone allow read,write,execute", str(selected)],
        check=True,
        capture_output=True,
        text=True,
    )

    try:
        with pytest.raises(PrivatePathError, match="opened safely"):
            require_private_directory(selected)
    finally:
        subprocess.run(["chmod", "-N", str(selected)], check=True, capture_output=True, text=True)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_real_darwin_mode_zero_target_granting_acl_is_rejected_after_recovery(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "mode-zero-target-allow-acl"
    selected.mkdir(mode=0o700)
    subprocess.run(
        ["chmod", "+a", "everyone allow delete", str(selected)],
        check=True,
        capture_output=True,
        text=True,
    )
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)

    try:
        with pytest.raises(PrivatePathError, match="granting ACL entries"):
            harden_private_directory_identity(identity)
        assert mode(selected) == 0o700
    finally:
        subprocess.run(["chmod", "-N", str(selected)], check=True, capture_output=True, text=True)
        selected.chmod(0o700)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACL regression")
def test_real_darwin_parent_granting_acl_blocks_mode_zero_recovery(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "mode-zero-parent-allow-acl"
    parent.mkdir(mode=0o700)
    selected = parent / "captured"
    selected.mkdir(mode=0o700)
    identity = capture_owned_directory_identity(selected)
    selected.chmod(0o000)
    subprocess.run(
        ["chmod", "+a", "everyone allow read", str(parent)],
        check=True,
        capture_output=True,
        text=True,
    )

    try:
        with pytest.raises(PrivatePathError, match="granting ACL entries"):
            harden_private_directory_identity(identity)
        assert stat.S_IMODE(selected.lstat().st_mode) == 0o000
    finally:
        subprocess.run(["chmod", "-N", str(parent)], check=True, capture_output=True, text=True)
        selected.chmod(0o700)
