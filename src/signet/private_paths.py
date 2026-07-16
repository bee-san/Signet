"""Descriptor-verified directory setup without mutating caller-owned paths."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

_DARWIN = sys.platform == "darwin"
_LINUX = sys.platform.startswith("linux")
_ACL_TYPE_EXTENDED = 0x00000100
_ACL_FIRST_ENTRY = 0
_ACL_NEXT_ENTRY = -1
_ACL_EXTENDED_ALLOW = 1
_ACL_EXTENDED_DENY = 2
_ACL_MAX_ENTRIES = 128


class PrivatePathError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class DirectoryIdentity:
    """A path plus the stable filesystem identity observed during verification."""

    path: Path
    device: int
    inode: int
    owner_uid: int

    def same_object(self, other: DirectoryIdentity) -> bool:
        return (
            self.device,
            self.inode,
            self.owner_uid,
        ) == (
            other.device,
            other.inode,
            other.owner_uid,
        )


def ensure_private_directory(path: Path) -> Path:
    """Create a private directory or require an existing exact mode-0700 path."""

    return _ensure_directory(Path(path), private=True)


def ensure_owned_directory(path: Path) -> Path:
    """Create a private directory or accept an owned, non-writable parent."""

    return _ensure_directory(Path(path), private=False, create=True)


def require_owned_directory(path: Path) -> Path:
    """Require an existing owned, non-writable directory without creating anything."""

    return _ensure_directory(Path(path), private=False, create=False)


def require_private_directory(path: Path) -> Path:
    """Require an existing owned mode-0700 directory without creating anything."""

    return _ensure_directory(Path(path), private=True, create=False)


def require_owned_directory_identity(path: Path) -> DirectoryIdentity:
    """Require an existing safe directory and capture its filesystem identity."""

    return _ensure_directory_identity(Path(path), private=False, create=False)


def require_private_directory_identity(path: Path) -> DirectoryIdentity:
    """Require an existing private directory and capture its filesystem identity."""

    return _ensure_directory_identity(Path(path), private=True, create=False)


def revalidate_directory_identity(
    identity: DirectoryIdentity,
    *,
    private: bool,
) -> Path:
    """Require that a verified path still names the same safe directory."""

    current = _ensure_directory_identity(identity.path, private=private, create=False)
    if not identity.same_object(current):
        raise PrivatePathError("directory identity changed")
    return current.path


def require_no_acl_grants(descriptor: int) -> None:
    """Reject macOS ALLOW entries while preserving ACLs that only restrict access."""

    if not _DARWIN:
        return
    if _darwin_descriptor_acl_grants_access(descriptor):
        raise PrivatePathError("granting ACL entries are not allowed on private paths")


def capture_owned_directory_identity(path: Path) -> DirectoryIdentity:
    """Capture one current-user-owned directory without changing it."""

    selected = Path(path)
    try:
        metadata = selected.lstat()
    except (OSError, ValueError) as exc:
        raise PrivatePathError("directory could not be inspected safely") from exc
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != current_uid:
        raise PrivatePathError("directory is unavailable or unsafe")
    return DirectoryIdentity(
        path=selected,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
    )


def harden_private_directory_identity(identity: DirectoryIdentity) -> DirectoryIdentity:
    """Set mode 0700 on one captured directory without following symlinks."""

    try:
        descriptor = _open_directory_identity_descriptor(identity.path)
    except PermissionError as exc:
        if not _DARWIN:
            raise PrivatePathError("captured directory could not be opened safely") from exc
        return _harden_darwin_directory_identity_from_parent(identity)
    except OSError as exc:
        raise PrivatePathError("captured directory could not be opened safely") from exc
    operation_error: BaseException | None = None
    try:
        hardened = _harden_directory_descriptor(descriptor, expected=identity)
        current = identity.path.lstat()
        if not _same_directory(hardened, current):
            raise PrivatePathError("directory identity changed during hardening")
        return DirectoryIdentity(
            path=identity.path,
            device=hardened.st_dev,
            inode=hardened.st_ino,
            owner_uid=hardened.st_uid,
        )
    except BaseException as exc:
        operation_error = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if operation_error is None:
                raise PrivatePathError(
                    "directory hardening descriptor could not be closed safely"
                ) from exc


def _harden_darwin_directory_identity_from_parent(
    identity: DirectoryIdentity,
) -> DirectoryIdentity:
    try:
        selected = Path(os.path.abspath(identity.path))
        encoded = os.fsencode(selected)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        raise PrivatePathError("captured directory path is unavailable or unsafe") from exc
    if b"\x00" in encoded or selected.name in {"", ".", ".."}:
        raise PrivatePathError("captured directory path is unavailable or unsafe")
    try:
        parent_descriptor = _open_with_stable_ancestry(selected.parent, create=False)
    except PrivatePathError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise PrivatePathError("captured directory parent could not be opened safely") from exc
    operation_error: BaseException | None = None
    try:
        hardened = _harden_directory_entry(
            parent_descriptor,
            selected.name,
            expected=identity,
        )
        current = selected.lstat()
        if not _same_directory(hardened, current):
            raise PrivatePathError("directory identity changed during hardening")
        return DirectoryIdentity(
            path=identity.path,
            device=hardened.st_dev,
            inode=hardened.st_ino,
            owner_uid=hardened.st_uid,
        )
    except BaseException as exc:
        operation_error = exc
        raise
    finally:
        try:
            os.close(parent_descriptor)
        except OSError as exc:
            if operation_error is None:
                raise PrivatePathError(
                    "directory hardening parent descriptor could not be closed safely"
                ) from exc


def harden_private_directory_descendant(
    root: DirectoryIdentity,
    relative: Path,
) -> DirectoryIdentity:
    """Harden a descendant through a captured root without following any path edge."""

    selected = Path(relative)
    parts = selected.parts
    if selected.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise PrivatePathError("private descendant path is unavailable or unsafe")
    flags = _normal_directory_open_flags()
    try:
        parent_descriptor = os.open(root.path, flags)
    except OSError as exc:
        raise PrivatePathError("private tree root could not be opened safely") from exc
    try:
        parent = os.fstat(parent_descriptor)
        if not _metadata_matches_identity(parent, root):
            raise PrivatePathError("private tree root identity changed")
        require_no_acl_grants(parent_descriptor)
        current_path = root.path
        for index, component in enumerate(parts):
            try:
                before = os.stat(component, dir_fd=parent_descriptor, follow_symlinks=False)
            except OSError as exc:
                raise PrivatePathError("private descendant could not be inspected safely") from exc
            expected = DirectoryIdentity(
                path=current_path / component,
                device=before.st_dev,
                inode=before.st_ino,
                owner_uid=before.st_uid,
            )
            hardened = _harden_directory_entry(
                parent_descriptor,
                component,
                expected=expected,
            )
            current_path = expected.path
            if index == len(parts) - 1:
                return DirectoryIdentity(
                    path=current_path,
                    device=hardened.st_dev,
                    inode=hardened.st_ino,
                    owner_uid=hardened.st_uid,
                )
            try:
                child_descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            except OSError as exc:
                raise PrivatePathError("private descendant ancestry could not be opened") from exc
            try:
                opened = os.fstat(child_descriptor)
                if not _same_directory(hardened, opened):
                    raise PrivatePathError("private descendant ancestry changed")
                require_no_acl_grants(child_descriptor)
            except BaseException:
                os.close(child_descriptor)
                raise
            os.close(parent_descriptor)
            parent_descriptor = child_descriptor
        raise PrivatePathError("private descendant path is unavailable or unsafe")
    finally:
        os.close(parent_descriptor)


def _ensure_directory(path: Path, *, private: bool, create: bool = True) -> Path:
    return _ensure_directory_identity(path, private=private, create=create).path


def _ensure_directory_identity(
    path: Path,
    *,
    private: bool,
    create: bool = True,
) -> DirectoryIdentity:
    try:
        expanded = path.expanduser()
    except (OSError, RuntimeError) as exc:
        raise PrivatePathError("directory path could not be expanded safely") from exc
    if any("\x00" in component for component in expanded.parts):
        raise PrivatePathError("directory path contains an invalid component")
    if ".." in expanded.parts:
        raise PrivatePathError("directory path must not contain parent traversal")
    try:
        os.fsencode(expanded)
        selected = Path(os.path.abspath(expanded))
    except (OSError, RuntimeError, ValueError) as exc:
        raise PrivatePathError("directory path contains an invalid component") from exc
    if not create:
        try:
            selected.lstat()
        except FileNotFoundError:
            raise PrivatePathError("directory is unavailable or unsafe") from None
        except (OSError, ValueError) as exc:
            raise PrivatePathError("directory could not be inspected safely") from exc

    descriptor: int | None = None
    try:
        descriptor = _open_with_stable_ancestry(selected, create=create)
        resolved = selected.resolve(strict=True)
        opened = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        before = selected.lstat()
    except (OSError, RuntimeError, ValueError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise PrivatePathError("directory could not be opened safely") from exc

    try:
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        mode = stat.S_IMODE(opened.st_mode)
        unsafe_mode = mode != 0o700 if private else bool(mode & 0o022)
        if (
            resolved != selected
            or not stat.S_ISDIR(before.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != current_uid
            or unsafe_mode
        ):
            raise PrivatePathError("directory is not an owned safe directory")
        return DirectoryIdentity(
            path=resolved,
            device=opened.st_dev,
            inode=opened.st_ino,
            owner_uid=opened.st_uid,
        )
    finally:
        os.close(descriptor)


def _open_with_stable_ancestry(selected: Path, *, create: bool) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor = os.open(selected.anchor, flags)
    created_directories: list[tuple[int, str, int, int]] = []
    try:
        parent = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        for component in selected.parts[1:]:
            created = False
            try:
                before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not create or not _parent_accepts_current_owned_child(parent, current_uid):
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if created:
                    expected = DirectoryIdentity(
                        path=selected,
                        device=before.st_dev,
                        inode=before.st_ino,
                        owner_uid=before.st_uid,
                    )
                    try:
                        _harden_directory_entry(descriptor, component, expected=expected)
                    except BaseException:
                        _remove_created_directory(
                            descriptor,
                            component,
                            device=before.st_dev,
                            inode=before.st_ino,
                        )
                        raise
            try:
                child_descriptor = os.open(component, flags, dir_fd=descriptor)
            except BaseException:
                if created:
                    _remove_created_directory(
                        descriptor,
                        component,
                        device=before.st_dev,
                        inode=before.st_ino,
                    )
                raise
            try:
                opened = os.fstat(child_descriptor)
                require_no_acl_grants(child_descriptor)
                after = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                    or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                    or not _ancestor_edge_is_stable(parent, opened, current_uid)
                ):
                    raise PrivatePathError("directory ancestry is unavailable or unsafe")
                if created:
                    created_directories.append(
                        (os.dup(descriptor), component, opened.st_dev, opened.st_ino)
                    )
            except BaseException:
                os.close(child_descriptor)
                if created:
                    _remove_created_directory(
                        descriptor,
                        component,
                        device=before.st_dev,
                        inode=before.st_ino,
                    )
                raise
            os.close(descriptor)
            descriptor = child_descriptor
            parent = opened
        for parent_descriptor, _name, _device, _inode in created_directories:
            with suppress(OSError):
                os.close(parent_descriptor)
        return descriptor
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        for parent_descriptor, name, device, inode in reversed(created_directories):
            try:
                metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == (
                    device,
                    inode,
                ):
                    os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            finally:
                with suppress(OSError):
                    os.close(parent_descriptor)
        raise


def _remove_created_directory(
    parent_descriptor: int,
    name: str,
    *,
    device: int,
    inode: int,
) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == (
            device,
            inode,
        ):
            os.rmdir(name, dir_fd=parent_descriptor)
    except OSError:
        pass


def _normal_directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )


def _identity_directory_open_flags() -> int:
    access = os.O_PATH if _LINUX and hasattr(os, "O_PATH") else os.O_RDONLY
    return (
        access
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )


def _open_directory_identity_descriptor(
    path: Path | str,
    *,
    dir_fd: int | None = None,
) -> int:
    normal_flags = _normal_directory_open_flags()
    try:
        if dir_fd is None:
            return os.open(path, normal_flags)
        return os.open(path, normal_flags, dir_fd=dir_fd)
    except PermissionError:
        identity_flags = _identity_directory_open_flags()
        if identity_flags == normal_flags:
            raise
        if dir_fd is None:
            return os.open(path, identity_flags)
        return os.open(path, identity_flags, dir_fd=dir_fd)


def _harden_directory_entry(
    parent_descriptor: int,
    component: str,
    *,
    expected: DirectoryIdentity,
) -> os.stat_result:
    try:
        descriptor = _open_directory_identity_descriptor(
            component,
            dir_fd=parent_descriptor,
        )
    except PermissionError as exc:
        if not _DARWIN:
            raise PrivatePathError("directory entry could not be opened safely") from exc
        _harden_darwin_directory_entry_from_parent(
            parent_descriptor,
            component,
            expected=expected,
        )
        try:
            descriptor = os.open(
                component,
                _normal_directory_open_flags(),
                dir_fd=parent_descriptor,
            )
        except OSError as retry_error:
            raise PrivatePathError("directory entry could not be opened safely") from retry_error
    except OSError as exc:
        raise PrivatePathError("directory entry could not be opened safely") from exc
    try:
        hardened = _harden_directory_descriptor(descriptor, expected=expected)
        after = os.stat(component, dir_fd=parent_descriptor, follow_symlinks=False)
        if not _same_directory(hardened, after):
            raise PrivatePathError("directory entry changed during hardening")
        return hardened
    finally:
        os.close(descriptor)


def _harden_darwin_directory_entry_from_parent(
    parent_descriptor: int,
    component: str,
    *,
    expected: DirectoryIdentity,
) -> None:
    if component in {"", ".", ".."} or Path(component).name != component:
        raise PrivatePathError("directory entry is unavailable or unsafe")
    try:
        parent = os.fstat(parent_descriptor)
        require_no_acl_grants(parent_descriptor)
        before = os.stat(component, dir_fd=parent_descriptor, follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise PrivatePathError("directory entry could not be inspected safely") from exc
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or not _parent_accepts_current_owned_child(parent, current_uid)
        or not _metadata_matches_identity(before, expected)
        or before.st_uid != current_uid
        or not stat.S_ISDIR(before.st_mode)
    ):
        raise PrivatePathError("captured directory identity changed")
    try:
        # Darwin has no public O_PATH equivalent; this is the documented
        # cooperative-same-user fallback and never follows the selected edge.
        os.chmod(
            component,
            stat.S_IRWXU,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        after = os.stat(component, dir_fd=parent_descriptor, follow_symlinks=False)
    except (NotImplementedError, OSError, ValueError) as exc:
        raise PrivatePathError("descriptor-relative directory hardening is unavailable") from exc
    if (
        not _same_directory(before, after)
        or not _metadata_matches_identity(after, expected)
        or stat.S_IMODE(after.st_mode) != 0o700
    ):
        raise PrivatePathError("descriptor-relative directory hardening could not be confirmed")


def _harden_directory_descriptor(
    descriptor: int,
    *,
    expected: DirectoryIdentity,
) -> os.stat_result:
    before = os.fstat(descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if (
        not _metadata_matches_identity(before, expected)
        or before.st_uid != current_uid
        or not stat.S_ISDIR(before.st_mode)
    ):
        raise PrivatePathError("captured directory identity changed")
    _fchmod_identity_descriptor(descriptor, 0o700)
    require_no_acl_grants(descriptor)
    after = os.fstat(descriptor)
    if (
        not _same_directory(before, after)
        or after.st_uid != current_uid
        or stat.S_IMODE(after.st_mode) != 0o700
    ):
        raise PrivatePathError("captured directory could not be hardened privately")
    return after


def _fchmod_identity_descriptor(descriptor: int, mode: int) -> None:
    try:
        os.fchmod(descriptor, mode)
        return
    except OSError as initial_error:
        if not (_LINUX and hasattr(os, "O_PATH") and initial_error.errno == errno.EBADF):
            raise

    before = os.fstat(descriptor)
    proc_descriptor = Path("/proc/self/fd") / str(descriptor)
    try:
        linked = proc_descriptor.stat()
        if not _same_directory(before, linked):
            raise PrivatePathError("descriptor-bound directory hardening identity changed")
        # procfs resolves this kernel-owned magic link to the held O_PATH object.
        os.chmod(proc_descriptor, mode)
    except (OSError, ValueError) as exc:
        raise PrivatePathError("descriptor-bound directory hardening is unavailable") from exc
    after = os.fstat(descriptor)
    if not _same_directory(before, after) or stat.S_IMODE(after.st_mode) != mode:
        raise PrivatePathError("descriptor-bound directory hardening could not be confirmed")


def _metadata_matches_identity(
    metadata: os.stat_result,
    identity: DirectoryIdentity,
) -> bool:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
    ) == (
        identity.device,
        identity.inode,
        identity.owner_uid,
    )


def _same_directory(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(first.st_mode)
        and stat.S_ISDIR(second.st_mode)
        and (
            first.st_dev,
            first.st_ino,
            first.st_uid,
        )
        == (
            second.st_dev,
            second.st_ino,
            second.st_uid,
        )
    )


def _parent_accepts_current_owned_child(parent: os.stat_result, current_uid: int) -> bool:
    parent_mode = stat.S_IMODE(parent.st_mode)
    return bool(
        parent.st_uid in {0, current_uid}
        and (not parent_mode & 0o022 or parent_mode & stat.S_ISVTX)
    )


def _ancestor_edge_is_stable(
    parent: os.stat_result,
    child: os.stat_result,
    current_uid: int,
) -> bool:
    parent_mode = stat.S_IMODE(parent.st_mode)
    if parent.st_uid not in {0, current_uid}:
        return False
    if not parent_mode & 0o022:
        return True
    return bool(parent_mode & stat.S_ISVTX and child.st_uid == current_uid)


def _darwin_descriptor_acl_grants_access(descriptor: int) -> bool:
    try:
        library = ctypes.CDLL(None, use_errno=True)
        get_acl = cast(Any, library.acl_get_fd_np)
        validate_acl = cast(Any, library.acl_valid)
        get_entry = cast(Any, library.acl_get_entry)
        get_tag = cast(Any, library.acl_get_tag_type)
        free_acl = cast(Any, library.acl_free)
    except (AttributeError, OSError) as exc:
        raise PrivatePathError("extended ACL inspection is unavailable") from exc

    get_acl.argtypes = (ctypes.c_int, ctypes.c_int)
    get_acl.restype = ctypes.c_void_p
    validate_acl.argtypes = (ctypes.c_void_p,)
    validate_acl.restype = ctypes.c_int
    get_entry.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    )
    get_entry.restype = ctypes.c_int
    get_tag.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))
    get_tag.restype = ctypes.c_int
    free_acl.argtypes = (ctypes.c_void_p,)
    free_acl.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = get_acl(descriptor, _ACL_TYPE_EXTENDED)
    if not acl:
        error = ctypes.get_errno()
        # Darwin libc uses ENOENT here specifically to report that no ACL property exists.
        if error == errno.ENOENT:
            return False
        error = error or errno.EIO
        raise PrivatePathError("ACL grants could not be inspected") from OSError(
            error,
            os.strerror(error),
        )

    try:
        ctypes.set_errno(0)
        if int(validate_acl(acl)) != 0:
            error = ctypes.get_errno() or errno.EIO
            raise PrivatePathError("ACL grants could not be validated") from OSError(
                error,
                os.strerror(error),
            )

        entry = ctypes.c_void_p()
        entry_id = _ACL_FIRST_ENTRY
        for entry_index in range(_ACL_MAX_ENTRIES + 1):
            ctypes.set_errno(0)
            entry_result = int(get_entry(acl, entry_id, ctypes.byref(entry)))
            entry_error = ctypes.get_errno()
            # Darwin libc reports normal ACL iteration exhaustion as EINVAL.
            if entry_result == -1 and entry_error == errno.EINVAL:
                return False
            if entry_result != 0:
                error = entry_error or errno.EIO
                raise PrivatePathError("ACL grants could not be inspected") from OSError(
                    error,
                    os.strerror(error),
                )
            if entry_index == _ACL_MAX_ENTRIES:
                raise PrivatePathError("ACL contains too many entries")

            tag = ctypes.c_int()
            ctypes.set_errno(0)
            if int(get_tag(entry, ctypes.byref(tag))) != 0:
                error = ctypes.get_errno() or errno.EIO
                raise PrivatePathError("ACL entry type could not be inspected") from OSError(
                    error,
                    os.strerror(error),
                )
            if tag.value == _ACL_EXTENDED_ALLOW:
                return True
            if tag.value != _ACL_EXTENDED_DENY:
                raise PrivatePathError("ACL contains an unknown entry type")
            entry_id = _ACL_NEXT_ENTRY
        raise PrivatePathError("ACL inspection did not terminate safely")
    finally:
        ctypes.set_errno(0)
        free_result = int(free_acl(acl))
        if free_result != 0:
            error = ctypes.get_errno() or errno.EIO
            raise PrivatePathError("ACL inspection could not be completed") from OSError(
                error,
                os.strerror(error),
            )
