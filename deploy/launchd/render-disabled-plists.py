#!/usr/bin/env python3
"""Render inert downstream-disabled launchd plists from validated local paths."""

from __future__ import annotations

import argparse
import os
import plistlib
import stat
from contextlib import suppress
from pathlib import Path
from typing import Any

MCP_NAME = "ai.hermes.signet.mcp.plist"
WEB_NAME = "ai.hermes.signet.web.plist"
_TEMPLATES = {
    "mcp": ("ai.hermes.signet.mcp.plist.example", MCP_NAME, "serve-mcp"),
    "web": ("ai.hermes.signet.web.plist.example", WEB_NAME, "serve-web"),
}


class RenderError(RuntimeError):
    """The selected paths or templates cannot produce reviewed private plists."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render, but do not install or load, disabled Signet launchd plists."
    )
    parser.add_argument("--signet-executable", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--working-directory", type=Path, required=True)
    parser.add_argument("--logs-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        executable = _existing_path(
            args.signet_executable,
            label="Signet executable",
            kind="file",
            require_private=False,
            require_executable=True,
        )
        config = _existing_path(
            args.config,
            label="disabled config",
            kind="file",
            require_private=True,
        )
        working = _existing_path(
            args.working_directory,
            label="working directory",
            kind="directory",
            require_private=False,
        )
        logs = _existing_path(
            args.logs_directory,
            label="logs directory",
            kind="directory",
            require_private=True,
        )
        output = _existing_path(
            args.output_directory,
            label="output directory",
            kind="directory",
            require_private=True,
        )
        rendered = {
            output_name: _render_template(
                template_name,
                service=service,
                executable=executable,
                config=config,
                working=working,
                logs=logs,
            )
            for service, (template_name, output_name, _command) in _TEMPLATES.items()
        }
        _write_outputs(output, rendered)
    except RenderError as exc:
        parser.exit(1, f"error: {exc}\n")

    print("Rendered two inactive mode-0600 launchd plists for review.")
    return 0


def _existing_path(
    path: Path,
    *,
    label: str,
    kind: str,
    require_private: bool,
    require_executable: bool = False,
) -> Path:
    if not path.is_absolute():
        raise RenderError(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise RenderError(f"{label} must already exist") from exc
    if path != resolved:
        raise RenderError(f"{label} path must be canonical and contain no symlinks")
    if kind == "file":
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RenderError(f"{label} must be a single-link regular file")
    elif not stat.S_ISDIR(metadata.st_mode):
        raise RenderError(f"{label} must be a directory")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise RenderError(f"{label} must be owned by the current user")
    mode = stat.S_IMODE(metadata.st_mode)
    if require_private and mode != (0o600 if kind == "file" else 0o700):
        required = "0600" if kind == "file" else "0700"
        raise RenderError(f"{label} must have exact mode {required}")
    if not require_private and mode & 0o022:
        raise RenderError(f"{label} must not be group/world writable")
    if require_executable and not metadata.st_mode & stat.S_IXUSR:
        raise RenderError(f"{label} must be executable by its owner")
    if any(ord(character) < 32 or ord(character) == 127 for character in str(path)):
        raise RenderError(f"{label} path contains a control character")
    return resolved


def _render_template(
    template_name: str,
    *,
    service: str,
    executable: Path,
    config: Path,
    working: Path,
    logs: Path,
) -> bytes:
    template_path = Path(__file__).with_name(template_name)
    try:
        document = plistlib.loads(template_path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        raise RenderError("launchd template is not a valid property list") from None
    _validate_template(document, service=service)
    command = _TEMPLATES[service][2]
    document["ProgramArguments"] = [
        str(executable),
        "deployment",
        command,
        "--config",
        str(config),
    ]
    document["WorkingDirectory"] = str(working)
    document["StandardOutPath"] = str(logs / f"{service}.log")
    document["StandardErrorPath"] = str(logs / f"{service}-error.log")
    rendered = plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=False)
    if b"/ABSOLUTE/PATH/" in rendered:
        raise RenderError("launchd template still contains a path placeholder")
    return rendered


def _validate_template(document: Any, *, service: str) -> None:
    if not isinstance(document, dict):
        raise RenderError("launchd template must contain one dictionary")
    command = _TEMPLATES[service][2]
    expected_arguments = [
        "/ABSOLUTE/PATH/TO/SIGNET/.venv/bin/signet",
        "deployment",
        command,
        "--config",
        "/ABSOLUTE/PATH/TO/SIGNET-DATA/config/disabled.json",
    ]
    expected = {
        "Label": f"ai.hermes.signet.{service}",
        "ProgramArguments": expected_arguments,
        "WorkingDirectory": "/ABSOLUTE/PATH/TO/SIGNET",
        "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"},
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "ThrottleInterval": 10,
        "Umask": 63,
        "StandardOutPath": f"/ABSOLUTE/PATH/TO/SIGNET-DATA/logs/{service}.log",
        "StandardErrorPath": (f"/ABSOLUTE/PATH/TO/SIGNET-DATA/logs/{service}-error.log"),
    }
    if document != expected:
        raise RenderError("launchd template does not match the reviewed disabled shape")


def _write_outputs(directory_path: Path, rendered: dict[str, bytes]) -> None:
    directory: int | None = None
    created: dict[str, tuple[int, int]] = {}
    complete = False
    try:
        directory = os.open(
            directory_path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(directory)
        current = directory_path.stat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (hasattr(os, "getuid") and opened.st_uid != os.getuid())
        ):
            raise RenderError("output directory changed during rendering")
        for name in rendered:
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise RenderError("a rendered launchd output already exists")
        for name, content in rendered.items():
            created[name] = _write_new_file(directory, name, content)
        os.fsync(directory)
        complete = True
    except OSError as exc:
        raise RenderError("launchd outputs could not be created safely") from exc
    finally:
        if directory is not None:
            if not complete:
                for name, identity in created.items():
                    _unlink_created(directory, name, identity)
            os.close(directory)


def _write_new_file(directory: int, name: str, content: bytes) -> tuple[int, int]:
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        identity = metadata.st_dev, metadata.st_ino
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        return identity
    except OSError:
        if identity is not None:
            _unlink_created(directory, name, identity)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _unlink_created(directory: int, name: str, identity: tuple[int, int]) -> None:
    with suppress(OSError):
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISREG(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == identity:
            os.unlink(name, dir_fd=directory)


if __name__ == "__main__":
    raise SystemExit(main())
