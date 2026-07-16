#!/usr/bin/env python3
"""Create or validate one canonical owned directory through stable ancestry."""

from __future__ import annotations

import argparse
from pathlib import Path

from signet.private_paths import PrivatePathError, ensure_owned_directory


class PreparationError(RuntimeError):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or validate one canonical owned non-writable directory."
    )
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        _prepare(args.directory)
    except (OSError, PrivatePathError, PreparationError) as exc:
        parser.exit(1, f"error: private directory preparation failed: {exc}\n")
    return 0


def _prepare(directory: Path) -> None:
    if (
        not directory.is_absolute()
        or ".." in directory.parts
        or any("\x00" in component for component in directory.parts)
    ):
        raise PreparationError("directory must be an absolute canonical path")
    prepared = ensure_owned_directory(directory)
    if prepared != directory:
        raise PreparationError("directory must be canonical and contain no symlinks")


if __name__ == "__main__":
    raise SystemExit(main())
