#!/usr/bin/env python3
"""Emit a deterministic inventory of one installed Signet runtime."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "signet-runtime-manifest-v1"
EXPECTED_PYTHON = (3, 12, 13)


class RuntimeManifestError(RuntimeError):
    """Raised when the inspected environment cannot produce reviewed evidence."""


def _implementation_version() -> str:
    value = sys.implementation.version
    version = f"{value.major}.{value.minor}.{value.micro}"
    if value.releaselevel != "final":
        version += f"{value.releaselevel[0]}{value.serial}"
    return version


def _marker_environment() -> dict[str, str]:
    return {
        "implementation_name": sys.implementation.name,
        "implementation_version": _implementation_version(),
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_python_implementation": platform.python_implementation(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "sys_platform": sys.platform,
    }


def build_manifest(*, source_sha: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise RuntimeManifestError("source SHA must be 40 lowercase hexadecimal characters")
    if sys.version_info[:3] != EXPECTED_PYTHON:
        raise RuntimeManifestError("runtime manifest requires exact Python 3.12.13")

    packages: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata["Name"]
        if not name:
            raise RuntimeManifestError("installed distribution has no Name metadata")
        identity = (re.sub(r"[-_.]+", "-", name).casefold(), distribution.version)
        if identity in identities:
            raise RuntimeManifestError(f"duplicate installed distribution: {name}")
        identities.add(identity)
        packages.append(
            {
                "name": name,
                "requires_dist": sorted(distribution.requires or []),
                "version": distribution.version,
            }
        )
    packages.sort(key=lambda item: (item["name"].casefold(), item["version"]))
    return {
        "marker_environment": _marker_environment(),
        "packages": packages,
        "schema": SCHEMA,
        "source_sha": source_sha,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise RuntimeManifestError(f"refusing to overwrite runtime manifest: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        value = build_manifest(source_sha=args.source_sha)
        args.output.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, RuntimeManifestError) as error:
        print(f"runtime manifest failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
