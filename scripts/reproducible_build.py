#!/usr/bin/env python3
"""Build one distribution twice and emit source-bound reproducibility evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Literal

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ReproducibleBuildError(RuntimeError):
    """Raised when a build is ambiguous or not byte-for-byte reproducible."""


def _run(command: list[str], *, cwd: Path, environment: dict[str, str]) -> str:
    completed = subprocess.run(  # nosec B603
        command,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no build output"
        raise ReproducibleBuildError(f"command failed ({command[0]}): {detail}")
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _single_artifact(directory: Path, kind: Literal["wheel", "sdist"]) -> Path:
    pattern = "*.whl" if kind == "wheel" else "*.tar.gz"
    artifacts = tuple(path for path in directory.glob(pattern) if path.is_file())
    if len(artifacts) != 1:
        raise ReproducibleBuildError(
            f"expected exactly one {kind} artifact, found {len(artifacts)}"
        )
    return artifacts[0]


def _verify_source_evidence(
    *, source: Path, evidence_path: Path | None, source_sha: str
) -> dict[str, object]:
    if source.is_dir():
        if evidence_path is not None:
            raise ReproducibleBuildError("directory source must not have archive evidence")
        return {}
    if evidence_path is None:
        raise ReproducibleBuildError("archive source requires reproducible source evidence")
    value = json.loads(evidence_path.resolve(strict=True).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReproducibleBuildError("source evidence is not an object")
    if (
        value.get("artifact") != source.name
        or value.get("build_kind") != "sdist"
        or value.get("source_sha") != source_sha
        or value.get("reproducible") is not True
        or value.get("sha256") != _sha256(source)
        or value.get("rebuild_sha256") != _sha256(source)
    ):
        raise ReproducibleBuildError("archive source does not match its source-bound evidence")
    return {
        "input_artifact": source.name,
        "input_sha256": _sha256(source),
    }


def build_reproducibly(
    *,
    repository: Path,
    source: Path,
    source_evidence: Path | None,
    kind: Literal["wheel", "sdist"],
    output_directory: Path,
    evidence_path: Path,
    source_sha: str,
    platform_name: str,
    uv_executable: str,
) -> dict[str, object]:
    """Build twice with SOURCE_DATE_EPOCH and copy only identical output."""

    repository = repository.resolve(strict=True)
    source = source.resolve(strict=True)
    if not _SHA_PATTERN.fullmatch(source_sha):
        raise ReproducibleBuildError("source SHA must be one full lowercase Git commit digest")
    if not platform_name or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", platform_name):
        raise ReproducibleBuildError("platform name must be a lowercase release identifier")
    if evidence_path.parent.resolve() != output_directory.resolve():
        raise ReproducibleBuildError("evidence must be written beside the distribution")

    head = _run(["git", "rev-parse", "HEAD"], cwd=repository, environment=os.environ.copy())
    if head != source_sha:
        raise ReproducibleBuildError(f"checked-out HEAD {head} does not match source {source_sha}")
    tracked_status = _run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=repository,
        environment=os.environ.copy(),
    )
    if tracked_status:
        raise ReproducibleBuildError("repository has tracked changes outside the source commit")
    if source.is_dir():
        if source != repository:
            raise ReproducibleBuildError("directory source must be the exact Git repository root")
        repository_status = _run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=repository,
            environment=os.environ.copy(),
        )
        if repository_status:
            raise ReproducibleBuildError("directory source contains untracked release inputs")
    input_evidence = _verify_source_evidence(
        source=source,
        evidence_path=source_evidence,
        source_sha=source_sha,
    )
    epoch_text = _run(
        ["git", "show", "-s", "--format=%ct", source_sha],
        cwd=repository,
        environment=os.environ.copy(),
    )
    if not epoch_text.isdecimal():
        raise ReproducibleBuildError("Git commit timestamp is not a decimal SOURCE_DATE_EPOCH")

    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": epoch_text,
            "TZ": "UTC",
            "UV_NO_PROGRESS": "1",
        }
    )
    temporary_parent = os.environ.get("RUNNER_TEMP")
    with (
        tempfile.TemporaryDirectory(
            prefix="signet-build-a-", dir=temporary_parent
        ) as first_raw,
        tempfile.TemporaryDirectory(
            prefix="signet-build-b-", dir=temporary_parent
        ) as second_raw,
    ):
        first = Path(first_raw)
        second = Path(second_raw)
        command = [
            uv_executable,
            "build",
            "--no-cache",
            f"--{kind}",
            "--no-sources",
        ]
        source_argument = str(source)
        _run(
            [*command, "--out-dir", str(first), source_argument],
            cwd=repository,
            environment=environment,
        )
        _run(
            [*command, "--out-dir", str(second), source_argument],
            cwd=repository,
            environment=environment,
        )
        first_artifact = _single_artifact(first, kind)
        second_artifact = _single_artifact(second, kind)
        if first_artifact.name != second_artifact.name:
            raise ReproducibleBuildError("rebuild changed the distribution filename")
        first_digest = _sha256(first_artifact)
        second_digest = _sha256(second_artifact)
        if (
            first_digest != second_digest
            or first_artifact.read_bytes() != second_artifact.read_bytes()
        ):
            raise ReproducibleBuildError(
                "distribution rebuild was not byte-for-byte reproducible"
            )

        output_directory.mkdir(parents=True, exist_ok=True)
        destination = output_directory / first_artifact.name
        if destination.exists() or evidence_path.exists():
            raise ReproducibleBuildError("refusing to replace existing release output")
        shutil.copyfile(first_artifact, destination)

    uv_output = _run(
        [uv_executable, "--version"], cwd=repository, environment=environment
    )
    uv_match = re.match(r"^uv (\d+\.\d+\.\d+)(?:\s|$)", uv_output)
    if uv_match is None or uv_match.group(1) != "0.11.28":
        raise ReproducibleBuildError(f"release build requires uv 0.11.28; found {uv_output}")
    uv_version = f"uv {uv_match.group(1)}"
    evidence: dict[str, object] = {
        "artifact": destination.name,
        "build_kind": kind,
        "builder": "scripts/reproducible_build.py",
        "platform": platform_name,
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        "rebuild_sha256": first_digest,
        "reproducible": True,
        "schema": 1,
        "sha256": first_digest,
        "size": destination.stat().st_size,
        "source_date_epoch": int(epoch_text),
        "source_sha": source_sha,
        "sqlite": sqlite3.sqlite_version,
        "uv": uv_version,
        **input_evidence,
    }
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--source-evidence", type=Path)
    parser.add_argument("--kind", choices=("wheel", "sdist"), required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--uv", default="uv")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = build_reproducibly(
            repository=args.repository,
            source=args.source,
            source_evidence=args.source_evidence,
            kind=args.kind,
            output_directory=args.output_directory,
            evidence_path=args.evidence,
            source_sha=args.source_sha,
            platform_name=args.platform,
            uv_executable=args.uv,
        )
    except (OSError, ReproducibleBuildError) as exc:
        print(f"reproducible build failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(evidence, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
