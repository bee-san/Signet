#!/usr/bin/env python3
"""Semantic contract checks for the stable release workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

_PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
_REQUIRED_JOBS = {"gate", "source", "wheel", "verify-release", "publish"}
_EXPECTED_SEMANTIC_SHA256 = "2daec2f46a3753c8f8c14681a93fc2bd9f07d22f976658187e83473294ce6987"
_EXPECTED_STEP_NAMES = {
    "gate": (
        "Check out the complete tagged history",
        "Install pinned uv",
        "Install pinned managed Python",
        "Verify immutable tag, project, repository, and exact current main",
        "Require successful exact-commit main CI",
    ),
    "source": (
        "Check out exact source",
        "Install pinned uv",
        "Install pinned managed Python",
        "Install locked release environment",
        "Verify Python and SQLite release baseline",
        "Build source distribution twice",
        "Check source metadata",
        "Scan source",
        "Audit locked runtime dependencies",
        "Install exact runtime for SBOM and license inventory",
        "Verify source, evidence, SBOM, and license closure",
        "Upload reviewed source artifacts",
    ),
    "wheel": (
        "Check out exact source",
        "Download reviewed source distribution",
        "Install pinned uv",
        "Install pinned managed Python",
        "Install locked test environment",
        "Run package and installed-wheel regressions",
        "Rebuild wheel twice from reviewed sdist",
        "Verify native wheel contents and evidence",
        "Install wheel from the hashed runtime closure",
        "Upload reviewed native wheel",
    ),
    "verify-release": (
        "Check out exact source",
        "Download current-run release artifacts",
        "Install pinned uv",
        "Install pinned managed Python",
        "Install locked release verification tools",
        "Verify exact aggregate artifact set",
        "Generate and verify exact checksums",
        "Sign and verify release artifacts",
        "Attest build provenance",
        "Attest runtime SBOM",
        "Verify GitHub attestations and checksums",
        "Upload signed verified release set",
    ),
    "publish": (
        "Check out exact source",
        "Download only the current-run verified release set",
        "Install pinned uv",
        "Install pinned managed Python",
        "Install locked release verification tools",
        "Reverify exact tag and current main after approval",
        "Reverify approved release identity and artifacts",
        "Reverify GitHub attestations",
        "Publish distributions with PyPI trusted publishing",
        "Publish immutable GitHub release evidence",
    ),
}
_EXPECTED_GATE_RUN = (
    "set -euo pipefail\n"
    "git fetch --force --no-tags origin \\\n"
    "  +refs/heads/main:refs/remotes/origin/main\n"
    "uv lock --check\n"
    "uv run --frozen --group release python scripts/release_gate.py verify-ref \\\n"
    '  --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" \\\n'
    '  --event-name "$GITHUB_EVENT_NAME" --ref-type "$GITHUB_REF_TYPE" \\\n'
    '  --repository "$GITHUB_REPOSITORY" --main-ref refs/remotes/origin/main\n'
)
_EXPECTED_POST_APPROVAL_RUN = (
    "set -euo pipefail\n"
    "git fetch --force --no-tags origin \\\n"
    "  +refs/heads/main:refs/remotes/origin/main \\\n"
    '  "+refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}"\n'
    "uv lock --check\n"
    "uv run --frozen --group release python scripts/release_gate.py verify-ref \\\n"
    '  --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" \\\n'
    '  --event-name "$GITHUB_EVENT_NAME" --ref-type "$GITHUB_REF_TYPE" \\\n'
    '  --repository "$GITHUB_REPOSITORY" --main-ref refs/remotes/origin/main\n'
)
_EXPECTED_PUBLISH_RUN = "uv publish --trusted-publishing always dist/*.whl dist/*.tar.gz"
_EXPECTED_PUBLISH_ARTIFACTS_RUN = (
    "set -euo pipefail\n"
    "uv run --frozen --group release python scripts/release_gate.py \\\n"
    '  verify-artifacts --directory dist --source-sha "$GITHUB_SHA" \\\n'
    "  --platform linux-x86_64 --platform linux-aarch64 \\\n"
    "  --platform macos-arm64 --expect-sdist --require-evidence \\\n"
    "  --require-sbom --require-license-report --require-signatures\n"
    "uv run --frozen --group release python scripts/release_gate.py \\\n"
    "  verify-checksums --directory dist\n"
    "for artifact in \\\n"
    "  dist/*.whl dist/*.tar.gz dist/*.build.json dist/*.cdx.json \\\n"
    "  dist/*.licenses.json dist/*.runtime.json dist/SHA256SUMS; do\n"
    "  uv run --frozen --group release sigstore verify identity \\\n"
    '    --bundle "${artifact}.sigstore.json" \\\n'
    "    --cert-identity \\\n"
    '    "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}" \\\n'
    "    --cert-oidc-issuer https://token.actions.githubusercontent.com \\\n"
    '    "$artifact"\n'
    "done\n"
)
_EXPECTED_PUBLISH_ATTESTATIONS_RUN = (
    "set -euo pipefail\n"
    "for artifact in dist/*.whl dist/*.tar.gz; do\n"
    '  gh attestation verify "$artifact" --repo "$GITHUB_REPOSITORY" \\\n'
    '    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \\\n'
    '    --source-ref "$GITHUB_REF" --source-digest "$GITHUB_SHA"\n'
    '  gh attestation verify "$artifact" --repo "$GITHUB_REPOSITORY" \\\n'
    "    --predicate-type https://cyclonedx.org/bom \\\n"
    '    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \\\n'
    '    --source-ref "$GITHUB_REF" --source-digest "$GITHUB_SHA"\n'
    "done\n"
)
_EXPECTED_GITHUB_RELEASE_RUN = (
    'gh release create "$GITHUB_REF_NAME" dist/* --verify-tag '
    '--title "Signet ${GITHUB_REF_NAME}" --notes-file CHANGELOG.md'
)


class WorkflowContractError(RuntimeError):
    """Raised when stable release automation weakens a required boundary."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise WorkflowContractError(f"{label} must be a string-keyed mapping")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise WorkflowContractError(f"{label} must be a sequence")
    return value


def _load(path: Path) -> Mapping[str, Any]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise WorkflowContractError(f"cannot parse release workflow: {exc}") from exc
    return _mapping(value, "workflow")


def _job(jobs: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return _mapping(jobs.get(name), f"job {name}")


def _steps(job: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
    return [
        _mapping(step, f"step in {name}")
        for step in _sequence(job.get("steps"), f"steps in {name}")
    ]


def _needs(job: Mapping[str, Any]) -> set[str]:
    value = job.get("needs")
    if isinstance(value, str):
        return {value}
    return {str(item) for item in _sequence(value, "job needs")}


def _permissions(job: Mapping[str, Any], name: str) -> dict[str, str]:
    return {
        str(key): str(value)
        for key, value in _mapping(job.get("permissions"), f"permissions in {name}").items()
    }


def _step_by_name(steps: Sequence[Mapping[str, Any]], name: str) -> Mapping[str, Any]:
    matches = [step for step in steps if step.get("name") == name]
    if len(matches) != 1:
        raise WorkflowContractError(f"expected exactly one {name!r} step")
    return matches[0]


def _active_shell(run: str, label: str) -> str:
    """Return non-comment shell lines used by command contract checks."""

    active: list[str] = []
    for line in run.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"\s#", line):
            raise WorkflowContractError(f"{label} contains an inline shell comment")
        active.append(line)
    return "\n".join(active)


def _require_exact_run(step: Mapping[str, Any], *, label: str, expected: str) -> str:
    actual = str(step.get("run", ""))
    if actual != expected:
        raise WorkflowContractError(f"{label} command contract changed")
    return _active_shell(actual, label)


def _require_step_order(steps: Sequence[Mapping[str, Any]], names: Sequence[str]) -> None:
    positions: list[int] = []
    for name in names:
        matches = [index for index, step in enumerate(steps) if step.get("name") == name]
        if len(matches) != 1:
            raise WorkflowContractError(f"expected exactly one {name!r} step")
        positions.append(matches[0])
    if positions != sorted(positions):
        raise WorkflowContractError(f"release steps are out of order: {', '.join(names)}")


def _all_scalars(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        scalars: list[str] = []
        for key, item in value.items():
            scalars.extend((str(key), *_all_scalars(item)))
        return scalars
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        scalars = []
        for item in value:
            scalars.extend(_all_scalars(item))
        return scalars
    return [str(value)]


def validate_release_workflow(path: Path) -> None:
    """Validate parsed workflow structure rather than security phrases in raw text."""

    workflow = _load(path)
    canonical = json.dumps(workflow, sort_keys=True, separators=(",", ":")).encode()
    semantic_sha256 = hashlib.sha256(canonical).hexdigest()
    if semantic_sha256 != _EXPECTED_SEMANTIC_SHA256:
        raise WorkflowContractError(
            "parsed release workflow changed; review the full semantic diff and update its digest"
        )
    trigger = _mapping(workflow.get("on"), "release trigger")
    if set(trigger) != {"push"}:
        raise WorkflowContractError("stable release must trigger only on a pushed tag")
    push = _mapping(trigger.get("push"), "push trigger")
    if push.get("tags") != ["v*.*.*"]:
        raise WorkflowContractError("stable release tag filter must be exactly v*.*.*")
    if workflow.get("permissions") != {"contents": "read"}:
        raise WorkflowContractError("top-level release permissions must be contents: read")

    jobs = _mapping(workflow.get("jobs"), "jobs")
    if set(jobs) != _REQUIRED_JOBS:
        raise WorkflowContractError("release workflow contains missing or alternate jobs")
    gate = _job(jobs, "gate")
    source = _job(jobs, "source")
    wheel = _job(jobs, "wheel")
    verify = _job(jobs, "verify-release")
    publish = _job(jobs, "publish")

    for name, job in (
        ("gate", gate),
        ("source", source),
        ("wheel", wheel),
        ("verify-release", verify),
        ("publish", publish),
    ):
        if "if" in job or "continue-on-error" in job:
            raise WorkflowContractError(f"{name} can bypass dependency failure")

    if _needs(source) != {"gate"}:
        raise WorkflowContractError("source build must depend on the release gate")
    if _needs(wheel) != {"gate", "source"}:
        raise WorkflowContractError("wheel builds must depend on gate and source")
    if _needs(verify) != {"source", "wheel"}:
        raise WorkflowContractError("release verification must depend on source and wheels")
    if _needs(publish) != {"verify-release"}:
        raise WorkflowContractError("publication must depend only on verified release output")

    if _permissions(gate, "gate") != {"actions": "read", "contents": "read"}:
        raise WorkflowContractError("gate permissions are not least privilege")
    if "permissions" in source or "permissions" in wheel:
        raise WorkflowContractError("build jobs must inherit read-only top-level permissions")
    if _permissions(verify, "verify-release") != {
        "actions": "read",
        "artifact-metadata": "write",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
    }:
        raise WorkflowContractError("verification permissions do not match attestation duties")
    if _permissions(publish, "publish") != {
        "actions": "read",
        "attestations": "read",
        "contents": "write",
        "id-token": "write",
    }:
        raise WorkflowContractError("publication permissions do not match release duties")

    environment = _mapping(publish.get("environment"), "publish environment")
    if environment.get("name") != "pypi":
        raise WorkflowContractError("publication must use the protected pypi environment")

    steps_by_job = {
        name: _steps(_job(jobs, name), name)
        for name in ("gate", "source", "wheel", "verify-release", "publish")
    }
    for name, steps in steps_by_job.items():
        if tuple(str(step.get("name")) for step in steps) != _EXPECTED_STEP_NAMES[name]:
            raise WorkflowContractError(f"{name} step inventory or order changed")
        for step in steps:
            if "if" in step or "continue-on-error" in step:
                raise WorkflowContractError(f"{name} contains a conditional or soft-fail step")
            if "run" in step and step.get("shell") not in (None, "bash"):
                raise WorkflowContractError(f"{name} contains a non-Bash command step")
            action = step.get("uses")
            if action is not None and not _PINNED_ACTION.fullmatch(str(action)):
                raise WorkflowContractError(f"{name} uses an action without a full SHA pin")
            if str(action).startswith("actions/checkout@"):
                options = _mapping(step.get("with"), f"checkout options in {name}")
                if options.get("persist-credentials") != "false":
                    raise WorkflowContractError("release checkout must not persist credentials")

    gate_steps = steps_by_job["gate"]
    _require_step_order(
        gate_steps,
        (
            "Verify immutable tag, project, repository, and exact current main",
            "Require successful exact-commit main CI",
        ),
    )
    gate_run = _require_exact_run(
        _step_by_name(
            gate_steps, "Verify immutable tag, project, repository, and exact current main"
        ),
        label="release gate",
        expected=_EXPECTED_GATE_RUN,
    )
    for required in (
        "git fetch --force --no-tags origin",
        "scripts/release_gate.py verify-ref",
        "--main-ref refs/remotes/origin/main",
    ):
        if required not in gate_run:
            raise WorkflowContractError(f"release gate is missing {required!r}")
    ci_run = _active_shell(
        str(_step_by_name(gate_steps, "Require successful exact-commit main CI").get("run", "")),
        "exact-commit CI gate",
    )
    for required in (
        '-f head_sha="$GITHUB_SHA"',
        '.head_branch == \\"main\\"',
        "gh api --method GET",
    ):
        if required not in ci_run:
            raise WorkflowContractError(f"exact-commit CI gate is missing {required!r}")

    verify_steps = steps_by_job["verify-release"]
    _require_step_order(
        verify_steps,
        (
            "Verify exact aggregate artifact set",
            "Generate and verify exact checksums",
            "Sign and verify release artifacts",
            "Attest build provenance",
            "Attest runtime SBOM",
            "Verify GitHub attestations and checksums",
            "Upload signed verified release set",
        ),
    )
    verify_download = _step_by_name(verify_steps, "Download current-run release artifacts")
    if _mapping(verify_download.get("with"), "release artifact download").get("pattern") != (
        "{source-release,wheel-*}"
    ):
        raise WorkflowContractError("verification must download only current-run source and wheels")
    verify_upload = _step_by_name(verify_steps, "Upload signed verified release set")
    if _mapping(verify_upload.get("with"), "verified release upload").get("name") != (
        "verified-release"
    ):
        raise WorkflowContractError("verified release artifact name changed")

    publish_steps = steps_by_job["publish"]
    _require_step_order(
        publish_steps,
        (
            "Reverify exact tag and current main after approval",
            "Reverify approved release identity and artifacts",
            "Reverify GitHub attestations",
            "Publish distributions with PyPI trusted publishing",
            "Publish immutable GitHub release evidence",
        ),
    )
    approved_identity_run = _require_exact_run(
        _step_by_name(publish_steps, "Reverify exact tag and current main after approval"),
        label="post-approval release identity gate",
        expected=_EXPECTED_POST_APPROVAL_RUN,
    )
    for required in (
        "git fetch --force --no-tags origin",
        "+refs/heads/main:refs/remotes/origin/main",
        "+refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}",
        "scripts/release_gate.py verify-ref",
        "--main-ref refs/remotes/origin/main",
    ):
        if required not in approved_identity_run:
            raise WorkflowContractError(
                f"post-approval release identity gate is missing {required!r}"
            )
    publish_download = _step_by_name(
        publish_steps, "Download only the current-run verified release set"
    )
    if _mapping(publish_download.get("with"), "publish artifact download").get("name") != (
        "verified-release"
    ):
        raise WorkflowContractError("publication must download only verified-release")
    _require_exact_run(
        _step_by_name(publish_steps, "Publish distributions with PyPI trusted publishing"),
        label="trusted publication",
        expected=_EXPECTED_PUBLISH_RUN,
    )
    for step_name, expected in (
        ("Install pinned managed Python", "uv python install 3.12.13"),
        ("Install locked release verification tools", "uv sync --frozen --group release"),
        ("Reverify approved release identity and artifacts", _EXPECTED_PUBLISH_ARTIFACTS_RUN),
        ("Reverify GitHub attestations", _EXPECTED_PUBLISH_ATTESTATIONS_RUN),
        ("Publish immutable GitHub release evidence", _EXPECTED_GITHUB_RELEASE_RUN),
    ):
        _require_exact_run(
            _step_by_name(publish_steps, step_name),
            label=f"publish step {step_name!r}",
            expected=expected,
        )

    run_commands = {
        name: "\n".join(_active_shell(str(step.get("run", "")), f"{name} step") for step in steps)
        for name, steps in steps_by_job.items()
    }
    publish_command = "uv publish --trusted-publishing always"
    if run_commands["publish"].count(publish_command) != 1:
        raise WorkflowContractError("trusted publication command must appear exactly once")
    if any(
        publish_command in commands for name, commands in run_commands.items() if name != "publish"
    ):
        raise WorkflowContractError("a non-publish job can publish to PyPI")
    if "gh attestation verify" not in run_commands["verify-release"]:
        raise WorkflowContractError("release verification does not verify GitHub attestations")
    if "gh attestation verify" not in run_commands["publish"]:
        raise WorkflowContractError("publication does not reverify GitHub attestations")

    serialized_scalars = "\n".join(_all_scalars(workflow))
    for prohibited in ("PYPI_API_TOKEN", "UV_PUBLISH_TOKEN", "TWINE_PASSWORD", "secrets."):
        if prohibited in serialized_scalars:
            raise WorkflowContractError(
                f"release workflow references prohibited secret {prohibited}"
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        validate_release_workflow(arguments.workflow)
    except WorkflowContractError as exc:
        print(f"release workflow contract failed: {exc}")
        return 2
    print("release workflow contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
