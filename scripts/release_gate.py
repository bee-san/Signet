#!/usr/bin/env python3
"""Fail-closed source, artifact, dependency, and checksum release gates."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import stat
import subprocess  # nosec B404
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

EXPECTED_REPOSITORY = "bee-san/Signet"
EXPECTED_DISTRIBUTION = "signet-gateway"
EXPECTED_PYTHON = ">=3.12,<3.13"
EXPECTED_PLATFORMS = {
    "linux-aarch64": "linux_aarch64",
    "linux-x86_64": "linux_x86_64",
    "macos-arm64": "macosx_11_0_arm64",
}
_STABLE_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_LICENSE = re.compile(r"(?:^|\W)(?:A?GPL|LGPL|UNKNOWN)(?:$|\W)", re.IGNORECASE)
_REQUIRED_WHEEL_FILES = {
    "signet/migrations/0020_production_user_roles.sql",
    "signet/py.typed",
    "signet/reference_plugins/fastmail/manifest.json",
    "signet/reference_plugins/telegram/manifest.json",
    "signet/reference_plugins/whatsapp/manifest.json",
    "signet/static/app.css",
    "signet/static/app.js",
    "signet/static/authenticators.js",
    "signet/static/icons/signet-1254.png",
    "signet/static/manifest.webmanifest",
    "signet/static/service-worker.js",
    "signet/templates/setup.html",
}
_REQUIRED_SDIST_FILES = {
    ".github/workflows/release-dry-run.yml",
    ".github/workflows/release.yml",
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "docs/man/signet.1",
    "docs/releasing.md",
    "hatch_build.py",
    "pyproject.toml",
    "scripts/release_gate.py",
    "scripts/reproducible_build.py",
    "scripts/runtime_manifest.py",
    "src/signet/static/app.css",
    "tests/test_release_pipeline.py",
    "uv.lock",
}


class ReleaseGateError(RuntimeError):
    """Raised when release identity or artifacts are not exactly reviewed."""


def _project(root: Path) -> dict[str, Any]:
    document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = document.get("project")
    if not isinstance(project, dict):
        raise ReleaseGateError("pyproject.toml has no project table")
    return project


def validate_release_identity(
    *,
    tag: str,
    version: str,
    event_name: str,
    ref_type: str,
    repository: str,
) -> None:
    """Validate immutable trusted-publisher identity before any build or OIDC use."""

    match = _STABLE_TAG.fullmatch(tag)
    if match is None:
        raise ReleaseGateError("release tag must be exact stable vMAJOR.MINOR.PATCH")
    parsed = Version(version)
    if parsed.is_prerelease or parsed.is_devrelease or parsed.is_postrelease or parsed.local:
        raise ReleaseGateError("project version must be one stable public version")
    if tag != f"v{parsed}":
        raise ReleaseGateError(f"tag {tag} does not match project version {parsed}")
    if event_name != "push" or ref_type != "tag":
        raise ReleaseGateError("stable publication is permitted only for a pushed tag")
    if repository != EXPECTED_REPOSITORY:
        raise ReleaseGateError("trusted-publisher repository identity does not match")


def _git(root: Path, *arguments: str, check: bool = True) -> str:
    completed = subprocess.run(  # nosec B603 B607
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no Git output"
        raise ReleaseGateError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout.strip()


def _git_is_clean(root: Path, *arguments: str) -> bool:
    completed = subprocess.run(  # nosec B603 B607
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        timeout=60,
    )
    return completed.returncode == 0 and not completed.stdout and not completed.stderr


def verify_ref(
    *,
    root: Path,
    tag: str,
    sha: str,
    event_name: str,
    ref_type: str,
    repository: str,
    main_ref: str,
) -> None:
    root = root.resolve(strict=True)
    project = _project(root)
    name = str(project.get("name", ""))
    version = str(project.get("version", ""))
    if canonicalize_name(name) != canonicalize_name(EXPECTED_DISTRIBUTION):
        raise ReleaseGateError("project distribution name does not match trusted publisher")
    validate_release_identity(
        tag=tag,
        version=version,
        event_name=event_name,
        ref_type=ref_type,
        repository=repository,
    )
    if not _SHA40.fullmatch(sha):
        raise ReleaseGateError("release source must be one full lowercase Git commit SHA")
    if _git(root, "rev-parse", "HEAD") != sha:
        raise ReleaseGateError("checked-out HEAD does not match the tag event SHA")
    if _git(root, "cat-file", "-t", f"refs/tags/{tag}") != "tag":
        raise ReleaseGateError("stable releases require an annotated Git tag")
    if _git(root, "rev-parse", f"refs/tags/{tag}^{{commit}}") != sha:
        raise ReleaseGateError("tag does not peel to the exact event commit")
    completed = subprocess.run(  # nosec B603
        ["git", "merge-base", "--is-ancestor", sha, main_ref],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise ReleaseGateError("tagged commit is not an ancestor of origin/main")
    if not _git_is_clean(root, "diff", "--quiet") or not _git_is_clean(
        root, "diff", "--cached", "--quiet"
    ):
        raise ReleaseGateError("release source checkout has tracked modifications")
    committed_project = _git(root, "show", f"{sha}:pyproject.toml")
    current_project = (root / "pyproject.toml").read_text(encoding="utf-8").rstrip("\n")
    if committed_project != current_project:
        raise ReleaseGateError("working project metadata differs from the tagged source")


def _metadata(raw: bytes) -> Mapping[str, str]:
    message = BytesParser(policy=compat32).parsebytes(raw)
    return {key: str(value) for key, value in message.items()}


def _metadata_requirements(raw: bytes) -> set[Requirement]:
    message = BytesParser(policy=compat32).parsebytes(raw)
    return {Requirement(str(value)) for value in message.get_all("Requires-Dist", [])}


def _expected_requirements(project: Mapping[str, Any]) -> set[Requirement]:
    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) for item in dependencies
    ):
        raise ReleaseGateError("project runtime dependencies must be a string list")
    return {Requirement(item) for item in dependencies}


def _exact_requirement_version(requirement: Requirement) -> str:
    specifiers = list(requirement.specifier)
    if (
        len(specifiers) != 1
        or specifiers[0].operator != "=="
        or specifiers[0].version.endswith(".*")
    ):
        raise ReleaseGateError(f"dependency is not pinned exactly: {requirement}")
    return specifiers[0].version


def _active_project_requirements(
    project: Mapping[str, Any], environment: Mapping[str, str] | None = None
) -> dict[str, Requirement]:
    active: dict[str, Requirement] = {}
    for requirement in _expected_requirements(project):
        if requirement.marker is not None and not requirement.marker.evaluate(environment):
            continue
        name = canonicalize_name(requirement.name)
        if name in active:
            raise ReleaseGateError(f"duplicate active runtime dependency: {name}")
        _exact_requirement_version(requirement)
        active[name] = requirement
    return active


def _assert_metadata(raw: bytes, *, project: Mapping[str, Any]) -> None:
    metadata = _metadata(raw)
    expected = {
        "Name": EXPECTED_DISTRIBUTION,
        "Version": str(project["version"]),
        "License-Expression": "MIT",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ReleaseGateError(f"distribution metadata {key} does not match {value}")
    if SpecifierSet(str(metadata.get("Requires-Python", ""))) != SpecifierSet(EXPECTED_PYTHON):
        raise ReleaseGateError("distribution metadata Requires-Python does not match policy")
    if _metadata_requirements(raw) != _expected_requirements(project):
        raise ReleaseGateError("wheel dependency metadata does not match the reviewed closure")


def _verify_record(archive: zipfile.ZipFile, names: set[str]) -> None:
    records = [name for name in names if name.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise ReleaseGateError("wheel must contain exactly one RECORD")
    rows = list(csv.reader(archive.read(records[0]).decode("utf-8").splitlines()))
    if len(rows) != len(names):
        raise ReleaseGateError("wheel RECORD does not cover every member exactly once")
    covered: set[str] = set()
    for name, digest, size in rows:
        if name in covered or name not in names:
            raise ReleaseGateError("wheel RECORD has a duplicate or unknown path")
        covered.add(name)
        if name == records[0]:
            if digest or size:
                raise ReleaseGateError("wheel RECORD self-entry must have empty digest and size")
            continue
        if not digest.startswith("sha256=") or not size.isdecimal():
            raise ReleaseGateError("wheel RECORD entry is missing a SHA-256 digest or size")
        payload = archive.read(name)
        actual = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        if digest.removeprefix("sha256=") != actual or int(size) != len(payload):
            raise ReleaseGateError(f"wheel RECORD verification failed for {name}")


def _verify_zip_members(archive: zipfile.ZipFile) -> None:
    names: set[str] = set()
    for member in archive.infolist():
        name = member.filename
        pure = PurePosixPath(name)
        file_type = stat.S_IFMT(member.external_attr >> 16)
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", name)
            or pure.is_absolute()
            or ".." in pure.parts
            or str(pure) != name
            or member.is_dir()
            or file_type not in (0, stat.S_IFREG)
        ):
            raise ReleaseGateError(f"wheel contains unsafe archive member: {name}")
        if name in names:
            raise ReleaseGateError(f"wheel contains duplicate archive member: {name}")
        names.add(name)


def _verify_wheel(path: Path, *, project: Mapping[str, Any], platform_tag: str) -> None:
    expected_prefix = f"signet_gateway-{project['version']}-py3-none-{platform_tag}"
    if path.name != f"{expected_prefix}.whl":
        raise ReleaseGateError(f"unexpected wheel filename: {path.name}")
    with zipfile.ZipFile(path) as archive:
        _verify_zip_members(archive)
        names = set(archive.namelist())
        if not names >= _REQUIRED_WHEEL_FILES:
            missing = sorted(_REQUIRED_WHEEL_FILES - names)
            raise ReleaseGateError(f"wheel is missing runtime assets: {missing}")
        forbidden = [
            name
            for name in names
            if name.startswith(("tests/", "qa_artifacts/", ".git/"))
            or name.endswith((".pyc", ".env"))
            or "__pycache__" in PurePosixPath(name).parts
        ]
        if forbidden:
            raise ReleaseGateError(f"wheel contains forbidden files: {sorted(forbidden)}")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        licenses = [name for name in names if ".dist-info/licenses/LICENSE" in name]
        manpages = [name for name in names if name.endswith("/share/man/man1/signet.1")]
        metadata_groups = (metadata_names, wheel_names, entry_points, licenses, manpages)
        if not all(len(group) == 1 for group in metadata_groups):
            raise ReleaseGateError("wheel metadata, license, entry point, or manpage is ambiguous")
        _assert_metadata(archive.read(metadata_names[0]), project=project)
        wheel_metadata = archive.read(wheel_names[0]).decode("utf-8")
        if f"Tag: py3-none-{platform_tag}\n" not in wheel_metadata:
            raise ReleaseGateError("wheel internal platform tag does not match its filename")
        expected_entry_point = "[console_scripts]\nsignet = signet.app:main\n"
        if archive.read(entry_points[0]).decode("utf-8") != expected_entry_point:
            raise ReleaseGateError("wheel console entry point does not match the reviewed command")
        _verify_record(archive, names)


def _verify_sdist(path: Path, *, project: Mapping[str, Any]) -> None:
    expected_root = f"signet_gateway-{project['version']}"
    if path.name != f"{expected_root}.tar.gz":
        raise ReleaseGateError(f"unexpected source distribution filename: {path.name}")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        if len(names) != len(members):
            raise ReleaseGateError("source distribution contains duplicate paths")
        expected = {f"{expected_root}/{name}" for name in _REQUIRED_SDIST_FILES}
        if not names >= expected:
            missing = sorted(expected - names)
            raise ReleaseGateError(f"source distribution is missing files: {missing}")
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or member.issym() or member.islnk():
                raise ReleaseGateError(f"unsafe source distribution member: {member.name}")
            if member.ischr() or member.isblk() or member.isfifo():
                raise ReleaseGateError(f"special source distribution member: {member.name}")
        pkg_info = archive.extractfile(f"{expected_root}/PKG-INFO")
        if pkg_info is None:
            raise ReleaseGateError("source distribution has no PKG-INFO")
        _assert_metadata(pkg_info.read(), project=project)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_build_evidence(
    directory: Path,
    *,
    distributions: Sequence[Path],
    source_sha: str,
    source_date_epoch: int,
) -> None:
    evidence_paths = sorted(directory.glob("*.build.json"))
    evidence_by_artifact: dict[str, Mapping[str, Any]] = {}
    for path in evidence_paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ReleaseGateError(f"build evidence is not an object: {path.name}")
        artifact = value.get("artifact")
        if not isinstance(artifact, str) or artifact in evidence_by_artifact:
            raise ReleaseGateError("build evidence has a missing or duplicate artifact")
        evidence_by_artifact[artifact] = value
    if set(evidence_by_artifact) != {path.name for path in distributions}:
        raise ReleaseGateError("build evidence does not bind every distribution exactly once")
    for path in distributions:
        evidence = evidence_by_artifact[path.name]
        expected_digest = _sha256_file(path)
        if path.name.endswith(".whl"):
            platform_tag = path.name.removesuffix(".whl").rsplit("-", 1)[-1]
            expected_platform = {
                "linux_aarch64": "linux-arm64",
                "linux_x86_64": "linux-x86-64",
                "macosx_11_0_arm64": "macos-arm64",
            }.get(platform_tag)
            expected_kind = "wheel"
        else:
            expected_platform = "source"
            expected_kind = "sdist"
        if (
            evidence.get("schema") != 1
            or evidence.get("artifact") != path.name
            or evidence.get("build_kind") != expected_kind
            or evidence.get("builder") != "scripts/reproducible_build.py"
            or evidence.get("platform") != expected_platform
            or evidence.get("python") != "3.12.13"
            or evidence.get("uv") != "uv 0.11.28"
            or evidence.get("reproducible") is not True
            or evidence.get("source_sha") != source_sha
            or evidence.get("source_date_epoch") != source_date_epoch
            or evidence.get("sha256") != expected_digest
            or evidence.get("rebuild_sha256") != expected_digest
            or evidence.get("size") != path.stat().st_size
        ):
            raise ReleaseGateError(f"invalid reproducible build evidence for {path.name}")
        try:
            sqlite_version = tuple(int(part) for part in str(evidence["sqlite"]).split("."))
        except (KeyError, ValueError) as exc:
            raise ReleaseGateError(f"invalid SQLite build evidence for {path.name}") from exc
        if sqlite_version < (3, 51, 3):
            raise ReleaseGateError(f"release artifact used unsupported SQLite for {path.name}")
        if expected_kind == "wheel":
            input_artifact = evidence.get("input_artifact")
            input_digest = evidence.get("input_sha256")
            if not isinstance(input_artifact, str) or not input_artifact.endswith(".tar.gz"):
                raise ReleaseGateError(
                    f"wheel evidence has no reviewed sdist input for {path.name}"
                )
            if not isinstance(input_digest, str) or not _SHA256.fullmatch(input_digest):
                raise ReleaseGateError(f"wheel evidence has no sdist digest for {path.name}")

    sdists = [path for path in distributions if path.name.endswith(".tar.gz")]
    if sdists:
        source = sdists[0]
        source_digest = _sha256_file(source)
        for wheel in (path for path in distributions if path.name.endswith(".whl")):
            evidence = evidence_by_artifact[wheel.name]
            if (
                evidence.get("input_artifact") != source.name
                or evidence.get("input_sha256") != source_digest
            ):
                raise ReleaseGateError(f"wheel {wheel.name} was not rebuilt from reviewed sdist")


def _runtime_dependency_graph(
    manifest: Mapping[str, Any], *, project: Mapping[str, Any]
) -> tuple[dict[str, str], dict[str, set[str]]]:
    if manifest.get("schema") != "signet-runtime-manifest-v1":
        raise ReleaseGateError("runtime manifest schema does not match")
    environment_value = manifest.get("marker_environment")
    packages_value = manifest.get("packages")
    if not isinstance(environment_value, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in environment_value.items()
    ):
        raise ReleaseGateError("runtime manifest marker environment is malformed")
    environment = dict(environment_value)
    if (
        environment.get("python_full_version") != "3.12.13"
        or environment.get("python_version") != "3.12"
    ):
        raise ReleaseGateError("runtime manifest environment is outside release policy")
    if not isinstance(packages_value, list):
        raise ReleaseGateError("runtime manifest package inventory is absent")

    root_name = canonicalize_name(EXPECTED_DISTRIBUTION)
    project_requirements = _active_project_requirements(project, environment)
    expected_versions = {
        root_name: str(project["version"]),
        **{
            name: _exact_requirement_version(requirement)
            for name, requirement in project_requirements.items()
        },
    }
    package_requirements: dict[str, list[Requirement]] = {}
    observed_versions: dict[str, str] = {}
    for package in packages_value:
        if not isinstance(package, dict):
            raise ReleaseGateError("runtime manifest package entry is not an object")
        name = canonicalize_name(str(package.get("name", "")))
        version = str(package.get("version", ""))
        raw_requirements = package.get("requires_dist")
        if (
            not name
            or name in observed_versions
            or not version
            or not isinstance(raw_requirements, list)
            or not all(isinstance(item, str) for item in raw_requirements)
        ):
            raise ReleaseGateError("runtime manifest package identity is missing or duplicated")
        try:
            requirements = [Requirement(item) for item in raw_requirements]
        except ValueError as error:
            raise ReleaseGateError("runtime manifest has invalid dependency metadata") from error
        observed_versions[name] = version
        package_requirements[name] = requirements
    if observed_versions != expected_versions:
        raise ReleaseGateError("runtime manifest versions differ from the reviewed closure")
    if set(package_requirements[root_name]) != _expected_requirements(project):
        raise ReleaseGateError("runtime manifest root metadata differs from the project")

    active_extras = {name: set() for name in expected_versions}
    graph = {name: set() for name in expected_versions}
    changed = True
    while changed:
        changed = False
        for parent, requirements in package_requirements.items():
            marker_extras = {"", *active_extras[parent]}
            for requirement in requirements:
                target = canonicalize_name(requirement.name)
                # cyclonedx-py records every declared edge whose target is installed,
                # including optional edges satisfied elsewhere in the locked closure.
                if target in expected_versions:
                    graph[parent].add(target)
                applies = requirement.marker is None or any(
                    requirement.marker.evaluate({**environment, "extra": extra})
                    for extra in marker_extras
                )
                if not applies:
                    continue
                if target not in expected_versions:
                    raise ReleaseGateError(
                        f"runtime manifest dependency is outside reviewed closure: {target}"
                    )
                if requirement.specifier and not requirement.specifier.contains(
                    expected_versions[target], prereleases=True
                ):
                    raise ReleaseGateError(
                        f"runtime manifest dependency constraint excludes {target}"
                    )
                new_extras = set(requirement.extras) - active_extras[target]
                if new_extras:
                    active_extras[target].update(new_extras)
                    changed = True
    return expected_versions, graph


def _verify_sbom(
    path: Path,
    *,
    project: Mapping[str, Any],
    runtime_manifest: Mapping[str, Any],
) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX":
        raise ReleaseGateError("runtime SBOM is not CycloneDX JSON")
    metadata = value.get("metadata")
    root = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(root, dict):
        raise ReleaseGateError("runtime SBOM has no root component")
    if canonicalize_name(str(root.get("name", ""))) != canonicalize_name(EXPECTED_DISTRIBUTION):
        raise ReleaseGateError("runtime SBOM root package name does not match")
    if str(root.get("version", "")) != str(project["version"]):
        raise ReleaseGateError("runtime SBOM root version does not match")
    root_ref = root.get("bom-ref")
    dependencies = value.get("dependencies")
    components = value.get("components")
    if (
        not isinstance(root_ref, str)
        or not isinstance(dependencies, list)
        or not isinstance(components, list)
    ):
        raise ReleaseGateError("runtime SBOM dependency graph is absent")
    expected_versions, expected_graph = _runtime_dependency_graph(runtime_manifest, project=project)
    expected_versions.pop(canonicalize_name(EXPECTED_DISTRIBUTION))
    components_by_name: dict[str, Mapping[str, Any]] = {}
    component_refs: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise ReleaseGateError("runtime SBOM component is not an object")
        name = canonicalize_name(str(component.get("name", "")))
        reference = component.get("bom-ref")
        if not name or name in components_by_name or not isinstance(reference, str):
            raise ReleaseGateError("runtime SBOM component identity is missing or duplicated")
        if reference in component_refs:
            raise ReleaseGateError("runtime SBOM component reference is duplicated")
        components_by_name[name] = component
        component_refs.add(reference)
    if set(components_by_name) != set(expected_versions):
        raise ReleaseGateError("runtime SBOM component set differs from dependency closure")
    for name, expected_version in expected_versions.items():
        version = str(components_by_name[name].get("version", ""))
        if version != expected_version:
            raise ReleaseGateError(f"runtime SBOM version differs from locked dependency: {name}")

    edges: dict[str, set[str]] = {}
    for item in dependencies:
        if not isinstance(item, dict) or not isinstance(item.get("ref"), str):
            raise ReleaseGateError("runtime SBOM dependency edge is malformed")
        reference = item["ref"]
        depends_on = item.get("dependsOn", [])
        if (
            reference in edges
            or not isinstance(depends_on, list)
            or not all(isinstance(dependency, str) for dependency in depends_on)
        ):
            raise ReleaseGateError("runtime SBOM dependency edge is missing or duplicated")
        edges[reference] = set(depends_on)
    if set(edges) != component_refs | {root_ref}:
        raise ReleaseGateError("runtime SBOM dependency graph omits or invents components")
    if any(not child_refs <= component_refs for child_refs in edges.values()):
        raise ReleaseGateError("runtime SBOM dependency graph references unknown components")
    references_by_name = {
        name: str(component["bom-ref"]) for name, component in components_by_name.items()
    }
    references_by_name[canonicalize_name(EXPECTED_DISTRIBUTION)] = root_ref
    for parent, children in expected_graph.items():
        expected_children = {references_by_name[child] for child in children}
        if edges[references_by_name[parent]] != expected_children:
            raise ReleaseGateError(f"runtime SBOM dependency graph differs for package: {parent}")


def _verify_licenses(path: Path, *, project: Mapping[str, Any]) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not value:
        raise ReleaseGateError("license report is empty or not a list")
    reported: dict[str, str] = {}
    for item in value:
        if not isinstance(item, dict):
            raise ReleaseGateError("license report entry is not an object")
        name = canonicalize_name(str(item.get("Name", "")))
        version = str(item.get("Version", ""))
        license_name = str(item.get("License", "")).strip()
        if not name or not version or not license_name or _FORBIDDEN_LICENSE.search(license_name):
            package = name or "unknown package"
            raise ReleaseGateError(f"unreviewed or forbidden license for {package}")
        if name in reported:
            raise ReleaseGateError(f"duplicate license report entry for {name}")
        reported[name] = version
    expected: dict[str, str] = {canonicalize_name(EXPECTED_DISTRIBUTION): str(project["version"])}
    expected.update(
        {
            name: _exact_requirement_version(requirement)
            for name, requirement in _active_project_requirements(project).items()
        }
    )
    if reported != expected:
        raise ReleaseGateError(
            "license report package/version set differs from runtime closure: "
            f"missing={sorted(expected.keys() - reported.keys())}, "
            f"extra={sorted(reported.keys() - expected.keys())}"
        )


def _unsigned_artifacts(directory: Path) -> set[Path]:
    return {
        path
        for path in directory.iterdir()
        if path.is_file()
        and (
            path.suffix == ".whl"
            or path.name.endswith(".tar.gz")
            or path.name.endswith((".build.json", ".cdx.json", ".licenses.json", ".runtime.json"))
        )
    }


def _verify_directory_members(directory: Path, *, require_signatures: bool) -> None:
    unsigned = _unsigned_artifacts(directory)
    checksum = directory / "SHA256SUMS"
    signatures = {path for path in directory.iterdir() if path.name.endswith(".sigstore.json")}
    allowed = unsigned | signatures
    if checksum.exists():
        allowed.add(checksum)
    actual = set(directory.iterdir())
    if actual != allowed:
        unexpected = sorted(path.name for path in actual - allowed)
        raise ReleaseGateError(f"unexpected release directory members: {unexpected}")
    if signatures or require_signatures:
        signed = unsigned | ({checksum} if checksum.exists() else set())
        expected = {directory / f"{path.name}.sigstore.json" for path in signed}
        if signatures != expected:
            missing = sorted(path.name for path in expected - signatures)
            extra = sorted(path.name for path in signatures - expected)
            raise ReleaseGateError(
                f"Sigstore bundle set differs from release payloads: missing={missing}, "
                f"extra={extra}"
            )


def verify_artifacts(
    *,
    root: Path,
    directory: Path,
    source_sha: str,
    expected_platform_names: Sequence[str],
    expect_sdist: bool,
    require_evidence: bool,
    require_sbom: bool,
    require_license_report: bool,
    require_signatures: bool,
) -> None:
    root = root.resolve(strict=True)
    directory = directory.resolve(strict=True)
    project = _project(root)
    if not _SHA40.fullmatch(source_sha):
        raise ReleaseGateError("artifact source SHA must be one full lowercase Git commit digest")
    platform_tags: list[str] = []
    for name in expected_platform_names:
        try:
            platform_tags.append(EXPECTED_PLATFORMS[name])
        except KeyError as exc:
            raise ReleaseGateError(f"unknown supported platform: {name}") from exc
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != len(platform_tags):
        raise ReleaseGateError(f"expected {len(platform_tags)} wheels, found {len(wheels)}")
    if len(sdists) != int(expect_sdist):
        expected_count = int(expect_sdist)
        raise ReleaseGateError(
            f"expected {expected_count} source distributions, found {len(sdists)}"
        )
    wheels_by_tag = {path.name.removesuffix(".whl").rsplit("-", 1)[-1]: path for path in wheels}
    if set(wheels_by_tag) != set(platform_tags):
        raise ReleaseGateError("wheel platform set does not match the supported release matrix")
    for platform_tag, wheel in wheels_by_tag.items():
        _verify_wheel(wheel, project=project, platform_tag=platform_tag)
    for sdist in sdists:
        _verify_sdist(sdist, project=project)
    distributions = [*wheels, *sdists]
    if require_evidence:
        source_date_epoch = int(_git(root, "show", "-s", "--format=%ct", source_sha))
        _verify_build_evidence(
            directory,
            distributions=distributions,
            source_sha=source_sha,
            source_date_epoch=source_date_epoch,
        )
    sboms = sorted(directory.glob("*.cdx.json"))
    if len(sboms) != int(require_sbom):
        raise ReleaseGateError(f"expected {int(require_sbom)} runtime SBOMs, found {len(sboms)}")
    manifests = sorted(directory.glob("*.runtime.json"))
    if len(manifests) != int(require_sbom):
        raise ReleaseGateError(
            f"expected {int(require_sbom)} runtime manifests, found {len(manifests)}"
        )
    runtime_manifest: Mapping[str, Any] | None = None
    if manifests:
        manifest_value = json.loads(manifests[0].read_text(encoding="utf-8"))
        if not isinstance(manifest_value, dict):
            raise ReleaseGateError("runtime manifest root is not an object")
        if manifest_value.get("source_sha") != source_sha:
            raise ReleaseGateError("runtime manifest source SHA does not match")
        environment = manifest_value.get("marker_environment")
        if not isinstance(environment, dict) or (
            environment.get("sys_platform") != "linux"
            or environment.get("platform_machine") not in {"x86_64", "amd64"}
        ):
            raise ReleaseGateError("release SBOM must describe the Linux x86_64 runtime")
        runtime_manifest = manifest_value
    for sbom in sboms:
        if runtime_manifest is None:
            raise ReleaseGateError("runtime SBOM has no runtime manifest")
        _verify_sbom(sbom, project=project, runtime_manifest=runtime_manifest)
    licenses = sorted(directory.glob("*.licenses.json"))
    if len(licenses) != int(require_license_report):
        raise ReleaseGateError(
            f"expected {int(require_license_report)} license reports, found {len(licenses)}"
        )
    for license_report in licenses:
        _verify_licenses(license_report, project=project)
    _verify_directory_members(directory, require_signatures=require_signatures)


def write_checksums(directory: Path) -> Path:
    directory = directory.resolve(strict=True)
    destination = directory / "SHA256SUMS"
    if destination.exists():
        raise ReleaseGateError("refusing to replace existing SHA256SUMS")
    _verify_directory_members(directory, require_signatures=False)
    artifacts = sorted(_unsigned_artifacts(directory))
    if not artifacts:
        raise ReleaseGateError("no release artifacts available for checksums")
    destination.write_text(
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in artifacts),
        encoding="utf-8",
    )
    return destination


def verify_checksums(directory: Path) -> None:
    directory = directory.resolve(strict=True)
    _verify_directory_members(directory, require_signatures=False)
    checksum_path = directory / "SHA256SUMS"
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ReleaseGateError("SHA256SUMS is empty")
    seen: set[str] = set()
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if match is None:
            raise ReleaseGateError("SHA256SUMS contains a malformed line")
        digest, name = match.groups()
        if name in seen:
            raise ReleaseGateError(f"SHA256SUMS contains duplicate path {name}")
        seen.add(name)
        path = directory / name
        if not path.is_file() or _sha256_file(path) != digest:
            raise ReleaseGateError(f"checksum verification failed for {name}")
    expected = {path.name for path in _unsigned_artifacts(directory)}
    if seen != expected:
        raise ReleaseGateError("SHA256SUMS does not cover the exact unsigned artifact set")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    ref = commands.add_parser("verify-ref")
    ref.add_argument("--root", type=Path, default=Path.cwd())
    ref.add_argument("--tag", required=True)
    ref.add_argument("--sha", required=True)
    ref.add_argument("--event-name", required=True)
    ref.add_argument("--ref-type", required=True)
    ref.add_argument("--repository", required=True)
    ref.add_argument("--main-ref", default="origin/main")

    artifacts = commands.add_parser("verify-artifacts")
    artifacts.add_argument("--root", type=Path, default=Path.cwd())
    artifacts.add_argument("--directory", type=Path, required=True)
    artifacts.add_argument("--source-sha", required=True)
    artifacts.add_argument("--platform", action="append", default=[])
    artifacts.add_argument("--expect-sdist", action="store_true")
    artifacts.add_argument("--require-evidence", action="store_true")
    artifacts.add_argument("--require-sbom", action="store_true")
    artifacts.add_argument("--require-license-report", action="store_true")
    artifacts.add_argument("--require-signatures", action="store_true")

    checksums = commands.add_parser("write-checksums")
    checksums.add_argument("--directory", type=Path, required=True)
    verify = commands.add_parser("verify-checksums")
    verify.add_argument("--directory", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify-ref":
            verify_ref(
                root=args.root,
                tag=args.tag,
                sha=args.sha,
                event_name=args.event_name,
                ref_type=args.ref_type,
                repository=args.repository,
                main_ref=args.main_ref,
            )
        elif args.command == "verify-artifacts":
            verify_artifacts(
                root=args.root,
                directory=args.directory,
                source_sha=args.source_sha,
                expected_platform_names=args.platform,
                expect_sdist=args.expect_sdist,
                require_evidence=args.require_evidence,
                require_sbom=args.require_sbom,
                require_license_report=args.require_license_report,
                require_signatures=args.require_signatures,
            )
        elif args.command == "write-checksums":
            write_checksums(args.directory)
        elif args.command == "verify-checksums":
            verify_checksums(args.directory)

    except (KeyError, OSError, ReleaseGateError, ValueError, zipfile.BadZipFile) as exc:
        print(f"release gate failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
