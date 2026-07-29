from __future__ import annotations

import json
import re
import runpy
import subprocess  # nosec B404
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path
from typing import Any

import pytest
from packaging.specifiers import SpecifierSet

ROOT = Path(__file__).resolve().parents[1]
RELEASE_GATE = ROOT / "scripts" / "release_gate.py"
REPRODUCIBLE_BUILD = ROOT / "scripts" / "reproducible_build.py"
RUNTIME_MANIFEST = ROOT / "scripts" / "runtime_manifest.py"
WORKFLOW_CONTRACT = ROOT / "scripts" / "workflow_contract.py"
PINNED_ACTION = re.compile(r"^\s*uses:\s+[^\s]+@[0-9a-f]{40}(?:\s+#.*)?$")


def _load_script(path: Path) -> dict[str, Any]:
    assert path.is_file(), f"missing release tool: {path.relative_to(ROOT)}"
    return runpy.run_path(str(path), run_name=f"test_{path.stem}")


def test_release_metadata_declares_stable_supported_distribution() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["name"] == "signet-gateway"
    assert project["version"] == "0.1.0"
    assert project["requires-python"] == ">=3.12,<3.13"
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert project["scripts"] == {"signet": "signet.app:main"}
    assert set(project["classifiers"]) >= {
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    }
    assert project["urls"]["Changelog"].endswith("/blob/main/CHANGELOG.md")
    assert project["urls"]["Security"].endswith("/security/policy")


def test_wheel_policy_rejects_unsupported_platforms() -> None:
    namespace = runpy.run_path(str(ROOT / "hatch_build.py"))
    supported_wheel_tag = namespace.get("supported_wheel_tag")
    assert callable(supported_wheel_tag)

    assert supported_wheel_tag("darwin", "arm64", "macosx-11.0-arm64") == (
        "py3-none-macosx_11_0_arm64"
    )
    assert supported_wheel_tag("darwin", "arm64", "macosx-14.0-arm64") == (
        "py3-none-macosx_11_0_arm64"
    )
    assert supported_wheel_tag("linux", "x86_64", "linux-x86_64") == ("py3-none-linux_x86_64")
    assert supported_wheel_tag("linux", "aarch64", "linux-aarch64") == "py3-none-linux_aarch64"
    with pytest.raises(RuntimeError, match="unsupported release platform"):
        supported_wheel_tag("darwin", "x86_64", "macosx-10.9-x86_64")
    with pytest.raises(RuntimeError, match="unsupported release platform"):
        supported_wheel_tag("win32", "AMD64", "win-amd64")


def test_release_ref_policy_rejects_mismatches_and_non_stable_tags() -> None:
    namespace = _load_script(RELEASE_GATE)
    validate_release_identity = namespace["validate_release_identity"]
    error = namespace["ReleaseGateError"]

    validate_release_identity(
        tag="v0.1.0",
        version="0.1.0",
        event_name="push",
        ref_type="tag",
        repository="bee-san/Signet",
    )
    for overrides in (
        {"tag": "v0.1.1"},
        {"tag": "v0.1.0rc1"},
        {"tag": "release-0.1.0"},
        {"event_name": "workflow_dispatch"},
        {"ref_type": "branch"},
        {"repository": "attacker/Signet"},
    ):
        values = {
            "tag": "v0.1.0",
            "version": "0.1.0",
            "event_name": "push",
            "ref_type": "tag",
            "repository": "bee-san/Signet",
            **overrides,
        }
        with pytest.raises(error):
            validate_release_identity(**values)


def test_release_ref_requires_exact_current_main_tip(tmp_path: Path) -> None:
    namespace = _load_script(RELEASE_GATE)
    verify_ref = namespace["verify_ref"]
    error = namespace["ReleaseGateError"]
    repository = tmp_path / "repository"
    repository.mkdir()

    for command in (
        ["git", "init", "--quiet", "--initial-branch=main"],
        ["git", "config", "user.name", "Release Test"],
        ["git", "config", "user.email", "release-test@example.invalid"],
    ):
        subprocess.run(command, cwd=repository, check=True, timeout=60)  # nosec B603 B607
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "signet-gateway"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    subprocess.run(  # nosec B603 B607
        ["git", "add", "pyproject.toml"], cwd=repository, check=True, timeout=60
    )
    subprocess.run(  # nosec B603 B607
        ["git", "commit", "--quiet", "-m", "release source"],
        cwd=repository,
        check=True,
        timeout=60,
    )
    release_sha = subprocess.run(  # nosec B603 B607
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()
    subprocess.run(  # nosec B603 B607
        ["git", "tag", "-a", "v0.1.0", "-m", "release"],
        cwd=repository,
        check=True,
        timeout=60,
    )
    (repository / "security-fix.txt").write_text("newer reviewed source\n", encoding="utf-8")
    subprocess.run(  # nosec B603 B607
        ["git", "add", "security-fix.txt"], cwd=repository, check=True, timeout=60
    )
    subprocess.run(  # nosec B603 B607
        ["git", "commit", "--quiet", "-m", "security fix"],
        cwd=repository,
        check=True,
        timeout=60,
    )
    subprocess.run(  # nosec B603 B607
        ["git", "checkout", "--quiet", "--detach", release_sha],
        cwd=repository,
        check=True,
        timeout=60,
    )

    with pytest.raises(error, match="exact current main tip"):
        verify_ref(
            root=repository,
            tag="v0.1.0",
            sha=release_sha,
            event_name="push",
            ref_type="tag",
            repository="bee-san/Signet",
            main_ref="main",
        )

    subprocess.run(  # nosec B603 B607
        ["git", "branch", "--force", "main", release_sha],
        cwd=repository,
        check=True,
        timeout=60,
    )
    verify_ref(
        root=repository,
        tag="v0.1.0",
        sha=release_sha,
        event_name="push",
        ref_type="tag",
        repository="bee-san/Signet",
        main_ref="main",
    )


def test_release_gate_rejects_archive_traversal_and_incomplete_sbom(tmp_path: Path) -> None:
    namespace = _load_script(RELEASE_GATE)
    error = namespace["ReleaseGateError"]
    malicious_wheel = tmp_path / "malicious.whl"
    with zipfile.ZipFile(malicious_wheel, "w") as archive:
        archive.writestr("../../outside", b"escape")
    with (
        zipfile.ZipFile(malicious_wheel) as archive,
        pytest.raises(error, match="unsafe archive member"),
    ):
        namespace["_verify_zip_members"](archive)

    project = {
        "name": "signet-gateway",
        "version": "0.1.0",
        "dependencies": ["alpha==1.0", "bravo==2.0"],
    }
    runtime_manifest = {
        "schema": "signet-runtime-manifest-v1",
        "source_sha": "a" * 40,
        "marker_environment": {
            "implementation_name": "cpython",
            "platform_machine": "x86_64",
            "platform_python_implementation": "CPython",
            "python_full_version": "3.12.13",
            "python_version": "3.12",
            "sys_platform": "linux",
        },
        "packages": [
            {
                "name": "signet-gateway",
                "version": "0.1.0",
                "requires_dist": ["alpha==1.0", "bravo==2.0"],
            },
            {
                "name": "alpha",
                "version": "1.0",
                "requires_dist": ["bravo==2.0; extra == 'optional'"],
            },
            {"name": "bravo", "version": "2.0", "requires_dist": []},
        ],
    }
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "metadata": {
            "component": {
                "bom-ref": "root-component",
                "name": "signet-gateway",
                "version": "0.1.0",
            }
        },
        "components": [
            {"bom-ref": "alpha==1.0", "name": "alpha", "version": "1.0"},
            {"bom-ref": "bravo==2.0", "name": "bravo", "version": "2.0"},
        ],
        "dependencies": [
            {
                "ref": "root-component",
                "dependsOn": ["alpha==1.0", "bravo==2.0"],
            },
            {"ref": "alpha==1.0"},
            {"ref": "bravo==2.0"},
        ],
    }
    sbom_path = tmp_path / "adversarial.cdx.json"
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
    with pytest.raises(error, match="dependency graph"):
        namespace["_verify_sbom"](
            sbom_path,
            project=project,
            runtime_manifest=runtime_manifest,
        )

    sbom["components"][0]["version"] = "1.0+forged"
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
    with pytest.raises(error, match="locked dependency"):
        namespace["_verify_sbom"](
            sbom_path,
            project=project,
            runtime_manifest=runtime_manifest,
        )

    license_report = [
        {"Name": "signet-gateway", "Version": "0.1.0", "License": "MIT"},
        {"Name": "alpha", "Version": "1.0+forged", "License": "MIT"},
        {"Name": "bravo", "Version": "2.0", "License": "MIT"},
    ]
    license_path = tmp_path / "adversarial.licenses.json"
    license_path.write_text(json.dumps(license_report), encoding="utf-8")
    with pytest.raises(error, match="version"):
        namespace["_verify_licenses"](license_path, project=project)


def test_release_build_evidence_is_reproducible_and_source_bound(tmp_path: Path) -> None:
    namespace = _load_script(REPRODUCIBLE_BUILD)
    build_reproducibly = namespace["build_reproducibly"]
    default_uv_executable = namespace["_default_uv_executable"]
    error = namespace["ReproducibleBuildError"]
    repository = tmp_path / "repository"
    package = repository / "src" / "evidence_demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repository / "pyproject.toml").write_text(
        """[build-system]
requires = ["hatchling==1.31.0"]
build-backend = "hatchling.build"

[project]
name = "evidence-demo"
version = "1.0.0"
requires-python = ">=3.12,<3.13"

[tool.hatch.build.targets.sdist]
include = ["/pyproject.toml", "/src/**"]

[tool.hatch.build.targets.wheel]
packages = ["src/evidence_demo"]
""",
        encoding="utf-8",
    )
    for command in (
        ["git", "init", "--quiet"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test source",
        ],
    ):
        subprocess.run(command, cwd=repository, check=True, timeout=60)  # nosec B603 B607
    source_sha = subprocess.run(  # nosec B603 B607
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()

    evidence = build_reproducibly(
        repository=repository,
        source=repository,
        source_evidence=None,
        kind="sdist",
        output_directory=tmp_path / "dist",
        evidence_path=tmp_path / "dist" / "source.build.json",
        source_sha=source_sha,
        platform_name="source",
        uv_executable=default_uv_executable(),
    )

    artifact = tmp_path / "dist" / str(evidence["artifact"])
    assert artifact.is_file()
    assert evidence["reproducible"] is True
    assert evidence["sha256"] == evidence["rebuild_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", str(evidence["sha256"]))
    assert evidence["source_sha"] == source_sha
    assert evidence["uv"] == "uv 0.11.28"

    (package / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(error, match="tracked changes"):
        build_reproducibly(
            repository=repository,
            source=repository,
            source_evidence=None,
            kind="sdist",
            output_directory=tmp_path / "dirty-dist",
            evidence_path=tmp_path / "dirty-dist" / "source.build.json",
            source_sha=source_sha,
            platform_name="source",
            uv_executable=default_uv_executable(),
        )


def test_reproducible_build_falls_back_when_the_environment_has_no_uv_sibling(
    tmp_path: Path,
) -> None:
    namespace = _load_script(REPRODUCIBLE_BUILD)
    default_uv_executable = namespace["_default_uv_executable"]
    python = tmp_path / "venv" / "bin" / "python"

    assert default_uv_executable(python) == "uv"

    sibling = python.with_name("uv")
    sibling.parent.mkdir(parents=True)
    sibling.write_text("#!/bin/sh\n", encoding="utf-8")
    sibling.chmod(0o755)
    assert default_uv_executable(python) == str(sibling)


def test_runtime_manifest_is_deterministic_and_source_bound() -> None:
    namespace = _load_script(RUNTIME_MANIFEST)
    build_manifest = namespace["build_manifest"]
    error = namespace["RuntimeManifestError"]
    source_sha = "b" * 40

    first = build_manifest(source_sha=source_sha)
    second = build_manifest(source_sha=source_sha)

    assert first == second
    assert first["schema"] == "signet-runtime-manifest-v1"
    assert first["source_sha"] == source_sha
    packages = first["packages"]
    assert isinstance(packages, list)
    names = [item["name"] for item in packages]
    assert names == sorted(names, key=str.casefold)
    assert any(item["name"] == "signet-gateway" for item in packages)
    with pytest.raises(error, match="40 lowercase"):
        build_manifest(source_sha="not-a-source-sha")


def test_built_artifacts_contain_production_assets_and_metadata(tmp_path: Path) -> None:
    built = subprocess.run(  # nosec B603 B607
        ["uv", "build", "--no-cache", "--no-sources", "--out-dir", str(tmp_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert built.returncode == 0, built.stderr
    wheel = next(tmp_path.glob("*.whl"))
    sdist = next(tmp_path.glob("*.tar.gz"))

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata_bytes = archive.read(metadata_name)
        metadata = metadata_bytes.decode("utf-8")
        parsed_metadata = BytesParser(policy=compat32).parsebytes(metadata_bytes)
        for required in (
            "signet/static/app.css",
            "signet/static/app.js",
            "signet/static/authenticators.js",
            "signet/static/manifest.webmanifest",
            "signet/static/service-worker.js",
            "signet/static/icons/signet-1254.png",
            "signet/templates/setup.html",
            "signet/migrations/0020_production_user_roles.sql",
            "signet/reference_plugins/fastmail/manifest.json",
            "signet/py.typed",
        ):
            assert required in names
        assert any(name.endswith("/share/man/man1/signet.1") for name in names)
        for guide in (
            "README.md",
            "setup.md",
            "setup-resume.md",
            "provider-setup.md",
            "health-and-doctor.md",
            "backup-and-restore.md",
            "upgrade-and-rollback.md",
            "uninstall.md",
            "recovery.md",
            "storage.md",
            "security.md",
            "troubleshooting.md",
        ):
            assert any(name.endswith(f"/share/doc/signet/{guide}") for name in names)
        assert "Name: signet-gateway\n" in metadata
        assert "Version: 0.1.0\n" in metadata
        assert SpecifierSet(parsed_metadata["Requires-Python"]) == SpecifierSet(">=3.12,<3.13")
        assert "License-Expression: MIT\n" in metadata

    with tarfile.open(sdist, "r:gz") as archive:
        names = set(archive.getnames())
        root = next(iter(names)).split("/", 1)[0]
        for required in (
            "CHANGELOG.md",
            "LICENSE",
            "README.md",
            "SECURITY.md",
            "docs/README.md",
            "docs/backup-and-restore.md",
            "docs/man/signet.1",
            "docs/provider-setup.md",
            "docs/releasing.md",
            "docs/security.md",
            "docs/setup-resume.md",
            "docs/storage.md",
            "docs/troubleshooting.md",
            "docs/uninstall.md",
            "docs/upgrade-and-rollback.md",
            "hatch_build.py",
            "pyproject.toml",
            "scripts/release_gate.py",
            "scripts/reproducible_build.py",
            "scripts/runtime_manifest.py",
            "scripts/workflow_contract.py",
            "src/signet/static/app.css",
            "tests/test_release_pipeline.py",
            "uv.lock",
        ):
            assert f"{root}/{required}" in names
        for member in archive.getmembers():
            assert not member.issym() and not member.islnk()
            assert not member.name.startswith("/")
            assert ".." not in Path(member.name).parts


def test_release_workflow_semantic_contract_rejects_comment_decoys(tmp_path: Path) -> None:
    namespace = _load_script(WORKFLOW_CONTRACT)
    validate_release_workflow = namespace["validate_release_workflow"]
    error = namespace["WorkflowContractError"]

    validate_release_workflow(ROOT / ".github" / "workflows" / "release.yml")

    unsafe = tmp_path / "unsafe-release.yml"
    unsafe.write_text(
        """name: Unsafe manual publisher
on:
  workflow_dispatch:
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
      - run: uv publish --trusted-publishing always dist/*
# fetch-depth: 0
# scripts/release_gate.py verify-ref
# name: pypi
# gh attestation verify
""",
        encoding="utf-8",
    )
    with pytest.raises(error):
        validate_release_workflow(unsafe)

    release_text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    comment_decoys = (
        (
            "gate",
            "          git fetch --force --no-tags origin \\\n",
            "          # git fetch --force --no-tags origin \\\n",
        ),
        (
            "publish",
            "          uv publish --trusted-publishing always dist/*.whl dist/*.tar.gz\n",
            "          # uv publish --trusted-publishing always dist/*.whl dist/*.tar.gz\n",
        ),
        (
            "printf",
            "          git fetch --force --no-tags origin \\\n",
            "          printf '%s' 'git fetch --force --no-tags origin' \\\n",
        ),
    )
    for label, active, commented in comment_decoys:
        assert active in release_text
        decoy = tmp_path / f"{label}-comment-decoy.yml"
        decoy.write_text(release_text.replace(active, commented), encoding="utf-8")
        with pytest.raises(error):
            validate_release_workflow(decoy)

    structural_decoys = (
        (
            "post-verification-mutation",
            "      - name: Publish distributions with PyPI trusted publishing\n",
            "      - name: Replace verified distributions\n"
            "        run: printf tampered > dist/signet_gateway-0.1.0.tar.gz\n"
            "      - name: Publish distributions with PyPI trusted publishing\n",
        ),
        (
            "disabled-gate",
            "      - name: Reverify exact tag and current main after approval\n"
            "        shell: bash\n",
            "      - name: Reverify exact tag and current main after approval\n"
            "        if: ${{ false }}\n"
            "        shell: bash\n",
        ),
        (
            "publish-container",
            "  publish:\n    name: Publish approved trusted release\n    needs: verify-release\n",
            "  publish:\n"
            "    name: Publish approved trusted release\n"
            "    needs: verify-release\n"
            "    container: attacker-controlled.example/release:latest\n",
        ),
        (
            "publication-working-directory",
            "      - name: Publish distributions with PyPI trusted publishing\n        run: >-\n",
            "      - name: Publish distributions with PyPI trusted publishing\n"
            "        working-directory: attacker-controlled\n"
            "        run: >-\n",
        ),
    )
    for label, active, replacement in structural_decoys:
        assert active in release_text
        decoy = tmp_path / f"{label}.yml"
        decoy.write_text(release_text.replace(active, replacement), encoding="utf-8")
        with pytest.raises(error):
            validate_release_workflow(decoy)


def test_publish_revalidates_tag_and_current_main_after_environment_approval() -> None:
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    reverify = "- name: Reverify exact tag and current main after approval"
    artifacts = "- name: Reverify approved release identity and artifacts"

    assert release.index(reverify) < release.index(artifacts)
    assert "+refs/heads/main:refs/remotes/origin/main" in release[release.index(reverify) :]
    assert (
        "+refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}"
        in release[release.index(reverify) :]
    )
    assert "verify-ref" in release[release.index(reverify) : release.index(artifacts)]


def test_release_dry_run_uses_an_isolated_index_without_publication() -> None:
    path = ROOT / ".github" / "workflows" / "release-dry-run.yml"
    assert path.is_file()
    workflow = path.read_text(encoding="utf-8")

    uses_lines = [line for line in workflow.splitlines() if re.match(r"^\s*uses:", line)]
    assert uses_lines and all(PINNED_ACTION.fullmatch(line) for line in uses_lines)
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" in workflow
    assert "--index-url http://127.0.0.1:" in workflow
    assert "pypi-server run" in workflow
    assert "uv publish --publish-url http://127.0.0.1:" in workflow
    assert "--no-deps" in workflow
    for arguments in ("--version", "setup --help", "doctor --help", "status --help"):
        assert re.search(rf"signet[\"']? {re.escape(arguments)}", workflow)
    assert "pypi.org" not in workflow
    assert "test.pypi.org" not in workflow
    assert "trusted-publishing" not in workflow
    assert "id-token: write" not in workflow
    assert "contents: write" not in workflow
    assert "secrets." not in workflow
    assert '- "scripts/runtime_manifest.py"' in workflow
    assert '- "docs/**"' in workflow


def test_release_documentation_defines_support_verification_and_compromise_response() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8")

    assert "## [0.1.0] - Unreleased" in changelog
    for required in (
        "Linux x86_64",
        "Linux arm64",
        "macOS arm64",
        "Python >=3.12,<3.13",
        "SQLite 3.51.3",
        "release-dry-run.yml",
        "protected `pypi` environment",
        "required reviewers",
        "bee-san/Signet",
        ".github/workflows/release.yml",
        "uv publish --trusted-publishing always",
        "sigstore verify identity",
        "gh attestation verify",
        "SHA256SUMS",
        "yank",
        "never reuse",
    ):
        assert required in release
    assert "for artifact in signet_gateway-*.whl signet_gateway-*.tar.gz" in release
    assert release.count('gh attestation verify "$artifact"') == 2
    assert "--predicate-type https://cyclonedx.org/bom" in release
    assert "gh attestation verify signet_gateway-*.whl signet_gateway-*.tar.gz" not in release
