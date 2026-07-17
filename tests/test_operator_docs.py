from __future__ import annotations

import os
import re
import shutil
import subprocess
import textwrap
import time
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
OPERATOR_CONSOLE_PATHS = (
    ROOT / "README.md",
    ROOT / "docs" / "deployment.md",
    ROOT / "docs" / "operator-runbook.md",
    ROOT / "deploy" / "hermes" / "README.md",
)
CONSOLE_BLOCK_PATTERN = re.compile(
    r"^[ \t]*```console[ \t]*\n(?P<body>.*?)^[ \t]*```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
HERMES_SEEDED_ENV = (
    b"# Per-profile secrets for this Hermes profile.\n"
    b"# API keys and tokens set here override the shell environment.\n"
    b"# Behavioral settings belong in config.yaml, not here.\n"
)


def _console_blocks(path: Path) -> list[str]:
    document = path.read_text(encoding="utf-8")
    blocks = [
        textwrap.dedent(match.group("body")) for match in CONSOLE_BLOCK_PATTERN.finditer(document)
    ]
    assert blocks, path
    assert len(blocks) == document.count("```console"), path
    return blocks


def _console_block_containing(path: Path, marker: str) -> str:
    matches = [block for block in _console_blocks(path) if marker in block]
    assert len(matches) == 1, (path, marker)
    return matches[0]


def _shell_or_skip(shell_name: str) -> str:
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip(f"{shell_name} is not installed")
    return shell


def _write_hermes_uv_stub(stub_dir: Path) -> Path:
    uv_stub = stub_dir / "uv"
    uv_stub.write_text(
        """#!/bin/sh
set -eu
test "$HERMES_HOME" = "$HOME/.hermes"
test "$HERMES_MANAGED_DIR" = "$HOME/.no-managed-scope"
test "${UV_INDEX+x}" != x
test "${UV_FIND_LINKS+x}" != x
test "${UV_OVERRIDE+x}" != x
test "$1" = run
test "$2" = --locked
test "$3" = --isolated
test "$4" = --no-config
test "$5" = --exclude-newer
test "$6" = 2026-07-09T00:00:00Z
test "$7" = --no-env-file
test "$8" = --no-sources
test "$9" = --no-build
test "${10}" = --project
test -f "${11}/pyproject.toml"
test -f "${11}/uv.lock"
test "${12}" = hermes
shift 12
mkdir -p "$HERMES_HOME/logs"
chmod 700 "$HERMES_HOME/logs"
: >> "$HERMES_HOME/.update_check"
: >> "$HERMES_HOME/logs/agent.log"
: >> "$HERMES_HOME/logs/errors.log"
chmod 600 "$HERMES_HOME/.update_check" \
  "$HERMES_HOME/logs/agent.log" "$HERMES_HOME/logs/errors.log"
seed_runtime_profile_state() {
  profile_path="$1"
  test -d "$profile_path" || return
  for directory in audio_cache hooks image_cache pairing \
    logs logs/curator; do
    mkdir -p "$profile_path/$directory"
    chmod 700 "$profile_path/$directory"
  done
  : >> "$profile_path/logs/agent.log"
  : >> "$profile_path/logs/errors.log"
  chmod 600 "$profile_path/logs/agent.log" "$profile_path/logs/errors.log"
  if test -f "$HOME/.unsafe-profile-mutation"; then
    : > "$profile_path/logs/unsafe-after-path"
    chmod 644 "$profile_path/logs/unsafe-after-path"
  fi
}
case "$*" in
  "profile create "*" --no-alias --no-skills")
    profile_name="$3"
    profile_path="$HERMES_HOME/profiles/$profile_name"
    mkdir -m 700 "$profile_path" || exit 1
    for directory in cron home logs memories plans sessions skills skins workspace; do
      mkdir -m 700 "$profile_path/$directory"
    done
    printf '%s\n' \
      '# Per-profile secrets for this Hermes profile.' \
      '# API keys and tokens set here override the shell environment.' \
      '# Behavioral settings belong in config.yaml, not here.' \
      > "$profile_path/.env"
    printf '%s\n' 'This profile opted out of bundled-skill seeding.' \
      > "$profile_path/.no-bundled-skills"
    printf '%s\n' 'You are Hermes Agent.' > "$profile_path/SOUL.md"
    chmod 600 "$profile_path/.env" "$profile_path/.no-bundled-skills" \
      "$profile_path/SOUL.md"
    : > "$HOME/.hermes-create-called"
    ;;
  "-p "*" config path")
    profile_name="$2"
    seed_runtime_profile_state "$HERMES_HOME/profiles/$profile_name"
    if test -f "$HOME/.misreport"; then
      report_parent="$HERMES_HOME/other/$profile_name"
      mkdir -p "$report_parent"
    else
      report_parent="$HERMES_HOME/profiles/$profile_name"
    fi
    printf '%s/config.yaml\n' "$report_parent"
    ;;
  "-p "*" config env-path")
    profile_name="$2"
    seed_runtime_profile_state "$HERMES_HOME/profiles/$profile_name"
    if test -f "$HOME/.misreport"; then
      report_parent="$HERMES_HOME/other/$profile_name"
      mkdir -p "$report_parent"
    else
      report_parent="$HERMES_HOME/profiles/$profile_name"
    fi
    printf '%s/.env\n' "$report_parent"
    ;;
  "profile delete "*" -y")
    profile_name="$3"
    profile_path="$HERMES_HOME/profiles/$profile_name"
    : > "$HOME/.hermes-delete-called"
    rm -rf "$profile_path"
    ;;
esac
""",
        encoding="utf-8",
    )
    uv_stub.chmod(0o700)
    return uv_stub


def test_operator_runbook_is_linked_from_entrypoint_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    deploy = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "operator-runbook.md").read_text(encoding="utf-8")

    assert "docs/operator-runbook.md" in readme
    assert "docs/operator-runbook.md" in deploy
    assert "operator-runbook.md" in deployment
    assert (ROOT / "docs" / "operator-runbook.md").is_file()
    assert "docs/mcp-client-integration.md" in readme
    assert "mcp-client-integration.md" in runbook
    assert (ROOT / "docs" / "mcp-client-integration.md").is_file()


def test_checkout_verification_pins_uv_browser_and_hermes_lock_before_tests() -> None:
    paths = (
        ROOT / "README.md",
        ROOT / "docs" / "deployment.md",
        ROOT / "docs" / "operator-runbook.md",
    )
    for path in paths:
        document = path.read_text(encoding="utf-8")
        assert "pipx install 'uv==0.11.28'" in document
        assert "https://docs.astral.sh/uv/getting-started/installation/" in document
        assert 'UV_VERSION="$(uv --version)"' in document
        assert '"uv 0.11.28"|"uv 0.11.28 "*' in document
        sync = document.index("uv sync --frozen")
        runtime_lock = document.index("uv lock --check --project deploy/hermes/runtime")
        browser = document.index("uv run playwright install --with-deps chromium")
        tests = document.index("uv run pytest -q")
        assert sync < runtime_lock < browser < tests


def test_hermes_references_are_bound_to_the_locked_release() -> None:
    paths = (
        ROOT / "docs" / "operator-runbook.md",
        ROOT / "deploy" / "hermes" / "README.md",
    )
    documents = [path.read_text(encoding="utf-8") for path in paths]
    combined = "\n".join(documents)

    assert "github.com/NousResearch/hermes-agent/blob/main/" not in combined
    assert combined.count("github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/") == 7
    assert "uv lock --check --project deploy/hermes/runtime" in documents[1]


def test_provider_neutral_client_guide_preserves_transport_and_safety_contract() -> None:
    path = ROOT / "docs" / "mcp-client-integration.md"
    document = path.read_text(encoding="utf-8")
    normalized_document = " ".join(document.split())

    example_match = re.search(r"```yaml\n(?P<body>.*?)\n```", document, re.DOTALL)
    assert example_match is not None
    servers = yaml.safe_load(example_match.group("body"))["servers"]
    aliases = {
        "signet_fastmail": "fastmail",
        "signet_whatsapp": "whatsapp",
        "signet_approvals": "approvals",
    }
    assert set(servers) == set(aliases)
    for name, alias in aliases.items():
        assert servers[name] == {
            "transport": "streamable-http",
            "url": f"http://127.0.0.1:8789/mcp/{alias}",
            "headers": {"Authorization": "Bearer ${SIGNET_MCP_CALLER_TOKEN}"},
        }
    for expected in (
        "streamable-http",
        'Authorization: "Bearer ${SIGNET_MCP_CALLER_TOKEN}"',
        "client-local server names",
        "pending_approval",
        "check_approval_status",
        "list_pending_approvals",
        "outcome_unknown",
        "Never automatically resubmit",
        "no trailing slash",
        "must not forward `Authorization` across a redirect",
        "unauthenticated MCP access returns `401`",
        "no direct provider MCP route",
        "Live provider deployment | None shipped",
    ):
        assert expected in normalized_document
    assert re.search(r"fake:sgt_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}", document) is None
    assert re.search(r"(?<!fake:)sgt_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}", document) is None


def test_demo_hermes_profile_is_loopback_fake_scoped_and_restrictive() -> None:
    path = ROOT / "deploy" / "hermes" / "demo-profile.mcp.yaml.example"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    servers = document["mcp_servers"]

    assert set(servers) == {
        "signet_demo_fastmail",
        "signet_demo_whatsapp",
        "signet_demo_approvals",
    }
    aliases = {
        "signet_demo_fastmail": "fastmail",
        "signet_demo_whatsapp": "whatsapp",
        "signet_demo_approvals": "approvals",
    }
    for name, alias in aliases.items():
        server = servers[name]
        assert server == {
            "url": f"http://127.0.0.1:8789/mcp/{alias}",
            "headers": {"Authorization": "Bearer ${SIGNET_DEMO_MCP_CALLER_TOKEN}"},
            "enabled": True,
            "connect_timeout": 10,
            "timeout": 120,
            "supports_parallel_tool_calls": False,
            "tools": {"resources": False, "prompts": False},
            "sampling": {"enabled": False},
        }
    serialized = path.read_text(encoding="utf-8")
    assert "sgt_" not in serialized
    assert "fastmail.com" not in serialized
    assert "wacli" not in serialized


def test_hermes_runtime_is_fully_locked_and_overrides_vulnerable_upstream_pins() -> None:
    runtime = ROOT / "deploy" / "hermes" / "runtime"
    project = tomllib.loads((runtime / "pyproject.toml").read_text(encoding="utf-8"))
    lock = (runtime / "uv.lock").read_text(encoding="utf-8")

    assert project["project"]["dependencies"] == ["hermes-agent[mcp]==0.18.2"]
    assert set(project["tool"]["uv"]["override-dependencies"]) == {
        "cryptography==48.0.1",
        "mcp==1.28.1",
        "pillow==12.3.0",
        "starlette==1.3.1",
    }
    for package, version in (
        ("cryptography", "48.0.1"),
        ("hermes-agent", "0.18.2"),
        ("mcp", "1.28.1"),
        ("pillow", "12.3.0"),
        ("starlette", "1.3.1"),
    ):
        assert f'name = "{package}"\nversion = "{version}"' in lock
    assert 'source = { registry = "https://pypi.org/simple" }' in lock
    assert 'hash = "sha256:' in lock


def test_distribution_name_does_not_collide_with_signet_package() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))

    assert project["project"]["name"] == "signet-gateway"
    assert set(project["project"]["classifiers"]) >= {
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
    }
    declared: dict[str, str] = {}
    for requirement in project["project"]["dependencies"]:
        match = re.fullmatch(
            r"(?P<name>[A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?"
            r"==(?P<version>[^; ]+)(?:; .+)?",
            requirement,
        )
        assert match is not None, requirement
        declared[match.group("name").lower().replace("_", "-")] = match.group("version")

    packages_by_name: dict[str, list[dict[str, object]]] = {}
    locked_versions: dict[str, set[str]] = {}
    for package in lock["package"]:
        name = str(package["name"])
        packages_by_name.setdefault(name, []).append(package)
        if "version" in package:
            locked_versions.setdefault(name, set()).add(str(package["version"]))

    root = next(package for package in lock["package"] if package["name"] == "signet-gateway")
    pending = list(root["dependencies"])
    runtime_closure: set[str] = set()
    while pending:
        dependency = pending.pop()
        marker = str(dependency.get("marker", ""))
        if marker == "sys_platform == 'win32'":
            continue
        name = str(dependency["name"])
        if name in runtime_closure:
            continue
        runtime_closure.add(name)
        for package in packages_by_name[name]:
            pending.extend(package.get("dependencies", []))

    assert set(declared) == runtime_closure
    for name, version in declared.items():
        assert locked_versions[name] == {version}
    for requirement in project["build-system"]["requires"]:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[^; ]+", requirement)
    assert project["project"]["scripts"] == {"signet": "signet.app:main"}
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/signet"]


def test_operator_commands_use_shipped_entrypoints_and_exact_paths() -> None:
    runbook = (ROOT / "docs" / "operator-runbook.md").read_text(encoding="utf-8")

    for command in (
        "uv sync --frozen",
        "uv run signet --help",
        'SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1',
        "export SIGNET_HOME",
        'export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"',
        'uv run signet demo init --data-dir "$SIGNET_DEMO_DIR"',
        'uv run signet demo smoke --data-dir "$SIGNET_DEMO_DIR"',
        'uv run signet demo serve --data-dir "$SIGNET_DEMO_DIR"',
        'uv run signet demo hermes-config --data-dir "$SIGNET_DEMO_DIR"',
        'uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field mcp-token',
        'uv run signet demo backup --data-dir "$SIGNET_DEMO_DIR"',
        'uv run signet demo restore --data-dir "$SIGNET_DEMO_DIR"',
        "uv run pytest -q",
        "uv run ruff check .",
        "uv run mypy",
        "http://127.0.0.1:8789/healthz",
        "http://127.0.0.1:8790/healthz",
        "http://127.0.0.1:8789/mcp/approvals",
        "hermes profile create signet-demo --no-alias --no-skills",
        "v0.16.0",
        "hermes-agent[mcp]==0.18.2",
        "hermes -p signet-demo config path",
        "hermes -p signet-demo config env-path",
        ': > "$SIGNET_DEMO_HERMES_CONFIG"',
        ': > "$SIGNET_DEMO_HERMES_ENV"',
        "hermes -p signet-demo config check",
        "hermes -p signet-demo mcp test signet_demo_fastmail",
        "hermes -p signet-demo mcp test signet_demo_whatsapp",
        "hermes -p signet-demo mcp test signet_demo_approvals",
        "hermes profile delete signet-demo -y",
    ):
        assert command in runbook

    assert "tailscale serve reset" not in runbook
    assert "$PWD/" not in runbook
    assert 'export SIGNET_REPO="$(pwd -P)"' not in runbook
    assert "kill -9" in runbook and "Do not use" in runbook
    assert "configure-demo-profile.py" in runbook
    assert (
        "if ! signet_demo_hermes profile create signet-demo --no-alias --no-skills; then"
    ) in runbook
    assert "refusing existing Hermes config" in runbook
    assert "refusing linked Hermes environment" in runbook
    assert "mcp.client.streamable_http" in runbook
    assert "Never substitute a global Hermes or independently upgrade the SDK" in runbook
    assert "Config version: 0 -> N (update available)" in runbook
    assert "Do not run `config migrate`" in runbook
    assert "BackupBundleManager" in runbook
    assert "no key enters argv or the environment" in runbook
    assert "--mcp-port 8889 --web-port 8890" in runbook
    assert "`4`, `3`, and `4` tools respectively" in runbook
    assert "Recent approvals and denials" in runbook
    assert "confirmation method and path" in runbook
    assert "active-backup rejection is not an incomplete purge" in runbook
    assert "storage or retention-worker failure after authorization" in " ".join(runbook.split())


def test_operator_paths_use_fail_closed_physical_roots() -> None:
    paths = (
        ROOT / "README.md",
        ROOT / "docs" / "deployment.md",
        ROOT / "docs" / "operator-runbook.md",
        ROOT / "deploy" / "hermes" / "README.md",
    )
    documents = [path.read_text(encoding="utf-8") for path in paths]

    for document in documents:
        assert "$PWD/" not in document
        assert '"$HOME/.hermes/services/signet' not in document
        assert "/var/operator-demo" not in document
        assert 'export SIGNET_DEMO_DIR="$SIGNET_REPO/' not in document
        assert (
            re.search(
                r'export [A-Z0-9_]+="\$\((?:pwd -P|cd "\$HOME" && pwd -P)',
                document,
            )
            is None
        )
    for document in documents:
        assert 'SIGNET_HOME="$(cd "$HOME" && pwd -P)"' in document
    for document in (documents[0], documents[1], documents[3]):
        assert 'export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"' in document
    for document in (documents[0], documents[2], documents[3]):
        assert 'export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"' in document

    assert 'SIGNET_REPO="$(pwd -P)"' not in documents[0]
    assert '"$SIGNET_REPO/deploy/hermes/configure-demo-profile.py"' in documents[2]
    assert '"$SIGNET_REPO/deploy/hermes/configure-demo-profile.py"' in documents[3]


def test_operator_procedures_fail_closed_on_intermediate_errors() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "operator-runbook.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    hermes = (ROOT / "deploy" / "hermes" / "README.md").read_text(encoding="utf-8")

    assert "set -e" in runbook
    assert "set -o pipefail" in runbook
    assert 'SIGNET_UNAUTHENTICATED_STATUS="$(' in runbook
    assert 'if test "$SIGNET_UNAUTHENTICATED_STATUS" != 401; then' in runbook
    assert "expected unauthenticated MCP status 401" in runbook
    assert "refusing existing demo backup artifacts" in runbook
    assert "refuses to reuse a stale bundle" in runbook
    assert "--connect-timeout 5 --max-time 10" in runbook
    assert "refusing non-absolute Hermes config path" in runbook
    assert "refusing canonical Hermes config path outside physical HOME" in runbook
    assert "refusing canonical Hermes environment path outside physical HOME" in runbook
    normalized_readme = " ".join(readme.replace("\\\n", " ").split())
    normalized_runbook = " ".join(runbook.replace("\\\n", " ").split())
    assert (
        'test ! -e "$SIGNET_DEMO_DIR" && test ! -L "$SIGNET_DEMO_DIR" || exit 1'
        in normalized_readme
    )
    assert (
        'test ! -e "$SIGNET_DEMO_BACKUP" && test ! -L "$SIGNET_DEMO_BACKUP" || exit 1'
        in normalized_runbook
    )
    assert (
        'test ! -e "$SIGNET_DEMO_RESTORE" && test ! -L "$SIGNET_DEMO_RESTORE" || exit 1'
        in normalized_runbook
    )

    assert "signet_rollback_launchd_install" in deployment
    assert "signet_finish_launchd_install" in deployment
    assert "signet_rollback_launchd_bootstrap" in deployment
    assert "signet_finish_launchd_bootstrap" in deployment
    assert "SIGNET_BOOTOUT_FAILED" in deployment
    assert "one or more launchd bootouts failed" in deployment
    assert "launchd install and rollback both failed" in deployment
    assert "refusing rollback of unexpected launchd destination" in deployment
    assert "refusing existing launchd label" in deployment
    assert "launchd bootstrap and rollback both failed" in deployment
    assert "SIGNET_LAUNCHD_DESTINATION_CANONICAL" in deployment
    assert "SIGNET_UNSAFE_LAUNCHD_DESTINATION" in deployment
    assert "signet_release_launchd_bootstrap_lock" in deployment
    assert "refusing concurrent or stale launchd bootstrap lock" in deployment
    assert "signet_release_launchd_install_lock" in deployment
    assert "refusing concurrent or stale launchd install lock" in deployment
    assert deployment.count("deploy/validate-private-paths.py") >= 5

    assert "set -o pipefail" in hermes
    assert "signet_demo_hermes -p signet-demo config check" in hermes
    assert '(umask 077 && set -o noclobber && : > "$SIGNET_DEMO_HERMES_CONFIG")' in hermes
    assert "refusing unexpected Hermes profile file paths" in hermes
    assert hermes.count("deploy/prepare-owned-directory.py") == 2
    assert hermes.index("deploy/prepare-owned-directory.py") < hermes.index(
        "signet_demo_hermes --version"
    )
    assert "do not invoke Hermes deletion" in hermes
    assert runbook.index("deploy/prepare-owned-directory.py") < runbook.index(
        "signet_demo_hermes --version"
    )
    for document in (hermes, runbook):
        assert 'env -i PATH="$PATH" HOME=' in document
        assert "uv run --locked --isolated --no-config" in document
        assert "--exclude-newer 2026-07-09T00:00:00Z" in document
        assert "--no-env-file --no-sources --no-build" in document
        assert '--project "$SIGNET_REPO/deploy/hermes/runtime"' in document
        assert document.count("--private-tree") >= 2
        assert "same-filesystem bind mount" in document
        assert "process running as the same UID" in document
        assert "retry the complete checked transaction" in document
    assert "signet_reviewed_live_hermes" in hermes
    assert "never substitute a raw global" in deployment
    assert "do not invoke another Hermes command" in runbook
    assert '"$SIGNET_REPO/deploy/hermes/configure-disabled-profile.py"' in deployment
    assert '"$SIGNET_REPO/deploy/hermes/configure-disabled-profile.py"' in hermes


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_operator_console_blocks_parse_in_bash_and_zsh(shell_name: str) -> None:
    shell = _shell_or_skip(shell_name)

    for path in OPERATOR_CONSOLE_PATHS:
        blocks = _console_blocks(path)
        for index, block in enumerate(blocks, start=1):
            result = subprocess.run(
                [shell, "-n"],
                check=False,
                input=block,
                text=True,
                capture_output=True,
            )
            assert result.returncode == 0, (
                f"{shell_name} rejected console block {index} in {path}: {result.stderr}"
            )


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_existence_guard_stops_on_existing_path(shell_name: str, tmp_path: Path) -> None:
    shell = _shell_or_skip(shell_name)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    target = home / ".signet-fake-demo"
    target.write_text("do not replace\n", encoding="utf-8")
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    marker = tmp_path / "uv-was-called"
    uv_stub = stub_dir / "uv"
    uv_stub.write_text(
        '#!/bin/sh\n: > "$SIGNET_GUARD_MARKER"\n',
        encoding="utf-8",
    )
    uv_stub.chmod(0o700)
    block = _console_block_containing(
        ROOT / "README.md", 'export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"'
    )
    result = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_GUARD_MARKER": str(marker),
        },
        timeout=10,
    )

    assert result.returncode != 0
    assert not marker.exists()
    assert target.read_text(encoding="utf-8") == "do not replace\n"


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
@pytest.mark.parametrize(
    "document_path",
    (
        ROOT / "docs" / "operator-runbook.md",
        ROOT / "deploy" / "hermes" / "README.md",
    ),
)
def test_documented_hermes_paths_are_canonical_and_created_exclusively(
    shell_name: str, document_path: Path, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    _write_hermes_uv_stub(stub_dir)
    block = _console_block_containing(document_path, "SIGNET_DEMO_HERMES_PARENT")

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    dedicated_home = home / ".signet-fake-hermes-home"
    root = dedicated_home / ".hermes"
    profile = root / "profiles" / "signet-demo"
    config = profile / "config.yaml"
    env_file = profile / ".env"
    create_marker = dedicated_home / ".hermes-create-called"
    hostile_home = tmp_path / "hostile-hermes-home"
    environment = {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
        "HERMES_HOME": str(hostile_home),
        "HERMES_MANAGED_DIR": str(tmp_path / "hostile-managed"),
        "UV_INDEX": "http://127.0.0.1:9/simple",
        "UV_FIND_LINKS": str(tmp_path / "hostile-links"),
        "UV_OVERRIDE": str(tmp_path / "hostile-overrides.txt"),
    }
    created = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment,
        cwd=ROOT,
        timeout=10,
    )
    assert created.returncode == 0, created
    assert create_marker.is_file()
    assert config.read_bytes() == b""
    assert env_file.read_bytes() == HERMES_SEEDED_ENV
    assert config.stat().st_mode & 0o777 == 0o600
    assert env_file.stat().st_mode & 0o777 == 0o600
    assert (root / ".env").read_bytes() == b""
    assert (root / ".update_check").stat().st_mode & 0o777 == 0o600
    assert (root / "logs" / "agent.log").stat().st_mode & 0o777 == 0o600
    for name in (
        "audio_cache",
        "cron",
        "home",
        "hooks",
        "image_cache",
        "logs",
        "memories",
        "pairing",
        "plans",
        "sessions",
        "skills",
        "skins",
        "workspace",
    ):
        assert (profile / name).stat().st_mode & 0o777 == 0o700
    for name in (".no-bundled-skills", "SOUL.md"):
        assert (profile / name).stat().st_mode & 0o777 == 0o600
    assert not hostile_home.exists()

    config.write_text("preserve existing config\n", encoding="utf-8")
    create_marker.unlink()
    refused_existing = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment,
        cwd=ROOT,
        timeout=10,
    )
    assert refused_existing.returncode != 0, refused_existing
    assert not create_marker.exists()
    assert config.read_text(encoding="utf-8") == "preserve existing config\n"

    linked_home = tmp_path / "linked-home"
    linked_home.mkdir(mode=0o700)
    outside_hermes = tmp_path / "outside-hermes"
    outside_hermes.mkdir(mode=0o700)
    linked_profile = outside_hermes / ".hermes" / "profiles" / "signet-demo"
    (linked_home / ".signet-fake-hermes-home").symlink_to(outside_hermes, target_is_directory=True)
    linked_environment = {
        **environment,
        "HOME": str(linked_home),
    }
    refused_link = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=linked_environment,
        cwd=ROOT,
        timeout=10,
    )
    assert refused_link.returncode != 0, refused_link
    assert not create_marker.exists()
    assert not (linked_profile / "config.yaml").exists()
    assert not (linked_profile / ".env").exists()

    unsafe_home = tmp_path / "unsafe-home"
    unsafe_home.mkdir(mode=0o700)
    unsafe_home.chmod(0o777)
    unsafe_profile = (
        unsafe_home / ".signet-fake-hermes-home" / ".hermes" / "profiles" / "signet-demo"
    )
    unsafe_environment = {
        **environment,
        "HOME": str(unsafe_home),
    }
    refused_writable_ancestor = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=unsafe_environment,
        cwd=ROOT,
        timeout=10,
    )
    assert refused_writable_ancestor.returncode != 0, refused_writable_ancestor
    assert not create_marker.exists()
    assert not (unsafe_profile / "config.yaml").exists()
    assert not (unsafe_profile / ".env").exists()

    create_marker.unlink(missing_ok=True)
    misreported_home = tmp_path / "misreported-home"
    misreported_home.mkdir(mode=0o700)
    misreported_dedicated = misreported_home / ".signet-fake-hermes-home"
    misreported_dedicated.mkdir(mode=0o700)
    (misreported_dedicated / ".misreport").touch(mode=0o600)
    expected_profile = misreported_dedicated / ".hermes" / "profiles" / "signet-demo"
    misreported_profile = misreported_dedicated / ".hermes" / "other" / "signet-demo"
    misreported = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **environment,
            "HOME": str(misreported_home),
        },
        cwd=ROOT,
        timeout=10,
    )
    assert misreported.returncode != 0, misreported
    assert (misreported_dedicated / ".hermes-create-called").is_file()
    assert expected_profile.is_dir()
    assert not (misreported_profile / "config.yaml").exists()
    assert not (misreported_profile / ".env").exists()

    poisoned_home = tmp_path / "poisoned-home"
    poisoned_root = poisoned_home / ".signet-fake-hermes-home" / ".hermes"
    (poisoned_root / "profiles").mkdir(parents=True, mode=0o700)
    poisoned_home.chmod(0o700)
    (poisoned_root / ".env").write_text("UNTRUSTED=1\n", encoding="utf-8")
    (poisoned_root / ".env").chmod(0o600)
    poisoned = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={**environment, "HOME": str(poisoned_home)},
        cwd=ROOT,
        timeout=10,
    )
    assert poisoned.returncode != 0, poisoned
    assert not (poisoned_home / ".signet-fake-hermes-home" / ".hermes-create-called").exists()


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_hermes_cleanup_validates_exact_profile_before_delete(
    shell_name: str, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    _write_hermes_uv_stub(stub_dir)
    block = _console_block_containing(
        ROOT / "docs" / "operator-runbook.md", "SIGNET_CLEANUP_HERMES_CONFIG"
    )
    preparation_block = _console_block_containing(
        ROOT / "docs" / "operator-runbook.md", "SIGNET_DEMO_HERMES_PARENT"
    )

    def environment_for(home: Path) -> dict[str, str]:
        return {
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "HERMES_HOME": str(tmp_path / "hostile-hermes-home"),
            "HERMES_MANAGED_DIR": str(tmp_path / "hostile-managed"),
            "UV_INDEX": "http://127.0.0.1:9/simple",
        }

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    dedicated_home = home / ".signet-fake-hermes-home"
    root = dedicated_home / ".hermes"
    profile = root / "profiles" / "signet-demo"
    profile.mkdir(parents=True, mode=0o700)
    (root / ".env").write_bytes(b"")
    (root / ".env").chmod(0o600)
    (profile / "config.yaml").write_text("demo\n", encoding="utf-8")
    (profile / ".env").write_text("fake\n", encoding="utf-8")
    (profile / "config.yaml").chmod(0o600)
    (profile / ".env").chmod(0o600)
    result = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment_for(home),
        cwd=ROOT,
        timeout=10,
    )
    assert result.returncode == 0, result
    delete_marker = dedicated_home / ".hermes-delete-called"
    assert delete_marker.is_file()
    assert not profile.exists()
    assert (root / ".update_check").is_file()

    rerun = subprocess.run(
        [shell, "-f"],
        check=False,
        input=preparation_block,
        text=True,
        capture_output=True,
        env=environment_for(home),
        cwd=ROOT,
        timeout=10,
    )
    assert rerun.returncode == 0, rerun
    assert profile.is_dir()
    assert (profile / "config.yaml").stat().st_mode & 0o777 == 0o600
    assert (profile / ".env").stat().st_mode & 0o777 == 0o600

    linked_home = tmp_path / "linked-home-cleanup"
    linked_home.mkdir(mode=0o700)
    outside = tmp_path / "outside-cleanup"
    linked_root = outside / ".hermes"
    linked_profile = linked_root / "profiles" / "signet-demo"
    linked_profile.mkdir(parents=True, mode=0o700)
    (linked_root / ".env").write_bytes(b"")
    (linked_root / ".env").chmod(0o600)
    (linked_home / ".signet-fake-hermes-home").symlink_to(outside, target_is_directory=True)
    refused_link = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment_for(linked_home),
        cwd=ROOT,
        timeout=10,
    )
    assert refused_link.returncode != 0, refused_link
    assert not (outside / ".hermes-delete-called").exists()
    assert linked_profile.is_dir()

    wrong_home = tmp_path / "wrong-reported-cleanup"
    wrong_home.mkdir(mode=0o700)
    wrong_dedicated = wrong_home / ".signet-fake-hermes-home"
    wrong_root = wrong_dedicated / ".hermes"
    expected_profile = wrong_root / "profiles" / "signet-demo"
    expected_profile.mkdir(parents=True, mode=0o700)
    (wrong_root / ".env").write_bytes(b"")
    (wrong_root / ".env").chmod(0o600)
    wrong_dedicated.joinpath(".misreport").touch(mode=0o600)
    for name in ("config.yaml", ".env"):
        path = expected_profile / name
        path.write_text("fake-only\n", encoding="utf-8")
        path.chmod(0o600)
    refused_report = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment_for(wrong_home),
        cwd=ROOT,
        timeout=10,
    )
    assert refused_report.returncode != 0, refused_report
    assert not (wrong_dedicated / ".hermes-delete-called").exists()
    assert expected_profile.is_dir()

    mutated_home = tmp_path / "mutated-cleanup"
    mutated_home.mkdir(mode=0o700)
    mutated_dedicated = mutated_home / ".signet-fake-hermes-home"
    mutated_root = mutated_dedicated / ".hermes"
    mutated_profile = mutated_root / "profiles" / "signet-demo"
    mutated_profile.mkdir(parents=True, mode=0o700)
    (mutated_root / ".env").write_bytes(b"")
    (mutated_root / ".env").chmod(0o600)
    mutated_dedicated.joinpath(".unsafe-profile-mutation").touch(mode=0o600)
    for name in ("config.yaml", ".env"):
        selected = mutated_profile / name
        selected.write_text("fake-only\n", encoding="utf-8")
        selected.chmod(0o600)
    refused_mutation = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment_for(mutated_home),
        cwd=ROOT,
        timeout=10,
    )
    assert refused_mutation.returncode != 0, refused_mutation
    assert mutated_profile.joinpath("logs", "unsafe-after-path").is_file()
    assert not (mutated_dedicated / ".hermes-delete-called").exists()

    unexpected_home = tmp_path / "unexpected-cleanup"
    unexpected_home.mkdir(mode=0o700)
    unexpected_root = unexpected_home / ".signet-fake-hermes-home" / ".hermes"
    unexpected_profile = unexpected_root / "profiles" / "signet-demo"
    unexpected_profile.mkdir(parents=True, mode=0o700)
    (unexpected_root / ".env").write_bytes(b"")
    (unexpected_root / ".env").chmod(0o600)
    (unexpected_profile / "unrelated.txt").write_text("preserve\n", encoding="utf-8")
    (unexpected_profile / "unrelated.txt").chmod(0o644)
    refused_unsafe_tree = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment_for(unexpected_home),
        cwd=ROOT,
        timeout=10,
    )
    assert refused_unsafe_tree.returncode != 0, refused_unsafe_tree
    assert unexpected_profile.is_dir()
    assert not (unexpected_home / ".signet-fake-hermes-home" / ".hermes-delete-called").exists()


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_launchd_install_rolls_back_partial_copy(
    shell_name: str, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    real_install = shutil.which("install")
    if real_install is None:
        pytest.skip("install is not available")

    home = tmp_path / "home"
    (home / "Library").mkdir(parents=True, mode=0o700)
    review = home / ".hermes" / "services" / "signet" / "launchd-review"
    review.mkdir(parents=True, mode=0o700)
    for name in ("ai.hermes.signet.mcp.plist", "ai.hermes.signet.web.plist"):
        path = review / name
        path.write_text(f"reviewed {name}\n", encoding="utf-8")
        path.chmod(0o600)

    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    install_stub = stub_dir / "install"
    install_stub.write_text(
        """#!/bin/sh
if test "${4-}" = "$SIGNET_SIGNAL_INSTALL_DESTINATION"; then
  "$SIGNET_REAL_INSTALL" "$@"
  kill -TERM "$PPID"
  sleep 1
  exit 0
fi
if test "${4-}" = "$SIGNET_PAUSE_INSTALL_DESTINATION"; then
  "$SIGNET_REAL_INSTALL" "$@" || exit 1
  : > "$SIGNET_INSTALL_PAUSE_MARKER"
  while test ! -e "$SIGNET_INSTALL_PAUSE_GATE"; do
    sleep 0.1
  done
  exit 0
fi
if test "${4-}" = "$SIGNET_FAIL_INSTALL_DESTINATION"; then
  "$SIGNET_REAL_INSTALL" "$@"
  exit 41
fi
exec "$SIGNET_REAL_INSTALL" "$@"
""",
        encoding="utf-8",
    )
    install_stub.chmod(0o700)
    rm_stub = stub_dir / "rm"
    rm_stub.write_text(
        """#!/bin/sh
if test -n "${SIGNET_FAIL_RM_PATH-}" && test "${2-}" = "$SIGNET_FAIL_RM_PATH"; then
  exit 42
fi
exec /bin/rm "$@"
""",
        encoding="utf-8",
    )
    rm_stub.chmod(0o700)
    destination = home / "Library" / "LaunchAgents"
    block = _console_block_containing(
        ROOT / "docs" / "deployment.md", "SIGNET_LAUNCHD_INSTALL_COMMITTED"
    )
    result = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": str(destination / "ai.hermes.signet.web.plist"),
            "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
        },
        cwd=ROOT,
        timeout=10,
    )

    assert result.returncode != 0, result
    assert not (destination / "ai.hermes.signet.mcp.plist").exists()
    assert not (destination / "ai.hermes.signet.web.plist").exists()
    install_lock = destination / ".ai.hermes.signet.install.lock"
    assert not install_lock.exists()

    rollback_failed = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": str(destination / "ai.hermes.signet.web.plist"),
            "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
            "SIGNET_FAIL_RM_PATH": str(destination / "ai.hermes.signet.mcp.plist"),
        },
        cwd=ROOT,
        timeout=10,
    )
    assert rollback_failed.returncode != 0, rollback_failed
    assert "launchd install and rollback both failed" in rollback_failed.stderr
    assert (destination / "ai.hermes.signet.mcp.plist").is_file()
    assert not (destination / "ai.hermes.signet.web.plist").exists()
    assert not install_lock.exists()
    (destination / "ai.hermes.signet.mcp.plist").unlink()

    interrupted = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": "",
            "SIGNET_SIGNAL_INSTALL_DESTINATION": str(destination / "ai.hermes.signet.mcp.plist"),
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
        },
        cwd=ROOT,
        timeout=10,
    )
    assert interrupted.returncode != 0, interrupted
    assert not (destination / "ai.hermes.signet.mcp.plist").exists()
    assert not (destination / "ai.hermes.signet.web.plist").exists()
    assert not install_lock.exists()

    succeeded = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": "",
            "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
        },
        cwd=ROOT,
        timeout=10,
    )
    assert succeeded.returncode == 0, succeeded
    assert not install_lock.exists()
    for name in ("ai.hermes.signet.mcp.plist", "ai.hermes.signet.web.plist"):
        installed = destination / name
        assert installed.read_text(encoding="utf-8") == f"reviewed {name}\n"
        assert installed.stat().st_mode & 0o777 == 0o600
        installed.unlink()

    cleanup_failed = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": "",
            "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
            "SIGNET_FAIL_RM_PATH": str(install_lock),
        },
        cwd=ROOT,
        timeout=10,
    )
    assert cleanup_failed.returncode != 0, cleanup_failed
    assert "launchd install lock cleanup failed" in cleanup_failed.stderr
    assert install_lock.is_file()
    for name in ("ai.hermes.signet.mcp.plist", "ai.hermes.signet.web.plist"):
        (destination / name).unlink()
    install_lock.unlink()

    install_lock.write_text("stale-lock-owned-by-another-run\n", encoding="utf-8")
    install_lock.chmod(0o600)
    refused_stale_lock = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": "",
            "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
        },
        cwd=ROOT,
        timeout=10,
    )
    assert refused_stale_lock.returncode != 0, refused_stale_lock
    assert install_lock.read_text(encoding="utf-8") == ("stale-lock-owned-by-another-run\n")
    assert not (destination / "ai.hermes.signet.mcp.plist").exists()
    assert not (destination / "ai.hermes.signet.web.plist").exists()
    install_lock.unlink()

    destination.rmdir()
    outside = tmp_path / "outside-launch-agents"
    outside.mkdir()
    destination.symlink_to(outside, target_is_directory=True)
    linked = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": "",
            "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
        },
        cwd=ROOT,
        timeout=10,
    )
    assert linked.returncode != 0, linked
    assert destination.is_symlink()
    assert list(outside.iterdir()) == []

    unsafe_home = tmp_path / "unsafe-launchd-home"
    unsafe_library = unsafe_home / "Library"
    unsafe_library.mkdir(parents=True, mode=0o700)
    unsafe_review = unsafe_home / ".hermes" / "services" / "signet" / "launchd-review"
    unsafe_review.mkdir(parents=True, mode=0o700)
    for name in ("ai.hermes.signet.mcp.plist", "ai.hermes.signet.web.plist"):
        path = unsafe_review / name
        path.write_text(f"reviewed {name}\n", encoding="utf-8")
        path.chmod(0o600)
    unsafe_home.chmod(0o777)
    refused_writable_ancestor = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(unsafe_home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_INSTALL": real_install,
            "SIGNET_FAIL_INSTALL_DESTINATION": "",
            "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
            "SIGNET_PAUSE_INSTALL_DESTINATION": "",
        },
        cwd=ROOT,
        timeout=10,
    )
    assert refused_writable_ancestor.returncode != 0, refused_writable_ancestor
    assert not (unsafe_library / "LaunchAgents").exists()


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_launchd_install_serializes_concurrent_invocations(
    shell_name: str, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    real_install = shutil.which("install")
    if real_install is None:
        pytest.skip("install is not available")

    home = tmp_path / "home"
    (home / "Library").mkdir(parents=True, mode=0o700)
    review = home / ".hermes" / "services" / "signet" / "launchd-review"
    review.mkdir(parents=True, mode=0o700)
    names = ("ai.hermes.signet.mcp.plist", "ai.hermes.signet.web.plist")
    for name in names:
        path = review / name
        path.write_text(f"reviewed {name}\n", encoding="utf-8")
        path.chmod(0o600)

    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    install_stub = stub_dir / "install"
    install_stub.write_text(
        """#!/bin/sh
if test "${4-}" = "$SIGNET_PAUSE_INSTALL_DESTINATION"; then
  "$SIGNET_REAL_INSTALL" "$@" || exit 1
  : > "$SIGNET_INSTALL_PAUSE_MARKER"
  while test ! -e "$SIGNET_INSTALL_PAUSE_GATE"; do
    sleep 0.1
  done
  exit 0
fi
exec "$SIGNET_REAL_INSTALL" "$@"
""",
        encoding="utf-8",
    )
    install_stub.chmod(0o700)

    destination = home / "Library" / "LaunchAgents"
    marker = tmp_path / "first-copy-paused"
    gate = tmp_path / "release-first-copy"
    block = _console_block_containing(
        ROOT / "docs" / "deployment.md", "SIGNET_LAUNCHD_INSTALL_COMMITTED"
    )
    environment = {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
        "SIGNET_REAL_INSTALL": real_install,
        "SIGNET_FAIL_INSTALL_DESTINATION": "",
        "SIGNET_SIGNAL_INSTALL_DESTINATION": "",
        "SIGNET_PAUSE_INSTALL_DESTINATION": str(destination / "ai.hermes.signet.mcp.plist"),
        "SIGNET_INSTALL_PAUSE_MARKER": str(marker),
        "SIGNET_INSTALL_PAUSE_GATE": str(gate),
    }
    first = subprocess.Popen(
        [shell, "-f", "-c", block],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=ROOT,
    )
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            if first.poll() is not None:
                stdout, stderr = first.communicate()
                pytest.fail(f"first install exited before pause: {stdout}\n{stderr}")
            time.sleep(0.05)
        assert marker.is_file(), "first install never reached the pause boundary"

        second = subprocess.run(
            [shell, "-f"],
            check=False,
            input=block,
            text=True,
            capture_output=True,
            env=environment,
            cwd=ROOT,
            timeout=10,
        )
        assert second.returncode != 0, second
        assert "refusing concurrent or stale launchd install lock" in second.stderr
    finally:
        gate.touch()

    first_stdout, first_stderr = first.communicate(timeout=10)
    assert first.returncode == 0, (first_stdout, first_stderr)
    for name in names:
        installed = destination / name
        assert installed.read_text(encoding="utf-8") == f"reviewed {name}\n"
        assert installed.stat().st_mode & 0o777 == 0o600
    assert not (destination / ".ai.hermes.signet.install.lock").exists()


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_launchd_bootstrap_rolls_back_only_transaction_labels(
    shell_name: str, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    launch_agents = home / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True, mode=0o700)
    for name in ("ai.hermes.signet.mcp.plist", "ai.hermes.signet.web.plist"):
        path = launch_agents / name
        path.write_text(f"reviewed {name}\n", encoding="utf-8")
        path.chmod(0o600)
    bootstrap_lock = launch_agents / ".ai.hermes.signet.bootstrap.lock"
    state = tmp_path / "launchctl-state"
    state.mkdir()
    bootout_log = tmp_path / "bootout.log"
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    launchctl_stub = stub_dir / "launchctl"
    launchctl_stub.write_text(
        """#!/bin/sh
action="$1"
target="${2-}"
case "$action" in
  print)
    test -f "$SIGNET_LAUNCHCTL_STATE/${target##*/}"
    ;;
  bootstrap)
    plist="${3##*/}"
    label="${plist%.plist}"
    : > "$SIGNET_LAUNCHCTL_STATE/$label"
    if test "$label" = "$SIGNET_SIGNAL_BOOTSTRAP_LABEL"; then
      kill -TERM "$PPID"
      sleep 1
      exit 0
    fi
    if test "$label" = "ai.hermes.signet.web" && \
       test "$SIGNET_FAIL_WEB_BOOTSTRAP" -eq 1; then
      exit 42
    fi
    ;;
  bootout)
    label="${target##*/}"
    rm -f "$SIGNET_LAUNCHCTL_STATE/$label"
    printf '%s\\n' "$label" >> "$SIGNET_BOOTOUT_LOG"
    ;;
  *) exit 64 ;;
esac
""",
        encoding="utf-8",
    )
    launchctl_stub.chmod(0o700)
    rm_stub = stub_dir / "rm"
    rm_stub.write_text(
        """#!/bin/sh
if test -n "${SIGNET_FAIL_RM_PATH-}" && test "${2-}" = "$SIGNET_FAIL_RM_PATH"; then
  exit 42
fi
exec /bin/rm "$@"
""",
        encoding="utf-8",
    )
    rm_stub.chmod(0o700)
    block = _console_block_containing(
        ROOT / "docs" / "deployment.md", "SIGNET_LAUNCHD_BOOTSTRAP_COMMITTED"
    )
    environment = {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
        "SIGNET_LAUNCHCTL_STATE": str(state),
        "SIGNET_BOOTOUT_LOG": str(bootout_log),
        "SIGNET_SIGNAL_BOOTSTRAP_LABEL": "",
        "SIGNET_FAIL_WEB_BOOTSTRAP": "1",
    }

    partial = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment,
        cwd=ROOT,
        timeout=10,
    )
    assert partial.returncode != 0, partial
    assert list(state.iterdir()) == []
    assert set(bootout_log.read_text(encoding="utf-8").splitlines()) == {
        "ai.hermes.signet.mcp",
        "ai.hermes.signet.web",
    }
    assert not bootstrap_lock.exists()

    bootout_log.unlink()
    interrupted_environment = {
        **environment,
        "SIGNET_SIGNAL_BOOTSTRAP_LABEL": "ai.hermes.signet.mcp",
    }
    interrupted = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=interrupted_environment,
        cwd=ROOT,
        timeout=10,
    )
    assert interrupted.returncode != 0, interrupted
    assert list(state.iterdir()) == []
    assert bootout_log.read_text(encoding="utf-8").splitlines() == ["ai.hermes.signet.mcp"]
    assert not bootstrap_lock.exists()

    bootout_log.unlink()
    bootstrap_lock.write_text("stale-lock-owned-by-another-run\n", encoding="utf-8")
    bootstrap_lock.chmod(0o600)
    refused_stale_lock = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment,
        cwd=ROOT,
        timeout=10,
    )
    assert refused_stale_lock.returncode != 0, refused_stale_lock
    assert bootstrap_lock.read_text(encoding="utf-8") == "stale-lock-owned-by-another-run\n"
    assert list(state.iterdir()) == []
    assert not bootout_log.exists()
    bootstrap_lock.unlink()

    preexisting = state / "ai.hermes.signet.mcp"
    preexisting.write_text("pre-existing\n", encoding="utf-8")
    refused = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env=environment,
        cwd=ROOT,
        timeout=10,
    )
    assert refused.returncode != 0, refused
    assert preexisting.read_text(encoding="utf-8") == "pre-existing\n"
    assert not bootout_log.exists()
    assert not bootstrap_lock.exists()

    preexisting.unlink()
    cleanup_failed = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **environment,
            "SIGNET_FAIL_WEB_BOOTSTRAP": "0",
            "SIGNET_FAIL_RM_PATH": str(bootstrap_lock),
        },
        cwd=ROOT,
        timeout=10,
    )
    assert cleanup_failed.returncode != 0, cleanup_failed
    assert "launchd bootstrap lock cleanup failed" in cleanup_failed.stderr
    assert bootstrap_lock.is_file()
    assert {path.name for path in state.iterdir()} == {
        "ai.hermes.signet.mcp",
        "ai.hermes.signet.web",
    }
    bootstrap_lock.unlink()
    for path in tuple(state.iterdir()):
        path.unlink()

    succeeded = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={**environment, "SIGNET_FAIL_WEB_BOOTSTRAP": "0"},
        cwd=ROOT,
        timeout=10,
    )
    assert succeeded.returncode == 0, succeeded
    assert {path.name for path in state.iterdir()} == {
        "ai.hermes.signet.mcp",
        "ai.hermes.signet.web",
    }
    assert not bootout_log.exists()
    assert not bootstrap_lock.exists()


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_stale_launchd_lock_recovery_only_removes_valid_exact_locks(
    shell_name: str, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    real_rm = shutil.which("rm")
    real_wc = shutil.which("wc")
    if real_rm is None or real_wc is None:
        pytest.skip("rm or wc is not available")
    stub_dir = tmp_path / "stale-lock-bin"
    stub_dir.mkdir()
    wc_stub = stub_dir / "wc"
    wc_stub.write_text(
        """#!/bin/sh
result="$("$SIGNET_REAL_WC" "$@")" || exit 1
if test -n "${SIGNET_MUTATE_STALE_LOCK-}" && \
   test ! -e "$SIGNET_WC_MUTATED_MARKER"; then
    printf '%064d\n' 1 > "$SIGNET_MUTATE_STALE_LOCK"
  : > "$SIGNET_WC_MUTATED_MARKER"
fi
printf '%s\n' "$result"
""",
        encoding="utf-8",
    )
    wc_stub.chmod(0o700)
    rm_stub = stub_dir / "rm"
    rm_stub.write_text(
        """#!/bin/sh
if test "${SIGNET_FAIL_STALE_RM-0}" = 1; then
  exit 42
fi
exec "$SIGNET_REAL_RM" "$@"
""",
        encoding="utf-8",
    )
    rm_stub.chmod(0o700)
    block = _console_block_containing(
        ROOT / "docs" / "deployment.md", "SIGNET_OBSERVED_STALE_LOCK_TOKEN"
    )

    def make_state(name: str) -> tuple[Path, Path, Path]:
        home = tmp_path / name
        destination = home / "Library" / "LaunchAgents"
        destination.mkdir(parents=True, mode=0o700)
        home.chmod(0o700)
        (home / "Library").chmod(0o700)
        destination.chmod(0o700)
        lock = destination / ".ai.hermes.signet.install.lock"
        lock.write_text(f"{'a' * 64}\n", encoding="ascii")
        lock.chmod(0o600)
        return home, destination, lock

    def run(home: Path, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "SIGNET_REAL_RM": real_rm,
            "SIGNET_REAL_WC": real_wc,
        }
        if extra is not None:
            environment.update(extra)
        return subprocess.run(
            [shell, "-f"],
            check=False,
            input=block,
            text=True,
            capture_output=True,
            env=environment,
            cwd=ROOT,
            timeout=10,
        )

    success_home, _success_destination, success_lock = make_state("stale-success")
    success_bootstrap_lock = success_lock.with_name(".ai.hermes.signet.bootstrap.lock")
    success_bootstrap_lock.write_text(f"{'b' * 64}\n", encoding="ascii")
    success_bootstrap_lock.chmod(0o600)
    success = run(success_home)
    assert success.returncode == 0, success
    assert not success_lock.exists()
    assert not success_bootstrap_lock.exists()

    plist_home, plist_destination, plist_lock = make_state("stale-plist")
    plist = plist_destination / "ai.hermes.signet.mcp.plist"
    plist.write_text("existing\n", encoding="utf-8")
    plist.chmod(0o600)
    recovered_with_plist = run(plist_home)
    assert recovered_with_plist.returncode == 0, recovered_with_plist
    assert not plist_lock.exists()
    assert plist.read_text(encoding="utf-8") == "existing\n"

    linked_home, linked_destination, linked_lock = make_state("stale-linked")
    linked_lock.unlink()
    outside = tmp_path / "stale-outside"
    outside.write_text(f"{'a' * 64}\n", encoding="ascii")
    outside.chmod(0o600)
    linked_lock.symlink_to(outside)
    refused_link = run(linked_home)
    assert refused_link.returncode != 0, refused_link
    assert linked_lock.is_symlink()
    assert linked_destination.is_dir()

    mode_home, _mode_destination, mode_lock = make_state("stale-mode")
    mode_lock.chmod(0o644)
    refused_mode = run(mode_home)
    assert refused_mode.returncode != 0, refused_mode
    assert mode_lock.is_file()

    hardlink_home, _hardlink_destination, hardlink_lock = make_state("stale-hardlink")
    hardlink_peer = tmp_path / "stale-hardlink-peer"
    os.link(hardlink_lock, hardlink_peer)
    refused_hardlink = run(hardlink_home)
    assert refused_hardlink.returncode != 0, refused_hardlink
    assert hardlink_lock.is_file()

    changed_home, _changed_destination, changed_lock = make_state("stale-changed")
    refused_changed = run(
        changed_home,
        {
            "SIGNET_MUTATE_STALE_LOCK": str(changed_lock),
            "SIGNET_WC_MUTATED_MARKER": str(tmp_path / "wc-mutated"),
        },
    )
    assert refused_changed.returncode != 0, refused_changed
    assert changed_lock.is_file()

    trailing_home, _trailing_destination, trailing_lock = make_state("stale-trailing")
    trailing_lock.write_bytes(("c" * 64 + "\nTRAILING").encode("ascii"))
    refused_trailing = run(trailing_home)
    assert refused_trailing.returncode != 0, refused_trailing
    assert trailing_lock.is_file()

    rm_home, _rm_destination, rm_lock = make_state("stale-rm-failure")
    refused_rm = run(rm_home, {"SIGNET_FAIL_STALE_RM": "1"})
    assert refused_rm.returncode != 0, refused_rm
    assert rm_lock.is_file()


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_persistent_hermes_paths_are_created_exclusively(
    shell_name: str, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    _write_hermes_uv_stub(stub_dir)
    block = _console_block_containing(
        ROOT / "deploy" / "hermes" / "README.md", "SIGNET_DISABLED_HERMES_PARENT"
    )

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    service_config = home / ".hermes" / "services" / "signet" / "config"
    service_config.mkdir(parents=True, mode=0o700)
    dedicated_home = service_config.parent / "hermes-home"
    profile = dedicated_home / ".hermes" / "profiles" / "signet-disabled"
    config = profile / "config.yaml"
    env_file = profile / ".env"
    create_marker = dedicated_home / ".hermes-create-called"
    result = subprocess.run(
        [shell, "-f"],
        check=False,
        input=block,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "HERMES_HOME": str(tmp_path / "hostile-hermes-home"),
            "HERMES_MANAGED_DIR": str(tmp_path / "hostile-managed"),
            "UV_INDEX": "http://127.0.0.1:9/simple",
            "UV_FIND_LINKS": str(tmp_path / "hostile-links"),
        },
        cwd=ROOT,
        timeout=10,
    )

    assert result.returncode == 0, result
    assert create_marker.is_file()
    fragment = service_config / "disabled-profile.mcp.yaml"
    assert config.read_bytes() == b""
    assert env_file.read_bytes() == HERMES_SEEDED_ENV
    assert (
        fragment.read_bytes()
        == (ROOT / "deploy" / "hermes" / "disabled-profile.mcp.yaml.example").read_bytes()
    )
    for path in (config, env_file, fragment):
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("shell_name", ("bash", "zsh"))
def test_documented_persistent_hermes_recovery_is_checked_and_repeatable(
    shell_name: str, tmp_path: Path
) -> None:
    shell = _shell_or_skip(shell_name)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    _write_hermes_uv_stub(stub_dir)
    document = ROOT / "deploy" / "hermes" / "README.md"
    recovery_block = _console_block_containing(document, "SIGNET_RECOVERY_DISABLED_HERMES_CONFIG")
    preparation_block = _console_block_containing(document, "SIGNET_DISABLED_HERMES_PARENT")

    def environment_for(home: Path) -> dict[str, str]:
        return {
            **os.environ,
            "HOME": str(home),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "HERMES_HOME": str(tmp_path / "hostile-hermes-home"),
            "HERMES_MANAGED_DIR": str(tmp_path / "hostile-managed"),
            "UV_INDEX": "http://127.0.0.1:9/simple",
        }

    home = tmp_path / "persistent-recovery-home"
    home.mkdir(mode=0o700)
    service_root = home / ".hermes" / "services" / "signet"
    (service_root / "config").mkdir(parents=True, mode=0o700)
    dedicated_home = service_root / "hermes-home"
    root = dedicated_home / ".hermes"
    profile = root / "profiles" / "signet-disabled"
    profile.mkdir(parents=True, mode=0o700)
    (root / ".env").write_bytes(b"")
    (root / ".env").chmod(0o600)
    (profile / ".env").write_text("# seeded by Hermes\n", encoding="utf-8")
    (profile / ".env").chmod(0o600)

    recovered = subprocess.run(
        [shell, "-f"],
        check=False,
        input=recovery_block,
        text=True,
        capture_output=True,
        env=environment_for(home),
        cwd=ROOT,
        timeout=10,
    )
    assert recovered.returncode == 0, recovered
    assert (dedicated_home / ".hermes-delete-called").is_file()
    assert not profile.exists()

    prepared_again = subprocess.run(
        [shell, "-f"],
        check=False,
        input=preparation_block,
        text=True,
        capture_output=True,
        env=environment_for(home),
        cwd=ROOT,
        timeout=10,
    )
    assert prepared_again.returncode == 0, prepared_again
    assert profile.is_dir()
    assert (profile / "config.yaml").stat().st_mode & 0o777 == 0o600
    assert (profile / ".env").stat().st_mode & 0o777 == 0o600

    wrong_home = tmp_path / "persistent-wrong-report"
    wrong_home.mkdir(mode=0o700)
    wrong_root = wrong_home / ".hermes" / "services" / "signet" / "hermes-home" / ".hermes"
    wrong_profile = wrong_root / "profiles" / "signet-disabled"
    wrong_profile.mkdir(parents=True, mode=0o700)
    (wrong_root / ".env").write_bytes(b"")
    (wrong_root / ".env").chmod(0o600)
    wrong_root.parent.joinpath(".misreport").touch(mode=0o600)
    refused_report = subprocess.run(
        [shell, "-f"],
        check=False,
        input=recovery_block,
        text=True,
        capture_output=True,
        env=environment_for(wrong_home),
        cwd=ROOT,
        timeout=10,
    )
    assert refused_report.returncode != 0, refused_report
    assert wrong_profile.is_dir()
    assert not (wrong_root.parent / ".hermes-delete-called").exists()

    unexpected_home = tmp_path / "persistent-unexpected-entry"
    unexpected_home.mkdir(mode=0o700)
    unexpected_root = (
        unexpected_home / ".hermes" / "services" / "signet" / "hermes-home" / ".hermes"
    )
    unexpected_profile = unexpected_root / "profiles" / "signet-disabled"
    unexpected_profile.mkdir(parents=True, mode=0o700)
    (unexpected_root / ".env").write_bytes(b"")
    (unexpected_root / ".env").chmod(0o600)
    (unexpected_profile / "unrelated.txt").write_text("preserve\n", encoding="utf-8")
    (unexpected_profile / "unrelated.txt").chmod(0o644)
    refused_unsafe_tree = subprocess.run(
        [shell, "-f"],
        check=False,
        input=recovery_block,
        text=True,
        capture_output=True,
        env=environment_for(unexpected_home),
        cwd=ROOT,
        timeout=10,
    )
    assert refused_unsafe_tree.returncode != 0, refused_unsafe_tree
    assert unexpected_profile.is_dir()
    assert not (unexpected_root.parent / ".hermes-delete-called").exists()


def test_persistent_disabled_hermes_path_is_executable_and_single_profile() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    hermes = (ROOT / "deploy" / "hermes" / "README.md").read_text(encoding="utf-8")
    combined = "\n".join((readme, deployment, hermes))

    for expected in (
        "signet.deployment:create_mcp_app",
        "signet.deployment:create_web_app",
        "configure-disabled-profile.py",
        "SIGNET_DISABLED_MCP_CALLER_TOKEN",
        "set -o pipefail",
        '--namespace "profile:$SIGNET_DISABLED_PROFILE"',
        "signet_disabled_hermes profile create",
        "mcp test signet_disabled_approvals",
        "discover exactly five tools",
        "exactly one caller namespace",
        "no principal-add command",
    ):
        assert expected in combined

    assert "deployment.assembly:create_mcp_app" not in readme
    assert "deployment.assembly:create_web_app" not in readme
    assert (ROOT / "deploy" / "hermes" / "configure-disabled-profile.py").is_file()
    assert hermes.count("if ! signet_demo_hermes profile create") == 1
    assert hermes.count("if ! signet_disabled_hermes profile create") == 1


def test_launchd_guide_renders_then_lints_exact_private_outputs() -> None:
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")

    for expected in (
        "deploy/launchd/render-disabled-plists.py",
        '--signet-executable "$SIGNET_REPO/.venv/bin/signet"',
        '--config "$SIGNET_SERVICE_ROOT/config/disabled.json"',
        '--output-directory "$SIGNET_LAUNCHD_REVIEW"',
        'plutil -lint "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.mcp.plist"',
        'plutil -lint "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.web.plist"',
        "refusing existing launchd destination",
    ):
        assert expected in deployment

    assert "plutil -lint ./ai.hermes.signet.mcp.plist" not in deployment
    assert (ROOT / "deploy" / "launchd" / "render-disabled-plists.py").is_file()


def test_wacli_boundary_documents_descriptor_store_and_disabled_migration_gate() -> None:
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    deploy_readme = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
    boundary_path = ROOT / "docs" / "wacli-process-boundary.md"
    boundary = boundary_path.read_text(encoding="utf-8")
    normalized = " ".join(boundary.split())

    assert "wacli-process-boundary.md" in deployment
    assert "wacli-process-boundary.md" in deploy_readme
    for expected in (
        "--store /proc/self/fd/STORE_FD",
        "distinct direct children",
        "must be disjoint",
        "never inherited",
        "Re-pair",
        "no generic copy command",
        "macOS local-process activation blocker",
        "process_boundary_platform_unsupported",
        "must_not_dispatch",
        "live local-process activation is blocked",
    ):
        assert expected in normalized
    assert "cp -R" not in boundary
    assert "--account ACCOUNT" not in boundary


def test_operator_docs_do_not_claim_demo_or_live_readiness() -> None:
    paths = (
        ROOT / "README.md",
        ROOT / "docs" / "operator-runbook.md",
        ROOT / "deploy" / "README.md",
        ROOT / "deploy" / "hermes" / "README.md",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    assert "does not make a live deployment ready" in combined
    assert "not evidence" in combined
    assert "no-live" in combined.lower()
    assert "SIGNET_DEMO_CLI_TBD" not in combined
    assert "SIGNET_DEMO_BACKUP_CLI_TBD" not in combined
    assert "still being integrated" not in combined
    assert "still being assembled" not in combined
    assert "changes a Hermes profile" not in (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"(?<!\d)\d{6}(?!\d)", combined) is None
    assert "demo approvals server intentionally omits `approve_request`" in combined


def test_live_deployment_guide_does_not_misrepresent_demo_backup_as_live() -> None:
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")

    assert "There is no general or live `signet backup` shell command" in deployment
    assert "deliberately restricted to state marked" in deployment
    assert "they are not deployment commands" in deployment
    assert "not live profile editors" in deployment


def test_policy_guide_documents_shipped_durable_coordinators() -> None:
    policy_guide = (ROOT / "docs" / "policy-guide.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    approval_tools = (ROOT / "docs" / "mcp-approval-tools.md").read_text(encoding="utf-8")
    security_model = (ROOT / "docs" / "security-model.md").read_text(encoding="utf-8")
    normalized = " ".join(policy_guide.split())

    assert "`DurableSchemaRegistry`" in policy_guide
    assert "`SQLitePolicyPromotionBoundary`" in policy_guide
    assert "does not perform live discovery by itself" in normalized
    assert "not evidence that any live provider schema" in normalized
    assert "does not enroll a human proof or authorize a live policy change" in normalized
    assert "does not yet ship the concrete" not in policy_guide
    assert "does not yet provide a production durable policy coordinator" not in policy_guide
    assert "does not ship that concrete coordinator" not in approval_tools
    assert "requires a passkey for promotion" not in (
        policy_guide + approval_tools + security_model
    )
    assert "fresh passkey or TOTP confirmation" in approval_tools
    assert "`SQLitePolicyPromotionBoundary`" in approval_tools
    assert "`DurableSchemaRegistry.restore()`" in deployment


def test_private_directory_hardening_documents_platform_requirements() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    security = (ROOT / "docs" / "security-model.md").read_text(encoding="utf-8")

    assert "kernel-owned `/proc/self/fd`" in readme
    assert "mounted kernel procfs at `/proc/self/fd`" in deployment
    assert "already-held `O_PATH` descriptor" in security
    assert "parent-descriptor-relative `fchmodat`" in deployment
    assert "`AT_SYMLINK_NOFOLLOW`" in security
    assert "malicious same-user process" in security


def test_fake_quickstart_seeds_review_without_model_or_network() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "operator-runbook.md").read_text(encoding="utf-8")

    command = 'signet demo seed-request --data-dir "$SIGNET_DEMO_DIR"'
    assert command in readme
    assert runbook.count(command) >= 2
    assert "same gateway pipeline used by MCP" in runbook
    assert "makes no Hermes, model, network, or provider call" in runbook
    assert "must run while the server is stopped" in readme
