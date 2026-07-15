from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_operator_runbook_is_linked_from_entrypoint_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    deploy = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")

    assert "docs/operator-runbook.md" in readme
    assert "docs/operator-runbook.md" in deploy
    assert "operator-runbook.md" in deployment
    assert (ROOT / "docs" / "operator-runbook.md").is_file()


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


def test_operator_commands_use_shipped_entrypoints_and_exact_paths() -> None:
    runbook = (ROOT / "docs" / "operator-runbook.md").read_text(encoding="utf-8")

    for command in (
        "uv sync --frozen",
        "uv run signet --help",
        'export SIGNET_DEMO_DIR="$PWD/var/operator-demo"',
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
        "hermes-agent[mcp]==0.16.0",
        "hermes -p signet-demo config path",
        "hermes -p signet-demo config env-path",
        'install -m 0600 /dev/null "$SIGNET_DEMO_HERMES_CONFIG"',
        'install -m 0600 /dev/null "$SIGNET_DEMO_HERMES_ENV"',
        "hermes -p signet-demo config check",
        "hermes -p signet-demo mcp test signet_demo_fastmail",
        "hermes -p signet-demo mcp test signet_demo_whatsapp",
        "hermes -p signet-demo mcp test signet_demo_approvals",
        "hermes profile delete signet-demo -y",
    ):
        assert command in runbook

    assert "tailscale serve reset" not in runbook
    assert "kill -9" in runbook and "Do not use" in runbook
    assert "configure-demo-profile.py" in runbook
    assert "refusing to overwrite existing Hermes profile file" in runbook
    assert "mcp.client.streamable_http" in runbook
    assert "Do not independently upgrade the SDK" in runbook
    assert "Config version: 0 -> 27 (update available)" in runbook
    assert "Do not run `config migrate`" in runbook
    assert "BackupBundleManager" in runbook
    assert "no key enters argv or the environment" in runbook
    assert "--mcp-port 8889 --web-port 8890" in runbook


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
    assert re.search(r"(?<!\d)\d{6}(?!\d)", combined) is None
    assert "demo approvals server intentionally omits `approve_request`" in combined


def test_live_deployment_guide_does_not_misrepresent_demo_backup_as_live() -> None:
    deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")

    assert "There is no general or live `signet backup` shell command" in deployment
    assert "deliberately restricted to state marked" in deployment
    assert "they are not deployment commands" in deployment
    assert "not a live profile editor" in deployment


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
