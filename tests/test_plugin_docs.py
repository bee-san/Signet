from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEGRATIONS = ROOT / "docs" / "plugin-integrations.md"
READINESS = ROOT / "docs" / "plugin-readiness.md"
REFERENCES = ("fastmail", "telegram", "whatsapp")


def _normalized(document: str) -> str:
    return " ".join(document.split())


def test_plugin_guides_are_linked_from_readme_safety_and_development() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert readme.count("docs/plugin-integrations.md") >= 3
    assert readme.count("docs/plugin-readiness.md") >= 3
    assert INTEGRATIONS.is_file()
    assert READINESS.is_file()


def test_plugin_guide_records_the_exact_staged_cli_lifecycle() -> None:
    guide = INTEGRATIONS.read_text(encoding="utf-8")
    commands = (
        'signet plugin validate "$MANIFEST" --sha256 "$MANIFEST_SHA256"',
        'signet plugin install "$MANIFEST" --sha256 "$MANIFEST_SHA256"',
        "signet plugin list --database",
        "signet plugin show example.mail --database",
        "signet plugin disable example.mail --database",
        "signet connector configure",
        "--plugin example.mail",
        "--connector mail",
        "--alias example-mail-staged",
        "--config ./example-mail-connector.json",
        "signet connector discover example-mail-staged",
        "--fixture ./example-mail-tools-list.json",
        "--live-discovery",
        "--command-references ./reviewed-commands.json",
        "--command-references-sha256",
    )
    for command in commands:
        assert command in guide

    assert "Fixture discovery is the default" in guide
    assert "There is no connector `--sha256` flag" in guide
    assert "no `tools/call`, sampling, elicitation, resources, or prompts" in guide
    assert "does not alter an executable policy" in _normalized(
        READINESS.read_text(encoding="utf-8")
    )


def test_docs_separate_untrusted_evidence_from_fresh_human_conclusions() -> None:
    guide = INTEGRATIONS.read_text(encoding="utf-8")

    assert "MCP annotations supplied by the server. They are untrusted hints" in guide
    assert "Conservative name and schema heuristics" in guide
    assert "plugin's proposed effect profile" in guide
    assert "authenticated human's final effect profile" in guide
    assert "fresh existing passkey or TOTP ceremony" in guide
    for axis in (
        "mutation",
        "external_communication",
        "code_execution",
        "privilege_change",
        "open_world",
        "idempotent",
    ):
        assert axis in guide


def test_readiness_report_denies_dispatch_and_records_zero_reference_effects() -> None:
    report = READINESS.read_text(encoding="utf-8")

    assert "live_dispatch_enabled=false" in report
    for reference in REFERENCES:
        assert f"reference.{reference}.provider_effect_count=0" in report
    assert "No plugin path can issue MCP `tools/call`" in report
    assert "No manifest is fetched from a URL, Git repository" in report
    assert "No WhatsApp CLI is invoked directly" in report
    assert "provider-specific adapter" in report
