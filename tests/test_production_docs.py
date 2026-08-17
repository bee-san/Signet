from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from signet.app import _parser

ROOT = Path(__file__).resolve().parents[1]
USER_GUIDES = (
    ROOT / "README.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "setup.md",
    ROOT / "docs" / "setup-resume.md",
    ROOT / "docs" / "provider-setup.md",
    ROOT / "docs" / "health-and-doctor.md",
    ROOT / "docs" / "backup-and-restore.md",
    ROOT / "docs" / "upgrade-and-rollback.md",
    ROOT / "docs" / "uninstall.md",
    ROOT / "docs" / "recovery.md",
    ROOT / "docs" / "storage.md",
    ROOT / "docs" / "security.md",
    ROOT / "docs" / "troubleshooting.md",
)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]+\]\((?P<target>[^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(?P<text>.+?)\s*$", re.MULTILINE)
PLAN_ID = "a" * 64


def _document(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalized(document: str) -> str:
    return " ".join(document.lower().split())


def _heading_ids(document: str) -> set[str]:
    identifiers: set[str] = set()
    counts: dict[str, int] = {}
    for match in HEADING.finditer(document):
        text = re.sub(r"`([^`]*)`", r"\1", match.group("text")).strip().lower()
        slug = re.sub(r"[^a-z0-9 _-]", "", text)
        slug = re.sub(r"[ _]+", "-", slug).strip("-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        identifiers.add(slug if count == 0 else f"{slug}-{count}")
    return identifiers


def test_user_documentation_local_links_and_fragments_resolve() -> None:
    for source in USER_GUIDES:
        document = _document(source)
        for match in MARKDOWN_LINK.finditer(document):
            raw_target = match.group("target").strip().strip("<>")
            parsed = urlsplit(raw_target)
            if parsed.scheme or parsed.netloc:
                continue
            if not parsed.path:
                target_path = source
            else:
                target_path = (source.parent / unquote(parsed.path)).resolve()
            assert target_path.exists(), f"{source.relative_to(ROOT)} -> {raw_target}"
            if parsed.fragment and target_path.suffix.lower() == ".md":
                assert unquote(parsed.fragment) in _heading_ids(_document(target_path)), (
                    f"{source.relative_to(ROOT)} -> {raw_target}"
                )


def test_readme_leads_with_packaged_setup_before_development() -> None:
    readme = _document(ROOT / "README.md")
    quick_start = readme.index("## Production quick start")
    development = readme.index("## Development")

    assert quick_start < readme.index("pipx install 'signet-gateway==0.1.0'") < development
    assert quick_start < readme.index("signet setup") < development
    assert "does not require a source checkout" in readme[quick_start:development]
    assert "https://<tailscale-node-name>:8443/setup" in readme[quick_start:development]
    assert "macOS arm64" in readme[quick_start:development]
    assert "Linux x86_64" in readme[quick_start:development]
    assert "Linux arm64" in readme[quick_start:development]
    assert "pipx install signet-gateway\n" not in readme[quick_start:development]


def test_user_guides_cover_required_operator_topics() -> None:
    required = {
        "setup-resume.md": ("same setup command", "capability expired"),
        "provider-setup.md": ("Human-only and live", "one test"),
        "health-and-doctor.md": ("signet status", "signet doctor"),
        "backup-and-restore.md": ("signet backup", "signet restore"),
        "upgrade-and-rollback.md": ("signet upgrade", "no generic package rollback"),
        "uninstall.md": ("signet uninstall", "--purge"),
        "recovery.md": ("multiple named passkeys", "no self-service bypass"),
        "storage.md": ("4 GiB", "--data-root"),
        "security.md": ("approval_optimistic", "same operating-system user"),
        "troubleshooting.md": ("Tailscale", "Interrupted backup"),
    }
    for filename, phrases in required.items():
        document = _normalized(_document(ROOT / "docs" / filename))
        for phrase in phrases:
            assert phrase.lower() in document, f"{filename} is missing {phrase!r}"


def test_authenticator_and_policy_copy_preserve_security_semantics() -> None:
    corpus = "\n".join(_document(path) for path in USER_GUIDES)
    security = _document(ROOT / "docs" / "security.md")

    for phrase in (
        "multiple independently enrolled, named TOTP authenticators",
        "multiple named passkeys",
        "copying one seed",
        "password alone",
        "pending_approval",
        "real mutation remains pending",
        "not a selectable packaged-provider mode in 0.1",
        "virtualize_local",
        "same operating-system user",
    ):
        assert phrase.lower() in _normalized(corpus)
    assert security.index("`approval` is transparent") < security.index("`approval_optimistic`")


def test_live_provider_retry_and_upgrade_latest_are_not_misrepresented() -> None:
    provider = _normalized(_document(ROOT / "docs" / "provider-setup.md"))
    upgrade = _document(ROOT / "docs" / "upgrade-and-rollback.md")

    assert "can perform another live test send" in provider
    assert "not a read-only status check" in provider
    assert "pipx upgrade signet-gateway" not in upgrade
    assert 'pipx install --force "signet-gateway==$SIGNET_VERSION"' in upgrade


def test_user_guides_do_not_show_secret_arguments_or_contact_examples() -> None:
    corpus = "\n".join(_document(path) for path in USER_GUIDES)

    assert re.search(r"--token(?:=|\s)", corpus) is None
    assert re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", corpus, re.IGNORECASE) is None
    assert re.search(r"(?<![A-Za-z0-9])\+?\d{10,15}(?![A-Za-z0-9])", corpus) is None
    for prohibited in (
        "paste the token into",
        "put the token in yaml",
        "send the capability in chat",
    ):
        assert prohibited not in corpus.lower()


def test_documented_signet_command_shapes_parse_with_current_cli() -> None:
    parser = _parser()
    commands = (
        ("setup",),
        ("setup", "--plan", "--profile", "personal", "--profile", "work"),
        ("setup", "--owner", "user:owner", "--no-open-browser"),
        ("status",),
        ("doctor",),
        ("verify",),
        ("authenticators", "open"),
        ("provider", "status"),
        ("provider", "setup", "fastmail"),
        ("provider", "setup", "whatsapp"),
        ("provider", "disable", "fastmail"),
        ("provider", "enable", "fastmail"),
        ("backup",),
        ("backup", "--apply", PLAN_ID),
        ("restore", "/tmp/archive.signet-backup"),
        ("restore", "/tmp/archive.signet-backup", "--apply", PLAN_ID),
        ("upgrade",),
        ("upgrade", "--apply", PLAN_ID),
        ("uninstall",),
        ("uninstall", "--apply", PLAN_ID),
        ("uninstall", "--purge"),
        ("uninstall", "--purge", "--apply", PLAN_ID),
        ("manage", "status"),
        ("manage", "restart"),
        ("manage", "stop", "--rollback", PLAN_ID),
    )

    for command in commands:
        parsed = parser.parse_args(command)
        assert parsed.command == command[0]


def test_command_reference_and_docs_use_the_same_public_lifecycle_names() -> None:
    corpus = "\n".join(_document(path) for path in USER_GUIDES)
    help_text = _parser().format_help()

    for command in (
        "setup",
        "status",
        "doctor",
        "verify",
        "backup",
        "restore",
        "upgrade",
        "uninstall",
        "authenticators",
        "provider",
    ):
        assert f"signet {command}" in corpus
        assert command in help_text

    assert "signet rollback" not in corpus
    assert "signet install" not in corpus


def test_cli_help_marks_human_only_and_live_boundaries(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = _parser()

    with pytest.raises(SystemExit) as setup_exit:
        parser.parse_args(("setup", "--help"))
    assert setup_exit.value.code == 0
    setup_help = _normalized(capsys.readouterr().out)
    assert "one owner with one or more independent hermes profile callers" in setup_help
    assert "only the human owner can complete authentication" in setup_help
    assert "keep the fail-closed deny default" in setup_help
    assert "does not automate the human-only browser ceremony" in setup_help

    with pytest.raises(SystemExit) as provider_exit:
        parser.parse_args(("provider", "setup", "fastmail", "--help"))
    assert provider_exit.value.code == 0
    provider_help = _normalized(capsys.readouterr().out)
    assert "one attended live test email" in provider_help
    assert "reviewed private secret broker" in provider_help
    assert "one live test still occurs" in provider_help


def test_installed_man_page_matches_the_package_quick_start() -> None:
    manual = _document(ROOT / "docs" / "man" / "signet.1")

    assert '"signet-gateway 0.1.0"' in manual
    assert ".B signet provider setup fastmail\n" in manual
    assert ".B signet provider setup whatsapp\n" in manual
    assert "--from ADDRESS" not in manual
    assert "--to PHONE_OR_JID" not in manual
    assert "human-only" in manual
    assert "multiple independently enrolled, named TOTP" in manual
    assert "docs/README.md" in manual
