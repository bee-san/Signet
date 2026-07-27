"""End-user setup and installed-lifecycle command line."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import shlex
import shutil
import subprocess
import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO, cast

from signet.lifecycle import setup_lifecycle_lock
from signet.provider_setup import ProviderSetupOperations
from signet.setup_operations import SetupOperations
from signet.setup_platform import ProductionSetupPlatform
from signet.setup_state import (
    PolicyMode,
    SetupEngine,
    SetupError,
    SetupJournalStore,
    SetupPlan,
    SetupSpec,
)

_SETUP_COMMANDS = frozenset(
    {
        "setup",
        "manage",
        "status",
        "doctor",
        "verify",
        "backup",
        "restore",
        "upgrade",
        "uninstall",
        "authenticators",
        "provider",
        "production",
    }
)


def add_setup_parsers(subcommands: Any) -> None:
    setup = subcommands.add_parser(
        "setup",
        help="print, apply, resume, or roll back a private installation plan",
    )
    _root_argument(setup)
    setup.add_argument("--origin", help="canonical private HTTPS origin")
    setup.add_argument("--owner", help="canonical owner ID (default: user:owner)")
    setup.add_argument(
        "--profile",
        dest="profiles",
        action="append",
        help="Hermes profile to integrate; repeat for multiple profiles",
    )
    setup.add_argument(
        "--policy-mode",
        choices=("deny", "direct", "approval", "approval_with_edit"),
        help="default policy mode (default: deny)",
    )
    setup.add_argument(
        "--plan",
        action="store_true",
        help="print the read-only setup plan and exit",
    )
    setup.add_argument(
        "--rollback",
        action="store_true",
        help="after destructive confirmation, resume rollback of applied steps",
    )
    setup.add_argument(
        "--yes",
        action="store_true",
        help="confirm the reviewed plan non-interactively",
    )
    setup.add_argument(
        "--no-open-browser",
        action="store_true",
        help="print the exact owner URL without opening a browser",
    )
    setup.add_argument("--executable", help=argparse.SUPPRESS)

    manage = subcommands.add_parser(
        "manage",
        help="manage plan, apply, roll back, or inspect Signet services",
    )
    _root_argument(manage)
    manage.add_argument("action", choices=("start", "stop", "restart", "status"))
    manage_mode = manage.add_mutually_exclusive_group()
    manage_mode.add_argument(
        "--apply",
        metavar="PLAN_ID",
        help="apply the exact reviewed service plan",
    )
    manage_mode.add_argument(
        "--rollback",
        metavar="PLAN_ID",
        help="resume rollback of the exact reviewed service plan",
    )

    status = subcommands.add_parser("status", help="show persisted setup and runtime status")
    _root_argument(status)

    doctor = subcommands.add_parser("doctor", help="run non-secret installation diagnostics")
    _root_argument(doctor)

    verify = subcommands.add_parser(
        "verify",
        help="classify automatic checks, human ceremonies, and deferred provider proof",
    )
    _root_argument(verify)

    backup = subcommands.add_parser(
        "backup",
        help="backup plan or apply a verified encrypted backup",
    )
    _root_argument(backup)
    backup.add_argument("--destination", type=Path)
    backup.add_argument(
        "--apply",
        metavar="PLAN_ID",
        help="apply the exact reviewed backup plan",
    )

    restore = subcommands.add_parser(
        "restore",
        help="restore plan or apply verification into a new staging root",
    )
    _root_argument(restore)
    restore.add_argument("bundle", type=Path)
    restore.add_argument(
        "--apply",
        metavar="PLAN_ID",
        help="apply the exact reviewed restore plan",
    )

    upgrade = subcommands.add_parser(
        "upgrade",
        help="upgrade plan or apply a backed-up installed-package migration",
    )
    _root_argument(upgrade)
    upgrade.add_argument(
        "--apply",
        metavar="PLAN_ID",
        help="apply the exact reviewed upgrade plan",
    )

    uninstall = subcommands.add_parser(
        "uninstall",
        help="uninstall plan or apply exact service and Hermes removal",
    )
    _root_argument(uninstall)
    uninstall.add_argument(
        "--purge",
        action="store_true",
        help="back up, then remove owned data and secrets",
    )
    uninstall.add_argument(
        "--apply",
        metavar="PLAN_ID",
        help="apply the exact reviewed uninstall or purge plan",
    )

    authenticators = subcommands.add_parser(
        "authenticators",
        help="open named passkey and TOTP management",
    )
    authenticator_commands = authenticators.add_subparsers(
        dest="authenticator_command",
        required=True,
    )
    authenticator_open = authenticator_commands.add_parser(
        "open",
        help="open named passkey and TOTP enrollment in the authenticated browser",
        description=(
            "Print the exact private URL, then open authenticated browser management for "
            "named passkey and TOTP enrollment. Credential material never crosses the CLI."
        ),
    )
    _root_argument(authenticator_open)
    authenticator_open.add_argument(
        "--no-open-browser",
        action="store_true",
        help="print the exact management URL without opening a browser",
    )

    provider = subcommands.add_parser(
        "provider",
        help="configure and control Fastmail or WhatsApp",
    )
    provider_commands = provider.add_subparsers(dest="provider_command", required=True)
    provider_setup = provider_commands.add_parser("setup", help="configure and test a provider")
    setup_commands = provider_setup.add_subparsers(dest="provider_name", required=True)
    fastmail = setup_commands.add_parser("fastmail", help="configure Fastmail")
    _root_argument(fastmail)
    fastmail.add_argument("--from", dest="sender", help="sender email address")
    fastmail.add_argument("--to", dest="recipient", help="test recipient email address")
    fastmail.add_argument(
        "--token-stdin",
        action="store_true",
        help="read the Fastmail API token from standard input",
    )
    fastmail.add_argument("--yes", action="store_true", help="confirm the test send")

    whatsapp = setup_commands.add_parser("whatsapp", help="configure WhatsApp on Linux")
    _root_argument(whatsapp)
    whatsapp.add_argument("--to", dest="recipient", help="test phone number or JID")
    whatsapp.add_argument(
        "--yes",
        action="store_true",
        help="confirm the verified wacli download, pairing, and test send",
    )

    provider_status = provider_commands.add_parser("status", help="show provider status")
    _root_argument(provider_status)
    for action in ("enable", "disable"):
        control = provider_commands.add_parser(action, help=f"{action} provider rollout")
        _root_argument(control)
        control.add_argument("provider_name", choices=("fastmail", "whatsapp"))

    production = subcommands.add_parser(
        "production",
        help="run an installed-package production component (service-manager use)",
    )
    production_commands = production.add_subparsers(dest="production_command", required=True)
    for component in ("mcp", "web"):
        service = production_commands.add_parser(f"serve-{component}")
        service.add_argument("--config", type=Path, required=True)
        service.add_argument("--limit-concurrency", type=int, choices=range(1, 257), default=64)


def is_setup_command(command: str | None) -> bool:
    return command in _SETUP_COMMANDS


def run_setup_command(
    args: argparse.Namespace,
    *,
    output: Callable[[str], None] = print,
    input_fn: Callable[[str], str] = input,
    platform: ProductionSetupPlatform | Any | None = None,
    operations_factory: Callable[..., SetupOperations] = SetupOperations,
    provider_operations_factory: Callable[..., ProviderSetupOperations] = ProviderSetupOperations,
    runner: Callable[..., Any] | None = None,
    secret_input_fn: Callable[[str], str] = getpass.getpass,
    stdin: TextIO | None = None,
    browser_opener: Callable[[str], bool] = webbrowser.open,
) -> int:
    selected_platform = platform or ProductionSetupPlatform(output=output)
    if args.command == "production":
        return _run_production_service(args, runner=runner)
    root = _absolute_path(args.root)
    if args.command == "provider":
        providers = provider_operations_factory(root, platform=selected_platform)
        if args.provider_command == "status":
            provider_result = providers.status()
        elif args.provider_command == "enable":
            provider_result = providers.enable(args.provider_name)
        elif args.provider_command == "disable":
            provider_result = providers.disable(args.provider_name)
        elif args.provider_name == "fastmail":
            _require_confirmation(
                args.yes,
                input_fn,
                "LIVE PROVIDER PROOF — configure Fastmail, send one test email, and enable it?",
            )
            token = (
                (stdin or sys.stdin).readline().rstrip("\r\n")
                if args.token_stdin
                else secret_input_fn("Fastmail API token: ")
            )
            sender = args.sender or input_fn("Fastmail sender address: ").strip()
            recipient = args.recipient or input_fn("Fastmail test recipient: ").strip()
            provider_result = providers.setup_fastmail(
                token=token,
                sender=sender,
                recipient=recipient,
            )
        else:
            _require_confirmation(
                args.yes,
                input_fn,
                "HUMAN CEREMONY + LIVE PROVIDER PROOF — download verified wacli if needed, "
                "pair WhatsApp, send one test, and enable it?",
            )
            recipient = args.recipient or input_fn("WhatsApp test recipient: ").strip()
            provider_result = providers.setup_whatsapp(
                recipient=recipient,
                install_wacli=True,
            )
        _emit(provider_result, output)
        return 0
    if args.command == "setup":
        store = SetupJournalStore(root)
        spec = _setup_spec(args, store)
        engine = SetupEngine(store, selected_platform)
        if args.plan and args.rollback:
            raise ValueError("--plan and --rollback cannot be combined")
        if args.plan:
            plan = engine.plan(spec)
            _emit(_setup_plan_document(plan), output)
            return 0
        if args.rollback:
            _require_confirmation(
                args.yes,
                input_fn,
                "DESTRUCTIVE — back up and roll back all setup-owned Signet resources?",
            )
            rollback_document = operations_factory(root, platform=selected_platform).uninstall(
                purge=True
            )
            _emit(rollback_document, output)
            return 0
        _emit(_setup_plan_document(engine.plan(spec)), output)
        _require_confirmation(
            args.yes,
            input_fn,
            "Apply the reviewed automatic steps, then continue with the labelled human ceremonies?",
        )
        with setup_lifecycle_lock(root):
            journal = engine.apply(spec)
        output(
            "Review the generated MCP entry, then run /reload-mcp in each selected Hermes profile; "
            "Signet never restarts the Hermes gateway."
        )
        _emit(
            {
                "setup_status": journal.status,
                "setup_id": journal.setup_id,
                "owner_setup_url": f"{spec.public_origin}/setup",
                "provider_rollout": "disabled",
            },
            output,
        )
        return 0

    operations = operations_factory(root, platform=selected_platform)
    if args.command == "authenticators":
        management_url = f"{operations.spec().public_origin}/authenticators"
        output(
            "HUMAN CEREMONY — named passkey and TOTP management requires your "
            "authenticated browser."
        )
        output(f"Authenticator management URL: {management_url}")
        opened = False
        if not args.no_open_browser:
            opened = bool(browser_opener(management_url))
            if not opened:
                raise SetupError(
                    "the browser did not accept the authenticator management URL; "
                    "rerun with --no-open-browser and open the printed private URL"
                )
        _emit(
            {
                "authenticator_management_url": management_url,
                "browser_opened": opened,
                "credential_material_in_cli": False,
                "enrollment": ["named_passkey", "named_totp"],
            },
            output,
        )
        return 0
    document: dict[str, Any]
    if args.command == "manage":
        if args.action == "status":
            if args.apply is not None or args.rollback is not None:
                raise ValueError("manage status cannot apply or roll back a plan")
            document = operations.status()
        elif args.rollback is not None:
            document = operations.rollback_service_plan(args.rollback)
        elif args.apply is not None:
            document = operations.apply_service_plan(args.action, args.apply)
        else:
            document = operations.plan_services(args.action).document()
    elif args.command == "status":
        document = operations.status()
    elif args.command == "doctor":
        document = operations.doctor()
    elif args.command == "verify":
        document = operations.verify()
    elif args.command == "backup":
        destination = _absolute_path(args.destination) if args.destination is not None else None
        document = (
            operations.apply_backup(args.apply, destination)
            if args.apply is not None
            else operations.plan_backup(destination).document()
        )
    elif args.command == "restore":
        bundle = _absolute_path(args.bundle)
        document = (
            operations.apply_restore(args.apply, bundle)
            if args.apply is not None
            else operations.plan_restore(bundle).document()
        )
    elif args.command == "upgrade":
        document = (
            operations.apply_upgrade(args.apply)
            if args.apply is not None
            else operations.plan_upgrade().document()
        )
    elif args.command == "uninstall":
        document = (
            operations.apply_uninstall(args.apply, purge=args.purge)
            if args.apply is not None
            else operations.plan_uninstall(purge=args.purge).document()
        )
    else:  # pragma: no cover - parser and main dispatch are closed over this set
        raise SetupError("unsupported setup command")
    _emit(document, output)
    return 0


def _setup_plan_document(plan: SetupPlan) -> dict[str, Any]:
    spec = plan.spec
    automatic_steps = [step.name for step in plan.steps if step.name != "owner_bootstrap"]
    return {
        "root": str(spec.root),
        "owner_setup_url": f"{spec.public_origin}/setup",
        "provider_rollout": plan.provider_rollout,
        "policy_mode": spec.policy_mode,
        "hermes_profiles": list(spec.hermes_profiles),
        "steps": [step.name for step in plan.steps],
        "automatic_steps": automatic_steps,
        "human_ceremonies": [
            "owner_authentication_enrollment",
            "hermes_mcp_review_and_reload",
        ],
        "deferred_provider_proof": [
            "credential_configuration",
            "read_only_discovery",
            "live_send",
        ],
        "destructive_actions": [],
        "browser_will_open": spec.open_browser,
        "gateway_restart": False,
    }


def _setup_spec(args: argparse.Namespace, store: SetupJournalStore) -> SetupSpec:
    existing = store.load_optional()
    if existing is not None:
        document = existing.spec
        return SetupSpec(
            root=Path(document["root"]),
            public_origin=args.origin or str(document["public_origin"]),
            owner_user_id=args.owner or str(document["owner_user_id"]),
            hermes_profiles=(
                tuple(args.profiles)
                if args.profiles is not None
                else tuple(str(profile) for profile in document["hermes_profiles"])
            ),
            executable=(
                _absolute_path(args.executable)
                if args.executable is not None
                else Path(document["executable"])
            ),
            open_browser=(False if args.no_open_browser else bool(document["open_browser"])),
            policy_mode=cast(
                PolicyMode,
                args.policy_mode or document.get("policy_mode", "deny"),
            ),
        )
    origin = args.origin or _discover_tailscale_origin()
    owner = args.owner or "user:owner"
    profiles = tuple(args.profiles or _discover_hermes_profiles())
    executable_text = args.executable or shutil.which("signet")
    if executable_text is None:
        raise ValueError("the installed signet executable is not on PATH")
    return SetupSpec(
        root=_absolute_path(args.root),
        public_origin=origin,
        owner_user_id=owner,
        hermes_profiles=profiles,
        executable=_absolute_path(Path(executable_text)),
        open_browser=not args.no_open_browser,
        policy_mode=cast(PolicyMode, args.policy_mode or "deny"),
    )


def _discover_tailscale_origin() -> str:
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        document = json.loads(result.stdout) if result.returncode == 0 else {}
        dns_name = document.get("Self", {}).get("DNSName")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        dns_name = None
    if not isinstance(dns_name, str) or not dns_name.strip("."):
        raise ValueError("--origin is required when a Tailscale DNS name cannot be discovered")
    hostname = dns_name.rstrip(".").lower()
    return f"https://{hostname}:8443"


def _discover_hermes_profiles() -> list[str]:
    hermes_home = Path.home() / ".hermes"
    profiles_root = hermes_home / "profiles"
    if not hermes_home.is_dir() or hermes_home.is_symlink():
        raise ValueError("--profile is required when Hermes profiles cannot be discovered")
    profiles = ["default"]
    if profiles_root.is_dir() and not profiles_root.is_symlink():
        profiles.extend(
            sorted(
                child.name
                for child in profiles_root.iterdir()
                if child.is_dir()
                and not child.is_symlink()
                and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", child.name) is not None
            )
        )
    return profiles


def _root_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home() / ".local" / "share" / "signet",
        help="private setup root (default: ~/.local/share/signet)",
    )


def _absolute_path(path: Path | str) -> Path:
    selected = Path(path).expanduser()
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    if ".." in selected.parts:
        raise ValueError("paths must be absolute lexical paths without '..'")
    return selected.absolute()


def setup_error_message(args: argparse.Namespace, error: Exception) -> str:
    """Return a redacted, command-specific recovery message for stable CLI exit 2."""

    message = str(error)
    root_value = getattr(args, "root", Path.home() / ".local" / "share" / "signet")
    try:
        root = _absolute_path(root_value)
    except ValueError:
        return message
    quoted_root = shlex.quote(str(root))
    status_command = f"signet status --root {quoted_root}"
    if "different setup specification" in message:
        return (
            f"{message}\nRefused to adopt or overwrite foreign or conflicting setup state. "
            f"Recovery: run {status_command}, compare the recorded root/origin/owner/profiles, "
            "and choose a separate empty --root if this installation is not the intended one."
        )
    if args.command == "setup":
        return (
            f"{message}\nRecovery: run {status_command}; correct the reported condition, then "
            "rerun the same signet setup command to resume. Review signet setup --rollback "
            f"--root {quoted_root} before reversing owned changes."
        )
    if args.command == "provider":
        return (
            f"{message}\nRecovery: run {status_command} and signet provider status --root "
            f"{quoted_root}; correct credential, discovery, or live-proof readiness, then rerun "
            "the same provider command."
        )
    if args.command == "authenticators":
        return (
            f"{message}\nRecovery: run {status_command}; then run signet authenticators open "
            f"--no-open-browser --root {quoted_root} and open the printed private URL."
        )
    if args.command in {"status", "doctor", "verify"}:
        return f"{message}\nRecovery: correct the reported read-only check and rerun the command."
    if args.command == "production":
        return (
            f"{message}\nRecovery: run {status_command}, inspect the user service-manager logs, "
            "and repair the installed assembly before restarting the exact component."
        )
    return (
        f"{message}\nRecovery: run {status_command}; inspect the lifecycle_operation receipt, "
        "then rerun only the exact reviewed command and PLAN_ID shown by status."
    )


def _require_confirmation(
    confirmed: bool,
    input_fn: Callable[[str], str],
    prompt: str,
) -> None:
    if confirmed:
        return
    if input_fn(f"{prompt} [y/N] ").strip().lower() not in {"y", "yes"}:
        raise ValueError("operation requires explicit confirmation")


def _emit(document: Any, output: Callable[[str], None]) -> None:
    output(json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True))


def _run_production_service(
    args: argparse.Namespace,
    *,
    runner: Callable[..., Any] | None,
) -> int:
    import uvicorn

    from signet.production import create_owned_production_service

    config_path = _absolute_path(args.config)
    component = args.production_command.removeprefix("serve-")
    config, application = create_owned_production_service(
        config_path,
        component=component,
    )
    if component == "mcp":
        host, port = config.mcp_host, config.mcp_port
    else:
        host, port = config.web_host, config.web_port
    selected_runner = runner or uvicorn.run
    selected_runner(
        application,
        factory=False,
        host=host,
        port=port,
        server_header=False,
        limit_concurrency=args.limit_concurrency,
        proxy_headers=False,
    )
    return 0
