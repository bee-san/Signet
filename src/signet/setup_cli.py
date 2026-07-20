"""End-user setup and installed-lifecycle command line."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from signet.setup_operations import SetupOperations
from signet.setup_platform import ProductionSetupPlatform
from signet.setup_state import PolicyMode, SetupEngine, SetupError, SetupJournalStore, SetupSpec

_SETUP_COMMANDS = frozenset(
    {
        "setup",
        "manage",
        "status",
        "doctor",
        "backup",
        "restore",
        "upgrade",
        "uninstall",
        "production",
    }
)


def add_setup_parsers(subcommands: Any) -> None:
    setup = subcommands.add_parser(
        "setup",
        help="plan or apply a resumable private Signet installation",
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
    setup.add_argument("--plan", action="store_true", help="print a read-only setup plan")
    setup.add_argument("--rollback", action="store_true", help="resume rollback of applied steps")
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
        help="start, stop, restart, or inspect Signet services",
    )
    _root_argument(manage)
    manage.add_argument("action", choices=("start", "stop", "restart", "status"))

    status = subcommands.add_parser("status", help="show persisted setup and runtime status")
    _root_argument(status)

    doctor = subcommands.add_parser("doctor", help="run non-secret installation diagnostics")
    _root_argument(doctor)

    backup = subcommands.add_parser("backup", help="create a verified encrypted backup")
    _root_argument(backup)
    backup.add_argument("--destination", type=Path)

    restore = subcommands.add_parser("restore", help="verify and stage an encrypted backup")
    _root_argument(restore)
    restore.add_argument("bundle", type=Path)

    upgrade = subcommands.add_parser(
        "upgrade",
        help="back up data and apply installed-package schema upgrades",
    )
    _root_argument(upgrade)
    upgrade.add_argument("--yes", action="store_true")

    uninstall = subcommands.add_parser(
        "uninstall",
        help="remove service and Hermes integration while preserving data",
    )
    _root_argument(uninstall)
    uninstall.add_argument(
        "--purge",
        action="store_true",
        help="back up, then remove owned data and secrets",
    )
    uninstall.add_argument("--yes", action="store_true")

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
    runner: Callable[..., Any] | None = None,
) -> int:
    selected_platform = platform or ProductionSetupPlatform(output=output)
    if args.command == "production":
        return _run_production_service(args, runner=runner)
    root = _absolute_path(args.root)
    if args.command == "setup":
        store = SetupJournalStore(root)
        spec = _setup_spec(args, store)
        engine = SetupEngine(store, selected_platform)
        if args.plan and args.rollback:
            raise ValueError("--plan and --rollback cannot be combined")
        if args.plan:
            plan = engine.plan(spec)
            _emit(
                {
                    "setup_id": plan.setup_id,
                    "root": str(spec.root),
                    "owner_setup_url": f"{spec.public_origin}/setup",
                    "provider_rollout": plan.provider_rollout,
                    "policy_mode": spec.policy_mode,
                    "hermes_profiles": list(spec.hermes_profiles),
                    "steps": [step.name for step in plan.steps],
                    "automatic_steps": [step.name for step in plan.steps[:-1]],
                    "human_ceremonies": [
                        "owner_authentication_enrollment",
                        "hermes_mcp_review_and_reload",
                    ],
                    "deferred_provider_proof": [
                        "credential_configuration",
                        "read_only_discovery",
                        "live_send",
                    ],
                    "browser_will_open": spec.open_browser,
                    "gateway_restart": False,
                },
                output,
            )
            return 0
        if args.rollback:
            _require_confirmation(
                args.yes,
                input_fn,
                "Roll back setup-owned resources?",
            )
            before = store.load()
            backup_path: Path | None = None
            if before.step("database").status == "completed":
                backup_path = operations_factory(root, platform=selected_platform).backup()
            journal = engine.rollback(spec)
            rollback_output = {"setup_status": journal.status, "setup_id": journal.setup_id}
            if backup_path is not None:
                rollback_output["backup"] = str(backup_path)
            _emit(rollback_output, output)
            return 0
        _require_confirmation(args.yes, input_fn, "Apply this setup plan?")
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
    document: dict[str, Any]
    if args.command == "manage":
        document = (
            operations.status() if args.action == "status" else operations.manage(args.action)
        )
    elif args.command == "status":
        document = operations.status()
    elif args.command == "doctor":
        document = operations.doctor()
    elif args.command == "backup":
        destination = _absolute_path(args.destination) if args.destination is not None else None
        document = {"backup": str(operations.backup(destination))}
    elif args.command == "restore":
        restored = operations.restore(_absolute_path(args.bundle))
        document = {
            "restored_to": str(restored.root),
            "database": str(restored.database_path),
            "activated": False,
        }
    elif args.command == "upgrade":
        _require_confirmation(
            args.yes,
            input_fn,
            "Create a backup and apply installed schema upgrades?",
        )
        document = operations.upgrade()
    elif args.command == "uninstall":
        prompt = (
            "Back up and purge all setup-owned Signet data?"
            if args.purge
            else "Remove Signet services and Hermes integration while preserving data?"
        )
        _require_confirmation(args.yes, input_fn, prompt)
        document = operations.uninstall(purge=args.purge)
    else:  # pragma: no cover - parser and main dispatch are closed over this set
        raise SetupError("unsupported setup command")
    _emit(document, output)
    return 0


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

    from signet.production import load_production_config

    config_path = _absolute_path(args.config)
    config = load_production_config(config_path)
    component = args.production_command.removeprefix("serve-")
    if component == "mcp":
        factory = "signet.production:create_production_mcp_app_from_environment"
        host, port = config.mcp_host, config.mcp_port
    else:
        factory = "signet.production:create_production_web_app_from_environment"
        host, port = config.web_host, config.web_port
    selected_runner = runner or uvicorn.run
    previous = os.environ.get("SIGNET_PRODUCTION_CONFIG")
    os.environ["SIGNET_PRODUCTION_CONFIG"] = str(config_path)
    try:
        selected_runner(
            factory,
            factory=True,
            host=host,
            port=port,
            server_header=False,
            limit_concurrency=args.limit_concurrency,
            proxy_headers=False,
        )
    finally:
        if previous is None:
            os.environ.pop("SIGNET_PRODUCTION_CONFIG", None)
        else:
            os.environ["SIGNET_PRODUCTION_CONFIG"] = previous
    return 0
