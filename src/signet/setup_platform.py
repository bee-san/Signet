"""Operating-system boundaries and renderers used by the setup state machine."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import plistlib
import re
import secrets
import stat
import subprocess
import sys
import time
import webbrowser
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import keyring
import yaml

from signet.authenticator_management import KeychainTotpSecretProvisioner
from signet.backup import BackupError, remove_private_tree_checked
from signet.browser_auth import (
    BootstrapAlreadyComplete,
    BootstrapClaimRequired,
    BootstrapService,
)
from signet.config import production_health_proof, production_instance_identity
from signet.credential_broker import CredentialError, KeychainSecretStore, SecretReference
from signet.db import Database
from signet.private_paths import (
    DirectoryIdentity,
    PrivatePathError,
    ensure_owned_directory,
    ensure_private_directory,
    exchange_entries,
    rename_entry_no_replace,
    require_no_acl_grants,
    require_owned_directory_identity,
    require_private_directory_identity,
    revalidate_directory_identity,
)
from signet.production import (
    ProductionAssemblyError,
    create_production_assembly,
    load_production_config,
)
from signet.setup_state import SetupError, SetupJournalStore, SetupSpec
from signet.totp_enrollment import TotpEnrollmentService

_CONFIG_NAME = "production.json"
_POLICY_NAME = "policy.yaml"
_SECRET_PURPOSES = ("session", "csrf", "capability", "payload", "attachment", "backup")
_SERVICE_NAME = "Signet-Setup"
_PRODUCTION_MCP_ALIASES = ("approvals", "fastmail", "whatsapp")
_HERMES_SERVER_NAMES = {alias: f"signet_{alias}" for alias in _PRODUCTION_MCP_ALIASES}
_DATABASE_OWNERSHIP_MARKER = ".signet-database-ownership.json"
_PRIVATE_PATH_RECEIPT_PREFIX = ".signet-private-path-"
_DATABASE_RUNTIME_NAMES = frozenset(
    {
        "signet.db",
        ".signet.db.maintenance.lock",
        "signet.db-wal",
        "signet.db-shm",
        "signet.db-journal",
    }
)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "duplicate mapping key",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def render_production_config(spec: SetupSpec, *, setup_id: str) -> dict[str, Any]:
    hostname = urlsplit(spec.public_origin).hostname
    if hostname is None:  # validated by SetupSpec
        raise ValueError("setup origin has no host")
    root = spec.root
    return {
        "version": 1,
        "mode": "production",
        "owner_user_id": spec.owner_user_id,
        "public_origin": spec.public_origin,
        "rp_id": hostname,
        "allowed_hosts": [hostname, "127.0.0.1", "localhost"],
        "mcp_host": "127.0.0.1",
        "mcp_port": 8789,
        "web_host": "127.0.0.1",
        "web_port": 8790,
        "policy_path": str(root / _POLICY_NAME),
        "storage": {
            "data_dir": str(root / "data"),
            "backup_dir": str(root / "backups"),
            "restore_dir": str(root / "restore"),
            "attachment_staging_dir": str(root / "staging"),
            "attachment_source_roots": [str(root / "attachments")],
        },
        "secrets": {
            "session_secret_ref": _secret_reference(setup_id, "session"),
            "csrf_secret_ref": _secret_reference(setup_id, "csrf"),
            "capability_key_ref": _secret_reference(setup_id, "capability"),
            "payload_key_ref": _secret_reference(setup_id, "payload"),
            "attachment_key_ref": _secret_reference(setup_id, "attachment"),
            "totp_secret_ref": None,
            "vapid_private_key_ref": None,
        },
        "capabilities": {
            "storage_ready": True,
            "secret_broker_ready": True,
            "mcp_ready": True,
            "web_ready": True,
            "workers_ready": True,
            "policy_ready": True,
            "live_providers_ready": False,
        },
        "caller_principals": [
            {
                "namespace": f"profile:{profile}",
                "allowed_aliases": list(_PRODUCTION_MCP_ALIASES),
            }
            for profile in spec.hermes_profiles
        ],
        "connectors": {},
        "provider_rollout": {"state": "disabled"},
    }


def render_launchd_services(spec: SetupSpec, *, active: bool = False) -> dict[str, bytes]:
    config = spec.root / _CONFIG_NAME
    logs = spec.root / "logs"
    result: dict[str, bytes] = {}
    for component in ("mcp", "web"):
        name = f"ai.hermes.signet.{component}.plist"
        document = {
            "Label": f"ai.hermes.signet.{component}",
            "ProgramArguments": [
                str(spec.executable),
                "production",
                f"serve-{component}",
                "--config",
                str(config),
            ],
            "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"},
            "RunAtLoad": active,
            "KeepAlive": active,
            "ProcessType": "Background",
            "ThrottleInterval": 10,
            "Umask": 63,
            "StandardOutPath": str(logs / f"{component}.log"),
            "StandardErrorPath": str(logs / f"{component}-error.log"),
        }
        result[name] = plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=False)
    return result


def render_systemd_services(spec: SetupSpec, *, active: bool = False) -> dict[str, str]:
    config = _systemd_quote(str(spec.root / _CONFIG_NAME))
    executable = _systemd_executable(str(spec.executable))
    result: dict[str, str] = {}
    for component in ("mcp", "web"):
        lines = [
            "[Unit]",
            f"Description=Signet {component.upper()} service",
            "After=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            f"ExecStart=:{executable} production serve-{component} --config {config}",
            "Restart=on-failure",
            "RestartSec=10",
            "UMask=0077",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
        ]
        if active:
            lines.extend(["", "[Install]", "WantedBy=default.target"])
        result[f"signet-{component}.service"] = "\n".join(lines) + "\n"
    return result


def browser_assisted_setup(
    public_origin: str,
    bootstrap_value: str | None,
    *,
    output: Callable[[str], None] = print,
    opener: Callable[[str], bool] = webbrowser.open,
    open_browser: bool = True,
    handoff_path: Path | None = None,
) -> None:
    public_url = f"{public_origin}/setup"
    output(f"Owner setup URL: {public_url}")
    if not open_browser:
        if bootstrap_value is not None:
            if handoff_path is None:
                raise SetupError("the private owner setup handoff path is unavailable")
            output(f"Private owner setup capability file: {handoff_path}")
        return
    if bootstrap_value is None:
        private_url = public_url
    else:
        private_url = f"{public_url}#bootstrap={quote(bootstrap_value, safe='')}"
    if not opener(private_url):
        raise SetupError("the browser did not accept the owner setup URL")


class ProductionSetupPlatform:
    """Concrete idempotent operations for a packaged Signet installation."""

    def __init__(
        self,
        *,
        hermes_home: Path | None = None,
        output: Callable[[str], None] = print,
        opener: Callable[[str], bool] = webbrowser.open,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.hermes_home = hermes_home or Path.home() / ".hermes" / "profiles"
        self.output = output
        self.opener = opener
        self.command_runner = command_runner
        self._database_override: Database | None = None

    @contextmanager
    def use_database(self, database: Database) -> Iterator[None]:
        if self._database_override is not None:
            raise SetupError("a setup database override is already active")
        self._database_override = database
        try:
            yield
        finally:
            self._database_override = None

    def _owned_database(self, spec: SetupSpec, setup_id: str) -> Database | None:
        if self._database_override is not None:
            return self._database_override
        database_path = spec.root / "data" / "signet.db"
        marker = database_path.parent / _DATABASE_OWNERSHIP_MARKER
        if not (marker.exists() or marker.is_symlink()):
            if database_path.exists() or database_path.is_symlink():
                raise SetupError("database exists without an active ownership receipt")
            return None
        database_identity, lock_identity = validate_active_database_runtime_ownership(
            database_path.parent,
            setup_id=setup_id,
        )
        return Database(
            database_path,
            expected_identity=database_identity,
            expected_lock_identity=lock_identity,
        )

    def _hermes_profile_directory(self, profile: str) -> Path:
        if profile == "default":
            return self.hermes_home.parent
        return self.hermes_home / profile

    def preflight(self, spec: SetupSpec) -> None:
        self._apply_preflight(spec, "preflight")

    def apply(self, step: str, spec: SetupSpec, setup_id: str) -> None:
        operation = getattr(self, f"_apply_{step}", None)
        if operation is None:
            raise SetupError(f"unsupported setup step: {step}")
        operation(spec, setup_id)

    def rollback(self, step: str, spec: SetupSpec, setup_id: str) -> None:
        operation = getattr(self, f"_rollback_{step}", None)
        if operation is not None:
            operation(spec, setup_id)

    def manage_services(self, spec: SetupSpec, action: str) -> None:
        if action not in {"start", "stop", "restart"}:
            raise SetupError("service action must be start, stop, or restart")
        if sys.platform == "darwin":
            rendered = render_launchd_services(spec, active=True)
            target = Path.home() / "Library" / "LaunchAgents"
            uid = os.getuid()
            for name, content in rendered.items():
                _require_exact_owned_file(target / name, content)
            for name in rendered:
                path = target / name
                label = name.removesuffix(".plist")
                if action == "stop":
                    command = ["launchctl", "bootout", f"gui/{uid}/{label}"]
                elif action == "restart":
                    command = ["launchctl", "kickstart", "-k", f"gui/{uid}/{label}"]
                else:
                    command = ["launchctl", "bootstrap", f"gui/{uid}", str(path)]
                if action == "stop":
                    self._stop_launchd_unit(command)
                    continue
                result = self.command_runner(command, text=True, capture_output=True, check=False)
                if result.returncode != 0:
                    message = (result.stderr or "").lower()
                    if not (action == "start" and "already" in message):
                        raise SetupError(f"launchd {action} failed for {label}")
        else:
            rendered = render_systemd_services(spec, active=True)
            target = Path.home() / ".config" / "systemd" / "user"
            for name, content in rendered.items():
                _require_exact_owned_file(target / name, content.encode("utf-8"))
            self._run_checked(
                ["systemctl", "--user", action, *rendered],
                f"systemd {action} failed for Signet",
            )

    def service_status(self, spec: SetupSpec) -> dict[str, str]:
        result: dict[str, str] = {}
        if sys.platform == "darwin":
            rendered = render_launchd_services(spec, active=True)
            target = Path.home() / "Library" / "LaunchAgents"
            uid = os.getuid()
            for name, content in rendered.items():
                path = target / name
                label = name.removesuffix(".plist")
                try:
                    _require_exact_owned_file(path, content)
                except SetupError:
                    result[label] = "missing_or_changed"
                    continue
                status = self.command_runner(
                    ["launchctl", "print", f"gui/{uid}/{label}"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                result[label] = "active" if status.returncode == 0 else "inactive"
        else:
            rendered = render_systemd_services(spec, active=True)
            target = Path.home() / ".config" / "systemd" / "user"
            for name, content in rendered.items():
                try:
                    _require_exact_owned_file(target / name, content.encode("utf-8"))
                except SetupError:
                    result[name] = "missing_or_changed"
                    continue
                status = self.command_runner(
                    ["systemctl", "--user", "is-active", name],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                result[name] = "active" if status.returncode == 0 else "inactive"
        port = _managed_tailnet_port(spec)
        if port is not None:
            try:
                serve = self._tailscale_json(
                    ["tailscale", "serve", "status", "--json"],
                    "Tailscale Serve status is unavailable",
                )
            except SetupError:
                result[f"tailscale:{port}"] = "unavailable"
            else:
                private_route = _serve_config_has_private_route(
                    serve,
                    host_port=_managed_tailnet_host_port(spec, port),
                    port=port,
                    target="http://127.0.0.1:8790",
                )
                result[f"tailscale:{port}"] = "active" if private_route else "missing_or_changed"
        return result

    def remove_setup_secrets(self, setup_id: str, *, preserve_backup: bool) -> None:
        purposes = (*_SECRET_PURPOSES, "browser-bootstrap", "fastmail")
        errors: list[str] = []
        for purpose in purposes:
            if preserve_backup and purpose in _SECRET_PURPOSES:
                continue
            account = _secret_account(setup_id, purpose)
            try:
                if keyring.get_password(_SERVICE_NAME, account) is not None:
                    keyring.delete_password(_SERVICE_NAME, account)
                if keyring.get_password(_SERVICE_NAME, account) is not None:
                    errors.append(purpose)
            except Exception:
                errors.append(purpose)
        if errors:
            raise SetupError("secret cleanup could not be verified for: " + ", ".join(errors))

    def _apply_preflight(self, spec: SetupSpec, setup_id: str) -> None:
        del setup_id
        if sys.platform not in {"darwin", "linux"}:
            raise SetupError("setup supports macOS and Linux user services")
        try:
            metadata = spec.executable.stat()
        except OSError as exc:
            raise SetupError("the installed Signet executable is unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & stat.S_IXUSR
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise SetupError("the installed Signet executable is not a reviewed executable file")
        if sys.platform == "linux":
            try:
                render_systemd_services(spec)
            except ValueError as exc:
                raise SetupError(str(exc)) from exc
        for profile in spec.hermes_profiles:
            directory = self._hermes_profile_directory(profile)
            if not directory.is_dir() or directory.is_symlink():
                raise SetupError(f"Hermes profile {profile!r} does not exist")
            profile_metadata = directory.stat()
            if stat.S_IMODE(profile_metadata.st_mode) & 0o022:
                raise SetupError(f"Hermes profile {profile!r} is group/world writable")
        if _managed_tailnet_port(spec) is not None:
            status = self._tailscale_json(
                ["tailscale", "status", "--json"],
                "Tailscale status is unavailable",
            )
            dns_name = status.get("Self", {}).get("DNSName") if isinstance(status, dict) else None
            expected_host = urlsplit(spec.public_origin).hostname
            if not isinstance(dns_name, str) or dns_name.rstrip(".").lower() != expected_host:
                raise SetupError("the private origin does not match this Tailscale node")

    def validate_private_paths(self, spec: SetupSpec, setup_id: str) -> None:
        try:
            root = require_private_directory_identity(spec.root)
            for name in (
                "data",
                "backups",
                "attachments",
                "staging",
                "services",
                "logs",
                "restore",
            ):
                path = spec.root / name
                _read_private_path_receipt(path, setup_id=setup_id)
                pending = _private_path_pending_path(spec.root, name, setup_id)
                if pending.exists() or pending.is_symlink():
                    raise SetupError(
                        f"private setup path {name!r} has an ambiguous pending publication"
                    )
            revalidate_directory_identity(root, private=True)
        except PrivatePathError as exc:
            raise SetupError("private setup paths are unavailable or unsafe") from exc

    def _apply_private_paths(self, spec: SetupSpec, setup_id: str) -> None:
        try:
            root = ensure_private_directory(spec.root)
            for path in (
                spec.root / "data",
                spec.root / "backups",
                spec.root / "restore",
                spec.root / "logs",
                spec.root / "services",
                spec.root / "staging",
                spec.root / "attachments",
            ):
                _create_or_verify_receipted_private_directory(root, path, setup_id=setup_id)
        except PrivatePathError as exc:
            raise SetupError("private setup path could not be prepared safely") from exc

    def _rollback_private_paths(self, spec: SetupSpec, setup_id: str) -> None:
        try:
            root_identity = require_private_directory_identity(spec.root)
            owned: list[tuple[Path, DirectoryIdentity | None, Path, bytes]] = []
            for name in reversed(("data", "attachments", "staging", "services", "logs", "restore")):
                path = spec.root / name
                pending = _private_path_pending_path(spec.root, name, setup_id)
                path_exists = path.exists() or path.is_symlink()
                pending_exists = pending.exists() or pending.is_symlink()
                receipt_path = _private_path_receipt_path(spec.root, name)
                receipt_exists = receipt_path.exists() or receipt_path.is_symlink()
                if receipt_exists and not path_exists and not pending_exists:
                    recorded = _read_owned_json(receipt_path)
                    intent = _private_path_creation_intent(name, setup_id)
                    if isinstance(recorded, dict) and recorded.get("format") == 3:
                        if recorded != intent:
                            raise SetupError(
                                f"private setup path {name!r} creation intent is invalid"
                            )
                        staging_name = intent["staging_name"]
                        assert isinstance(staging_name, str)
                        _remove_unbound_private_path_staging(spec.root, staging_name)
                        _remove_exact_owned_file(
                            receipt_path,
                            _json_bytes(intent),
                            expected_parent_identity=root_identity,
                            parent_private=True,
                        )
                        continue
                if receipt_exists and not path_exists and not pending_exists:
                    pending_exists = _resume_receipted_private_path_staging(
                        spec.root,
                        name,
                        setup_id=setup_id,
                    )
                if path_exists and pending_exists:
                    raise SetupError(
                        f"private setup path {name!r} has an ambiguous pending publication"
                    )
                if path_exists:
                    tree_identity, receipt_path, receipt_bytes = _read_private_path_receipt(
                        path,
                        setup_id=setup_id,
                    )
                    owned.append((path, tree_identity, receipt_path, receipt_bytes))
                    continue
                if pending_exists:
                    tree_identity, receipt_path, receipt_bytes = _read_private_path_receipt(
                        pending,
                        setup_id=setup_id,
                        expected_name=name,
                    )
                    owned.append((pending, tree_identity, receipt_path, receipt_bytes))
                    continue
                receipt_path = _private_path_receipt_path(spec.root, name)
                if receipt_path.exists() or receipt_path.is_symlink():
                    _, receipt_path, receipt_bytes = _read_private_path_receipt(
                        path,
                        setup_id=setup_id,
                        validate_tree=False,
                    )
                    owned.append((path, None, receipt_path, receipt_bytes))
            for path, owned_identity, receipt_path, receipt_bytes in owned:
                if owned_identity is not None:
                    remove_private_tree_checked(
                        path,
                        parent_identity=root_identity,
                        tree_identity=owned_identity,
                    )
                _remove_exact_owned_file(
                    receipt_path,
                    receipt_bytes,
                    expected_parent_identity=root_identity,
                    parent_private=True,
                )
        except (BackupError, PrivatePathError) as exc:
            raise SetupError("gateway-owned private data could not be removed safely") from exc

    def _apply_secrets(self, spec: SetupSpec, setup_id: str) -> None:
        del spec
        for purpose in _SECRET_PURPOSES:
            account = _secret_account(setup_id, purpose)
            try:
                existing = keyring.get_password(_SERVICE_NAME, account)
            except Exception as exc:
                raise SetupError("the platform secret store is unavailable") from exc
            if existing is not None:
                if len(existing) < 32:
                    raise SetupError(f"owned {purpose} secret is invalid")
                continue
            value = secrets.token_urlsafe(48)
            try:
                keyring.set_password(_SERVICE_NAME, account, value)
                stored = keyring.get_password(_SERVICE_NAME, account)
            except Exception as exc:
                raise SetupError(f"the {purpose} secret could not be stored") from exc
            finally:
                value = ""
            if stored is None or len(stored) < 32:
                raise SetupError(f"the {purpose} secret could not be verified")

    def _rollback_secrets(self, spec: SetupSpec, setup_id: str) -> None:
        backup_root = spec.root / "backups"
        journal = SetupJournalStore(spec.root).load()
        preserve_backup = journal.purge_backup is not None or (
            backup_root.is_dir()
            and any(
                path.is_file() and not path.is_symlink()
                for path in backup_root.glob("*.signet-backup")
            )
        )
        self.remove_setup_secrets(setup_id, preserve_backup=preserve_backup)

    def _apply_configuration(self, spec: SetupSpec, setup_id: str) -> None:
        policy = f"version: 1\ndefault_mode: {spec.policy_mode}\ndownstreams: {{}}\n".encode()
        config = (
            json.dumps(
                render_production_config(spec, setup_id=setup_id),
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
        _create_or_verify_private_file(spec.root / _POLICY_NAME, policy)
        _create_or_verify_private_file(spec.root / _CONFIG_NAME, config)
        # Validate the exact persisted document before any database or service action.
        load_production_config(spec.root / _CONFIG_NAME)

    def _rollback_configuration(self, spec: SetupSpec, setup_id: str) -> None:
        expected = {
            spec.root / _POLICY_NAME: (
                f"version: 1\ndefault_mode: {spec.policy_mode}\ndownstreams: {{}}\n".encode()
            ),
            spec.root / _CONFIG_NAME: (
                json.dumps(
                    render_production_config(spec, setup_id=setup_id),
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("utf-8"),
        }
        for path, content in expected.items():
            _remove_exact_owned_file(path, content)

    def _apply_database(self, spec: SetupSpec, setup_id: str) -> None:
        database_path = spec.root / "data" / "signet.db"
        maintenance_lock_path = database_path.with_name(f".{database_path.name}.maintenance.lock")
        marker = database_path.parent / _DATABASE_OWNERSHIP_MARKER
        if database_path.exists() and database_path.is_symlink():
            raise SetupError("the Signet database must not be a symbolic link")
        data_identity = require_private_directory_identity(database_path.parent)
        unbound_initializing = {
            "format": 4,
            "setup_id": setup_id,
            "data_device": data_identity.device,
            "data_inode": data_identity.inode,
            "data_owner_uid": data_identity.owner_uid,
            "removal_phase": "initializing",
        }
        unbound_initializing_bytes = _json_bytes(unbound_initializing)
        marker_exists = marker.exists() or marker.is_symlink()
        if not marker_exists:
            if database_path.exists():
                raise SetupError("refusing database adoption without an ownership receipt")
            _create_or_verify_private_file(marker, unbound_initializing_bytes)
        recorded = _read_owned_json(marker)
        bound_initializing: dict[str, Any] | None = None
        expected_database_identity: tuple[int, int] | None = None
        expected_lock_identity: tuple[int, int] | None = None
        if recorded == unbound_initializing:
            existing = {
                child.name
                for child in database_path.parent.iterdir()
                if child.name != _DATABASE_OWNERSHIP_MARKER
            }
            if existing:
                raise SetupError("refusing database adoption after unbound initialization")
            for runtime_path in (database_path, maintenance_lock_path):
                descriptor = -1
                try:
                    descriptor = os.open(
                        runtime_path,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                    )
                    os.fchmod(descriptor, 0o600)
                    require_no_acl_grants(descriptor)
                    os.fsync(descriptor)
                except (OSError, PrivatePathError) as exc:
                    raise SetupError(
                        "database initialization ownership could not be bound"
                    ) from exc
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            created_database_identity = _owned_runtime_file_identity(database_path)
            created_lock_identity = _owned_runtime_file_identity(maintenance_lock_path)
            expected_database_identity = (
                created_database_identity["device"],
                created_database_identity["inode"],
            )
            expected_lock_identity = (
                created_lock_identity["device"],
                created_lock_identity["inode"],
            )
            bound_initializing = {
                "format": 5,
                "setup_id": setup_id,
                "data_device": data_identity.device,
                "data_inode": data_identity.inode,
                "data_owner_uid": data_identity.owner_uid,
                "database_device": created_database_identity["device"],
                "database_inode": created_database_identity["inode"],
                "maintenance_lock_device": created_lock_identity["device"],
                "maintenance_lock_inode": created_lock_identity["inode"],
                "removal_phase": "initializing",
            }
            _replace_private_file(
                marker,
                _json_bytes(bound_initializing),
                expected_content=unbound_initializing_bytes,
                expected_parent_identity=data_identity,
                require_present=True,
            )
            _fsync_owned_directory(database_path.parent)
        elif isinstance(recorded, dict) and recorded.get("format") == 5:
            expected_fields = {
                "format",
                "setup_id",
                "data_device",
                "data_inode",
                "data_owner_uid",
                "database_device",
                "database_inode",
                "maintenance_lock_device",
                "maintenance_lock_inode",
                "removal_phase",
            }
            if (
                set(recorded) != expected_fields
                or recorded.get("setup_id") != setup_id
                or recorded.get("removal_phase") != "initializing"
                or any(
                    type(recorded.get(field)) is not int
                    for field in expected_fields - {"format", "setup_id", "removal_phase"}
                )
                or (
                    recorded["data_device"],
                    recorded["data_inode"],
                    recorded["data_owner_uid"],
                )
                != (data_identity.device, data_identity.inode, data_identity.owner_uid)
            ):
                raise SetupError("database ownership receipt is invalid")
            bound_database_identity = _owned_runtime_file_identity(database_path)
            if bound_database_identity != {
                "device": recorded["database_device"],
                "inode": recorded["database_inode"],
            }:
                raise SetupError("database changed after initialization ownership was bound")
            expected_database_identity = (
                recorded["database_device"],
                recorded["database_inode"],
            )
            bound_lock_identity = _owned_runtime_file_identity(maintenance_lock_path)
            if bound_lock_identity != {
                "device": recorded["maintenance_lock_device"],
                "inode": recorded["maintenance_lock_inode"],
            }:
                raise SetupError(
                    "maintenance lock changed after initialization ownership was bound"
                )
            expected_lock_identity = (
                recorded["maintenance_lock_device"],
                recorded["maintenance_lock_inode"],
            )
            existing = {
                child.name
                for child in database_path.parent.iterdir()
                if child.name != _DATABASE_OWNERSHIP_MARKER
            }
            if existing != {"signet.db", maintenance_lock_path.name}:
                raise SetupError("database directory contains an unowned runtime artifact")
            bound_initializing = recorded
        elif isinstance(recorded, dict) and recorded.get("format") == 3:
            _validate_active_database_ownership(
                database_path.parent,
                recorded,
                setup_id=setup_id,
                data_identity=data_identity,
            )
            database_identity = recorded["runtime_files"]["signet.db"]
            expected_database_identity = (
                database_identity["device"],
                database_identity["inode"],
            )
            lock_identity = recorded["runtime_files"][maintenance_lock_path.name]
            expected_lock_identity = (
                lock_identity["device"],
                lock_identity["inode"],
            )
        else:
            raise SetupError("database ownership receipt is invalid")

        assert expected_database_identity is not None
        assert expected_lock_identity is not None
        owned_database = Database(
            database_path,
            expected_identity=expected_database_identity,
            expected_lock_identity=expected_lock_identity,
        )
        owned_database.initialize(
            post_initialize=lambda: _publish_database_ownership(
                database_path,
                marker,
                data_identity=data_identity,
                setup_id=setup_id,
                bound_initializing=bound_initializing,
            )
        )
        # Assembly validates the deny-by-default policy, secret references, and setup state.
        create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
            database_override=self._database_override or owned_database,
        )

    def _rollback_database(self, spec: SetupSpec, setup_id: str) -> None:
        data_directory = spec.root / "data"
        marker = data_directory / _DATABASE_OWNERSHIP_MARKER
        if not marker.exists() and not marker.is_symlink():
            try:
                leftovers = tuple(data_directory.iterdir())
            except FileNotFoundError:
                return
            if leftovers:
                raise SetupError("refusing database cleanup without an ownership receipt")
            return
        ownership = _read_owned_json(marker)
        if isinstance(ownership, dict) and ownership.get("format") in {4, 5}:
            bound = ownership.get("format") == 5
            initializing_fields = {
                "format",
                "setup_id",
                "data_device",
                "data_inode",
                "data_owner_uid",
                "removal_phase",
            }
            if bound:
                initializing_fields |= {
                    "database_device",
                    "database_inode",
                    "maintenance_lock_device",
                    "maintenance_lock_inode",
                }
            if (
                set(ownership) != initializing_fields
                or ownership.get("setup_id") != setup_id
                or ownership.get("removal_phase") != "initializing"
                or any(
                    type(ownership.get(field)) is not int
                    for field in initializing_fields - {"format", "setup_id", "removal_phase"}
                )
            ):
                raise SetupError("database ownership receipt is invalid")
            data_identity = DirectoryIdentity(
                path=data_directory,
                device=ownership["data_device"],
                inode=ownership["data_inode"],
                owner_uid=ownership["data_owner_uid"],
            )
            try:
                revalidate_directory_identity(data_identity, private=True)
            except PrivatePathError as exc:
                raise SetupError("database directory changed after setup") from exc
            discovered_runtime_files = {}
            for child in data_directory.iterdir():
                if child.name == _DATABASE_OWNERSHIP_MARKER:
                    continue
                if child.name not in _DATABASE_RUNTIME_NAMES:
                    raise SetupError("database directory contains an unowned runtime artifact")
                discovered_runtime_files[child.name] = _owned_runtime_file_identity(child)
            if not bound:
                if discovered_runtime_files:
                    raise SetupError("refusing database cleanup after unbound initialization")
                _remove_exact_owned_file(marker, _json_bytes(ownership))
                _fsync_owned_directory(data_directory)
                return
            if discovered_runtime_files.get("signet.db") != {
                "device": ownership["database_device"],
                "inode": ownership["database_inode"],
            }:
                raise SetupError("database changed after initialization ownership was bound")
            lock_name = ".signet.db.maintenance.lock"
            if discovered_runtime_files.get(lock_name) != {
                "device": ownership["maintenance_lock_device"],
                "inode": ownership["maintenance_lock_inode"],
            }:
                raise SetupError(
                    "maintenance lock changed after initialization ownership was bound"
                )
            if set(discovered_runtime_files) != {"signet.db", lock_name}:
                raise SetupError("database directory contains an unowned runtime artifact")
            upgraded = {
                "format": 3,
                "setup_id": setup_id,
                "data_device": data_identity.device,
                "data_inode": data_identity.inode,
                "data_owner_uid": data_identity.owner_uid,
                "database_device": ownership["database_device"],
                "database_inode": ownership["database_inode"],
                "runtime_files": discovered_runtime_files,
                "removal_phase": "active",
                "quarantine": {
                    name: _database_runtime_quarantine_name(setup_id, name, identity)
                    for name, identity in discovered_runtime_files.items()
                },
            }
            _replace_private_file(
                marker,
                _json_bytes(upgraded),
                expected_content=_json_bytes(ownership),
                expected_parent_identity=data_identity,
                require_present=True,
            )
            ownership = upgraded
        integer_fields = (
            "data_device",
            "data_inode",
            "data_owner_uid",
            "database_device",
            "database_inode",
        )
        common_fields = {"format", "setup_id", "runtime_files", *integer_fields}
        if (
            not isinstance(ownership, dict)
            or ownership.get("format") not in {2, 3}
            or ownership.get("setup_id") != setup_id
            or any(type(ownership.get(field)) is not int for field in integer_fields)
            or (ownership.get("format") == 2 and set(ownership) != common_fields)
            or (
                ownership.get("format") == 3
                and set(ownership) != common_fields | {"removal_phase", "quarantine"}
            )
        ):
            raise SetupError("database ownership receipt is invalid")
        runtime_files = ownership.get("runtime_files")
        if (
            not isinstance(runtime_files, dict)
            or "signet.db" not in runtime_files
            or not set(runtime_files).issubset(_DATABASE_RUNTIME_NAMES)
            or any(
                not isinstance(identity, dict)
                or set(identity) != {"device", "inode"}
                or any(type(identity.get(field)) is not int for field in ("device", "inode"))
                for identity in runtime_files.values()
            )
            or runtime_files["signet.db"]
            != {
                "device": ownership["database_device"],
                "inode": ownership["database_inode"],
            }
        ):
            raise SetupError("database ownership receipt is invalid")
        data_identity = DirectoryIdentity(
            path=data_directory,
            device=ownership["data_device"],
            inode=ownership["data_inode"],
            owner_uid=ownership["data_owner_uid"],
        )
        try:
            revalidate_directory_identity(data_identity, private=True)
        except PrivatePathError as exc:
            raise SetupError("database directory changed after setup") from exc
        if ownership["format"] == 2:
            upgraded = {
                **ownership,
                "format": 3,
                "removal_phase": "active",
                "quarantine": {
                    name: _database_runtime_quarantine_name(setup_id, name, identity)
                    for name, identity in runtime_files.items()
                },
            }
            _replace_private_file(
                marker,
                _json_bytes(upgraded),
                expected_content=_json_bytes(ownership),
                expected_parent_identity=data_identity,
                require_present=True,
            )
            ownership = upgraded
        phase = ownership.get("removal_phase")
        quarantine = ownership.get("quarantine")
        expected_quarantine = {
            name: _database_runtime_quarantine_name(setup_id, name, identity)
            for name, identity in runtime_files.items()
        }
        if (
            phase not in {"active", "quarantined"}
            or not isinstance(quarantine, dict)
            or quarantine != expected_quarantine
        ):
            raise SetupError("database ownership receipt is invalid")
        descriptor = -1
        try:
            descriptor = os.open(
                data_directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (data_identity.device, data_identity.inode):
                raise SetupError("database directory changed during rollback")
            present = set(os.listdir(descriptor))
            allowed = {
                _DATABASE_OWNERSHIP_MARKER,
                *runtime_files,
                *expected_quarantine.values(),
            }
            unreceipted = present - allowed
            active_fence = self._database_override
            transient_fence_files = {"signet.db-wal", "signet.db-shm"}
            fence_is_active = (
                phase == "active"
                and active_fence is not None
                and active_fence.path == (data_directory / "signet.db").absolute()
                and active_fence.has_active_write_fence()
            )
            if unreceipted and (not fence_is_active or not unreceipted <= transient_fence_files):
                raise SetupError(
                    "database directory contains an unreceipted database runtime artifact"
                )
            if fence_is_active:
                refreshed_runtime_files = dict(runtime_files)
                for name in transient_fence_files:
                    recorded_identity = runtime_files.get(name)
                    recorded_quarantine = (
                        expected_quarantine.get(name) if recorded_identity is not None else None
                    )
                    source_present = name in present
                    quarantine_present = (
                        recorded_quarantine is not None and recorded_quarantine in present
                    )
                    if source_present and quarantine_present:
                        raise SetupError(
                            "database runtime removal state is incomplete or ambiguous"
                        )
                    if source_present:
                        refreshed_runtime_files[name] = _owned_runtime_file_identity(
                            data_directory / name
                        )
                    elif not quarantine_present:
                        refreshed_runtime_files.pop(name, None)
                refreshed_quarantine = {
                    name: _database_runtime_quarantine_name(setup_id, name, identity)
                    for name, identity in refreshed_runtime_files.items()
                }
                refreshed_ownership = {
                    **ownership,
                    "runtime_files": refreshed_runtime_files,
                    "quarantine": refreshed_quarantine,
                }
                if refreshed_ownership != ownership:
                    _replace_private_file(
                        marker,
                        _json_bytes(refreshed_ownership),
                        expected_content=_json_bytes(ownership),
                        expected_parent_identity=data_identity,
                        require_present=True,
                    )
                    os.fsync(descriptor)
                ownership = refreshed_ownership
                runtime_files = refreshed_runtime_files
                expected_quarantine = refreshed_quarantine
            removal_order = sorted(runtime_files, key=lambda name: name == "signet.db")
            if phase == "active":
                for name in removal_order:
                    identity = runtime_files[name]
                    quarantine_name = expected_quarantine[name]
                    source_present = name in present
                    quarantine_present = quarantine_name in present
                    if source_present == quarantine_present:
                        raise SetupError(
                            "database runtime removal state is incomplete or ambiguous"
                        )
                    if source_present:
                        _quarantine_owned_runtime_file(
                            descriptor,
                            name,
                            quarantine_name,
                            expected_identity=(identity["device"], identity["inode"]),
                        )
                    else:
                        _verify_owned_runtime_entry(
                            descriptor,
                            quarantine_name,
                            expected_identity=(identity["device"], identity["inode"]),
                            logical_name=name,
                        )
                os.fsync(descriptor)
                quarantined = {**ownership, "removal_phase": "quarantined"}
                _replace_private_file(
                    marker,
                    _json_bytes(quarantined),
                    expected_content=_json_bytes(ownership),
                    expected_parent_identity=data_identity,
                    require_present=True,
                )
                ownership = quarantined
                phase = "quarantined"
                os.fsync(descriptor)
            if phase == "quarantined":
                present = set(os.listdir(descriptor))
                if set(runtime_files) & present:
                    raise SetupError("database runtime removal state is incomplete or ambiguous")
                for name in removal_order:
                    identity = runtime_files[name]
                    _remove_quarantined_runtime_file(
                        descriptor,
                        expected_quarantine[name],
                        expected_identity=(identity["device"], identity["inode"]),
                        logical_name=name,
                    )
                os.fsync(descriptor)
        except OSError as exc:
            raise SetupError("database rollback could not remove owned runtime files") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        _remove_exact_owned_file(
            marker,
            _json_bytes(ownership),
            expected_parent_identity=data_identity,
            parent_private=True,
        )
        _fsync_owned_directory(data_directory)

    def _apply_services(self, spec: SetupSpec, setup_id: str) -> None:
        del setup_id
        plan_dir = spec.root / "services"
        self._preflight_tailnet_route(spec)
        if sys.platform == "darwin":
            rendered = render_launchd_services(spec, active=True)
            target = Path.home() / "Library" / "LaunchAgents"
            ensure_owned_directory(target)
            for name, content in rendered.items():
                plan_path = plan_dir / name
                target_path = target / name
                plan_exists = plan_path.exists() or plan_path.is_symlink()
                target_exists = target_path.exists() or target_path.is_symlink()
                if target_exists and not plan_exists:
                    raise SetupError("launchd unit exists without an ownership plan")
                if plan_exists:
                    _require_exact_owned_file(plan_path, content)
                if target_exists:
                    _require_exact_owned_file(target_path, content)
            for name, content in rendered.items():
                _create_or_verify_private_file(plan_dir / name, content)
                _create_or_verify_private_file(
                    target / name,
                    content,
                    parent_private=False,
                )
            uid = os.getuid()
            for name in rendered:
                path = target / name
                result = self.command_runner(
                    ["launchctl", "bootstrap", f"gui/{uid}", str(path)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode != 0 and "already" not in (result.stderr or "").lower():
                    raise SetupError(f"launchd could not load {name}")
        else:
            rendered_text = render_systemd_services(spec, active=True)
            target = Path.home() / ".config" / "systemd" / "user"
            ensure_owned_directory(target)
            for name, content in rendered_text.items():
                encoded = content.encode("utf-8")
                plan_path = plan_dir / name
                target_path = target / name
                plan_exists = plan_path.exists() or plan_path.is_symlink()
                target_exists = target_path.exists() or target_path.is_symlink()
                if target_exists and not plan_exists:
                    raise SetupError("systemd unit exists without an ownership plan")
                if plan_exists:
                    _require_exact_owned_file(plan_path, encoded)
                if target_exists:
                    _require_exact_owned_file(target_path, encoded)
            for name, content in rendered_text.items():
                encoded = content.encode("utf-8")
                _create_or_verify_private_file(plan_dir / name, encoded)
                _create_or_verify_private_file(
                    target / name,
                    encoded,
                    parent_private=False,
                )
            self._run_checked(["systemctl", "--user", "daemon-reload"], "systemd reload failed")
            self._run_checked(
                ["systemctl", "--user", "enable", "--now", *rendered_text],
                "systemd could not start Signet",
            )
        self._wait_for_local_services(spec)
        self._apply_tailnet_route(spec)

    def _rollback_services(self, spec: SetupSpec, setup_id: str) -> None:
        del setup_id
        self._rollback_tailnet_route(spec)
        if sys.platform == "darwin":
            rendered: Mapping[str, bytes] = render_launchd_services(spec, active=True)
            target = Path.home() / "Library" / "LaunchAgents"
            uid = os.getuid()
            for name, content in rendered.items():
                target_path = target / name
                plan_path = spec.root / "services" / name
                target_exists = target_path.exists() or target_path.is_symlink()
                plan_exists = plan_path.exists() or plan_path.is_symlink()
                if target_exists and not plan_exists:
                    raise SetupError("launchd unit exists without its ownership plan")
                if target_exists:
                    _verify_exact_owned_file(target_path, content)
                if plan_exists:
                    _verify_exact_owned_file(plan_path, content)
            for name in rendered:
                path = target / name
                self._stop_launchd_unit(["launchctl", "bootout", f"gui/{uid}", str(path)])
            for name in rendered:
                label = name.removesuffix(".plist")
                status = self.command_runner(
                    ["launchctl", "print", f"gui/{uid}/{label}"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if status.returncode == 0:
                    raise SetupError("launchd did not quiesce every Signet service")
            for name, content in rendered.items():
                path = target / name
                plan_path = spec.root / "services" / name
                if path.exists() or path.is_symlink():
                    _remove_exact_owned_file(path, content)
                if plan_path.exists() or plan_path.is_symlink():
                    _remove_exact_owned_file(plan_path, content)
        else:
            rendered_text = render_systemd_services(spec, active=True)
            target = Path.home() / ".config" / "systemd" / "user"
            for name, content in rendered_text.items():
                encoded = content.encode("utf-8")
                target_path = target / name
                plan_path = spec.root / "services" / name
                target_exists = target_path.exists() or target_path.is_symlink()
                plan_exists = plan_path.exists() or plan_path.is_symlink()
                if target_exists and not plan_exists:
                    raise SetupError("systemd unit exists without its ownership plan")
                if target_exists:
                    _verify_exact_owned_file(target_path, encoded)
                if plan_exists:
                    _verify_exact_owned_file(plan_path, encoded)
            for name in rendered_text:
                self._stop_systemd_units(["systemctl", "--user", "disable", "--now", name])
            for name in rendered_text:
                status = self.command_runner(
                    ["systemctl", "--user", "is-active", name],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if status.returncode == 0:
                    raise SetupError("systemd did not quiesce every Signet service")
            for name, content in rendered_text.items():
                encoded = content.encode("utf-8")
                target_path = target / name
                if target_path.exists() or target_path.is_symlink():
                    _remove_exact_owned_file(target_path, encoded)
            self._run_checked(
                ["systemctl", "--user", "daemon-reload"],
                "systemd reload after rollback failed",
            )
            for name, content in rendered_text.items():
                plan_path = spec.root / "services" / name
                if plan_path.exists() or plan_path.is_symlink():
                    _remove_exact_owned_file(
                        plan_path,
                        content.encode("utf-8"),
                    )

    def verify_service_health(self, spec: SetupSpec) -> None:
        """Require both local services to answer for this exact Signet instance."""

        self._wait_for_local_services(spec)

    def _health_secret(self, spec: SetupSpec) -> str:
        try:
            config = load_production_config(spec.root / _CONFIG_NAME)
            reference = SecretReference.parse(config.secrets.session_secret_ref)
            return KeychainSecretStore().get(reference).reveal()
        except (CredentialError, OSError, ProductionAssemblyError, ValueError) as exc:
            raise SetupError("the local service health proof secret is unavailable") from exc

    def _wait_for_local_services(self, spec: SetupSpec) -> None:
        pending: dict[int, Literal["mcp", "web"]] = {8789: "mcp", 8790: "web"}
        expected_identity = production_instance_identity(spec.root)
        health_secret = self._health_secret(spec)
        deadline = time.monotonic() + 20
        while pending and time.monotonic() < deadline:
            for port, component in tuple(pending.items()):
                challenge = secrets.token_urlsafe(32)
                expected_proof = production_health_proof(
                    health_secret,
                    identity=expected_identity,
                    component=component,
                    challenge=challenge,
                )
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request(
                        "GET",
                        "/healthz",
                        headers={"X-Signet-Health-Challenge": challenge},
                    )
                    response = connection.getresponse()
                    response.read(4097)
                    proof = response.getheader("X-Signet-Health-Proof")
                    if (
                        response.status == 200
                        and response.getheader("X-Signet-Instance") == expected_identity
                        and isinstance(proof, str)
                        and hmac.compare_digest(proof, expected_proof)
                    ):
                        del pending[port]
                except OSError:
                    pass
                finally:
                    connection.close()
            if pending:
                time.sleep(0.2)
        if pending:
            raise SetupError(f"services did not become healthy: {', '.join(map(str, pending))}")

    def _preflight_tailnet_route(self, spec: SetupSpec) -> None:
        self._apply_tailnet_route(spec, preflight_only=True)

    def _apply_tailnet_route(self, spec: SetupSpec, *, preflight_only: bool = False) -> None:
        port = _managed_tailnet_port(spec)
        if port is None:
            return
        record_path = spec.root / "services" / "tailscale-serve-before.json"
        after_path = spec.root / "services" / "tailscale-serve-after.json"
        current = _normalize_serve_config(
            self._tailscale_json(
                ["tailscale", "serve", "status", "--json"],
                "Tailscale Serve status is unavailable",
            )
        )
        host_port = _managed_tailnet_host_port(spec, port)
        target = "http://127.0.0.1:8790"
        if record_path.exists():
            before = _read_owned_json(record_path)
            if (
                not isinstance(before, dict)
                or set(before) != {"format", "serve"}
                or before.get("format") != 2
            ):
                raise SetupError("Tailscale rollback record is invalid")
            recorded_after = _read_owned_json(after_path) if after_path.exists() else None
            if recorded_after is not None:
                if (
                    not isinstance(recorded_after, dict)
                    or set(recorded_after) != {"format", "serve"}
                    or recorded_after.get("format") != 2
                    or _normalize_serve_config(recorded_after.get("serve")) != current
                    or not _serve_config_has_private_route(
                        current,
                        host_port=host_port,
                        port=port,
                        target=target,
                    )
                ):
                    raise SetupError("the managed Tailscale snapshot changed after setup")
                return
            listener_present = _serve_config_mentions_listener(
                current,
                host_port=host_port,
                port=port,
            )
            if current != _normalize_serve_config(before.get("serve")) and not listener_present:
                raise SetupError("the pre-setup Tailscale snapshot changed before apply completed")
            if listener_present:
                if not _serve_config_has_private_route(
                    current,
                    host_port=host_port,
                    port=port,
                    target=target,
                ):
                    raise SetupError("the managed Tailscale listener changed ownership")
                if _serve_config_without_private_route(
                    current,
                    host_port=host_port,
                    port=port,
                    target=target,
                ) != _normalize_serve_config(before.get("serve")):
                    raise SetupError("the Tailscale baseline changed concurrently with setup")
                if preflight_only:
                    return
                if recorded_after is None:
                    _create_or_verify_private_file(
                        after_path,
                        _canonical_json_bytes({"format": 2, "serve": current}),
                    )
                return
        else:
            if _serve_config_mentions_listener(current, host_port=host_port, port=port):
                raise SetupError(f"Tailscale listener {port} is already in use")
            if preflight_only:
                return
            _create_or_verify_private_file(
                record_path,
                _canonical_json_bytes({"format": 2, "serve": current}),
            )
        if preflight_only:
            return
        self._run_checked(
            ["tailscale", "serve", "--yes", "--bg", f"--https={port}", target],
            "Tailscale Serve listener could not be installed",
            timeout_seconds=15.0,
        )
        after = _normalize_serve_config(
            self._tailscale_json(
                ["tailscale", "serve", "status", "--json"],
                "Tailscale Serve verification failed",
            )
        )
        if not _serve_config_has_private_route(
            after,
            host_port=host_port,
            port=port,
            target=target,
        ):
            raise SetupError("Tailscale Serve listener did not match the requested private route")
        before = _read_owned_json(record_path)
        if _serve_config_without_private_route(
            after,
            host_port=host_port,
            port=port,
            target=target,
        ) != _normalize_serve_config(before.get("serve")):
            raise SetupError("the Tailscale baseline changed concurrently with setup")
        _create_or_verify_private_file(
            after_path,
            _canonical_json_bytes({"format": 2, "serve": after}),
        )

    def _rollback_tailnet_route(self, spec: SetupSpec) -> None:
        port = _managed_tailnet_port(spec)
        if port is None:
            return
        record_path = spec.root / "services" / "tailscale-serve-before.json"
        current = _normalize_serve_config(
            self._tailscale_json(
                ["tailscale", "serve", "status", "--json"],
                "Tailscale Serve status is unavailable",
            )
        )
        host_port = _managed_tailnet_host_port(spec, port)
        if not record_path.exists():
            if _serve_config_mentions_listener(current, host_port=host_port, port=port):
                raise SetupError("refusing Tailscale rollback without an ownership receipt")
            return
        before = _read_owned_json(record_path)
        if (
            not isinstance(before, dict)
            or set(before) != {"format", "serve"}
            or before.get("format") != 2
        ):
            raise SetupError("Tailscale rollback record is invalid")
        before_serve = _normalize_serve_config(before["serve"])
        if _serve_config_mentions_listener(before_serve, host_port=host_port, port=port):
            raise SetupError("Tailscale rollback record does not describe a free listener")
        after_path = spec.root / "services" / "tailscale-serve-after.json"
        recorded_after = _read_owned_json(after_path) if after_path.exists() else None
        if recorded_after is None:
            if current != before_serve:
                raise SetupError("Tailscale apply receipt is missing for a changed configuration")
            _remove_exact_owned_file(record_path, _canonical_json_bytes(before))
            return
        if (
            not isinstance(recorded_after, dict)
            or set(recorded_after) != {"format", "serve"}
            or recorded_after.get("format") != 2
        ):
            raise SetupError("Tailscale apply receipt is invalid")
        if current == before_serve:
            _remove_exact_owned_file(after_path, _canonical_json_bytes(recorded_after))
            _remove_exact_owned_file(record_path, _canonical_json_bytes(before))
            return
        if _normalize_serve_config(recorded_after.get("serve")) != current:
            raise SetupError("refusing to overwrite a changed Tailscale snapshot")
        target = "http://127.0.0.1:8790"
        if not _serve_config_has_private_route(
            current,
            host_port=host_port,
            port=port,
            target=target,
        ):
            raise SetupError("refusing to remove a changed Tailscale listener")
        self._run_checked(
            ["tailscale", "serve", f"--https={port}", "off"],
            "Tailscale Serve listener rollback failed",
        )
        restored = _normalize_serve_config(
            self._tailscale_json(
                ["tailscale", "serve", "status", "--json"],
                "Tailscale Serve rollback verification failed",
            )
        )
        if restored != before_serve:
            raise SetupError("Tailscale did not return to the exact pre-setup snapshot")
        _remove_exact_owned_file(after_path, _canonical_json_bytes(recorded_after))
        _remove_exact_owned_file(record_path, _canonical_json_bytes(before))

    def _tailscale_json(self, command: list[str], message: str) -> Any:
        result = self.command_runner(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        if result.returncode != 0:
            raise SetupError(message)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SetupError(message) from exc

    def _apply_hermes_profiles(self, spec: SetupSpec, setup_id: str) -> None:
        assembly = create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
            database_override=self._owned_database(spec, setup_id),
        )
        attempted_profiles: list[str] = []
        issued_token_ids: list[str] = []
        prior_revocations_unconfirmed: set[str] = set()
        try:
            for profile in spec.hermes_profiles:
                profile_dir = self._hermes_profile_directory(profile)
                try:
                    profile_identity = require_private_directory_identity(profile_dir)
                except PrivatePathError as exc:
                    raise SetupError("Hermes profile directory is unavailable or unsafe") from exc
                if _finish_hermes_snapshot_cleanup(spec, profile, setup_id=setup_id):
                    snapshot_base = _hermes_snapshot_directory(spec, profile).parent
                    if snapshot_base.exists() and not any(snapshot_base.iterdir()):
                        snapshot_base.rmdir()
                        _fsync_owned_directory(snapshot_base.parent)
                token_name = _profile_token_name(profile)
                config_path = profile_dir / "config.yaml"
                env_path = profile_dir / ".env"
                (
                    config_exists,
                    existing_config,
                    config_identity,
                    config_parent_identity,
                ) = _observe_optional_private_file(config_path)
                (
                    environment_exists,
                    existing_env,
                    environment_identity,
                    environment_parent_identity,
                ) = _observe_optional_private_file(env_path)
                if not profile_identity.same_object(
                    config_parent_identity
                ) or not profile_identity.same_object(environment_parent_identity):
                    raise SetupError("Hermes profile directory changed during setup")
                _capture_hermes_profile_snapshot(
                    spec,
                    profile,
                    profile_identity=profile_identity,
                    config=existing_config,
                    environment=existing_env,
                    config_exists=config_exists,
                    environment_exists=environment_exists,
                    setup_id=setup_id,
                )
                attempted_profiles.append(profile)
                snapshot = _read_hermes_profile_snapshot(
                    spec,
                    profile,
                    profile_directory=profile_dir,
                )
                if snapshot is None:  # pragma: no cover - captured immediately above
                    raise SetupError("Hermes profile snapshot disappeared during setup")
                snapshot_token_id = snapshot[3]
                if snapshot_token_id is not None:
                    prior_revocations_unconfirmed.add(profile)
                    assembly.token_registry.revoke(snapshot_token_id)
                    metadata = assembly.token_registry.metadata(snapshot_token_id)
                    if metadata is None or metadata.revoked_at is None:
                        raise SetupError("prior Hermes caller token revocation was not durable")
                    _clear_hermes_snapshot_token(
                        spec,
                        profile,
                        profile_directory=profile_dir,
                        token_id=snapshot_token_id,
                    )
                    prior_revocations_unconfirmed.remove(profile)
                merged = _merge_hermes_config(
                    existing_config,
                    token_name=token_name,
                    setup_id=setup_id,
                )
                token = _existing_profile_token(existing_env, token_name=token_name)
                if token is not None:
                    try:
                        principal = assembly.token_registry.authenticate(
                            f"Bearer {token}", alias="approvals"
                        )
                        if principal.namespace != f"profile:{profile}":
                            token = None
                    except CredentialError:
                        token = None
                if token is None:
                    issued = assembly.token_registry.issue(
                        f"profile:{profile}",
                        set(_PRODUCTION_MCP_ALIASES),
                    )
                    token = issued.token
                    token_id = token.removeprefix("sgt_").split(".", 1)[0]
                    issued_token_ids.append(token_id)
                    _bind_hermes_snapshot_token(
                        spec,
                        profile,
                        profile_directory=profile_dir,
                        token_id=token_id,
                    )
                updated_env = _merge_profile_environment(
                    existing_env,
                    token_name=token_name,
                    token=token,
                    setup_id=setup_id,
                )
                _replace_private_file(
                    config_path,
                    merged,
                    require_absent=not config_exists,
                    expected_content=existing_config if config_exists else None,
                    expected_parent_identity=profile_identity,
                    expected_identity=config_identity,
                    require_present=config_exists,
                )
                _replace_private_file(
                    env_path,
                    updated_env,
                    require_absent=not environment_exists,
                    expected_content=existing_env if environment_exists else None,
                    expected_parent_identity=profile_identity,
                    expected_identity=environment_identity,
                    require_present=environment_exists,
                )
        except Exception:
            try:
                for token_id in reversed(issued_token_ids):
                    assembly.token_registry.revoke(token_id)
                    metadata = assembly.token_registry.metadata(token_id)
                    if metadata is None or metadata.revoked_at is None:
                        raise SetupError("issued Hermes caller token revocation was not durable")
                for profile in reversed(attempted_profiles):
                    if profile in prior_revocations_unconfirmed:
                        continue
                    _restore_hermes_profile_snapshot(
                        spec,
                        profile,
                        profile_directory=self._hermes_profile_directory(profile),
                        token_name=_profile_token_name(profile),
                        setup_id=setup_id,
                        allow_unassigned_managed_token=True,
                    )
            except Exception as cleanup_exc:
                raise SetupError(
                    "Hermes profile rollback after an edit failure failed"
                ) from cleanup_exc
            raise
        self.output(
            "Hermes profiles staged with disabled Signet MCP entries. Signet did not restart "
            "the gateway; review and enable each entry, then run /reload-mcp in that profile."
        )

    def revoke_hermes_tokens_for_rollback(self, spec: SetupSpec, setup_id: str) -> None:
        """Durably revoke snapshot-bound callers before any enclosing DB rollback fence."""

        assembly = create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
            database_override=self._owned_database(spec, setup_id),
        )
        for profile in spec.hermes_profiles:
            profile_dir = self._hermes_profile_directory(profile)
            snapshot = _read_hermes_profile_snapshot(
                spec,
                profile,
                profile_directory=profile_dir,
            )
            if snapshot is None or snapshot[3] is None:
                continue
            token_id = snapshot[3]
            assembly.token_registry.revoke(token_id)
            metadata = assembly.token_registry.metadata(token_id)
            if metadata is None or metadata.revoked_at is None:
                raise SetupError("Hermes caller token revocation was not durable")

    def _rollback_hermes_profiles(self, spec: SetupSpec, setup_id: str) -> None:
        assembly = create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
            database_override=self._owned_database(spec, setup_id),
        )
        for profile in spec.hermes_profiles:
            profile_dir = self._hermes_profile_directory(profile)
            token_name = _profile_token_name(profile)
            if _finish_hermes_snapshot_cleanup(spec, profile, setup_id=setup_id):
                snapshot_base = _hermes_snapshot_directory(spec, profile).parent
                if snapshot_base.exists() and not any(snapshot_base.iterdir()):
                    snapshot_base.rmdir()
                continue
            config_path = profile_dir / "config.yaml"
            env_path = profile_dir / ".env"
            current_config = _read_optional_private_file(config_path)
            current_env = _read_optional_private_file(env_path)
            snapshot = _read_hermes_profile_snapshot(
                spec,
                profile,
                profile_directory=profile_dir,
            )
            token = _existing_profile_token(current_env, token_name=token_name)
            if snapshot is not None:
                managed_token_id = snapshot[3]
                allow_unassigned = managed_token_id is not None and token is None
                if not allow_unassigned and (
                    _validated_hermes_profile_snapshot_restore(
                        spec,
                        profile,
                        profile_directory=profile_dir,
                        token_name=token_name,
                        setup_id=setup_id,
                    )
                    is None
                ):
                    raise SetupError("Hermes profile snapshot disappeared during rollback")
                if managed_token_id is not None:
                    assembly.token_registry.revoke(managed_token_id)
                    token_metadata = assembly.token_registry.metadata(managed_token_id)
                    if token_metadata is None or token_metadata.revoked_at is None:
                        raise SetupError("Hermes caller token revocation was not durable")
                if allow_unassigned and (
                    _validated_hermes_profile_snapshot_restore(
                        spec,
                        profile,
                        profile_directory=profile_dir,
                        token_name=token_name,
                        setup_id=setup_id,
                        allow_unassigned_managed_token=True,
                    )
                    is None
                ):
                    raise SetupError("Hermes profile snapshot disappeared during rollback")
                _restore_hermes_profile_snapshot(
                    spec,
                    profile,
                    profile_directory=profile_dir,
                    token_name=token_name,
                    setup_id=setup_id,
                    allow_unassigned_managed_token=allow_unassigned,
                )
                continue
            if _has_profile_token_assignment(current_env, token_name=token_name) and token is None:
                raise SetupError("Hermes profile has a foreign Signet token assignment")
            desired_config = _remove_hermes_config(
                current_config,
                token_name=token_name,
                setup_id=setup_id,
            )
            desired_environment = _remove_profile_environment(
                current_env,
                token_name=token_name,
                setup_id=setup_id,
            )
            if desired_config != current_config or desired_environment != current_env:
                raise SetupError("refusing Hermes rollback without a bound profile snapshot")
            if token is not None:
                raise SetupError("refusing Hermes token rollback without a bound profile snapshot")

    def _apply_owner_bootstrap(self, spec: SetupSpec, setup_id: str) -> None:
        secret_store = KeychainSecretStore()
        assembly = create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=secret_store,
            components=frozenset(),
            database_override=self._owned_database(spec, setup_id),
        )
        bootstrap = BootstrapService(
            assembly.database,
            owner_user_id=spec.owner_user_id,
            totp_enrollments=TotpEnrollmentService(
                assembly.database,
                provisioner=KeychainTotpSecretProvisioner(),
                secret_store=secret_store,
            ),
        )
        account = _secret_account(setup_id, "browser-bootstrap")
        try:
            stored = keyring.get_password(_SERVICE_NAME, account)
        except Exception as exc:
            raise SetupError("the browser setup handoff store is unavailable") from exc
        now = _now()
        handoff_path = spec.root / ".owner-bootstrap-capability"
        handoff_exists = handoff_path.exists() or handoff_path.is_symlink()
        existing_handoff = _read_optional_private_file(handoff_path)
        handoff_capability: str | None = None
        if handoff_exists:
            handoff_capability = _decode_owner_handoff(existing_handoff)
        handoff_is_recorded = bool(
            handoff_capability is not None and bootstrap.capability_is_recorded(handoff_capability)
        )
        handoff_is_current = bool(
            handoff_capability is not None
            and bootstrap.capability_is_current(handoff_capability, now=now)
        )
        if (
            handoff_capability is not None
            and not handoff_is_recorded
            and handoff_capability != stored
        ):
            raise SetupError("the private owner setup handoff changed or is ambiguous")
        status = bootstrap.status(now=now)
        claim_is_current = _bootstrap_claim_is_current(assembly.database, now=now)
        if status.complete or claim_is_current:
            capability: str | None = None
        elif handoff_is_current:
            capability = handoff_capability
        elif stored is not None and bootstrap.capability_is_current(stored, now=now):
            capability = stored
        else:
            try:
                capability = bootstrap.issue_capability(
                    now=now,
                    replace_existing=True,
                )
            except BootstrapAlreadyComplete:
                capability = None
            except BootstrapClaimRequired:
                if not _bootstrap_claim_is_current(assembly.database, now=now):
                    raise
                capability = None
        if capability is not None and not spec.open_browser:
            _replace_private_file(
                handoff_path,
                capability.encode("utf-8") + b"\n",
                expected_content=existing_handoff,
            )
        if capability is not None and capability != stored:
            try:
                keyring.set_password(_SERVICE_NAME, account, capability)
            except Exception as exc:
                raise SetupError("the browser setup handoff could not be stored") from exc
        if (spec.open_browser or capability is None) and handoff_exists:
            if handoff_capability is None:  # pragma: no cover - validated above
                raise AssertionError("browser bootstrap handoff validation was incomplete")
            _remove_exact_owned_file(
                handoff_path,
                handoff_capability.encode("utf-8") + b"\n",
            )
        browser_assisted_setup(
            spec.public_origin,
            capability,
            output=self.output,
            opener=self.opener,
            open_browser=spec.open_browser,
            handoff_path=handoff_path if capability is not None else None,
        )

    def _rollback_owner_bootstrap(self, spec: SetupSpec, setup_id: str) -> None:
        account = _secret_account(setup_id, "browser-bootstrap")
        handoff_path = spec.root / ".owner-bootstrap-capability"
        try:
            capability = keyring.get_password(_SERVICE_NAME, account)
            if handoff_path.exists() or handoff_path.is_symlink():
                encoded_handoff = _read_optional_private_file(handoff_path)
                handoff_capability = _decode_owner_handoff(encoded_handoff)
                if capability != handoff_capability and not BootstrapService(
                    Database(spec.root / "data" / "signet.db"),
                    owner_user_id=spec.owner_user_id,
                ).capability_is_recorded(handoff_capability):
                    raise SetupError("the private owner setup handoff is ambiguous")
                _remove_exact_owned_file(
                    handoff_path,
                    encoded_handoff,
                )
            if capability is not None:
                keyring.delete_password(_SERVICE_NAME, account)
        except SetupError:
            raise
        except Exception as exc:
            raise SetupError("browser setup handoff cleanup failed") from exc

    def _run_checked(
        self,
        command: list[str],
        message: str,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        try:
            result = self.command_runner(
                command,
                text=True,
                capture_output=True,
                check=False,
                **({"timeout": timeout_seconds} if timeout_seconds is not None else {}),
            )
        except subprocess.TimeoutExpired as exc:
            raise SetupError(message) from exc
        if result.returncode != 0:
            raise SetupError(message)

    def _stop_systemd_units(self, command: list[str]) -> None:
        result = self.command_runner(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
        detail = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        already_stopped = any(
            marker in detail
            for marker in (
                "is not loaded",
                "not loaded",
                "does not exist",
                "not-found",
                "no files found",
            )
        )
        if result.returncode != 0 and not already_stopped:
            raise SetupError("systemd could not stop Signet")

    def _stop_launchd_unit(self, command: list[str]) -> None:
        result = self.command_runner(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
        detail = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        already_stopped = "no such process" in detail or "could not find service" in detail
        if result.returncode != 0 and not already_stopped:
            raise SetupError("launchd could not stop Signet")


def _json_bytes(document: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _private_path_receipt_path(root: Path, name: str) -> Path:
    return root / f"{_PRIVATE_PATH_RECEIPT_PREFIX}{name}.json"


def _private_path_pending_path(root: Path, name: str, setup_id: str) -> Path:
    digest = hashlib.sha256(f"{setup_id}:{name}".encode()).hexdigest()[:16]
    return root / f"{_PRIVATE_PATH_RECEIPT_PREFIX}{name}.{digest}.pending"


def _private_path_staging_name(name: str, setup_id: str) -> str:
    digest = hashlib.sha256(f"{setup_id}:{name}:staging".encode()).hexdigest()[:24]
    return f"{_PRIVATE_PATH_RECEIPT_PREFIX}{name}.{digest}.staging"


def _private_path_creation_intent(name: str, setup_id: str) -> dict[str, Any]:
    return {
        "format": 3,
        "setup_id": setup_id,
        "name": name,
        "staging_name": _private_path_staging_name(name, setup_id),
        "creation_state": "planned",
    }


def _read_private_path_receipt(
    path: Path,
    *,
    setup_id: str,
    expected_name: str | None = None,
    validate_tree: bool = True,
    receipt_root: Path | None = None,
) -> tuple[DirectoryIdentity, Path, bytes]:
    name = expected_name or path.name
    receipt_path = _private_path_receipt_path(receipt_root or path.parent, name)
    if not receipt_path.exists() and not receipt_path.is_symlink():
        raise SetupError(f"private setup path {name!r} has no ownership receipt")
    receipt = _read_owned_json(receipt_path)
    required = {
        "format",
        "setup_id",
        "name",
        "tree_device",
        "tree_inode",
        "tree_owner_uid",
    }
    format_version = receipt.get("format") if isinstance(receipt, dict) else None
    if format_version == 2:
        required.add("staging_name")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != required
        or format_version not in {1, 2}
        or receipt.get("setup_id") != setup_id
        or receipt.get("name") != name
        or any(
            type(receipt.get(field)) is not int
            for field in ("tree_device", "tree_inode", "tree_owner_uid")
        )
        or (
            format_version == 2
            and (
                not isinstance(receipt.get("staging_name"), str)
                or re.fullmatch(
                    rf"{re.escape(_PRIVATE_PATH_RECEIPT_PREFIX + name)}\.[A-Za-z0-9_-]+\.staging",
                    receipt["staging_name"],
                )
                is None
            )
        )
    ):
        raise SetupError(f"private setup path {name!r} ownership receipt is invalid")
    identity = DirectoryIdentity(
        path=path,
        device=receipt["tree_device"],
        inode=receipt["tree_inode"],
        owner_uid=receipt["tree_owner_uid"],
    )
    if validate_tree:
        try:
            revalidate_directory_identity(identity, private=True)
        except PrivatePathError as exc:
            raise SetupError(f"private setup path {name!r} changed after creation") from exc
    return identity, receipt_path, _json_bytes(receipt)


def _resume_receipted_private_path_staging(
    root: Path,
    name: str,
    *,
    setup_id: str,
) -> bool:
    receipt_path = _private_path_receipt_path(root, name)
    receipt = _read_owned_json(receipt_path)
    if not isinstance(receipt, dict) or receipt.get("format") != 2:
        return False
    staging_name = receipt.get("staging_name")
    if not isinstance(staging_name, str):
        raise SetupError(f"private setup path {name!r} ownership receipt is invalid")
    staging = root.parent / staging_name
    if not staging.exists() and not staging.is_symlink():
        return False
    pending = _private_path_pending_path(root, name, setup_id)
    if (
        pending.exists()
        or pending.is_symlink()
        or (root / name).exists()
        or (root / name).is_symlink()
    ):
        raise SetupError(f"private setup path {name!r} has ambiguous publication state")
    identity, _, _ = _read_private_path_receipt(
        staging,
        setup_id=setup_id,
        expected_name=name,
        receipt_root=root,
    )
    source_parent = require_owned_directory_identity(root.parent)
    target_parent = require_private_directory_identity(root)
    source_descriptor = -1
    target_descriptor = -1
    try:
        source_descriptor = os.open(
            root.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        target_descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        source_metadata = os.fstat(source_descriptor)
        target_metadata = os.fstat(target_descriptor)
        if (
            source_metadata.st_dev,
            source_metadata.st_ino,
            source_metadata.st_uid,
        ) != (source_parent.device, source_parent.inode, source_parent.owner_uid) or (
            target_metadata.st_dev,
            target_metadata.st_ino,
            target_metadata.st_uid,
        ) != (target_parent.device, target_parent.inode, target_parent.owner_uid):
            raise SetupError(f"private setup path {name!r} parent changed before publication")
        current = os.stat(staging_name, dir_fd=source_descriptor, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (identity.device, identity.inode):
            raise SetupError(f"private setup path {name!r} staging directory changed")
        rename_entry_no_replace(
            source_descriptor,
            staging_name,
            target_descriptor,
            pending.name,
        )
        moved = os.stat(pending.name, dir_fd=target_descriptor, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) != (identity.device, identity.inode):
            raise SetupError(f"private setup path {name!r} changed during staging publication")
        os.fsync(source_descriptor)
        os.fsync(target_descriptor)
        revalidate_directory_identity(source_parent, private=False)
        revalidate_directory_identity(target_parent, private=True)
    except SetupError:
        raise
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"private setup path {name!r} staging could not be published") from exc
    finally:
        if target_descriptor >= 0:
            os.close(target_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
    _read_private_path_receipt(pending, setup_id=setup_id, expected_name=name)
    return True


def _remove_unbound_private_path_staging(root: Path, staging_name: str) -> None:
    staging = root.parent / staging_name
    if not staging.exists() and not staging.is_symlink():
        return
    parent_identity = require_owned_directory_identity(root.parent)
    parent_descriptor = -1
    staging_descriptor = -1
    quarantine_name = f".signet-private-staging-remove-{secrets.token_urlsafe(24)}"
    try:
        parent_descriptor = os.open(
            root.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_parent = os.fstat(parent_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_identity.device,
            parent_identity.inode,
        ):
            raise SetupError("private path staging parent changed during recovery")
        before = os.stat(staging_name, dir_fd=parent_descriptor, follow_symlinks=False)
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(staging_descriptor)
        require_no_acl_grants(staging_descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != current_uid
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or os.listdir(staging_descriptor)
        ):
            raise SetupError("private path staging intent names an ambiguous object")
        rename_entry_no_replace(
            parent_descriptor,
            staging_name,
            parent_descriptor,
            quarantine_name,
        )
        moved = os.stat(quarantine_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) != (opened.st_dev, opened.st_ino):
            raise SetupError("private path staging changed during recovery")
        os.rmdir(quarantine_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        for removed_name in (staging_name, quarantine_name):
            try:
                os.stat(removed_name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise SetupError("private path staging removal could not be confirmed")
        revalidate_directory_identity(parent_identity, private=False)
    except SetupError:
        raise
    except (OSError, PrivatePathError) as exc:
        raise SetupError("private path staging could not be recovered safely") from exc
    finally:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _bind_private_path_creation_intent(
    root: Path,
    name: str,
    *,
    setup_id: str,
    intent: Mapping[str, Any],
    recover_existing: bool,
) -> None:
    expected_intent = _private_path_creation_intent(name, setup_id)
    if intent != expected_intent:
        raise SetupError(f"private setup path {name!r} creation intent is invalid")
    staging_name = expected_intent["staging_name"]
    assert isinstance(staging_name, str)
    staging = root.parent / staging_name
    if staging.exists() or staging.is_symlink():
        if not recover_existing:
            _remove_exact_owned_file(
                _private_path_receipt_path(root, name),
                _json_bytes(expected_intent),
                expected_parent_identity=require_private_directory_identity(root),
                parent_private=True,
            )
            raise SetupError(f"private setup path {name!r} staging appeared before creation")
        _remove_unbound_private_path_staging(root, staging_name)
    try:
        os.mkdir(staging, 0o700)
        identity = require_private_directory_identity(staging)
        _fsync_owned_directory(staging)
        parent_descriptor = os.open(
            root.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except FileExistsError as exc:
        _remove_exact_owned_file(
            _private_path_receipt_path(root, name),
            _json_bytes(expected_intent),
            expected_parent_identity=require_private_directory_identity(root),
            parent_private=True,
        )
        raise SetupError(f"private setup path {name!r} staging appeared before creation") from exc
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"private setup path {name!r} could not be created safely") from exc
    receipt = {
        "format": 2,
        "setup_id": setup_id,
        "name": name,
        "tree_device": identity.device,
        "tree_inode": identity.inode,
        "tree_owner_uid": identity.owner_uid,
        "staging_name": staging_name,
    }
    _replace_private_file(
        _private_path_receipt_path(root, name),
        _json_bytes(receipt),
        expected_content=_json_bytes(expected_intent),
        expected_parent_identity=require_private_directory_identity(root),
        require_present=True,
    )


def _create_or_verify_receipted_private_directory(
    root: Path,
    path: Path,
    *,
    setup_id: str,
) -> Path:
    if path.parent != root or path.name in {"", ".", ".."}:
        raise SetupError("private setup path is not canonical")
    receipt_path = _private_path_receipt_path(root, path.name)
    pending = _private_path_pending_path(root, path.name, setup_id)
    receipt_exists = receipt_path.exists() or receipt_path.is_symlink()
    created_intent = False
    path_exists = path.exists() or path.is_symlink()
    pending_exists = pending.exists() or pending.is_symlink()
    if not receipt_exists:
        if path_exists or pending_exists:
            raise SetupError(f"private setup path {path.name!r} has no ownership receipt")
        intent = _private_path_creation_intent(path.name, setup_id)
        staging_name = intent["staging_name"]
        assert isinstance(staging_name, str)
        staging = root.parent / staging_name
        if staging.exists() or staging.is_symlink():
            raise SetupError(f"private setup path {path.name!r} has no creation intent")
        _replace_private_file(
            receipt_path,
            _json_bytes(intent),
            require_absent=True,
            expected_parent_identity=require_private_directory_identity(root),
        )
        receipt_exists = True
        created_intent = True
    recorded = _read_owned_json(receipt_path)
    if isinstance(recorded, dict) and recorded.get("format") == 3:
        if path_exists or pending_exists:
            raise SetupError(f"private setup path {path.name!r} has ambiguous publication state")
        _bind_private_path_creation_intent(
            root,
            path.name,
            setup_id=setup_id,
            intent=recorded,
            recover_existing=not created_intent,
        )
    if receipt_exists:
        if path_exists and pending_exists:
            raise SetupError(f"private setup path {path.name!r} has ambiguous publication state")
        if path_exists:
            _read_private_path_receipt(path, setup_id=setup_id)
            return path
        if not pending_exists:
            pending_exists = _resume_receipted_private_path_staging(
                root,
                path.name,
                setup_id=setup_id,
            )
        if not pending_exists:
            raise SetupError(
                f"private setup path {path.name!r} disappeared while its ownership receipt remains"
            )
        _read_private_path_receipt(pending, setup_id=setup_id, expected_name=path.name)
    parent_descriptor = -1
    try:
        root_identity = require_private_directory_identity(root)
        parent_descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_root = os.fstat(parent_descriptor)
        if (
            opened_root.st_dev,
            opened_root.st_ino,
            opened_root.st_uid,
        ) != (root_identity.device, root_identity.inode, root_identity.owner_uid):
            raise SetupError("private path root changed before publication")
        rename_entry_no_replace(
            parent_descriptor,
            pending.name,
            parent_descriptor,
            path.name,
        )
        os.fsync(parent_descriptor)
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"private setup path {path.name!r} could not be published safely") from exc
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
    _read_private_path_receipt(path, setup_id=setup_id)
    return path


def _fsync_owned_directory(path: Path) -> None:
    descriptor = -1
    try:
        identity = require_private_directory_identity(path)
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (identity.device, identity.inode):
            raise SetupError("owned directory changed before durability barrier")
        os.fsync(descriptor)
    except (OSError, PrivatePathError) as exc:
        raise SetupError("owned directory could not be made durable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _owned_runtime_file_identity(path: Path) -> dict[str, int]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        named = path.stat(follow_symlinks=False)
        require_no_acl_grants(descriptor)
    except (OSError, PrivatePathError) as exc:
        raise SetupError("database runtime artifact ownership could not be recorded") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != current_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino)
    ):
        raise SetupError("database runtime artifact is not an owned private regular file")
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _database_runtime_quarantine_name(
    setup_id: str,
    name: str,
    identity: Mapping[str, int],
) -> str:
    digest = hashlib.sha256(
        f"{setup_id}\0{name}\0{identity['device']}\0{identity['inode']}".encode()
    ).hexdigest()
    return f".signet-runtime-remove-{digest}"


def _publish_database_ownership(
    database_path: Path,
    marker: Path,
    *,
    data_identity: DirectoryIdentity,
    setup_id: str,
    bound_initializing: dict[str, Any] | None,
) -> None:
    database_descriptor = -1
    try:
        database_descriptor = os.open(
            database_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        database_identity = os.fstat(database_descriptor)
        require_no_acl_grants(database_descriptor)
        named_database = database_path.stat(follow_symlinks=False)
    except (OSError, PrivatePathError) as exc:
        raise SetupError("database ownership could not be recorded safely") from exc
    finally:
        if database_descriptor >= 0:
            os.close(database_descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if (
        not stat.S_ISREG(database_identity.st_mode)
        or database_identity.st_uid != current_uid
        or database_identity.st_nlink != 1
        or stat.S_IMODE(database_identity.st_mode) != 0o600
        or (named_database.st_dev, named_database.st_ino)
        != (database_identity.st_dev, database_identity.st_ino)
    ):
        raise SetupError("database ownership could not be recorded safely")
    runtime_files: dict[str, dict[str, int]] = {}
    for child in database_path.parent.iterdir():
        if child.name == _DATABASE_OWNERSHIP_MARKER:
            continue
        if child.name not in _DATABASE_RUNTIME_NAMES:
            raise SetupError("database directory contains an unowned runtime artifact")
        runtime_files[child.name] = _owned_runtime_file_identity(child)
    if "signet.db" not in runtime_files:
        raise SetupError("database ownership could not be recorded safely")
    ownership = {
        "format": 3,
        "setup_id": setup_id,
        "data_device": data_identity.device,
        "data_inode": data_identity.inode,
        "data_owner_uid": data_identity.owner_uid,
        "database_device": database_identity.st_dev,
        "database_inode": database_identity.st_ino,
        "runtime_files": runtime_files,
        "removal_phase": "active",
        "quarantine": {
            name: _database_runtime_quarantine_name(setup_id, name, identity)
            for name, identity in runtime_files.items()
        },
    }
    ownership_bytes = _json_bytes(ownership)
    if bound_initializing is not None:
        _replace_private_file(
            marker,
            ownership_bytes,
            expected_content=_json_bytes(bound_initializing),
            expected_parent_identity=data_identity,
            require_present=True,
        )
    else:
        _create_or_verify_private_file(marker, ownership_bytes)


def _validate_active_database_ownership(
    data_directory: Path,
    ownership: Mapping[str, Any],
    *,
    setup_id: str,
    data_identity: DirectoryIdentity,
) -> None:
    integer_fields = {
        "data_device",
        "data_inode",
        "data_owner_uid",
        "database_device",
        "database_inode",
    }
    required = {
        "format",
        "setup_id",
        "runtime_files",
        "removal_phase",
        "quarantine",
        *integer_fields,
    }
    runtime_files = ownership.get("runtime_files")
    quarantine = ownership.get("quarantine")
    if (
        set(ownership) != required
        or ownership.get("format") != 3
        or ownership.get("setup_id") != setup_id
        or ownership.get("removal_phase") != "active"
        or any(type(ownership.get(field)) is not int for field in integer_fields)
        or not isinstance(runtime_files, dict)
        or not isinstance(quarantine, dict)
        or (
            ownership.get("data_device"),
            ownership.get("data_inode"),
            ownership.get("data_owner_uid"),
        )
        != (data_identity.device, data_identity.inode, data_identity.owner_uid)
    ):
        raise SetupError("database ownership receipt is invalid")
    if set(runtime_files) != set(quarantine) or "signet.db" not in runtime_files:
        raise SetupError("database ownership receipt is invalid")
    for name, identity in runtime_files.items():
        if (
            name not in _DATABASE_RUNTIME_NAMES
            or not isinstance(identity, dict)
            or set(identity) != {"device", "inode"}
            or any(type(identity.get(field)) is not int for field in ("device", "inode"))
            or quarantine.get(name) != _database_runtime_quarantine_name(setup_id, name, identity)
        ):
            raise SetupError("database ownership receipt is invalid")
    if runtime_files["signet.db"] != {
        "device": ownership["database_device"],
        "inode": ownership["database_inode"],
    }:
        raise SetupError("database ownership receipt is invalid")
    current_names = {
        child.name for child in data_directory.iterdir() if child.name != _DATABASE_OWNERSHIP_MARKER
    }
    allowed_names = {
        "signet.db",
        ".signet.db.maintenance.lock",
        "signet.db-wal",
        "signet.db-shm",
        "signet.db-journal",
    }
    stable_names = {"signet.db", ".signet.db.maintenance.lock"}
    if not stable_names <= current_names or not current_names <= allowed_names:
        raise SetupError("database directory contains an unowned runtime artifact")
    if not stable_names <= set(runtime_files) or not set(runtime_files) <= allowed_names:
        raise SetupError("database ownership receipt runtime inventory is invalid")
    for name in stable_names:
        if _owned_runtime_file_identity(data_directory / name) != runtime_files[name]:
            raise SetupError(_runtime_identity_error(name))
    for name in current_names - stable_names:
        _owned_runtime_file_identity(data_directory / name)


def validate_active_database_runtime_ownership(
    data_directory: Path,
    *,
    setup_id: str,
) -> tuple[tuple[int, int], tuple[int, int]]:
    """Validate the setup receipt and return the bound database and lock identities."""

    try:
        data_identity = require_private_directory_identity(data_directory)
    except PrivatePathError as exc:
        raise SetupError("database directory ownership could not be verified") from exc
    ownership = _read_owned_json(data_directory / _DATABASE_OWNERSHIP_MARKER)
    if not isinstance(ownership, dict):
        raise SetupError("database ownership receipt is invalid")
    _validate_active_database_ownership(
        data_directory,
        ownership,
        setup_id=setup_id,
        data_identity=data_identity,
    )
    database_identity = ownership["runtime_files"]["signet.db"]
    lock_identity = ownership["runtime_files"][".signet.db.maintenance.lock"]
    return (
        (int(database_identity["device"]), int(database_identity["inode"])),
        (int(lock_identity["device"]), int(lock_identity["inode"])),
    )


def validate_active_database_ownership(
    data_directory: Path,
    *,
    setup_id: str,
) -> tuple[int, int]:
    """Validate the setup receipt and return the bound main-database identity."""

    database_identity, _lock_identity = validate_active_database_runtime_ownership(
        data_directory,
        setup_id=setup_id,
    )
    return database_identity


def _runtime_identity_error(logical_name: str) -> str:
    if logical_name == "signet.db":
        return "database changed after setup ownership was recorded"
    return "database runtime artifact changed after ownership was recorded"


def _open_verified_owned_runtime_entry(
    parent_descriptor: int,
    entry_name: str,
    *,
    expected_identity: tuple[int, int],
    logical_name: str,
) -> int:
    descriptor = os.open(
        entry_name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_descriptor,
    )
    try:
        metadata = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        current = os.stat(entry_name, dir_fd=parent_descriptor, follow_symlinks=False)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != current_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or (current.st_dev, current.st_ino) != expected_identity
            or (metadata.st_dev, metadata.st_ino) != expected_identity
        ):
            raise SetupError(_runtime_identity_error(logical_name))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_owned_runtime_entry(
    parent_descriptor: int,
    entry_name: str,
    *,
    expected_identity: tuple[int, int],
    logical_name: str,
) -> None:
    descriptor = _open_verified_owned_runtime_entry(
        parent_descriptor,
        entry_name,
        expected_identity=expected_identity,
        logical_name=logical_name,
    )
    os.close(descriptor)


def _quarantine_owned_runtime_file(
    parent_descriptor: int,
    name: str,
    quarantine: str,
    *,
    expected_identity: tuple[int, int],
) -> None:
    descriptor = _open_verified_owned_runtime_entry(
        parent_descriptor,
        name,
        expected_identity=expected_identity,
        logical_name=name,
    )
    try:
        rename_entry_no_replace(
            parent_descriptor,
            name,
            parent_descriptor,
            quarantine,
        )
        moved = os.stat(quarantine, dir_fd=parent_descriptor, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) != expected_identity:
            raise SetupError("database runtime file changed during quarantine")
    finally:
        os.close(descriptor)


def _remove_quarantined_runtime_file(
    parent_descriptor: int,
    quarantine: str,
    *,
    expected_identity: tuple[int, int],
    logical_name: str,
) -> None:
    try:
        descriptor = _open_verified_owned_runtime_entry(
            parent_descriptor,
            quarantine,
            expected_identity=expected_identity,
            logical_name=logical_name,
        )
    except FileNotFoundError:
        return
    removal_name = f".signet-runtime-delete-{secrets.token_urlsafe(24)}"
    try:
        rename_entry_no_replace(
            parent_descriptor,
            quarantine,
            parent_descriptor,
            removal_name,
        )
        moved = os.stat(removal_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) != expected_identity:
            with suppress(OSError, PrivatePathError):
                rename_entry_no_replace(
                    parent_descriptor,
                    removal_name,
                    parent_descriptor,
                    quarantine,
                )
            raise SetupError("database runtime file changed during final removal")
        os.unlink(removal_name, dir_fd=parent_descriptor)
        if os.fstat(descriptor).st_nlink != 0:
            raise SetupError("database runtime file deletion could not be confirmed")
    except FileNotFoundError as exc:
        raise SetupError("database runtime file cleanup state is uncertain") from exc
    except (OSError, PrivatePathError) as exc:
        raise SetupError("database runtime file could not be removed safely") from exc
    finally:
        os.close(descriptor)


def _secret_account(setup_id: str, purpose: str) -> str:
    return f"{setup_id}-{purpose}"


def _bootstrap_claim_is_current(database: Database, *, now: int) -> bool:
    with database.read() as connection:
        state = connection.execute(
            """
            SELECT claimed_at, capability_expires_at
            FROM browser_bootstrap_state WHERE state_id = 1
            """
        ).fetchone()
    return bool(
        state is not None
        and state["claimed_at"] is not None
        and state["capability_expires_at"] is not None
        and now < int(state["capability_expires_at"])
    )


def _decode_owner_handoff(encoded: bytes) -> str:
    try:
        capability = encoded.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError:
        raise SetupError("the private owner setup handoff changed or is ambiguous") from None
    if not capability or encoded != capability.encode("utf-8") + b"\n":
        raise SetupError("the private owner setup handoff changed or is ambiguous")
    return capability


def _secret_reference(setup_id: str, purpose: str) -> str:
    return f"keychain://{_SERVICE_NAME}/{_secret_account(setup_id, purpose)}"


def _create_or_verify_private_file(
    path: Path,
    content: bytes,
    *,
    parent_private: bool = True,
) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink():
            raise SetupError(f"refusing symbolic-link resource: {path}")
        try:
            metadata = path.stat()
            existing = path.read_bytes()
        except OSError as exc:
            raise SetupError(f"owned resource is unavailable: {path}") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or existing != content
        ):
            raise SetupError(f"existing resource is foreign or ambiguous: {path}")
        return
    _replace_private_file(
        path,
        content,
        require_absent=True,
        parent_private=parent_private,
    )


def _require_exact_owned_file(path: Path, content: bytes) -> None:
    if not path.exists() or path.is_symlink():
        raise SetupError(f"owned resource is unavailable: {path}")
    try:
        metadata = path.stat()
        actual = path.read_bytes()
    except OSError as exc:
        raise SetupError(f"owned resource is unavailable: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or actual != content
    ):
        raise SetupError(f"owned resource changed or is ambiguous: {path}")


def _replace_private_file(
    path: Path,
    content: bytes,
    *,
    require_absent: bool = False,
    parent_private: bool = True,
    expected_content: bytes | None = None,
    expected_parent_identity: DirectoryIdentity | None = None,
    expected_identity: tuple[int, int] | None = None,
    require_present: bool = False,
) -> None:
    if require_absent and require_present:
        raise ValueError("private resource cannot be both required absent and present")
    try:
        if expected_parent_identity is not None:
            parent = revalidate_directory_identity(
                expected_parent_identity,
                private=parent_private,
            )
        else:
            prepare_parent = ensure_private_directory if parent_private else ensure_owned_directory
            parent = prepare_parent(path.parent)
            identity_reader = (
                require_private_directory_identity
                if parent_private
                else require_owned_directory_identity
            )
            expected_parent_identity = identity_reader(parent)
    except PrivatePathError as exc:
        raise SetupError(f"private resource parent is unsafe: {path.parent}") from exc
    if parent != path.parent:
        raise SetupError(f"private resource parent is not canonical: {path.parent}")
    temporary_name = f".{path.name}.{secrets.token_urlsafe(16)}.tmp"
    parent_descriptor = -1
    descriptor: int | None = None
    target_descriptor: int | None = None
    temporary_identity: tuple[int, int] | None = None
    try:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_parent = os.fstat(parent_descriptor)
        assert expected_parent_identity is not None
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            expected_parent_identity.device,
            expected_parent_identity.inode,
        ):
            raise SetupError(f"private resource parent changed: {path.parent}")
        observed_target_identity = _require_publish_target(
            parent_descriptor,
            path,
            require_absent=require_absent,
            require_present=require_present,
            expected_content=expected_content,
            expected_identity=expected_identity,
        )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        temporary_identity = (created.st_dev, created.st_ino)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short private-file write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        opened_target = _open_publish_target(
            parent_descriptor,
            path,
            require_absent=require_absent,
            require_present=require_present,
            expected_content=expected_content,
            expected_identity=expected_identity,
        )
        if opened_target is None:
            target_identity = None
        else:
            target_descriptor, target_identity = opened_target
        if target_identity != observed_target_identity:
            raise SetupError(f"owned resource changed or is ambiguous: {path}")
        if target_identity is None:
            try:
                rename_entry_no_replace(
                    parent_descriptor,
                    temporary_name,
                    parent_descriptor,
                    path.name,
                )
            except FileExistsError as exc:
                raise SetupError(f"resource already exists: {path}") from exc
            published = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (published.st_dev, published.st_ino) != temporary_identity:
                raise SetupError(f"private resource publication changed: {path}")
            temporary_identity = None
        else:
            exchange_entries(
                parent_descriptor,
                temporary_name,
                parent_descriptor,
                path.name,
            )
            displaced = os.stat(
                temporary_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            published = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            displaced_identity = (displaced.st_dev, displaced.st_ino)
            published_identity = (published.st_dev, published.st_ino)
            assert target_descriptor is not None
            guarded = os.fstat(target_descriptor)
            guarded_identity = (guarded.st_dev, guarded.st_ino)
            guarded_content_matches = True
            if expected_content is not None:
                os.lseek(target_descriptor, 0, os.SEEK_SET)
                guarded_content_matches = (
                    _read_owned_descriptor(target_descriptor, len(expected_content) + 1)
                    == expected_content
                )
            if (
                displaced_identity != target_identity
                or published_identity != temporary_identity
                or guarded_identity != target_identity
                or not stat.S_ISREG(guarded.st_mode)
                or guarded.st_nlink != 1
                or not guarded_content_matches
            ):
                if published_identity == temporary_identity:
                    try:
                        exchange_entries(
                            parent_descriptor,
                            temporary_name,
                            parent_descriptor,
                            path.name,
                        )
                    except (OSError, PrivatePathError) as exc:
                        raise SetupError(
                            f"private resource publication rollback is uncertain: {path}"
                        ) from exc
                raise SetupError(f"owned resource changed or is ambiguous: {path}")
            _remove_owned_private_entry(
                parent_descriptor,
                temporary_name,
                expected_identity=target_identity,
                label=str(path),
            )
            temporary_identity = None
        os.fsync(parent_descriptor)
        try:
            assert expected_parent_identity is not None
            revalidate_directory_identity(expected_parent_identity, private=parent_private)
        except PrivatePathError as exc:
            raise SetupError(f"private resource parent changed: {path.parent}") from exc
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"private resource could not be published: {path}") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if target_descriptor is not None:
            with suppress(OSError):
                os.close(target_descriptor)
        if parent_descriptor >= 0:
            primary = sys.exception()
            cleanup_failure: SetupError | None = None
            if temporary_identity is not None:
                try:
                    _remove_owned_private_entry(
                        parent_descriptor,
                        temporary_name,
                        expected_identity=temporary_identity,
                        label=str(path),
                    )
                except SetupError as cleanup_error:
                    cleanup_failure = cleanup_error
            os.close(parent_descriptor)
            if cleanup_failure is not None:
                if primary is None:
                    raise cleanup_failure
                primary.add_note(f"private publication cleanup is uncertain: {cleanup_failure}")


def _require_publish_target(
    parent_descriptor: int,
    path: Path,
    *,
    require_absent: bool,
    require_present: bool,
    expected_content: bytes | None,
    expected_identity: tuple[int, int] | None,
) -> tuple[int, int] | None:
    opened = _open_publish_target(
        parent_descriptor,
        path,
        require_absent=require_absent,
        require_present=require_present,
        expected_content=expected_content,
        expected_identity=expected_identity,
    )
    if opened is None:
        return None
    descriptor, identity = opened
    try:
        return identity
    finally:
        os.close(descriptor)


def _open_publish_target(
    parent_descriptor: int,
    path: Path,
    *,
    require_absent: bool,
    require_present: bool,
    expected_content: bytes | None,
    expected_identity: tuple[int, int] | None,
) -> tuple[int, tuple[int, int]] | None:
    target_descriptor = -1
    retain_descriptor = False
    try:
        target_descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        if (
            require_present
            or expected_identity is not None
            or (expected_content is not None and expected_content != b"")
        ):
            raise SetupError(f"owned resource changed or is ambiguous: {path}") from None
        return None
    except OSError as exc:
        raise SetupError(f"owned resource changed or is ambiguous: {path}") from exc
    try:
        if require_absent:
            raise SetupError(f"resource already exists: {path}")
        metadata = os.fstat(target_descriptor)
        require_no_acl_grants(target_descriptor)
        named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != current_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino)
            or expected_identity is not None
            and (metadata.st_dev, metadata.st_ino) != expected_identity
        ):
            raise SetupError(f"owned resource changed or is ambiguous: {path}")
        if expected_content is not None:
            actual = _read_owned_descriptor(target_descriptor, len(expected_content) + 1)
            if actual != expected_content:
                raise SetupError(f"owned resource changed or is ambiguous: {path}")
        identity = (metadata.st_dev, metadata.st_ino)
        retain_descriptor = True
        return target_descriptor, identity
    except PrivatePathError as exc:
        raise SetupError(f"owned resource changed or is ambiguous: {path}") from exc
    finally:
        if target_descriptor >= 0 and not retain_descriptor:
            os.close(target_descriptor)


def _remove_owned_private_entry(
    parent_descriptor: int,
    name: str,
    *,
    expected_identity: tuple[int, int],
    label: str,
) -> None:
    descriptor = -1
    removal_name = f".signet-private-remove-{secrets.token_urlsafe(24)}"
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != expected_identity or (
            current.st_dev,
            current.st_ino,
        ) != expected_identity:
            raise SetupError(f"refusing to remove changed private resource: {label}")
        rename_entry_no_replace(
            parent_descriptor,
            name,
            parent_descriptor,
            removal_name,
        )
        moved = os.stat(removal_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) != expected_identity:
            with suppress(OSError, PrivatePathError):
                rename_entry_no_replace(
                    parent_descriptor,
                    removal_name,
                    parent_descriptor,
                    name,
                )
            raise SetupError(f"refusing to remove changed private resource: {label}")
        os.unlink(removal_name, dir_fd=parent_descriptor)
        if os.fstat(descriptor).st_nlink != 0:
            raise SetupError(f"private resource deletion could not be confirmed: {label}")
    except FileNotFoundError as exc:
        raise SetupError(f"private resource cleanup is uncertain: {label}") from exc
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"private resource could not be removed safely: {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_exact_owned_file(path: Path, expected: bytes) -> None:
    _inspect_exact_owned_file(path, expected)


def _remove_exact_owned_file(
    path: Path,
    expected: bytes,
    *,
    expected_parent_identity: DirectoryIdentity | None = None,
    expected_identity: tuple[int, int] | None = None,
    parent_private: bool = False,
) -> None:
    inspected = _inspect_exact_owned_file(
        path,
        expected,
        expected_parent_identity=expected_parent_identity,
        parent_private=parent_private,
    )
    if inspected is None:
        return
    metadata, parent_identity = inspected
    if (
        expected_identity is not None
        and (
            metadata.st_dev,
            metadata.st_ino,
        )
        != expected_identity
    ):
        raise SetupError(f"refusing to remove changed or foreign resource: {path}")
    _quarantine_and_remove_owned_file(
        path,
        expected,
        metadata=metadata,
        parent_identity=parent_identity,
    )


def _quarantine_and_remove_owned_file(
    path: Path,
    expected: bytes,
    *,
    metadata: os.stat_result,
    parent_identity: DirectoryIdentity,
) -> None:
    quarantine_name = f".signet-remove-{secrets.token_urlsafe(32)}"
    parent_descriptor = -1
    quarantine_descriptor = -1
    owned_descriptor = -1
    try:
        revalidate_directory_identity(parent_identity, private=False)
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened_parent = os.fstat(parent_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_identity.device,
            parent_identity.inode,
        ):
            raise SetupError(f"owned resource parent changed: {path.parent}")
        os.mkdir(quarantine_name, mode=0o700, dir_fd=parent_descriptor)
        quarantine_descriptor = os.open(
            quarantine_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        os.fchmod(quarantine_descriptor, 0o700)
        require_no_acl_grants(quarantine_descriptor)
        current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SetupError(f"refusing to remove changed or foreign resource: {path}")
        os.rename(
            path.name,
            "owned",
            src_dir_fd=parent_descriptor,
            dst_dir_fd=quarantine_descriptor,
        )
        try:
            owned_descriptor = os.open(
                "owned",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=quarantine_descriptor,
            )
            moved = os.fstat(owned_descriptor)
            require_no_acl_grants(owned_descriptor)
            actual = _read_owned_descriptor(owned_descriptor, len(expected) + 1)
            named = os.stat("owned", dir_fd=quarantine_descriptor, follow_symlinks=False)
        except (OSError, PrivatePathError):
            _restore_quarantined_file(path, parent_descriptor, quarantine_descriptor)
            raise
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            (moved.st_dev, moved.st_ino) != (metadata.st_dev, metadata.st_ino)
            or (named.st_dev, named.st_ino) != (moved.st_dev, moved.st_ino)
            or not stat.S_ISREG(moved.st_mode)
            or moved.st_nlink != 1
            or moved.st_uid != current_uid
            or stat.S_IMODE(moved.st_mode) != 0o600
            or actual != expected
        ):
            os.close(owned_descriptor)
            owned_descriptor = -1
            _restore_quarantined_file(path, parent_descriptor, quarantine_descriptor)
            raise SetupError(f"refusing to remove changed or foreign resource: {path}")
        os.unlink("owned", dir_fd=quarantine_descriptor)
        if os.fstat(owned_descriptor).st_nlink != 0:
            raise SetupError(f"owned resource deletion lost its verified inode: {path}")
        os.close(owned_descriptor)
        owned_descriptor = -1
        os.fsync(parent_descriptor)
    except SetupError:
        raise
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"owned resource could not be removed safely: {path}") from exc
    finally:
        if owned_descriptor >= 0:
            os.close(owned_descriptor)
        if quarantine_descriptor >= 0:
            os.close(quarantine_descriptor)
        if parent_descriptor >= 0:
            with suppress(OSError):
                os.rmdir(quarantine_name, dir_fd=parent_descriptor)
            os.close(parent_descriptor)


def _restore_quarantined_file(
    path: Path,
    parent_descriptor: int,
    quarantine_descriptor: int,
) -> None:
    try:
        os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        os.rename(
            "owned",
            path.name,
            src_dir_fd=quarantine_descriptor,
            dst_dir_fd=parent_descriptor,
        )


def _inspect_exact_owned_file(
    path: Path,
    expected: bytes,
    *,
    expected_parent_identity: DirectoryIdentity | None = None,
    parent_private: bool = False,
) -> tuple[os.stat_result, DirectoryIdentity] | None:
    if not path.exists() and not path.is_symlink():
        return None
    descriptor = -1
    parent_identity = expected_parent_identity or require_owned_directory_identity(path.parent)
    if expected_parent_identity is not None:
        try:
            revalidate_directory_identity(parent_identity, private=parent_private)
        except PrivatePathError as exc:
            raise SetupError(f"owned resource parent changed: {path.parent}") from exc
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        actual = _read_owned_descriptor(descriptor, len(expected) + 1)
        current = path.lstat()
        revalidate_directory_identity(parent_identity, private=parent_private)
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"owned resource could not be inspected: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != current_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or actual != expected
        or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
    ):
        raise SetupError(f"refusing to remove changed or foreign resource: {path}")
    return metadata, parent_identity


def _read_owned_descriptor(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_optional_private_file(path: Path) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise SetupError(f"profile resource is unavailable or unsafe: {path}") from exc
    try:
        before = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        encoded = _read_owned_descriptor(descriptor, 1_048_577)
        after = os.fstat(descriptor)
        current = path.lstat()
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"profile resource is unavailable or unsafe: {path}") from exc
    finally:
        os.close(descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != current_uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise SetupError(f"profile resource is not an owned private regular file: {path}")
    if identity != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or identity != (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    ):
        raise SetupError(f"profile resource changed during inspection: {path}")
    if len(encoded) > 1_048_576 or b"\x00" in encoded:
        raise SetupError(f"profile resource is invalid or too large: {path}")
    return encoded


def _observe_optional_private_file(
    path: Path,
) -> tuple[bool, bytes, tuple[int, int] | None, DirectoryIdentity]:
    try:
        parent_identity = require_private_directory_identity(path.parent)
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except (OSError, PrivatePathError) as exc:
        raise SetupError(
            f"profile resource parent is unavailable or unsafe: {path.parent}"
        ) from exc
    descriptor = -1
    try:
        opened_parent = os.fstat(parent_descriptor)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_identity.device,
            parent_identity.inode,
        ):
            raise SetupError(f"profile resource parent changed during inspection: {path.parent}")
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            revalidate_directory_identity(parent_identity, private=True)
            return False, b"", None, parent_identity
        metadata = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        encoded = _read_owned_descriptor(descriptor, 1_048_577)
        after = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        revalidate_directory_identity(parent_identity, private=True)
    except (OSError, PrivatePathError) as exc:
        raise SetupError(f"profile resource is unavailable or unsafe: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)
    current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    identity = (metadata.st_dev, metadata.st_ino)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != current_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        or (named.st_dev, named.st_ino) != identity
        or len(encoded) > 1_048_576
        or b"\x00" in encoded
    ):
        raise SetupError(f"profile resource changed during inspection: {path}")
    return True, encoded, identity, parent_identity


def _hermes_snapshot_directory(spec: SetupSpec, profile: str) -> Path:
    profile_id = hashlib.sha256(profile.encode("utf-8")).hexdigest()[:24]
    return spec.root / "services" / "hermes-profile-snapshots" / profile_id


def _hermes_resource_matches_snapshot(
    current: bytes,
    *,
    current_exists: bool,
    original: bytes | None,
    remove_managed: Callable[[bytes], bytes],
) -> bool:
    expected = original or b""
    original_exists = original is not None
    if current_exists == original_exists and current == expected:
        return True
    return current_exists and current != expected and remove_managed(current) == expected


def _capture_hermes_profile_snapshot(
    spec: SetupSpec,
    profile: str,
    *,
    profile_identity: DirectoryIdentity,
    config: bytes,
    environment: bytes,
    config_exists: bool,
    environment_exists: bool,
    setup_id: str | None = None,
) -> None:
    base = ensure_private_directory(spec.root / "services" / "hermes-profile-snapshots")
    directory = ensure_private_directory(_hermes_snapshot_directory(spec, profile))
    metadata_path = directory / "metadata.json"
    if metadata_path.exists() or metadata_path.is_symlink():
        snapshot = _read_hermes_profile_snapshot(
            spec,
            profile,
            profile_directory=profile_identity.path,
        )
        if snapshot is None:  # pragma: no cover
            raise SetupError("Hermes profile snapshot disappeared during validation")
        if not snapshot[0].same_object(profile_identity):
            raise SetupError("Hermes profile directory changed after its setup snapshot")
        if setup_id is not None:
            token_name = _profile_token_name(profile)
            if not _hermes_resource_matches_snapshot(
                config,
                current_exists=config_exists,
                original=snapshot[1],
                remove_managed=lambda value: _remove_hermes_config(
                    value,
                    token_name=token_name,
                    setup_id=setup_id,
                ),
            ):
                raise SetupError("Hermes profile config changed after its setup snapshot")
            if not _hermes_resource_matches_snapshot(
                environment,
                current_exists=environment_exists,
                original=snapshot[2],
                remove_managed=lambda value: _remove_profile_environment(
                    value,
                    token_name=token_name,
                    setup_id=setup_id,
                ),
            ):
                raise SetupError("Hermes profile environment changed after its setup snapshot")
        return
    metadata = {
        "format": 3,
        "profile": profile,
        "profile_device": profile_identity.device,
        "profile_inode": profile_identity.inode,
        "profile_owner_uid": profile_identity.owner_uid,
        "config_present": config_exists,
        "config_sha256": hashlib.sha256(config).hexdigest() if config_exists else None,
        "environment_present": environment_exists,
        "environment_sha256": (
            hashlib.sha256(environment).hexdigest() if environment_exists else None
        ),
        "managed_token_id": None,
    }
    if config_exists:
        _create_or_verify_private_file(directory / "config.yaml", config)
    if environment_exists:
        _create_or_verify_private_file(directory / "environment", environment)
    _create_or_verify_private_file(metadata_path, _canonical_json_bytes(metadata))
    if base != directory.parent:  # pragma: no cover - defensive path invariant
        raise SetupError("Hermes snapshot path escaped its private root")


def _read_hermes_profile_snapshot(
    spec: SetupSpec,
    profile: str,
    *,
    profile_directory: Path,
) -> tuple[DirectoryIdentity, bytes | None, bytes | None, str | None] | None:
    directory = _hermes_snapshot_directory(spec, profile)
    metadata_path = directory / "metadata.json"
    if not metadata_path.exists() and not metadata_path.is_symlink():
        return None
    metadata = _read_owned_json(metadata_path)
    common_keys = {
        "format",
        "profile",
        "config_present",
        "config_sha256",
        "environment_present",
        "environment_sha256",
    }
    format_two_keys = common_keys | {
        "profile_device",
        "profile_inode",
        "profile_owner_uid",
    }
    format_three_keys = format_two_keys | {"managed_token_id"}
    if not isinstance(metadata, dict) or metadata.get("profile") != profile:
        raise SetupError("Hermes profile snapshot metadata is invalid")
    try:
        if (
            metadata.get("format") not in {2, 3}
            or (metadata.get("format") == 2 and set(metadata) != format_two_keys)
            or (metadata.get("format") == 3 and set(metadata) != format_three_keys)
        ):
            raise SetupError("Hermes profile snapshot metadata is invalid")
        if any(
            type(metadata[key]) is not int
            for key in ("profile_device", "profile_inode", "profile_owner_uid")
        ):
            raise SetupError("Hermes profile snapshot metadata is invalid")
        managed_token_id = metadata.get("managed_token_id")
        if managed_token_id is not None and (
            not isinstance(managed_token_id, str)
            or not 1 <= len(managed_token_id) <= 256
            or not managed_token_id.isascii()
            or any(not (character.isalnum() or character in "_-") for character in managed_token_id)
        ):
            raise SetupError("Hermes profile snapshot metadata is invalid")
        profile_identity = DirectoryIdentity(
            path=profile_directory,
            device=metadata["profile_device"],
            inode=metadata["profile_inode"],
            owner_uid=metadata["profile_owner_uid"],
        )
        revalidate_directory_identity(profile_identity, private=True)
    except (TypeError, ValueError, PrivatePathError) as exc:
        raise SetupError("Hermes profile directory changed after its setup snapshot") from exc

    def snapshot_file(name: str, present_key: str, digest_key: str) -> bytes | None:
        path = directory / name
        present = metadata[present_key]
        digest = metadata[digest_key]
        if not isinstance(present, bool):
            raise SetupError("Hermes profile snapshot metadata is invalid")
        if not present:
            if digest is not None or path.exists() or path.is_symlink():
                raise SetupError("Hermes profile snapshot metadata is inconsistent")
            return None
        encoded = _read_optional_private_file(path)
        if not isinstance(digest, str) or hashlib.sha256(encoded).hexdigest() != digest:
            raise SetupError("Hermes profile snapshot content changed")
        return encoded

    return (
        profile_identity,
        snapshot_file("config.yaml", "config_present", "config_sha256"),
        snapshot_file("environment", "environment_present", "environment_sha256"),
        managed_token_id,
    )


def _bind_hermes_snapshot_token(
    spec: SetupSpec,
    profile: str,
    *,
    profile_directory: Path,
    token_id: str,
) -> None:
    snapshot = _read_hermes_profile_snapshot(
        spec,
        profile,
        profile_directory=profile_directory,
    )
    if snapshot is None:
        raise SetupError("Hermes profile token cannot be bound without a setup snapshot")
    metadata_path = _hermes_snapshot_directory(spec, profile) / "metadata.json"
    metadata_exists, metadata_bytes, metadata_identity, metadata_parent_identity = (
        _observe_optional_private_file(metadata_path)
    )
    if not metadata_exists:
        raise SetupError("Hermes profile snapshot metadata disappeared")
    try:
        metadata = json.loads(metadata_bytes)
    except json.JSONDecodeError as exc:
        raise SetupError("Hermes profile snapshot metadata is invalid") from exc
    if not isinstance(metadata, dict):  # pragma: no cover - validated above
        raise SetupError("Hermes profile snapshot metadata is invalid")
    existing = snapshot[3]
    if existing not in {None, token_id}:
        raise SetupError("Hermes profile snapshot is bound to a different token")
    if existing == token_id:
        return
    updated = {**metadata, "format": 3, "managed_token_id": token_id}
    _replace_private_file(
        metadata_path,
        _canonical_json_bytes(updated),
        expected_content=metadata_bytes,
        expected_parent_identity=metadata_parent_identity,
        expected_identity=metadata_identity,
        require_present=True,
    )


def _clear_hermes_snapshot_token(
    spec: SetupSpec,
    profile: str,
    *,
    profile_directory: Path,
    token_id: str,
) -> None:
    snapshot = _read_hermes_profile_snapshot(
        spec,
        profile,
        profile_directory=profile_directory,
    )
    if snapshot is None or snapshot[3] != token_id:
        raise SetupError("Hermes profile snapshot token binding changed before revocation")
    metadata_path = _hermes_snapshot_directory(spec, profile) / "metadata.json"
    metadata_exists, metadata_bytes, metadata_identity, metadata_parent_identity = (
        _observe_optional_private_file(metadata_path)
    )
    if not metadata_exists:
        raise SetupError("Hermes profile snapshot metadata disappeared")
    try:
        metadata = json.loads(metadata_bytes)
    except json.JSONDecodeError as exc:
        raise SetupError("Hermes profile snapshot metadata is invalid") from exc
    if not isinstance(metadata, dict):  # pragma: no cover - validated above
        raise SetupError("Hermes profile snapshot metadata is invalid")
    updated = {**metadata, "managed_token_id": None}
    _replace_private_file(
        metadata_path,
        _canonical_json_bytes(updated),
        expected_content=metadata_bytes,
        expected_parent_identity=metadata_parent_identity,
        expected_identity=metadata_identity,
        require_present=True,
    )


def _hermes_snapshot_cleanup_paths(spec: SetupSpec, profile: str) -> tuple[Path, Path]:
    directory = _hermes_snapshot_directory(spec, profile)
    return (
        directory.parent / f".{directory.name}.cleanup",
        directory.parent / f".{directory.name}.cleanup.json",
    )


def _finish_hermes_snapshot_cleanup(spec: SetupSpec, profile: str, *, setup_id: str) -> bool:
    directory = _hermes_snapshot_directory(spec, profile)
    tombstone, receipt_path = _hermes_snapshot_cleanup_paths(spec, profile)
    if not receipt_path.exists() and not receipt_path.is_symlink():
        if tombstone.exists() or tombstone.is_symlink():
            raise SetupError("Hermes snapshot cleanup has an unreceipted tombstone")
        return False
    receipt = _read_owned_json(receipt_path)
    fields = (
        "parent_device",
        "parent_inode",
        "parent_owner_uid",
        "tree_device",
        "tree_inode",
        "tree_owner_uid",
    )
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"format", "profile", "setup_id", *fields}
        or receipt.get("format") != 1
        or receipt.get("profile") != profile
        or receipt.get("setup_id") != setup_id
        or any(type(receipt.get(field)) is not int for field in fields)
    ):
        raise SetupError("Hermes snapshot cleanup receipt is invalid")
    parent_identity = DirectoryIdentity(
        path=directory.parent,
        device=receipt["parent_device"],
        inode=receipt["parent_inode"],
        owner_uid=receipt["parent_owner_uid"],
    )
    tree_identity = DirectoryIdentity(
        path=tombstone,
        device=receipt["tree_device"],
        inode=receipt["tree_inode"],
        owner_uid=receipt["tree_owner_uid"],
    )
    try:
        revalidate_directory_identity(parent_identity, private=True)
        directory_present = directory.exists() or directory.is_symlink()
        tombstone_present = tombstone.exists() or tombstone.is_symlink()
        if directory_present and tombstone_present:
            raise SetupError("Hermes snapshot cleanup has ambiguous directory state")
        if directory_present:
            active_identity = DirectoryIdentity(
                path=directory,
                device=tree_identity.device,
                inode=tree_identity.inode,
                owner_uid=tree_identity.owner_uid,
            )
            revalidate_directory_identity(active_identity, private=True)
            parent_descriptor = os.open(
                directory.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.rename(
                    directory.name,
                    tombstone.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        remove_private_tree_checked(
            tombstone,
            parent_identity=parent_identity,
            tree_identity=tree_identity,
        )
    except (OSError, PrivatePathError, BackupError) as exc:
        raise SetupError("Hermes snapshot cleanup could not be completed safely") from exc
    _remove_exact_owned_file(
        receipt_path,
        _canonical_json_bytes(receipt),
        expected_parent_identity=parent_identity,
        parent_private=True,
    )
    return True


def _begin_hermes_snapshot_cleanup(spec: SetupSpec, profile: str, *, setup_id: str) -> None:
    directory = _hermes_snapshot_directory(spec, profile)
    parent_identity = require_private_directory_identity(directory.parent)
    tree_identity = require_private_directory_identity(directory)
    receipt = {
        "format": 1,
        "profile": profile,
        "setup_id": setup_id,
        "parent_device": parent_identity.device,
        "parent_inode": parent_identity.inode,
        "parent_owner_uid": parent_identity.owner_uid,
        "tree_device": tree_identity.device,
        "tree_inode": tree_identity.inode,
        "tree_owner_uid": tree_identity.owner_uid,
    }
    _, receipt_path = _hermes_snapshot_cleanup_paths(spec, profile)
    _create_or_verify_private_file(receipt_path, _canonical_json_bytes(receipt))
    if not _finish_hermes_snapshot_cleanup(spec, profile, setup_id=setup_id):
        raise SetupError("Hermes snapshot cleanup receipt was not honored")


def _validated_hermes_profile_snapshot_restore(
    spec: SetupSpec,
    profile: str,
    *,
    profile_directory: Path,
    token_name: str,
    setup_id: str,
    allow_unassigned_managed_token: bool = False,
) -> (
    tuple[
        tuple[DirectoryIdentity, bytes | None, bytes | None, str | None],
        tuple[
            bool,
            bytes,
            tuple[int, int] | None,
            DirectoryIdentity,
        ],
        tuple[
            bool,
            bytes,
            tuple[int, int] | None,
            DirectoryIdentity,
        ],
    ]
    | None
):
    snapshot = _read_hermes_profile_snapshot(
        spec,
        profile,
        profile_directory=profile_directory,
    )
    if snapshot is None:
        return None
    profile_identity, original_config, original_environment, managed_token_id = snapshot
    config_path = profile_directory / "config.yaml"
    env_path = profile_directory / ".env"
    config_observation = _observe_optional_private_file(config_path)
    environment_observation = _observe_optional_private_file(env_path)
    config_exists, current_config, _config_identity, config_parent = config_observation
    environment_exists, current_environment, _env_identity, env_parent = environment_observation
    try:
        current_profile_identity = require_private_directory_identity(profile_directory)
    except PrivatePathError as exc:
        raise SetupError("Hermes profile directory changed after its setup snapshot") from exc
    if (
        config_parent != profile_identity
        or env_parent != profile_identity
        or current_profile_identity != profile_identity
    ):
        raise SetupError("Hermes profile directory changed after its setup snapshot")
    if managed_token_id is not None:
        assigned_token = _existing_profile_token(current_environment, token_name=token_name)
        if assigned_token is None and allow_unassigned_managed_token:
            pass
        elif (
            assigned_token is None
            or assigned_token.removeprefix("sgt_").split(".", 1)[0] != managed_token_id
        ):
            raise SetupError("Hermes managed caller token assignment changed after setup")
    if not _hermes_resource_matches_snapshot(
        current_config,
        current_exists=config_exists,
        original=original_config,
        remove_managed=lambda value: _remove_hermes_config(
            value,
            token_name=token_name,
            setup_id=setup_id,
        ),
    ):
        raise SetupError("Hermes profile config changed after its setup snapshot")
    if not _hermes_resource_matches_snapshot(
        current_environment,
        current_exists=environment_exists,
        original=original_environment,
        remove_managed=lambda value: _remove_profile_environment(
            value,
            token_name=token_name,
            setup_id=setup_id,
        ),
    ):
        raise SetupError("Hermes profile environment changed after its setup snapshot")
    return snapshot, config_observation, environment_observation


def _restore_hermes_profile_snapshot(
    spec: SetupSpec,
    profile: str,
    *,
    profile_directory: Path,
    token_name: str,
    setup_id: str,
    allow_unassigned_managed_token: bool = False,
) -> bool:
    if _finish_hermes_snapshot_cleanup(spec, profile, setup_id=setup_id):
        base = _hermes_snapshot_directory(spec, profile).parent
        if base.exists() and not any(base.iterdir()):
            base.rmdir()
        return True
    validated = _validated_hermes_profile_snapshot_restore(
        spec,
        profile,
        profile_directory=profile_directory,
        token_name=token_name,
        setup_id=setup_id,
        allow_unassigned_managed_token=allow_unassigned_managed_token,
    )
    if validated is None:
        return False
    snapshot, config_observation, environment_observation = validated
    _profile_identity, original_config, original_environment, _managed_token_id = snapshot
    config_path = profile_directory / "config.yaml"
    env_path = profile_directory / ".env"

    def restore_file(
        path: Path,
        observation: tuple[bool, bytes, tuple[int, int] | None, DirectoryIdentity],
        original: bytes | None,
    ) -> None:
        present, current, identity, parent_identity = observation
        if original is None:
            if present:
                _remove_exact_owned_file(
                    path,
                    current,
                    expected_parent_identity=parent_identity,
                    expected_identity=identity,
                    parent_private=True,
                )
            return
        _replace_private_file(
            path,
            original,
            expected_content=current,
            expected_parent_identity=parent_identity,
            expected_identity=identity,
            require_present=True,
        )

    restore_file(config_path, config_observation, original_config)
    restore_file(env_path, environment_observation, original_environment)
    directory = _hermes_snapshot_directory(spec, profile)
    _begin_hermes_snapshot_cleanup(spec, profile, setup_id=setup_id)
    base = directory.parent
    if base.exists() and not any(base.iterdir()):
        base.rmdir()
    return True


def _normalize_serve_config(document: Any) -> Any:
    return {} if document is None else document


def _managed_tailnet_port(spec: SetupSpec) -> int | None:
    parsed = urlsplit(spec.public_origin)
    hostname = parsed.hostname or ""
    if hostname.endswith(".ts.net") and parsed.port == 8443:
        return 8443
    return None


def _managed_tailnet_host_port(spec: SetupSpec, port: int) -> str:
    hostname = urlsplit(spec.public_origin).hostname
    if not hostname:
        raise SetupError("the managed tailnet hostname is invalid")
    return f"{hostname}:{port}"


def _canonical_json_bytes(document: Any) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _read_owned_json(path: Path) -> Any:
    encoded = _read_optional_private_file(path)
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SetupError(f"owned route record has unsafe permissions: {path}")
    try:
        return json.loads(encoded)
    except json.JSONDecodeError as exc:
        raise SetupError(f"owned route record is invalid: {path}") from exc


def _serve_config_mentions_listener(document: Any, *, host_port: str, port: int) -> bool:
    if not isinstance(document, dict):
        return False
    tcp = document.get("TCP")
    web = document.get("Web")
    allow_funnel = document.get("AllowFunnel")
    foreground = document.get("Foreground")
    foreground_mentions = isinstance(foreground, dict) and any(
        _serve_config_mentions_listener(candidate, host_port=host_port, port=port)
        for candidate in foreground.values()
    )
    return (
        isinstance(tcp, dict)
        and str(port) in tcp
        or isinstance(web, dict)
        and host_port in web
        or isinstance(allow_funnel, dict)
        and host_port in allow_funnel
        or foreground_mentions
    )


def _serve_config_has_private_route(
    document: Any,
    *,
    host_port: str,
    port: int,
    target: str,
) -> bool:
    if not isinstance(document, dict):
        return False
    tcp = document.get("TCP")
    web = document.get("Web")
    allow_funnel = document.get("AllowFunnel")
    if not isinstance(tcp, dict) or tcp.get(str(port)) != {"HTTPS": True}:
        return False
    expected_web = {"Handlers": {"/": {"Proxy": target}}}
    if not isinstance(web, dict) or web.get(host_port) != expected_web:
        return False
    foreground = document.get("Foreground")
    if isinstance(foreground, dict) and any(
        _serve_config_mentions_listener(candidate, host_port=host_port, port=port)
        for candidate in foreground.values()
    ):
        return False
    return not (isinstance(allow_funnel, dict) and allow_funnel.get(host_port) is True)


def _serve_config_without_private_route(
    document: Any,
    *,
    host_port: str,
    port: int,
    target: str,
) -> dict[str, Any]:
    if not _serve_config_has_private_route(
        document,
        host_port=host_port,
        port=port,
        target=target,
    ):
        raise SetupError("the managed Tailscale route is not an exact private listener")
    assert isinstance(document, dict)
    baseline = dict(document)
    for section, key in (
        ("TCP", str(port)),
        ("Web", host_port),
        ("AllowFunnel", host_port),
    ):
        if section not in baseline:
            continue
        values = dict(baseline[section])
        del values[key]
        if values:
            baseline[section] = values
        else:
            del baseline[section]
    return baseline


def _document_contains_value(document: Any, expected: str) -> bool:
    if isinstance(document, str):
        return document == expected
    if isinstance(document, dict):
        return any(
            _document_contains_value(key, expected) or _document_contains_value(value, expected)
            for key, value in document.items()
        )
    if isinstance(document, list):
        return any(_document_contains_value(value, expected) for value in document)
    return False


def _merge_hermes_config(
    encoded: bytes,
    *,
    token_name: str,
    setup_id: str,
) -> bytes:
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise SetupError("Hermes profile config is not UTF-8") from None
    document = _yaml_document(encoded)
    servers = document.get("mcp_servers")
    if servers is not None and not isinstance(servers, dict):
        raise SetupError("Hermes mcp_servers must be a mapping")
    expected = _hermes_servers(token_name)
    existing = (
        {
            alias: servers.get(server_name)
            for alias, server_name in _HERMES_SERVER_NAMES.items()
            if servers.get(server_name) is not None
        }
        if isinstance(servers, dict)
        else {}
    )
    if existing:
        if set(existing) != set(_PRODUCTION_MCP_ALIASES) or any(
            not _is_owned_hermes_server(value, token_name=token_name, alias=alias)
            for alias, value in existing.items()
        ):
            raise SetupError("Hermes profile has a conflicting Signet MCP server")
        _, owned, _ = _remove_owned_block(
            text,
            label="hermes config",
            setup_id=setup_id,
        )
        if owned:
            return encoded
        raise SetupError("Hermes profile has an unowned Signet MCP server")

    key_match = re.search(r"(?m)^mcp_servers:\s*(?:#.*)?$", text)
    if "mcp_servers" in document and key_match is None:
        raise SetupError("Hermes mcp_servers must use an editable block mapping")
    if key_match is None:
        rendered = yaml.safe_dump(
            {"mcp_servers": expected},
            sort_keys=False,
            allow_unicode=False,
        )
        merged_text = _append_owned_block(
            text,
            rendered,
            label="hermes config",
            setup_id=setup_id,
        )
    else:
        if key_match.end() == len(text):
            raise SetupError("Hermes mcp_servers block must end with a newline")
        insertion = _mapping_block_end(text, key_match.end())
        rendered = yaml.safe_dump(
            expected,
            sort_keys=False,
            allow_unicode=False,
        )
        indented = "".join(f"  {line}" for line in rendered.splitlines(keepends=True))
        block = (
            f"  # signet setup {setup_id}: hermes config begin\n"
            f"{indented}"
            f"  # signet setup {setup_id}: hermes config end\n"
        )
        merged_text = text[:insertion] + block + text[insertion:]
    merged = merged_text.encode("utf-8")
    merged_document = _yaml_document(merged)
    merged_servers = merged_document.get("mcp_servers")
    if not isinstance(merged_servers, dict) or any(
        merged_servers.get(server_name) != expected[server_name]
        for server_name in _HERMES_SERVER_NAMES.values()
    ):
        raise SetupError("Hermes profile integration could not be rendered safely")
    return merged


def _remove_hermes_config(
    encoded: bytes,
    *,
    token_name: str,
    setup_id: str,
) -> bytes:
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise SetupError("Hermes profile config is not UTF-8") from None
    document = _yaml_document(encoded)
    servers = document.get("mcp_servers")
    existing = (
        {
            alias: servers.get(server_name)
            for alias, server_name in _HERMES_SERVER_NAMES.items()
            if servers.get(server_name) is not None
        }
        if isinstance(servers, dict)
        else {}
    )
    if any(
        not _is_owned_hermes_server(value, token_name=token_name, alias=alias)
        for alias, value in existing.items()
    ):
        raise SetupError("Hermes profile has a changed or foreign Signet MCP server")
    owned_block = _owned_hermes_block_document(text, setup_id=setup_id)
    if owned_block is not None:
        indent, block_payload = owned_block
        named_existing = {_HERMES_SERVER_NAMES[alias]: value for alias, value in existing.items()}
        expected_document = {"mcp_servers": named_existing} if indent == "" else named_existing
        expected_payload = yaml.safe_dump(
            expected_document,
            sort_keys=False,
            allow_unicode=False,
        )
        if not existing or block_payload != expected_payload:
            raise SetupError("Hermes profile has changed or foreign content inside its marker")
    restored, removed, _ = _remove_owned_block(
        text,
        label="hermes config",
        setup_id=setup_id,
    )
    if existing and not removed:
        raise SetupError("Hermes profile has an unowned Signet MCP server")
    restored_document = _yaml_document(restored.encode("utf-8"))
    restored_servers = restored_document.get("mcp_servers")
    if isinstance(restored_servers, dict) and any(
        name in restored_servers for name in _HERMES_SERVER_NAMES.values()
    ):
        raise SetupError("Hermes profile integration rollback was incomplete")
    return restored.encode("utf-8")


def _owned_hermes_block_document(
    text: str,
    *,
    setup_id: str,
) -> tuple[str, str] | None:
    _validate_owned_marker_metadata(text, label="hermes config", setup_id=setup_id)
    for label in ("hermes config no-final-newline", "hermes config"):
        pattern = re.compile(
            rf"(?m)^(?P<indent> *)# signet setup {re.escape(setup_id)}: "
            rf"{re.escape(label)} begin\n"
        )
        match = pattern.search(text)
        if match is None:
            continue
        indent = match.group("indent")
        end_marker = f"{indent}# signet setup {setup_id}: {label} end\n"
        end = text.find(end_marker, match.end())
        if end < 0:
            raise SetupError("owned Hermes integration marker is incomplete")
        lines = text[match.end() : end].splitlines(keepends=True)
        if indent and any(line.strip() and not line.startswith(indent) for line in lines):
            raise SetupError("Hermes profile has changed or foreign content inside its marker")
        payload = "".join(line[len(indent) :] if line.strip() else line for line in lines)
        return indent, payload
    return None


def _mapping_block_end(text: str, key_end: int) -> int:
    line_end = text.find("\n", key_end)
    if line_end < 0:
        return len(text)
    position = line_end + 1
    for line in text[position:].splitlines(keepends=True):
        if line.strip() and not line[0].isspace():
            return position
        position += len(line)
    return len(text)


def _append_owned_block(text: str, content: str, *, label: str, setup_id: str) -> str:
    separator = "\n" if text and not text.endswith("\n") else ""
    marker_label = f"{label} no-final-newline" if separator else label
    return (
        text
        + separator
        + f"# signet setup {setup_id}: {marker_label} begin\n"
        + content
        + f"# signet setup {setup_id}: {marker_label} end\n"
    )


def _validate_owned_marker_metadata(text: str, *, label: str, setup_id: str) -> None:
    marker_pattern = re.compile(
        r"(?m)^ *# signet setup (?P<setup>[^:\s]+): "
        r"(?P<label>[^\n]+?) (?P<boundary>begin|end)$"
    )
    markers = list(marker_pattern.finditer(text))
    if not markers:
        return
    accepted_labels = {label, f"{label} no-final-newline"}
    if any(
        marker.group("setup") != setup_id or marker.group("label") not in accepted_labels
        for marker in markers
    ):
        raise SetupError("owned Hermes integration marker metadata is invalid")
    if len(markers) != 2:
        raise SetupError("owned Hermes integration marker is ambiguous")


def _remove_owned_block(text: str, *, label: str, setup_id: str) -> tuple[str, bool, str]:
    _validate_owned_marker_metadata(text, label=label, setup_id=setup_id)
    for candidate, remove_separator in (
        (f"{label} no-final-newline", True),
        (label, False),
    ):
        pattern = re.compile(
            rf"(?m)^(?P<indent> *)# signet setup {re.escape(setup_id)}: "
            rf"{re.escape(candidate)} begin\n"
        )
        matches = list(pattern.finditer(text))
        if not matches:
            continue
        if len(matches) != 1:
            raise SetupError("owned Hermes integration marker is ambiguous")
        match = matches[0]
        end_marker = f"{match.group('indent')}# signet setup {setup_id}: {candidate} end\n"
        end = text.find(end_marker, match.end())
        if end < 0 or text.find(end_marker, end + len(end_marker)) >= 0:
            raise SetupError("owned Hermes integration marker is incomplete")
        start = match.start()
        if remove_separator:
            if start == 0 or text[start - 1] != "\n":
                raise SetupError("owned Hermes integration separator is invalid")
            start -= 1
        return (
            text[:start] + text[end + len(end_marker) :],
            True,
            text[match.end() : end],
        )
    return text, False, ""


def _yaml_document(encoded: bytes) -> dict[str, Any]:
    if not encoded.strip():
        return {}
    try:
        loader = _UniqueKeyLoader(encoded)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()  # type: ignore[no-untyped-call]
    except (UnicodeError, yaml.YAMLError):
        raise SetupError("Hermes profile config is invalid YAML") from None
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SetupError("Hermes profile config must contain one mapping")
    return dict(value)


def _is_owned_hermes_server(value: Any, *, token_name: str, alias: str) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        return False
    normalized = dict(value)
    normalized["enabled"] = False
    return normalized == _hermes_server(token_name, alias=alias)


def _hermes_servers(token_name: str) -> dict[str, dict[str, Any]]:
    return {
        server_name: _hermes_server(token_name, alias=alias)
        for alias, server_name in _HERMES_SERVER_NAMES.items()
    }


def _hermes_server(token_name: str, *, alias: str) -> dict[str, Any]:
    return {
        "url": f"http://127.0.0.1:8789/mcp/{alias}",
        "headers": {"Authorization": f"Bearer ${{{token_name}}}"},
        "enabled": False,
        "connect_timeout": 10,
        "timeout": 120,
        "supports_parallel_tool_calls": False,
        "tools": {"resources": False, "prompts": False},
        "sampling": {"enabled": False},
    }


def _profile_token_name(profile: str) -> str:
    return "SIGNET_MCP_CALLER_TOKEN_" + re.sub(r"[^A-Za-z0-9]", "_", profile).upper()


def _existing_profile_token(encoded: bytes, *, token_name: str) -> str | None:
    pattern = re.compile(
        rf"(?m)^{re.escape(token_name)}="
        r"(sgt_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43})$"
    )
    match = pattern.search(encoded.decode("utf-8"))
    return match.group(1) if match is not None else None


def _merge_profile_environment(
    encoded: bytes,
    *,
    token_name: str,
    token: str,
    setup_id: str,
) -> bytes:
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise SetupError("Hermes profile environment is not UTF-8") from None
    assignment = re.compile(rf"(?m)^(?:export\s+)?{re.escape(token_name)}=.*$")
    exact = f"{token_name}={token}"
    match = assignment.search(text)
    if match is not None:
        _, owned, payload = _remove_owned_block(
            text,
            label="hermes environment",
            setup_id=setup_id,
        )
        if match.group(0) != exact or not owned or payload != exact + "\n":
            raise SetupError("Hermes profile has a conflicting Signet token assignment")
        return encoded
    return _append_owned_block(
        text,
        exact + "\n",
        label="hermes environment",
        setup_id=setup_id,
    ).encode("utf-8")


def _has_profile_token_assignment(encoded: bytes, *, token_name: str) -> bool:
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise SetupError("Hermes profile environment is not UTF-8") from None
    return re.search(rf"(?m)^(?:export\s+)?{re.escape(token_name)}=", text) is not None


def _remove_profile_environment(
    encoded: bytes,
    *,
    token_name: str,
    setup_id: str,
) -> bytes:
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise SetupError("Hermes profile environment is not UTF-8") from None
    has_assignment = _has_profile_token_assignment(encoded, token_name=token_name)
    restored, removed, payload = _remove_owned_block(
        text,
        label="hermes environment",
        setup_id=setup_id,
    )
    if has_assignment and not removed:
        raise SetupError("Hermes profile has an unowned Signet token assignment")
    token = _existing_profile_token(encoded, token_name=token_name)
    if removed and (token is None or payload != f"{token_name}={token}\n"):
        raise SetupError("Hermes profile environment marker contains foreign content")
    if _has_profile_token_assignment(restored.encode("utf-8"), token_name=token_name):
        raise SetupError("Hermes profile environment rollback was incomplete")
    return restored.encode("utf-8")


def _systemd_quote(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("service path contains a control character")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if not any(character.isspace() or character in "\\\"'" for character in value):
        return escaped
    return f'"{escaped}"'


def _systemd_executable(value: str) -> str:
    if any(character in '\\"' for character in value):
        raise ValueError("systemd executable path contains an unsupported quote or backslash")
    return _systemd_quote(value)


def _now() -> int:
    import time

    return int(time.time())
