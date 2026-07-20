"""Operating-system boundaries and renderers used by the setup state machine."""

from __future__ import annotations

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
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import keyring
import yaml

from signet.browser_auth import BootstrapAlreadyComplete, BootstrapService
from signet.config import production_instance_identity
from signet.credential_broker import CredentialError, KeychainSecretStore
from signet.db import Database
from signet.private_paths import (
    PrivatePathError,
    ensure_owned_directory,
    ensure_private_directory,
)
from signet.production import create_production_assembly, load_production_config
from signet.setup_state import SetupError, SetupSpec

_CONFIG_NAME = "production.json"
_POLICY_NAME = "policy.yaml"
_SECRET_PURPOSES = ("session", "csrf", "capability", "payload", "attachment", "backup")
_SERVICE_NAME = "Signet-Setup"
_HERMES_SERVER_NAME = "signet_approvals"


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
            {"namespace": f"profile:{profile}", "allowed_aliases": ["approvals"]}
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

    def _hermes_profile_directory(self, profile: str) -> Path:
        if profile == "default":
            return self.hermes_home.parent
        return self.hermes_home / profile

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
                path = target / name
                _require_exact_owned_file(path, content)
                label = name.removesuffix(".plist")
                if action == "stop":
                    command = ["launchctl", "bootout", f"gui/{uid}/{label}"]
                elif action == "restart":
                    command = ["launchctl", "kickstart", "-k", f"gui/{uid}/{label}"]
                else:
                    command = ["launchctl", "bootstrap", f"gui/{uid}", str(path)]
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
                funnel = self._tailscale_json(
                    ["tailscale", "funnel", "status", "--json"],
                    "Tailscale Funnel status is unavailable",
                )
            except SetupError:
                result[f"tailscale:{port}"] = "unavailable"
            else:
                private_route = _document_has_managed_route(
                    serve, port, "http://127.0.0.1:8790"
                ) and not _document_mentions_port(funnel, port)
                result[f"tailscale:{port}"] = "active" if private_route else "missing_or_changed"
        return result

    def remove_setup_secrets(self, setup_id: str, *, preserve_backup: bool) -> None:
        purposes = (*_SECRET_PURPOSES, "browser-bootstrap")
        errors: list[str] = []
        for purpose in purposes:
            if preserve_backup and purpose in {
                "capability",
                "payload",
                "attachment",
                "backup",
            }:
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

    def _apply_private_paths(self, spec: SetupSpec, setup_id: str) -> None:
        del setup_id
        for path in (
            spec.root / "data",
            spec.root / "backups",
            spec.root / "restore",
            spec.root / "logs",
            spec.root / "services",
            spec.root / "staging",
            spec.root / "attachments",
        ):
            try:
                resolved = ensure_private_directory(path)
            except PrivatePathError as exc:
                raise SetupError(f"private setup path could not be prepared: {path.name}") from exc
            if resolved != path:
                raise SetupError(f"private setup path is not canonical: {path.name}")

    def _rollback_private_paths(self, spec: SetupSpec, setup_id: str) -> None:
        del setup_id
        for name in ("attachments", "staging", "services", "logs", "restore", "backups", "data"):
            path = spec.root / name
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                # Non-empty paths are preserved for explicit operator inspection.
                continue

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
        preserve_backup = backup_root.is_dir() and any(
            path.is_file() and not path.is_symlink() for path in backup_root.glob("*.signet-backup")
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
        del setup_id
        database_path = spec.root / "data" / "signet.db"
        if database_path.exists() and database_path.is_symlink():
            raise SetupError("the Signet database must not be a symbolic link")
        Database(database_path).initialize()
        # Assembly validates the deny-by-default policy, secret references, and setup state.
        create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
        )

    def _rollback_database(self, spec: SetupSpec, setup_id: str) -> None:
        del setup_id
        for suffix in ("-shm", "-wal", ""):
            path = spec.root / "data" / f"signet.db{suffix}"
            if path.is_symlink():
                raise SetupError("database rollback refused a symbolic link")
            with suppress(FileNotFoundError):
                path.unlink()

    def _apply_services(self, spec: SetupSpec, setup_id: str) -> None:
        del setup_id
        plan_dir = spec.root / "services"
        if sys.platform == "darwin":
            rendered = render_launchd_services(spec, active=True)
            target = Path.home() / "Library" / "LaunchAgents"
            ensure_owned_directory(target)
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
                _verify_exact_owned_file(target / name, content)
                _verify_exact_owned_file(spec.root / "services" / name, content)
            for name in rendered:
                path = target / name
                self._stop_launchd_unit(["launchctl", "bootout", f"gui/{uid}", str(path)])
            for name, content in rendered.items():
                path = target / name
                _remove_exact_owned_file(path, content)
                _remove_exact_owned_file(spec.root / "services" / name, content)
        else:
            rendered_text = render_systemd_services(spec, active=True)
            target = Path.home() / ".config" / "systemd" / "user"
            for name, content in rendered_text.items():
                encoded = content.encode("utf-8")
                _verify_exact_owned_file(target / name, encoded)
                _verify_exact_owned_file(spec.root / "services" / name, encoded)
            self._run_checked(
                ["systemctl", "--user", "disable", "--now", *rendered_text],
                "systemd could not stop Signet",
            )
            for name, content in rendered_text.items():
                encoded = content.encode("utf-8")
                _remove_exact_owned_file(target / name, encoded)
                _remove_exact_owned_file(spec.root / "services" / name, encoded)
            self._run_checked(
                ["systemctl", "--user", "daemon-reload"],
                "systemd reload after rollback failed",
            )

    def _wait_for_local_services(self, spec: SetupSpec) -> None:
        pending = {8789, 8790}
        expected_identity = production_instance_identity(spec.root)
        deadline = time.monotonic() + 20
        while pending and time.monotonic() < deadline:
            for port in tuple(pending):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request("GET", "/healthz")
                    response = connection.getresponse()
                    response.read(4097)
                    if (
                        response.status == 200
                        and response.getheader("X-Signet-Instance") == expected_identity
                    ):
                        pending.remove(port)
                except OSError:
                    pass
                finally:
                    connection.close()
            if pending:
                time.sleep(0.2)
        if pending:
            selected = ", ".join(str(port) for port in sorted(pending))
            raise SetupError(f"Signet services did not become healthy on ports: {selected}")

    def _apply_tailnet_route(self, spec: SetupSpec) -> None:
        port = _managed_tailnet_port(spec)
        if port is None:
            return
        record_path = spec.root / "services" / "tailscale-serve-before.json"
        current_serve = self._tailscale_json(
            ["tailscale", "serve", "status", "--json"],
            "Tailscale Serve status is unavailable",
        )
        current_funnel = self._tailscale_json(
            ["tailscale", "funnel", "status", "--json"],
            "Tailscale Funnel status is unavailable",
        )
        target = "http://127.0.0.1:8790"
        if record_path.exists():
            _read_owned_json(record_path)
            if _document_mentions_port(current_funnel, port):
                raise SetupError("the managed Tailscale listener is now exposed by Funnel")
            if _document_mentions_port(current_serve, port):
                if not _document_has_managed_route(current_serve, port, target):
                    raise SetupError("the managed Tailscale listener changed ownership")
                return
        else:
            if _document_mentions_port(current_serve, port) or _document_mentions_port(
                current_funnel,
                port,
            ):
                raise SetupError(f"Tailscale listener {port} is already in use")
            before = _canonical_json_bytes({"serve": current_serve, "funnel": current_funnel})
            _create_or_verify_private_file(record_path, before)
        self._run_checked(
            [
                "tailscale",
                "serve",
                "--bg",
                f"--https={port}",
                target,
            ],
            "Tailscale Serve listener could not be installed",
        )
        after = self._tailscale_json(
            ["tailscale", "serve", "status", "--json"],
            "Tailscale Serve verification failed",
        )
        if not _document_has_managed_route(after, port, target):
            raise SetupError("Tailscale Serve listener did not match the requested private route")
        _create_or_verify_private_file(
            spec.root / "services" / "tailscale-serve-after.json",
            _canonical_json_bytes(after),
        )

    def _rollback_tailnet_route(self, spec: SetupSpec) -> None:
        port = _managed_tailnet_port(spec)
        record_path = spec.root / "services" / "tailscale-serve-before.json"
        if port is None or not record_path.exists():
            return
        before = _read_owned_json(record_path)
        if not isinstance(before, dict) or set(before) != {"serve", "funnel"}:
            raise SetupError("Tailscale rollback record is invalid")
        if _document_mentions_port(before["serve"], port) or _document_mentions_port(
            before["funnel"], port
        ):
            raise SetupError("Tailscale rollback record does not describe a free listener")
        after_path = spec.root / "services" / "tailscale-serve-after.json"
        recorded_after = _read_owned_json(after_path) if after_path.exists() else None
        current_serve = self._tailscale_json(
            ["tailscale", "serve", "status", "--json"],
            "Tailscale Serve status is unavailable",
        )
        current_funnel = self._tailscale_json(
            ["tailscale", "funnel", "status", "--json"],
            "Tailscale Funnel status is unavailable",
        )
        if _document_mentions_port(current_funnel, port):
            raise SetupError("refusing to remove a listener now exposed by Funnel")
        target = "http://127.0.0.1:8790"
        if _document_mentions_port(current_serve, port):
            if not _document_has_managed_route(current_serve, port, target):
                raise SetupError("refusing to remove a changed Tailscale listener")
            self._run_checked(
                ["tailscale", "serve", f"--https={port}", "off"],
                "Tailscale Serve listener rollback failed",
            )
            current_serve = self._tailscale_json(
                ["tailscale", "serve", "status", "--json"],
                "Tailscale Serve rollback verification failed",
            )
        if _document_mentions_port(current_serve, port):
            raise SetupError("Tailscale Serve listener remains after rollback")
        if recorded_after is not None:
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
        )
        for profile in spec.hermes_profiles:
            profile_dir = self._hermes_profile_directory(profile)
            token_name = _profile_token_name(profile)
            config_path = profile_dir / "config.yaml"
            env_path = profile_dir / ".env"
            existing_config = _read_optional_private_file(config_path)
            existing_env = _read_optional_private_file(env_path)
            merged = _merge_hermes_config(
                existing_config,
                token_name=token_name,
                setup_id=setup_id,
            )
            token = _existing_profile_token(existing_env, token_name=token_name)
            if token is not None:
                try:
                    assembly.token_registry.authenticate(f"Bearer {token}", alias="approvals")
                except CredentialError:
                    token = None
            if token is None:
                for metadata in assembly.token_registry.list_metadata():
                    if metadata.namespace == f"profile:{profile}" and metadata.revoked_at is None:
                        assembly.token_registry.revoke(metadata.token_id)
                issued = assembly.token_registry.issue(f"profile:{profile}", {"approvals"})
                token = issued.token
            updated_env = _merge_profile_environment(
                existing_env,
                token_name=token_name,
                token=token,
                setup_id=setup_id,
            )
            _replace_private_file(
                config_path,
                merged,
                expected_content=existing_config,
            )
            _replace_private_file(
                env_path,
                updated_env,
                expected_content=existing_env,
            )
        self.output(
            "Hermes profiles staged with disabled Signet MCP entries. Signet did not restart "
            "the gateway; review and enable each entry, then run /reload-mcp in that profile."
        )

    def _rollback_hermes_profiles(self, spec: SetupSpec, setup_id: str) -> None:
        assembly = create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
        )
        for profile in spec.hermes_profiles:
            profile_dir = self._hermes_profile_directory(profile)
            token_name = _profile_token_name(profile)
            config_path = profile_dir / "config.yaml"
            env_path = profile_dir / ".env"
            current_config = _read_optional_private_file(config_path)
            current_env = _read_optional_private_file(env_path)
            token = _existing_profile_token(current_env, token_name=token_name)
            if _has_profile_token_assignment(current_env, token_name=token_name) and token is None:
                raise SetupError("Hermes profile has a foreign Signet token assignment")
            if config_path.exists() or config_path.is_symlink():
                _replace_private_file(
                    config_path,
                    _remove_hermes_config(
                        current_config,
                        token_name=token_name,
                        setup_id=setup_id,
                    ),
                    expected_content=current_config,
                )
            if env_path.exists() or env_path.is_symlink():
                _replace_private_file(
                    env_path,
                    _remove_profile_environment(
                        current_env,
                        token_name=token_name,
                        setup_id=setup_id,
                    ),
                    expected_content=current_env,
                )
            if token is not None:
                token_id = token.removeprefix("sgt_").split(".", 1)[0]
                assembly.token_registry.revoke(token_id)
            else:
                for metadata in assembly.token_registry.list_metadata():
                    if metadata.namespace == f"profile:{profile}" and metadata.revoked_at is None:
                        assembly.token_registry.revoke(metadata.token_id)

    def _apply_owner_bootstrap(self, spec: SetupSpec, setup_id: str) -> None:
        assembly = create_production_assembly(
            spec.root / _CONFIG_NAME,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
        )
        bootstrap = BootstrapService(assembly.database, owner_user_id=spec.owner_user_id)
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
        with assembly.database.read() as connection:
            state = connection.execute(
                "SELECT claimed_at FROM browser_bootstrap_state WHERE state_id = 1"
            ).fetchone()
        already_claimed = state is not None and state["claimed_at"] is not None
        if status.complete or already_claimed:
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

    def _run_checked(self, command: list[str], message: str) -> None:
        result = self.command_runner(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise SetupError(message)

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


def _secret_account(setup_id: str, purpose: str) -> str:
    return f"{setup_id}-{purpose}"


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
) -> None:
    try:
        prepare_parent = ensure_private_directory if parent_private else ensure_owned_directory
        parent = prepare_parent(path.parent)
    except PrivatePathError as exc:
        raise SetupError(f"private resource parent is unsafe: {path.parent}") from exc
    if parent != path.parent:
        raise SetupError(f"private resource parent is not canonical: {path.parent}")
    if path.is_symlink():
        raise SetupError(f"refusing symbolic-link resource: {path}")
    if require_absent and path.exists():
        raise SetupError(f"resource already exists: {path}")
    temporary = path.with_name(f".{path.name}.{secrets.token_urlsafe(8)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short private-file write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if require_absent:
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError as exc:
                raise SetupError(f"resource already exists: {path}") from exc
            temporary.unlink()
        else:
            if expected_content is not None:
                if path.exists() or path.is_symlink():
                    _require_exact_owned_file(path, expected_content)
                elif expected_content != b"":
                    raise SetupError(f"owned resource changed or is ambiguous: {path}")
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise SetupError(f"private resource could not be published: {path}") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def _verify_exact_owned_file(path: Path, expected: bytes) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        raise SetupError(f"refusing to remove symbolic-link resource: {path}")
    try:
        metadata = path.stat()
        actual = path.read_bytes()
    except OSError as exc:
        raise SetupError(f"owned resource could not be inspected: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or actual != expected:
        raise SetupError(f"refusing to remove changed or foreign resource: {path}")


def _remove_exact_owned_file(path: Path, expected: bytes) -> None:
    _verify_exact_owned_file(path, expected)
    if not path.exists() and not path.is_symlink():
        return
    path.unlink()


def _read_optional_private_file(path: Path) -> bytes:
    if not path.exists():
        return b""
    if path.is_symlink():
        raise SetupError(f"refusing symbolic-link profile file: {path}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SetupError(f"profile resource is not a regular file: {path}")
    encoded = path.read_bytes()
    if len(encoded) > 1_048_576 or b"\x00" in encoded:
        raise SetupError(f"profile resource is invalid or too large: {path}")
    return encoded


def _managed_tailnet_port(spec: SetupSpec) -> int | None:
    parsed = urlsplit(spec.public_origin)
    hostname = parsed.hostname or ""
    if hostname.endswith(".ts.net") and parsed.port == 8443:
        return 8443
    return None


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


def _document_mentions_port(document: Any, port: int) -> bool:
    if isinstance(document, bool):
        return False
    if isinstance(document, int):
        return document == port
    if isinstance(document, str):
        return re.search(rf"(?<!\d){port}(?!\d)", document) is not None
    if isinstance(document, dict):
        return any(
            _document_mentions_port(key, port) or _document_mentions_port(value, port)
            for key, value in document.items()
        )
    if isinstance(document, list):
        return any(_document_mentions_port(value, port) for value in document)
    return False


def _document_has_managed_route(document: Any, port: int, target: str) -> bool:
    scopes: list[Any] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if _document_mentions_port(key, port):
                    scopes.append(child)
                else:
                    collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    def proxy_targets(value: Any) -> set[str]:
        found: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and key.casefold() == "proxy" and isinstance(child, str):
                    found.add(child)
                else:
                    found.update(proxy_targets(child))
        elif isinstance(value, list):
            for child in value:
                found.update(proxy_targets(child))
        return found

    collect(document)
    return bool(scopes) and all(proxy_targets(scope) == {target} for scope in scopes)


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
    expected = _hermes_server(token_name)
    existing = servers.get(_HERMES_SERVER_NAME) if isinstance(servers, dict) else None
    if existing is not None:
        if not _is_owned_hermes_server(existing, token_name=token_name):
            raise SetupError("Hermes profile has a conflicting Signet MCP server")
        _, owned = _remove_owned_block(
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
            {"mcp_servers": {_HERMES_SERVER_NAME: expected}},
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
            {_HERMES_SERVER_NAME: expected},
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
    if not isinstance(merged_servers, dict) or merged_servers.get(_HERMES_SERVER_NAME) != expected:
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
    existing = servers.get(_HERMES_SERVER_NAME) if isinstance(servers, dict) else None
    if existing is not None and not _is_owned_hermes_server(
        existing,
        token_name=token_name,
    ):
        raise SetupError("Hermes profile has a changed or foreign Signet MCP server")
    restored, removed = _remove_owned_block(
        text,
        label="hermes config",
        setup_id=setup_id,
    )
    if existing is not None and not removed:
        raise SetupError("Hermes profile has an unowned Signet MCP server")
    restored_document = _yaml_document(restored.encode("utf-8"))
    restored_servers = restored_document.get("mcp_servers")
    if isinstance(restored_servers, dict) and _HERMES_SERVER_NAME in restored_servers:
        raise SetupError("Hermes profile integration rollback was incomplete")
    return restored.encode("utf-8")


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


def _remove_owned_block(text: str, *, label: str, setup_id: str) -> tuple[str, bool]:
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
        return text[:start] + text[end + len(end_marker) :], True
    return text, False


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


def _is_owned_hermes_server(value: Any, *, token_name: str) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        return False
    normalized = dict(value)
    normalized["enabled"] = False
    return normalized == _hermes_server(token_name)


def _hermes_server(token_name: str) -> dict[str, Any]:
    return {
        "url": "http://127.0.0.1:8789/mcp/approvals",
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
        _, owned = _remove_owned_block(
            text,
            label="hermes environment",
            setup_id=setup_id,
        )
        if match.group(0) != exact or not owned:
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
    restored, removed = _remove_owned_block(
        text,
        label="hermes environment",
        setup_id=setup_id,
    )
    if has_assignment and not removed:
        raise SetupError("Hermes profile has an unowned Signet token assignment")
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
