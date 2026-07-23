"""Guided setup for the two production provider integrations."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import platform as host_platform
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

import keyring
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from signet.adapters.whatsapp import WHATSAPP_FILE_SCHEMA, WHATSAPP_TEXT_SCHEMA
from signet.canonical import canonical_json, sha256_hex
from signet.config import (
    DownstreamConfig,
    ProductionConfig,
    ProductionProviderRollout,
    ProductionWacliConfig,
)
from signet.credential_broker import KeychainSecretStore, SecretReference
from signet.downstream import DownstreamClient, pinned_tls_http_connector
from signet.mcp_mirror import SchemaMirror, tool_schema_digest, validate_lossless_tool
from signet.policy import PolicySnapshot, load_policy, parse_policy, policy_document
from signet.production import create_production_assembly, load_production_config
from signet.production_connectors import provider_credential_identity_digest
from signet.schema_registry import DurableSchemaRegistry
from signet.setup_operations import SetupOperations
from signet.setup_platform import (
    ProductionSetupPlatform,
    _replace_private_file,
)
from signet.setup_state import SetupError
from signet.wacli_wrapper import REVIEWED_WACLI_VERSION, WacliConfig, WacliWrapper

ProviderName = Literal["fastmail", "whatsapp"]

FASTMAIL_ENDPOINT = "https://api.fastmail.com/mcp"
WACLI_ARCHIVE_URL = (
    "https://github.com/openclaw/wacli/releases/download/v0.12.0/wacli_0.12.0_linux_amd64.tar.gz"
)
WACLI_ARCHIVE_SHA256 = "49baa180fa7f0f4a694f683b8f7386ea64023ed79c0307037f0680bd21c116e0"
_WACLI_ACCOUNT = "signet"
_WACLI_OUTPUT_LIMIT = 256 * 1024
_DOWNLOAD_LIMIT = 32 * 1024 * 1024
_SERVICE_NAME = "Signet-Setup"

_WHATSAPP_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["sent", "message_id"],
    "properties": {
        "sent": {"const": True},
        "message_id": {"type": "string", "minLength": 1, "maxLength": 256},
    },
}


class ProviderSetupOperations:
    def __init__(
        self,
        root: Path,
        *,
        platform: ProductionSetupPlatform | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.root = root
        self.platform = platform or ProductionSetupPlatform()
        self.setup = SetupOperations(root, platform=self.platform)
        self.command_runner = command_runner
        self.clock = clock or (lambda: int(time.time()))

    def setup_fastmail(
        self,
        *,
        token: str,
        sender: str,
        recipient: str,
    ) -> dict[str, Any]:
        if not token or any(character in token for character in "\x00\r\n"):
            raise SetupError("Fastmail token is empty or invalid")
        if not sender or not recipient:
            raise SetupError("Fastmail sender and test recipient are required")
        with self.setup.lifecycle_lock():
            current = self._require_installed_config()
            current = self._disable_for_setup(current)
            setup_id = self.setup.store.load().setup_id
            credential_ref = f"keychain://{_SERVICE_NAME}/{setup_id}-fastmail"
            self._store_fastmail_token(credential_ref, token)
            certificate_pem, certificate_digest = _fetch_fastmail_certificate(FASTMAIL_ENDPOINT)
            certificate_path = self.root / "providers" / "fastmail-server.pem"
            _write_private_resource(certificate_path, certificate_pem)
            credential_digest = provider_credential_identity_digest(
                reference=credential_ref,
                secret=token,
                identity_key=self._capability_key(current),
            )
            probe_connector = DownstreamConfig(
                transport="http",
                credential_ref=credential_ref,
                credential_identity_digest=credential_digest,
                url=FASTMAIL_ENDPOINT,
                tls_server_certificate=certificate_path,
                tls_server_certificate_sha256=certificate_digest,
            )
            tools, initialization = asyncio.run(
                _probe_fastmail(
                    probe_connector,
                    certificate_pem=certificate_pem,
                    certificate_digest=certificate_digest,
                    sender=sender,
                    recipient=recipient,
                )
            )
            server_identity = sha256_hex(canonical_json(initialization))
            connector = probe_connector.model_copy(
                update={"server_identity_digest": server_identity}
            )
            policy = _provider_policy(
                load_policy(current.policy_path),
                alias="fastmail",
                connector=connector,
                tools=tools,
                account="account:fastmail",
            )
            configured = current.model_copy(
                update={
                    "connectors": {**current.connectors, "fastmail": connector},
                }
            )
            enabled = self._install_provider(
                current=current,
                configured=configured,
                policy=policy,
                alias="fastmail",
                tools=tools,
            )
            return {
                "provider": "fastmail",
                "configured": True,
                "test_send": "succeeded",
                "enabled": enabled.provider_rollout.state == "enabled",
            }

    def setup_whatsapp(
        self,
        *,
        recipient: str,
        install_wacli: bool,
    ) -> dict[str, Any]:
        if not _whatsapp_supported():
            raise SetupError("WhatsApp is unsupported on this platform")
        if not recipient:
            raise SetupError("WhatsApp test recipient is required")
        with self.setup.lifecycle_lock():
            current = self._require_installed_config()
            current = self._disable_for_setup(current)
            executable = self._managed_wacli_path()
            if not executable.is_file():
                if not install_wacli:
                    raise SetupError(
                        "wacli is not installed; rerun and confirm the verified download"
                    )
                self._install_wacli(executable)
            runtime_root = self.root / "wacli-runtime"
            home = runtime_root / "home"
            store = runtime_root / "store"
            snapshot_root = self.root / "wacli-execution-snapshots"
            for directory in (runtime_root, home, store, snapshot_root):
                _ensure_private_directory(directory)
            _write_wacli_account_config(home, store)
            self._pair_wacli(executable, home=home, store=store)
            linked_jid = self._wacli_linked_jid(executable, home=home, store=store)
            executable_digest = _file_sha256(executable)
            wrapper = WacliWrapper(
                WacliConfig(
                    account=_WACLI_ACCOUNT,
                    executable=executable,
                    expected_version=REVIEWED_WACLI_VERSION,
                    expected_linked_jid=linked_jid,
                    expected_sha256=executable_digest,
                    home=home,
                    store=store,
                    staging_root=current.storage.attachment_staging_dir,
                    reviewed_dispatch_enabled=True,
                    execution_snapshot_root=snapshot_root,
                )
            )
            asyncio.run(
                wrapper.send_text(
                    {
                        "to": recipient,
                        "message": "Signet setup test",
                    }
                )
            )
            credential_ref = current.secrets.capability_key_ref
            credential_digest = hashlib.sha256(
                canonical_json(
                    {
                        "account": _WACLI_ACCOUNT,
                        "linked_jid": linked_jid,
                        "store": str(store),
                    }
                )
            ).hexdigest()
            connector = DownstreamConfig(
                transport="stdio",
                credential_ref=credential_ref,
                credential_identity_digest=credential_digest,
                command=(str(executable),),
                working_directory=runtime_root,
                executable_sha256=executable_digest,
                execution_snapshot_root=snapshot_root,
                output_limit_bytes=_WACLI_OUTPUT_LIMIT,
            )
            boundary = ProductionWacliConfig(
                account=_WACLI_ACCOUNT,
                linked_jid=linked_jid,
                home=home,
                store=store,
                expected_version=REVIEWED_WACLI_VERSION,
                max_output_bytes=_WACLI_OUTPUT_LIMIT,
            )
            tools = _whatsapp_tools()
            policy = _provider_policy(
                load_policy(current.policy_path),
                alias="whatsapp",
                connector=connector,
                tools=tools,
                account=f"account:{_WACLI_ACCOUNT}",
            )
            configured = current.model_copy(
                update={
                    "connectors": {**current.connectors, "whatsapp": connector},
                    "provider_rollout": ProductionProviderRollout(
                        state="disabled",
                        wacli=boundary,
                    ),
                }
            )
            enabled = self._install_provider(
                current=current,
                configured=configured,
                policy=policy,
                alias="whatsapp",
                tools=tools,
            )
            return {
                "provider": "whatsapp",
                "configured": True,
                "test_send": "succeeded",
                "enabled": enabled.provider_rollout.state == "enabled",
            }

    def status(self) -> dict[str, Any]:
        config = self._require_installed_config()
        enabled = config.provider_rollout.state == "enabled"
        providers: dict[str, Any] = {}
        for alias in ("fastmail", "whatsapp"):
            connector = config.connectors.get(alias)
            supported = alias == "fastmail" or _whatsapp_supported()
            credential_ready = False
            if connector is not None:
                try:
                    KeychainSecretStore().get(SecretReference.parse(connector.credential_ref))
                except Exception:
                    credential_ready = False
                else:
                    credential_ready = True
            providers[alias] = {
                "supported": supported,
                "configured": connector is not None,
                "credential_ready": credential_ready,
                "enabled": bool(connector is not None and enabled),
            }
        return {
            "rollout": config.provider_rollout.state,
            "providers": providers,
        }

    def enable(self, provider: ProviderName) -> dict[str, Any]:
        with self.setup.lifecycle_lock():
            config = self._require_installed_config()
            self._require_provider(config, provider)
            updated = self._switch_rollout(config, enabled=True)
            return {
                "provider": provider,
                "rollout": updated.provider_rollout.state,
                "affected": sorted(updated.connectors),
            }

    def disable(self, provider: ProviderName) -> dict[str, Any]:
        with self.setup.lifecycle_lock():
            config = self._require_installed_config()
            self._require_provider(config, provider)
            updated = self._switch_rollout(config, enabled=False)
            return {
                "provider": provider,
                "rollout": updated.provider_rollout.state,
                "affected": sorted(updated.connectors),
            }

    def _require_installed_config(self) -> ProductionConfig:
        journal = self.setup.store.load()
        if journal.status != "completed":
            raise SetupError("complete signet setup before configuring providers")
        return load_production_config(self.root / "production.json")

    @staticmethod
    def _require_provider(config: ProductionConfig, provider: ProviderName) -> None:
        if provider not in config.connectors:
            raise SetupError(f"{provider} is not configured")
        if provider == "whatsapp" and not _whatsapp_supported():
            raise SetupError("WhatsApp is unsupported on this platform")

    def _disable_for_setup(self, config: ProductionConfig) -> ProductionConfig:
        if config.provider_rollout.state == "disabled":
            return config
        return self._switch_rollout(config, enabled=False)

    def _install_provider(
        self,
        *,
        current: ProductionConfig,
        configured: ProductionConfig,
        policy: PolicySnapshot,
        alias: ProviderName,
        tools: Sequence[Mapping[str, Any]],
    ) -> ProductionConfig:
        spec = self.setup.spec()
        config_path = self.root / "production.json"
        original_config = config_path.read_bytes()
        self.platform.manage_services(spec, "stop")
        assembly = create_production_assembly(
            config_path,
            secret_store=KeychainSecretStore(),
            components=frozenset(),
        )
        previous_policy = assembly.policy
        now = self.clock()
        config_changed = configured != current
        state_changed = False
        config_published = False
        try:
            if config_changed:
                assembly.state.configure_provider(
                    current_config=current,
                    next_config=configured,
                    alias=alias,
                    now=now,
                )
                state_changed = True
                _replace_private_file(
                    config_path,
                    _config_bytes(configured),
                    expected_content=original_config,
                    require_present=True,
                )
                config_published = True
            if policy != assembly.policy:
                assembly.policy_promotions.install_provider_setup(
                    policy,
                    alias=alias,
                    now=now,
                )
            _store_reviewed_schemas(
                assembly.database,
                policy,
                alias=alias,
                tools=tools,
                now=now,
            )
        except BaseException:
            try:
                if not assembly.policy_promotions.ready:
                    assembly.policy_promotions.recover(now=now)
                active_policy = assembly.policy
                if state_changed and not config_published:
                    assembly.state.configure_provider(
                        current_config=configured,
                        next_config=current,
                        alias=alias,
                        now=now,
                    )
                    state_changed = False
                if policy != previous_policy and active_policy != policy:
                    if active_policy != previous_policy:
                        raise SetupError("provider policy recovery produced an unexpected version")
                    if config_published:
                        current_bytes = config_path.read_bytes()
                        if current_bytes != _config_bytes(configured):
                            raise SetupError("provider configuration changed during recovery")
                        _replace_private_file(
                            config_path,
                            original_config,
                            expected_content=current_bytes,
                            require_present=True,
                        )
                        config_published = False
                    if state_changed:
                        assembly.state.configure_provider(
                            current_config=configured,
                            next_config=current,
                            alias=alias,
                            now=now,
                        )
                self._resume_services_after_failure(spec)
            except BaseException as recovery_exc:
                raise SetupError(
                    "provider setup failed and could not be recovered"
                ) from recovery_exc
            raise
        return self._switch_rollout(configured, enabled=True, services_stopped=True)

    def _switch_rollout(
        self,
        config: ProductionConfig,
        *,
        enabled: bool,
        services_stopped: bool = False,
    ) -> ProductionConfig:
        desired = "enabled" if enabled else "disabled"
        if config.provider_rollout.state == desired:
            if services_stopped:
                self.platform.manage_services(self.setup.spec(), "start")
                self.platform.verify_service_health(self.setup.spec())
            return config
        if not config.connectors:
            raise SetupError("no provider is configured")
        target = config.model_copy(
            update={
                "capabilities": config.capabilities.model_copy(
                    update={"live_providers_ready": enabled}
                ),
                "provider_rollout": config.provider_rollout.model_copy(update={"state": desired}),
            }
        )
        spec = self.setup.spec()
        if not services_stopped:
            self.platform.manage_services(spec, "stop")
        config_path = self.root / "production.json"
        previous_bytes = config_path.read_bytes()
        target_bytes = _config_bytes(target)
        try:
            _replace_private_file(
                config_path,
                target_bytes,
                expected_content=previous_bytes,
                require_present=True,
            )
            create_production_assembly(
                config_path,
                secret_store=KeychainSecretStore(),
                components=frozenset(),
            )
            self.platform.manage_services(spec, "start")
            self.platform.verify_service_health(spec)
        except BaseException as exc:
            try:
                self.platform.manage_services(spec, "stop")
                if config_path.read_bytes() == target_bytes:
                    _replace_private_file(
                        config_path,
                        previous_bytes,
                        expected_content=target_bytes,
                        require_present=True,
                    )
                create_production_assembly(
                    config_path,
                    secret_store=KeychainSecretStore(),
                    components=frozenset(),
                )
                self.platform.manage_services(spec, "start")
                self.platform.verify_service_health(spec)
            except BaseException as rollback_exc:
                raise SetupError(
                    "provider rollout failed and could not be restored"
                ) from rollback_exc
            raise SetupError("provider rollout failed and was restored") from exc
        return target

    def _resume_services_after_failure(self, spec: Any) -> None:
        try:
            self.platform.manage_services(spec, "start")
            self.platform.verify_service_health(spec)
        except Exception as exc:
            raise SetupError("provider setup failed and services could not be resumed") from exc

    def _capability_key(self, config: ProductionConfig) -> bytes:
        secret = KeychainSecretStore().get(SecretReference.parse(config.secrets.capability_key_ref))
        return secret.reveal().encode("utf-8")

    @staticmethod
    def _store_fastmail_token(reference: str, token: str) -> None:
        parsed = SecretReference.parse(reference)
        try:
            keyring.set_password(parsed.service, parsed.account, token)
            stored = keyring.get_password(parsed.service, parsed.account)
        except Exception as exc:
            raise SetupError("Fastmail token could not be stored") from exc
        if stored != token:
            raise SetupError("Fastmail token could not be verified")

    def _managed_wacli_path(self) -> Path:
        return self.root / "tools" / "wacli" / REVIEWED_WACLI_VERSION / "wacli"

    def _install_wacli(self, executable: Path) -> None:
        archive = _download_bounded(WACLI_ARCHIVE_URL)
        if hashlib.sha256(archive).hexdigest() != WACLI_ARCHIVE_SHA256:
            raise SetupError("downloaded wacli archive digest did not match")
        payload = _extract_wacli(archive)
        _write_private_resource(executable, payload)
        executable.chmod(0o500)

    def _pair_wacli(self, executable: Path, *, home: Path, store: Path) -> None:
        status = self._wacli_status(executable, home=home, store=store)
        if status.get("authenticated") is True:
            return
        result = self.command_runner(
            [
                str(executable),
                "--store",
                str(store),
                "auth",
                "--idle-exit",
                "30s",
            ],
            env=_wacli_environment(home),
            check=False,
            timeout=600,
        )
        if result.returncode != 0:
            raise SetupError("wacli pairing did not complete")

    def _wacli_status(
        self,
        executable: Path,
        *,
        home: Path,
        store: Path,
    ) -> dict[str, Any]:
        result = self.command_runner(
            [
                str(executable),
                "--store",
                str(store),
                "--json",
                "auth",
                "status",
                "--read-only",
            ],
            env=_wacli_environment(home),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        try:
            document = json.loads(result.stdout) if result.returncode == 0 else {}
        except (TypeError, json.JSONDecodeError):
            document = {}
        return cast(dict[str, Any], document) if isinstance(document, dict) else {}

    def _wacli_linked_jid(
        self,
        executable: Path,
        *,
        home: Path,
        store: Path,
    ) -> str:
        status = self._wacli_status(executable, home=home, store=store)
        linked_jid = status.get("linked_jid")
        if status.get("authenticated") is not True or not isinstance(linked_jid, str):
            raise SetupError("wacli is not authenticated")
        return linked_jid


async def _probe_fastmail(
    connector: DownstreamConfig,
    *,
    certificate_pem: bytes,
    certificate_digest: str,
    sender: str,
    recipient: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    client = DownstreamClient(
        "fastmail",
        connector,
        KeychainSecretStore(),
        http_connector=pinned_tls_http_connector(
            certificate_pem,
            certificate_digest,
        ),
    )
    try:
        await client.start()
        tools = [validate_lossless_tool(tool) for tool in await client.discover_all_tools()]
        by_name = {str(tool["name"]): tool for tool in tools}
        if set(by_name) != {str(tool["name"]) for tool in tools} or not {
            "send_email",
            "search_email",
        } <= set(by_name):
            raise SetupError("Fastmail did not expose the required tools")
        send_schema = by_name["send_email"].get("inputSchema")
        if not isinstance(send_schema, Mapping):
            raise SetupError("Fastmail send_email schema is invalid")
        required_fields = {"from", "to", "subject", "body"}
        properties = send_schema.get("properties")
        if not isinstance(properties, Mapping) or not required_fields <= set(properties):
            raise SetupError("Fastmail send_email schema is unsupported")
        result = await client.call_tool_raw(
            "send_email",
            {
                "from": sender,
                "to": [recipient],
                "subject": "Signet setup test",
                "body": "Signet successfully connected to Fastmail.",
            },
        )
        if result.get("isError") is True:
            raise SetupError("Fastmail test email failed")
        initialization = client.initialization_identity
        if not isinstance(initialization, dict):
            raise SetupError("Fastmail initialization identity is unavailable")
        return tools, initialization
    finally:
        await client.close()


def _provider_policy(
    current: PolicySnapshot,
    *,
    alias: ProviderName,
    connector: DownstreamConfig,
    tools: Sequence[Mapping[str, Any]],
    account: str,
) -> PolicySnapshot:
    document = policy_document(current)
    tool_policies: dict[str, Any] = {}
    for raw in tools:
        tool = validate_lossless_tool(raw)
        name = str(tool["name"])
        selected: dict[str, Any] = {
            "mode": "deny",
            "schema_digest": tool_schema_digest(tool),
        }
        if alias == "fastmail" and name == "send_email":
            selected.update(
                mode="approval",
                adapter="fastmail.send",
                communication_send=True,
                account_ref=account,
            )
        elif alias == "fastmail" and name == "search_email":
            selected.update(
                mode="passthrough",
                reviewed_read_only=True,
                account_ref=account,
            )
        elif alias == "whatsapp" and name in {"send_text", "send_file"}:
            selected.update(
                mode="approval",
                adapter=f"whatsapp.{name}",
                communication_send=True,
                account_ref=account,
            )
        tool_policies[name] = selected
    downstream: dict[str, Any] = {
        "transport": connector.transport,
        "credential_ref": connector.credential_ref,
        "account_ref": account,
        "tools": tool_policies,
    }
    if connector.transport == "http":
        downstream["url"] = connector.url
    else:
        downstream["command_ref"] = "wacli"
    document["downstreams"][alias] = downstream
    candidate = parse_policy(document)
    if candidate.downstreams[alias] == current.downstreams.get(alias):
        return current
    document["version"] = current.version + 1
    return parse_policy(document)


def _whatsapp_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "send_text",
            "description": "Send an approved WhatsApp text message.",
            "inputSchema": dict(WHATSAPP_TEXT_SCHEMA),
            "outputSchema": dict(_WHATSAPP_OUTPUT_SCHEMA),
        },
        {
            "name": "send_file",
            "description": "Send an approved WhatsApp file.",
            "inputSchema": dict(WHATSAPP_FILE_SCHEMA),
            "outputSchema": dict(_WHATSAPP_OUTPUT_SCHEMA),
        },
    ]


def _store_reviewed_schemas(
    database: Any,
    policy: PolicySnapshot,
    *,
    alias: ProviderName,
    tools: Sequence[Mapping[str, Any]],
    now: int,
) -> None:
    mirror = SchemaMirror(policy)
    registry = DurableSchemaRegistry(database=database, mirror=mirror, surfaces={})
    registry.capture_reviewed(alias, tools, discovered_at=now)


def _fetch_fastmail_certificate(url: str) -> tuple[bytes, str]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise SetupError("Fastmail endpoint is invalid")
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((parsed.hostname, parsed.port or 443), timeout=15) as raw,
            context.wrap_socket(raw, server_hostname=parsed.hostname) as secured,
        ):
            certificate_der = secured.getpeercert(binary_form=True)
    except OSError as exc:
        raise SetupError("Fastmail TLS certificate could not be retrieved") from exc
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise SetupError("Fastmail TLS certificate is unavailable")
    certificate = x509.load_der_x509_certificate(certificate_der)
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        hashlib.sha256(certificate_der).hexdigest(),
    )


def _download_bounded(url: str) -> bytes:
    if url != WACLI_ARCHIVE_URL:
        raise SetupError("wacli download URL is not reviewed")
    request = urllib.request.Request(url, headers={"User-Agent": "signet-gateway"})
    try:
        # The exact pinned HTTPS URL is checked before opening it.
        with urllib.request.urlopen(  # nosec B310
            request,
            timeout=60,
        ) as response:
            payload = cast(bytes, response.read(_DOWNLOAD_LIMIT + 1))
    except OSError as exc:
        raise SetupError("wacli download failed") from exc
    if len(payload) > _DOWNLOAD_LIMIT:
        raise SetupError("wacli download exceeded its size limit")
    return payload


def _extract_wacli(archive: bytes) -> bytes:
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            candidates = [
                member
                for member in bundle.getmembers()
                if member.isfile() and Path(member.name).name == "wacli"
            ]
            if len(candidates) != 1 or candidates[0].size > _DOWNLOAD_LIMIT:
                raise SetupError("wacli archive layout is invalid")
            stream = bundle.extractfile(candidates[0])
            payload = stream.read(_DOWNLOAD_LIMIT + 1) if stream is not None else b""
    except (tarfile.TarError, OSError) as exc:
        raise SetupError("wacli archive is invalid") from exc
    if not payload or len(payload) > _DOWNLOAD_LIMIT or not payload.startswith(b"\x7fELF"):
        raise SetupError("wacli archive did not contain the expected Linux executable")
    return payload


def _write_wacli_account_config(home: Path, store: Path) -> None:
    path = home / ".local" / "state" / "wacli" / "config.yaml"
    document = {
        "default_account": _WACLI_ACCOUNT,
        "accounts": {
            _WACLI_ACCOUNT: {
                "store": str(store),
            }
        },
    }
    encoded = yaml.safe_dump(document, sort_keys=False).encode("utf-8")
    _write_private_resource(path, encoded)


def _wacli_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError as exc:
        raise SetupError(f"provider directory could not be prepared: {path.name}") from exc
    if path.is_symlink() or not path.is_dir():
        raise SetupError(f"provider directory is invalid: {path.name}")


def _write_private_resource(path: Path, content: bytes) -> None:
    _ensure_private_directory(path.parent)
    existing = path.read_bytes() if path.is_file() and not path.is_symlink() else None
    _replace_private_file(
        path,
        content,
        require_absent=existing is None,
        require_present=existing is not None,
        expected_content=existing,
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise SetupError("wacli executable could not be read") from exc
    return digest.hexdigest()


def _config_bytes(config: ProductionConfig) -> bytes:
    return (
        json.dumps(
            config.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _whatsapp_supported() -> bool:
    return sys.platform == "linux" and host_platform.machine().lower() in {
        "amd64",
        "x86_64",
    }
