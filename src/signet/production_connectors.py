"""Shared lifecycle and credential-identity boundaries for live production connectors."""

from __future__ import annotations

import asyncio
import hmac
import inspect
import re
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from signet.adapters.base import ApprovalAdapter
from signet.adapters.fastmail import FastmailAdapter
from signet.adapters.whatsapp import WhatsAppAdapter
from signet.attachment_crypto import AttachmentCipher
from signet.canonical import canonical_json, sha256_hex
from signet.config import ProductionConfig
from signet.credential_broker import SecretReference, SecretStore
from signet.db import Database
from signet.downstream import DownstreamClient
from signet.mcp_mirror import tool_schema_digest, validate_lossless_tool
from signet.policy import PolicyMode, PolicySnapshot
from signet.staging import StagingStore
from signet.wacli_wrapper import WacliConfig, WacliWrapper

_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class ProductionConnectorError(RuntimeError):
    """A redacted live-connector assembly or lifecycle failure."""


class _ConnectorDelegate(Protocol):
    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> object: ...


class _LifecycleClient(Protocol):
    async def start(self) -> None: ...

    async def close(self) -> None: ...


class CredentialBoundClient:
    """Expose only a reviewed credential identity while containing its delegate."""

    __slots__ = ("_alias", "_delegate", "credential_identity_digest")

    def __init__(
        self,
        *,
        alias: str,
        credential_identity_digest: str,
        delegate: object,
    ) -> None:
        if (
            _ALIAS_RE.fullmatch(alias) is None
            or _SHA256_RE.fullmatch(credential_identity_digest) is None
        ):
            raise ValueError("production connector identity is invalid")
        if not callable(getattr(delegate, "call_tool", None)):
            raise ValueError("production connector delegate identity is invalid")
        self._alias = alias
        self.credential_identity_digest = credential_identity_digest
        self._delegate = cast(_ConnectorDelegate, delegate)

    async def start(self) -> None:
        start = getattr(self._delegate, "start", None)
        if not callable(start):
            start = getattr(self._delegate, "verify_version", None)
        if callable(start):
            result = start()
            if not inspect.isawaitable(result):
                raise ProductionConnectorError(
                    f"production connector lifecycle is invalid: {self._alias}"
                )
            await result

    async def close(self) -> None:
        close = getattr(self._delegate, "close", None)
        if callable(close):
            result = close()
            if not inspect.isawaitable(result):
                raise ProductionConnectorError(
                    f"production connector lifecycle is invalid: {self._alias}"
                )
            await result

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = await self._delegate.call_tool(tool_name, arguments)
        if not isinstance(result, Mapping):
            raise ProductionConnectorError(
                f"production connector returned an invalid result: {self._alias}"
            )
        return result

    async def call_tool_raw(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        call = getattr(self._delegate, "call_tool_raw", None)
        if not callable(call):
            call = self._delegate.call_tool
        result = await call(tool_name, arguments)
        if not isinstance(result, Mapping):
            raise ProductionConnectorError(
                f"production connector returned an invalid result: {self._alias}"
            )
        return result

    def __repr__(self) -> str:
        return (
            f"CredentialBoundClient(alias={self._alias!r}, "
            "credential_identity_digest=<redacted>, delegate=<redacted>)"
        )


class ProviderSessionPool:
    """Reference-count one fail-closed provider lifecycle per runtime process."""

    def __init__(
        self,
        clients: Mapping[str, object],
        *,
        expected_schema_digests: Mapping[str, Mapping[str, str]] | None = None,
        expected_server_identity_digests: Mapping[str, str] | None = None,
    ) -> None:
        if any(
            _ALIAS_RE.fullmatch(alias) is None
            or not callable(getattr(client, "start", None))
            or not callable(getattr(client, "close", None))
            for alias, client in clients.items()
        ):
            raise ValueError("production provider session inventory is invalid")
        self._clients = {alias: cast(_LifecycleClient, client) for alias, client in clients.items()}
        self._expected_schema_digests = {
            alias: dict(digests) for alias, digests in (expected_schema_digests or {}).items()
        }
        self._expected_server_identity_digests = dict(expected_server_identity_digests or {})
        if (
            not set(self._expected_schema_digests).issubset(self._clients)
            or not set(self._expected_server_identity_digests).issubset(self._clients)
            or any(
                _SHA256_RE.fullmatch(digest) is None
                for digest in self._expected_server_identity_digests.values()
            )
        ):
            raise ValueError("production provider identity review is invalid")
        self._lock = asyncio.Lock()
        self._users = 0
        self._started: tuple[tuple[str, _LifecycleClient], ...] = ()

    @property
    def active(self) -> bool:
        return bool(self._started)

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        """Keep the full reviewed session set alive for one consumer lifecycle."""

        await self._acquire()
        try:
            yield
        except asyncio.CancelledError:
            with suppress(asyncio.CancelledError, ProductionConnectorError):
                await asyncio.shield(self._release())
            raise
        except BaseException:
            await asyncio.shield(self._release())
            raise
        else:
            await asyncio.shield(self._release())

    async def _acquire(self) -> None:
        async with self._lock:
            if self._users:
                self._users += 1
                return
            started: list[tuple[str, _LifecycleClient]] = []
            failed_alias = "unknown"
            try:
                for alias, client in self._clients.items():
                    failed_alias = alias
                    started.append((alias, client))
                    await client.start()
                    await self._verify_identity_contract(alias, client)
            except asyncio.CancelledError:
                with suppress(ProductionConnectorError):
                    await self._close_started(started)
                raise
            except Exception:
                await self._close_started(started)
                raise ProductionConnectorError(
                    f"production provider session startup failed: {failed_alias}"
                ) from None
            self._started = tuple(started)
            self._users = 1

    async def _verify_identity_contract(self, alias: str, client: _LifecycleClient) -> None:
        expected_identity = self._expected_server_identity_digests.get(alias)
        if expected_identity is not None:
            identity = getattr(client, "initialization_identity", None)
            if not isinstance(identity, Mapping):
                raise ProductionConnectorError(
                    "production provider initialization identity is invalid"
                )
            actual_identity = sha256_hex(canonical_json(dict(identity)))
            if not hmac.compare_digest(actual_identity, expected_identity):
                raise ProductionConnectorError(
                    "production provider initialization identity drift was detected"
                )

        expected = self._expected_schema_digests.get(alias)
        if not expected:
            return
        discover = getattr(client, "discover_all_tools", None)
        if not callable(discover):
            raise ProductionConnectorError("production provider schema discovery is unavailable")
        operation = discover()
        if not inspect.isawaitable(operation):
            raise ProductionConnectorError("production provider schema discovery is invalid")
        raw_tools = await operation
        if not isinstance(raw_tools, list):
            raise ProductionConnectorError("production provider schema discovery is invalid")
        reviewed_tools = [validate_lossless_tool(raw) for raw in raw_tools]
        discovered = {str(raw["name"]): tool_schema_digest(raw) for raw in reviewed_tools}
        if len(discovered) != len(reviewed_tools) or discovered != expected:
            raise ProductionConnectorError("production provider schema drift was detected")

    async def _release(self) -> None:
        async with self._lock:
            if self._users < 1:
                raise ProductionConnectorError(
                    "production provider session lifecycle is unbalanced"
                )
            self._users -= 1
            if self._users:
                return
            started = list(self._started)
            self._started = ()
            await self._close_started(started)

    @staticmethod
    async def _close_started(started: list[tuple[str, _LifecycleClient]]) -> None:
        failure: str | None = None
        for alias, client in reversed(started):
            try:
                await client.close()
            except asyncio.CancelledError:
                failure = alias
            except Exception:
                failure = alias
        if failure is not None:
            raise ProductionConnectorError(
                f"production provider session shutdown failed: {failure}"
            ) from None


@dataclass(frozen=True, slots=True)
class ProductionProviderBundle:
    clients: Mapping[str, object]
    adapters: Mapping[tuple[str, str], ApprovalAdapter]
    staging: StagingStore
    sessions: ProviderSessionPool


def build_live_provider_bundle(
    config: ProductionConfig,
    *,
    database: Database,
    policy: PolicySnapshot,
    secret_store: SecretStore,
) -> ProductionProviderBundle:
    """Assemble the explicitly enabled provider paths without starting sessions."""

    if config.provider_rollout.state != "enabled":
        raise ProductionConnectorError("live provider rollout is disabled")
    staging_root = config.storage.attachment_staging_dir
    attachment_reference = config.secrets.attachment_key_ref
    if staging_root is None or attachment_reference is None:
        raise ProductionConnectorError("live provider attachment staging is unavailable")
    try:
        parsed_attachment_reference = SecretReference.parse(attachment_reference)
        attachment_secret = secret_store.get(parsed_attachment_reference)
        cipher = AttachmentCipher(attachment_secret, attachment_reference)
        staging = StagingStore(
            staging_root,
            database=database,
            cipher=cipher,
            allowed_source_roots=config.storage.attachment_source_roots,
        )
    except Exception:
        raise ProductionConnectorError(
            "live provider attachment staging could not be initialized"
        ) from None

    clients: dict[str, object] = {}
    adapters: dict[tuple[str, str], ApprovalAdapter] = {}
    for alias, connector in config.connectors.items():
        downstream = policy.downstreams[alias]
        missing_schema_digests = tuple(
            tool_name for tool_name, tool in downstream.tools.items() if tool.schema_digest is None
        )
        if missing_schema_digests:
            raise ProductionConnectorError(
                f"live provider policy is missing a reviewed schema digest: {alias}"
            )
        if alias == "fastmail":
            if connector.transport != "http":
                raise ProductionConnectorError("Fastmail requires the reviewed HTTP transport")
            if connector.server_identity_digest is None:
                raise ProductionConnectorError(
                    "Fastmail requires a reviewed MCP initialization identity"
                )
            search_policy = downstream.tools.get("search_email")
            if search_policy is None or search_policy.mode.value != "passthrough":
                raise ProductionConnectorError(
                    "Fastmail requires reviewed read-only reconciliation"
                )
            account = _policy_account(policy, alias, "send_email")
            if _policy_account(policy, alias, "search_email") != account:
                raise ProductionConnectorError(
                    "Fastmail reconciliation account scope is inconsistent"
                )
            http_client = DownstreamClient(alias, connector, secret_store)
            adapter = FastmailAdapter(
                staging_store=staging,
                account=account,
                reviewed_dispatch_enabled=True,
            )
            _require_approval_send(
                policy,
                alias,
                "send_email",
                adapter.adapter_id,
            )
            clients[alias] = http_client
            adapters[(alias, "send_email")] = cast(ApprovalAdapter, adapter)
            continue
        if alias == "whatsapp":
            client, whatsapp_adapters = _build_whatsapp(
                config,
                policy=policy,
                staging=staging,
            )
            clients[alias] = client
            adapters.update(whatsapp_adapters)
            continue
        raise ProductionConnectorError(f"live provider alias is unsupported: {alias}")
    if not clients:
        raise ProductionConnectorError("live provider rollout has no connector inventory")
    expected_schema_digests = {
        alias: {
            tool_name: cast(str, tool.schema_digest)
            for tool_name, tool in policy.downstreams[alias].tools.items()
        }
        for alias, client in clients.items()
        if isinstance(client, DownstreamClient)
    }
    sessions = ProviderSessionPool(
        clients,
        expected_schema_digests=expected_schema_digests,
        expected_server_identity_digests={
            alias: client.server_identity_digest
            for alias, client in config.connectors.items()
            if isinstance(clients[alias], DownstreamClient)
            and client.server_identity_digest is not None
        },
    )
    return ProductionProviderBundle(
        clients=clients,
        adapters=adapters,
        staging=staging,
        sessions=sessions,
    )


def _policy_account(policy: PolicySnapshot, alias: str, tool_name: str) -> str:
    try:
        downstream = policy.downstreams[alias]
        tool = downstream.tools[tool_name]
    except KeyError:
        raise ProductionConnectorError(
            f"live provider policy route is unavailable: {alias}/{tool_name}"
        ) from None
    accounts = tuple(
        account for account in (downstream.account_ref, tool.account_ref) if account is not None
    )
    if not accounts or len(set(accounts)) != 1:
        raise ProductionConnectorError(
            f"live provider account scope is unavailable: {alias}/{tool_name}"
        )
    return accounts[0]


def _build_whatsapp(
    config: ProductionConfig,
    *,
    policy: PolicySnapshot,
    staging: StagingStore,
) -> tuple[CredentialBoundClient, dict[tuple[str, str], ApprovalAdapter]]:
    connector = config.connectors["whatsapp"]
    boundary = config.provider_rollout.wacli
    if connector.transport != "stdio" or boundary is None:
        raise ProductionConnectorError("WhatsApp requires the owned wacli process boundary")
    if (
        len(connector.command) != 1
        or connector.url is not None
        or connector.working_directory != boundary.home.parent
        or connector.execution_snapshot_root is None
        or connector.executable_sha256 is None
        or connector.server_identity_digest is not None
        or connector.output_limit_bytes != boundary.max_output_bytes
    ):
        raise ProductionConnectorError("WhatsApp wacli process boundary is inconsistent")
    policy_account = _policy_account_for_whatsapp(policy)
    if policy_account != f"account:{boundary.account}":
        raise ProductionConnectorError("WhatsApp account boundary is inconsistent")
    try:
        delegate = WacliWrapper(
            WacliConfig(
                account=boundary.account,
                executable=Path(connector.command[0]),
                expected_version=boundary.expected_version,
                expected_sha256=connector.executable_sha256,
                staging_root=staging.root,
                home=boundary.home,
                store=boundary.store,
                timeout_seconds=connector.timeout_seconds,
                cli_timeout=boundary.cli_timeout,
                max_output_bytes=boundary.max_output_bytes,
                reviewed_dispatch_enabled=True,
                execution_snapshot_root=connector.execution_snapshot_root,
            ),
            staging_store=staging,
        )
    except Exception:
        raise ProductionConnectorError("WhatsApp wacli process boundary is unavailable") from None
    client = CredentialBoundClient(
        alias="whatsapp",
        credential_identity_digest=connector.credential_identity_digest,
        delegate=delegate,
    )
    adapters: dict[tuple[str, str], ApprovalAdapter] = {}
    whatsapp_policy = policy.downstreams["whatsapp"]
    for tool_name in ("send_text", "send_file"):
        if tool_name not in whatsapp_policy.tools:
            continue
        adapter = WhatsAppAdapter(
            tool_name=tool_name,
            staging_store=staging,
            account=_policy_account(policy, "whatsapp", tool_name),
            reviewed_dispatch_enabled=True,
        )
        _require_approval_send(
            policy,
            "whatsapp",
            tool_name,
            adapter.adapter_id,
        )
        adapters[("whatsapp", tool_name)] = cast(ApprovalAdapter, adapter)
    if not adapters:
        raise ProductionConnectorError("WhatsApp has no reviewed send tool")
    return client, adapters


def _policy_account_for_whatsapp(policy: PolicySnapshot) -> str:
    accounts = {
        _policy_account(policy, "whatsapp", tool_name)
        for tool_name in ("send_text", "send_file")
        if tool_name in policy.downstreams["whatsapp"].tools
    }
    if len(accounts) != 1:
        raise ProductionConnectorError("WhatsApp tools must share one account scope")
    return accounts.pop()


def _require_approval_send(
    policy: PolicySnapshot,
    alias: str,
    tool_name: str,
    adapter_id: str,
) -> None:
    tool = policy.downstreams[alias].tools[tool_name]
    if (
        tool.mode is not PolicyMode.APPROVAL
        or not tool.communication_send
        or tool.adapter != adapter_id
    ):
        raise ProductionConnectorError(
            f"live provider send route is not approval-bound: {alias}/{tool_name}"
        )
