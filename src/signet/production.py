"""Production-safe runtime assembly from the versioned configuration document."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from fastapi import FastAPI
from starlette.applications import Starlette

from signet.access_requests import FrozenAccessRequestFactory
from signet.adapters.base import ApprovalAdapter, MCPClient
from signet.adapters.tool_access import ToolAccessAdapter
from signet.admission import QueueAdmissionLimits
from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.auth import (
    Argon2PasswordVerifier,
    PasswordAuthenticator,
    ProofCapability,
    SessionManager,
    SQLiteAttemptLimiter,
    SQLiteAuthenticationTransactions,
    SQLitePasswordCredentialRepository,
    SQLiteSessionRepository,
)
from signet.config import ProductionConfig
from signet.credential_broker import (
    KeychainSecretStore,
    Secret,
    SecretReference,
    SecretStore,
    SQLiteTokenRegistry,
)
from signet.crypto import PayloadCipher
from signet.db import Database, PreMigrationBackup
from signet.execution_scope import PolicyExecutionScopeResolver
from signet.freezer import RequestFreezer
from signet.gateway import GatewayCallPipeline, RawDownstreamClient
from signet.gateway_tools import (
    GatewayTools,
    GatewayToolSurface,
    SafeRequestSummary,
)
from signet.mcp_mirror import AliasToolSurface, SchemaMirror
from signet.notifications import SQLitePushRepository
from signet.policy import PolicyEngine, PolicySnapshot, parse_policy_yaml
from signet.policy_persistence import (
    PolicyPersistenceError,
    SQLiteActionDraftRepository,
    SQLitePolicyPromotionBoundary,
)
from signet.private_paths import PrivatePathError, require_no_acl_grants
from signet.production_state import (
    ProductionServiceRecord,
    ProductionStateStore,
    ProductionStatus,
)
from signet.runtime import MCPRuntime, assemble_mcp_runtime, gateway_principal_provider
from signet.schema_registry import DurableSchemaRegistry, SchemaRegistryError
from signet.state_machine import ApprovalStateMachine
from signet.totp import SQLiteTotpCredentialRepository, TotpVerifier
from signet.web import CsrfManager, WebSettings, create_web_app
from signet.web_backend import EncryptedPayloadReviewer, PolicyPromotionBoundary
from signet.web_backend import WebBackend as PersistentWebBackend
from signet.webauthn import (
    SQLiteWebAuthnRepository,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
)

_REQUIRED_SECRET_PURPOSES = (
    "session_secret_ref",
    "csrf_secret_ref",
    "capability_key_ref",
    "payload_key_ref",
)
_CAPABILITY_ORDER = (
    "storage_ready",
    "secret_broker_ready",
    "mcp_ready",
    "web_ready",
    "workers_ready",
    "policy_ready",
    "live_providers_ready",
)
_MAX_PRIVATE_DOCUMENT_BYTES = 1_048_576


class ProductionAssemblyError(RuntimeError):
    """Production configuration could not be assembled without weakening safety."""


class ProductionDisabledProviderClient:
    """Provider boundary that cannot initialize or perform network/process calls."""

    def __init__(self, alias: str, *, credential_identity_digest: str) -> None:
        self.alias = alias
        self.credential_identity_digest = credential_identity_digest

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del tool_name, arguments
        raise ProductionAssemblyError(
            f"production provider {self.alias!r} is blocked until a later reviewed slice"
        )

    async def call_tool_raw(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        await self.call_tool(tool_name, arguments)
        raise AssertionError("blocked production provider returned unexpectedly")


class ProductionSummaryProvider:
    def __init__(self, reviewer: EncryptedPayloadReviewer) -> None:
        self._reviewer = reviewer

    def get(
        self,
        request_id: str,
        *,
        version: int,
        payload_hash: str,
    ) -> SafeRequestSummary:
        reviewed = self._reviewer.review(
            request_id,
            version=version,
            payload_hash=payload_hash,
        )
        return SafeRequestSummary(
            service=reviewed.summary.service,
            tool=reviewed.adapter.tool_name,
            destination_summary=reviewed.summary.destination_summary,
        )


class ProductionWorkers:
    """Explicit lifecycle for provider-free maintenance in a separate process."""

    def __init__(
        self,
        *,
        approvals: ApprovalStateMachine,
        policy_promotions: SQLitePolicyPromotionBoundary,
        interval_seconds: float = 5.0,
    ) -> None:
        if interval_seconds < 0.1 or interval_seconds > 300:
            raise ValueError("production worker interval must be 0.1 to 300 seconds")
        self._approvals = approvals
        self._policy_promotions = policy_promotions
        self._interval_seconds = interval_seconds
        self._running = False
        self._healthy = True

    @property
    def running(self) -> bool:
        return self._running

    @property
    def healthy(self) -> bool:
        return self._healthy

    async def run_once(self, *, now: int | None = None) -> None:
        selected_now = int(time.time()) if now is None else now
        if not isinstance(selected_now, int) or isinstance(selected_now, bool) or selected_now < 0:
            raise ValueError("production maintenance time is invalid")
        try:
            await self._policy_promotions.publish_pending(now=selected_now)
            await _run_sync(self._approvals.sweep_expired, now=selected_now, limit=100)
        except BaseException:
            self._healthy = False
            raise
        self._healthy = True

    async def serve(self, stop: asyncio.Event) -> None:
        """Recover execution fences, then maintain state until the stop event is set."""

        if not isinstance(stop, asyncio.Event):
            raise TypeError("production workers require an asyncio stop event")
        if self._running:
            raise RuntimeError("production workers are already running")
        self._running = True
        try:
            await _run_sync(self._approvals.recover_startup, now=int(time.time()))
            while not stop.is_set():
                await self.run_once()
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
                except TimeoutError:
                    continue
        finally:
            self._running = False


@dataclass(frozen=True, slots=True)
class ProductionAssembly:
    config: ProductionConfig
    database: Database
    policy: PolicySnapshot
    mcp: MCPRuntime
    web: FastAPI
    workers: ProductionWorkers
    state: ProductionStateStore
    schema_registry: DurableSchemaRegistry
    token_registry: SQLiteTokenRegistry
    provider_clients: Mapping[str, MCPClient]

    def status(self) -> ProductionStatus:
        return self.state.status()


def load_production_config(path: str | os.PathLike[str]) -> ProductionConfig:
    """Load a private JSON config without accepting environment secret material."""

    config_path = Path(path).expanduser().absolute()
    payload = _read_private_config(config_path)
    try:
        return ProductionConfig.model_validate_json(payload)
    except Exception as exc:
        raise ProductionAssemblyError("production configuration is invalid") from exc


def create_production_assembly(
    config_path: str | os.PathLike[str],
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
) -> ProductionAssembly:
    return build_production_runtime(
        load_production_config(config_path),
        secret_store=secret_store,
        pre_migration_backup=pre_migration_backup,
    )


def create_production_mcp_runtime(
    config_path: str | os.PathLike[str],
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
) -> MCPRuntime:
    return create_production_assembly(
        config_path,
        secret_store=secret_store,
        pre_migration_backup=pre_migration_backup,
    ).mcp


def create_production_web_app(
    config_path: str | os.PathLike[str],
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
) -> FastAPI:
    return create_production_assembly(
        config_path,
        secret_store=secret_store,
        pre_migration_backup=pre_migration_backup,
    ).web


def create_production_mcp_app_from_environment(
    *,
    secret_store: SecretStore | None = None,
) -> Starlette:
    """ASGI factory for the provider-disabled MCP service."""

    return create_production_mcp_runtime(
        _production_config_path_from_environment(),
        secret_store=secret_store or KeychainSecretStore(),
    ).app


def create_production_web_app_from_environment(
    *,
    secret_store: SecretStore | None = None,
) -> FastAPI:
    """ASGI factory for the staged production web service."""

    return create_production_web_app(
        _production_config_path_from_environment(),
        secret_store=secret_store or KeychainSecretStore(),
    )


def build_production_runtime(
    config: ProductionConfig,
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
    clock: Callable[[], int] | None = None,
) -> ProductionAssembly:
    """Assemble MCP, web, and provider-free workers without any provider calls."""

    now = clock or (lambda: int(time.time()))
    selected_now = now()
    if not isinstance(selected_now, int) or isinstance(selected_now, bool) or selected_now < 0:
        raise ProductionAssemblyError("production clock returned an invalid value")

    config.prepare_directories()
    policy = _load_policy(config.policy_path)
    _validate_policy_connector_bindings(config, policy)
    secret_references, secret_values = _resolve_secret_inventory(config, secret_store)
    _resolve_connector_credentials(config, secret_store)

    database = Database(config.storage.data_dir / "signet.db")
    database.initialize(pre_migration_backup=pre_migration_backup)

    capabilities = ProofCapability(secret_values["capability_key_ref"].reveal().encode("utf-8"))
    payload_cipher = PayloadCipher(
        secret_values["payload_key_ref"],
        secret_references["payload_key_ref"],
    )
    freezer = RequestFreezer(payload_cipher)
    engine = PolicyEngine(policy)
    mirror = SchemaMirror(policy)
    clients: Mapping[str, ProductionDisabledProviderClient] = MappingProxyType(
        {
            alias: ProductionDisabledProviderClient(
                alias,
                credential_identity_digest=connector.credential_identity_digest,
            )
            for alias, connector in config.connectors.items()
        }
    )
    execution_scopes = PolicyExecutionScopeResolver(mirror, clients)
    tool_access = ToolAccessAdapter()
    reviewer_adapters = {
        (tool_access.downstream_alias, tool_access.tool_name): cast(ApprovalAdapter, tool_access)
    }
    approvals = ApprovalStateMachine(
        database,
        capabilities=capabilities,
        notification_user_id=config.owner_user_id,
        admission_limits=QueueAdmissionLimits(
            queue_limit=1_000,
            origin_pending_limit=500,
            tool_pending_limit=500,
            minimum_free_bytes=1024 * 1024,
        ),
    )
    reviewer = EncryptedPayloadReviewer(
        approvals,
        payload_cipher,
        reviewer_adapters,
        execution_scopes,
    )
    surfaces: dict[str, AliasToolSurface] = {}

    async def notify_list_changed(aliases: frozenset[str]) -> None:
        for alias in sorted(aliases):
            surface = surfaces.get(alias)
            if surface is None:
                raise PolicyPersistenceError(
                    "policy publication target has no production MCP surface"
                )
            await surface.notify_list_changed(strict=True)

    def apply_policy(snapshot: PolicySnapshot) -> None:
        mirror.apply_policy(snapshot)

    policy_promotions = SQLitePolicyPromotionBoundary(
        database,
        approvals,
        reviewer,
        engine,
        config.policy_path,
        apply_policy=apply_policy,
        publication_gate=mirror,
        notify_list_changed=notify_list_changed,
    )
    pipeline = GatewayCallPipeline(
        mirror=mirror,
        downstream_clients=cast(Mapping[str, RawDownstreamClient], clients),
        local_handlers={},
        adapters={},
        execution_scopes=execution_scopes,
        freezer=freezer,
        enqueuer=approvals,
    )
    for alias in config.connectors:
        surfaces[alias] = AliasToolSurface(
            alias=alias,
            mirror=mirror,
            call_handler=pipeline.handle_call,
        )
    schema_registry = DurableSchemaRegistry(
        database=database,
        mirror=mirror,
        surfaces=surfaces,
    )
    try:
        schema_registry.restore()
    except SchemaRegistryError:
        raise ProductionAssemblyError(
            "the durable production tool schema cache failed closed"
        ) from None

    limiter = SQLiteAttemptLimiter(database)
    totp = TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        secret_store,
        limiter,
        capabilities=capabilities,
    )
    access_requests = FrozenAccessRequestFactory(
        freezer,
        policy_version=lambda: engine.snapshot.version,
    )
    gateway_tools = GatewayTools(
        state_machine=approvals,
        totp_verifier=totp,
        summaries=ProductionSummaryProvider(reviewer),
        access_requests=access_requests,
    )
    gateway_surface = GatewayToolSurface(
        tools=gateway_tools,
        principal_provider=gateway_principal_provider(config.owner_user_id),
    )
    token_registry = SQLiteTokenRegistry(database, allowed_principals={})
    mcp = assemble_mcp_runtime(
        aliases=surfaces,
        approvals=gateway_surface,
        tokens=token_registry,
        bind_host=config.mcp_host,
        bind_port=config.mcp_port,
    )

    sessions = SessionManager(
        SQLiteSessionRepository(database),
        signing_key=secret_values["session_secret_ref"].reveal().encode("utf-8"),
    )
    passwords = PasswordAuthenticator(
        SQLitePasswordCredentialRepository(database),
        limiter,
        capabilities=capabilities,
        verifier=Argon2PasswordVerifier(),
    )
    webauthn_repository = SQLiteWebAuthnRepository(database)
    webauthn_issuer = WebAuthnChallengeIssuer(webauthn_repository, rp_id=config.rp_id)
    webauthn_verifier = WebAuthnAssertionVerifier(
        webauthn_repository,
        rp_id=config.rp_id,
        origin=config.public_origin,
        capabilities=capabilities,
    )
    authentication_transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=secret_values["session_secret_ref"].reveal().encode("utf-8"),
        capabilities=capabilities,
    )
    backend = PersistentWebBackend(
        database,
        authorized_user_id=config.owner_user_id,
        sessions=sessions,
        passwords=passwords,
        totp=totp,
        webauthn_repository=webauthn_repository,
        webauthn_issuer=webauthn_issuer,
        webauthn_verifier=webauthn_verifier,
        authentication_transactions=authentication_transactions,
        state_machine=approvals,
        payloads=reviewer,
        action_drafts=SQLiteActionDraftRepository(database),
        policy_promotions=cast(PolicyPromotionBoundary, policy_promotions),
        pushes=SQLitePushRepository(database),
    )
    web = create_web_app(
        backend,
        settings=WebSettings(
            public_origin=config.public_origin,
            allowed_hosts=config.allowed_hosts,
        ),
        csrf=CsrfManager(secret_values["csrf_secret_ref"].reveal().encode("utf-8")),
    )
    workers = ProductionWorkers(
        approvals=approvals,
        policy_promotions=policy_promotions,
    )

    capability_status = MappingProxyType(
        {name: bool(getattr(config.capabilities, name)) for name in _CAPABILITY_ORDER}
    )
    state = ProductionStateStore(database)
    state.stage(
        config,
        policy,
        capabilities=capability_status,
        secret_references=secret_references,
        services=_service_inventory(config, capability_status),
        now=selected_now,
    )

    def production_health_probe() -> bool:
        return workers.healthy and state.status().ready

    web.state.signet_health_probe = production_health_probe
    return ProductionAssembly(
        config=config,
        database=database,
        policy=policy,
        mcp=mcp,
        web=web,
        workers=workers,
        state=state,
        schema_registry=schema_registry,
        token_registry=token_registry,
        provider_clients=clients,
    )


def _service_inventory(
    config: ProductionConfig,
    capabilities: Mapping[str, bool],
) -> tuple[ProductionServiceRecord, ...]:
    def staged(capability: str) -> str:
        return "staged" if capabilities[capability] else "blocked"

    return (
        ProductionServiceRecord(
            "mcp", "mcp", cast(Any, staged("mcp_ready")), config.mcp_host, config.mcp_port
        ),
        ProductionServiceRecord(
            "web", "web", cast(Any, staged("web_ready")), config.web_host, config.web_port
        ),
        ProductionServiceRecord("maintenance", "maintenance", cast(Any, staged("workers_ready"))),
        ProductionServiceRecord("delivery", "worker", "blocked"),
        ProductionServiceRecord("reconciliation", "worker", "blocked"),
        ProductionServiceRecord("retention", "worker", "blocked"),
        ProductionServiceRecord("notifications", "worker", "blocked"),
    )


def _resolve_secret_inventory(
    config: ProductionConfig,
    secret_store: SecretStore,
) -> tuple[Mapping[str, str], Mapping[str, Secret]]:
    references = {
        purpose: reference
        for purpose, reference in config.secrets.model_dump().items()
        if reference is not None
    }
    missing = tuple(purpose for purpose in _REQUIRED_SECRET_PURPOSES if purpose not in references)
    if missing:
        raise ProductionAssemblyError(
            "required production secret references are missing: " + ", ".join(missing)
        )
    values: dict[str, Secret] = {}
    try:
        for purpose, raw_reference in references.items():
            reference = SecretReference.parse(raw_reference)
            value = secret_store.get(reference)
            if purpose in _REQUIRED_SECRET_PURPOSES:
                encoded = value.reveal().encode("utf-8")
                if not 32 <= len(encoded) <= 4_096:
                    raise ProductionAssemblyError(
                        "production cryptographic secrets must be 32 to 4096 UTF-8 bytes"
                    )
            values[purpose] = value
    except ProductionAssemblyError:
        raise
    except Exception as exc:
        raise ProductionAssemblyError(
            "a configured production secret could not be resolved"
        ) from exc
    return MappingProxyType(references), MappingProxyType(values)


def _resolve_connector_credentials(
    config: ProductionConfig,
    secret_store: SecretStore,
) -> None:
    try:
        for connector in config.connectors.values():
            secret_store.get(SecretReference.parse(connector.credential_ref))
    except Exception as exc:
        raise ProductionAssemblyError(
            "a configured production connector credential could not be resolved"
        ) from exc


def _validate_policy_connector_bindings(
    config: ProductionConfig,
    policy: PolicySnapshot,
) -> None:
    if set(config.connectors) != set(policy.downstreams):
        raise ProductionAssemblyError(
            "production config and policy connector aliases must match exactly"
        )
    for alias, connector in config.connectors.items():
        downstream = policy.downstreams[alias]
        if (
            downstream.transport != connector.transport
            or downstream.credential_ref != connector.credential_ref
            or connector.transport == "http"
            and downstream.url != connector.url
        ):
            raise ProductionAssemblyError(
                f"production connector {alias!r} differs from its policy binding"
            )


def _load_policy(path: Path) -> PolicySnapshot:
    try:
        payload = _read_private_document(path, label="production policy")
        return parse_policy_yaml(payload.encode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProductionAssemblyError("production policy could not be loaded") from exc


def _read_private_config(path: Path) -> str:
    payload = _read_private_document(path, label="production configuration")
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ProductionAssemblyError("production configuration is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ProductionAssemblyError("production configuration must be a JSON object")
    return payload


def _production_config_path_from_environment() -> Path:
    raw_path = os.environ.get("SIGNET_PRODUCTION_CONFIG")
    if raw_path is None or not raw_path.strip() or "\x00" in raw_path:
        raise ProductionAssemblyError("SIGNET_PRODUCTION_CONFIG must name the private config file")
    return Path(raw_path).expanduser().absolute()


def _read_private_document(path: Path, *, label: str) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProductionAssemblyError(f"{label} could not be opened safely") from exc

    operation_error: BaseException | None = None
    try:
        before = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > _MAX_PRIVATE_DOCUMENT_BYTES
        ):
            raise ProductionAssemblyError(
                f"{label} must be an owned mode-0600 regular file within the size limit"
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65_536, _MAX_PRIVATE_DOCUMENT_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_PRIVATE_DOCUMENT_BYTES:
                raise ProductionAssemblyError(f"{label} exceeds the size limit")
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or size != after.st_size:
            raise ProductionAssemblyError(f"{label} changed while it was read")
        return b"".join(chunks).decode("utf-8")
    except (OSError, PrivatePathError, UnicodeDecodeError) as exc:
        operation_error = exc
        raise ProductionAssemblyError(f"{label} could not be read safely") from exc
    except BaseException as exc:
        operation_error = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if operation_error is None:
                raise ProductionAssemblyError(f"{label} descriptor could not be closed") from exc
