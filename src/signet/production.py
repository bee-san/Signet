"""Production-safe runtime assembly from the versioned configuration document."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import stat
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast

from fastapi import FastAPI
from starlette.applications import Starlette

from signet.access_requests import FrozenAccessRequestFactory
from signet.adapters.base import ApprovalAdapter, MCPClient
from signet.adapters.tool_access import ToolAccessAdapter
from signet.admission import QueueAdmissionLimits
from signet.async_support import (
    await_task_while_preserving_cancellation,
)
from signet.async_support import (
    run_sync_non_abandoning as _run_sync,
)
from signet.attachment_crypto import AttachmentCipher
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
from signet.authenticator_management import (
    AuthenticatorManager,
    KeychainTotpSecretProvisioner,
    TotpSecretProvisioner,
)
from signet.browser_auth import BootstrapService, BrowserAuthController
from signet.config import ProductionConfig
from signet.credential_broker import (
    KeychainSecretStore,
    Secret,
    SecretReference,
    SecretStore,
    SQLiteTokenRegistry,
)
from signet.crypto import PayloadCipher
from signet.db import (
    Database,
    MigrationBackupReceipt,
    PreMigrationBackup,
    PreMigrationBackupRequired,
    _file_sha256,
)
from signet.delivery import DeliveryDispatcher, DeliveryError, FrozenRequestLoader
from signet.execution_scope import PolicyExecutionScopeResolver
from signet.freezer import RequestFreezer
from signet.gateway import GatewayCallPipeline, RawDownstreamClient
from signet.gateway_tools import (
    GatewayTools,
    GatewayToolSurface,
    SafeRequestSummary,
)
from signet.mcp_mirror import AliasToolSurface, SchemaMirror
from signet.models import InvalidTransition, ReconciliationRejected, RequestState
from signet.notifications import SQLitePushRepository
from signet.policy import PolicyEngine, PolicySnapshot, parse_policy_yaml
from signet.policy_persistence import (
    PolicyPersistenceError,
    SQLiteActionDraftRepository,
    SQLitePolicyPromotionBoundary,
)
from signet.private_paths import PrivatePathError, require_no_acl_grants
from signet.production_connectors import (
    ProductionConnectorError,
    ProviderSessionPool,
    build_live_provider_bundle,
    build_review_only_provider_adapters,
    provider_execution_identity_digest,
)
from signet.production_state import (
    ProductionServiceRecord,
    ProductionStateStore,
    ProductionStatus,
)
from signet.reconcile import ReconciliationCoordinator
from signet.retention import RetentionManager, RetentionMatrix
from signet.runtime import (
    MCPRuntime,
    TrustedProxySourceMiddleware,
    assemble_mcp_runtime,
    gateway_principal_provider,
)
from signet.schema_registry import DurableSchemaRegistry, SchemaRegistryError
from signet.staging import (
    StagingError,
    StagingStore,
    open_confined_readonly,
    read_verified_descriptor,
)
from signet.state_machine import ApprovalStateMachine
from signet.totp import SQLiteTotpCredentialRepository, TotpVerifier
from signet.totp_enrollment import TotpEnrollmentService
from signet.web import CsrfManager, WebSettings, create_web_app
from signet.web_backend import (
    EncryptedPayloadReviewer,
    PolicyPromotionBoundary,
)
from signet.web_backend import (
    WebBackend as PersistentWebBackend,
)
from signet.webauthn import (
    SQLiteWebAuthnRepository,
    WebAuthnAssertionVerifier,
    WebAuthnChallengeIssuer,
)
from signet.webauthn_registration import (
    OfficialRegistrationProvider,
    PasskeyRegistrationService,
)

_REQUIRED_SECRET_PURPOSES = (
    "session_secret_ref",
    "csrf_secret_ref",
    "capability_key_ref",
    "payload_key_ref",
)
_MAX_PRIVATE_DOCUMENT_BYTES = 1_048_576


def _production_retention_matrix() -> RetentionMatrix:
    payload_delays: dict[RequestState, int | None] = dict.fromkeys(RequestState)
    payload_delays.update(
        {
            RequestState.SUCCEEDED: 7 * 24 * 60 * 60,
            RequestState.FAILED: 7 * 24 * 60 * 60,
            RequestState.DENIED: 7 * 24 * 60 * 60,
            RequestState.EXPIRED: 7 * 24 * 60 * 60,
            RequestState.CANCELLED: 7 * 24 * 60 * 60,
        }
    )
    attachment_delays = dict(payload_delays)
    attachment_delays.update(
        {
            RequestState.SUCCEEDED: 0,
            RequestState.DENIED: 0,
            RequestState.EXPIRED: 24 * 60 * 60,
            RequestState.CANCELLED: 24 * 60 * 60,
        }
    )
    return RetentionMatrix(attachment_delays, payload_delays)


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
    """Explicit lifecycle for maintenance and opt-in provider delivery."""

    def __init__(
        self,
        *,
        approvals: ApprovalStateMachine,
        policy_promotions: SQLitePolicyPromotionBoundary,
        state: ProductionStateStore,
        clock: Callable[[], int],
        database: Database | None = None,
        delivery: DeliveryDispatcher | None = None,
        reconciliation: ReconciliationCoordinator | None = None,
        retention: RetentionManager | None = None,
        provider_sessions: ProviderSessionPool | None = None,
        interval_seconds: float = 5.0,
    ) -> None:
        if interval_seconds < 0.1 or interval_seconds > 300:
            raise ValueError("production worker interval must be 0.1 to 300 seconds")
        self._approvals = approvals
        self._policy_promotions = policy_promotions
        self._state = state
        self._clock = clock
        if (delivery is None) != (reconciliation is None) or (delivery is None) != (
            provider_sessions is None
        ):
            raise ValueError("production provider worker dependencies must be complete")
        if (delivery is not None or retention is not None) and database is None:
            raise ValueError("production provider workers require the database")
        self._database = database
        self._delivery = delivery
        self._reconciliation = reconciliation
        self._retention = retention
        self._provider_sessions = provider_sessions
        self._interval_seconds = interval_seconds
        self._heartbeat_lease_seconds = max(1, math.ceil(interval_seconds * 3))
        self._running = False
        self._healthy = False
        self._startup_complete = asyncio.Event()
        self._startup_error: BaseException | None = None

    @property
    def running(self) -> bool:
        return self._running

    @property
    def healthy(self) -> bool:
        return self._healthy

    @property
    def heartbeat_lease_seconds(self) -> int:
        return self._heartbeat_lease_seconds

    async def wait_started(self) -> None:
        """Wait until startup is ready or has failed and begun unwinding."""

        await self._startup_complete.wait()
        if self._startup_error is not None:
            raise self._startup_error

    def _maintenance_time(self, now: int | None = None) -> int:
        selected_now = self._clock() if now is None else now
        if not isinstance(selected_now, int) or isinstance(selected_now, bool) or selected_now < 0:
            raise ValueError("production maintenance time is invalid")
        return selected_now

    async def run_once(
        self,
        *,
        now: int | None = None,
        stop: asyncio.Event | None = None,
    ) -> None:
        selected_now = self._maintenance_time(now)
        try:
            await self._policy_promotions.publish_pending(now=selected_now)
            await _run_sync(self._approvals.sweep_expired, now=selected_now, limit=100)
            if self._delivery is not None and self._reconciliation is not None:
                for request_id in await _run_sync(self._due_delivery_request_ids, selected_now):
                    if stop is not None and stop.is_set():
                        break
                    try:
                        await self._delivery.dispatch(
                            request_id,
                            worker_id="production:delivery",
                            now=self._maintenance_time(),
                            lease_seconds=30,
                        )
                    except (DeliveryError, InvalidTransition):
                        continue
                reconciliation_now = self._maintenance_time()
                due_reconciliations = await _run_sync(
                    self._reconciliation.due_request_ids,
                    now=reconciliation_now,
                    limit=16,
                )
                for request_id in due_reconciliations:
                    if stop is not None and stop.is_set():
                        break
                    try:
                        await self._reconciliation.reconcile_once(
                            request_id,
                            worker_id="production:reconciliation",
                            now=self._maintenance_time(),
                        )
                    except ReconciliationRejected:
                        continue
            if self._retention is not None and (stop is None or not stop.is_set()):
                await _run_sync(
                    self._retention.run_due,
                    now=self._maintenance_time(),
                    limit=100,
                )
            completed_now = self._maintenance_time(now)
        except BaseException:
            self._healthy = False
            if self._running:
                self._state.record_worker_state("blocked", ready=False, now=selected_now)
            raise
        if self._running:
            self._healthy = True
            self._state.record_worker_state("ready", ready=True, now=completed_now)

    def _due_delivery_request_ids(self, now: int) -> tuple[str, ...]:
        if self._database is None:
            return ()
        with self._database.read() as connection:
            return tuple(
                str(row["request_id"])
                for row in connection.execute(
                    """
                    SELECT request.request_id
                    FROM approval_requests AS request
                    LEFT JOIN execution_attempts AS attempt
                      ON attempt.request_id = request.request_id
                     AND attempt.version = request.current_version
                    WHERE request.state = 'approved'
                       OR (
                           request.state = 'executing'
                           AND attempt.phase IN ('preparing', 'redispatch_preparing')
                           AND attempt.lease_expires_at <= ?
                       )
                    ORDER BY COALESCE(request.approved_at, request.execution_started_at),
                             request.request_id
                    LIMIT 16
                    """,
                    (now,),
                ).fetchall()
            )

    async def serve(self, stop: asyncio.Event) -> None:
        """Recover execution fences, then maintain state until the stop event is set."""

        if not isinstance(stop, asyncio.Event):
            raise TypeError("production workers require an asyncio stop event")
        if self._running:
            raise RuntimeError("production workers are already running")
        self._startup_complete.clear()
        self._startup_error = None
        self._running = True
        self._healthy = False
        failed = False
        provider_stack = AsyncExitStack()
        try:
            selected_now = self._maintenance_time()
            self._state.record_worker_state("blocked", ready=False, now=selected_now)
            await provider_stack.__aenter__()
            if self._provider_sessions is not None:
                await provider_stack.enter_async_context(self._provider_sessions.run())
                self._state.record_provider_state(
                    "active",
                    ready=True,
                    now=self._maintenance_time(),
                )
            await _run_sync(self._approvals.recover_startup, now=self._maintenance_time())
            self._healthy = True
            self._state.record_worker_state("ready", ready=True, now=self._maintenance_time())
            self._startup_complete.set()
            while not stop.is_set():
                await self.run_once(stop=stop)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
                except TimeoutError:
                    continue
        except BaseException as exc:
            failed = True
            self._healthy = False
            self._startup_error = exc
            self._startup_complete.set()
            self._state.record_worker_state("blocked", ready=False, now=self._maintenance_time())
            raise
        finally:
            self._running = False
            self._startup_complete.set()
            try:
                await provider_stack.aclose()
            finally:
                if self._provider_sessions is not None:
                    provider_ready = self._provider_sessions.active
                    self._state.record_provider_state(
                        "active" if provider_ready else "blocked",
                        ready=provider_ready,
                        now=self._maintenance_time(),
                    )
            if not failed:
                self._healthy = False
                self._state.record_worker_state(
                    "stopped", ready=False, now=self._maintenance_time()
                )


@dataclass(frozen=True, slots=True)
class ProductionAssembly:
    config: ProductionConfig
    database: Database
    policy_engine: PolicyEngine
    mcp: MCPRuntime | None
    web: FastAPI | None
    workers: ProductionWorkers
    state: ProductionStateStore
    schema_registry: DurableSchemaRegistry
    token_registry: SQLiteTokenRegistry
    provider_clients: Mapping[str, MCPClient]
    adapters: Mapping[tuple[str, str], ApprovalAdapter]
    staging: StagingStore | None
    retention: RetentionManager | None
    provider_sessions: ProviderSessionPool | None
    authenticators: AuthenticatorManager

    @property
    def policy(self) -> PolicySnapshot:
        return self.policy_engine.snapshot

    def status(self) -> ProductionStatus:
        status = self.state.status()
        if self.provider_sessions is None or self.provider_sessions.active:
            return status
        missing = status.missing_prerequisites
        if "live_providers_ready" not in missing:
            missing = (*missing, "live_providers_ready")
        return replace(
            status,
            ready=False,
            missing_prerequisites=missing,
            live_providers_ready=False,
        )


def load_production_config(path: str | os.PathLike[str]) -> ProductionConfig:
    """Load a private JSON config without accepting environment secret material."""

    config_path = Path(path).expanduser().absolute()
    payload = _read_private_config(config_path)
    try:
        return ProductionConfig.model_validate_json(payload)
    except Exception:
        raise ProductionAssemblyError("production configuration is invalid") from None


def create_production_assembly(
    config_path: str | os.PathLike[str],
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
    components: frozenset[str] = frozenset({"mcp", "web"}),
) -> ProductionAssembly:
    config = load_production_config(config_path)
    return build_production_runtime(
        config,
        secret_store=secret_store,
        components=components,
        pre_migration_backup=(
            pre_migration_backup
            if pre_migration_backup is not None
            else _snapshot_pre_migration_backup(config.storage.backup_dir)
        ),
    )


def create_production_mcp_runtime(
    config_path: str | os.PathLike[str],
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
) -> MCPRuntime:
    runtime = create_production_assembly(
        config_path,
        secret_store=secret_store,
        pre_migration_backup=pre_migration_backup,
        components=frozenset({"mcp"}),
    ).mcp
    if runtime is None:
        raise AssertionError("MCP assembly did not produce its requested component")
    return runtime


def create_production_web_app(
    config_path: str | os.PathLike[str],
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
) -> FastAPI:
    app = create_production_assembly(
        config_path,
        secret_store=secret_store,
        pre_migration_backup=pre_migration_backup,
        components=frozenset({"web"}),
    ).web
    if app is None:
        raise AssertionError("web assembly did not produce its requested component")
    return app


def create_production_mcp_app_from_environment(
    *,
    secret_store: SecretStore | None = None,
) -> Starlette:
    """ASGI factory for the configured fail-closed MCP service."""

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


def production_listener_from_environment(
    service: Literal["mcp", "web"],
) -> tuple[str, int]:
    """Return the configured endpoint for a production environment factory."""

    config = load_production_config(_production_config_path_from_environment())
    if service == "mcp":
        return config.mcp_host, config.mcp_port
    if service == "web":
        return config.web_host, config.web_port
    raise ValueError("production listener service is invalid")


def build_production_runtime(
    config: ProductionConfig,
    *,
    secret_store: SecretStore,
    pre_migration_backup: PreMigrationBackup | None = None,
    totp_provisioner: TotpSecretProvisioner | None = None,
    clock: Callable[[], int] | None = None,
    components: frozenset[str] = frozenset({"mcp", "web"}),
) -> ProductionAssembly:
    """Assemble MCP, web, and workers without dispatching provider calls."""

    if not components <= {"mcp", "web"}:
        raise ProductionAssemblyError("production component selection is invalid")
    now = clock or (lambda: int(time.time()))
    selected_now = now()
    if not isinstance(selected_now, int) or isinstance(selected_now, bool) or selected_now < 0:
        raise ProductionAssemblyError("production clock returned an invalid value")

    config.prepare_directories()
    policy = _load_policy(config.policy_path)
    _validate_policy_connector_bindings(config, policy)
    secret_references, secret_values, secret_identities = _resolve_secret_inventory(
        config,
        secret_store,
    )

    database = Database(config.storage.data_dir / "signet.db")
    verified_backup_version: int | None = None

    def track_verified_backup(
        database: Database,
        current_version: int,
    ) -> MigrationBackupReceipt:
        nonlocal verified_backup_version
        if pre_migration_backup is None:
            raise AssertionError("pre-migration backup wrapper was installed without a callback")
        receipt = pre_migration_backup(database, current_version)
        verified_backup_version = current_version
        return receipt

    try:
        database.initialize(
            pre_migration_backup=(
                track_verified_backup if pre_migration_backup is not None else None
            )
        )
    except PreMigrationBackupRequired:
        raise ProductionAssemblyError(
            "production schema upgrade requires a verified pre-migration backup; "
            "migration was not started"
        ) from None

    capabilities = ProofCapability(secret_values["capability_key_ref"].reveal().encode("utf-8"))
    selected_totp_provisioner = totp_provisioner or KeychainTotpSecretProvisioner()
    authenticators = AuthenticatorManager(
        database,
        capabilities=capabilities,
        provisioner=selected_totp_provisioner,
    )
    payload_cipher = PayloadCipher(
        secret_values["payload_key_ref"],
        secret_references["payload_key_ref"],
    )
    freezer = RequestFreezer(payload_cipher)
    engine = PolicyEngine(policy)
    mirror = SchemaMirror(policy)
    provider_sessions: ProviderSessionPool | None = None
    staging: StagingStore | None = None
    provider_adapters: Mapping[tuple[str, str], ApprovalAdapter] = MappingProxyType({})
    reviewer_provider_adapters: Mapping[tuple[str, str], ApprovalAdapter]
    if config.provider_rollout.state == "enabled":
        try:
            live_providers = build_live_provider_bundle(
                config,
                database=database,
                policy=policy,
                secret_store=secret_store,
                credential_identity_key=secret_values["capability_key_ref"]
                .reveal()
                .encode("utf-8"),
            )
        except ProductionConnectorError as exc:
            raise ProductionAssemblyError(str(exc)) from None
        clients: Mapping[str, object] = MappingProxyType(dict(live_providers.clients))
        provider_adapters = MappingProxyType(dict(live_providers.adapters))
        reviewer_provider_adapters = provider_adapters
        staging = live_providers.staging
        provider_sessions = live_providers.sessions
    else:
        clients = MappingProxyType(
            {
                alias: ProductionDisabledProviderClient(
                    alias,
                    credential_identity_digest=provider_execution_identity_digest(config, alias),
                )
                for alias in config.connectors
            }
        )
        attachment_root = config.storage.attachment_staging_dir
        attachment_reference = config.secrets.attachment_key_ref
        if (
            attachment_root is not None
            and attachment_reference is not None
            and config.storage.attachment_source_roots
        ):
            try:
                staging = StagingStore(
                    attachment_root,
                    database=database,
                    cipher=AttachmentCipher(
                        secret_values["attachment_key_ref"],
                        attachment_reference,
                    ),
                    allowed_source_roots=config.storage.attachment_source_roots,
                )
            except Exception:
                raise ProductionAssemblyError(
                    "production attachment retention could not be initialized"
                ) from None
        reviewer_provider_adapters = MappingProxyType(
            dict(
                build_review_only_provider_adapters(
                    config,
                    policy=policy,
                    staging=staging,
                )
            )
        )
    execution_scopes = PolicyExecutionScopeResolver(mirror, clients)
    tool_access = ToolAccessAdapter()
    reviewer_adapters = {
        **reviewer_provider_adapters,
        (tool_access.downstream_alias, tool_access.tool_name): cast(ApprovalAdapter, tool_access),
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
        staging=staging,
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

    try:
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
    except Exception:
        if verified_backup_version is not None:
            raise _post_migration_startup_failure(verified_backup_version) from None
        raise
    pipeline = GatewayCallPipeline(
        mirror=mirror,
        downstream_clients=cast(Mapping[str, RawDownstreamClient], clients),
        local_handlers={},
        adapters={adapter.adapter_id: adapter for adapter in provider_adapters.values()},
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
        if verified_backup_version is not None:
            raise _post_migration_startup_failure(verified_backup_version) from None
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
    runtime_states: list[ProductionStateStore] = []

    def mcp_readiness() -> bool:
        return bool(
            runtime_states
            and runtime_states[0].status().services["mcp"].state == "ready"
            and (provider_sessions is None or provider_sessions.active)
        )

    def observe_mcp_lifecycle(state_name: str) -> None:
        if state_name not in {"ready", "blocked", "stopped"}:
            raise ProductionAssemblyError("MCP lifecycle emitted an invalid state")
        runtime_states[0].record_service_state(
            "mcp",
            cast(Any, state_name),
            capability="mcp_ready",
            ready=state_name == "ready",
            now=now(),
        )

    mcp = (
        assemble_mcp_runtime(
            aliases=surfaces,
            approvals=gateway_surface,
            tokens=token_registry,
            bind_host=config.mcp_host,
            bind_port=config.mcp_port,
            health_probe=mcp_readiness,
            readiness_probe=mcp_readiness,
            lifecycle_observer=observe_mcp_lifecycle,
        )
        if "mcp" in components
        else None
    )

    web = (
        _assemble_production_web(
            database=database,
            config=config,
            secret_values=secret_values,
            capabilities=capabilities,
            authenticators=authenticators,
            totp_provisioner=selected_totp_provisioner,
            secret_store=secret_store,
            limiter=limiter,
            totp=totp,
            approvals=approvals,
            reviewer=reviewer,
            policy_promotions=policy_promotions,
            clock=now,
        )
        if "web" in components
        else None
    )
    capability_status = MappingProxyType(
        {
            "storage_ready": True,
            "secret_broker_ready": all(
                purpose in secret_identities for purpose in _REQUIRED_SECRET_PURPOSES
            ),
            "mcp_ready": False,
            "web_ready": False,
            "workers_ready": False,
            "policy_ready": policy_promotions.ready,
            "live_providers_ready": False,
        }
    )
    services = _service_inventory(config, components)
    state = ProductionStateStore(
        database,
        provider_rollout_enabled=config.provider_rollout.state == "enabled",
    )
    try:
        state.stage(
            config,
            capabilities=capability_status,
            secret_references=secret_references,
            secret_identities=secret_identities,
            services=services,
            now=selected_now,
        )
    except Exception as exc:
        if verified_backup_version is not None:
            raise _post_migration_startup_failure(verified_backup_version) from None
        raise ProductionAssemblyError(str(exc)) from None
    runtime_states.append(state)
    delivery: DeliveryDispatcher | None = None
    reconciliation: ReconciliationCoordinator | None = None
    retention = (
        RetentionManager(
            database,
            staging,
            matrix=_production_retention_matrix(),
        )
        if staging is not None
        else None
    )
    if provider_sessions is not None:
        if staging is None:
            raise AssertionError("live provider staging is unavailable")
        request_loader = FrozenRequestLoader(
            approvals,
            payload_cipher,
            provider_adapters,
            execution_scopes,
        )
        delivery = DeliveryDispatcher(
            approvals,
            request_loader,
            cast(Mapping[str, MCPClient], clients),
        )
        reviewed_reconciliation_tools = {
            route: adapter.reconciliation_tools & frozenset(policy.downstreams[route[0]].tools)
            for route, adapter in provider_adapters.items()
        }
        reconciliation = ReconciliationCoordinator(
            approvals,
            request_loader,
            delivery,
            cast(Mapping[str, MCPClient], clients),
            reviewed_tools=reviewed_reconciliation_tools,
        )

    workers = ProductionWorkers(
        approvals=approvals,
        policy_promotions=policy_promotions,
        state=state,
        clock=now,
        database=database if delivery is not None or retention is not None else None,
        delivery=delivery,
        reconciliation=reconciliation,
        retention=retention,
        provider_sessions=provider_sessions,
    )
    if mcp is not None and provider_sessions is not None:
        _attach_provider_lifespan(mcp.app, provider_sessions, state, now)
    if web is not None and (provider_sessions is not None or retention is not None):
        _attach_production_worker_lifespan(web, workers)

    def production_health_probe() -> bool:
        status = state.status()
        maintenance = status.services["maintenance"]
        heartbeat_age = now() - maintenance.updated_at
        return (
            maintenance.state == "ready"
            and "workers_ready" not in status.missing_prerequisites
            and (provider_sessions is None or provider_sessions.active)
            and 0 <= heartbeat_age <= workers.heartbeat_lease_seconds
        )

    if web is not None:
        web.state.signet_health_probe = production_health_probe
    return ProductionAssembly(
        config=config,
        database=database,
        policy_engine=engine,
        mcp=mcp,
        web=web,
        workers=workers,
        state=state,
        schema_registry=schema_registry,
        token_registry=token_registry,
        provider_clients=cast(Mapping[str, MCPClient], clients),
        adapters=provider_adapters,
        staging=staging,
        retention=retention,
        provider_sessions=provider_sessions,
        authenticators=authenticators,
    )


def _attach_provider_lifespan(
    app: Starlette,
    sessions: ProviderSessionPool,
    state: ProductionStateStore,
    clock: Callable[[], int],
) -> None:
    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(selected: Starlette) -> AsyncIterator[None]:
        try:
            async with sessions.run():
                state.record_provider_state("active", ready=True, now=clock())
                async with original(selected):
                    yield
        except BaseException:
            ready = sessions.active
            state.record_provider_state(
                "active" if ready else "blocked",
                ready=ready,
                now=clock(),
            )
            raise
        else:
            ready = sessions.active
            state.record_provider_state(
                "active" if ready else "blocked",
                ready=ready,
                now=clock(),
            )

    app.router.lifespan_context = lifespan


def _attach_production_worker_lifespan(app: FastAPI, workers: ProductionWorkers) -> None:
    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(selected: FastAPI) -> AsyncIterator[None]:
        stop = asyncio.Event()
        task = asyncio.create_task(
            workers.serve(stop),
            name="signet-production-workers",
        )
        try:
            await asyncio.sleep(0)
            await workers.wait_started()
            await asyncio.sleep(0)
            if task.done():
                await task
            async with original(selected):
                yield
        finally:
            stop.set()
            await await_task_while_preserving_cancellation(task)

    app.router.lifespan_context = lifespan


def _post_migration_startup_failure(previous_version: int) -> ProductionAssemblyError:
    return ProductionAssemblyError(
        "production startup failed after upgrading the database from schema "
        f"{previous_version}; services remain blocked. Stop Signet processes and restore the "
        "verified pre-migration backup before retrying"
    )


def _assemble_production_web(
    *,
    database: Database,
    config: ProductionConfig,
    secret_values: Mapping[str, Secret],
    capabilities: ProofCapability,
    authenticators: AuthenticatorManager,
    totp_provisioner: TotpSecretProvisioner,
    secret_store: SecretStore,
    limiter: SQLiteAttemptLimiter,
    totp: TotpVerifier,
    approvals: ApprovalStateMachine,
    reviewer: EncryptedPayloadReviewer,
    policy_promotions: SQLitePolicyPromotionBoundary,
    clock: Callable[[], int],
) -> FastAPI:
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
    webauthn_issuer = WebAuthnChallengeIssuer(
        webauthn_repository,
        rp_id=config.rp_id,
        origin=config.public_origin,
    )
    webauthn_verifier = WebAuthnAssertionVerifier(
        webauthn_repository,
        rp_id=config.rp_id,
        origin=config.public_origin,
        capabilities=capabilities,
    )
    registrations = PasskeyRegistrationService(
        database,
        provider=OfficialRegistrationProvider(),
        rp_id=config.rp_id,
        origin=config.public_origin,
    )
    totp_enrollments = TotpEnrollmentService(
        database,
        provisioner=totp_provisioner,
        secret_store=secret_store,
    )
    browser_auth = BrowserAuthController(
        bootstrap=BootstrapService(
            database,
            owner_user_id=config.owner_user_id,
            totp_enrollments=totp_enrollments,
        ),
        registrations=registrations,
        manager=authenticators,
        totp_verifier=totp,
        webauthn_issuer=webauthn_issuer,
        webauthn_verifier=webauthn_verifier,
        webauthn_repository=webauthn_repository,
        totp_enrollments=totp_enrollments,
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
        browser_auth=browser_auth,
        clock=clock,
    )
    web.add_middleware(TrustedProxySourceMiddleware)
    return web


def _snapshot_pre_migration_backup(backup_dir: Path) -> PreMigrationBackup:
    def backup(database: Database, current_version: int) -> MigrationBackupReceipt:
        destination = backup_dir / (
            f"signet-pre-migration-v{current_version}-{time.time_ns()}.sqlite3"
        )
        snapshot = database.create_snapshot(destination)
        Database.verify_snapshot(snapshot)
        return MigrationBackupReceipt(
            database_path=database.path,
            source_schema_version=current_version,
            artifact_path=snapshot.absolute(),
            artifact_sha256=_file_sha256(snapshot),
            verified_restore_schema_version=current_version,
        )

    return backup


def _service_inventory(
    config: ProductionConfig,
    components: frozenset[str],
) -> tuple[ProductionServiceRecord, ...]:
    return (
        ProductionServiceRecord(
            "mcp",
            "mcp",
            "staged" if "mcp" in components else "blocked",
            config.mcp_host,
            config.mcp_port,
        ),
        ProductionServiceRecord(
            "web",
            "web",
            "staged" if "web" in components else "blocked",
            config.web_host,
            config.web_port,
        ),
        ProductionServiceRecord("maintenance", "maintenance", "blocked"),
        ProductionServiceRecord("delivery", "worker", "blocked"),
        ProductionServiceRecord("reconciliation", "worker", "blocked"),
        ProductionServiceRecord("retention", "worker", "blocked"),
        ProductionServiceRecord("notifications", "worker", "blocked"),
    )


def _resolve_secret_inventory(
    config: ProductionConfig,
    secret_store: SecretStore,
) -> tuple[Mapping[str, str], Mapping[str, Secret], Mapping[str, str]]:
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
    parsed_references: dict[str, SecretReference] = {}
    values: dict[str, Secret] = {}
    try:
        for purpose, raw_reference in references.items():
            parsed_references[purpose] = SecretReference.parse(raw_reference)
        resolved_purposes: tuple[str, ...] = _REQUIRED_SECRET_PURPOSES
        if "attachment_key_ref" in parsed_references:
            resolved_purposes += ("attachment_key_ref",)
        for purpose in resolved_purposes:
            reference = parsed_references[purpose]
            value = secret_store.get(reference)
            encoded = value.reveal().encode("utf-8")
            if not 32 <= len(encoded) <= 4_096:
                raise ProductionAssemblyError(
                    "production cryptographic secrets must be 32 to 4096 UTF-8 bytes"
                )
            values[purpose] = value
    except ProductionAssemblyError:
        raise
    except Exception:
        raise ProductionAssemblyError(
            "a configured production secret could not be resolved"
        ) from None
    identity_key = values["capability_key_ref"].reveal().encode("utf-8")
    identities = {
        purpose: hmac.new(
            identity_key,
            purpose.encode("utf-8") + b"\x00" + value.reveal().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        for purpose, value in values.items()
    }
    return (
        MappingProxyType(references),
        MappingProxyType(values),
        MappingProxyType(identities),
    )


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
    try:
        descriptor = open_confined_readonly(Path(path.anchor), path)
    except (OSError, StagingError) as exc:
        raise ProductionAssemblyError(f"{label} could not be opened safely") from exc

    operation_error: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        if (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > _MAX_PRIVATE_DOCUMENT_BYTES
        ):
            raise ProductionAssemblyError(
                f"{label} must be an owned mode-0600 regular file within the size limit"
            )
        return read_verified_descriptor(
            descriptor,
            maximum_bytes=_MAX_PRIVATE_DOCUMENT_BYTES,
        ).decode("utf-8")
    except (OSError, PrivatePathError, StagingError, UnicodeDecodeError) as exc:
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
