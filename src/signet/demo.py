"""Turnkey, fake-only Signet assembly for evaluation and integration tests."""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import ctypes
import errno
import fcntl
import hashlib
import http.client
import json
import os
import secrets
import signal
import stat
import sys
import time
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import mcp.types as mcp_types
import uvicorn
import yaml
from argon2 import PasswordHasher
from fastapi import FastAPI
from mcp.shared.exceptions import McpError

from signet.access_requests import FrozenAccessRequestFactory
from signet.adapters.base import ApprovalAdapter, MCPClient, copy_json_object
from signet.adapters.fastmail import FASTMAIL_SEND_SCHEMA, FastmailAdapter
from signet.adapters.tool_access import ToolAccessAdapter
from signet.adapters.whatsapp import WHATSAPP_TEXT_SCHEMA, WhatsAppAdapter, WhatsAppTextAdapter
from signet.admission import QueueAdmissionLimits
from signet.async_support import run_sync_non_abandoning as _run_sync
from signet.attachment_crypto import AttachmentCipher
from signet.auth import (
    Argon2PasswordVerifier,
    PasswordAuthenticator,
    PasswordCredential,
    ProofCapability,
    SessionManager,
    SQLiteAttemptLimiter,
    SQLiteAuthenticationTransactions,
    SQLitePasswordCredentialRepository,
    SQLiteSessionRepository,
)
from signet.backup import (
    BackupBundleManager,
    BackupCleanupStateUnknown,
    BackupError,
    BackupPublicationUnknown,
    BackupPublishedWithWarnings,
    BackupRetentionStateUnknown,
    RestoredBundle,
    remove_private_tree_checked,
)
from signet.credential_broker import (
    CallerPrincipal,
    CredentialError,
    MemorySecretStore,
    Secret,
    TokenRecord,
    TokenRegistry,
)
from signet.crypto import PayloadCipher
from signet.db import Database, DatabaseError, DatabaseFinalizationStateUnknown
from signet.delivery import DeliveryDispatcher, DeliveryError, FrozenRequestLoader
from signet.execution_scope import PolicyExecutionScopeResolver
from signet.freezer import RequestFreezer
from signet.gateway import GatewayCallPipeline
from signet.gateway_tools import (
    GATEWAY_TOOL_DEFINITIONS,
    GatewayPrincipal,
    GatewayTools,
    GatewayToolSurface,
    SafeRequestSummary,
)
from signet.integration_store import SQLiteIntegrationStore
from signet.integration_web_backend import SQLiteIntegrationWebBackend
from signet.mcp_mirror import (
    AliasToolSurface,
    InvocationIdentity,
    SchemaMirror,
    derive_invocation_identity,
)
from signet.models import AdmissionRejected, InvalidTransition, RequestState
from signet.notification_outbox import NotificationOutboxWorker, SQLiteNotificationOutbox
from signet.notifications import (
    NotificationDispatcher,
    PushSubscription,
    SQLitePushRepository,
)
from signet.policy import (
    PolicyEngine,
    PolicyError,
    PolicyMode,
    PolicySnapshot,
    dump_policy,
    parse_policy,
    parse_policy_yaml,
)
from signet.policy_persistence import (
    PolicyPersistenceError,
    SQLiteActionDraftRepository,
    SQLitePolicyPromotionBoundary,
)
from signet.private_paths import (
    DirectoryIdentity,
    PrivatePathError,
    capture_owned_directory_identity,
    harden_private_directory_identity,
    require_no_acl_grants,
    require_owned_directory_identity,
    require_private_directory,
    require_private_directory_identity,
    revalidate_directory_identity,
)
from signet.reconcile import ReconciliationCoordinator
from signet.retention import (
    BackupPins,
    PurgeIntent,
    RetentionError,
    RetentionManager,
    RetentionMatrix,
)
from signet.retention_contract import fake_unknown_purge_job_key
from signet.runtime import (
    APPROVALS_ALIAS,
    MCPRuntime,
    assemble_mcp_runtime,
    gateway_principal_provider,
)
from signet.staging import StagingError, StagingStore
from signet.state_machine import ApprovalStateMachine
from signet.totp import SQLiteTotpCredentialRepository, TotpCredential, TotpVerifier
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

DEMO_FORMAT = 1
DEMO_MODE = "fake-only"
DEMO_USER_ID = "fake:operator"
DEMO_NAMESPACE = "fake:hermes-demo"
DEMO_LOGIN_PROOF = "fake:login"
DEMO_ACTION_PROOF = "fake:approve"
DEMO_ALIASES = ("fastmail", "whatsapp", APPROVALS_ALIAS)
DEFAULT_MCP_PORT = 8789
DEFAULT_WEB_PORT = 8790
DEMO_GRACEFUL_SHUTDOWN_SECONDS = 5

_STATE_FILE = "demo-state.json"
_SECRETS_FILE = "demo-secrets.json"
_POLICY_FILE = "policy.yaml"
_DATABASE_FILE = "approvals.sqlite3"
_DATABASE_MAINTENANCE_LOCK_FILE = f".{_DATABASE_FILE}.maintenance.lock"
_SERVE_LOCK_FILE = ".serve.lock"
_BACKUP_MAINTENANCE_LOCK_FILE = ".backup-maintenance.lock"
_ATTACHMENTS_DIRECTORY = "attachments"
_IMPORTS_DIRECTORY = "imports"
_KEY_REFERENCE = "keychain://Signet/demo-payload-fake-only"
_ATTACHMENT_KEY_REFERENCE = "keychain://Signet/demo-attachment-fake-only"
_TOTP_REFERENCE = "keychain://Signet/demo-totp-fake-only"
_BACKUP_KEY_SIZE = 32
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_DEMO_SERVER_EXIT_SECONDS = DEMO_GRACEFUL_SHUTDOWN_SECONDS + 2
_DEMO_FORCE_CANCEL_SECONDS = 1
_SEED_ALIAS = "fastmail"
_SEED_TOOL = "send_email"
_SEED_INVOCATION_PREFIX = "signet-demo-seed-request-v1"
_MAX_SEED_REQUEST_SEQUENCE = 4_096


class DemoError(RuntimeError):
    """The fake-only demo could not be initialized or assembled safely."""


@dataclass(frozen=True, slots=True, repr=False)
class DemoSecrets:
    session_key: bytes
    csrf_key: bytes
    capability_key: bytes
    payload_secret: str
    attachment_secret: str
    backup_key: bytes
    totp_secret: str
    web_password: str
    mcp_token: str
    token_records: tuple[TokenRecord, ...]

    def __repr__(self) -> str:
        return "DemoSecrets(<redacted>)"


class DemoBackupService:
    """Marker-guarded serialization around every exposed demo backup operation."""

    def __init__(self, root: Path, manager: BackupBundleManager) -> None:
        self.root = root
        self._manager = manager

    def __repr__(self) -> str:
        return f"DemoBackupService(root={self.root!s})"

    def create(self, destination: Path, *, created_at: int | None = None) -> Path:
        with _demo_backup_maintenance_lock(self.root):
            return self._manager.create(destination, created_at=created_at)

    def restore(self, bundle: Path, destination_root: Path) -> RestoredBundle:
        with _demo_backup_maintenance_lock(self.root):
            return self._manager.restore(bundle, destination_root)

    def create_pre_migration_callback(
        self,
        backup_directory: Path,
    ) -> Callable[[Database, int], None]:
        callback = self._manager.create_pre_migration_callback(backup_directory)

        def locked_backup(database: Database, current_version: int) -> None:
            with _demo_backup_maintenance_lock(self.root):
                callback(database, current_version)

        return locked_backup


@dataclass(frozen=True, slots=True)
class DemoAssembly:
    root: Path
    database: Database
    state_machine: ApprovalStateMachine
    mcp: MCPRuntime
    web: FastAPI
    mirror: SchemaMirror
    token_registry: TokenRegistry
    staging: StagingStore
    backups: DemoBackupService
    workers: DemoWorkers
    provider_clients: Mapping[str, FakeOnlyProviderClient]
    gateway_pipeline: GatewayCallPipeline


class DemoTotpProvider:
    """Explicit fake proof provider that cannot accept authenticator-shaped input."""

    test_only = True

    def __init__(self, database: Database) -> None:
        self._database = database

    def verify_step(self, secret: Secret, proof: str, *, now: int) -> int | None:
        if not secret.reveal().startswith("fake:") or now < 0:
            return None
        if len(proof) == 6 and proof.isascii() and proof.isdigit():
            return None
        if not (
            secrets.compare_digest(proof, DEMO_LOGIN_PROOF)
            or secrets.compare_digest(proof, DEMO_ACTION_PROOF)
        ):
            return None
        with self._database.transaction() as connection:
            row = connection.execute(
                """
                INSERT INTO auth_rate_windows(
                    scope_key, window_start, attempts, blocked_until, updated_at
                ) VALUES ('fake:demo-totp-use-counter', 0, 1, NULL, ?)
                ON CONFLICT(scope_key) DO UPDATE SET
                    attempts = attempts + 1,
                    blocked_until = NULL,
                    updated_at = excluded.updated_at
                RETURNING attempts
                """,
                (now,),
            ).fetchone()
            step = int(row["attempts"])
            if step < 1 or step > 2**63 - 1:
                raise DemoError("fake proof-use counter is exhausted")
        return step


class FakeOnlyTokenRegistry(TokenRegistry):
    """Require an unmistakable demo prefix before production token verification."""

    def authenticate(self, authorization: str | None, *, alias: str) -> CallerPrincipal:
        prefix = "Bearer fake:"
        if authorization is None or not authorization.startswith(prefix):
            raise CredentialError("fake-only bearer authentication is required")
        raw = authorization.removeprefix(prefix)
        if not raw.startswith("sgt_") or raw.startswith("fake:"):
            raise CredentialError("invalid fake-only bearer token")
        return super().authenticate(f"Bearer {raw}", alias=alias)


class FakeOnlyProviderClient:
    """In-process reviewed provider fixture with no socket or process capability."""

    def __init__(self, alias: str) -> None:
        if alias not in {"fastmail", "whatsapp"}:
            raise DemoError("fake provider alias is invalid")
        self.alias = alias
        self._credential_identity_digest = hashlib.sha256(
            (f"signet/fake-provider-identity/v1\x00{alias}\x00fake:{alias}-account").encode()
        ).hexdigest()
        self._mutation_calls = 0
        self._sent_emails: dict[str, dict[str, Any]] = {}

    @property
    def credential_identity_digest(self) -> str:
        return self._credential_identity_digest

    @property
    def mutation_calls(self) -> int:
        return self._mutation_calls

    async def call_tool_raw(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        value: dict[str, Any]
        if self.alias == "fastmail" and tool_name == "search_email":
            value = self._search_email(arguments)
        elif arguments:
            raise DemoError("fake read tools accept no arguments")
        elif self.alias == "fastmail" and tool_name == "list_identities":
            value = {
                "identities": [
                    {
                        "id": "fake:identity:primary",
                        "email": "fake-sender@demo.invalid",
                        "name": "Fake Demo Sender",
                    }
                ]
            }
        elif self.alias == "whatsapp" and tool_name == "list_chats":
            value = {
                "chats": [
                    {
                        "jid": "15555550123@s.whatsapp.net",
                        "label": "fake:demo-chat",
                    }
                ]
            }
        else:
            raise DemoError("fake provider refused an unreviewed read tool")
        serialized = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        return {
            "content": [{"type": "text", "text": serialized}],
            "structuredContent": value,
            "isError": False,
        }

    async def call_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.alias == "fastmail" and tool_name == "search_email":
            return self._search_email(arguments)
        detached = copy_json_object(arguments)
        digest = hashlib.sha256(
            json.dumps(
                detached,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:24]
        if self.alias == "fastmail" and tool_name == "send_email":
            self._mutation_calls += 1
            result = {
                "messageId": f"fake:message:{digest}",
                "submissionId": f"fake:submission:{digest}",
                "threadId": f"fake:thread:{digest}",
                "status": "sent",
            }
            sent_record = {
                **result,
                "folder": "Sent",
                "from": detached.get("from"),
                "to": detached.get("to", []),
                "cc": detached.get("cc", []),
                "bcc": detached.get("bcc", []),
                "subject": detached.get("subject"),
                "body": detached.get("body"),
            }
            self._sent_emails[result["messageId"]] = sent_record
            self._sent_emails[result["submissionId"]] = sent_record
            return result
        if self.alias == "fastmail" and tool_name == "upload_attachment":
            self._mutation_calls += 1
            return {"attachmentId": f"fake:attachment:{digest}"}
        if self.alias == "whatsapp" and tool_name == "send_text":
            self._mutation_calls += 1
            return {"sent": True, "message_id": f"fake:chat-message:{digest}"}
        raise DemoError("fake provider refused an unreviewed mutation")

    def _search_email(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if (
            set(arguments) != {"query", "folder", "limit"}
            or not isinstance(arguments.get("query"), str)
            or arguments.get("folder") != "Sent"
            or arguments.get("limit") != 10
        ):
            raise DemoError("fake provider refused an invalid sent-mail lookup")
        selected = self._sent_emails.get(cast(str, arguments["query"]))
        return {"messages": [copy_json_object(selected)] if selected is not None else []}

    def __repr__(self) -> str:
        return f"FakeOnlyProviderClient(alias={self.alias!r})"


class DemoGatewayTools:
    """Expose gateway status tools while keeping demo approval web-only."""

    def __init__(self, tools: GatewayTools) -> None:
        self._tools = tools

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            copy.deepcopy(tool)
            for tool in GATEWAY_TOOL_DEFINITIONS
            if tool["name"] != "approve_request"
        ]

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        principal: GatewayPrincipal,
    ) -> dict[str, Any]:
        if name == "approve_request":
            raise McpError(
                mcp_types.ErrorData(
                    code=mcp_types.INVALID_PARAMS,
                    message="Demo approvals require the authenticated web UI",
                )
            )
        return await self._tools.call_tool(name, arguments, principal=principal)


class ReviewedSummaryProvider:
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
        adapter = reviewed.adapter
        if isinstance(adapter, (FastmailAdapter, WhatsAppAdapter)):
            destination_summary = adapter.masked_destination_summary(reviewed.arguments)
        elif isinstance(adapter, ToolAccessAdapter):
            destination_summary = reviewed.summary.destination_summary
        else:
            destination_summary = "Private details available in the web app"
        return SafeRequestSummary(
            service=reviewed.summary.service,
            tool=adapter.tool_name,
            destination_summary=destination_summary,
        )


class FakePushTransport:
    """A no-egress transport; demo subscriptions are acknowledged only locally."""

    async def send(
        self,
        subscription: PushSubscription,
        payload: Mapping[str, str | int],
    ) -> None:
        del subscription, payload


class DemoWorkers:
    """Bounded recovery, publication, delivery, maintenance, and notification workers."""

    def __init__(
        self,
        database: Database,
        state_machine: ApprovalStateMachine,
        policy_publications: SQLitePolicyPromotionBoundary,
        delivery: DeliveryDispatcher,
        reconciliation: ReconciliationCoordinator,
        retention: RetentionManager,
        notifications: NotificationOutboxWorker,
        *,
        serve_root: Path,
        interval_seconds: float = 0.25,
        maintenance_interval_seconds: int = 60,
        delivery_batch: int = 16,
        notification_batch: int = 32,
    ) -> None:
        if (
            interval_seconds < 0.05
            or interval_seconds > 60
            or maintenance_interval_seconds < 5
            or maintenance_interval_seconds > 60 * 60
            or delivery_batch < 1
            or delivery_batch > 100
            or notification_batch < 1
            or notification_batch > 100
        ):
            raise ValueError("demo worker bounds are invalid")
        self.database = database
        self.state_machine = state_machine
        self.policy_publications = policy_publications
        self.delivery = delivery
        self.reconciliation = reconciliation
        self.retention = retention
        self.notifications = notifications
        self.serve_root = serve_root
        self.interval_seconds = interval_seconds
        self.maintenance_interval_seconds = maintenance_interval_seconds
        self.delivery_batch = delivery_batch
        self.notification_batch = notification_batch
        self._next_maintenance_at = 0
        self._consecutive_failures = 0
        self._stopped = False

    async def serve(self, stop: asyncio.Event) -> None:
        if not isinstance(stop, asyncio.Event):
            raise TypeError("demo workers require an asyncio stop event")
        with self._serve_lock():
            await self._serve_locked(stop)

    async def _serve_locked(self, stop: asyncio.Event) -> None:
        self._stopped = False
        try:
            while not stop.is_set():
                try:
                    selected_now = int(time.time())
                    # Recovery is a serving-lifespan operation. Constructors and
                    # offline backup, restore, and smoke commands never cross this
                    # execution-fencing boundary.
                    await _run_sync(self.state_machine.recover_startup, now=selected_now)
                    await self.run_once(now=selected_now)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # Retry fake-only maintenance, but expose a persistent
                    # failure through the otherwise static health endpoint.
                    self._consecutive_failures += 1
                else:
                    self._consecutive_failures = 0
                try:
                    backoff = min(
                        5.0,
                        self.interval_seconds * (2 ** min(self._consecutive_failures, 4)),
                    )
                    await asyncio.wait_for(stop.wait(), timeout=backoff)
                except TimeoutError:
                    continue
        finally:
            self._stopped = True
            stop.set()

    @contextmanager
    def _serve_lock(self) -> Iterator[None]:
        with _demo_server_lock(self.serve_root):
            yield

    def healthy(self) -> bool:
        """Return coarse readiness without exposing request or maintenance data."""

        return not self._stopped and self._consecutive_failures < 3

    async def run_once(self, *, now: int | None = None) -> tuple[int, int]:
        selected_now = int(time.time()) if now is None else now
        if not isinstance(selected_now, int) or isinstance(selected_now, bool) or selected_now < 0:
            raise ValueError("demo worker time is invalid")

        await self.policy_publications.publish_pending(now=selected_now)
        await _run_sync(self.state_machine.sweep_expired, now=selected_now, limit=100)
        request_ids = await _run_sync(self._due_delivery_request_ids, selected_now)

        delivered = 0
        for request_id in request_ids:
            dispatch_now = max(selected_now, int(time.time()))
            try:
                await self.delivery.dispatch(
                    request_id,
                    worker_id="fake:demo-delivery",
                    now=dispatch_now,
                    lease_seconds=30,
                )
            except (DeliveryError, InvalidTransition):
                continue
            delivered += 1

        await self.reconciliation.run_due(
            worker_id="fake:demo-reconciliation",
            now=selected_now,
            limit=self.delivery_batch,
        )
        maintenance_due = selected_now >= self._next_maintenance_at
        if maintenance_due:
            await _run_sync(self._schedule_notification_maintenance, selected_now)
        report = await self.notifications.run_due(
            now=selected_now,
            limit=self.notification_batch,
        )
        if maintenance_due:
            await _run_sync(self.retention.run_due, now=selected_now, limit=100)
            self._next_maintenance_at = selected_now + self.maintenance_interval_seconds
        return delivered, report.delivered

    def _due_delivery_request_ids(self, now: int) -> tuple[str, ...]:
        with self.database.read() as connection:
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
                    LIMIT ?
                    """,
                    (now, self.delivery_batch),
                ).fetchall()
            )

    def _schedule_notification_maintenance(self, now: int) -> None:
        self.notifications.outbox.schedule_approaching_expiry(
            user_id=DEMO_USER_ID,
            now=now,
            limit=1_000,
        )
        self.notifications.outbox.schedule_daily_digest(
            user_id=DEMO_USER_ID,
            now=now,
        )


def _absolute_demo_path(root: Path) -> Path:
    return _absolute_artifact_path(
        root,
        message="demo data directory path is unavailable or unsafe",
    )


def _absolute_artifact_path(path: Path, *, message: str) -> Path:
    try:
        selected = Path(path).expanduser().absolute()
        encoded = os.fsencode(selected)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        raise DemoError(message) from exc
    if b"\x00" in encoded or selected.name in {"", ".", ".."}:
        raise DemoError(message)
    return selected


def initialize_demo(root: Path, *, now: int | None = None) -> Path:
    """Atomically create a new marker-guarded fake-only data directory."""

    requested = _absolute_demo_path(root)
    if requested.exists() or requested.is_symlink():
        raise DemoError("demo data directory must not already exist")
    try:
        parent_identity = require_owned_directory_identity(requested.parent)
    except PrivatePathError as exc:
        raise DemoError("demo data directory parent is unavailable or unsafe") from exc
    parent = parent_identity.path
    destination = parent / requested.name
    if destination.exists() or destination.is_symlink():
        raise DemoError("demo data directory must not already exist")
    temporary = destination.with_name(f".{destination.name}.init-{secrets.token_urlsafe(8)}")
    created_at = int(time.time()) if now is None else now
    temporary_created = False
    temporary_identity: DirectoryIdentity | None = None
    published = False
    try:
        try:
            temporary.mkdir(mode=0o700)
        except FileExistsError:
            raise
        except BaseException as exc:
            raise DemoError(
                "demo initialization did not complete, and initialization-tree creation "
                "cleanup could not be confirmed; inspect the demo parent before retrying"
            ) from exc
        temporary_created = True
        temporary_identity = capture_owned_directory_identity(temporary)
        temporary_identity = harden_private_directory_identity(temporary_identity)
        private_temporary = require_private_directory_identity(temporary)
        if not temporary_identity.same_object(private_temporary):
            raise DemoError("demo initialization directory changed or became unsafe")
        _require_unchanged_demo_directory(parent_identity, private=False)
        _write_new_file(temporary / _DATABASE_MAINTENANCE_LOCK_FILE, b"")
        database = Database(temporary / _DATABASE_FILE)
        database.initialize()
        generated = _new_secrets()
        _enroll_web_credentials(database, generated, now=created_at)
        policy = parse_policy(_demo_policy_document())
        _write_new_file(temporary / _POLICY_FILE, dump_policy(policy))
        imports = temporary / _IMPORTS_DIRECTORY
        imports.mkdir(mode=0o700)
        imports_identity = harden_private_directory_identity(
            capture_owned_directory_identity(imports)
        )
        if not imports_identity.same_object(require_private_directory_identity(imports)):
            raise DemoError("demo imports directory changed or became unsafe")
        _write_json(
            temporary / _STATE_FILE,
            {
                "format": DEMO_FORMAT,
                "mode": DEMO_MODE,
                "created_at": created_at,
                "database": _DATABASE_FILE,
                "policy": _POLICY_FILE,
                "attachments": _ATTACHMENTS_DIRECTORY,
                "imports": _IMPORTS_DIRECTORY,
                "user_id": DEMO_USER_ID,
                "namespace": DEMO_NAMESPACE,
                "aliases": list(DEMO_ALIASES),
            },
        )
        _write_json(temporary / _SECRETS_FILE, _secrets_document(generated))
        _fsync_directory(temporary)
        _require_unchanged_demo_directory(temporary_identity, private=True)
        _require_unchanged_demo_directory(parent_identity, private=False)
        if destination.exists() or destination.is_symlink():
            raise DemoError("demo data directory must not already exist")
        try:
            _rename_directory_no_replace(temporary, destination)
            published = True
        except BaseException as exc:
            try:
                revalidate_directory_identity(temporary_identity, private=True)
            except PrivatePathError:
                published = True
                raise DemoError(
                    "demo initialization outcome is unknown because durable publication "
                    "could not be confirmed; inspect the destination before retrying"
                ) from exc
            if isinstance(exc, FileExistsError):
                raise DemoError("demo data directory must not already exist") from exc
            raise
        try:
            published_identity = require_private_directory_identity(destination)
            if not temporary_identity.same_object(published_identity):
                raise PrivatePathError("published demo directory identity changed")
            _require_unchanged_demo_directory(parent_identity, private=False)
            _fsync_directory(parent)
            _require_unchanged_demo_directory(parent_identity, private=False)
            _require_unchanged_demo_directory(published_identity, private=True)
        except BaseException as exc:
            raise DemoError(
                "demo initialization outcome is unknown because durable publication "
                "could not be confirmed; inspect the destination before retrying"
            ) from exc
    except BaseException:
        if temporary_created and not published:
            try:
                _cleanup_demo_initialization_tree(
                    temporary,
                    parent_identity=parent_identity,
                    temporary_identity=temporary_identity,
                )
            except BaseException as cleanup_error:
                raise DemoError(
                    "demo initialization did not complete, but private initialization-tree "
                    "cleanup could not be confirmed; inspect the demo parent before retrying"
                ) from cleanup_error
        raise
    return destination


def build_demo(
    root: Path,
    *,
    mcp_port: int = DEFAULT_MCP_PORT,
    web_port: int = DEFAULT_WEB_PORT,
) -> DemoAssembly:
    """Build real Signet surfaces after validating an explicit fake-only marker."""

    _validate_port_pair(mcp_port, web_port)
    demo_root, state, demo_secrets = _load_demo(root)
    database = Database(demo_root / cast(str, state["database"]))
    attachment_cipher = AttachmentCipher(
        Secret(demo_secrets.attachment_secret),
        _ATTACHMENT_KEY_REFERENCE,
    )
    staging = StagingStore(
        demo_root / cast(str, state["attachments"]),
        database=database,
        cipher=attachment_cipher,
        allowed_source_roots=(demo_root / cast(str, state["imports"]),),
        max_file_bytes=25 * 1024 * 1024,
        max_total_bytes=50 * 1024 * 1024,
        minimum_free_bytes=1024 * 1024,
    )
    backup_manager = BackupBundleManager(
        database,
        staging=staging,
        encryption_key=demo_secrets.backup_key,
    )
    backups = DemoBackupService(demo_root, backup_manager)
    database.initialize(
        pre_migration_backup=backups.create_pre_migration_callback(
            demo_root / "pre-migration-backups"
        )
    )
    capabilities = ProofCapability(demo_secrets.capability_key)
    payload_cipher = PayloadCipher(
        Secret(demo_secrets.payload_secret),
        _KEY_REFERENCE,
    )
    freezer = RequestFreezer(payload_cipher)
    policy_path = demo_root / cast(str, state["policy"])
    snapshot = parse_policy_yaml(_read_bounded_regular(policy_path))
    _validate_fake_policy(snapshot)
    engine = PolicyEngine(snapshot)
    mirror = SchemaMirror(snapshot)
    tools = _captured_tools()
    for alias, definitions in tools.items():
        mirror.capture(alias, definitions)
        for definition in definitions:
            name = cast(str, definition["name"])
            digest = mirror.captured_digest(alias, name)
            mirror.approve_schema(alias, name, digest)

    adapters: dict[tuple[str, str], ApprovalAdapter] = {
        ("fastmail", "send_email"): cast(
            ApprovalAdapter,
            FastmailAdapter(
                staging_store=staging,
                account="fake:fastmail-account",
                reviewed_dispatch_enabled=True,
            ),
        ),
        ("whatsapp", "send_text"): cast(
            ApprovalAdapter,
            WhatsAppTextAdapter(
                staging_store=staging,
                account="fake:whatsapp-account",
                reviewed_dispatch_enabled=True,
            ),
        ),
    }
    tool_access = ToolAccessAdapter()
    reviewer_adapters = {
        **adapters,
        (tool_access.downstream_alias, tool_access.tool_name): cast(ApprovalAdapter, tool_access),
    }
    downstream_clients = {
        "fastmail": FakeOnlyProviderClient("fastmail"),
        "whatsapp": FakeOnlyProviderClient("whatsapp"),
    }
    execution_scopes = PolicyExecutionScopeResolver(
        mirror,
        downstream_clients,
    )
    state_machine = ApprovalStateMachine(
        database,
        capabilities=capabilities,
        notification_user_id=DEMO_USER_ID,
        admission_limits=QueueAdmissionLimits(
            queue_limit=1_000,
            origin_pending_limit=500,
            tool_pending_limit=500,
            minimum_free_bytes=1024 * 1024,
        ),
    )
    reviewer = EncryptedPayloadReviewer(
        state_machine,
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
                    "policy publication target has no reviewed MCP surface"
                )
            await surface.notify_list_changed(strict=True)

    def apply_policy(updated: PolicySnapshot) -> None:
        mirror.apply_policy(updated)

    policy_promotions = SQLitePolicyPromotionBoundary(
        database,
        state_machine,
        reviewer,
        engine,
        policy_path,
        apply_policy=apply_policy,
        publication_gate=mirror,
        notify_list_changed=notify_list_changed,
    )
    limiter = SQLiteAttemptLimiter(database)
    totp = TotpVerifier(
        SQLiteTotpCredentialRepository(database),
        MemorySecretStore({("Signet", "demo-totp-fake-only"): demo_secrets.totp_secret}),
        limiter,
        capabilities=capabilities,
        provider=DemoTotpProvider(database),
        allow_test_provider=True,
    )
    pipeline = GatewayCallPipeline(
        mirror=mirror,
        downstream_clients=downstream_clients,
        local_handlers={},
        adapters={adapter.adapter_id: adapter for adapter in adapters.values()},
        execution_scopes=execution_scopes,
        freezer=freezer,
        enqueuer=state_machine,
    )
    access_requests = FrozenAccessRequestFactory(
        freezer,
        policy_version=lambda: engine.snapshot.version,
    )

    def record_denied_event(namespace: str, alias: str, tool: str) -> None:
        event = access_requests.freeze_denied_event(
            origin_namespace=namespace,
            alias=alias,
            tool=tool,
            actor=f"mcp:{namespace}",
            created_at=int(time.time()),
        )
        try:
            state_machine.enqueue(event)
        except AdmissionRejected:
            # The policy denial remains authoritative when the review queue is full.
            return

    for alias in ("fastmail", "whatsapp"):
        surfaces[alias] = AliasToolSurface(
            alias=alias,
            mirror=mirror,
            call_handler=pipeline.handle_call,
            denied_event_handler=record_denied_event,
        )
    gateway_tools = GatewayTools(
        state_machine=state_machine,
        totp_verifier=totp,
        summaries=ReviewedSummaryProvider(reviewer),
        access_requests=access_requests,
    )
    approvals = GatewayToolSurface(
        tools=cast(Any, DemoGatewayTools(gateway_tools)),
        principal_provider=gateway_principal_provider(DEMO_USER_ID),
    )
    token_registry = FakeOnlyTokenRegistry(demo_secrets.token_records)
    mcp = assemble_mcp_runtime(
        aliases=surfaces,
        approvals=approvals,
        tokens=token_registry,
        bind_host="127.0.0.1",
        bind_port=mcp_port,
    )

    sessions = SessionManager(
        SQLiteSessionRepository(database),
        signing_key=demo_secrets.session_key,
    )
    password_verifier = Argon2PasswordVerifier()
    passwords = PasswordAuthenticator(
        SQLitePasswordCredentialRepository(database),
        limiter,
        capabilities=capabilities,
        verifier=password_verifier,
    )
    webauthn = SQLiteWebAuthnRepository(database)
    webauthn_issuer = WebAuthnChallengeIssuer(webauthn, rp_id="localhost")
    webauthn_verifier = WebAuthnAssertionVerifier(
        webauthn,
        rp_id="localhost",
        origin="https://localhost",
        capabilities=capabilities,
    )
    authentication_transactions = SQLiteAuthenticationTransactions(
        database,
        signing_key=demo_secrets.session_key,
        capabilities=capabilities,
    )
    web_backend = PersistentWebBackend(
        database,
        authorized_user_id=DEMO_USER_ID,
        sessions=sessions,
        passwords=passwords,
        totp=totp,
        webauthn_repository=webauthn,
        webauthn_issuer=webauthn_issuer,
        webauthn_verifier=webauthn_verifier,
        authentication_transactions=authentication_transactions,
        state_machine=state_machine,
        payloads=reviewer,
        action_drafts=SQLiteActionDraftRepository(database),
        policy_promotions=cast(PolicyPromotionBoundary, policy_promotions),
        pushes=SQLitePushRepository(database),
    )
    integration_backend = SQLiteIntegrationWebBackend(
        database,
        authorized_user_id=DEMO_USER_ID,
        sessions=sessions,
        store=SQLiteIntegrationStore(database),
        totp=totp,
        capabilities=capabilities,
        webauthn_repository=webauthn,
        webauthn_issuer=webauthn_issuer,
        webauthn_verifier=webauthn_verifier,
        opaque_id_key=demo_secrets.csrf_key,
    )
    web = create_web_app(
        web_backend,
        integrations=integration_backend,
        settings=WebSettings(
            public_origin=f"http://127.0.0.1:{web_port}",
            allowed_hosts=("127.0.0.1",),
            session_cookie="signet_demo_session",
            login_csrf_cookie="signet_demo_login_csrf",
            secure_cookies=False,
            fake_only_ui=True,
        ),
        csrf=CsrfManager(demo_secrets.csrf_key),
    )
    loader = FrozenRequestLoader(
        state_machine,
        payload_cipher,
        adapters,
        execution_scopes,
    )
    delivery = DeliveryDispatcher(
        state_machine,
        loader,
        cast(Mapping[str, MCPClient], downstream_clients),
    )
    reconciliation = ReconciliationCoordinator(
        state_machine,
        loader,
        delivery,
        cast(Mapping[str, MCPClient], downstream_clients),
        reviewed_tools={
            ("fastmail", "send_email"): frozenset({"search_email"}),
        },
    )
    retention_delays: dict[RequestState, int | None] = dict.fromkeys(RequestState)
    retention_delays.update(
        {
            RequestState.SUCCEEDED: 7 * 24 * 60 * 60,
            RequestState.FAILED: 7 * 24 * 60 * 60,
            RequestState.DENIED: 7 * 24 * 60 * 60,
            RequestState.EXPIRED: 7 * 24 * 60 * 60,
            RequestState.CANCELLED: 7 * 24 * 60 * 60,
        }
    )
    attachment_delays = dict(retention_delays)
    attachment_delays.update(
        {
            RequestState.SUCCEEDED: 0,
            RequestState.DENIED: 0,
            RequestState.EXPIRED: 24 * 60 * 60,
            RequestState.CANCELLED: 24 * 60 * 60,
        }
    )
    retention = RetentionManager(
        database,
        staging,
        matrix=RetentionMatrix(attachment_delays, retention_delays),
        allow_fake_only_unknown_purge=True,
    )
    pushes = SQLitePushRepository(database)
    notification_dispatcher = NotificationDispatcher(pushes, FakePushTransport())
    notification_worker = NotificationOutboxWorker(
        SQLiteNotificationOutbox(database),
        notification_dispatcher,
        worker_id="fake:demo-notifications",
    )
    workers = DemoWorkers(
        database,
        state_machine,
        policy_promotions,
        delivery,
        reconciliation,
        retention,
        notification_worker,
        serve_root=demo_root,
    )
    web.state.signet_health_probe = workers.healthy
    _attach_worker_lifespan(web, workers)
    return DemoAssembly(
        root=demo_root,
        database=database,
        state_machine=state_machine,
        mcp=mcp,
        web=web,
        mirror=mirror,
        token_registry=token_registry,
        staging=staging,
        backups=backups,
        workers=workers,
        provider_clients=downstream_clients,
        gateway_pipeline=pipeline,
    )


def credential_value(root: Path, field: str) -> str:
    _, _, demo_secrets = _load_demo(root)
    values = {
        "web-user": DEMO_USER_ID,
        "web-password": demo_secrets.web_password,
        "web-login-proof": DEMO_LOGIN_PROOF,
        "web-action-proof": DEMO_ACTION_PROOF,
        "mcp-token": demo_secrets.mcp_token,
    }
    try:
        return values[field]
    except KeyError as exc:
        raise DemoError("unknown demo credential field") from exc


def seed_demo_request(root: Path) -> dict[str, str | bool]:
    """Admit one realistic fake request while the demo server is stopped."""

    demo_root, _state, _secrets = _load_demo(root)
    with _demo_server_lock(demo_root):
        assembly = build_demo(demo_root)
        policy = assembly.mirror.policy.configured(_SEED_ALIAS, _SEED_TOOL)
        if policy is None or policy.mode is not PolicyMode.APPROVAL:
            raise DemoError("demo seed request requires the reviewed fake approval policy")

        selected_now = int(time.time())
        identity, created = _select_seed_invocation_identity(
            assembly,
            policy_version=assembly.mirror.policy.version,
            now=selected_now,
        )
        try:
            result = asyncio.run(
                assembly.gateway_pipeline.handle_call(
                    _SEED_ALIAS,
                    _SEED_TOOL,
                    _seed_request_arguments(),
                    DEMO_NAMESPACE,
                    identity,
                )
            )
        except Exception:
            raise DemoError("fake-only seed request could not be admitted safely") from None

        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise DemoError("fake-only seed request returned an invalid admission result")
        request_id = structured.get("request_id")
        if not isinstance(request_id, str):
            raise DemoError("fake-only seed request returned an invalid admission result")
        try:
            stored = assembly.state_machine.get_request(request_id)
        except Exception:
            raise DemoError("fake-only seed request could not be verified safely") from None
        if (
            structured.get("status") != RequestState.PENDING_APPROVAL.value
            or stored.get("state") != RequestState.PENDING_APPROVAL.value
            or stored.get("downstream_alias") != _SEED_ALIAS
            or stored.get("tool_name") != _SEED_TOOL
            or stored.get("origin_namespace") != DEMO_NAMESPACE
            or not isinstance(stored.get("expires_at"), int)
            or cast(int, stored["expires_at"]) <= selected_now
            or any(client.mutation_calls for client in assembly.provider_clients.values())
        ):
            raise DemoError("fake-only seed request could not be verified safely")

    return {
        "created": created,
        "request_id": request_id,
        "service": _SEED_ALIAS,
        "state": RequestState.PENDING_APPROVAL.value,
        "status": "ready_for_review",
        "tool": _SEED_TOOL,
    }


def _select_seed_invocation_identity(
    assembly: DemoAssembly,
    *,
    policy_version: int,
    now: int,
) -> tuple[InvocationIdentity, bool]:
    for sequence in range(1, _MAX_SEED_REQUEST_SEQUENCE + 1):
        identity = derive_invocation_identity(
            namespace=DEMO_NAMESPACE,
            alias=_SEED_ALIAS,
            tool=_SEED_TOOL,
            explicit_id=f"{_SEED_INVOCATION_PREFIX}:{policy_version}:{sequence}",
            explicit_id_present=True,
            session_scope="fake:offline-seed",
            request_id=sequence,
        )
        with assembly.database.read() as connection:
            existing = connection.execute(
                """
                SELECT record.request_id, request.state, request.expires_at
                FROM idempotency_records AS record
                LEFT JOIN approval_requests AS request
                  ON request.request_id = record.request_id
                WHERE record.origin_namespace = ?
                  AND record.downstream_alias = ?
                  AND record.tool_name = ?
                  AND record.invocation_key = ?
                """,
                (
                    DEMO_NAMESPACE,
                    _SEED_ALIAS,
                    _SEED_TOOL,
                    identity.invocation_key,
                ),
            ).fetchone()
        if existing is None:
            return identity, True
        existing_state = existing["state"]
        existing_expires_at = existing["expires_at"]
        if (
            not isinstance(existing_state, str)
            or not isinstance(existing_expires_at, int)
            or isinstance(existing_expires_at, bool)
        ):
            raise DemoError("fake-only seed request history is inconsistent")
        if existing_state == RequestState.PENDING_APPROVAL.value and existing_expires_at > now:
            return identity, False
    raise DemoError("fake-only seed request sequence is exhausted")


def _seed_request_arguments() -> dict[str, Any]:
    return {
        "from": "fake-sender@demo.invalid",
        "to": ["fake-customer-success@demo.invalid"],
        "cc": [],
        "bcc": [],
        "subject": "Fake onboarding status follow-up",
        "body": (
            "Hello Fake Customer Success Team,\n\n"
            "Please confirm the fake onboarding review is complete before this demo "
            "follow-up is sent. Reason for sending: the fake customer requested a status "
            "update for tomorrow's training exercise.\n\n"
            "This message is fake-only and cannot be delivered to a real provider."
        ),
        "attachments": [],
    }


def hermes_config(*, mcp_port: int = DEFAULT_MCP_PORT) -> str:
    _validate_port(mcp_port)
    servers: dict[str, Any] = {}
    for alias in DEMO_ALIASES:
        servers[f"signet_demo_{alias}"] = {
            "url": f"http://127.0.0.1:{mcp_port}/mcp/{alias}",
            "headers": {"Authorization": "Bearer ${SIGNET_DEMO_MCP_CALLER_TOKEN}"},
            "enabled": True,
            "connect_timeout": 10,
            "timeout": 120,
            "supports_parallel_tool_calls": False,
            "tools": {"resources": False, "prompts": False},
            "sampling": {"enabled": False},
        }
    return yaml.safe_dump(
        {"mcp_servers": servers},
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
    )


def backup_demo(root: Path, output: Path) -> Path:
    destination = _absolute_artifact_path(
        output,
        message="demo backup destination path is unavailable or unsafe",
    )
    _require_private_parent(destination.parent)
    assembly = build_demo(root)
    return assembly.backups.create(destination)


def restore_demo(source_root: Path, bundle: Path, destination: Path) -> RestoredBundle:
    bundle_path = _absolute_artifact_path(
        bundle,
        message="demo backup bundle path is unavailable or unsafe",
    )
    destination_path = _absolute_artifact_path(
        destination,
        message="demo restore destination path is unavailable or unsafe",
    )
    _require_private_parent(destination_path.parent)
    source = build_demo(source_root)
    restored = source.backups.restore(bundle_path, destination_path)
    try:
        source_policy = _read_bounded_regular(source.root / _POLICY_FILE)
        _write_new_file(destination_path / _POLICY_FILE, source_policy)
        imports = destination_path / _IMPORTS_DIRECTORY
        imports.mkdir(mode=0o700)
        imports_identity = harden_private_directory_identity(
            capture_owned_directory_identity(imports)
        )
        if not imports_identity.same_object(require_private_directory_identity(imports)):
            raise DemoError("restored demo imports directory changed or became unsafe")
        source_secrets = _load_demo(source_root)[2]
        rotated = _rotated_secrets(source_secrets)
        _enroll_web_credentials(
            Database(restored.database_path),
            rotated,
            now=int(time.time()),
        )
        _write_json(
            destination_path / _STATE_FILE,
            {
                "format": DEMO_FORMAT,
                "mode": DEMO_MODE,
                "created_at": int(time.time()),
                "database": _DATABASE_FILE,
                "policy": _POLICY_FILE,
                "attachments": _ATTACHMENTS_DIRECTORY,
                "imports": _IMPORTS_DIRECTORY,
                "user_id": DEMO_USER_ID,
                "namespace": DEMO_NAMESPACE,
                "aliases": list(DEMO_ALIASES),
            },
        )
        _write_json(destination_path / _SECRETS_FILE, _secrets_document(rotated))
        _fsync_directory(destination_path)
        build_demo(destination_path)
    except BaseException:
        try:
            remove_private_tree_checked(
                restored.root,
                parent_identity=restored.parent_identity,
                tree_identity=restored.root_identity,
            )
        except BaseException as cleanup_error:
            raise BackupCleanupStateUnknown(
                "demo restore did not complete, but its private restore tree could not be "
                "removed; inspect the restore parent and do not start that tree"
            ) from cleanup_error
        raise
    return restored


def purge_fake_unknown_content(
    root: Path,
    *,
    request_id: str,
    expected_version: int,
    expected_payload_hash: str,
    acknowledge_possible_delivery: bool,
    now: int | None = None,
) -> dict[str, int | str | bool]:
    """Redact one durably exhausted fake-only unknown while preserving uncertainty."""

    demo_root, _state, _secrets = _load_demo(root)
    selected_now = int(time.time()) if now is None else now
    with _demo_server_lock(demo_root):
        assembly = build_demo(demo_root)
        retention = assembly.workers.retention
        try:
            scheduled = retention.authorize_fake_only_exhausted_unknown_purge(
                request_id=request_id,
                expected_version=expected_version,
                expected_payload_hash=expected_payload_hash,
                acknowledge_possible_external_effect=acknowledge_possible_delivery,
                now=selected_now,
            )
        except RetentionError as exc:
            raise DemoError(str(exc)) from None

        claimed = completed = failed = 0
        for _ in range(2):
            claim = retention.claim_due(now=selected_now, request_id=request_id)
            if claim is None:
                break
            claimed += 1
            if retention.process(claim, now=selected_now):
                completed += 1
            else:
                failed += 1

        keys = tuple(
            fake_unknown_purge_job_key(
                request_id=request_id,
                version=expected_version,
                payload_hash=expected_payload_hash,
                intent=intent.value,
            )
            for intent in (PurgeIntent.ATTACHMENTS, PurgeIntent.SENSITIVE_ROWS)
        )
        with assembly.database.read() as connection:
            remaining = connection.execute(
                """
                SELECT count(*) FROM purge_jobs
                WHERE idempotency_key IN (?, ?) AND completed_at IS NULL
                """,
                keys,
            ).fetchone()[0]
        if remaining or failed:
            retry = retention.pending_retry_status(
                idempotency_keys=keys,
                now=selected_now,
            )
            raise DemoError(
                json.dumps(
                    {
                        "failed": failed,
                        "reason": retry.reason if retry is not None else "purge_incomplete",
                        "retry_after": retry.retry_after if retry is not None else 1,
                        "status": "fake_only_content_purge_incomplete",
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
    return {
        "claimed": claimed,
        "completed": completed,
        "failed": failed,
        "scheduled": scheduled,
        "state": RequestState.OUTCOME_UNKNOWN.value,
        "status": "fake_only_content_purged",
        "uncertainty_preserved": True,
    }


def release_abandoned_demo_backup_pins(
    root: Path,
    *,
    created_at_or_before: int,
    acknowledge_no_backup_active: bool,
    now: int | None = None,
) -> dict[str, int | str]:
    """Release abandoned pin rows only in a stopped, marker-guarded fake demo."""

    if acknowledge_no_backup_active is not True:
        raise DemoError("abandoned pin release requires explicit no-backup acknowledgement")
    demo_root, _state, _secrets = _load_demo(root)
    selected_now = int(time.time()) if now is None else now
    with _demo_server_lock(demo_root):
        assembly = build_demo(demo_root)
        with _demo_backup_maintenance_lock(demo_root):
            pins = BackupPins(assembly.database)
            try:
                released = pins.release_abandoned(
                    before=created_at_or_before,
                    now=selected_now,
                )
            except (RetentionError, ValueError) as exc:
                raise DemoError(str(exc)) from None
            with assembly.database.read() as connection:
                remaining = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM purge_jobs
                        WHERE intent = 'backup_pin' AND completed_at IS NULL
                        """
                    ).fetchone()[0]
                )
    return {
        "created_at_or_before": created_at_or_before,
        "released_pin_rows": released,
        "remaining_active_pin_rows": remaining,
        "scope": "fake_only_downstream_disabled",
        "status": "abandoned_backup_pins_released",
    }


def offline_smoke(root: Path) -> dict[str, Any]:
    assembly = build_demo(root)
    integrity, foreign_keys = assembly.database.integrity_check()
    if integrity != "ok" or foreign_keys:
        raise DemoError("demo database integrity check failed")
    for alias in DEMO_ALIASES:
        assembly.token_registry.authenticate(
            f"Bearer {credential_value(root, 'mcp-token')}",
            alias=alias,
        )
    return {
        "status": "ok",
        "mode": DEMO_MODE,
        "database": "ok",
        "aliases": list(DEMO_ALIASES),
        "network_provider_calls": 0,
    }


def live_smoke(
    *,
    mcp_port: int = DEFAULT_MCP_PORT,
    web_port: int = DEFAULT_WEB_PORT,
) -> dict[str, Any]:
    _validate_port_pair(mcp_port, web_port)
    services = {"mcp": mcp_port, "web": web_port}
    for name, port in services.items():
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            raw = response.read(4097)
            if len(raw) > 4096:
                raise DemoError(f"live {name} health check failed")
            payload = json.loads(raw)
        except (OSError, ValueError, http.client.HTTPException):
            raise DemoError(f"live {name} health check failed") from None
        finally:
            connection.close()
        if response.status != 200 or not isinstance(payload, dict) or payload.get("status") != "ok":
            raise DemoError(f"live {name} health check failed")
    return {"status": "ok", "mode": DEMO_MODE, "services": sorted(services)}


async def serve_demo(
    root: Path,
    *,
    mcp_port: int = DEFAULT_MCP_PORT,
    web_port: int = DEFAULT_WEB_PORT,
) -> None:
    demo_root, _state, _secrets = _load_demo(root)
    # Preserve a direct, bounded CLI error for the common already-running case.
    # The worker lifespan acquires the authoritative lock again before it can
    # recover or dispatch, so a concurrent startup race still fails closed.
    with _demo_server_lock(demo_root):
        pass
    await _serve_demo_process(demo_root, mcp_port=mcp_port, web_port=web_port)


async def _serve_demo_process(
    root: Path,
    *,
    mcp_port: int,
    web_port: int,
) -> None:
    assembly = build_demo(root, mcp_port=mcp_port, web_port=web_port)
    servers = (
        _NoSignalServer(
            uvicorn.Config(
                assembly.mcp.app,
                host="127.0.0.1",
                port=mcp_port,
                server_header=False,
                timeout_graceful_shutdown=DEMO_GRACEFUL_SHUTDOWN_SECONDS,
                limit_concurrency=64,
                access_log=False,
                log_level="critical",
            )
        ),
        _NoSignalServer(
            uvicorn.Config(
                assembly.web,
                host="127.0.0.1",
                port=web_port,
                server_header=False,
                timeout_graceful_shutdown=DEMO_GRACEFUL_SHUTDOWN_SECONDS,
                limit_concurrency=64,
                access_log=False,
                log_level="critical",
            )
        ),
    )
    tasks = tuple(asyncio.create_task(server.serve()) for server in servers)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    handled_signals = (signal.SIGINT, signal.SIGTERM)
    previous_handlers = {selected: signal.getsignal(selected) for selected in handled_signals}
    installed_handlers: list[signal.Signals] = []
    for selected in handled_signals:
        try:
            loop.add_signal_handler(selected, stop.set)
        except (NotImplementedError, RuntimeError, ValueError):
            continue
        installed_handlers.append(selected)
    stop_task = asyncio.create_task(stop.wait(), name="signet-demo-stop")
    try:
        while not all(server.started for server in servers):
            if any(task.done() for task in tasks):
                raise DemoError("a demo listener failed before readiness")
            await asyncio.sleep(0.02)
        print(
            "Signet fake-only demo MCP: "
            f"http://127.0.0.1:{mcp_port}/mcp/{{fastmail,whatsapp,approvals}}",
            flush=True,
        )
        print(
            f"Signet fake-only demo web: http://127.0.0.1:{web_port}/login",
            flush=True,
        )
        done, _pending = await asyncio.wait(
            (*tasks, stop_task),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stop_task not in done:
            raise DemoError("a demo listener stopped unexpectedly")
    finally:
        stop_task.cancel()
        shutdown_error: DemoError | None = None
        try:
            await _shutdown_demo_servers(servers, tasks)
        except DemoError as exc:
            shutdown_error = exc
        finally:
            await asyncio.gather(stop_task, return_exceptions=True)
            for selected in installed_handlers:
                loop.remove_signal_handler(selected)
                signal.signal(selected, previous_handlers[selected])
        if shutdown_error is not None:
            raise shutdown_error


async def _shutdown_demo_servers(
    servers: tuple[_NoSignalServer, ...],
    tasks: tuple[asyncio.Task[bool | None], ...],
) -> None:
    for server in servers:
        server.should_exit = True
    try:
        async with asyncio.timeout(_DEMO_SERVER_EXIT_SECONDS):
            results = await asyncio.gather(*tasks, return_exceptions=True)
    except TimeoutError:
        for task in tasks:
            task.cancel()
        try:
            async with asyncio.timeout(_DEMO_FORCE_CANCEL_SECONDS):
                await asyncio.gather(*tasks, return_exceptions=True)
        except TimeoutError:
            pass
        raise DemoError("demo shutdown exceeded its graceful safety deadline") from None
    if any(isinstance(result, BaseException) for result in results):
        raise DemoError("a demo listener failed during shutdown")
    if any(server.forced_shutdown for server in servers):
        raise DemoError("demo shutdown exceeded its graceful safety deadline")


class _NoSignalServer(uvicorn.Server):
    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)
        self.forced_shutdown = False

    @contextmanager
    def capture_signals(self) -> Any:
        yield

    async def shutdown(self, sockets: list[Any] | None = None) -> None:
        active_tasks = tuple(self.server_state.tasks)
        await super().shutdown(sockets)
        self.forced_shutdown = any(task.cancelled() or task.cancelling() for task in active_tasks)


def add_demo_parser(subcommands: Any) -> None:
    demo = subcommands.add_parser("demo", help="run a marker-guarded fake-only demo")
    commands = demo.add_subparsers(dest="demo_command", required=True)

    initialize = commands.add_parser("init", help="initialize a new fake-only data directory")
    _data_dir_argument(initialize)

    seed_request = commands.add_parser(
        "seed-request",
        help="create or return one idempotent fake approval request",
        description=(
            "Admit one realistic fake email through the reviewed gateway while the demo "
            "server is stopped. Re-running while it is pending returns the same request; "
            "after it is resolved, the next run creates a new fake request."
        ),
    )
    _data_dir_argument(seed_request)

    credentials = commands.add_parser(
        "credentials", help="print one explicitly requested fake credential"
    )
    _data_dir_argument(credentials)
    credentials.add_argument(
        "--field",
        required=True,
        choices=(
            "web-user",
            "web-password",
            "web-login-proof",
            "web-action-proof",
            "mcp-token",
        ),
    )

    serve = commands.add_parser("serve", help="serve fake MCP and authenticated web apps")
    _data_dir_argument(serve)
    _port_arguments(serve)

    config = commands.add_parser("hermes-config", help="print restrictive Hermes MCP YAML")
    _data_dir_argument(config)
    config.add_argument("--mcp-port", type=_port_type, default=DEFAULT_MCP_PORT)

    smoke = commands.add_parser("smoke", help="verify demo state or running listeners")
    _data_dir_argument(smoke)
    smoke.add_argument("--live", action="store_true")
    _port_arguments(smoke)

    backup = commands.add_parser("backup", help="create an encrypted demo backup")
    _data_dir_argument(backup)
    backup.add_argument("--output", type=Path, required=True)

    purge_unknown = commands.add_parser(
        "purge-unknown",
        help="redact content from one exhausted fake-only unknown outcome",
        description=(
            "FAKE-ONLY destructive logical redaction for a durably exhausted unknown "
            "outcome. Stop the demo server first. This preserves outcome_unknown and "
            "does not erase SQLite free pages, snapshots, swap, or prior backups."
        ),
    )
    _data_dir_argument(purge_unknown)
    purge_unknown.add_argument(
        "--request-id",
        required=True,
        help="exact request ID recorded from the authenticated expanded review",
    )
    purge_unknown.add_argument(
        "--expected-version",
        type=_positive_version_type,
        required=True,
        help="exact current version recorded before stopping the demo server",
    )
    purge_unknown.add_argument(
        "--expected-payload-hash",
        type=_payload_hash_type,
        required=True,
        help="exact full lowercase SHA-256 payload hash from the expanded review",
    )
    purge_unknown.add_argument(
        "--acknowledge-possible-delivery",
        action="store_true",
        required=True,
        help="confirm that delivery remains possible and uncertainty must be preserved",
    )

    release_pins = commands.add_parser(
        "release-abandoned-pins",
        help="release abandoned fake-only backup pin rows",
        description=(
            "FAKE-ONLY recovery for backup pin rows left by a terminated demo backup. "
            "Stop the demo server and every backup, restore, or snapshot process using this "
            "data directory before running it. The inclusive cutoff is a Unix timestamp."
        ),
    )
    _data_dir_argument(release_pins)
    release_pins.add_argument(
        "--created-at-or-before",
        type=_retention_cutoff_type,
        required=True,
        help="inclusive creation-time cutoff as non-negative Unix seconds",
    )
    release_pins.add_argument(
        "--acknowledge-no-backup-active",
        action="store_true",
        required=True,
        help="confirm no backup, restore, or snapshot process is using the data directory",
    )

    restore = commands.add_parser("restore", help="restore into a new rotated demo directory")
    _data_dir_argument(restore)
    restore.add_argument("--bundle", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)


def run_demo_command(args: argparse.Namespace) -> None:
    try:
        _run_demo_command(args)
    except DemoError:
        raise
    except (
        BackupPublicationUnknown,
        BackupPublishedWithWarnings,
        BackupRetentionStateUnknown,
        BackupCleanupStateUnknown,
    ) as exc:
        raise DemoError(exc.operator_message()) from None
    except DatabaseFinalizationStateUnknown as exc:
        raise DemoError(exc.operator_message()) from None
    except (
        BackupError,
        CredentialError,
        DatabaseError,
        OSError,
        PolicyError,
        PolicyPersistenceError,
        RetentionError,
        StagingError,
    ):
        raise DemoError(f"demo {args.demo_command} failed safely") from None


def _run_demo_command(args: argparse.Namespace) -> None:
    command = cast(str, args.demo_command)
    if command == "init":
        initialized = initialize_demo(args.data_dir)
        print(f"Initialized Signet fake-only demo at {initialized}")
        return
    if command == "seed-request":
        seeded = seed_demo_request(args.data_dir)
        print(json.dumps(seeded, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    if command == "credentials":
        print(credential_value(args.data_dir, args.field))
        return
    if command == "serve":
        try:
            asyncio.run(
                serve_demo(
                    args.data_dir,
                    mcp_port=args.mcp_port,
                    web_port=args.web_port,
                )
            )
        except KeyboardInterrupt:
            return
        return
    if command == "hermes-config":
        _load_demo(args.data_dir)
        print(hermes_config(mcp_port=args.mcp_port), end="")
        return
    if command == "smoke":
        result = (
            live_smoke(mcp_port=args.mcp_port, web_port=args.web_port)
            if args.live
            else offline_smoke(args.data_dir)
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    if command == "backup":
        created = backup_demo(args.data_dir, args.output)
        print(f"Created encrypted fake-only demo backup at {created}")
        return
    if command == "purge-unknown":
        result = purge_fake_unknown_content(
            args.data_dir,
            request_id=args.request_id,
            expected_version=args.expected_version,
            expected_payload_hash=args.expected_payload_hash,
            acknowledge_possible_delivery=args.acknowledge_possible_delivery,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    if command == "release-abandoned-pins":
        result = release_abandoned_demo_backup_pins(
            args.data_dir,
            created_at_or_before=args.created_at_or_before,
            acknowledge_no_backup_active=args.acknowledge_no_backup_active,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    if command == "restore":
        restored = restore_demo(args.data_dir, args.bundle, args.destination)
        print(f"Restored Signet fake-only demo at {restored.root}")
        return
    raise DemoError("unknown demo command")


def _data_dir_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", type=Path, required=True)


def _port_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mcp-port", type=_port_type, default=DEFAULT_MCP_PORT)
    parser.add_argument("--web-port", type=_port_type, default=DEFAULT_WEB_PORT)


def _port_type(value: str) -> int:
    try:
        port = int(value)
        _validate_port(port)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("port must be between 1024 and 65535") from None
    return port


def _positive_version_type(value: str) -> int:
    try:
        version = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("version must be a positive integer") from None
    if version <= 0:
        raise argparse.ArgumentTypeError("version must be a positive integer")
    return version


def _retention_cutoff_type(value: str) -> int:
    try:
        cutoff = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("cutoff must be non-negative Unix seconds") from None
    if cutoff < 0 or cutoff > 9_000_000_000_000:
        raise argparse.ArgumentTypeError("cutoff must be non-negative Unix seconds")
    return cutoff


def _payload_hash_type(value: str) -> str:
    if len(value) != 64 or value.lower() != value:
        raise argparse.ArgumentTypeError("payload hash must be lowercase SHA-256 hex")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise argparse.ArgumentTypeError("payload hash must be lowercase SHA-256 hex") from None
    return value


def _validate_port(port: int) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or port < 1024 or port > 65535:
        raise ValueError("demo ports must be between 1024 and 65535")


def _validate_port_pair(mcp_port: int, web_port: int) -> None:
    _validate_port(mcp_port)
    _validate_port(web_port)
    if mcp_port == web_port:
        raise ValueError("demo MCP and web ports must be distinct")


def _new_secrets() -> DemoSecrets:
    registry = TokenRegistry()
    issued = registry.issue(DEMO_NAMESPACE, DEMO_ALIASES)
    return DemoSecrets(
        session_key=secrets.token_bytes(32),
        csrf_key=secrets.token_bytes(32),
        capability_key=secrets.token_bytes(32),
        payload_secret=f"fake:payload:{secrets.token_urlsafe(48)}",
        attachment_secret=f"fake:attachment:{secrets.token_urlsafe(48)}",
        backup_key=secrets.token_bytes(_BACKUP_KEY_SIZE),
        totp_secret=f"fake:totp:{secrets.token_urlsafe(32)}",
        web_password=f"fake:password:{secrets.token_urlsafe(24)}",
        mcp_token=f"fake:{issued.token}",
        token_records=registry.export_records(),
    )


def _rotated_secrets(source: DemoSecrets) -> DemoSecrets:
    rotated = _new_secrets()
    return DemoSecrets(
        session_key=rotated.session_key,
        csrf_key=rotated.csrf_key,
        capability_key=rotated.capability_key,
        payload_secret=source.payload_secret,
        attachment_secret=source.attachment_secret,
        backup_key=rotated.backup_key,
        totp_secret=rotated.totp_secret,
        web_password=rotated.web_password,
        mcp_token=rotated.mcp_token,
        token_records=rotated.token_records,
    )


def _secrets_document(value: DemoSecrets) -> dict[str, Any]:
    return {
        "format": DEMO_FORMAT,
        "mode": DEMO_MODE,
        "session_key": _encode_bytes(value.session_key),
        "csrf_key": _encode_bytes(value.csrf_key),
        "capability_key": _encode_bytes(value.capability_key),
        "payload_secret": value.payload_secret,
        "attachment_secret": value.attachment_secret,
        "backup_key": _encode_bytes(value.backup_key),
        "totp_secret": value.totp_secret,
        "web_password": value.web_password,
        "mcp_token": value.mcp_token,
        "token_records": [
            {
                "token_id": record.token_id,
                "namespace": record.namespace,
                "allowed_aliases": sorted(record.allowed_aliases),
                "verifier": record.verifier,
                "revoked": record.revoked,
            }
            for record in value.token_records
        ],
    }


def _load_demo(root: Path) -> tuple[Path, dict[str, Any], DemoSecrets]:
    selected = _absolute_demo_path(root)
    try:
        resolved = selected.resolve(strict=True)
    except (OSError, RuntimeError):
        raise DemoError("demo data directory is unavailable or unsafe") from None
    if resolved != selected or selected.is_symlink() or not selected.is_dir():
        raise DemoError("demo data directory is unavailable or unsafe")
    selected = resolved
    metadata = selected.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise DemoError("demo data directory must be private mode 0700")
    try:
        selected = require_private_directory(selected)
    except PrivatePathError as exc:
        raise DemoError("demo data directory is unavailable or unsafe") from exc
    state = _read_json(selected / _STATE_FILE)
    required_state = {
        "format",
        "mode",
        "created_at",
        "database",
        "policy",
        "attachments",
        "imports",
        "user_id",
        "namespace",
        "aliases",
    }
    if (
        set(state) != required_state
        or state.get("format") != DEMO_FORMAT
        or state.get("mode") != DEMO_MODE
        or state.get("database") != _DATABASE_FILE
        or state.get("policy") != _POLICY_FILE
        or state.get("attachments") != _ATTACHMENTS_DIRECTORY
        or state.get("imports") != _IMPORTS_DIRECTORY
        or state.get("user_id") != DEMO_USER_ID
        or state.get("namespace") != DEMO_NAMESPACE
        or state.get("aliases") != list(DEMO_ALIASES)
        or isinstance(state.get("created_at"), bool)
        or not isinstance(state.get("created_at"), int)
    ):
        raise DemoError("demo fake-only marker is invalid")
    _require_private_child_directory(selected / _IMPORTS_DIRECTORY)
    raw = _read_json(selected / _SECRETS_FILE, secret=True)
    expected_secret_fields = {
        "format",
        "mode",
        "session_key",
        "csrf_key",
        "capability_key",
        "payload_secret",
        "attachment_secret",
        "backup_key",
        "totp_secret",
        "web_password",
        "mcp_token",
        "token_records",
    }
    if (
        set(raw) != expected_secret_fields
        or raw.get("format") != DEMO_FORMAT
        or raw.get("mode") != DEMO_MODE
    ):
        raise DemoError("demo secret document is invalid")
    text_fields = (
        "payload_secret",
        "attachment_secret",
        "totp_secret",
        "web_password",
        "mcp_token",
    )
    if any(
        not isinstance(raw.get(field), str)
        or not cast(str, raw[field])
        or len(cast(str, raw[field])) > 4096
        for field in text_fields
    ):
        raise DemoError("demo secret document is invalid")
    if (
        not cast(str, raw["payload_secret"]).startswith("fake:")
        or not cast(str, raw["attachment_secret"]).startswith("fake:")
        or not cast(str, raw["totp_secret"]).startswith("fake:")
        or not cast(str, raw["web_password"]).startswith("fake:")
    ):
        raise DemoError("demo refuses production-looking credentials")
    token_records = _parse_token_records(raw.get("token_records"))
    parsed = DemoSecrets(
        session_key=_decode_bytes(raw.get("session_key"), size=32),
        csrf_key=_decode_bytes(raw.get("csrf_key"), size=32),
        capability_key=_decode_bytes(raw.get("capability_key"), size=32),
        payload_secret=cast(str, raw["payload_secret"]),
        attachment_secret=cast(str, raw["attachment_secret"]),
        backup_key=_decode_bytes(raw.get("backup_key"), size=32),
        totp_secret=cast(str, raw["totp_secret"]),
        web_password=cast(str, raw["web_password"]),
        mcp_token=cast(str, raw["mcp_token"]),
        token_records=token_records,
    )
    if not parsed.mcp_token.startswith("fake:sgt_"):
        raise DemoError("demo refuses production-looking MCP credentials")
    registry = FakeOnlyTokenRegistry(parsed.token_records)
    for alias in DEMO_ALIASES:
        principal = registry.authenticate(f"Bearer {parsed.mcp_token}", alias=alias)
        if principal.namespace != DEMO_NAMESPACE:
            raise DemoError("demo MCP credential has a non-fake identity")
    return selected, state, parsed


def _parse_token_records(value: object) -> tuple[TokenRecord, ...]:
    if not isinstance(value, list) or len(value) != 1:
        raise DemoError("demo token registry is invalid")
    records: list[TokenRecord] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "token_id",
            "namespace",
            "allowed_aliases",
            "verifier",
            "revoked",
        }:
            raise DemoError("demo token registry is invalid")
        aliases = item.get("allowed_aliases")
        if (
            not isinstance(item.get("token_id"), str)
            or not isinstance(item.get("verifier"), str)
            or item.get("namespace") != DEMO_NAMESPACE
            or aliases != sorted(DEMO_ALIASES)
            or item.get("revoked") is not False
        ):
            raise DemoError("demo token registry is invalid")
        records.append(
            TokenRecord(
                token_id=cast(str, item["token_id"]),
                namespace=DEMO_NAMESPACE,
                allowed_aliases=frozenset(DEMO_ALIASES),
                verifier=cast(str, item["verifier"]),
                revoked=False,
            )
        )
    return tuple(records)


def _enroll_web_credentials(database: Database, value: DemoSecrets, *, now: int) -> None:
    password_hasher = PasswordHasher(
        time_cost=2,
        memory_cost=19_456,
        parallelism=1,
        hash_len=32,
        salt_len=16,
    )
    SQLitePasswordCredentialRepository(database).replace_password(
        PasswordCredential(
            credential_id=(
                "fake:password:"
                + hashlib.sha256(value.web_password.encode("utf-8")).hexdigest()[:24]
            ),
            user_id=DEMO_USER_ID,
            verifier=password_hasher.hash(value.web_password),
        ),
        now=now,
    )
    SQLiteTotpCredentialRepository(database).replace_totp(
        TotpCredential(
            credential_id=(
                "fake:totp:" + hashlib.sha256(value.totp_secret.encode("utf-8")).hexdigest()[:24]
            ),
            user_id=DEMO_USER_ID,
            secret_reference=_TOTP_REFERENCE,
        ),
        now=now,
    )


def _demo_policy_document() -> dict[str, Any]:
    return {
        "version": 1,
        "default_mode": "deny",
        "downstreams": {
            "fastmail": {
                "transport": "http",
                "url": "https://fastmail.fake.invalid/mcp",
                "account_ref": "fake:fastmail-account",
                "tools": {
                    "list_identities": {
                        "mode": "passthrough",
                        "reviewed_read_only": True,
                    },
                    "search_email": {
                        "mode": "passthrough",
                        "reviewed_read_only": True,
                    },
                    "send_email": {
                        "mode": "approval",
                        "adapter": "fastmail.send",
                        "communication_send": True,
                        "account_ref": "fake:fastmail-account",
                    },
                    "delete_email": {
                        "mode": "deny",
                        "reviewed_classification": "fake-destructive-deny",
                    },
                },
            },
            "whatsapp": {
                "transport": "http",
                "url": "https://whatsapp.fake.invalid/mcp",
                "account_ref": "fake:whatsapp-account",
                "tools": {
                    "list_chats": {
                        "mode": "passthrough",
                        "reviewed_read_only": True,
                    },
                    "send_text": {
                        "mode": "approval",
                        "adapter": "whatsapp.send_text",
                        "communication_send": True,
                        "account_ref": "fake:whatsapp-account",
                    },
                    "delete_chat": {
                        "mode": "deny",
                        "reviewed_classification": "fake-destructive-deny",
                    },
                },
            },
        },
    }


def _validate_fake_policy(snapshot: PolicySnapshot) -> None:
    expected = parse_policy(_demo_policy_document())
    if set(snapshot.downstreams) != set(expected.downstreams) or snapshot.version < 1:
        raise DemoError("demo refuses a non-fake policy configuration")
    for alias, reviewed in expected.downstreams.items():
        selected = snapshot.downstreams[alias]
        if (
            selected.transport != reviewed.transport
            or selected.url != reviewed.url
            or selected.command_ref is not None
            or selected.credential_ref is not None
            or selected.account_ref != reviewed.account_ref
            or selected.schema_review is not None
            or selected.wrapper_contract is not None
            or set(selected.tools) != set(reviewed.tools)
        ):
            raise DemoError("demo refuses a non-fake policy configuration")
        for name, expected_tool in reviewed.tools.items():
            tool = selected.tools[name]
            if (
                tool.adapter != expected_tool.adapter
                or tool.reviewed_read_only != expected_tool.reviewed_read_only
                or tool.communication_send != expected_tool.communication_send
                or tool.schema_digest != expected_tool.schema_digest
                or tool.limits != expected_tool.limits
                or tool.account_ref != expected_tool.account_ref
                or tool.reviewed_classification != expected_tool.reviewed_classification
            ):
                raise DemoError("demo refuses a non-fake policy configuration")


def _captured_tools() -> dict[str, list[dict[str, Any]]]:
    empty_input = {
        "type": "object",
        "additionalProperties": False,
        "maxProperties": 0,
    }
    return {
        "fastmail": [
            {
                "name": "list_identities",
                "description": "Return deterministic fake-only sender identities.",
                "inputSchema": empty_input,
                "outputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["identities"],
                    "properties": {
                        "identities": {
                            "type": "array",
                            "maxItems": 10,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["id", "email", "name"],
                                "properties": {
                                    "id": {"type": "string"},
                                    "email": {"type": "string"},
                                    "name": {"type": "string"},
                                },
                            },
                        }
                    },
                },
            },
            {
                "name": "search_email",
                "description": "Search deterministic fake-only sent-mail identifiers.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["query", "folder", "limit"],
                    "properties": {
                        "query": {"type": "string", "minLength": 1, "maxLength": 256},
                        "folder": {"const": "Sent"},
                        "limit": {"const": 10},
                    },
                },
                "outputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["messages"],
                    "properties": {
                        "messages": {
                            "type": "array",
                            "maxItems": 1,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["messageId", "submissionId", "threadId", "status"],
                                "properties": {
                                    "messageId": {"type": "string"},
                                    "submissionId": {"type": "string"},
                                    "threadId": {"type": "string"},
                                    "status": {"const": "sent"},
                                },
                            },
                        }
                    },
                },
            },
            {
                "name": "send_email",
                "description": "Queue a fake-only email for human review.",
                "inputSchema": dict(FASTMAIL_SEND_SCHEMA),
            },
            {
                "name": "delete_email",
                "description": "Demonstrate an explicitly denied mutation.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["message_id"],
                    "properties": {"message_id": {"type": "string", "minLength": 1}},
                },
            },
        ],
        "whatsapp": [
            {
                "name": "list_chats",
                "description": "Return a deterministic fake-only chat.",
                "inputSchema": empty_input,
                "outputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["chats"],
                    "properties": {
                        "chats": {
                            "type": "array",
                            "maxItems": 10,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["jid", "label"],
                                "properties": {
                                    "jid": {"type": "string"},
                                    "label": {"type": "string"},
                                },
                            },
                        }
                    },
                },
            },
            {
                "name": "send_text",
                "description": "Queue a fake-only WhatsApp message for human review.",
                "inputSchema": dict(WHATSAPP_TEXT_SCHEMA),
            },
            {
                "name": "delete_chat",
                "description": "Demonstrate an explicitly denied mutation.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["jid"],
                    "properties": {"jid": {"type": "string", "minLength": 1}},
                },
            },
        ],
    }


def _attach_worker_lifespan(app: FastAPI, workers: DemoWorkers) -> None:
    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(selected: FastAPI) -> AsyncIterator[None]:
        async with original(selected):
            stop = asyncio.Event()
            with workers._serve_lock():
                task = asyncio.create_task(
                    workers._serve_locked(stop),
                    name="signet-demo-workers",
                )
                try:
                    yield
                finally:
                    stop.set()
                    await task

    app.router.lifespan_context = lifespan


def _read_json(path: Path, *, secret: bool = False) -> dict[str, Any]:
    raw = _read_bounded_regular(path, require_private=secret)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise DemoError("demo state document is invalid") from None
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise DemoError("demo state document is invalid")
    return cast(dict[str, Any], value)


def _read_bounded_regular(path: Path, *, require_private: bool = False) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        require_no_acl_grants(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_CONFIG_BYTES
            or require_private
            and metadata.st_mode & 0o077
        ):
            raise DemoError("demo state file is unavailable or unsafe")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, _MAX_CONFIG_BYTES + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_CONFIG_BYTES:
                raise DemoError("demo state file exceeds its size limit")
        after = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or total != metadata.st_size:
            raise DemoError("demo state file changed while it was read")
        return b"".join(chunks)
    except (OSError, PrivatePathError) as exc:
        raise DemoError("demo state file is unavailable or unsafe") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_new_file(
        path,
        json.dumps(
            dict(value),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
    )


def _write_new_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        try:
            require_no_acl_grants(descriptor)
        except PrivatePathError as exc:
            raise DemoError("demo state file inherited an unsafe granting ACL") from exc
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise DemoError("demo state write failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_bytes(value: object, *, size: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise DemoError("demo secret document is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        raise DemoError("demo secret document is invalid") from None
    if len(decoded) != size or _encode_bytes(decoded) != value:
        raise DemoError("demo secret document is invalid")
    return decoded


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_no_replace(source: Path, destination: Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        function = cast(Any, getattr(library, "renameat2", None))
        if function is None:
            raise DemoError("atomic no-replace demo publication is unavailable")
        function.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        arguments = (-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    elif sys.platform == "darwin":
        function = cast(Any, getattr(library, "renamex_np", None))
        if function is None:
            raise DemoError("atomic no-replace demo publication is unavailable")
        function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        arguments = (os.fsencode(source), os.fsencode(destination), 0x00000004)
    else:
        raise DemoError("atomic no-replace demo publication is unavailable")
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    if function(*arguments) != 0:
        error = ctypes.get_errno() or errno.EIO
        failure = OSError(error, os.strerror(error), destination)
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), destination)
        raise DemoError("atomic no-replace demo publication failed") from failure


def _require_unchanged_demo_directory(
    identity: DirectoryIdentity,
    *,
    private: bool,
) -> Path:
    try:
        return revalidate_directory_identity(identity, private=private)
    except PrivatePathError as exc:
        raise DemoError("demo initialization directory changed or became unsafe") from exc


def _cleanup_demo_initialization_tree(
    temporary: Path,
    *,
    parent_identity: DirectoryIdentity,
    temporary_identity: DirectoryIdentity | None,
) -> None:
    revalidate_directory_identity(parent_identity, private=False)
    if temporary_identity is None:
        raise DemoError("demo initialization tree identity is unavailable for safe cleanup")
    if temporary_identity.path != temporary:
        raise DemoError("demo initialization tree identity is inconsistent")
    remove_private_tree_checked(
        temporary,
        parent_identity=parent_identity,
        tree_identity=temporary_identity,
    )


@contextmanager
def _demo_server_lock(root: Path) -> Iterator[None]:
    with _demo_named_lock(
        root,
        filename=_SERVE_LOCK_FILE,
        unsafe_message="demo serve lock is unavailable or unsafe",
        busy_message="this demo data directory is already being served",
        operation_description="demo server operation",
    ):
        yield


@contextmanager
def _demo_backup_maintenance_lock(root: Path) -> Iterator[None]:
    demo_root, _state, _secrets = _load_demo(root)
    with _demo_named_lock(
        demo_root,
        filename=_BACKUP_MAINTENANCE_LOCK_FILE,
        unsafe_message="demo backup maintenance lock is unavailable or unsafe",
        busy_message="demo backup maintenance is already active",
        operation_description="demo backup or restore operation",
    ):
        yield


def _safe_demo_operation_message(error: BaseException) -> str:
    if isinstance(
        error,
        (
            BackupPublicationUnknown,
            BackupPublishedWithWarnings,
            BackupRetentionStateUnknown,
            BackupCleanupStateUnknown,
        ),
    ):
        return error.operator_message()
    if isinstance(error, DemoError):
        return str(error)
    return "demo operation failed safely"


@contextmanager
def _demo_named_lock(
    root: Path,
    *,
    filename: str,
    unsafe_message: str,
    busy_message: str,
    operation_description: str,
) -> Iterator[None]:
    path = root / filename
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    lock_acquired = False
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != current_uid
            or metadata.st_nlink != 1
        ):
            raise DemoError(unsafe_message)
        os.fchmod(descriptor, 0o600)
        try:
            require_no_acl_grants(descriptor)
        except PrivatePathError as exc:
            raise DemoError(unsafe_message) from exc
        metadata = os.fstat(descriptor)
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise DemoError(unsafe_message)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DemoError(busy_message) from None
        lock_acquired = True
        locked = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (locked.st_dev, locked.st_ino)
            or current.st_uid != locked.st_uid
            or stat.S_IMODE(locked.st_mode) != 0o600
            or stat.S_IMODE(current.st_mode) != 0o600
            or locked.st_nlink != 1
            or current.st_nlink != 1
        ):
            raise DemoError(unsafe_message)
    except BaseException as exc:
        finalization_error = (
            _finalize_demo_lock_descriptor(descriptor, lock_acquired=lock_acquired)
            if descriptor is not None
            else None
        )
        if finalization_error is not None:
            if lock_acquired:
                raise DemoError(
                    "demo lock setup failed, and lock release could not be confirmed; stop all "
                    "demo processes and inspect the private lock file before retrying"
                ) from None
            raise DemoError(
                "demo lock setup failed, and lock descriptor cleanup could not be confirmed; "
                "stop all demo processes and inspect the private lock file before retrying"
            ) from None
        if isinstance(exc, DemoError):
            raise
        raise DemoError(unsafe_message) from exc

    operation_error: BaseException | None = None
    try:
        yield
    except BaseException as exc:
        operation_error = exc

    finalization_error = _finalize_demo_lock_descriptor(descriptor, lock_acquired=True)

    if finalization_error is not None:
        recovery = (
            "lock release could not be confirmed; stop all demo processes and inspect the "
            "private lock file before retrying"
        )
        if operation_error is not None:
            primary = _safe_demo_operation_message(operation_error)
            raise DemoError(f"{primary}; additionally, {recovery}") from None
        raise DemoError(
            f"{operation_description} completed, but {recovery}; inspect its destination result "
            "and do not repeat the operation blindly"
        ) from None
    if operation_error is not None:
        raise operation_error


def _finalize_demo_lock_descriptor(
    descriptor: int,
    *,
    lock_acquired: bool,
) -> BaseException | None:
    finalization_error: BaseException | None = None
    if lock_acquired:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except BaseException as exc:
            finalization_error = exc
    try:
        os.close(descriptor)
    except BaseException as exc:
        if finalization_error is None:
            finalization_error = exc
    return finalization_error


def _require_private_parent(path: Path) -> None:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise DemoError("backup parent must be an existing private directory") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise DemoError("backup parent must be an existing private directory")


def _require_private_child_directory(path: Path) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DemoError("demo private directory is unavailable or unsafe") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise DemoError("demo private directory is unavailable or unsafe")
