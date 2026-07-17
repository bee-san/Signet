"""Durable, non-secret inventory for the staged production runtime."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from signet.canonical import canonical_json
from signet.config import ProductionConfig
from signet.db import Database
from signet.policy import PolicySnapshot, policy_config_hash

_CAPABILITY_ORDER = (
    "storage_ready",
    "secret_broker_ready",
    "mcp_ready",
    "web_ready",
    "workers_ready",
    "policy_ready",
    "live_providers_ready",
)


class ProductionStateError(RuntimeError):
    """Staged production inventory conflicts with durable state."""


@dataclass(frozen=True, slots=True)
class ProductionServiceRecord:
    name: str
    kind: Literal["mcp", "web", "worker", "maintenance"]
    state: Literal["staged", "ready", "blocked", "stopped"]
    host: str | None = None
    port: int | None = None


@dataclass(frozen=True, slots=True)
class ProductionServiceStatus:
    kind: str
    state: str
    host: str | None
    port: int | None


@dataclass(frozen=True, slots=True)
class ProductionStatus:
    schema_version: int
    setup_status: str
    ready: bool
    missing_prerequisites: tuple[str, ...]
    services: Mapping[str, ProductionServiceStatus]


class ProductionStateStore:
    """Seed and inspect one idempotent production inventory snapshot."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def stage(
        self,
        config: ProductionConfig,
        policy: PolicySnapshot,
        *,
        capabilities: Mapping[str, bool],
        secret_references: Mapping[str, str],
        services: tuple[ProductionServiceRecord, ...],
        now: int,
    ) -> None:
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise ValueError("production inventory time is invalid")
        if tuple(capabilities) != _CAPABILITY_ORDER or any(
            not isinstance(value, bool) for value in capabilities.values()
        ):
            raise ValueError("production capability inventory is invalid")
        if len({service.name for service in services}) != len(services):
            raise ValueError("production service names must be unique")

        config_digest = production_config_digest(config)
        capability_json = json.dumps(dict(capabilities), sort_keys=True, separators=(",", ":"))
        with self.database.transaction() as connection:
            setup = connection.execute(
                "SELECT config_digest FROM production_setup_state WHERE state_id = 1"
            ).fetchone()
            if setup is not None and setup["config_digest"] != config_digest:
                raise ProductionStateError("staged production config differs from durable state")

            owners = connection.execute("SELECT user_id FROM production_users").fetchall()
            if any(row["user_id"] != config.owner_user_id for row in owners):
                raise ProductionStateError("durable production owner differs from configured owner")

            connection.execute(
                """
                INSERT OR IGNORE INTO production_users(
                    user_id, state, created_at, updated_at
                ) VALUES (?, 'staged', ?, ?)
                """,
                (config.owner_user_id, now, now),
            )
            self._stage_factors(connection, config, now=now)
            self._stage_policy(connection, policy, now=now)
            self._stage_secrets(connection, secret_references, now=now)
            self._stage_connectors(connection, config, now=now)
            self._stage_services(
                connection,
                services,
                config_digest=config_digest,
                now=now,
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO production_setup_state(
                    state_id, config_version, config_digest, setup_status,
                    capability_status_json, created_at, updated_at
                ) VALUES (1, ?, ?, 'staged', ?, ?, ?)
                """,
                (config.version, config_digest, capability_json, now, now),
            )
            stored = connection.execute(
                """
                SELECT config_version, config_digest, capability_status_json
                FROM production_setup_state WHERE state_id = 1
                """
            ).fetchone()
            if (
                stored is None
                or stored["config_version"] != config.version
                or stored["config_digest"] != config_digest
                or stored["capability_status_json"] != capability_json
            ):
                raise ProductionStateError("durable production setup state has diverged")

    def status(self) -> ProductionStatus:
        with self.database.read() as connection:
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            setup = connection.execute(
                """
                SELECT setup_status, capability_status_json
                FROM production_setup_state WHERE state_id = 1
                """
            ).fetchone()
            rows = connection.execute(
                """
                SELECT service_name, service_kind, state, host, port
                FROM production_services ORDER BY service_name
                """
            ).fetchall()
        if setup is None:
            raise ProductionStateError("production setup state is unavailable")
        try:
            capabilities = json.loads(str(setup["capability_status_json"]))
        except (TypeError, ValueError) as exc:
            raise ProductionStateError("production capability state is invalid") from exc
        if not isinstance(capabilities, dict) or tuple(sorted(capabilities)) != tuple(
            sorted(_CAPABILITY_ORDER)
        ):
            raise ProductionStateError("production capability state is invalid")
        missing = tuple(name for name in _CAPABILITY_ORDER if capabilities.get(name) is not True)
        setup_status = str(setup["setup_status"])
        services = MappingProxyType(
            {
                str(row["service_name"]): ProductionServiceStatus(
                    kind=str(row["service_kind"]),
                    state=str(row["state"]),
                    host=str(row["host"]) if row["host"] is not None else None,
                    port=int(row["port"]) if row["port"] is not None else None,
                )
                for row in rows
            }
        )
        return ProductionStatus(
            schema_version=schema_version,
            setup_status=setup_status,
            ready=setup_status == "ready" and not missing,
            missing_prerequisites=missing,
            services=services,
        )

    @staticmethod
    def _stage_factors(connection: Any, config: ProductionConfig, *, now: int) -> None:
        factors: list[tuple[str, str | None]] = [("password", None)]
        if config.secrets.totp_secret_ref is not None:
            factors.append(("totp", config.secrets.totp_secret_ref))
        for kind, reference in factors:
            factor_id = hashlib.sha256(
                canonical_json(
                    {
                        "factor_kind": kind,
                        "label": "primary",
                        "user_id": config.owner_user_id,
                    }
                )
            ).hexdigest()
            connection.execute(
                """
                INSERT OR IGNORE INTO production_user_factors(
                    factor_id, user_id, factor_kind, label, state,
                    credential_ref, created_at, updated_at
                ) VALUES (?, ?, ?, 'primary', 'staged', ?, ?, ?)
                """,
                (factor_id, config.owner_user_id, kind, reference, now, now),
            )
            stored = connection.execute(
                """
                SELECT user_id, factor_kind, label, state, credential_ref
                FROM production_user_factors WHERE factor_id = ?
                """,
                (factor_id,),
            ).fetchone()
            if stored is None or tuple(stored) != (
                config.owner_user_id,
                kind,
                "primary",
                "staged",
                reference,
            ):
                raise ProductionStateError("durable production factor inventory has diverged")

    @staticmethod
    def _stage_policy(connection: Any, policy: PolicySnapshot, *, now: int) -> None:
        digest = policy_config_hash(policy)
        connection.execute(
            """
            INSERT OR IGNORE INTO production_policies(
                policy_name, policy_version, policy_digest, state, created_at, updated_at
            ) VALUES ('primary', ?, ?, 'staged', ?, ?)
            """,
            (policy.version, digest, now, now),
        )
        stored = connection.execute(
            """
            SELECT policy_version, policy_digest FROM production_policies
            WHERE policy_name = 'primary'
            """
        ).fetchone()
        if (
            stored is None
            or stored["policy_version"] != policy.version
            or stored["policy_digest"] != digest
        ):
            raise ProductionStateError("durable production policy differs from configured policy")

    @staticmethod
    def _stage_secrets(
        connection: Any,
        references: Mapping[str, str],
        *,
        now: int,
    ) -> None:
        for purpose, reference in references.items():
            identity_digest = hashlib.sha256(
                canonical_json(
                    {
                        "generation": 1,
                        "purpose": purpose,
                        "secret_ref": reference,
                    }
                )
            ).hexdigest()
            connection.execute(
                """
                INSERT OR IGNORE INTO production_secret_references(
                    secret_ref, purpose, state, current_generation, created_at, updated_at
                ) VALUES (?, ?, 'present', 1, ?, ?)
                """,
                (reference, purpose, now, now),
            )
            stored = connection.execute(
                """
                SELECT purpose, state, current_generation
                FROM production_secret_references WHERE secret_ref = ?
                """,
                (reference,),
            ).fetchone()
            if (
                stored is None
                or stored["purpose"] != purpose
                or stored["state"] != "present"
                or stored["current_generation"] != 1
            ):
                raise ProductionStateError("durable production secret inventory has diverged")
            connection.execute(
                """
                INSERT OR IGNORE INTO production_secret_generations(
                    secret_ref, generation, identity_digest, state, observed_at
                ) VALUES (?, 1, ?, 'current', ?)
                """,
                (reference, identity_digest, now),
            )
            generation = connection.execute(
                """
                SELECT identity_digest, state FROM production_secret_generations
                WHERE secret_ref = ? AND generation = 1
                """,
                (reference,),
            ).fetchone()
            if (
                generation is None
                or generation["identity_digest"] != identity_digest
                or generation["state"] != "current"
            ):
                raise ProductionStateError("durable production secret generation has diverged")

    @staticmethod
    def _stage_connectors(connection: Any, config: ProductionConfig, *, now: int) -> None:
        configured_aliases = set(config.connectors)
        stored_aliases = {
            str(row["connector_alias"])
            for row in connection.execute(
                "SELECT connector_alias FROM production_connectors"
            ).fetchall()
        }
        if stored_aliases - configured_aliases:
            raise ProductionStateError("durable production connector inventory has diverged")
        for alias, connector in config.connectors.items():
            digest = hashlib.sha256(canonical_json(connector.model_dump(mode="json"))).hexdigest()
            connection.execute(
                """
                INSERT OR IGNORE INTO production_connectors(
                    connector_alias, config_digest, transport, credential_ref,
                    credential_identity_digest, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'blocked', ?, ?)
                """,
                (
                    alias,
                    digest,
                    connector.transport,
                    connector.credential_ref,
                    connector.credential_identity_digest,
                    now,
                    now,
                ),
            )
            stored = connection.execute(
                """
                SELECT config_digest, transport, credential_ref, credential_identity_digest
                FROM production_connectors WHERE connector_alias = ?
                """,
                (alias,),
            ).fetchone()
            if stored is None or tuple(stored) != (
                digest,
                connector.transport,
                connector.credential_ref,
                connector.credential_identity_digest,
            ):
                raise ProductionStateError("durable production connector differs from config")

    @staticmethod
    def _stage_services(
        connection: Any,
        services: tuple[ProductionServiceRecord, ...],
        *,
        config_digest: str,
        now: int,
    ) -> None:
        configured_names = {service.name for service in services}
        stored_names = {
            str(row["service_name"])
            for row in connection.execute("SELECT service_name FROM production_services").fetchall()
        }
        if stored_names - configured_names:
            raise ProductionStateError("durable production service inventory has diverged")
        for service in services:
            connection.execute(
                """
                INSERT OR IGNORE INTO production_services(
                    service_name, service_kind, host, port, state, config_digest, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    service.name,
                    service.kind,
                    service.host,
                    service.port,
                    service.state,
                    config_digest,
                    now,
                ),
            )
            stored = connection.execute(
                """
                SELECT service_kind, host, port, state, config_digest
                FROM production_services WHERE service_name = ?
                """,
                (service.name,),
            ).fetchone()
            if stored is None or tuple(stored) != (
                service.kind,
                service.host,
                service.port,
                service.state,
                config_digest,
            ):
                raise ProductionStateError("durable production service differs from config")


def production_config_digest(config: ProductionConfig) -> str:
    """Hash only the versioned non-secret config document and opaque references."""

    return hashlib.sha256(canonical_json(config.model_dump(mode="json"))).hexdigest()
