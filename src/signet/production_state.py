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
    updated_at: int


@dataclass(frozen=True, slots=True)
class ProductionFactorStatus:
    user_id: str
    kind: str
    label: str
    state: Literal["active", "disabled"]
    enrolled_at: int
    last_used_at: int | None


@dataclass(frozen=True, slots=True)
class ProductionStatus:
    schema_version: int
    setup_status: str
    ready: bool
    missing_prerequisites: tuple[str, ...]
    live_providers_ready: bool
    services: Mapping[str, ProductionServiceStatus]
    factors: Mapping[str, ProductionFactorStatus]


class ProductionStateStore:
    """Seed and inspect one idempotent production inventory snapshot."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def stage(
        self,
        config: ProductionConfig,
        *,
        capabilities: Mapping[str, bool],
        secret_references: Mapping[str, str],
        secret_identities: Mapping[str, str],
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
        config_changed = False
        with self.database.transaction() as connection:
            setup = connection.execute(
                "SELECT config_digest FROM production_setup_state WHERE state_id = 1"
            ).fetchone()
            if setup is not None and setup["config_digest"] != config_digest:
                opposite_rollout: Literal["disabled", "enabled"] = (
                    "disabled" if config.provider_rollout.state == "enabled" else "enabled"
                )
                transition_digest = production_config_digest(
                    config,
                    rollout_state=opposite_rollout,
                )
                compatible_digests = {
                    transition_digest,
                    _legacy_production_config_digest(config),
                    _rollout_preparation_base_digest(config),
                }
                if setup["config_digest"] not in compatible_digests:
                    raise ProductionStateError(
                        "staged production config differs from durable state"
                    )
                config_changed = True
                connection.execute(
                    """
                    UPDATE production_setup_state
                    SET config_digest = ?, capability_status_json = ?,
                        updated_at = MAX(updated_at, ?)
                    WHERE state_id = 1 AND config_digest = ?
                    """,
                    (config_digest, capability_json, now, setup["config_digest"]),
                )
                connection.execute(
                    """
                    UPDATE production_services
                    SET config_digest = ?, updated_at = MAX(updated_at, ?)
                    """,
                    (config_digest, now),
                )

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
            self._stage_secrets(
                connection,
                secret_references,
                identities=secret_identities,
                now=now,
            )
            self._stage_connectors(
                connection,
                config,
                now=now,
                reset_state=config_changed,
            )
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
                SELECT config_version, config_digest
                FROM production_setup_state WHERE state_id = 1
                """
            ).fetchone()
            if (
                stored is None
                or stored["config_version"] != config.version
                or stored["config_digest"] != config_digest
            ):
                raise ProductionStateError("durable production setup state has diverged")

    def record_worker_state(
        self,
        state: Literal["ready", "blocked", "stopped"],
        *,
        ready: bool,
        now: int,
    ) -> None:
        if (state == "ready") != ready:
            raise ValueError("worker readiness does not match lifecycle state")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise ValueError("production worker state time is invalid")
        with self.database.transaction() as connection:
            setup = connection.execute(
                "SELECT capability_status_json FROM production_setup_state WHERE state_id = 1"
            ).fetchone()
            if setup is None:
                raise ProductionStateError("production setup state is unavailable")
            capabilities = self._parse_capabilities(setup["capability_status_json"])
            capabilities["workers_ready"] = ready
            changed = connection.execute(
                """
                UPDATE production_services SET state = ?, updated_at = ?
                WHERE service_name = 'maintenance' AND service_kind = 'maintenance'
                """,
                (state, now),
            ).rowcount
            if changed != 1:
                raise ProductionStateError("production maintenance service is unavailable")
            connection.execute(
                """
                UPDATE production_setup_state
                SET capability_status_json = ?, updated_at = ?
                WHERE state_id = 1
                """,
                (
                    json.dumps(capabilities, sort_keys=True, separators=(",", ":")),
                    now,
                ),
            )

    def record_provider_state(
        self,
        state: Literal["active", "blocked"],
        *,
        ready: bool,
        now: int,
    ) -> None:
        """Atomically publish the live session-pool readiness observation."""

        if (state == "active") != ready:
            raise ValueError("provider readiness does not match lifecycle state")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise ValueError("production provider state time is invalid")
        with self.database.transaction() as connection:
            setup = connection.execute(
                "SELECT capability_status_json FROM production_setup_state WHERE state_id = 1"
            ).fetchone()
            if setup is None:
                raise ProductionStateError("production setup state is unavailable")
            capabilities = self._parse_capabilities(setup["capability_status_json"])
            capabilities["live_providers_ready"] = ready
            changed = connection.execute(
                "UPDATE production_connectors SET state = ?, updated_at = ?",
                (state, now),
            ).rowcount
            if changed < 1:
                raise ProductionStateError("production connector inventory is unavailable")
            connection.execute(
                """
                UPDATE production_setup_state
                SET capability_status_json = ?, updated_at = ? WHERE state_id = 1
                """,
                (json.dumps(capabilities, sort_keys=True, separators=(",", ":")), now),
            )

    def record_service_state(
        self,
        service_name: str,
        state: Literal["ready", "blocked", "stopped"],
        *,
        capability: Literal["mcp_ready", "web_ready"],
        ready: bool,
        now: int,
    ) -> None:
        if (state == "ready") != ready:
            raise ValueError("service readiness does not match lifecycle state")
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE production_services SET state = ?, updated_at = ?
                WHERE service_name = ?
                """,
                (state, now, service_name),
            ).rowcount
            setup = connection.execute(
                "SELECT capability_status_json FROM production_setup_state WHERE state_id = 1"
            ).fetchone()
            if updated != 1 or setup is None:
                raise ProductionStateError("production service state is not staged")
            capabilities = self._parse_capabilities(setup["capability_status_json"])
            capabilities[capability] = ready
            connection.execute(
                """
                UPDATE production_setup_state
                SET capability_status_json = ?, updated_at = ? WHERE state_id = 1
                """,
                (json.dumps(capabilities, sort_keys=True, separators=(",", ":")), now),
            )

    def rotate_secret(
        self,
        purpose: str,
        *,
        reference: str,
        current_identity: str,
        new_identity: str,
        now: int,
    ) -> None:
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in (current_identity, new_identity)
        ):
            raise ValueError("secret identity digest is invalid")
        if current_identity == new_identity:
            raise ValueError("secret rotation requires new material identity")
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE production_secret_references
                SET current_generation = current_generation + 1,
                    material_identity_digest = ?, updated_at = ?
                WHERE purpose = ? AND secret_ref = ? AND state = 'present'
                  AND material_identity_digest = ?
                """,
                (new_identity, now, purpose, reference, current_identity),
            ).rowcount
            if updated != 1:
                raise ProductionStateError("secret rotation precondition failed")

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
                SELECT service_name, service_kind, state, host, port, updated_at
                FROM production_services ORDER BY service_name
                """
            ).fetchall()
            factor_rows = connection.execute(
                """
                SELECT credential_id, user_id, kind, factor_label, enrolled_at,
                       disabled_at, last_used_at
                FROM auth_credentials ORDER BY credential_id
                """
            ).fetchall()
        if setup is None:
            raise ProductionStateError("production setup state is unavailable")
        capabilities = self._parse_capabilities(setup["capability_status_json"])
        missing = tuple(name for name in _CAPABILITY_ORDER if capabilities.get(name) is not True)
        setup_status = str(setup["setup_status"])
        services = MappingProxyType(
            {
                str(row["service_name"]): ProductionServiceStatus(
                    kind=str(row["service_kind"]),
                    state=str(row["state"]),
                    host=str(row["host"]) if row["host"] is not None else None,
                    port=int(row["port"]) if row["port"] is not None else None,
                    updated_at=int(row["updated_at"]),
                )
                for row in rows
            }
        )
        factors = MappingProxyType(
            {
                str(row["credential_id"]): ProductionFactorStatus(
                    user_id=str(row["user_id"]),
                    kind=str(row["kind"]),
                    label=str(row["factor_label"]),
                    state="disabled" if row["disabled_at"] is not None else "active",
                    enrolled_at=int(row["enrolled_at"]),
                    last_used_at=(
                        int(row["last_used_at"]) if row["last_used_at"] is not None else None
                    ),
                )
                for row in factor_rows
            }
        )
        return ProductionStatus(
            schema_version=schema_version,
            setup_status=setup_status,
            ready=setup_status == "ready" and not missing,
            missing_prerequisites=missing,
            live_providers_ready=capabilities["live_providers_ready"],
            services=services,
            factors=factors,
        )

    @staticmethod
    def _parse_capabilities(payload: Any) -> dict[str, bool]:
        try:
            capabilities = json.loads(str(payload))
        except (TypeError, ValueError) as exc:
            raise ProductionStateError("production capability state is invalid") from exc
        if (
            not isinstance(capabilities, dict)
            or tuple(sorted(capabilities)) != tuple(sorted(_CAPABILITY_ORDER))
            or any(not isinstance(value, bool) for value in capabilities.values())
        ):
            raise ProductionStateError("production capability state is invalid")
        return capabilities

    @staticmethod
    def _stage_secrets(
        connection: Any,
        references: Mapping[str, str],
        *,
        identities: Mapping[str, str],
        now: int,
    ) -> None:
        if set(identities) - set(references) or any(
            len(identity) != 64
            or any(character not in "0123456789abcdef" for character in identity)
            for identity in identities.values()
        ):
            raise ValueError("production secret identity inventory is invalid")
        for purpose, reference in references.items():
            identity = identities.get(purpose)
            stored = connection.execute(
                """
                SELECT secret_ref, state, current_generation, material_identity_digest
                FROM production_secret_references WHERE purpose = ?
                """,
                (purpose,),
            ).fetchone()
            if stored is None:
                connection.execute(
                    """
                    INSERT INTO production_secret_references(
                        secret_ref, purpose, current_generation,
                        material_identity_digest, state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reference,
                        purpose,
                        1 if identity is not None else None,
                        identity,
                        "present" if identity is not None else "required",
                        now,
                        now,
                    ),
                )
                continue
            if stored["secret_ref"] != reference:
                raise ProductionStateError("durable production secret inventory has diverged")
            if identity is None:
                if stored["state"] != "required":
                    raise ProductionStateError("required secret identity is no longer observable")
                continue
            if stored["state"] == "required":
                connection.execute(
                    """
                    UPDATE production_secret_references
                    SET current_generation = 1, material_identity_digest = ?,
                        state = 'present', updated_at = ?
                    WHERE purpose = ? AND state = 'required'
                    """,
                    (identity, now, purpose),
                )
                continue
            if (
                stored["state"] != "present"
                or stored["current_generation"] is None
                or stored["material_identity_digest"] != identity
            ):
                raise ProductionStateError(
                    "secret material changed without an explicit generation rotation"
                )

    @staticmethod
    def _stage_connectors(
        connection: Any,
        config: ProductionConfig,
        *,
        now: int,
        reset_state: bool,
    ) -> None:
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
            document = connector.model_dump(mode="json")
            digest = _connector_config_digest(document)
            desired_state = "blocked" if config.provider_rollout.state == "enabled" else "disabled"
            connection.execute(
                """
                INSERT OR IGNORE INTO production_connectors(
                    connector_alias, config_digest, transport, credential_ref,
                    credential_identity_digest, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alias,
                    digest,
                    connector.transport,
                    connector.credential_ref,
                    connector.credential_identity_digest,
                    desired_state,
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
            if stored is None or tuple(stored)[1:] != (
                connector.transport,
                connector.credential_ref,
                connector.credential_identity_digest,
            ):
                raise ProductionStateError("durable production connector differs from config")
            if stored["config_digest"] != digest:
                if not reset_state or stored["config_digest"] not in {
                    _legacy_connector_config_digest(document),
                    _rollout_preparation_connector_digest(document),
                }:
                    raise ProductionStateError("durable production connector differs from config")
                connection.execute(
                    """
                    UPDATE production_connectors
                    SET config_digest = ?, state = ?, updated_at = MAX(updated_at, ?)
                    WHERE connector_alias = ? AND config_digest = ?
                    """,
                    (digest, desired_state, now, alias, stored["config_digest"]),
                )
            elif reset_state:
                connection.execute(
                    """
                    UPDATE production_connectors
                    SET state = ?, updated_at = MAX(updated_at, ?)
                    WHERE connector_alias = ? AND state != ?
                    """,
                    (desired_state, now, alias, desired_state),
                )

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
                SELECT service_kind, host, port, config_digest
                FROM production_services WHERE service_name = ?
                """,
                (service.name,),
            ).fetchone()
            if stored is None or tuple(stored) != (
                service.kind,
                service.host,
                service.port,
                config_digest,
            ):
                raise ProductionStateError("durable production service differs from config")


def production_config_digest(
    config: ProductionConfig,
    *,
    rollout_state: Literal["disabled", "enabled"] | None = None,
) -> str:
    """Hash the complete versioned non-secret config document."""

    document = config.model_dump(mode="json")
    if rollout_state is not None:
        document["provider_rollout"]["state"] = rollout_state
        document["capabilities"]["live_providers_ready"] = rollout_state == "enabled"
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _connector_config_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _legacy_production_config_digest(config: ProductionConfig) -> str:
    """Reconstruct the pre-SP17 digest while allowing only new rollout fields to change."""

    document = config.model_dump(mode="json")
    document["storage"].pop("attachment_staging_dir", None)
    document["storage"].pop("attachment_source_roots", None)
    document["secrets"].pop("attachment_key_ref", None)
    document["capabilities"]["live_providers_ready"] = False
    document.pop("provider_rollout", None)
    for connector in document["connectors"].values():
        connector.pop("server_identity_digest", None)
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _legacy_connector_config_digest(document: dict[str, Any]) -> str:
    legacy = dict(document)
    legacy.pop("server_identity_digest", None)
    return hashlib.sha256(canonical_json(legacy)).hexdigest()


def _rollout_preparation_base_digest(config: ProductionConfig) -> str:
    """Reconstruct the disabled digest emitted before rollout prerequisites were staged."""

    document = config.model_dump(mode="json")
    document["storage"]["attachment_staging_dir"] = None
    document["storage"]["attachment_source_roots"] = []
    document["secrets"]["attachment_key_ref"] = None
    document["capabilities"]["live_providers_ready"] = False
    document["provider_rollout"] = {"state": "disabled", "wacli": None}
    for connector in document["connectors"].values():
        connector["server_identity_digest"] = None
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _rollout_preparation_connector_digest(document: dict[str, Any]) -> str:
    preparation = dict(document)
    preparation["server_identity_digest"] = None
    return hashlib.sha256(canonical_json(preparation)).hexdigest()
