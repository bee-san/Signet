"""Durable staged plugin, connector, discovery, evidence, and review history."""

from __future__ import annotations

import hmac
import json
import re
import secrets
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from signet.canonical import canonical_json, sha256_hex
from signet.db import Database, IntegrityError
from signet.effects import (
    EffectEvidence,
    EffectProfile,
    MutationEffect,
    RecommendedMode,
    TriState,
    recommend_policy,
)
from signet.mcp_mirror import tool_schema_digest, validate_lossless_tool
from signet.plugin_manifest import ValidatedPluginManifest

_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:authorization|cookie|password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|credential)$"
)
_CREDENTIAL_TEXT_RE = re.compile(
    r"(?i)(?:\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:sk|xox[baprs]|gh[pousr])-[A-Za-z0-9_-]{12,}|"
    r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@)"
)

MAX_ACTIVE_PLUGIN_IDS = 128
MAX_CONNECTOR_ALIASES = 128
MAX_RETAINED_TOOL_NAMES_PER_ALIAS = 512


class IntegrationStoreError(RuntimeError):
    """Staged integration state is malformed, stale, or conflicting."""


class ConnectorGenerationChangedError(IntegrationStoreError):
    """The connector pointer changed while discovery was in flight."""


@dataclass(frozen=True, slots=True)
class PluginIdentity:
    plugin_id: str
    plugin_version: str
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class PluginRecord:
    plugin: PluginIdentity
    installed_at: int
    disabled_at: int | None


@dataclass(frozen=True, slots=True)
class PluginDetail:
    record: PluginRecord
    manifest: dict[str, Any]
    mappings: tuple[ToolMappingRecord, ...]


@dataclass(frozen=True, slots=True, repr=False)
class ConnectorRecord:
    alias: str
    config_digest: str
    plugin: PluginIdentity
    connector_id: str
    credential_ref: str | None
    credential_identity_digest: str | None
    configured_at: int
    disabled_at: int | None = None
    plugin_current: bool = True

    @property
    def is_active(self) -> bool:
        """Whether both mutable pointers still select this exact configuration."""

        return self.disabled_at is None and self.plugin_current

    def __repr__(self) -> str:
        return (
            "ConnectorRecord("
            f"alias={self.alias!r}, config_digest={self.config_digest!r}, "
            f"plugin={self.plugin!r}, connector_id={self.connector_id!r}, "
            "credential_ref=<redacted>, credential_identity_digest=<redacted>, "
            f"configured_at={self.configured_at!r}, disabled_at={self.disabled_at!r}, "
            f"plugin_current={self.plugin_current!r})"
        )


@dataclass(frozen=True, slots=True)
class ToolMappingRecord:
    connector_id: str
    tool_name: str
    action_id: str
    display_label: str
    proposed_effect: EffectProfile


@dataclass(frozen=True, slots=True)
class DiscoveryRecord:
    run_id: str
    alias: str
    config_digest: str
    source: Literal["fixture", "live"]
    server_identity_digest: str | None
    status: Literal["succeeded", "failed"]
    tool_count: int
    discovered_at: int
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class CurrentToolRecord:
    alias: str
    tool_name: str
    run_id: str
    schema_digest: str
    present: bool
    discovered_at: int


@dataclass(frozen=True, slots=True)
class DiscoveryDetail:
    discovery: DiscoveryRecord
    initialize_result: dict[str, Any] | None
    tools: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class ToolDetail:
    current: CurrentToolRecord
    definition_run_id: str | None
    definition: dict[str, Any] | None
    evidence: tuple[dict[str, Any], ...]
    valid_review: EffectReviewRecord | None


@dataclass(frozen=True, slots=True)
class EffectReviewRecord:
    review_id: int
    plugin: PluginIdentity
    connector_id: str
    alias: str
    config_digest: str
    run_id: str
    server_identity_digest: str
    tool_name: str
    schema_digest: str
    action_id: str
    profile: EffectProfile
    recommended_mode: RecommendedMode
    evidence_bundle_digest: str
    actor: str
    auth_kind: Literal["totp", "webauthn"]
    auth_use_id: str
    reviewed_at: int


@dataclass(frozen=True, slots=True)
class EffectReviewTarget:
    """Exact current integration material to which one human review is bound."""

    plugin: PluginIdentity
    connector_id: str
    alias: str
    config_digest: str
    run_id: str
    server_identity_digest: str
    tool_name: str
    schema_digest: str
    action_id: str
    evidence_bundle_digest: str
    mapping_key: str
    snapshot_digest: str


class SQLiteIntegrationStore:
    """Store immutable review material and mutable pointers to its current generation."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def install_plugin(
        self,
        validated: ValidatedPluginManifest,
        *,
        installed_at: int,
    ) -> PluginIdentity:
        if not _timestamp(installed_at):
            raise ValueError("plugin installation time is invalid")
        manifest = validated.manifest
        canonical = bytes(validated.canonical_bytes)
        if sha256_hex(canonical) != validated.sha256:
            raise IntegrationStoreError("validated plugin manifest digest does not match")
        identity = PluginIdentity(
            plugin_id=manifest.plugin_id,
            plugin_version=manifest.plugin_version,
            manifest_sha256=validated.sha256,
        )
        try:
            with self.database.transaction() as connection:
                existing_pointer = connection.execute(
                    "SELECT 1 FROM plugin_active WHERE plugin_id = ?",
                    (identity.plugin_id,),
                ).fetchone()
                pointer_count = int(
                    connection.execute("SELECT count(*) FROM plugin_active").fetchone()[0]
                )
                if existing_pointer is None and pointer_count >= MAX_ACTIVE_PLUGIN_IDS:
                    raise IntegrationStoreError("installed plugin identifier limit reached")
                connection.execute(
                    """
                    INSERT INTO plugin_manifests(
                        plugin_id, plugin_version, manifest_sha256,
                        canonical_manifest, installed_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(plugin_id, plugin_version, manifest_sha256) DO NOTHING
                    """,
                    (*_plugin_tuple(identity), canonical, installed_at),
                )
                stored = connection.execute(
                    """
                    SELECT canonical_manifest FROM plugin_manifests
                    WHERE plugin_id = ? AND plugin_version = ? AND manifest_sha256 = ?
                    """,
                    _plugin_tuple(identity),
                ).fetchone()
                if stored is None or not hmac.compare_digest(bytes(stored[0]), canonical):
                    raise IntegrationStoreError("installed plugin identity conflicts with history")
                for mapping in manifest.tool_mappings:
                    profile = _manifest_profile(mapping.proposed_effects.model_dump(mode="python"))
                    proposed = canonical_json(profile.as_dict())
                    connection.execute(
                        """
                        INSERT INTO plugin_tool_mappings(
                            plugin_id, plugin_version, manifest_sha256, connector_id,
                            tool_name, action_id, display_label,
                            proposed_effect_json, proposed_effect_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(
                            plugin_id, plugin_version, manifest_sha256, connector_id, tool_name
                        ) DO NOTHING
                        """,
                        (
                            *_plugin_tuple(identity),
                            mapping.connector_id,
                            mapping.tool_name,
                            mapping.action_id,
                            mapping.display_label,
                            proposed,
                            sha256_hex(proposed),
                        ),
                    )
                    row = connection.execute(
                        """
                        SELECT action_id, display_label, proposed_effect_json
                        FROM plugin_tool_mappings
                        WHERE plugin_id = ? AND plugin_version = ? AND manifest_sha256 = ?
                          AND connector_id = ? AND tool_name = ?
                        """,
                        (*_plugin_tuple(identity), mapping.connector_id, mapping.tool_name),
                    ).fetchone()
                    if (
                        row is None
                        or row["action_id"] != mapping.action_id
                        or row["display_label"] != mapping.display_label
                        or not hmac.compare_digest(bytes(row["proposed_effect_json"]), proposed)
                    ):
                        raise IntegrationStoreError(
                            "plugin mapping conflicts with immutable history"
                        )
                connection.execute(
                    """
                    INSERT INTO plugin_active(
                        plugin_id, plugin_version, manifest_sha256, activated_at, disabled_at
                    ) VALUES (?, ?, ?, ?, NULL)
                    ON CONFLICT(plugin_id) DO UPDATE SET
                        plugin_version = excluded.plugin_version,
                        manifest_sha256 = excluded.manifest_sha256,
                        activated_at = excluded.activated_at,
                        disabled_at = NULL
                    """,
                    (*_plugin_tuple(identity), installed_at),
                )
        except IntegrityError as exc:
            raise IntegrationStoreError("plugin installation conflicts with durable state") from exc
        return identity

    def disable_plugin(self, plugin_id: str, *, disabled_at: int) -> bool:
        if not plugin_id or not _timestamp(disabled_at):
            raise ValueError("plugin disable scope is invalid")
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE plugin_active SET disabled_at = ?
                WHERE plugin_id = ? AND disabled_at IS NULL AND activated_at <= ?
                """,
                (disabled_at, plugin_id, disabled_at),
            ).rowcount
            connection.execute(
                """
                UPDATE connector_active SET disabled_at = ?
                WHERE disabled_at IS NULL AND alias IN (
                    SELECT active.alias
                    FROM connector_active AS active
                    JOIN connector_configurations AS config
                      ON config.alias = active.alias
                     AND config.config_digest = active.config_digest
                    WHERE config.plugin_id = ?
                )
                """,
                (disabled_at, plugin_id),
            )
        return int(updated) == 1

    def list_plugins(self, *, limit: int = 100) -> tuple[PluginRecord, ...]:
        """List bounded current plugin pointers, including disabled installations."""

        _validate_limit(limit, maximum=1000)
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT active.plugin_id, active.plugin_version, active.manifest_sha256,
                       manifest.installed_at, active.disabled_at
                FROM plugin_active AS active
                JOIN plugin_manifests AS manifest
                  ON manifest.plugin_id = active.plugin_id
                 AND manifest.plugin_version = active.plugin_version
                 AND manifest.manifest_sha256 = active.manifest_sha256
                ORDER BY active.plugin_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(_plugin_record_from_row(row) for row in rows)

    def get_plugin(self, plugin_id: str) -> PluginDetail | None:
        """Return the selected immutable manifest and its exact mapping proposals."""

        if not isinstance(plugin_id, str) or not plugin_id:
            raise ValueError("plugin identifier is invalid")
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT active.plugin_id, active.plugin_version, active.manifest_sha256,
                       manifest.installed_at, active.disabled_at,
                       manifest.canonical_manifest
                FROM plugin_active AS active
                JOIN plugin_manifests AS manifest
                  ON manifest.plugin_id = active.plugin_id
                 AND manifest.plugin_version = active.plugin_version
                 AND manifest.manifest_sha256 = active.manifest_sha256
                WHERE active.plugin_id = ?
                """,
                (plugin_id,),
            ).fetchone()
            if row is None:
                return None
            mapping_rows = connection.execute(
                """
                SELECT connector_id, tool_name, action_id, display_label,
                       proposed_effect_json
                FROM plugin_tool_mappings
                WHERE plugin_id = ? AND plugin_version = ? AND manifest_sha256 = ?
                ORDER BY connector_id, tool_name
                LIMIT 1025
                """,
                (row["plugin_id"], row["plugin_version"], row["manifest_sha256"]),
            ).fetchall()
        if len(mapping_rows) > 1024:
            raise IntegrationStoreError("stored plugin exceeds its mapping limit")
        manifest = _strict_json(bytes(row["canonical_manifest"]))
        if not isinstance(manifest, dict):
            raise IntegrationStoreError("stored plugin manifest is invalid")
        return PluginDetail(
            record=_plugin_record_from_row(row),
            manifest=manifest,
            mappings=tuple(_mapping_from_row(mapping) for mapping in mapping_rows),
        )

    def configure_connector(
        self,
        *,
        plugin_id: str,
        connector_id: str,
        alias: str,
        config: Mapping[str, Any],
        configured_at: int,
        credential_ref: str | None = None,
        credential_identity_digest: str | None = None,
        canonical_config_bytes: bytes | None = None,
        canonical_config_sha256: str | None = None,
    ) -> ConnectorRecord:
        _validate_alias(alias)
        if not connector_id or not _timestamp(configured_at):
            raise ValueError("connector configuration scope is invalid")
        _validate_credential_pair(credential_ref, credential_identity_digest)
        detached = dict(config)
        _reject_credentials(detached)
        if (canonical_config_bytes is None) != (canonical_config_sha256 is None):
            raise ValueError("canonical connector bytes and digest must be provided together")
        if canonical_config_bytes is None:
            envelope = {
                "config": detached,
                "credential_identity_digest": credential_identity_digest,
                "credential_ref": credential_ref,
            }
            canonical = canonical_json(envelope)
            digest = sha256_hex(canonical)
        else:
            canonical = bytes(canonical_config_bytes)
            _validate_digest(cast(str, canonical_config_sha256), "connector configuration digest")
            parsed = _strict_json(canonical)
            if (
                not isinstance(parsed, dict)
                or canonical_json(parsed) != canonical
                or parsed.get("credential_ref") != credential_ref
                or parsed.get("credential_identity_digest") != credential_identity_digest
            ):
                raise IntegrationStoreError(
                    "canonical connector configuration does not match its credential references"
                )
            noncredential_config = {
                key: value
                for key, value in parsed.items()
                if key not in {"credential_ref", "credential_identity_digest"}
            }
            if noncredential_config != detached:
                raise IntegrationStoreError(
                    "canonical connector configuration does not match its detached fields"
                )
            _reject_credentials(noncredential_config)
            digest = cast(str, canonical_config_sha256)
            if not hmac.compare_digest(sha256_hex(canonical), digest):
                raise IntegrationStoreError(
                    "canonical connector configuration digest does not match"
                )
        if len(canonical) > 1024 * 1024:
            raise IntegrationStoreError("connector configuration exceeds its byte limit")
        try:
            with self.database.transaction() as connection:
                existing_alias = connection.execute(
                    "SELECT 1 FROM connector_active WHERE alias = ?",
                    (alias,),
                ).fetchone()
                alias_count = int(
                    connection.execute("SELECT count(*) FROM connector_active").fetchone()[0]
                )
                if existing_alias is None and alias_count >= MAX_CONNECTOR_ALIASES:
                    raise IntegrationStoreError("connector alias limit reached")
                active = connection.execute(
                    """
                    SELECT plugin_version, manifest_sha256 FROM plugin_active
                    WHERE plugin_id = ? AND disabled_at IS NULL
                    """,
                    (plugin_id,),
                ).fetchone()
                if active is None:
                    raise IntegrationStoreError("plugin is not installed and active")
                identity = PluginIdentity(
                    plugin_id,
                    str(active["plugin_version"]),
                    str(active["manifest_sha256"]),
                )
                exists = connection.execute(
                    """
                    SELECT 1 FROM plugin_tool_mappings
                    WHERE plugin_id = ? AND plugin_version = ? AND manifest_sha256 = ?
                      AND connector_id = ? LIMIT 1
                    """,
                    (*_plugin_tuple(identity), connector_id),
                ).fetchone()
                if exists is None:
                    raise IntegrationStoreError("connector is not declared by the active plugin")
                connection.execute(
                    """
                    INSERT INTO connector_configurations(
                        alias, config_digest, plugin_id, plugin_version, manifest_sha256,
                        connector_id, canonical_config, credential_ref,
                        credential_identity_digest, configured_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(alias, config_digest) DO NOTHING
                    """,
                    (
                        alias,
                        digest,
                        *_plugin_tuple(identity),
                        connector_id,
                        canonical,
                        credential_ref,
                        credential_identity_digest,
                        configured_at,
                    ),
                )
                stored = connection.execute(
                    """
                    SELECT canonical_config, plugin_id, plugin_version, manifest_sha256,
                           connector_id, configured_at
                    FROM connector_configurations WHERE alias = ? AND config_digest = ?
                    """,
                    (alias, digest),
                ).fetchone()
                if (
                    stored is None
                    or not hmac.compare_digest(bytes(stored["canonical_config"]), canonical)
                    or tuple(
                        stored[key] for key in ("plugin_id", "plugin_version", "manifest_sha256")
                    )
                    != _plugin_tuple(identity)
                    or stored["connector_id"] != connector_id
                ):
                    raise IntegrationStoreError(
                        "connector identity conflicts with immutable history"
                    )
                connection.execute(
                    """
                    INSERT INTO connector_active(alias, config_digest, activated_at, disabled_at)
                    VALUES (?, ?, ?, NULL)
                    ON CONFLICT(alias) DO UPDATE SET
                        config_digest = excluded.config_digest,
                        activated_at = excluded.activated_at,
                        disabled_at = NULL
                    """,
                    (alias, digest, configured_at),
                )
        except IntegrityError as exc:
            raise IntegrationStoreError(
                "connector configuration conflicts with durable state"
            ) from exc
        return ConnectorRecord(
            alias=alias,
            config_digest=digest,
            plugin=identity,
            connector_id=connector_id,
            credential_ref=credential_ref,
            credential_identity_digest=credential_identity_digest,
            configured_at=configured_at,
        )

    def connector_configuration(self, alias: str) -> dict[str, Any]:
        """Return the exact current non-secret configuration for internal discovery use.

        The value may contain a Keychain reference and generation digest, never
        credential material.  CLI and web list methods intentionally return the
        redacted :class:`ConnectorRecord` instead.
        """

        connector = self.active_connector(alias)
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT canonical_config FROM connector_configurations
                WHERE alias = ? AND config_digest = ?
                """,
                (alias, connector.config_digest),
            ).fetchone()
        if row is None:
            raise IntegrationStoreError("connector configuration is unavailable")
        value = _strict_json(bytes(row["canonical_config"]))
        if not isinstance(value, dict):
            raise IntegrationStoreError("connector configuration is invalid")
        return value

    def disable_connector(self, alias: str, *, disabled_at: int) -> bool:
        _validate_alias(alias)
        if not _timestamp(disabled_at):
            raise ValueError("connector disable time is invalid")
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE connector_active SET disabled_at = ?
                WHERE alias = ? AND disabled_at IS NULL AND activated_at <= ?
                """,
                (disabled_at, alias, disabled_at),
            ).rowcount
        return int(updated) == 1

    def list_connectors(self, *, limit: int = 100) -> tuple[ConnectorRecord, ...]:
        """List bounded connector pointers without returning canonical configuration data."""

        _validate_limit(limit, maximum=1000)
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT config.alias, config.config_digest, config.plugin_id,
                       config.plugin_version, config.manifest_sha256, config.connector_id,
                       config.configured_at, active.disabled_at,
                       NULL AS credential_ref, NULL AS credential_identity_digest,
                       CASE WHEN plugin.plugin_id IS NULL THEN 0 ELSE 1 END AS plugin_current
                FROM connector_active AS active
                JOIN connector_configurations AS config
                  ON config.alias = active.alias AND config.config_digest = active.config_digest
                LEFT JOIN plugin_active AS plugin
                  ON plugin.plugin_id = config.plugin_id
                 AND plugin.plugin_version = config.plugin_version
                 AND plugin.manifest_sha256 = config.manifest_sha256
                 AND plugin.disabled_at IS NULL
                ORDER BY active.alias
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(_connector_from_row(row) for row in rows)

    def active_connector(self, alias: str) -> ConnectorRecord:
        _validate_alias(alias)
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT config.*, active.disabled_at
                FROM connector_active AS active
                JOIN connector_configurations AS config
                  ON config.alias = active.alias AND config.config_digest = active.config_digest
                JOIN plugin_active AS plugin
                  ON plugin.plugin_id = config.plugin_id
                 AND plugin.plugin_version = config.plugin_version
                 AND plugin.manifest_sha256 = config.manifest_sha256
                WHERE active.alias = ? AND active.disabled_at IS NULL
                  AND plugin.disabled_at IS NULL
                """,
                (alias,),
            ).fetchone()
        if row is None:
            raise IntegrationStoreError("connector is not configured and active")
        return _connector_from_row(row)

    def mappings_for_connector(self, connector: ConnectorRecord) -> tuple[ToolMappingRecord, ...]:
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT connector_id, tool_name, action_id, display_label, proposed_effect_json
                FROM plugin_tool_mappings
                WHERE plugin_id = ? AND plugin_version = ? AND manifest_sha256 = ?
                  AND connector_id = ?
                ORDER BY tool_name
                """,
                (*_plugin_tuple(connector.plugin), connector.connector_id),
            ).fetchall()
        return tuple(_mapping_from_row(row) for row in rows)

    def record_discovery(
        self,
        *,
        alias: str,
        source: Literal["fixture", "live"],
        initialize_result: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]],
        evidence: Mapping[str, Sequence[EffectEvidence]],
        discovered_at: int,
        run_id: str | None = None,
        expected_config_digest: str | None = None,
    ) -> DiscoveryRecord:
        connector = self.active_connector(alias)
        selected_config_digest = expected_config_digest or connector.config_digest
        _validate_digest(selected_config_digest, "expected connector configuration digest")
        if not hmac.compare_digest(connector.config_digest, selected_config_digest):
            raise ConnectorGenerationChangedError("connector changed during discovery")
        if source not in {"fixture", "live"} or not _timestamp(discovered_at):
            raise ValueError("connector discovery scope is invalid")
        selected_run_id = run_id or secrets.token_urlsafe(24)
        _validate_run_id(selected_run_id)
        initialized = canonical_json(dict(initialize_result))
        if not initialized or len(initialized) > 1024 * 1024:
            raise IntegrationStoreError("connector initialization identity exceeds its byte limit")
        server_digest = sha256_hex(initialized)
        prepared: list[tuple[str, str, bytes]] = []
        names: set[str] = set()
        aggregate = len(initialized)
        for candidate in tools:
            raw = validate_lossless_tool(candidate)
            name = raw.get("name")
            if not isinstance(name, str) or not name or name in names:
                raise IntegrationStoreError("discovery contains an invalid or duplicate tool name")
            _validate_tool_name(name)
            canonical = canonical_json(raw)
            aggregate += len(canonical)
            if aggregate > 8 * 1024 * 1024:
                raise IntegrationStoreError("discovery exceeds its aggregate byte limit")
            prepared.append((name, tool_schema_digest(raw), canonical))
            names.add(name)
        if set(evidence) != names:
            raise IntegrationStoreError("effect evidence must cover every exact discovered tool")
        try:
            with self.database.transaction() as connection:
                _require_current_connector_generation(
                    connection,
                    alias=alias,
                    expected_config_digest=selected_config_digest,
                )
                retained_names = int(
                    connection.execute(
                        "SELECT count(*) FROM connector_tool_state WHERE alias = ?",
                        (alias,),
                    ).fetchone()[0]
                )
                already_retained = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM connector_tool_state
                        WHERE alias = ?
                          AND tool_name IN (SELECT value FROM json_each(?))
                        """,
                        (alias, json.dumps(sorted(names), separators=(",", ":"))),
                    ).fetchone()[0]
                )
                if (
                    retained_names + len(names) - already_retained
                    > MAX_RETAINED_TOOL_NAMES_PER_ALIAS
                ):
                    raise IntegrationStoreError(
                        "connector retained tool-name limit reached; discovery was not recorded"
                    )
                connection.execute(
                    """
                    INSERT INTO connector_discovery_runs(
                        run_id, alias, config_digest, source, server_identity_digest,
                        canonical_initialize_result, status, error_code, tool_count, discovered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'succeeded', NULL, ?, ?)
                    """,
                    (
                        selected_run_id,
                        alias,
                        connector.config_digest,
                        source,
                        server_digest,
                        initialized,
                        len(prepared),
                        discovered_at,
                    ),
                )
                for name, digest, canonical in prepared:
                    connection.execute(
                        """
                        INSERT INTO connector_discovered_tools(
                            run_id, tool_name, schema_digest, canonical_tool
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (selected_run_id, name, digest, canonical),
                    )
                    packet = tuple(evidence[name])
                    sources = {item.source.value for item in packet}
                    if len(sources) != len(packet) or not packet:
                        raise IntegrationStoreError(
                            "effect evidence sources must be nonempty and unique"
                        )
                    for item in packet:
                        evidence_bytes = item.canonical_bytes
                        connection.execute(
                            """
                            INSERT INTO connector_effect_evidence(
                                run_id, tool_name, schema_digest, source,
                                canonical_evidence, evidence_digest, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                selected_run_id,
                                name,
                                digest,
                                item.source.value,
                                evidence_bytes,
                                item.digest,
                                discovered_at,
                            ),
                        )
                connection.execute(
                    """
                    UPDATE connector_tool_state
                    SET run_id = ?, present = 0, discovered_at = ?
                    WHERE alias = ? AND present = 1
                    """,
                    (selected_run_id, discovered_at, alias),
                )
                for name, digest, _canonical in prepared:
                    connection.execute(
                        """
                        INSERT INTO connector_tool_state(
                            alias, tool_name, run_id, schema_digest, present, discovered_at
                        ) VALUES (?, ?, ?, ?, 1, ?)
                        ON CONFLICT(alias, tool_name) DO UPDATE SET
                            run_id = excluded.run_id,
                            schema_digest = excluded.schema_digest,
                            present = 1,
                            discovered_at = excluded.discovered_at
                        """,
                        (alias, name, selected_run_id, digest, discovered_at),
                    )
        except IntegrityError as exc:
            raise IntegrationStoreError(
                "discovery conflicts with durable integration history"
            ) from exc
        return DiscoveryRecord(
            run_id=selected_run_id,
            alias=alias,
            config_digest=connector.config_digest,
            source=source,
            server_identity_digest=server_digest,
            status="succeeded",
            tool_count=len(prepared),
            discovered_at=discovered_at,
        )

    def record_discovery_failure(
        self,
        alias: str,
        *,
        source: Literal["fixture", "live"],
        error_code: str,
        discovered_at: int,
        run_id: str | None = None,
        expected_config_digest: str | None = None,
    ) -> DiscoveryRecord:
        connector = self.active_connector(alias)
        selected_config_digest = expected_config_digest or connector.config_digest
        _validate_digest(selected_config_digest, "expected connector configuration digest")
        if not hmac.compare_digest(connector.config_digest, selected_config_digest):
            raise ConnectorGenerationChangedError("connector changed during discovery")
        selected_run_id = run_id or secrets.token_urlsafe(24)
        _validate_run_id(selected_run_id)
        if (
            source not in {"fixture", "live"}
            or not _timestamp(discovered_at)
            or re.fullmatch(r"[a-z0-9][a-z0-9_:-]{0,63}", error_code) is None
        ):
            raise ValueError("failed discovery scope is invalid")
        try:
            with self.database.transaction() as connection:
                _require_current_connector_generation(
                    connection,
                    alias=alias,
                    expected_config_digest=selected_config_digest,
                )
                connection.execute(
                    """
                    INSERT INTO connector_discovery_runs(
                        run_id, alias, config_digest, source, server_identity_digest,
                        canonical_initialize_result, status, error_code, tool_count, discovered_at
                    ) VALUES (?, ?, ?, ?, NULL, NULL, 'failed', ?, 0, ?)
                    """,
                    (
                        selected_run_id,
                        alias,
                        connector.config_digest,
                        source,
                        error_code,
                        discovered_at,
                    ),
                )
        except IntegrityError as exc:
            raise IntegrationStoreError("failed discovery conflicts with durable history") from exc
        return DiscoveryRecord(
            run_id=selected_run_id,
            alias=alias,
            config_digest=connector.config_digest,
            source=source,
            server_identity_digest=None,
            status="failed",
            tool_count=0,
            discovered_at=discovered_at,
            error_code=error_code,
        )

    def current_tools(
        self,
        alias: str,
        *,
        include_removed: bool = False,
    ) -> tuple[CurrentToolRecord, ...]:
        _validate_alias(alias)
        with self.database.read() as connection:
            if include_removed:
                rows = connection.execute(
                    """
                    SELECT alias, tool_name, run_id, schema_digest, present, discovered_at
                    FROM connector_tool_state WHERE alias = ? ORDER BY tool_name
                    """,
                    (alias,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT alias, tool_name, run_id, schema_digest, present, discovered_at
                    FROM connector_tool_state
                    WHERE alias = ? AND present = 1 ORDER BY tool_name
                    """,
                    (alias,),
                ).fetchall()
        return tuple(
            CurrentToolRecord(
                alias=str(row["alias"]),
                tool_name=str(row["tool_name"]),
                run_id=str(row["run_id"]),
                schema_digest=str(row["schema_digest"]),
                present=bool(row["present"]),
                discovered_at=int(row["discovered_at"]),
            )
            for row in rows
        )

    def discovery_detail(
        self,
        alias: str,
        *,
        run_id: str | None = None,
        max_tools: int = 512,
    ) -> DiscoveryDetail | None:
        """Return one bounded immutable discovery snapshot for review display."""

        _validate_alias(alias)
        _validate_limit(max_tools, maximum=10_000)
        if run_id is not None:
            _validate_run_id(run_id)
        with self.database.read() as connection:
            if run_id is None:
                row = connection.execute(
                    """
                    SELECT * FROM connector_discovery_runs
                    WHERE alias = ?
                    ORDER BY discovered_at DESC, run_id DESC LIMIT 1
                    """,
                    (alias,),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT * FROM connector_discovery_runs
                    WHERE alias = ? AND run_id = ?
                    ORDER BY discovered_at DESC, run_id DESC LIMIT 1
                    """,
                    (alias, run_id),
                ).fetchone()
            if row is None:
                return None
            tool_rows = connection.execute(
                """
                SELECT canonical_tool FROM connector_discovered_tools
                WHERE run_id = ? ORDER BY tool_name LIMIT ?
                """,
                (row["run_id"], max_tools + 1),
            ).fetchall()
        if len(tool_rows) > max_tools:
            raise IntegrationStoreError("discovery detail exceeds its requested tool limit")
        initialized: dict[str, Any] | None = None
        if row["canonical_initialize_result"] is not None:
            parsed = _strict_json(bytes(row["canonical_initialize_result"]))
            if not isinstance(parsed, dict):
                raise IntegrationStoreError("stored connector initialization is invalid")
            initialized = parsed
        tools: list[dict[str, Any]] = []
        for tool_row in tool_rows:
            parsed = _strict_json(bytes(tool_row["canonical_tool"]))
            if not isinstance(parsed, dict):
                raise IntegrationStoreError("stored connector tool is invalid")
            tools.append(parsed)
        return DiscoveryDetail(
            discovery=_discovery_from_row(row),
            initialize_result=initialized,
            tools=tuple(tools),
        )

    def tool_detail(self, alias: str, tool_name: str) -> ToolDetail | None:
        """Return the current pointer and last exact definition/evidence for one tool."""

        _validate_alias(alias)
        _validate_tool_name(tool_name)
        current = next(
            (
                item
                for item in self.current_tools(alias, include_removed=True)
                if item.tool_name == tool_name
            ),
            None,
        )
        if current is None:
            return None
        with self.database.read() as connection:
            definition_row = connection.execute(
                """
                SELECT tool.run_id, tool.canonical_tool
                FROM connector_discovered_tools AS tool
                JOIN connector_discovery_runs AS run ON run.run_id = tool.run_id
                WHERE run.alias = ? AND tool.tool_name = ? AND tool.schema_digest = ?
                  AND run.discovered_at <= ?
                ORDER BY run.discovered_at DESC, run.run_id DESC LIMIT 1
                """,
                (alias, tool_name, current.schema_digest, current.discovered_at),
            ).fetchone()
            evidence_rows = []
            if definition_row is not None:
                evidence_rows = connection.execute(
                    """
                    SELECT canonical_evidence FROM connector_effect_evidence
                    WHERE run_id = ? AND tool_name = ? AND schema_digest = ?
                    ORDER BY source LIMIT 4
                    """,
                    (definition_row["run_id"], tool_name, current.schema_digest),
                ).fetchall()
        definition: dict[str, Any] | None = None
        definition_run_id: str | None = None
        if definition_row is not None:
            parsed_definition = _strict_json(bytes(definition_row["canonical_tool"]))
            if not isinstance(parsed_definition, dict):
                raise IntegrationStoreError("stored connector tool is invalid")
            definition = parsed_definition
            definition_run_id = str(definition_row["run_id"])
        evidence: list[dict[str, Any]] = []
        for evidence_row in evidence_rows:
            parsed_evidence = _strict_json(bytes(evidence_row["canonical_evidence"]))
            if not isinstance(parsed_evidence, dict):
                raise IntegrationStoreError("stored connector evidence is invalid")
            evidence.append(parsed_evidence)
        return ToolDetail(
            current=current,
            definition_run_id=definition_run_id,
            definition=definition,
            evidence=tuple(evidence),
            valid_review=self.current_valid_review(alias, tool_name),
        )

    def current_evidence_bundle_digest(self, alias: str, tool_name: str) -> str:
        rows = self._current_evidence_rows(alias, tool_name)
        packet = [_strict_json(bytes(row["canonical_evidence"])) for row in rows]
        if not packet:
            raise IntegrationStoreError("current tool has no effect evidence")
        return sha256_hex(canonical_json(packet))

    def current_review_target(
        self,
        alias: str,
        tool_name: str,
    ) -> EffectReviewTarget | None:
        """Return the exact active target and its complete review snapshot digest."""

        _validate_alias(alias)
        _validate_tool_name(tool_name)
        with self.database.read() as connection:
            return self.current_review_target_in_transaction(
                connection,
                alias=alias,
                tool_name=tool_name,
            )

    def current_review_target_in_transaction(
        self,
        connection: Any,
        *,
        alias: str,
        tool_name: str,
    ) -> EffectReviewTarget | None:
        """Load a target using the caller's transaction for atomic revalidation."""

        _validate_alias(alias)
        _validate_tool_name(tool_name)
        row = connection.execute(_CURRENT_TARGET_SQL, (alias, tool_name)).fetchone()
        if row is None:
            return None
        evidence_rows = connection.execute(
            """
            SELECT canonical_evidence FROM connector_effect_evidence
            WHERE run_id = ? AND tool_name = ? AND schema_digest = ?
            ORDER BY source
            """,
            (row["run_id"], tool_name, row["schema_digest"]),
        ).fetchall()
        packet = [_strict_json(bytes(item["canonical_evidence"])) for item in evidence_rows]
        if not packet:
            raise IntegrationStoreError("current tool has no effect evidence")
        evidence_digest = sha256_hex(canonical_json(packet))
        mapping_material = {
            "action_id": str(row["action_id"]),
            "alias": alias,
            "config_digest": str(row["config_digest"]),
            "connector_id": str(row["connector_id"]),
            "manifest_sha256": str(row["manifest_sha256"]),
            "plugin_id": str(row["plugin_id"]),
            "plugin_version": str(row["plugin_version"]),
            "tool_name": tool_name,
            "version": 1,
        }
        mapping_key = sha256_hex(canonical_json(mapping_material))
        snapshot_material = {
            **mapping_material,
            "evidence_bundle_digest": evidence_digest,
            "run_id": str(row["run_id"]),
            "schema_digest": str(row["schema_digest"]),
            "server_identity_digest": str(row["server_identity_digest"]),
        }
        return EffectReviewTarget(
            plugin=PluginIdentity(
                str(row["plugin_id"]),
                str(row["plugin_version"]),
                str(row["manifest_sha256"]),
            ),
            connector_id=str(row["connector_id"]),
            alias=alias,
            config_digest=str(row["config_digest"]),
            run_id=str(row["run_id"]),
            server_identity_digest=str(row["server_identity_digest"]),
            tool_name=tool_name,
            schema_digest=str(row["schema_digest"]),
            action_id=str(row["action_id"]),
            evidence_bundle_digest=evidence_digest,
            mapping_key=mapping_key,
            snapshot_digest=sha256_hex(canonical_json(snapshot_material)),
        )

    def _append_effect_review_in_transaction(
        self,
        connection: Any,
        *,
        target: EffectReviewTarget,
        profile: EffectProfile,
        actor: str,
        auth_kind: Literal["totp", "webauthn"],
        auth_use_id: str,
        reviewed_at: int,
    ) -> int:
        """Append inside the proof consumer's transaction; never call from UI/CLI code."""

        if (
            not actor
            or len(actor.encode("utf-8")) > 256
            or auth_kind not in {"totp", "webauthn"}
            or not auth_use_id
            or len(auth_use_id.encode("utf-8")) > 256
            or not _timestamp(reviewed_at)
        ):
            raise ValueError("effect review identity is invalid")
        recommendation = recommend_policy(profile)
        cursor = connection.execute(
            """
            INSERT INTO connector_effect_reviews(
                plugin_id, plugin_version, manifest_sha256, connector_id,
                alias, config_digest, run_id, server_identity_digest,
                tool_name, schema_digest, action_id, mutation,
                external_communication, code_execution, privilege_change,
                open_world, idempotent, recommended_mode,
                evidence_bundle_digest, actor, auth_kind, auth_use_id, reviewed_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                *_plugin_tuple(target.plugin),
                target.connector_id,
                target.alias,
                target.config_digest,
                target.run_id,
                target.server_identity_digest,
                target.tool_name,
                target.schema_digest,
                target.action_id,
                profile.mutation.value,
                profile.external_communication.value,
                profile.code_execution.value,
                profile.privilege_change.value,
                profile.open_world.value,
                profile.idempotent.value,
                recommendation.value,
                target.evidence_bundle_digest,
                actor,
                auth_kind,
                auth_use_id,
                reviewed_at,
            ),
        )
        return int(cursor.lastrowid)

    def review_by_id(self, review_id: int) -> EffectReviewRecord | None:
        if not isinstance(review_id, int) or isinstance(review_id, bool) or review_id < 1:
            return None
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM connector_effect_reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
        return _review_from_row(row) if row is not None else None

    def current_valid_review(self, alias: str, tool_name: str) -> EffectReviewRecord | None:
        _validate_alias(alias)
        _validate_tool_name(tool_name)
        with self.database.read() as connection:
            row = connection.execute(
                _CURRENT_REVIEW_SQL,
                (alias, tool_name),
            ).fetchone()
        return _review_from_row(row) if row is not None else None

    def list_effect_reviews(
        self,
        alias: str,
        tool_name: str,
        *,
        limit: int = 100,
    ) -> tuple[EffectReviewRecord, ...]:
        """Return bounded append-only review history, newest first."""

        _validate_alias(alias)
        _validate_tool_name(tool_name)
        _validate_limit(limit, maximum=1000)
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM connector_effect_reviews
                WHERE alias = ? AND tool_name = ?
                ORDER BY review_id DESC LIMIT ?
                """,
                (alias, tool_name, limit),
            ).fetchall()
        return tuple(_review_from_row(row) for row in rows)

    def _current_evidence_rows(self, alias: str, tool_name: str) -> list[Any]:
        _validate_alias(alias)
        _validate_tool_name(tool_name)
        with self.database.read() as connection:
            target = connection.execute(_CURRENT_TARGET_SQL, (alias, tool_name)).fetchone()
            if target is None:
                return []
            return cast(
                list[Any],
                connection.execute(
                    """
                    SELECT canonical_evidence FROM connector_effect_evidence
                    WHERE run_id = ? AND tool_name = ? AND schema_digest = ?
                    ORDER BY source
                    """,
                    (target["run_id"], tool_name, target["schema_digest"]),
                ).fetchall(),
            )


_CURRENT_TARGET_SQL = """
    SELECT config.plugin_id, config.plugin_version, config.manifest_sha256,
           config.connector_id, config.config_digest, state.run_id,
           state.schema_digest, run.server_identity_digest, mapping.action_id
    FROM connector_active AS active
    JOIN connector_configurations AS config
      ON config.alias = active.alias AND config.config_digest = active.config_digest
    JOIN plugin_active AS plugin
      ON plugin.plugin_id = config.plugin_id
     AND plugin.plugin_version = config.plugin_version
     AND plugin.manifest_sha256 = config.manifest_sha256
    JOIN connector_tool_state AS state
      ON state.alias = active.alias AND state.present = 1
    JOIN connector_discovery_runs AS run
      ON run.run_id = state.run_id AND run.alias = active.alias
     AND run.config_digest = active.config_digest AND run.status = 'succeeded'
    JOIN plugin_tool_mappings AS mapping
      ON mapping.plugin_id = config.plugin_id
     AND mapping.plugin_version = config.plugin_version
     AND mapping.manifest_sha256 = config.manifest_sha256
     AND mapping.connector_id = config.connector_id
     AND mapping.tool_name = state.tool_name
    WHERE active.alias = ? AND state.tool_name = ?
      AND active.disabled_at IS NULL AND plugin.disabled_at IS NULL
"""

_CURRENT_REVIEW_SQL = """
    SELECT review.*
    FROM connector_effect_reviews AS review
    JOIN plugin_active AS plugin
      ON plugin.plugin_id = review.plugin_id
     AND plugin.plugin_version = review.plugin_version
     AND plugin.manifest_sha256 = review.manifest_sha256
    JOIN connector_active AS active
      ON active.alias = review.alias AND active.config_digest = review.config_digest
    JOIN connector_configurations AS config
      ON config.alias = active.alias AND config.config_digest = active.config_digest
     AND config.plugin_id = review.plugin_id
     AND config.plugin_version = review.plugin_version
     AND config.manifest_sha256 = review.manifest_sha256
     AND config.connector_id = review.connector_id
    JOIN connector_tool_state AS state
      ON state.alias = review.alias AND state.tool_name = review.tool_name
     AND state.present = 1 AND state.schema_digest = review.schema_digest
    JOIN connector_discovery_runs AS run
      ON run.run_id = state.run_id AND run.alias = review.alias
     AND run.config_digest = review.config_digest AND run.status = 'succeeded'
     AND run.server_identity_digest = review.server_identity_digest
    JOIN plugin_tool_mappings AS mapping
      ON mapping.plugin_id = review.plugin_id
     AND mapping.plugin_version = review.plugin_version
     AND mapping.manifest_sha256 = review.manifest_sha256
     AND mapping.connector_id = review.connector_id
     AND mapping.tool_name = review.tool_name
     AND mapping.action_id = review.action_id
    WHERE review.alias = ? AND review.tool_name = ?
      AND active.disabled_at IS NULL AND plugin.disabled_at IS NULL
      AND NOT EXISTS (
          SELECT old.source, old.evidence_digest
          FROM connector_effect_evidence AS old
          WHERE old.run_id = review.run_id
            AND old.tool_name = review.tool_name
            AND old.schema_digest = review.schema_digest
          EXCEPT
          SELECT current.source, current.evidence_digest
          FROM connector_effect_evidence AS current
          WHERE current.run_id = state.run_id
            AND current.tool_name = state.tool_name
            AND current.schema_digest = state.schema_digest
      )
      AND NOT EXISTS (
          SELECT current.source, current.evidence_digest
          FROM connector_effect_evidence AS current
          WHERE current.run_id = state.run_id
            AND current.tool_name = state.tool_name
            AND current.schema_digest = state.schema_digest
          EXCEPT
          SELECT old.source, old.evidence_digest
          FROM connector_effect_evidence AS old
          WHERE old.run_id = review.run_id
            AND old.tool_name = review.tool_name
            AND old.schema_digest = review.schema_digest
      )
    ORDER BY review.review_id DESC LIMIT 1
"""


def _manifest_profile(value: Mapping[str, Any]) -> EffectProfile:
    def tri(selected: object) -> TriState:
        if selected is True:
            return TriState.TRUE
        if selected is False:
            return TriState.FALSE
        if selected == "unknown":
            return TriState.UNKNOWN
        raise IntegrationStoreError("plugin proposed effect contains an invalid tri-state")

    try:
        mutation = MutationEffect(str(value["mutation"]))
        return EffectProfile(
            mutation=mutation,
            external_communication=tri(value["external_communication"]),
            code_execution=tri(value["code_execution"]),
            privilege_change=tri(value["privilege_change"]),
            open_world=tri(value["open_world"]),
            idempotent=tri(value["idempotent"]),
        )
    except (KeyError, TypeError, ValueError):
        raise IntegrationStoreError("plugin proposed effect is incomplete") from None


def _mapping_from_row(row: Any) -> ToolMappingRecord:
    raw = _strict_json(bytes(row["proposed_effect_json"]))
    if not isinstance(raw, dict):
        raise IntegrationStoreError("stored plugin effect proposal is invalid")
    return ToolMappingRecord(
        connector_id=str(row["connector_id"]),
        tool_name=str(row["tool_name"]),
        action_id=str(row["action_id"]),
        display_label=str(row["display_label"]),
        proposed_effect=EffectProfile.from_mapping(raw),
    )


def _plugin_record_from_row(row: Any) -> PluginRecord:
    return PluginRecord(
        plugin=PluginIdentity(
            str(row["plugin_id"]),
            str(row["plugin_version"]),
            str(row["manifest_sha256"]),
        ),
        installed_at=int(row["installed_at"]),
        disabled_at=(int(row["disabled_at"]) if row["disabled_at"] is not None else None),
    )


def _discovery_from_row(row: Any) -> DiscoveryRecord:
    return DiscoveryRecord(
        run_id=str(row["run_id"]),
        alias=str(row["alias"]),
        config_digest=str(row["config_digest"]),
        source=cast(Literal["fixture", "live"], str(row["source"])),
        server_identity_digest=(
            str(row["server_identity_digest"])
            if row["server_identity_digest"] is not None
            else None
        ),
        status=cast(Literal["succeeded", "failed"], str(row["status"])),
        tool_count=int(row["tool_count"]),
        discovered_at=int(row["discovered_at"]),
        error_code=(str(row["error_code"]) if row["error_code"] is not None else None),
    )


def _connector_from_row(row: Any) -> ConnectorRecord:
    row_keys = tuple(row.keys())
    return ConnectorRecord(
        alias=str(row["alias"]),
        config_digest=str(row["config_digest"]),
        plugin=PluginIdentity(
            str(row["plugin_id"]),
            str(row["plugin_version"]),
            str(row["manifest_sha256"]),
        ),
        connector_id=str(row["connector_id"]),
        credential_ref=(str(row["credential_ref"]) if row["credential_ref"] is not None else None),
        credential_identity_digest=(
            str(row["credential_identity_digest"])
            if row["credential_identity_digest"] is not None
            else None
        ),
        configured_at=int(row["configured_at"]),
        disabled_at=(int(row["disabled_at"]) if row["disabled_at"] is not None else None),
        plugin_current=(bool(row["plugin_current"]) if "plugin_current" in row_keys else True),
    )


def _review_from_row(row: Any) -> EffectReviewRecord:
    profile = EffectProfile(
        mutation=MutationEffect(str(row["mutation"])),
        external_communication=TriState(str(row["external_communication"])),
        code_execution=TriState(str(row["code_execution"])),
        privilege_change=TriState(str(row["privilege_change"])),
        open_world=TriState(str(row["open_world"])),
        idempotent=TriState(str(row["idempotent"])),
    )
    return EffectReviewRecord(
        review_id=int(row["review_id"]),
        plugin=PluginIdentity(
            str(row["plugin_id"]),
            str(row["plugin_version"]),
            str(row["manifest_sha256"]),
        ),
        connector_id=str(row["connector_id"]),
        alias=str(row["alias"]),
        config_digest=str(row["config_digest"]),
        run_id=str(row["run_id"]),
        server_identity_digest=str(row["server_identity_digest"]),
        tool_name=str(row["tool_name"]),
        schema_digest=str(row["schema_digest"]),
        action_id=str(row["action_id"]),
        profile=profile,
        recommended_mode=RecommendedMode(str(row["recommended_mode"])),
        evidence_bundle_digest=str(row["evidence_bundle_digest"]),
        actor=str(row["actor"]),
        auth_kind=cast(Literal["totp", "webauthn"], str(row["auth_kind"])),
        auth_use_id=str(row["auth_use_id"]),
        reviewed_at=int(row["reviewed_at"]),
    )


def _plugin_tuple(identity: PluginIdentity) -> tuple[str, str, str]:
    return identity.plugin_id, identity.plugin_version, identity.manifest_sha256


def _validate_alias(alias: str) -> None:
    if not isinstance(alias, str) or _ALIAS_RE.fullmatch(alias) is None:
        raise ValueError("connector alias is invalid")


def _validate_tool_name(name: str) -> None:
    if (
        not isinstance(name, str)
        or not name
        or len(name.encode("utf-8")) > 256
        or name.startswith(".")
        or any(marker in name for marker in ("*", "/", "\\"))
    ):
        raise IntegrationStoreError("tool name is not an exact safe identifier")


def _validate_run_id(run_id: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9_-]{16,128}", run_id) is None:
        raise ValueError("discovery run identifier is invalid")


def _require_current_connector_generation(
    connection: sqlite3.Connection,
    *,
    alias: str,
    expected_config_digest: str,
) -> None:
    row = connection.execute(
        """
        SELECT config.config_digest
        FROM connector_active AS active
        JOIN connector_configurations AS config
          ON config.alias = active.alias AND config.config_digest = active.config_digest
        JOIN plugin_active AS plugin
          ON plugin.plugin_id = config.plugin_id
         AND plugin.plugin_version = config.plugin_version
         AND plugin.manifest_sha256 = config.manifest_sha256
        WHERE active.alias = ? AND active.disabled_at IS NULL
          AND plugin.disabled_at IS NULL
        """,
        (alias,),
    ).fetchone()
    if row is None or not hmac.compare_digest(str(row[0]), expected_config_digest):
        raise ConnectorGenerationChangedError("connector changed during discovery")


def _validate_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _validate_limit(value: int, *, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > maximum:
        raise ValueError("read limit is invalid")


def _validate_credential_pair(reference: str | None, identity: str | None) -> None:
    if (reference is None) != (identity is None):
        raise ValueError("credential reference and generation digest must be provided together")
    if reference is not None and (
        not reference.startswith("keychain://")
        or len(reference.encode("utf-8")) > 512
        or any(character in reference for character in "\x00\r\n")
    ):
        raise ValueError("connector credentials must use a bounded Keychain reference")
    if identity is not None:
        _validate_digest(identity, "credential generation digest")


def _reject_credentials(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 50_000 or depth > 32:
            raise IntegrationStoreError("connector configuration exceeds structural limits")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise IntegrationStoreError("connector configuration contains an invalid key")
                if _SENSITIVE_KEY_RE.search(key):
                    raise IntegrationStoreError(
                        "connector configuration contains credential material"
                    )
                visit(child, depth + 1)
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str) and (
            len(item.encode("utf-8")) > 64 * 1024 or _CREDENTIAL_TEXT_RE.search(item)
        ):
            raise IntegrationStoreError("connector configuration contains credential material")

    visit(value, 0)


def _strict_json(value: bytes) -> Any:
    try:
        return json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationStoreError("stored integration JSON is invalid") from None


def _timestamp(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
