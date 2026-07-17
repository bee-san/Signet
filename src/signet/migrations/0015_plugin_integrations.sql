CREATE TABLE plugin_manifests (
    plugin_id TEXT NOT NULL CHECK (
        length(plugin_id) BETWEEN 1 AND 128 AND
        plugin_id GLOB '[a-z]*' AND
        plugin_id NOT GLOB '*[^a-z0-9.-]*' AND
        plugin_id NOT LIKE '%..%'
    ),
    plugin_version TEXT NOT NULL CHECK (
        length(plugin_version) BETWEEN 1 AND 64 AND
        plugin_version NOT GLOB '*[^A-Za-z0-9._+-]*'
    ),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64 AND
        manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_manifest BLOB NOT NULL CHECK (
        length(canonical_manifest) BETWEEN 2 AND 524288
    ),
    installed_at INTEGER NOT NULL CHECK (installed_at >= 0),
    PRIMARY KEY (plugin_id, plugin_version, manifest_sha256)
) STRICT;

CREATE TRIGGER plugin_manifests_no_update
BEFORE UPDATE ON plugin_manifests
BEGIN
    SELECT RAISE(ABORT, 'plugin manifests are immutable');
END;

CREATE TRIGGER plugin_manifests_no_delete
BEFORE DELETE ON plugin_manifests
BEGIN
    SELECT RAISE(ABORT, 'plugin manifests are retained');
END;

CREATE TABLE plugin_active (
    plugin_id TEXT PRIMARY KEY,
    plugin_version TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    activated_at INTEGER NOT NULL CHECK (activated_at >= 0),
    disabled_at INTEGER CHECK (disabled_at IS NULL OR disabled_at >= activated_at),
    FOREIGN KEY (plugin_id, plugin_version, manifest_sha256)
        REFERENCES plugin_manifests(plugin_id, plugin_version, manifest_sha256)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE plugin_tool_mappings (
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    connector_id TEXT NOT NULL CHECK (
        length(connector_id) BETWEEN 1 AND 128 AND
        connector_id GLOB '[a-z]*' AND
        connector_id NOT GLOB '*[^a-z0-9._-]*' AND
        connector_id NOT LIKE '%..%'
    ),
    tool_name TEXT NOT NULL CHECK (
        length(tool_name) BETWEEN 1 AND 256 AND
        tool_name NOT GLOB '*[*/\\]*' AND
        tool_name NOT LIKE '.%'
    ),
    action_id TEXT NOT NULL CHECK (
        length(action_id) BETWEEN 1 AND 128 AND
        action_id GLOB '[a-z]*' AND
        action_id NOT GLOB '*[^a-z0-9._:-]*'
    ),
    display_label TEXT NOT NULL CHECK (length(display_label) BETWEEN 1 AND 256),
    proposed_effect_json BLOB NOT NULL CHECK (
        length(proposed_effect_json) BETWEEN 2 AND 1048576
    ),
    proposed_effect_sha256 TEXT NOT NULL CHECK (
        length(proposed_effect_sha256) = 64 AND
        proposed_effect_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (
        plugin_id, plugin_version, manifest_sha256, connector_id, tool_name
    ),
    UNIQUE (
        plugin_id, plugin_version, manifest_sha256, connector_id, tool_name, action_id
    ),
    FOREIGN KEY (plugin_id, plugin_version, manifest_sha256)
        REFERENCES plugin_manifests(plugin_id, plugin_version, manifest_sha256)
        ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER plugin_tool_mappings_no_update
BEFORE UPDATE ON plugin_tool_mappings
BEGIN
    SELECT RAISE(ABORT, 'plugin tool mappings are immutable');
END;

CREATE TRIGGER plugin_tool_mappings_no_delete
BEFORE DELETE ON plugin_tool_mappings
BEGIN
    SELECT RAISE(ABORT, 'plugin tool mappings are retained');
END;

CREATE TABLE connector_configurations (
    alias TEXT NOT NULL CHECK (
        length(alias) BETWEEN 1 AND 64 AND
        alias GLOB '[a-z]*' AND
        alias NOT GLOB '*[^a-z0-9_-]*'
    ),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND
        config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    connector_id TEXT NOT NULL CHECK (
        length(connector_id) BETWEEN 1 AND 128 AND
        connector_id GLOB '[a-z]*' AND
        connector_id NOT GLOB '*[^a-z0-9._-]*' AND
        connector_id NOT LIKE '%..%'
    ),
    canonical_config BLOB NOT NULL CHECK (
        length(canonical_config) BETWEEN 2 AND 1048576
    ),
    credential_ref TEXT CHECK (
        credential_ref IS NULL OR (
            length(credential_ref) BETWEEN 12 AND 512 AND
            substr(credential_ref, 1, 11) = 'keychain://'
        )
    ),
    credential_identity_digest TEXT CHECK (
        credential_identity_digest IS NULL OR (
            length(credential_identity_digest) = 64 AND
            credential_identity_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    configured_at INTEGER NOT NULL CHECK (configured_at >= 0),
    PRIMARY KEY (alias, config_digest),
    UNIQUE (
        alias, config_digest, plugin_id, plugin_version, manifest_sha256, connector_id
    ),
    FOREIGN KEY (plugin_id, plugin_version, manifest_sha256)
        REFERENCES plugin_manifests(plugin_id, plugin_version, manifest_sha256)
        ON DELETE RESTRICT,
    CHECK ((credential_ref IS NULL) = (credential_identity_digest IS NULL))
) STRICT;

CREATE TRIGGER connector_configurations_no_update
BEFORE UPDATE ON connector_configurations
BEGIN
    SELECT RAISE(ABORT, 'connector configurations are immutable');
END;

CREATE TRIGGER connector_configurations_no_delete
BEFORE DELETE ON connector_configurations
BEGIN
    SELECT RAISE(ABORT, 'connector configurations are retained');
END;

CREATE TABLE connector_active (
    alias TEXT PRIMARY KEY,
    config_digest TEXT NOT NULL,
    activated_at INTEGER NOT NULL CHECK (activated_at >= 0),
    disabled_at INTEGER CHECK (disabled_at IS NULL OR disabled_at >= activated_at),
    FOREIGN KEY (alias, config_digest)
        REFERENCES connector_configurations(alias, config_digest)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE connector_discovery_runs (
    run_id TEXT PRIMARY KEY CHECK (
        length(run_id) BETWEEN 16 AND 128 AND
        run_id NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    alias TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('fixture', 'live')),
    server_identity_digest TEXT CHECK (
        server_identity_digest IS NULL OR (
            length(server_identity_digest) = 64 AND
            server_identity_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    canonical_initialize_result BLOB,
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    error_code TEXT CHECK (
        error_code IS NULL OR (
            length(error_code) BETWEEN 1 AND 64 AND
            error_code NOT GLOB '*[^a-z0-9_:-]*'
        )
    ),
    tool_count INTEGER NOT NULL CHECK (tool_count BETWEEN 0 AND 10000),
    discovered_at INTEGER NOT NULL CHECK (discovered_at >= 0),
    UNIQUE (run_id, alias, config_digest, server_identity_digest),
    FOREIGN KEY (alias, config_digest)
        REFERENCES connector_configurations(alias, config_digest)
        ON DELETE RESTRICT,
    CHECK (
        (status = 'succeeded' AND server_identity_digest IS NOT NULL AND
         canonical_initialize_result IS NOT NULL AND error_code IS NULL) OR
        (status = 'failed' AND server_identity_digest IS NULL AND
         canonical_initialize_result IS NULL AND error_code IS NOT NULL AND tool_count = 0)
    )
) STRICT;

CREATE INDEX connector_discovery_runs_alias_idx
    ON connector_discovery_runs(alias, discovered_at DESC, run_id DESC);

CREATE TRIGGER connector_discovery_runs_no_update
BEFORE UPDATE ON connector_discovery_runs
BEGIN
    SELECT RAISE(ABORT, 'connector discovery runs are immutable');
END;

CREATE TRIGGER connector_discovery_runs_no_delete
BEFORE DELETE ON connector_discovery_runs
BEGIN
    SELECT RAISE(ABORT, 'connector discovery runs are retained');
END;

CREATE TABLE connector_discovered_tools (
    run_id TEXT NOT NULL,
    tool_name TEXT NOT NULL CHECK (
        length(tool_name) BETWEEN 1 AND 256 AND
        tool_name NOT GLOB '*[*/\\]*' AND
        tool_name NOT LIKE '.%'
    ),
    schema_digest TEXT NOT NULL CHECK (
        length(schema_digest) = 64 AND
        schema_digest NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_tool BLOB NOT NULL CHECK (length(canonical_tool) BETWEEN 2 AND 1048576),
    PRIMARY KEY (run_id, tool_name),
    UNIQUE (run_id, tool_name, schema_digest),
    FOREIGN KEY (run_id) REFERENCES connector_discovery_runs(run_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER connector_discovered_tools_no_update
BEFORE UPDATE ON connector_discovered_tools
BEGIN
    SELECT RAISE(ABORT, 'discovered tools are immutable');
END;

CREATE TRIGGER connector_discovered_tools_no_delete
BEFORE DELETE ON connector_discovered_tools
BEGIN
    SELECT RAISE(ABORT, 'discovered tools are retained');
END;

CREATE TABLE connector_tool_state (
    alias TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    run_id TEXT NOT NULL,
    schema_digest TEXT NOT NULL CHECK (
        length(schema_digest) = 64 AND
        schema_digest NOT GLOB '*[^0-9a-f]*'
    ),
    present INTEGER NOT NULL CHECK (present IN (0, 1)),
    discovered_at INTEGER NOT NULL CHECK (discovered_at >= 0),
    PRIMARY KEY (alias, tool_name),
    FOREIGN KEY (run_id) REFERENCES connector_discovery_runs(run_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX connector_tool_state_present_idx
    ON connector_tool_state(alias, present, tool_name);

CREATE TABLE connector_effect_evidence (
    evidence_id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    schema_digest TEXT NOT NULL,
    source TEXT NOT NULL CHECK (
        source IN ('mcp_annotations', 'name_schema_heuristic', 'plugin_proposal')
    ),
    canonical_evidence BLOB NOT NULL CHECK (
        length(canonical_evidence) BETWEEN 2 AND 1048576
    ),
    evidence_digest TEXT NOT NULL CHECK (
        length(evidence_digest) = 64 AND
        evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (run_id, tool_name, source),
    FOREIGN KEY (run_id, tool_name, schema_digest)
        REFERENCES connector_discovered_tools(run_id, tool_name, schema_digest)
        ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER connector_effect_evidence_no_update
BEFORE UPDATE ON connector_effect_evidence
BEGIN
    SELECT RAISE(ABORT, 'effect evidence is immutable');
END;

CREATE TRIGGER connector_effect_evidence_no_delete
BEFORE DELETE ON connector_effect_evidence
BEGIN
    SELECT RAISE(ABORT, 'effect evidence is retained');
END;

CREATE TABLE connector_effect_review_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) BETWEEN 16 AND 128),
    challenge BLOB NOT NULL CHECK (length(challenge) = 32),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    effect_mapping_key TEXT NOT NULL CHECK (
        length(effect_mapping_key) = 64 AND
        effect_mapping_key NOT GLOB '*[^0-9a-f]*'
    ),
    effect_review_digest TEXT NOT NULL CHECK (
        length(effect_review_digest) = 64 AND
        effect_review_digest NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 16 AND 128),
    http_method TEXT NOT NULL CHECK (http_method = 'POST'),
    offered_credential_ids_json TEXT NOT NULL CHECK (
        length(offered_credential_ids_json) BETWEEN 4 AND 16384 AND
        json_valid(offered_credential_ids_json) AND
        json_type(offered_credential_ids_json) = 'array' AND
        json_array_length(offered_credential_ids_json) BETWEEN 1 AND 32
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at INTEGER,
    invalidated_at INTEGER,
    CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
) STRICT;

CREATE INDEX connector_effect_review_challenges_active_idx
    ON connector_effect_review_challenges(
        user_id, consumed_at, invalidated_at, expires_at
    );

CREATE TABLE connector_effect_review_drafts (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) BETWEEN 16 AND 128),
    opaque_id TEXT NOT NULL CHECK (
        length(opaque_id) BETWEEN 16 AND 128 AND
        opaque_id NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    alias TEXT NOT NULL CHECK (
        length(alias) BETWEEN 1 AND 64 AND
        alias GLOB '[a-z]*' AND
        alias NOT GLOB '*[^a-z0-9_-]*'
    ),
    tool_name TEXT NOT NULL CHECK (
        length(tool_name) BETWEEN 1 AND 256 AND
        tool_name NOT GLOB '*[*/\\]*' AND
        tool_name NOT LIKE '.%'
    ),
    target_snapshot_digest TEXT NOT NULL CHECK (
        length(target_snapshot_digest) = 64 AND
        target_snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    effect_mapping_key TEXT NOT NULL CHECK (
        length(effect_mapping_key) = 64 AND
        effect_mapping_key NOT GLOB '*[^0-9a-f]*'
    ),
    effect_review_digest TEXT NOT NULL CHECK (
        length(effect_review_digest) = 64 AND
        effect_review_digest NOT GLOB '*[^0-9a-f]*'
    ),
    mutation TEXT NOT NULL CHECK (
        mutation IN ('none', 'additive', 'mutating', 'destructive', 'unknown')
    ),
    external_communication TEXT NOT NULL CHECK (
        external_communication IN ('true', 'false', 'unknown')
    ),
    code_execution TEXT NOT NULL CHECK (
        code_execution IN ('true', 'false', 'unknown')
    ),
    privilege_change TEXT NOT NULL CHECK (
        privilege_change IN ('true', 'false', 'unknown')
    ),
    open_world TEXT NOT NULL CHECK (open_world IN ('true', 'false', 'unknown')),
    idempotent TEXT NOT NULL CHECK (idempotent IN ('true', 'false', 'unknown')),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 16 AND 128),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    FOREIGN KEY (challenge_id)
        REFERENCES connector_effect_review_challenges(challenge_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX connector_effect_review_drafts_expiry_idx
    ON connector_effect_review_drafts(expires_at, challenge_id);

CREATE TRIGGER connector_effect_review_drafts_no_update
BEFORE UPDATE ON connector_effect_review_drafts
BEGIN
    SELECT RAISE(ABORT, 'effect review drafts are immutable');
END;

CREATE TABLE connector_effect_reviews (
    review_id INTEGER PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    server_identity_digest TEXT NOT NULL CHECK (
        length(server_identity_digest) = 64 AND
        server_identity_digest NOT GLOB '*[^0-9a-f]*'
    ),
    tool_name TEXT NOT NULL,
    schema_digest TEXT NOT NULL,
    action_id TEXT NOT NULL,
    mutation TEXT NOT NULL CHECK (
        mutation IN ('none', 'additive', 'mutating', 'destructive', 'unknown')
    ),
    external_communication TEXT NOT NULL CHECK (
        external_communication IN ('true', 'false', 'unknown')
    ),
    code_execution TEXT NOT NULL CHECK (
        code_execution IN ('true', 'false', 'unknown')
    ),
    privilege_change TEXT NOT NULL CHECK (
        privilege_change IN ('true', 'false', 'unknown')
    ),
    open_world TEXT NOT NULL CHECK (open_world IN ('true', 'false', 'unknown')),
    idempotent TEXT NOT NULL CHECK (idempotent IN ('true', 'false', 'unknown')),
    recommended_mode TEXT NOT NULL CHECK (
        recommended_mode IN ('deny', 'approval', 'passthrough')
    ),
    evidence_bundle_digest TEXT NOT NULL CHECK (
        length(evidence_bundle_digest) = 64 AND
        evidence_bundle_digest NOT GLOB '*[^0-9a-f]*'
    ),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    auth_kind TEXT NOT NULL CHECK (auth_kind IN ('totp', 'webauthn')),
    auth_use_id TEXT NOT NULL CHECK (length(auth_use_id) BETWEEN 1 AND 256),
    reviewed_at INTEGER NOT NULL CHECK (reviewed_at >= 0),
    UNIQUE (auth_kind, auth_use_id),
    FOREIGN KEY (plugin_id, plugin_version, manifest_sha256)
        REFERENCES plugin_manifests(plugin_id, plugin_version, manifest_sha256)
        ON DELETE RESTRICT,
    FOREIGN KEY (
        alias, config_digest, plugin_id, plugin_version, manifest_sha256, connector_id
    ) REFERENCES connector_configurations(
        alias, config_digest, plugin_id, plugin_version, manifest_sha256, connector_id
    )
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, alias, config_digest, server_identity_digest)
        REFERENCES connector_discovery_runs(
            run_id, alias, config_digest, server_identity_digest
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, tool_name, schema_digest)
        REFERENCES connector_discovered_tools(run_id, tool_name, schema_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (
        plugin_id, plugin_version, manifest_sha256, connector_id, tool_name, action_id
    ) REFERENCES plugin_tool_mappings(
        plugin_id, plugin_version, manifest_sha256, connector_id, tool_name, action_id
    ) ON DELETE RESTRICT
) STRICT;

CREATE INDEX connector_effect_reviews_target_idx
    ON connector_effect_reviews(alias, tool_name, review_id DESC);

CREATE TRIGGER connector_effect_reviews_no_update
BEFORE UPDATE ON connector_effect_reviews
BEGIN
    SELECT RAISE(ABORT, 'effect reviews are append-only');
END;

CREATE TRIGGER connector_effect_reviews_no_delete
BEFORE DELETE ON connector_effect_reviews
BEGIN
    SELECT RAISE(ABORT, 'effect reviews are append-only');
END;
