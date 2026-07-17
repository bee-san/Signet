CREATE TABLE production_users (
    user_id TEXT PRIMARY KEY NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    state TEXT NOT NULL CHECK (state IN ('staged', 'active', 'disabled')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE production_user_factors (
    factor_id TEXT PRIMARY KEY NOT NULL CHECK (length(factor_id) BETWEEN 1 AND 128),
    user_id TEXT NOT NULL REFERENCES production_users(user_id) ON DELETE RESTRICT,
    factor_kind TEXT NOT NULL CHECK (factor_kind IN ('password', 'totp', 'webauthn')),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    state TEXT NOT NULL CHECK (state IN ('staged', 'active', 'revoked')),
    credential_ref TEXT CHECK (
        credential_ref IS NULL OR (
            length(credential_ref) BETWEEN 12 AND 512 AND
            substr(credential_ref, 1, 11) = 'keychain://'
        )
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE(user_id, factor_kind, label)
) STRICT;

CREATE INDEX idx_production_user_factors_user_id
    ON production_user_factors(user_id);

CREATE TABLE production_connectors (
    connector_alias TEXT PRIMARY KEY NOT NULL CHECK (
        length(connector_alias) BETWEEN 1 AND 64 AND
        connector_alias GLOB '[a-z]*' AND
        connector_alias NOT GLOB '*[^a-z0-9_-]*'
    ),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    transport TEXT NOT NULL CHECK (transport IN ('http', 'stdio')),
    credential_ref TEXT NOT NULL CHECK (
        length(credential_ref) BETWEEN 12 AND 512 AND
        substr(credential_ref, 1, 11) = 'keychain://'
    ),
    credential_identity_digest TEXT NOT NULL CHECK (
        length(credential_identity_digest) = 64 AND
        credential_identity_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('staged', 'active', 'blocked', 'disabled')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE production_policies (
    policy_name TEXT PRIMARY KEY NOT NULL CHECK (length(policy_name) BETWEEN 1 AND 128),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    policy_digest TEXT NOT NULL CHECK (
        length(policy_digest) = 64 AND policy_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('staged', 'published', 'active', 'retired')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE production_secret_references (
    secret_ref TEXT PRIMARY KEY NOT NULL CHECK (
        length(secret_ref) BETWEEN 12 AND 512 AND
        substr(secret_ref, 1, 11) = 'keychain://'
    ),
    purpose TEXT NOT NULL UNIQUE CHECK (
        length(purpose) BETWEEN 1 AND 64 AND purpose NOT GLOB '*[^a-z0-9_]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('required', 'present', 'missing', 'disabled')),
    current_generation INTEGER NOT NULL CHECK (current_generation >= 1),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE production_secret_generations (
    secret_ref TEXT NOT NULL REFERENCES production_secret_references(secret_ref) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    identity_digest TEXT NOT NULL CHECK (
        length(identity_digest) = 64 AND identity_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('current', 'rotated', 'revoked', 'missing')),
    observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
    PRIMARY KEY (secret_ref, generation)
) STRICT;

CREATE INDEX idx_production_secret_generations_secret_ref
    ON production_secret_generations(secret_ref);

CREATE TABLE production_services (
    service_name TEXT PRIMARY KEY NOT NULL CHECK (length(service_name) BETWEEN 1 AND 128),
    service_kind TEXT NOT NULL CHECK (service_kind IN ('mcp', 'web', 'worker', 'maintenance')),
    host TEXT CHECK (host IS NULL OR length(host) BETWEEN 2 AND 45),
    port INTEGER CHECK (port IS NULL OR port BETWEEN 1024 AND 65535),
    state TEXT NOT NULL CHECK (state IN ('staged', 'ready', 'blocked', 'stopped')),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    CHECK (
        (service_kind IN ('mcp', 'web') AND host IS NOT NULL AND port IS NOT NULL) OR
        (service_kind IN ('worker', 'maintenance') AND host IS NULL AND port IS NULL)
    )
) STRICT;

CREATE TABLE production_setup_state (
    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
    config_version INTEGER NOT NULL CHECK (config_version = 1),
    config_digest TEXT NOT NULL CHECK (
        length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
    ),
    setup_status TEXT NOT NULL CHECK (
        setup_status IN (
            'staged', 'installed', 'ready', 'degraded', 'rollback_pending',
            'restoring', 'removed'
        )
    ),
    capability_status_json TEXT NOT NULL CHECK (
        length(capability_status_json) BETWEEN 2 AND 4096 AND
        json_valid(capability_status_json) AND
        json_type(capability_status_json) = 'object'
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;
