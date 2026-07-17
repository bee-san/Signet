DROP INDEX IF EXISTS auth_credentials_one_active_totp;

ALTER TABLE auth_credentials ADD COLUMN factor_label TEXT NOT NULL
    DEFAULT 'Primary factor'
    CHECK (length(factor_label) BETWEEN 1 AND 64 AND factor_label = trim(factor_label));

UPDATE auth_credentials
SET factor_label = kind || ' ' || substr(credential_id, 1, 48);

CREATE UNIQUE INDEX auth_credentials_active_factor_label
    ON auth_credentials(user_id, kind, factor_label)
    WHERE disabled_at IS NULL;

CREATE TABLE production_users (
    user_id TEXT PRIMARY KEY NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    state TEXT NOT NULL CHECK (state IN ('staged', 'active', 'disabled')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

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

CREATE TABLE production_secret_references (
    secret_ref TEXT PRIMARY KEY NOT NULL CHECK (
        length(secret_ref) BETWEEN 12 AND 512 AND
        substr(secret_ref, 1, 11) = 'keychain://'
    ),
    purpose TEXT NOT NULL UNIQUE CHECK (
        length(purpose) BETWEEN 1 AND 64 AND purpose NOT GLOB '*[^a-z0-9_]*'
    ),
    current_generation INTEGER CHECK (current_generation >= 1),
    material_identity_digest TEXT CHECK (
        length(material_identity_digest) = 64 AND
        material_identity_digest NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('required', 'present', 'missing', 'disabled')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    CHECK (
        (state = 'present' AND current_generation IS NOT NULL
            AND material_identity_digest IS NOT NULL) OR
        (state <> 'present' AND current_generation IS NULL
            AND material_identity_digest IS NULL)
    )
) STRICT;

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
