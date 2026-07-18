ALTER TABLE auth_credentials
    ADD COLUMN discoverable INTEGER NOT NULL DEFAULT 0
    CHECK (discoverable IN (0, 1));

ALTER TABLE auth_credentials
    ADD COLUMN transports_json TEXT NOT NULL DEFAULT '[]'
    CHECK (
        length(transports_json) <= 512 AND
        json_valid(transports_json) AND
        json_type(transports_json) = 'array'
    );

CREATE TABLE auth_factors (
    factor_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(factor_id) BETWEEN 20 AND 64 AND substr(factor_id, 1, 4) = 'fac_'
    ),
    credential_id TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('password', 'totp', 'webauthn')),
    label TEXT NOT NULL CHECK (
        length(label) BETWEEN 1 AND 64 AND label = trim(label)
    ),
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked', 'compromised')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    last_used_at INTEGER CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    compromised_at INTEGER CHECK (compromised_at IS NULL OR compromised_at >= created_at),
    created_audit_ref TEXT NOT NULL CHECK (length(created_audit_ref) BETWEEN 1 AND 128),
    state_audit_ref TEXT CHECK (state_audit_ref IS NULL OR length(state_audit_ref) BETWEEN 1 AND 128),
    FOREIGN KEY (credential_id) REFERENCES auth_credentials(credential_id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE RESTRICT,
    CHECK (
        (state = 'active' AND revoked_at IS NULL AND compromised_at IS NULL) OR
        (state = 'revoked' AND revoked_at IS NOT NULL AND compromised_at IS NULL) OR
        (state = 'compromised' AND revoked_at IS NOT NULL AND compromised_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX auth_factors_active_label
    ON auth_factors(user_id, kind, label) WHERE state = 'active';
CREATE INDEX auth_factors_user_state
    ON auth_factors(user_id, state, kind, factor_id);

INSERT INTO auth_factors(
    factor_id, credential_id, user_id, kind, label, state,
    created_at, updated_at, last_used_at, revoked_at, compromised_at,
    created_audit_ref, state_audit_ref
)
SELECT
    'fac_' || lower(hex(randomblob(18))),
    credential_id,
    user_id,
    kind,
    factor_label,
    CASE WHEN disabled_at IS NULL THEN 'active' ELSE 'revoked' END,
    enrolled_at,
    max(enrolled_at, coalesce(disabled_at, enrolled_at), coalesce(last_used_at, enrolled_at)),
    last_used_at,
    disabled_at,
    NULL,
    'migration:17:' || credential_id,
    CASE WHEN disabled_at IS NULL THEN NULL ELSE 'migration:17:' || credential_id END
FROM auth_credentials;

CREATE TABLE auth_factor_events (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id) BETWEEN 16 AND 128),
    factor_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('migrated', 'added', 'renamed', 'revoked', 'compromised', 'recovered', 'replaced')
    ),
    actor_factor_id TEXT,
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    payload_hash TEXT NOT NULL CHECK (
        length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    details_json TEXT NOT NULL CHECK (
        length(details_json) BETWEEN 2 AND 2048 AND json_valid(details_json)
        AND json_type(details_json) = 'object'
    ),
    FOREIGN KEY (factor_id) REFERENCES auth_factors(factor_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_factor_id) REFERENCES auth_factors(factor_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX auth_factor_events_user_time
    ON auth_factor_events(user_id, created_at, event_id);

INSERT INTO auth_factor_events(
    event_id, factor_id, user_id, action, actor_factor_id,
    operation_id, payload_hash, created_at, details_json
)
SELECT
    created_audit_ref,
    factor_id,
    user_id,
    'migrated',
    NULL,
    'schema-17-migration',
    lower(hex(zeroblob(32))),
    created_at,
    json_object('kind', kind, 'state', state)
FROM auth_factors;

CREATE TABLE auth_factor_challenges (
    challenge_id TEXT PRIMARY KEY NOT NULL CHECK (length(challenge_id) BETWEEN 16 AND 128),
    challenge BLOB NOT NULL CHECK (length(challenge) = 32),
    user_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN (
            'add_authenticator', 'rename_authenticator', 'revoke_authenticator',
            'replace_authenticator'
        )
    ),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    version INTEGER NOT NULL CHECK (version = 1),
    payload_hash TEXT NOT NULL CHECK (
        length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL,
    http_method TEXT NOT NULL CHECK (http_method = 'POST'),
    expected_rp_id TEXT NOT NULL CHECK (length(expected_rp_id) BETWEEN 1 AND 253),
    expected_origin TEXT NOT NULL CHECK (length(expected_origin) BETWEEN 9 AND 2048),
    offered_credential_ids_json TEXT NOT NULL CHECK (
        length(offered_credential_ids_json) BETWEEN 2 AND 65536
        AND json_valid(offered_credential_ids_json)
        AND json_type(offered_credential_ids_json) = 'array'
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at INTEGER,
    invalidated_at INTEGER,
    FOREIGN KEY (session_id) REFERENCES web_sessions(session_id) ON DELETE RESTRICT,
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (invalidated_at IS NULL OR invalidated_at >= created_at),
    CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
) STRICT;

CREATE INDEX auth_factor_challenges_active_user
    ON auth_factor_challenges(user_id, expires_at)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;
