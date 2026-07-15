CREATE TABLE auth_users (
    user_id TEXT PRIMARY KEY CHECK (length(user_id) BETWEEN 1 AND 256),
    auth_generation INTEGER NOT NULL DEFAULT 0 CHECK (auth_generation >= 0),
    created_at INTEGER NOT NULL,
    credentials_changed_at INTEGER
) STRICT;

CREATE TABLE web_sessions (
    session_id TEXT PRIMARY KEY CHECK (length(session_id) BETWEEN 32 AND 128),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    auth_method TEXT NOT NULL CHECK (length(auth_method) BETWEEN 1 AND 64),
    credential_id TEXT CHECK (credential_id IS NULL OR length(credential_id) BETWEEN 1 AND 256),
    auth_generation INTEGER NOT NULL CHECK (auth_generation >= 0),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES auth_users(user_id) ON DELETE RESTRICT,
    CHECK (last_seen_at >= created_at),
    CHECK (absolute_expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

CREATE INDEX web_sessions_user_active_idx
    ON web_sessions(user_id, revoked_at, absolute_expires_at);

CREATE TABLE auth_attempts (
    scope_key TEXT PRIMARY KEY CHECK (length(scope_key) BETWEEN 1 AND 128),
    failures INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    locked_until INTEGER,
    last_attempt_id TEXT NOT NULL CHECK (length(last_attempt_id) BETWEEN 16 AND 128),
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE auth_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) BETWEEN 16 AND 128),
    challenge BLOB NOT NULL CHECK (length(challenge) = 32),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
    request_id TEXT,
    version INTEGER CHECK (version IS NULL OR version > 0),
    current_payload_hash TEXT CHECK (
        current_payload_hash IS NULL OR length(current_payload_hash) = 64
    ),
    prospective_payload_hash TEXT CHECK (
        prospective_payload_hash IS NULL OR length(prospective_payload_hash) = 64
    ),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 16 AND 128),
    http_method TEXT NOT NULL CHECK (http_method IN ('POST')),
    offered_credential_ids_json TEXT NOT NULL CHECK (
        length(offered_credential_ids_json) BETWEEN 4 AND 16384 AND
        json_valid(offered_credential_ids_json) AND
        json_type(offered_credential_ids_json) = 'array' AND
        json_array_length(offered_credential_ids_json) BETWEEN 1 AND 32
    ),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    invalidated_at INTEGER,
    FOREIGN KEY (request_id, version, current_payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash) ON DELETE RESTRICT,
    CHECK (
        (request_id IS NULL AND version IS NULL AND current_payload_hash IS NULL) OR
        (request_id IS NOT NULL AND version IS NOT NULL AND current_payload_hash IS NOT NULL)
    ),
    CHECK (action != 'login' OR request_id IS NULL),
    CHECK (action = 'login' OR request_id IS NOT NULL),
    CHECK (prospective_payload_hash IS NULL OR action = 'edit'),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
) STRICT;

CREATE INDEX auth_challenges_user_active_idx
    ON auth_challenges(user_id, consumed_at, invalidated_at, expires_at);

CREATE INDEX auth_challenges_request_idx
    ON auth_challenges(request_id, version, action);

CREATE TABLE auth_login_consumptions (
    kind TEXT NOT NULL CHECK (kind IN ('totp', 'webauthn')),
    use_id TEXT NOT NULL CHECK (length(use_id) BETWEEN 16 AND 256),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 32 AND 128),
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY (kind, use_id),
    FOREIGN KEY (session_id) REFERENCES web_sessions(session_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE auth_proof_consumptions (
    kind TEXT NOT NULL CHECK (kind IN ('totp', 'webauthn')),
    use_id TEXT NOT NULL CHECK (length(use_id) BETWEEN 1 AND 256),
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'mutation')),
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY (kind, use_id)
) STRICT;

INSERT INTO auth_proof_consumptions(kind, use_id, purpose, consumed_at)
SELECT kind, use_id, 'mutation', consumed_at FROM confirmation_consumptions;

ALTER TABLE auth_credentials ADD COLUMN user_handle BLOB;

CREATE UNIQUE INDEX auth_credentials_one_active_password
    ON auth_credentials(user_id) WHERE kind = 'password' AND disabled_at IS NULL;

CREATE UNIQUE INDEX auth_credentials_one_active_totp
    ON auth_credentials(user_id) WHERE kind = 'totp' AND disabled_at IS NULL;

ALTER TABLE confirmation_consumptions ADD COLUMN action TEXT;
ALTER TABLE confirmation_consumptions ADD COLUMN user_id TEXT;
ALTER TABLE confirmation_consumptions ADD COLUMN session_id TEXT;
ALTER TABLE confirmation_consumptions ADD COLUMN http_method TEXT;
ALTER TABLE confirmation_consumptions ADD COLUMN prospective_payload_hash TEXT;
