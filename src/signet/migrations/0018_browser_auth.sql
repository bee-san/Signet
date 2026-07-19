CREATE TABLE browser_bootstrap_state (
    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    status TEXT NOT NULL CHECK (status IN ('pending', 'complete')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    completed_at INTEGER,
    CHECK (
        (status = 'pending' AND completed_at IS NULL) OR
        (status = 'complete' AND completed_at IS NOT NULL)
    ),
    CHECK (updated_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
) STRICT;

CREATE TABLE auth_registration_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) BETWEEN 16 AND 128),
    challenge BLOB NOT NULL CHECK (length(challenge) = 32),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    flow TEXT NOT NULL CHECK (flow IN ('bootstrap', 'management')),
    session_id TEXT CHECK (session_id IS NULL OR length(session_id) BETWEEN 16 AND 128),
    factor_label TEXT NOT NULL CHECK (length(factor_label) BETWEEN 1 AND 64),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    verified_at INTEGER,
    consumed_at INTEGER,
    invalidated_at INTEGER,
    credential_id TEXT,
    public_key BLOB,
    sign_count INTEGER CHECK (sign_count IS NULL OR sign_count >= 0),
    device_type TEXT CHECK (device_type IS NULL OR device_type IN ('single_device', 'multi_device')),
    backed_up INTEGER CHECK (backed_up IS NULL OR backed_up IN (0, 1)),
    transports_json TEXT,
    discoverable INTEGER CHECK (discoverable IS NULL OR discoverable IN (0, 1)),
    CHECK (
        (flow = 'bootstrap' AND session_id IS NULL) OR
        (flow = 'management' AND session_id IS NOT NULL)
    ),
    CHECK (expires_at > created_at),
    CHECK (verified_at IS NULL OR verified_at >= created_at),
    CHECK (consumed_at IS NULL OR verified_at IS NOT NULL),
    CHECK (consumed_at IS NULL OR invalidated_at IS NULL),
    CHECK (
        (verified_at IS NULL AND credential_id IS NULL AND public_key IS NULL AND
         sign_count IS NULL AND device_type IS NULL AND backed_up IS NULL AND
         transports_json IS NULL AND discoverable IS NULL) OR
        (verified_at IS NOT NULL AND credential_id IS NOT NULL AND public_key IS NOT NULL AND
         sign_count IS NOT NULL AND device_type IS NOT NULL AND backed_up IS NOT NULL AND
         transports_json IS NOT NULL AND discoverable IS NOT NULL)
    )
) STRICT;

CREATE INDEX auth_registration_challenges_active_idx
    ON auth_registration_challenges(user_id, flow, expires_at)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE browser_totp_enrollments (
    enrollment_id TEXT PRIMARY KEY CHECK (length(enrollment_id) BETWEEN 16 AND 128),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    flow TEXT NOT NULL CHECK (flow IN ('bootstrap', 'management')),
    session_id TEXT CHECK (session_id IS NULL OR length(session_id) BETWEEN 16 AND 128),
    factor_id TEXT NOT NULL UNIQUE CHECK (length(factor_id) BETWEEN 20 AND 64),
    credential_id TEXT NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 20 AND 64),
    factor_label TEXT NOT NULL CHECK (length(factor_label) BETWEEN 1 AND 64),
    secret_reference TEXT NOT NULL UNIQUE CHECK (secret_reference LIKE 'keychain://%'),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    verified_at INTEGER,
    consumed_at INTEGER,
    invalidated_at INTEGER,
    CHECK (
        (flow = 'bootstrap' AND session_id IS NULL) OR
        (flow = 'management' AND session_id IS NOT NULL)
    ),
    CHECK (expires_at > created_at),
    CHECK (verified_at IS NULL OR verified_at >= created_at),
    CHECK (consumed_at IS NULL OR verified_at IS NOT NULL),
    CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
) STRICT;

CREATE INDEX browser_totp_enrollments_active_idx
    ON browser_totp_enrollments(user_id, flow, expires_at)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;
