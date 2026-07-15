CREATE TABLE web_action_drafts (
    challenge_id TEXT PRIMARY KEY CHECK (length(challenge_id) BETWEEN 16 AND 128),
    action TEXT NOT NULL CHECK (
        action IN (
            'approve', 'deny', 'cancel', 'edit',
            'promote_approval', 'promote_passthrough'
        )
    ),
    binding_action TEXT NOT NULL CHECK (
        binding_action IN (
            'approve', 'deny', 'human_cancel', 'edit',
            'promote_approval', 'promote_passthrough'
        )
    ),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    version INTEGER NOT NULL CHECK (version > 0),
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    prospective_payload_hash TEXT CHECK (
        prospective_payload_hash IS NULL OR length(prospective_payload_hash) = 64
    ),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 16 AND 128),
    policy_change INTEGER NOT NULL CHECK (policy_change IN (0, 1)),
    edit_encrypted_payload BLOB,
    edit_payload_hash TEXT CHECK (
        edit_payload_hash IS NULL OR length(edit_payload_hash) = 64
    ),
    edit_canonical_size INTEGER CHECK (
        edit_canonical_size IS NULL OR edit_canonical_size >= 0
    ),
    edit_policy_version TEXT,
    edit_adapter_version TEXT,
    edit_schema_version TEXT,
    edit_encryption_key_ref TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    FOREIGN KEY (challenge_id) REFERENCES auth_challenges(challenge_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (request_id, version, payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash)
        ON DELETE RESTRICT,
    CHECK (
        (binding_action = 'edit' AND prospective_payload_hash IS NOT NULL) OR
        (binding_action != 'edit' AND prospective_payload_hash IS NULL)
    ),
    CHECK (
        (action = 'edit' AND
         edit_encrypted_payload IS NOT NULL AND edit_payload_hash IS NOT NULL AND
         edit_canonical_size IS NOT NULL AND edit_policy_version IS NOT NULL AND
         edit_adapter_version IS NOT NULL AND edit_schema_version IS NOT NULL AND
         edit_encryption_key_ref IS NOT NULL AND
         edit_payload_hash = prospective_payload_hash) OR
        (action != 'edit' AND
         edit_encrypted_payload IS NULL AND edit_payload_hash IS NULL AND
         edit_canonical_size IS NULL AND edit_policy_version IS NULL AND
         edit_adapter_version IS NULL AND edit_schema_version IS NULL AND
         edit_encryption_key_ref IS NULL)
    ),
    CHECK (
        policy_change = (action IN ('promote_approval', 'promote_passthrough') OR
                         binding_action IN ('promote_approval', 'promote_passthrough'))
    )
) STRICT;

CREATE INDEX web_action_drafts_expiry_idx
    ON web_action_drafts(expires_at, challenge_id);

CREATE TRIGGER web_action_drafts_no_update
BEFORE UPDATE ON web_action_drafts
BEGIN
    SELECT RAISE(ABORT, 'web action drafts are immutable');
END;

CREATE TABLE durable_policy_snapshots (
    policy_version_id INTEGER PRIMARY KEY,
    config_hash TEXT NOT NULL UNIQUE CHECK (length(config_hash) = 64),
    prior_config_hash TEXT CHECK (
        prior_config_hash IS NULL OR length(prior_config_hash) = 64
    ),
    snapshot_yaml BLOB NOT NULL CHECK (length(snapshot_yaml) > 0),
    file_sha256 TEXT NOT NULL CHECK (length(file_sha256) = 64),
    FOREIGN KEY (policy_version_id) REFERENCES policy_versions(policy_version_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE durable_policy_file_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    policy_version_id INTEGER NOT NULL,
    config_hash TEXT NOT NULL CHECK (length(config_hash) = 64),
    file_sha256 TEXT NOT NULL CHECK (length(file_sha256) = 64),
    sync_state TEXT NOT NULL CHECK (sync_state IN ('pending', 'synced')),
    publication_pending INTEGER NOT NULL CHECK (publication_pending IN (0, 1)),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    FOREIGN KEY (policy_version_id) REFERENCES durable_policy_snapshots(policy_version_id)
        ON DELETE RESTRICT,
    UNIQUE (policy_version_id, config_hash, file_sha256)
) STRICT;

CREATE TRIGGER durable_policy_snapshots_no_update
BEFORE UPDATE ON durable_policy_snapshots
BEGIN
    SELECT RAISE(ABORT, 'durable policy snapshots are immutable');
END;

CREATE TRIGGER durable_policy_snapshots_no_delete
BEFORE DELETE ON durable_policy_snapshots
BEGIN
    SELECT RAISE(ABORT, 'durable policy snapshots are append-only');
END;

CREATE TRIGGER policy_versions_no_update
BEFORE UPDATE ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy versions are immutable');
END;

CREATE TRIGGER policy_versions_no_delete
BEFORE DELETE ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy versions are append-only');
END;
