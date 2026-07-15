CREATE TABLE schema_meta (
    migration_id INTEGER PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at INTEGER NOT NULL,
    min_reader_version INTEGER NOT NULL,
    max_reader_version INTEGER NOT NULL
) STRICT;

CREATE TABLE payload_versions (
    request_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    encrypted_payload BLOB,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    canonical_size INTEGER NOT NULL CHECK (canonical_size >= 0),
    policy_version TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    editor_actor TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    encryption_key_ref TEXT,
    key_destroyed_at INTEGER,
    purged_at INTEGER,
    purge_reason TEXT,
    PRIMARY KEY (request_id, version),
    UNIQUE (request_id, payload_hash),
    UNIQUE (request_id, version, payload_hash),
    FOREIGN KEY (request_id) REFERENCES approval_requests(request_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (encrypted_payload IS NOT NULL AND purged_at IS NULL) OR
        (encrypted_payload IS NULL AND purged_at IS NOT NULL)
    ),
    CHECK (key_destroyed_at IS NULL OR purged_at IS NOT NULL)
) STRICT;

CREATE TABLE approval_requests (
    request_id TEXT PRIMARY KEY,
    downstream_alias TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    policy_mode TEXT NOT NULL CHECK (
        policy_mode IN ('deny', 'approval', 'passthrough', 'virtualize_local')
    ),
    state TEXT NOT NULL CHECK (
        state IN (
            'received', 'validating', 'pending_approval', 'approved',
            'executing', 'succeeded', 'failed', 'outcome_unknown',
            'denied', 'expired', 'cancelled'
        )
    ),
    current_version INTEGER NOT NULL CHECK (current_version > 0),
    current_payload_hash TEXT NOT NULL CHECK (length(current_payload_hash) = 64),
    origin_namespace TEXT NOT NULL,
    pending_result BLOB NOT NULL,
    retry_of_request_id TEXT,
    gateway_internal INTEGER NOT NULL DEFAULT 0 CHECK (gateway_internal IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    approved_at INTEGER,
    execution_started_at INTEGER,
    completed_at INTEGER,
    safe_outcome_json TEXT,
    failure_reason TEXT,
    manual_retry_allowed INTEGER NOT NULL DEFAULT 0
        CHECK (manual_retry_allowed IN (0, 1)),
    duplicate_warning_required INTEGER NOT NULL DEFAULT 0
        CHECK (duplicate_warning_required IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    FOREIGN KEY (request_id, current_version, current_payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (retry_of_request_id) REFERENCES approval_requests(request_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX approval_requests_queue_idx
    ON approval_requests(state, expires_at, created_at);
CREATE INDEX approval_requests_namespace_idx
    ON approval_requests(origin_namespace, state, created_at);

CREATE TABLE attachments (
    attachment_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    storage_path TEXT,
    created_at INTEGER NOT NULL,
    purge_after INTEGER,
    purged_at INTEGER,
    PRIMARY KEY (attachment_id, request_id, version),
    FOREIGN KEY (request_id, version, payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash) ON DELETE RESTRICT,
    CHECK ((storage_path IS NULL) = (purged_at IS NOT NULL))
) STRICT;

CREATE INDEX attachments_request_version_idx
    ON attachments(request_id, version);

CREATE TABLE idempotency_records (
    origin_namespace TEXT NOT NULL,
    downstream_alias TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    invocation_key TEXT NOT NULL,
    payload_fingerprint TEXT NOT NULL,
    request_id TEXT NOT NULL,
    pending_result BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    tombstoned_at INTEGER,
    PRIMARY KEY (
        origin_namespace, downstream_alias, tool_name, invocation_key
    ),
    FOREIGN KEY (request_id) REFERENCES approval_requests(request_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX idempotency_request_idx ON idempotency_records(request_id);

CREATE TABLE execution_attempts (
    attempt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    fencing_token TEXT NOT NULL UNIQUE,
    worker_id TEXT NOT NULL,
    worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
    phase TEXT NOT NULL CHECK (
        phase IN (
            'preparing', 'dispatch_started', 'outcome_unknown',
            'redispatch_preparing', 'redispatch_started', 'succeeded', 'failed'
        )
    ),
    claimed_at INTEGER NOT NULL,
    lease_expires_at INTEGER,
    dispatch_started_at INTEGER,
    redispatch_started_at INTEGER,
    downstream_idempotency_key TEXT,
    reconciliation_attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (reconciliation_attempt_count >= 0),
    reconciliation_next_at INTEGER,
    reconciliation_resolution TEXT CHECK (
        reconciliation_resolution IS NULL OR reconciliation_resolution IN (
            'confirmed_effect', 'confirmed_no_effect', 'inconclusive',
            'exhausted', 'startup_abandoned_after_dispatch'
        )
    ),
    reconciliation_exhausted_at INTEGER,
    reconciliation_notification_required INTEGER NOT NULL DEFAULT 0
        CHECK (reconciliation_notification_required IN (0, 1)),
    redispatch_used INTEGER NOT NULL DEFAULT 0 CHECK (redispatch_used IN (0, 1)),
    completed_at INTEGER,
    safe_completion_json TEXT,
    outcome_classification TEXT,
    failure_reason TEXT,
    UNIQUE (request_id, version),
    FOREIGN KEY (request_id, version, payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash) ON DELETE RESTRICT
) STRICT;

CREATE INDEX execution_reconciliation_idx
    ON execution_attempts(phase, reconciliation_next_at);
CREATE INDEX execution_lease_idx ON execution_attempts(phase, lease_expires_at);

CREATE TABLE result_aliases (
    result_alias_id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    downstream_alias TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    account_namespace TEXT NOT NULL,
    identifier_kind TEXT NOT NULL,
    downstream_identifier TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (
        downstream_alias, tool_name, account_namespace,
        identifier_kind, downstream_identifier
    ),
    FOREIGN KEY (request_id) REFERENCES approval_requests(request_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE request_events (
    event_id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    safe_details_json TEXT,
    FOREIGN KEY (request_id, version, payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash) ON DELETE RESTRICT
) STRICT;

CREATE INDEX request_events_timeline_idx
    ON request_events(request_id, event_id);

CREATE TRIGGER request_events_no_update
BEFORE UPDATE ON request_events
BEGIN
    SELECT RAISE(ABORT, 'request_events are append-only');
END;

CREATE TRIGGER request_events_no_delete
BEFORE DELETE ON request_events
BEGIN
    SELECT RAISE(ABORT, 'request_events are append-only');
END;

CREATE TABLE policy_versions (
    policy_version_id INTEGER PRIMARY KEY,
    actor TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    mode_diffs_json TEXT NOT NULL,
    originating_event TEXT NOT NULL CHECK (
        originating_event IN (
            'one_click_promotion', 'request_tool_access', 'file_change',
            'rollback', 'schema_drift'
        )
    ),
    config_hash TEXT NOT NULL UNIQUE,
    applied INTEGER NOT NULL DEFAULT 1 CHECK (applied IN (0, 1))
) STRICT;

CREATE TABLE push_subscriptions (
    subscription_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    endpoint TEXT NOT NULL UNIQUE,
    p256dh_key BLOB NOT NULL,
    auth_key BLOB NOT NULL,
    device_label TEXT NOT NULL,
    categories_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_success_at INTEGER,
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    disabled_at INTEGER
) STRICT;

CREATE TABLE auth_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('webauthn', 'password', 'totp')),
    public_material BLOB,
    secret_reference TEXT,
    enrolled_at INTEGER NOT NULL,
    disabled_at INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until INTEGER,
    last_used_at INTEGER,
    sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    backup_eligible INTEGER CHECK (backup_eligible IS NULL OR backup_eligible IN (0, 1)),
    backup_state INTEGER CHECK (backup_state IS NULL OR backup_state IN (0, 1)),
    CHECK (public_material IS NOT NULL OR secret_reference IS NOT NULL)
) STRICT;

CREATE INDEX auth_credentials_user_kind_idx
    ON auth_credentials(user_id, kind);

CREATE TABLE caller_tokens (
    token_id TEXT PRIMARY KEY,
    origin_namespace TEXT NOT NULL,
    verifier TEXT NOT NULL,
    allowed_aliases_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER,
    revoked_at INTEGER
) STRICT;

CREATE TABLE schema_cache (
    downstream_alias TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    schema_digest TEXT NOT NULL,
    tool_schema_json BLOB NOT NULL,
    discovered_at INTEGER NOT NULL,
    review_state TEXT NOT NULL CHECK (
        review_state IN ('unreviewed', 'approved', 'disabled_drift')
    ),
    reviewed_at INTEGER,
    PRIMARY KEY (downstream_alias, tool_name)
) STRICT;

CREATE TABLE purge_jobs (
    purge_job_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    intent TEXT NOT NULL CHECK (
        intent IN ('sensitive_rows', 'attachments', 'encryption_key', 'backup_pin')
    ),
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    last_error TEXT,
    FOREIGN KEY (request_id) REFERENCES approval_requests(request_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE confirmation_consumptions (
    kind TEXT NOT NULL CHECK (kind IN ('totp', 'webauthn')),
    use_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    path TEXT NOT NULL CHECK (path IN ('web', 'mcp')),
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY (kind, use_id),
    FOREIGN KEY (request_id, version, payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash) ON DELETE RESTRICT
) STRICT;

CREATE TABLE approval_challenges (
    challenge_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('totp', 'webauthn')),
    request_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    invalidated_at INTEGER,
    FOREIGN KEY (request_id, version, payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash) ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
) STRICT;

CREATE INDEX approval_challenges_request_idx
    ON approval_challenges(request_id, version);

CREATE TABLE browser_views (
    view_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    request_revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    invalidated_at INTEGER,
    FOREIGN KEY (request_id, version, payload_hash)
        REFERENCES payload_versions(request_id, version, payload_hash) ON DELETE RESTRICT
) STRICT;

CREATE INDEX browser_views_request_idx ON browser_views(request_id, version);

CREATE TRIGGER payload_versions_immutable_fields
BEFORE UPDATE ON payload_versions
WHEN
    OLD.request_id IS NOT NEW.request_id OR
    OLD.version IS NOT NEW.version OR
    OLD.payload_hash IS NOT NEW.payload_hash OR
    OLD.canonical_size IS NOT NEW.canonical_size OR
    OLD.policy_version IS NOT NEW.policy_version OR
    OLD.adapter_version IS NOT NEW.adapter_version OR
    OLD.schema_version IS NOT NEW.schema_version OR
    OLD.editor_actor IS NOT NEW.editor_actor OR
    OLD.created_at IS NOT NEW.created_at OR
    (
        OLD.encrypted_payload IS NOT NEW.encrypted_payload AND NOT (
            NEW.encrypted_payload IS NULL AND
            NEW.purged_at IS NOT NULL AND
            NEW.key_destroyed_at IS NOT NULL
        )
    ) OR
    (
        OLD.encryption_key_ref IS NOT NEW.encryption_key_ref AND NOT (
            NEW.encryption_key_ref IS NULL AND
            NEW.purged_at IS NOT NULL AND
            NEW.key_destroyed_at IS NOT NULL
        )
    ) OR
    (OLD.purged_at IS NOT NULL AND OLD.purged_at IS NOT NEW.purged_at) OR
    (OLD.key_destroyed_at IS NOT NULL AND OLD.key_destroyed_at IS NOT NEW.key_destroyed_at)
BEGIN
    SELECT RAISE(ABORT, 'payload versions are immutable except for one-way purge');
END;
