CREATE TABLE notification_outbox (
    outbox_id TEXT PRIMARY KEY CHECK (length(outbox_id) BETWEEN 16 AND 128),
    dedupe_key TEXT NOT NULL UNIQUE CHECK (length(dedupe_key) BETWEEN 1 AND 512),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    kind TEXT NOT NULL CHECK (
        kind IN (
            'new_pending', 'approaching_expiry', 'mcp_approved',
            'outcome_unknown_entered', 'outcome_unknown_resolved',
            'outcome_unknown_exhausted', 'daily_digest'
        )
    ),
    request_id TEXT,
    service TEXT,
    action TEXT,
    count INTEGER,
    created_at INTEGER NOT NULL,
    available_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claim_token TEXT,
    claim_owner TEXT,
    claimed_at INTEGER,
    delivered_at INTEGER,
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) BETWEEN 1 AND 128),
    FOREIGN KEY (request_id) REFERENCES approval_requests(request_id) ON DELETE RESTRICT,
    CHECK (available_at >= created_at),
    CHECK (
        (claim_token IS NULL AND claim_owner IS NULL AND claimed_at IS NULL) OR
        (claim_token IS NOT NULL AND claim_owner IS NOT NULL AND claimed_at IS NOT NULL)
    ),
    CHECK (delivered_at IS NULL OR claim_token IS NULL),
    CHECK (
        (kind = 'daily_digest' AND service IS NULL AND action IS NULL
            AND count IS NOT NULL AND count >= 0 AND request_id IS NULL) OR
        (kind != 'daily_digest' AND service IS NOT NULL AND action IS NOT NULL
            AND count IS NULL)
    )
) STRICT;

CREATE INDEX notification_outbox_due_idx
    ON notification_outbox(available_at, created_at, outbox_id)
    WHERE delivered_at IS NULL;

CREATE INDEX notification_outbox_request_idx
    ON notification_outbox(request_id, kind)
    WHERE request_id IS NOT NULL;
