CREATE TABLE auth_rate_windows (
    scope_key TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL CHECK (window_start >= 0),
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    blocked_until INTEGER CHECK (blocked_until IS NULL OR blocked_until >= window_start),
    updated_at INTEGER NOT NULL CHECK (updated_at >= window_start)
) STRICT;
