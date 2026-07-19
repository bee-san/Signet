ALTER TABLE browser_bootstrap_state
    ADD COLUMN capability_id TEXT
    CHECK (capability_id IS NULL OR length(capability_id) BETWEEN 16 AND 128);

ALTER TABLE browser_bootstrap_state
    ADD COLUMN capability_verifier BLOB
    CHECK (capability_verifier IS NULL OR length(capability_verifier) = 32);

ALTER TABLE browser_bootstrap_state
    ADD COLUMN capability_expires_at INTEGER;

ALTER TABLE browser_bootstrap_state
    ADD COLUMN claimant_verifier BLOB
    CHECK (claimant_verifier IS NULL OR length(claimant_verifier) = 32);

ALTER TABLE browser_bootstrap_state
    ADD COLUMN claimed_at INTEGER;

ALTER TABLE browser_bootstrap_state
    ADD COLUMN staged_password_verifier BLOB;

CREATE UNIQUE INDEX browser_bootstrap_capability_idx
    ON browser_bootstrap_state(capability_id)
    WHERE capability_id IS NOT NULL;

CREATE TABLE browser_enrollment_authorizations (
    authorization_id TEXT PRIMARY KEY CHECK (length(authorization_id) BETWEEN 20 AND 128),
    user_id TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 16 AND 128),
    action TEXT NOT NULL CHECK (action IN ('add_passkey', 'add_totp')),
    factor_label TEXT NOT NULL CHECK (length(factor_label) BETWEEN 1 AND 64),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 16 AND 128),
    actor_factor_id TEXT NOT NULL CHECK (length(actor_factor_id) BETWEEN 20 AND 64),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    claimed_at INTEGER,
    consumed_at INTEGER,
    CHECK (expires_at > created_at),
    CHECK (claimed_at IS NULL OR claimed_at >= created_at),
    CHECK (consumed_at IS NULL OR claimed_at IS NOT NULL),
    CHECK (consumed_at IS NULL OR consumed_at >= claimed_at)
) STRICT;

CREATE INDEX browser_enrollment_authorizations_active_idx
    ON browser_enrollment_authorizations(user_id, session_id, expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE auth_registration_challenges
    ADD COLUMN authorization_id TEXT
    REFERENCES browser_enrollment_authorizations(authorization_id);

ALTER TABLE auth_registration_challenges
    ADD COLUMN operation_id TEXT
    CHECK (operation_id IS NULL OR length(operation_id) BETWEEN 16 AND 128);

ALTER TABLE browser_totp_enrollments
    ADD COLUMN authorization_id TEXT
    REFERENCES browser_enrollment_authorizations(authorization_id);

ALTER TABLE browser_totp_enrollments
    ADD COLUMN operation_id TEXT
    CHECK (operation_id IS NULL OR length(operation_id) BETWEEN 16 AND 128);

ALTER TABLE browser_totp_enrollments
    ADD COLUMN cleanup_completed_at INTEGER
    CHECK (cleanup_completed_at IS NULL OR invalidated_at IS NOT NULL);

UPDATE browser_bootstrap_state
SET status = 'complete',
    completed_at = max(updated_at, created_at),
    capability_id = NULL,
    capability_verifier = NULL,
    capability_expires_at = NULL,
    claimant_verifier = NULL,
    claimed_at = NULL
WHERE status = 'pending'
  AND EXISTS (
      SELECT 1 FROM auth_credentials
      WHERE user_id = browser_bootstrap_state.user_id
        AND kind = 'password' AND disabled_at IS NULL
  )
  AND EXISTS (
      SELECT 1 FROM auth_credentials
      WHERE user_id = browser_bootstrap_state.user_id
        AND kind IN ('totp', 'webauthn') AND disabled_at IS NULL
  );

INSERT INTO browser_bootstrap_state(
    state_id, user_id, status, created_at, updated_at, completed_at
)
SELECT 1, eligible.user_id, 'complete', eligible.created_at, eligible.created_at, eligible.created_at
FROM (
    SELECT u.user_id, u.created_at
    FROM auth_users AS u
    WHERE EXISTS (
        SELECT 1 FROM auth_credentials AS password
        WHERE password.user_id = u.user_id
          AND password.kind = 'password' AND password.disabled_at IS NULL
    )
      AND EXISTS (
        SELECT 1 FROM auth_credentials AS authenticator
        WHERE authenticator.user_id = u.user_id
          AND authenticator.kind IN ('totp', 'webauthn')
          AND authenticator.disabled_at IS NULL
    )
) AS eligible
WHERE (SELECT count(*) FROM (
    SELECT u2.user_id
    FROM auth_users AS u2
    WHERE EXISTS (
        SELECT 1 FROM auth_credentials AS p2
        WHERE p2.user_id = u2.user_id
          AND p2.kind = 'password' AND p2.disabled_at IS NULL
    )
      AND EXISTS (
        SELECT 1 FROM auth_credentials AS a2
        WHERE a2.user_id = u2.user_id
          AND a2.kind IN ('totp', 'webauthn') AND a2.disabled_at IS NULL
    )
)) = 1
ON CONFLICT(state_id) DO NOTHING;
