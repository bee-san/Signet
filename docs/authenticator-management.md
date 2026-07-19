# Authenticator management

Signet schema 17 supports more than one active password, TOTP credential, or
WebAuthn/passkey per account. Schemas 18 and 19 add browser bootstrap and
authenticator-management ceremonies without weakening the backend proof boundary.
The browser routes can enroll a real device only when a deployment deliberately
wires and exposes the authenticated web application; tests and the disabled staging
assembly use fake credentials and providers.

## Records and safe metadata

`auth_credentials` remains the secret/public-material record used by the
verifiers. `auth_factors` adds a stable opaque `fac_...` identifier, the
credential identifier, account, kind, label, state, timestamps, and audit
references. Passkeys therefore retain both the WebAuthn credential ID and an
independent factor ID.

Call `AuthenticatorManager.list_factors(user_id)` or `get_factor(...)` for
management views. Their `FactorMetadata` result never contains a TOTP seed,
secret reference, WebAuthn public key, session token, challenge bytes, or proof
capability. Do not query `auth_credentials` to populate management UI.

TOTP generation and storage is behind `TotpSecretProvisioner`:

- `KeychainTotpSecretProvisioner.create(factor_id)` generates a unique seed and
  stores it in the OS keychain. It returns only a `keychain://` reference.
- `delete(reference)` is used for best-effort cleanup when a database mutation
  rolls back.
- The manager never receives or returns the seed. `TotpEnrollmentService` is the
  separate one-time browser display boundary: it returns the QR/manual key only to
  the claimed bootstrap browser or after fresh management authorization. The UI
  removes those values immediately after verification. Do not add seed fields to
  `FactorMetadata`, logs, screenshots, or accessibility artifacts.

## Mutation API

The backend exposes these guarded operations:

- `add_totp` and `add_passkey`
- `rename_factor`
- `revoke_factor` with `revoked` or `compromised` state
- `replace_totp`, which adds the replacement and revokes the old factor in one
  database transaction
- `recover_totp`, available only when
  `RecoveryPolicy.allow_bootstrap_without_factor` is explicitly enabled and no
  active TOTP or passkey authenticator exists

Password records are visible in the safe factor catalogue, but rename and revoke
remain behind the dedicated password-management boundary rather than this API.

## Browser ceremonies

Initial owner setup remains inaccessible until the operator issues a short-lived,
one-use setup capability locally and one browser claims it. Password and
authenticator material is staged for that claimant; publication and bootstrap
completion share one database transaction. Existing valid owner credentials cause
startup to reconcile setup as complete rather than reopen enrollment.
Reissuing an expired capability discards the prior claimant's staged password and
passkey state and deletes any pending bootstrap TOTP material before returning the
replacement capability.

An authenticated session and CSRF token are not sufficient to add an authenticator.
Before Signet invokes a WebAuthn registration provider or provisions a TOTP secret,
an active existing TOTP or passkey must freshly authorize the exact enrollment kind,
label, operation, user, and session. The resulting enrollment authorization is
short-lived and one-use. Finalization publishes the new credential, consumes that
authorization, records the audit event, and revokes existing sessions in one
database transaction. Failed authorization therefore creates no registration
challenge or TOTP secret.

Pending browser challenges and TOTP enrollments are durable and can resume only in
their bound claimant or authenticated session until expiry. Verification clears
TOTP QR/manual-key values from the page. Expiry invalidates pending TOTP enrollments
and deletes their provisioned secrets. If cleanup after expiry or another failed
enrollment cannot be verified, Signet records cleanup debt and fails closed instead
of silently abandoning credential material.

Use the corresponding `binding_for_*` method before verification. The returned
`ActionBinding` includes an opaque operation ID and a SHA-256 digest of the
account, action, and exact mutation payload. Passkey-add bindings include every
registration field, with public-key and user-handle material represented only
by SHA-256 digests. TOTP verification should pass the
selected `credential_id`; this selects one factor and uses its independent
rate-limit key. WebAuthn management challenges are persisted in
`auth_factor_challenges` and are bound to the same operation, session, POST
method, RP ID, and canonical origin.

Pass the resulting `VerifiedTotp` or `VerifiedWebAuthn` object to the mutation.
The manager verifies the proof capability, user, action payload, session,
issuing and expiry timestamps, and active confirming factor. It consumes the
proof and performs the mutation in one short `BEGIN IMMEDIATE` transaction.
Proof reuse, operation substitution, cross-user use, stale proofs, stale
WebAuthn counters, and consumed challenges fail closed. A successful mutation
revokes the account's existing sessions.

`auth_factor_events` stores only safe event data and references the factor used
for confirmation. It must not contain credential material, secrets, assertions,
or proof capabilities.

Successful password+TOTP login updates both exact factor records. Passkey login
and fresh TOTP/WebAuthn action confirmation update the exact factor consumed.
Missing active factor metadata fails closed so usage cannot silently become
unattributed.

## Lockout and recovery rules

The default `RecoveryPolicy()` rejects removal of an account's final active
TOTP or passkey authenticator. Password records do not bypass this guard because
they cannot complete fresh factor confirmation by themselves. The policy also
rejects removal of the final authenticator for the staged/active production
owner. Concurrent removals serialize under `BEGIN IMMEDIATE`, so two valid
requests cannot both pass the final-factor check.

Do not enable any recovery flag as a convenience. `allow_bootstrap_without_factor`
is an operator-controlled backend break-glass path, is not exposed by the browser
routes, and must be paired with an external identity-recovery procedure.
`allow_last_factor_revocation` and
`allow_last_admin_factor_revocation` are separate explicit policy decisions;
the administrator guard still applies unless both relevant flags are enabled.

Lost-device handling uses a fresh proof from another active factor to mark the
lost factor `revoked` or `compromised`. Public listing should exclude inactive
factors by passing `include_inactive=False`, but audit and operator views may
retain them.

## Schema 17–19 upgrade and rollback

Schema 17 creates `auth_factors`, `auth_factor_events`, and
`auth_factor_challenges`, then backfills one stable factor record and migration
audit event for every existing credential. No seed or WebAuthn public material
is copied into the safe metadata table. Schema 18 adds durable browser setup,
registration, and TOTP-enrollment state. Schema 19 adds one-use setup claims,
staged bootstrap publication, fresh enrollment authorizations, and verified TOTP
cleanup tracking. An upgrade with one unambiguous already configured owner
reconciles setup as complete; it does not issue or claim a setup capability.

Upgrading an existing database follows the normal Signet migration contract:

1. Stop writers and retain a local-filesystem database path.
2. Run the pre-migration backup callback. The callback must return a
   `MigrationBackupReceipt` whose artifact SHA-256 and restored schema version
   have both been verified.
3. Run `Database.initialize(...)`. Schema changes, backfill, migration checksums,
   and `PRAGMA user_version = 19` commit atomically with `synchronous=FULL`.
4. Verify `Database.integrity_check()` and confirm every `auth_credentials` row
   has exactly one `auth_factors` row.
5. Restart application processes only after verification succeeds.

If migration or post-check fails, SQLite rolls the schema transaction back to the
pre-upgrade version and Signet does not start against a partial schema. To roll back
after a successful migration, stop all writers and restore the verified
pre-migration artifact; do not delete schema rows or edit `schema_meta` by hand.
Verify the restored database reports its prior schema and passes integrity
checks before starting the old binary. TOTP seed material remains in the
keychain and is not part of the SQLite backup, so preserve the existing
keychain backup/recovery procedure as well.
