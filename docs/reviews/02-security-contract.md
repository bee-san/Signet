# SP 02: Production authentication, credential, and recovery contract

This document is the normative production target for Signet's human-auth boundary.
It defines the required factor ledger, bootstrap/recovery behavior, and abuse-case
acceptance matrix. It does not authorize live enrollment, credential issuance,
sends, or system changes from this run.

## 1. Normative invariants

- Every factor is owned by exactly one user.
- A user may hold zero or more passkey factors and zero or more TOTP factors.
- No singleton-factor assumption: one passkey or one TOTP row must never be
  treated as "the user's only factor" by schema or code.
- Each TOTP enrollment has its own secret and record; cloning one seed into
  another label or device is not a separate enrollment.
- Each passkey has its own credential ID, public key, counter, backup metadata,
  and audit identity.
- Factor records must be opaque, stable, labelable, auditable, and secret-free in
  logs.
- If passwords are retained at all, they are bootstrap/recovery helpers only and
  never count as the minimum usable factor floor.
- Login and action confirmation are separate policies.
- A proof authorizes one purpose, one subject, one request, one selected factor,
  once.
- Same-UID compromise is outside the hard boundary; separate-account or
  separate-host hardening is required for that threat.

## 2. Canonical data model

```yaml
auth_users:
  user_id: opaque stable ID
  role: user | admin | support | ...
  status: active | disabled
  auth_generation: monotonically increasing int
  created_at: unix seconds
  disabled_at: unix seconds | null

auth_factors:
  factor_id: opaque stable ID, never derived from secret material
  user_id: owner
  kind: passkey | totp | recovery_code
  label: user-managed name, unique per user within kind
  state: provisioning | active | disabled | revoked | lost | replaced
  created_at: unix seconds
  last_used_at: unix seconds | null
  disabled_at: unix seconds | null
  revoked_at: unix seconds | null
  audit_identity: non-secret digest for logs and support
  kind_data:
    passkey:
      credential_id: public opaque credential ID
      public_key: public key bytes
      sign_count: compare-and-swap counter
      device_type: single_device | multi_device
      backed_up: bool
      backup_eligible: bool
      user_handle: authenticator user handle bytes
    totp:
      secret_reference: keychain/secret-broker reference, not the seed
      secret_version: optional rotation/version label
      issuer: display-only issuer string
      account_label: display-only account string
      period_seconds: integer
      digits: 6 | 8
    recovery_code:
      code_hash: one-way hash
      code_version: rotation batch
      issued_at: unix seconds
      consumed_at: unix seconds | null
      expires_at: unix seconds | null

auth_challenges:
  challenge_id: opaque stable ID
  user_id: owner
  purpose: login | mutation
  action: exact action name
  request_id: immutable request ID | null
  version: immutable version | null
  current_payload_hash: sha256 | null
  prospective_payload_hash: sha256 | null
  session_id: bound session
  http_method: POST
  origin: exact HTTPS origin
  host: exact Host value
  factor_allowlist: list of factor_id values
  created_at: unix seconds
  expires_at: unix seconds
  consumed_at: unix seconds | null
  invalidated_at: unix seconds | null

auth_consumptions:
  login: (kind, use_id, user_id, session_id, consumed_at)
  mutation: (kind, use_id, purpose, request_id, version, consumed_at)
```

Notes:

- `factor_id` is the stable opaque handle for the factor record.
- `kind` is the factor class, not the user-facing label.
- `use_id` is a one-time proof identity or timestep identity, never a raw code or
  secret value.
- Any unique index or repository method that enforces only one active TOTP per
  user is non-conforming to this contract.

## 3. Bootstrap and enrollment

1. The initial bootstrap ceremony is allowed only at the final HTTPS origin, with
   exact host/origin checks and the intended RP ID.
2. Bootstrap mode is explicit and temporary. It ends as soon as the first durable
   production factor set is committed. After that, bootstrap-only paths must stay
   off until a separate audited reset occurs.
3. A new passkey or TOTP may be added only by presenting a fresh existing factor or
   an equivalent break-glass code. The factor being added cannot authenticate its
   own creation.
4. A new passkey enrollment creates a new factor record with a new credential ID
   and its own counter/backup metadata.
5. A new TOTP enrollment creates a new factor record with a new secret reference.
   Reusing or cloning a seed into a second record is not an independent factor.
6. Password verifiers, if a deployment keeps them, are bootstrap/recovery material
   only; they do not satisfy the production factor floor by themselves.

## 4. Login vs action confirmation

- Login is for creating or rotating a session.
- Action confirmation is for approving one exact request, one exact version, and
  one exact payload hash set.
- A login proof cannot approve a mutation, revoke a factor, weaken policy, or
  bootstrap another factor.
- A mutation proof cannot be reused as a login proof.
- Login and mutation use separate challenge IDs and separate consumption ledgers.
- Every login or sensitive factor change rotates the authenticated session and
  revokes the pre-rotation session.
- Unsafe methods require the configured HTTPS origin, host, and CSRF token bound
  to the session and purpose before a proof is even considered.

## 5. Replay, rate limiting, and challenge binding

- Each factor has its own rate-limit scope, and each caller/source also has its own
  rate-limit scope.
- TOTP replay prevention is per factor and per timestep. A timestep can be
  consumed once for a given purpose and cannot be reused by the same factor, a
  different factor, or a different user.
- WebAuthn challenges are bound to the exact origin, RP ID, host, session ID,
  method, action, request ID, version, and payload hashes needed for the
  operation.
- Verification is read-only. The challenge is consumed only in the same
  transaction as the approved login or mutation.
- A proof can authorize only the exact request it was bound to; any stale version,
  stale hash, or foreign request is rejected.

## 6. Factor lifecycle and recovery

- Renaming a factor changes only the label and audit metadata.
- Revoking or disabling a factor is explicit and irreversible unless a separate,
  audited admin/support repair path exists.
- Lost-device recovery requires another surviving factor or a valid break-glass
  code, plus a fresh final-origin ceremony.
- Replacing a credential means creating a new factor, verifying it, then retiring
  the old factor.
- Disabled users cannot log in, enroll, revoke, or recover factors.
- The last protected factor for a user cannot be removed by mistake.
- The last admin-capable factor for the last enabled admin cannot be removed by
  mistake.
- If break-glass recovery codes are offered, they must be few, one-time, hashed,
  shown once, auditable, and rotated on use or compromise. Any equivalent
  break-glass primitive must have the same properties.

## 7. Multi-user and authorization boundaries

- Factor ownership never implies role membership.
- Cross-user factor CRUD requires explicit admin/support authorization and a fresh
  factor proof.
- If the deployment does not support roles, cross-user factor CRUD is forbidden.
- A factor proof from user A cannot satisfy user B's request, even if the action
  shape is identical.
- Role elevation and factor enrollment are separate decisions and separate audit
  events.

## 8. Storage, backup, deletion, and compromise response

- TOTP seeds live behind a secret broker or Keychain boundary. Only the opaque
  reference is stored in the auth database.
- Passkey public material is stored as public data, but it is still audit-sensitive
  and must be redacted in logs and debug output.
- Backups must preserve factor IDs, labels, counters, backup state, and audit
  timestamps. Restore must not silently collapse multiple factors into one.
- Migration must preserve cardinality and factor identity. Re-enrollment must not
  happen implicitly during schema changes.
- Deletion removes or tombstones the factor record, revokes sessions and open
  challenges, and rotates any dependent break-glass material.
- A compromised-factor response revokes the compromised factor, invalidates open
  sessions and challenges, and leaves surviving factors usable.

## 9. Same-UID limitation

This contract does not claim defense against malicious code running under the same
macOS user account. A same-UID process may be able to read local files, request the
same user's secrets, or tamper with writable state. Production hardening therefore
requires a separate account or a separate host, restrictive ACLs, and an
authenticated boundary that the same-UID adversary cannot casually bypass.

## 10. Abuse-case test matrix

Every row below must fail closed. When a rejection is expected, the target state
must remain unchanged except for the relevant audit/event record.

| ID | Abuse case | Expected outcome |
| --- | --- | --- |
| B-1 | Non-final HTTPS origin or wrong Host attempts first bootstrap | Reject; no bootstrap state or factor is created. |
| B-2 | Bootstrap mode is explicitly closed, then a bootstrap-only endpoint is replayed | Reject; bootstrap cannot silently reopen. |
| E-1 | Existing passkey enrolls another passkey | Accept; the new factor gets its own factor ID, credential ID, and counter. |
| E-2 | Existing factor tries to self-enroll or replay its own enrollment proof | Reject; no duplicate factor record. |
| E-3 | Existing factor enrolls a second TOTP with a fresh secret | Accept; the new record has a distinct secret reference. |
| E-4 | The same TOTP seed is cloned to another label/device and presented as a new factor | Reject; it is not an independent enrollment. |
| A-1 | Login proof is submitted to a mutation endpoint | Reject; no commit and no session upgrade. |
| A-2 | Mutation proof is replayed against a second request or version | Reject; the proof is already consumed. |
| A-3 | One TOTP timestep is reused for the same factor, another factor, or another user | Reject; the step ledger blocks replay. |
| A-4 | WebAuthn assertion uses the wrong origin, RP ID, host, session, action, or request hash | Reject; the challenge is invalid or unconsumed. |
| A-5 | A browser or agent session lacking a fresh selected factor attempts approve, edit, deny, cancel, enroll, revoke, recover, or weaken policy | Reject all of them; no state change. |
| F-1 | Rename, revoke, or disable is attempted without a fresh selected factor | Reject; the label/state remains unchanged. |
| F-2 | Removing the last protected factor is attempted | Reject unless a distinct break-glass path is already live and audited. |
| F-3 | Removing the last admin-capable factor is attempted | Reject; the admin floor is preserved. |
| R-1 | Recovery code is used twice or used after rotation | Reject; the code hash is marked used or revoked. |
| R-2 | Disabled user tries to log in, enroll, revoke, or recover | Reject; no new session or factor change. |
| M-1 | Factor proof from user A is replayed for user B or for a different action | Reject; ownership or purpose mismatch. |
| C-1 | Compromised factor response after suspected theft | Revoke the compromised factor, invalidate sessions/challenges, and keep surviving factors usable. |

Implementation note: the current repository still has a singleton-active-TOTP
implementation path. That is a known gap versus this contract; future
implementation work must replace it with per-factor TOTP records and lookups.
