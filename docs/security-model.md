# Security model

Signet is a human approval boundary for explicitly managed MCP routes. Its primary
security property is narrow: an autonomous caller cannot turn a configured gated
tool call into a downstream mutation until a fresh human confirmation authorizes
the exact immutable request version. The caller receives truthful durable state,
not a synthetic provider success result.

Signet is not a sandbox for the entire host. In the default shared-user deployment
it is not a hard boundary against malicious code running under the same macOS
account. This document states those limits directly.

## Security invariants

1. Unknown and schema-drifted tools fail closed.
2. `approval` mode commits the exact canonical encrypted payload and pending
   acknowledgement before returning `pending_approval`; no downstream mutation,
   provider attachment upload, or provider draft occurs first.
3. Approval is bound to request ID, immutable version, executable payload hash,
   action, authentication path, human identity, and credential use.
4. One confirmation can win one transition. Replay, stale version, stale edit,
   expired request, foreign namespace, and double submission perform zero calls.
5. Dispatch crosses a durable fencing boundary before network I/O. A crash after
   possible dispatch becomes `outcome_unknown`, never an assumed failure and never
   a blind retry.
6. Policy grants are never approved over the MCP TOTP path. The authenticated web
   backend binds them to a fresh passkey or TOTP confirmation through the injected
   durable promotion boundary, and communication sends can never become
   `passthrough`.
7. Push, logs, health checks, queue summaries, and operational audits exclude full
   payloads, targets, filenames, credentials, TOTP values, WebAuthn challenges,
   subscription keys, and raw provider responses.

## Assets

Signet protects:

- frozen message bodies, targets, attachment metadata and bytes;
- downstream provider credentials and local caller bearer tokens;
- password verifier, TOTP secret reference, WebAuthn public credential state,
  challenge state, server sessions, CSRF key, and proof-capability key;
- payload and backup encryption keys;
- approval, policy, dispatch, reconciliation, notification, and audit state;
- the mapping from a caller namespace to its requests and allowed MCP aliases.

The SQLite database necessarily retains non-secret operational metadata such as
random request ID, alias, tool, state, timestamps, version, payload hash, and safe
outcome classification. Payload bodies are encrypted, but database possession can
still reveal activity patterns. Filesystem permissions and deployment isolation
remain important.

## Trust boundaries

### MCP caller to Signet

The MCP HTTP runtime binds to a numeric loopback address and rejects untrusted Host
headers. Every alias path requires a bearer token from the local token registry and
an alias-specific scope. The authenticated token supplies a stable caller namespace
and allowed aliases. Raw bearer values are not placed in the MCP SDK `AccessToken`
object or logs.

Namespace ownership is part of authorization, not merely display filtering. A
foreign request ID is indistinguishable from an unknown one. Strong replay
deduplication is scoped to namespace, alias, tool, and a one-way invocation digest.
An explicit stable invocation ID is the durable option; a JSON-RPC request ID alone
is only session-scoped correlation.

Loopback reduces network exposure but is not caller authentication by itself.
Another same-user process may be able to connect locally or obtain that user's
files; bearer token handling and the shared-user limitation still matter.

### Signet to downstream MCP

Only Signet owns downstream credentials and mutation-capable clients for managed
routes. HTTP and stdio clients are created from reviewed non-secret configuration;
stdio launchers use an argument vector rather than a shell, bounded environment,
working directory, timeout, and captured output. Provider results are preserved for
protocol behavior but only adapter-reviewed safe metadata enters status output.

Reconciliation receives a structurally restricted read-only client with an exact
allowlist. It cannot call an arbitrary mutation because an adapter labels the call
"reconciliation." A missing or inconclusive lookup never proves no effect.

### Browser to web application

The web listener is separate from MCP. Login authorizes queue viewing; it does not
authorize a later mutation. Each approve, deny, edit, cancel, or policy action
requires a fresh action-bound confirmation.

Unsafe HTTP methods require the exact configured HTTPS `Origin`, a valid session,
and a purpose-bound CSRF token. Sessions are server-side, rotate at authentication,
and enforce idle and absolute expiry. The application rejects hostile Host values,
CORS preflight, and unauthenticated queue access. Sensitive responses use
`Cache-Control: no-store`; the current service worker has push/click handlers only,
caches no responses, and does not perform background sync or offline approval. Any
future cache is limited to immutable unauthenticated shell assets.

Security headers include a self-only CSP, `frame-ancestors 'none'`,
`base-uri 'none'`, no objects or remote frames, HSTS, `nosniff`, no referrer,
same-origin opener/resource policies, and a restrictive permissions policy.
Untrusted review text is escaped plain text. It is never allowed to place trusted
action controls inside provider content.

### Reverse proxy or Tailscale Serve

The application trusts neither Tailscale identity headers nor a reverse proxy's
user assertion. Serve is a reference way to obtain tailnet-only reachability and
TLS; normal Signet login remains mandatory if Serve is removed or replaced. The
MCP listener is never proxied. Funnel and other public exposure are outside the MVP
and remain disabled.

## Human authentication

### WebAuthn

WebAuthn/passkeys are primary because a user-verifying authenticator signs a
server-issued challenge bound to the exact RP ID and HTTPS origin. Signet verifies
challenge purpose, request action, current version/hash, credential ownership,
user-presence and user-verification flags, signature, counter and backup state, and
single-use challenge consumption. The private key stays in the authenticator.

WebAuthn is web-only. Passing an assertion through the model would discard the
browser/origin ceremony that provides its phishing-resistant context. Policy
promotions are especially sensitive durable capability grants; the current backend
requires passkey confirmation for them.

WebAuthn does not make the displayed review content trustworthy if the host or
Signet process is compromised, and a syncable passkey has a different device
boundary from a hardware-bound key. Credential backup eligibility/state is tracked
and counter transitions use compare-and-swap, but deployment policy must still
decide which authenticators are acceptable.

### Password plus TOTP web fallback

Password verification uses a stored password verifier, not plaintext. TOTP secrets
are resolved behind a secret reference. Password and TOTP failures share durable
rate-limit and escalating lockout state across relevant paths. A successful login
creates a server-side session; later web state changes still require a new TOTP or
WebAuthn action confirmation as supported by that action.

TOTP is not phishing-resistant. Anyone who obtains the current code within its
valid time window may try to use it. TLS, exact request binding, single-use
consumption, source/user rate limiting, short time windows, and receipt/push review
reduce risk but do not turn TOTP into WebAuthn.

### MCP TOTP approval and swap risk

`approve_request` lets the AI relay a human's current TOTP code for one normal
caller-owned pending request. Signet verifies and atomically binds the resulting
proof to the exact request ID, version, payload hash, MCP path, human user, caller
source, and attempt. A stale hash, replayed use, wrong user, wrong path, lockout, or
policy-change request performs no transition.

This proves that someone with the TOTP secret was present near the call. It does
**not** prove that the human saw the same full request the gateway approved. Two
related attacks remain:

1. **Request swap.** A compromised or confused AI describes benign request A but
   calls `approve_request` for malicious pending request B with the human's code.
   Binding prevents the code from drifting after the call reaches Signet, but the
   model selected the binding.
2. **Code-pretext escalation.** The AI asks for a code under a vague pretext such as
   "security verification," then spends it on a hidden request. A policy request is
   blocked on this path, but a malicious normal send may still be selected.

Mitigations are operational as well as technical:

- list pending requests first and repeat the request ID, tool, masked destination,
  and version hash prefix before asking for a code;
- use the authenticated web app for full target/body/attachment inspection or any
  surprising request;
- display an approval receipt echoing the real tool, destination summary, version,
  and hash, and send an out-of-band "approved via chat" notification;
- prevent MCP denial, editing, manual retry, credential changes, and policy grants;
- rate-limit attempts and consume a valid code with the approval transition;
- treat the authenticated web event timeline as authoritative.

The receipt echo is trustworthy only if the chat client renders the actual tool
result verbatim. Model-generated prose can misstate it. The web event timeline and
approval push are the independent records. Never type a code for an unidentified
request, and never treat a code as a general unlock token.

## Payload and credential protection

Normal settings accept only opaque `keychain://` secret references. Credential
values do not belong in YAML, launchd environment variables, process arguments,
logs, the approval database, browser storage, or MCP client profiles. A credential
broker resolves a reference at the narrow use site and redacts representations.

Canonical payloads use an authenticated AES-256-GCM envelope. Each encryption gets
a fresh 256-bit data key; the data key and payload use separate nonces and domain-
separated authenticated data. The envelope is bound to request ID, immutable
version, payload hash, and key reference. Corrupt ciphertext and wrong-context
decryption have the same privacy-safe failure.

This is envelope encryption in format, but cryptographic erasure depends on key
isolation. If all per-request data keys are wrapped by one shared master key and no
individually destroyable key exists outside the database, deleting a row is only
logical deletion. It must not be advertised as guaranteed physical erasure.

## Canonicalization and immutable review

Signet distinguishes executable values from display normalization. Canonical JSON
preserves null versus omitted, strings, Unicode, whitespace, and array order. The
hash covers the exact executable payload. Display summaries may normalize for
comparison but cannot silently alter what dispatch receives.

Editing creates a new immutable version and prospective payload hash. Saving an
edit and approving it are separate confirmed actions. Every old WebAuthn challenge,
TOTP binding, hash prefix, and stale browser card fails against the new version.
Attachment bytes are staged under gateway ownership, hashed, fsynced, confined,
and reverified before dispatch.

## Delivery ambiguity

No local service can generally prove exactly once across SQLite and an arbitrary
remote provider. Signet instead guarantees one local winner and an honest outcome:

- an approved version has at most one initial dispatch intent;
- the fencing token is committed before bytes may be sent;
- a definite pre-dispatch error is `failed` with no effect;
- a timeout, disconnect, or crash after possible dispatch is `outcome_unknown`;
- startup recovery never replays an abandoned post-boundary attempt;
- bounded adapter reconciliation uses read-only calls;
- exactly one automatic redispatch is possible only after confirmed no effect and
  only with the original reviewed stable provider idempotency key;
- unresolved unknown outcomes remain prominent and notification-backed.

The user must not "send again" merely because the provider response was lost.

## Notifications and privacy

Push subscriptions are per user and device. Subscription endpoints and public-key
material are sensitive even though they are not provider credentials. They are
stored server-side, can be revoked, and are pruned after persistent failure.

Notification payloads use fixed categories and aggregate counts: new pending,
approaching expiry, approved via chat, unknown outcome, unknown resolution or
exhaustion, and daily digest. They exclude request ID, alias-specific target,
subject, body, recipient, phone number, attachment filename, and provider response.
Push failure never rolls back an approval state transition; a transactional outbox
retries delivery while the web queue remains authoritative.

A provider-capable assembly must allow only exact, reviewed browser-vendor push
origins. The transport rejects credentials, fragments, non-HTTPS endpoints,
non-global IP literals (including legacy decimal/octal/hex IPv4 spellings), local
suffixes, redirects, and environment proxies. DNS for an allowlisted hostname is a
deployment trust boundary: never allow an operator- or requester-controlled domain,
and use a resolver/network policy that cannot redirect that hostname to private
infrastructure.

Logs and metrics should expose bounded counts, ages, durations, state and error
classes only. Debug logging of raw MCP requests/results is incompatible with this
model. Health endpoints return static status only and do not report queue contents,
database paths, credentials, or downstream connectivity.

## Retention, purge, and backup

The schema records one-way purge state for payloads and attachments. Production
preserves exhausted `outcome_unknown` content indefinitely because it may still be
needed for investigation and no production manual-purge action consumes a fresh,
request-bound human confirmation. Gateway-owned staged bytes can be purged through
descriptor-confined storage operations. Operators must use the release's explicit
retention coordinator and verify its configured matrix; direct file deletion can
break the database/manifest relationship.

The marker-guarded fake demo has one deliberate exception for fault-injection tests.
After reconciliation is durably exhausted, `demo purge-unknown` requires the exact
version/hash and an explicit possible-delivery acknowledgement, freezes further
reconciliation, and logically redacts only fake content. The state remains
`outcome_unknown`, and append-only authorization/completion events preserve that
truth. This path is disabled by default in the retention manager, absent from the
downstream-disabled assembly, and is not TOTP/WebAuthn-backed production
authorization. Enabling its fake-only flag in a provider-capable assembly violates
this security model.

Schema 13 makes one bounded privacy exception to append-only event storage. During
the locked migration transaction it rewrites only affected legacy
`safe_details_json`: malformed decisions become a fresh one-key fixed-reason
object, while malformed non-decisions or non-decisions containing a reason become
`NULL`. Duplicate keys, including escaped duplicates and nested duplicates, are
treated as malformed so hidden private text cannot survive sanitation. The
migration preserves the original event ID and request/version/hash binding and
appends a sanitation event referencing that ID before restoring the no-update
trigger. The mandatory pre-migration snapshot is the sole retained source of the
old free-form text and must follow the sensitive backup retention policy.

Even after logical purge, old plaintext or keys may persist in SQLite WAL/free
pages, APFS snapshots, swap, crash dumps, or backups. `VACUUM` and WAL checkpointing
reduce some remnants but do not erase snapshots or independently retained backup
keys. Claims of cryptographic destruction require a per-request key boundary whose
destroy operation is verified.

Encrypted backups use the SQLite backup API, an authenticated manifest, attachment
size/hash verification, key references rather than key values, and AES-GCM. Restore
extracts only into a new path, verifies database integrity and foreign keys,
relocates restored attachment paths, and re-verifies files. A successfully created
bundle is still not operationally trusted until a separate-path restore drill
passes and the required external secret references are available.

Do not restore an older database after Signet returned a pending acknowledgement
that the backup does not contain. That would forget a live caller-visible request
ID. Repair forward unless a proven schema-compatible rollback preserves every
acknowledged request and the idempotency ledger.

## Same-user threat model

The shared-user MVP assumes cooperative local software. A malicious process with
the same unrestricted user account may be able to:

- read database, staged files, deployment configuration, or bearer-token files;
- request the same user's Keychain items subject to macOS access controls;
- inspect another process's memory or environment where OS policy allows;
- connect to loopback listeners and imitate a configured client if it steals a
  token;
- replace executables, Python packages, launchers, or reviewed files writable by
  that user;
- use direct provider credentials, browser sessions, native messaging adapters,
  terminal tools, SDKs, or webhooks that never pass through Signet.

Independent action-bound human confirmation still helps against a merely
autonomous caller, but it does not survive full compromise of the process that
renders the request and verifies the confirmation.

A harder boundary requires a separate operating-system account with restrictive
file/Keychain ACLs and a narrow authenticated local interface, or a separate host.
The human review device should then connect over authenticated TLS. Provider
credentials, payload decryption, dispatch, and policy state belong on the isolated
side. That deployment is not implemented by simply changing a bind address.

## Bypass control

Signet governs only routes actually pointed through it. Before cutover, inventory
active and disabled Hermes profiles, configuration and environment files, launchd,
cron, scripts, skills, backups, browser provider sessions, native messaging paths,
terminal/SDK/JMAP clients, webhooks, shell environment, direct MCP URLs, and
credential references. Report names and locations only, never values or
fingerprints.

`python -m signet.operations audit-bypasses` evaluates an explicitly supplied
metadata inventory; it does not scan the host. Missing coverage, unknown routes, or
an active write-capable direct path makes the report non-clean. Cutover readiness
also requires matching live schema digests, fake-provider acceptance, reviewed
route diffs, disabled Funnel, a restore drill, enrolled authentication and provider
credentials, and explicit human authorization.
The offline readiness helper validates only supplied shapes and references. It
always reports `ready=false` and `authorizes_live_changes=false`; a human must
independently verify the referenced records and authorize every live operation.

## Security claims not made

Signet does not claim that:

- shared-user secrets are hidden from malicious same-user code;
- TOTP-in-chat proves the human reviewed the full payload;
- an approved request has already been delivered;
- arbitrary providers support exactly-once delivery;
- a provider reconciliation search is conclusive unless the reviewed adapter says
  so for that exact contract;
- logical purge removes APFS snapshots, backups, WAL remnants, or swap;
- Tailscale identity replaces Signet authentication;
- a clean supplied bypass inventory proves the host was scanned correctly;
- native Hermes tools, browser automation, scripts, SDKs, or direct APIs are gated;
- the staged deployment templates are installed or production-ready without a
  deployment assembly and the deferred human ceremony.

These limits are acceptance criteria, not footnotes. A deployment that needs a
stronger claim must move the corresponding secret, process, or human ceremony
across a real isolation boundary and test that boundary adversarially.
