# Policy and onboarding guide

Signet policy is exact and deny-by-default, with a required versioned-change
contract. There are no wildcard tool rules and no inference that silently enables
a capability. A tool becomes callable
only when its downstream alias, exact name, current schema digest, reviewed
classification, and mode all agree.

The executable baseline is `spec/policy-v1.yaml`. The runtime parser is
`signet.policy.load_policy`; it rejects duplicate YAML keys, unknown fields,
wildcards, malformed endpoints, non-Keychain credential references, invalid modes,
and unsafe passthrough classifications.

## Four modes

### `passthrough`

Use only for an explicitly reviewed read-only tool. The gateway validates the
arguments against the captured input schema, calls the downstream immediately, and
returns its MCP result losslessly, including explicit null and extension fields.

Policy requires `reviewed_read_only: true`. A tool marked
`communication_send: true` can never use passthrough. A tool that is unreviewed,
write-capable, destructive, open-ended, or ambiguous cannot use it either. Names
such as `get_*` and an MCP `readOnlyHint` are review clues, not proof.

### `virtualize_local`

Use for a reviewed operation whose object can remain entirely under gateway-owned
local storage, such as staging an attachment or a local draft. It requires an
`adapter`. It makes zero downstream calls and creates no standalone approval.
The adapter result must validate against the captured provider output schema so a
later gated send can refer to the local object through the reviewed contract.

Virtualized objects are scoped by adapter, account, and caller namespace. Staging
uses bounded streaming, mode-0600 files, hashes and fsync, opaque IDs, no-follow
descriptor traversal, and root confinement. An adapter must not represent a
provider-side draft or upload as local virtualization.

### `approval`

Use for consequential writes. It requires a reviewed `adapter`. The gateway
validates and canonicalizes the exact arguments, stages local dependencies,
encrypts an immutable payload version, commits the request and byte-identical
pending acknowledgement, and returns `pending_approval`. It performs zero
downstream mutations before approval.

Communication sends remain in this mode permanently. Adding approval mode for a
new send-like tool requires reviewed preview/canonicalization, outcome
classification, safe result projection, an explicit read-only reconciliation
allowlist or documented unconditional `inconclusive`, and fake-provider evidence
of zero pre-approval calls.

### `deny`

There are two intentionally different deny cases:

1. **Explicit reviewed deny.** The exact tool is configured with `mode: deny`, so
   it may appear in `tools/list` after schema review. Calling it returns the stable
   `policy_denied` domain error and makes no downstream call. This is useful when a
   client needs to see that a known capability is deliberately unavailable.
2. **Implicit unknown deny.** An unconfigured alias/tool resolves to the global
   default `deny`, is not listed, and an attempted call is an unknown-tool protocol
   error. This prevents discovery drift from expanding the attack surface.

Schema drift also disables a configured tool until the new exact definition is
reviewed. It does not fall back to a guessed mode.

## Policy format

A minimal policy is:

```yaml
version: 1
default_mode: deny

downstreams:
  example:
    transport: http
    url: https://provider.example.invalid/mcp
    credential_ref: keychain://Signet/example
    tools:
      list_items:
        mode: passthrough
        reviewed_read_only: true
        schema_digest: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      stage_file:
        mode: virtualize_local
        adapter: example.stage_file
        schema_digest: 1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      send_item:
        mode: approval
        adapter: example.send_item
        communication_send: true
        schema_digest: 2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        limits:
          payload_bytes: 1048576
      delete_item:
        mode: deny
        schema_digest: 3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Root fields:

| Field | Contract |
| --- | --- |
| `version` | Positive integer. A change is an auditable policy version, not an arbitrary timestamp. |
| `default_mode` | Must be exactly `deny`. |
| `downstreams` | Mapping from exact safe aliases to transport and exact tools. |
| `mode_contracts` | Optional declarative fixture metadata; unknown root fields still fail. |
| `policy_changes` | Optional declarative fixture metadata for approval-channel rules. |

Downstream fields:

| Field | Contract |
| --- | --- |
| `transport` | Exactly `http` or `stdio`. |
| `url` | Required for HTTP. HTTPS, or loopback HTTP only; no userinfo, query, fragment, or invalid port. |
| `command_ref` | Required for stdio instead of `url`; an opaque reviewed launcher reference, not a shell command. |
| `credential_ref` | Optional opaque `keychain://` reference. Never a credential value. |
| `tools` | Exact tool-name mapping. Empty means everything remains implicitly denied. |
| `schema_review`, `account_ref`, `wrapper_contract` | Optional reviewed metadata used by deployment/adapters; it cannot override tool safety rules. |

Tool fields:

| Field | Contract |
| --- | --- |
| `mode` | One of the four modes; required. |
| `adapter` | Required for `approval` and `virtualize_local`; exact registered adapter identifier. |
| `reviewed_read_only` | Must be true before passthrough. |
| `communication_send` | Marks send semantics and permanently blocks passthrough. |
| `schema_digest` | Lowercase 64-character SHA-256 of the exact lossless MCP Tool definition. |
| `limits` | Mapping of deployment/adapter limit names to positive integers; no boolean or zero values. |
| `account_ref`, `reviewed_classification` | Optional non-secret review metadata. |

The HTTP endpoint parser accepts loopback HTTP so a gateway-owned downstream may
remain local. A remote endpoint must use HTTPS. Stdio execution configuration
(executable allowlist, argument vector, environment, working directory, timeout,
and output cap) lives in non-secret runtime configuration and cannot be replaced by
an arbitrary policy string.

## Schema review and drift

Signet computes the digest over the exact MCP `Tool` object using canonical JSON.
This includes descriptions, input/output schemas, annotations, explicit nulls, and
provider extension fields. For approval mode, Signet deliberately replaces only
the advertised output schema and augments the description upstream; the captured
provider definition and its digest remain the review source.

A tool is enabled only if:

1. it was captured from a complete paginated `tools/list` result;
2. its exact name is configured;
3. the current digest equals the configured or explicitly reviewed digest;
4. its mode-specific classification and adapter requirements pass;
5. it does not advertise unsupported MCP task execution.

Removal or any definition change marks the tool drifted. Connected MCP sessions
advertise `listChanged` capability, and `AliasToolSurface.notify_list_changed()` can
notify currently tracked sessions. `DurableSchemaRegistry` now joins the exact
lossless capture, SQLite review state, the shared `SchemaMirror`, and each affected
alias surface. A deployment must call `restore()` before serving traffic and route
complete, bounded discovery results through `refresh()`; the core does not perform
live discovery by itself.

Refresh and manual review serialize against calls on the affected surface. The
registry persists removals and changed definitions as disabled drift, restores only
present integrity-checked schemas after restart, and sends
`notifications/tools/list_changed` when the exposed list changes. If any connected
session cannot receive a publication notification, a newly captured or reviewed
tool remains disabled rather than being exposed inconsistently. Reconnecting clients
receive the current list from durable state. This tested coordinator is a safety
boundary, not evidence that any live provider schema has been captured or reviewed.

Never update `schema_digest` mechanically just to clear drift. Review semantic
changes, argument defaults, new union branches, open object properties, task
support, annotations, provider extensions, and result changes before approving the
new digest.

## Policy changes

Policy changes are durable capability changes, not ordinary sends.
`SQLitePolicyPromotionBoundary` now joins proof consumption, request state, policy
version history, the exact serialized policy snapshot, atomic policy-file writeback,
the in-memory `PolicyEngine`, and injected runtime publication callbacks. Each
applied change records actor, timestamp, prior mode, new mode, originating event,
and configuration hash in the durable history. The boundary holds a private file
lock, refuses concurrent or stale promotion, and preserves every strict policy field
other than the reviewed mode/version change.

SQLite and the policy file cannot share one physical transaction. The boundary
therefore fsyncs an exact pending file, commits a pending ledger record with the
single-use proof, atomically replaces the policy file, then marks file and runtime
publication complete. On restart it completes only the byte-identical committed
pending snapshot and replays an outstanding publication callback. A changed policy
file, conflicting ledger hash, corrupt snapshot, or ambiguous pending artifact
fails closed with policy mutation unavailable. A deployment must still wire this
boundary to its exact policy path, shared engine/mirror, and list-change callback;
its existence does not enroll a human proof or authorize a live policy change.

There are two user flows:

- From a pending or denied event, the web UI can propose "always gate this tool" or
  "always allow this tool." The action needs a fresh human confirmation.
- An AI can call `request_tool_access(alias, tool, reason)`. That creates an
  encrypted gateway-internal pending request. It never applies policy by itself.

The MCP `approve_request` path rejects every gateway-internal policy request with
`web_only`. The authenticated web backend can bind promotion to either a fresh
passkey or TOTP confirmation. The visible "always" shortcut buttons currently use
the passkey path; a gateway-internal request can also be confirmed through its web
authenticator fallback. The policy engine enforces these non-negotiable guards:

- only a discovered, reviewed exact tool can be promoted;
- passthrough requires reviewed read-only classification;
- a communication send can never be passthrough;
- approval/local virtualization require a reviewed adapter;
- a policy update and the approval event must share one durable boundary so a
  "successful" approval cannot exist without the applied policy version.

Rollback is another reviewed, versioned policy change with its own actor and origin.
The current web actions promote an exact tool to `approval` or eligible
`passthrough`; they are not a general policy editor. Do not hand-edit history,
restore an older YAML file, or invent a downgrade path that diverges from the
durable ledger. A deny/demotion workflow must use the same proof, version, file,
ledger, and publication guarantees before it is exposed.

## Offline onboarding workflow

The helpers in `signet.operations` are intentionally local-only. They do not open a
socket, invoke an MCP server, inspect the home directory, or discover a credential.
An authorized operator or separate reviewed capture tool must first save a complete
secret-free `tools/list` response as a local fixture.

All commands create mode-0600 output exclusively and refuse to overwrite it.

### 1. Normalize discovery

Accepted input is either `{"tools": [...]}` or a complete MCP result
`{"result": {"tools": [...], "nextCursor": null}}`. A non-null cursor is rejected
because reviewing only the first page is unsafe.

```console
uv run python -m signet.operations capture-discovery \
  --alias example \
  --input ./review/tools-list.raw.json \
  --output ./review/example.discovery.json
```

The output preserves every exact Tool definition, adds its runtime-compatible
digest, records `network_used: false`, bounds size/depth/tool count, rejects
duplicate names and duplicate JSON keys, and rejects obvious secret-like values.
It is still the operator's responsibility to ensure the source fixture contains no
credential, provider data, or sensitive example/default value.

### 2. Generate classification hints

```console
uv run python -m signet.operations classify \
  --capture ./review/example.discovery.json \
  --output ./review/example.classification.json
```

Hints use tool-name words and MCP read/destructive annotations. Every entry has
`review_status: human_required`, `automatic_enablement: false`, and
`generated_mode: deny`. A likely-write or send-like entry explicitly requires an
adapter review and reconciliation characterization before approval can be proposed.

Reviewers must read the complete schema and provider semantics. "List" operations
may mutate cursors or mark records read; "create draft" may create a remote object;
"search" may execute arbitrary query plugins. Heuristics never settle those facts.

### 3. Generate an all-deny policy

```console
uv run python -m signet.operations generate-policy \
  --capture ./review/example.discovery.json \
  --transport http \
  --output ./review/example.policy.yaml
```

For HTTP, replace the generated `https://example.replace.invalid/mcp` only after
endpoint review. For stdio, replace the generated `configured-example-launcher`
with an exact launcher reference. The credential field remains a Keychain
reference. Every discovered tool is explicitly denied and the global default is
deny. Promote entries one at a time only after review.

### 4. Build fake-adapter contract input

Create fake arguments containing no real target or credential:

```console
uv run python -m signet.operations fake-contract-input \
  --capture ./review/example.discovery.json \
  --tool send_item \
  --arguments ./review/send-item.fake-arguments.json \
  --output ./review/send-item.fake-contract.json
```

The helper validates the arguments against the captured input schema and creates an
explicit `fake:<alias>:<tool>` fixture. A generic fake-provider harness must report
downstream call counts for validation, durable queueing, denial, expiry,
cancellation, stale approval, and approval. The required counts are zero for every
pre-approval/terminal-no-send scenario and exactly one for approval.
The report must also include `network_used: false`; the verifier propagates that
marker and fails a network-using report even when all counts match.

```console
uv run python -m signet.operations verify-fake-contract \
  --contract ./review/send-item.fake-contract.json \
  --report ./review/send-item.fake-report.json \
  --output ./review/send-item.fake-result.json
```

The verifier accepts only `provider: fake`, requires the report to bind the exact
fixture identity, rejects missing/extra scenarios, and exits `2` on any mismatch.
It does not invoke the adapter itself; the test harness produces the report and is
responsible for truthfully reporting network use.

### 5. Review the adapter

For a new approval adapter, require tests for:

- exact input validation and canonical executable payload;
- bounded, escaped web summary/detail with complete targets and attachments;
- no external draft/upload/mutation before approval;
- deterministic safe result metadata with no raw provider content;
- definite failure versus unknown outcome classification at each boundary;
- an exact read-only reconciliation allowlist and bounded schedule, or explicit
  unconditional `inconclusive`;
- stable provider idempotency-key semantics before enabling a single redispatch;
- staged-file confinement, hash verification, MIME/size bounds, and purge behavior;
- duplicate invocation, stale edit, expiry, denial, cancellation, crash recovery,
  and fake-provider call-count tests;
- credential resolution only inside Signet and absence from args/env/logs/results.

Communication sends remain approval-mode even after the adapter passes.

## Metadata-only bypass audit

The operations module evaluates supplied inventory; it never scans live paths. A
reviewer builds a JSON document with:

- `fixture_version: 1` and `source: provided_metadata_only`;
- `coverage` containing every required kind with `complete`, `not_applicable`, or
  `unknown`;
- `records` containing exactly `kind`, `name`, `location`, `status`, `capability`,
  and `route`.

Required kinds cover active and disabled Hermes profiles, configs, environment
files, launchd plists, cron, scripts, skills, backups, browser sessions, native
adapters, terminal paths, SDK paths, JMAP paths, webhooks, shell environment,
direct MCP URLs, and credential references. The fail-closed skeleton is
`deploy/operations/bypass-inventory.blocked.example.json`.

Allowed record enums:

```text
status:     active | disabled | present | absent | unknown
capability: write | send | credential | provider_session | read_only | unknown
route:      signet | direct | not_applicable | unknown
```

The output contains finding names, locations, kinds, and reasons only. It rejects
extra "value" fields, secret-like text, and fingerprint-like strings. Unknown
coverage, an unresolved active record, or an active write/send/credential/session
path not routed through Signet makes the audit non-clean and exits `2`.

```console
uv run python -m signet.operations audit-bypasses \
  --inventory ./review/bypass-inventory.json \
  --output ./review/bypass-report.json
```

A clean report proves only that the supplied metadata is internally complete and
contains no declared bypass. It cannot prove the host inventory was accurate.

## Cutover readiness

Readiness combines the normalized capture, a complete reviewed manifest, a JSON
array of verified fake-contract results, the bypass report, and explicit human/live
evidence. The manifest partitions every captured tool into an exact mode and binds
its digest:

```json
{
  "schema_digests": {
    "list_items": "<reviewed lowercase SHA-256>",
    "send_item": "<reviewed lowercase SHA-256>"
  },
  "modes": {
    "list_items": "passthrough",
    "send_item": "approval"
  }
}
```

`fake-results.json` is an array containing the exact output of
`verify-fake-contract` for every tool whose reviewed mode is `approval`. Missing,
duplicate, extra, wrong-alias, wrong-digest, failed, or network-using results block
the packet.

```console
uv run python -m signet.operations cutover-readiness \
  --capture ./review/example.discovery.json \
  --review-manifest ./review/example.review-manifest.json \
  --fake-results ./review/fake-results.json \
  --bypass-report ./review/bypass-report.json \
  --live-evidence ./review/live-evidence.json \
  --output ./review/cutover-readiness.json
```

The command is deliberately advisory and always exits `2`; it can never authorize
or activate live cutover. Its report has `ready: false` and
`authorizes_live_changes: false` in every case. `inputs_complete: true` and
`disposition: human_review_required` mean only that all local checks below passed
and a human can review the referenced external records. Missing or invalid input
yields `inputs_complete: false` and `disposition: blocked`.

Completeness requires all schema digests and modes to match, fake contracts for
every approval-mode tool to pass without network use, the metadata-only bypass
report to be clean and fully covered, and every following prerequisite to have
`present: true` plus a non-secret change-record reference:

- human cutover authorization;
- web authenticator enrollment;
- downstream credential enrollment;
- live schema digest review;
- human review of the current bypass inventory;
- verified backup restore drill;
- approved route diffs;
- Funnel disabled for the Signet listener.

Omitting `--live-evidence` is valid for CI and produces a blocked report. The
supplied blocked skeleton in `deploy/operations/` must not be changed merely to make
automation green. Those entries become present only after the real human/live
ceremony documented in `deployment.md`, and their text is not independently
verified by this offline helper. A human reviews the records; automation must never
use this report as an enablement flag.
