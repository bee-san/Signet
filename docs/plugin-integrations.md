# Staged plugin integrations

Signet's version 1 plugin system is an onboarding and review surface, not a live
provider runtime. It accepts local, operator-supplied, SHA-256-pinned manifests,
records non-secret connector configuration, discovers exact MCP tool definitions,
and lets an authenticated human record effect conclusions. None of those steps
enables `tools/call`, installs a dispatch route, changes an active policy, or
authorizes a provider effect.

The normal extension tier is a strict data-only manifest. An optional advanced
tier can name a separately executed, hash-pinned worker, but Signet never imports
plugin Python entry points into its process. Plugins cannot be installed from a
URL, Git repository, package index, or online marketplace. Signet does not fetch
dependencies for them.

## Manifest contract

A manifest is one bounded UTF-8 JSON object with exactly these version 1 fields:

```json
{
  "plugin_manifest_version": 1,
  "plugin_id": "example.mail",
  "plugin_version": "1.0.0",
  "display_name": "Example Mail staged integration",
  "description": "Synthetic onboarding mappings for an MCP server.",
  "connectors": [
    {
      "connector_id": "mail",
      "display_name": "Example Mail MCP",
      "protocol": "mcp",
      "transports": ["streamable_http"],
      "requires_mcp_shim": false
    }
  ],
  "tool_mappings": [
    {
      "connector_id": "mail",
      "tool_name": "send_email",
      "action_id": "example.send_email",
      "display_label": "Send email",
      "sensitive_json_paths": ["/to", "/subject", "/body"],
      "safe_result_fields": ["/message_id"],
      "proposed_effects": {
        "mutation": "additive",
        "external_communication": true,
        "code_execution": false,
        "privilege_change": false,
        "open_world": true,
        "idempotent": "unknown"
      },
      "adapter_requirement": "provider_specific"
    }
  ]
}
```

`plugin_manifest_version` must be `1`. Plugin, connector, action, and tool
identifiers are exact names; mappings do not allow globs, regular expressions,
wildcards, traversal, or aliases. Every connector must be referenced by at least
one mapping, and connector IDs, exact `(connector_id, tool_name)` pairs, and action
IDs must be unique. `protocol` is exactly `mcp`; supported transports are
`streamable_http` and `stdio`.

Each mapping carries independent effect axes. `mutation` is one of `none`,
`additive`, `mutating`, `destructive`, or `unknown`. Each of
`external_communication`, `code_execution`, `privilege_change`, `open_world`, and
`idempotent` is `true`, `false`, or the string `"unknown"`. Sensitive and safe
result paths are exact JSON Pointers, not JSONPath expressions. The adapter
requirement is either `generic_json_staged` or `provider_specific`; both remain
dispatch-disabled in this release.

The optional root `worker` object has exactly this shape:

```json
{
  "command_ref": "reviewed-example-worker",
  "executable_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "protocol_version": 1,
  "operations": ["identity", "validate_schema", "canonicalize", "review_summary", "redact", "classify_fake_outcome"]
}
```

Only the operations actually supported by the worker should be listed. A manifest
contains an opaque reviewed command reference and executable digest, never an
executable path or command line.

Parsing rejects unknown fields, duplicate JSON keys at any depth, unsupported
versions, non-finite numbers, embedded credential-like text, ambiguous JSON paths,
duplicate identities, oversized input, and excessive depth or node count. The
identity used by Signet is the SHA-256 of the validated canonical JSON, not the
byte hash of the operator's whitespace and key ordering. Validation and install
therefore require the trusted canonical digest supplied out of band.

## Connector configuration

Connector configuration is another strict local JSON object. It never contains a
credential value. `credential_ref` is an exact Keychain reference, while
`credential_identity_digest` identifies the credential generation without
revealing it. A Streamable HTTP configuration is:

```json
{
  "connector_config_version": 1,
  "transport": "streamable_http",
  "credential_ref": "keychain://Signet/example-mail-staged",
  "credential_identity_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "url": "https://mail-mcp.example.invalid/mcp",
  "timeout_seconds": 30.0,
  "output_limit_bytes": 1048576
}
```

A stdio configuration replaces `url` with both `command_ref` and
`executable_sha256`:

```json
{
  "connector_config_version": 1,
  "transport": "stdio",
  "credential_ref": "keychain://Signet/example-mail-staged",
  "credential_identity_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "command_ref": "reviewed-example-mail-mcp",
  "executable_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "timeout_seconds": 30.0,
  "output_limit_bytes": 1048576
}
```

Transport-specific fields cannot be mixed. Cleartext HTTP is allowed only for a
loopback host; URLs cannot carry user information, query parameters, or fragments.
The configured transport must be allowed by the exact plugin connector template.
Signet computes, persists, and prints the canonical connector-configuration digest
when it configures an alias. There is no connector `--sha256` flag.

For live stdio discovery, the opaque command reference must resolve through a
separately reviewed, SHA-256-pinned command document. Its version 1 shape
is:

```json
{
  "reviewed_command_document_version": 1,
  "commands": [
    {
      "command_ref": "reviewed-example-mail-mcp",
      "executable": "/opt/signet/bin/example-mail-mcp",
      "executable_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "cwd": "/var/empty/signet-example-mail",
      "snapshot_root": "/opt/signet/bin",
      "args": []
    }
  ]
}
```

Paths are absolute and lexical, shell executables and secret-bearing arguments are
rejected, and the executable digest must match the connector configuration. This
document does not provide environment variables or credential values.

## Exact CLI lifecycle

The following is the complete staged lifecycle. `--database PATH` is optional on
stateful plugin and connector commands. If omitted, Signet uses
`$SIGNET_DATABASE_PATH`, then its standard data database. Use a separately trusted
canonical manifest digest; do not derive the expected value from an untrusted file
and then treat that comparison as review.

```console
export SIGNET_DATABASE_PATH="/absolute/private/path/signet.sqlite3"
export MANIFEST="./example-mail-manifest.json"
export MANIFEST_SHA256="<trusted-lowercase-canonical-sha256>"

uv run signet plugin validate "$MANIFEST" --sha256 "$MANIFEST_SHA256"
uv run signet plugin install "$MANIFEST" --sha256 "$MANIFEST_SHA256" \
  --database "$SIGNET_DATABASE_PATH"
uv run signet plugin list --database "$SIGNET_DATABASE_PATH"
uv run signet plugin show example.mail --database "$SIGNET_DATABASE_PATH"

uv run signet connector configure \
  --plugin example.mail \
  --connector mail \
  --alias example-mail-staged \
  --config ./example-mail-connector.json \
  --database "$SIGNET_DATABASE_PATH"

uv run signet connector discover example-mail-staged \
  --fixture ./example-mail-tools-list.json \
  --database "$SIGNET_DATABASE_PATH"
```

Fixture discovery is the default and expected path. The fixture is a local,
secret-free, complete MCP `tools/list` result, either `{"tools": [...]}` or
`{"result": {"tools": [...], "nextCursor": null}}`. Fixture discovery performs
no initialization, transport launch, credential lookup, or network access.

Live discovery is exceptional and requires the literal `--live-discovery` opt-in:

```console
uv run signet connector discover example-mail-staged \
  --live-discovery \
  --database "$SIGNET_DATABASE_PATH"
```

When the selected connector is stdio, supply the reviewed command document if the
assembled session requires it:

```console
uv run signet connector discover example-mail-staged \
  --live-discovery \
  --command-references ./reviewed-commands.json \
  --command-references-sha256 "<trusted-lowercase-canonical-sha256>" \
  --database "$SIGNET_DATABASE_PATH"
```

Live discovery is limited to MCP initialization followed by bounded, paginated
`tools/list`. The default bounds are 30 seconds overall, 32 pages, 512 tools, and
8 MiB aggregate data; repeated, empty, or oversized cursors fail closed. The
discovery client has no `tools/call`, sampling, elicitation, resources, or prompts
operation. A live flag does not broaden that interface.

Durable workspace cardinality is also bounded: at most 128 plugin IDs, 128
connector aliases, and 512 retained exact tool names per alias. A new identity
that would cross a bound is rejected before its transaction is recorded; existing
history is not truncated or silently hidden. Older plugin generations referenced
by a stale connector remain visible and denied in the web workspace.

After discovery, sign in to the assembled authenticated web application and open
`/integrations`. Review the exact server identity, tool description, annotations,
input schema, schema digest, classifier signals, plugin proposal, and any
disagreements. Every newly discovered or changed tool begins unreviewed and denied.
A removed tool is disabled. Schema or identity drift invalidates a prior mapping.

An operator can later disable the installed plugin explicitly:

```console
uv run signet plugin disable example.mail --database "$SIGNET_DATABASE_PATH"
```

Disabling is fail-closed. Reinstalling a new plugin version or manifest digest is a
new generation and does not inherit an old review.

## Evidence is not a conclusion

Signet records these inputs separately:

- MCP annotations supplied by the server. They are untrusted hints, including
  `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`.
- Conservative name and schema heuristics.
- The plugin's proposed effect profile and action identifier.
- The authenticated human's final effect profile.

No annotation, familiar name, description, plugin mapping, or previously known
schema digest activates a tool. Conflicts remain visible rather than being merged
away. A final review is bound to the plugin ID, plugin version, canonical manifest
digest, connector alias and configuration generation, discovered server identity,
exact tool name, exact tool-schema digest, and complete evidence snapshot. A
change to any bound material makes the review stale.

Recording the conclusion requires a fresh existing passkey or TOTP ceremony. The
review must fill all six axes. The conservative recommendation is:

- `passthrough` candidate only for a complete, closed-world,
  non-communicating read-only profile;
- `approval` candidate for an ordinary write or communication when all dangerous
  axes are explicitly false;
- `deny` for destructive, code-executing, privilege-changing, open-world,
  unknown, conflicting, or incomplete profiles.

The recommendation is review metadata in version 1, not an activated policy.
`idempotentHint` and a reviewed `idempotent=true` conclusion do not independently
authorize a retry.

## Extension-worker boundary

An optional worker runs as a separate hash-pinned executable over one canonical
JSON request line and one strictly validated canonical JSON response line. Signet
resolves its opaque command reference through reviewed configuration and verifies
the executable SHA-256 immediately before every launch. It does not import worker
code.

Version 1 workers receive synthetic onboarding fixtures only. They cannot receive
credential or encryption-key values, attachment paths, a database path or handle,
or a downstream client. The supported operations are identity handshake, schema
validation, deterministic canonicalization, review summary, redaction, and fake
outcome classification. Input, output, stderr, JSON depth, node count, scalar
size, and runtime are bounded. The child gets a temporary working directory and a
minimal fixed environment. Timeouts, cancellation, invalid JSON, protocol drift,
nondeterminism, executable replacement, or schema mismatch fail closed.

A worker is not a provider adapter and has no dispatch capability. It is not a
sandbox sufficient for hostile code; adding an executable expands the trusted
computing base and requires separate review.

## Reference plugins

The packaged Fastmail, Telegram, and WhatsApp plugins and their `tools/list`
documents are synthetic contract fixtures:

- Fastmail maps search/read, send, move, and delete actions.
- Telegram maps message send/edit/delete and membership/administrator actions.
- WhatsApp defines an inert MCP stdio shim around a CLI boundary. Signet supports
  one connector protocol, so a non-MCP WhatsApp CLI must remain behind that MCP
  shim. Text and media sends are communication writes.

They do not contact those providers. `GenericJSONAdapter` may describe staged
ordinary-write contracts but is dispatch-disabled. Future live destructive,
administrator, code-execution, attachment, payment, or
reconciliation-sensitive operations require a provider-specific adapter and the
additional prerequisites in the [plugin readiness report](plugin-readiness.md).
