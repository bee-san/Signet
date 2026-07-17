# Plugin readiness boundary

This report states the release boundary for Signet's generic MCP plugin system.
It is intentionally a negative readiness result: manifests, discovery snapshots,
effect proposals, authenticated reviews, and fake worker contracts do not prove
that provider dispatch is safe.

```text
readiness_report_version=1
live_dispatch_enabled=false
reference.fastmail.provider_effect_count=0
reference.telegram.provider_effect_count=0
reference.whatsapp.provider_effect_count=0
```

Those values are release invariants. The three reference integrations must finish
their fixture and fake-contract tests with `provider_effect_count=0`; a test that
sends, edits, moves, deletes, invites, removes, promotes, uploads, or otherwise
changes a provider is a failure, not readiness evidence.

## What version 1 is ready for

- Validating and installing bounded local manifests against a separately supplied
  canonical SHA-256 pin.
- Persisting canonical manifest bytes and digest without accepting credentials.
- Recording non-secret connector configuration and credential-generation digests
  while retaining Keychain references instead of values.
- Ingesting local fake `tools/list` fixtures by default.
- Explicit, bounded live MCP initialization and paginated `tools/list` discovery
  for schema review only.
- Persisting exact tool definitions, effect evidence, disagreements, schema drift,
  removals, and append-only human conclusions.
- Requiring a fresh existing passkey or TOTP proof for each effect review.
- Running optional hash-pinned workers on synthetic onboarding fixtures over the
  bounded canonical JSON-lines protocol.
- Exercising Fastmail, Telegram, and WhatsApp reference contracts with zero
  provider effects.

These capabilities support review and staging only. A recommendation of
`passthrough` or `approval` is inert metadata and does not alter an executable
policy.

## Capabilities intentionally absent

- No plugin path can issue MCP `tools/call`.
- No plugin or connector command activates live dispatch.
- No extension worker receives a credential, encryption key, attachment path,
  database handle, downstream client, or live provider outcome.
- No manifest is fetched from a URL, Git repository, package index, or online
  marketplace.
- No Python entry point is imported into the Signet process.
- No WhatsApp CLI is invoked directly; it requires a separately reviewed MCP shim.
- No MCP annotation, name heuristic, plugin proposal, schema match, or human effect
  review automatically enables a tool.
- No `idempotentHint` or reviewed idempotence value authorizes automatic retry.
- No reference plugin is provider-ready merely because its fake contract passes.

The current `GenericJSONAdapter` remains suitable only for staged ordinary-write
contracts and is dispatch-disabled. It is not the fallback for dangerous or
provider-sensitive operations.

## Per-reference status

| Reference | Staged coverage | Readiness boundary |
| --- | --- | --- |
| Fastmail | Search/read, send, move, and delete mappings with a fake MCP fixture | `provider_effect_count=0`; no live JMAP/MCP client, destructive adapter, credential scope, or reconciliation proof |
| Telegram | Send/edit/delete message and membership/administrator mappings with a fake MCP fixture | `provider_effect_count=0`; no live Bot API/MTProto client, administrator adapter, credential scope, or reconciliation proof |
| WhatsApp | Text/media mappings for an inert MCP stdio shim contract around a CLI boundary | `provider_effect_count=0`; no direct CLI integration, live shim, media boundary authorization, credential scope, or reconciliation proof |

## Requirements before any future live release

A later release must not flip `live_dispatch_enabled` merely because the generic
staging tests pass. At minimum it needs all of the following, scoped to each exact
provider action:

1. An explicit release decision and independent security review of the expanded
   threat model and trusted computing base.
2. A sandbox and process/network boundary appropriate to the provider adapter,
   including reviewed executable provenance where a process is involved.
3. Least-privilege, action-scoped credential brokering with generation tracking,
   rotation, revocation, and proof that plugin and worker code cannot read the raw
   credential outside the reviewed boundary.
4. A live server-identity and complete `tools/list` capture whose exact tool name,
   description, annotations, schema, server identity, connector configuration,
   plugin version, and manifest digest receive fresh human review.
5. A provider-specific adapter for every destructive, administrator,
   code-execution, attachment, payment, or reconciliation-sensitive operation.
   The adapter must validate a frozen action-specific contract rather than accept
   arbitrary JSON.
6. Fenced dispatch, provider idempotency analysis, safe outcome classification,
   crash characterization, and bounded reconciliation that never turns ambiguity
   into a blind retry.
7. Provider-specific redaction and safe-result rules, attachment and size limits
   where relevant, audit coverage, retention behavior, cancellation tests, and
   credential-leak tests.
8. End-to-end tests against an authorized isolated provider sandbox, followed by a
   separate human cutover procedure. Fake fixtures remain in the suite and must
   continue to report zero real provider effects.

Until those requirements are implemented and reviewed, the authoritative status
remains:

```text
live_dispatch_enabled=false
```

See the [staged plugin integration guide](plugin-integrations.md) for the exact
manifest, configuration, CLI, discovery, review, and worker contracts.
