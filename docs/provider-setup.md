# Connect and review a provider

Provider setup is separate from `signet setup` because it crosses real provider
boundaries. The installation and owner ceremony must be complete first. Providers are
disabled until this attended flow succeeds.

## Before the live test

Run these **read-only** checks:

```console
signet doctor
signet provider status
```

Confirm that you are on the intended host and owner account. Choose a sender/account
and a test recipient you control. The test recipient will receive a real message.

Do not put provider credentials in command arguments, YAML, Hermes configuration,
shell history, logs, tickets, screenshots, or chat. Signet stores a secret reference
in configuration and puts the value directly in the operating-system keyring.

## Fastmail

Fastmail is supported on macOS arm64, Linux x86_64, and Linux arm64.

```console
signet provider setup fastmail
```

**Human-only and live:** the command asks for confirmation, prompts without echo for
the API token, prompts for sender and test recipient, discovers the live MCP schemas,
sends one test email, installs the reviewed schemas and policy, and enables the
provider rollout. Stop if any displayed account, server identity, schema, or recipient
is not the one you intended.

For an already private secret-broker pipeline, `--token-stdin` reads exactly one token
line. Do not use shell interpolation or a here-document that records the token. The
interactive hidden prompt is the normal path.

## WhatsApp

WhatsApp is supported only on Linux x86_64 with the reviewed `wacli 0.12.0` artifact.

```console
signet provider setup whatsapp
```

**Human-only and live:** Signet confirms the reviewed download and digest, opens an
attended WhatsApp pairing ceremony, prompts for the test recipient, sends one test
message, installs the reviewed schemas and policy, and enables the rollout. macOS and
Linux arm64 refuse this path.

## What policy provider setup installs

The packaged 0.1 provider policy is deliberately narrow:

- Fastmail `send_email` uses transparent `approval`.
- Fastmail `search_email` uses reviewed read-only `passthrough`.
- WhatsApp `send_text` and `send_file` use transparent `approval`.
- Discovered tools outside those reviewed cases remain `deny`.

Transparent approval returns `pending_approval` after the exact request is durably
queued. It does not claim a send occurred. The provider mutation happens only after a
fresh human approval of that frozen request version.

`approval_optimistic` is a distinct architecture contract: it may return a captured,
upstream-compatible success shape while the real provider mutation is still pending,
but only when exact compatibility is proven. It is not a selectable packaged-provider
mode in 0.1. `virtualize_local` is also distinct and never performs a provider effect.
See [Security and approval semantics](security.md) and the [policy guide](policy-guide.md).

## Inspect, disable, or re-enable

```console
signet provider status
signet provider disable fastmail
signet provider enable fastmail
```

Substitute `whatsapp` on a supported configured host. The rollout gate is shared, so
enable and disable output lists every configured alias affected. Disabling blocks new
provider dispatch but does not erase credentials, policy, pending records, or evidence
about possibly completed effects.

If setup or startup health verification fails, Signet restores the disabled
configuration. Correct the reported condition and rerun the guided setup; do not
manually patch generated policy, connector identity, credential references, or rollout
state.

Re-running provider setup converges the same connector and policy records, but it is
not a read-only status check: after confirmation it can perform another live test send.
Use `signet provider status` when you only need to inspect state.

## Bypass warning

Signet governs only the MCP routes that point through it. Direct provider scripts,
old Hermes routes, native integrations, browser sessions, and webhooks can bypass the
approval boundary. Inventory and remove direct mutation routes only after the Signet
route and rollback plan have been reviewed. The expert
[connector boundary](production-connectors.md) documents schema pinning, identity,
reconciliation, and cutover rules.
