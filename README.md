# Signet

[![CI](https://github.com/bee-san/Signet/actions/workflows/ci.yml/badge.svg)](https://github.com/bee-san/Signet/actions/workflows/ci.yml)

Signet is a provider-neutral MCP human approval gateway. A configured write call
returns an honest `pending_approval` result only after the exact executable
payload, expiry, origin namespace, and byte-identical acknowledgement are durable.
That acknowledgement never claims the external action succeeded. The downstream
mutation remains unsent until a fresh human confirmation authorizes the frozen
request version.

The first reviewed adapters cover Fastmail email and an owned `wacli` WhatsApp
wrapper. The core is generic: exact MCP schemas are mirrored behind four policy
modes, immutable payloads are encrypted, approval transitions are persisted in
SQLite, dispatch is fenced, ambiguous delivery enters bounded reconciliation, and
the authenticated web app presents the private review queue.

## Safety status

This repository is in no-live implementation mode. Tests use explicit `fake:*`
identities and fake downstreams. No repository command enrolls a passkey or TOTP,
reads a live credential, sends a real message, changes a Hermes profile, installs
a launchd job, changes Tailscale Serve, or performs cutover.

The files under `deploy/` are inert review templates. Their placeholders prevent
installation without review. The installed `signet deployment` commands provide a
runnable downstream-disabled staging assembly: it has no provider transport,
credential resolver, dispatch worker, or downstream MCP alias. Its authenticated
`approvals` tools all return `deployment_disabled`. This is not a live deployment
or a substitute for deferred human setup and cutover. `signet.operations` consumes
local, bounded fixtures only; it has no discovery network client or host scanner.

## Guarantees

- Unknown tools resolve to `deny`. A tool is exposed only after exact schema
  capture, policy configuration, and digest review.
- `approval` tools make zero downstream calls before approval and return the
  normative pending shape in `spec/fixtures/gateway-pending-result.json`.
- A fresh TOTP proof or WebAuthn assertion is bound to one action, request,
  immutable version, and payload hash, then consumed transactionally.
- The MCP TOTP path can approve a normal caller-owned request, but cannot deny,
  edit, retry, manage credentials, or approve a policy change.
- Dispatch crosses a durable fenced boundary before network I/O. A possible
  post-dispatch crash becomes `outcome_unknown`, never a blind retry.
- Push messages contain category and count information only. The authenticated
  queue remains authoritative if push delivery fails.
- Provider credentials are references such as `keychain://Signet/fastmail`, not
  values accepted by normal configuration models.
- The MCP listener is loopback-only. The separately bound web app supplies its own
  login, sessions, CSRF validation, action confirmation, and security headers.

These controls protect managed MCP routes. They do not prevent a malicious process
running as the same operating-system user from reading that user's files, memory,
or Keychain items, and they cannot govern direct provider scripts, native adapters,
browser sessions, webhooks, or other paths that bypass Signet. See
[`docs/security-model.md`](docs/security-model.md).

## Development

Signet requires Python 3.12 and uses `uv`.

```console
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run mypy
```

The package entry point serves only an explicitly supplied application factory:

```console
uv run signet serve-mcp --factory deployment.assembly:create_mcp_app \
  --host 127.0.0.1 --port 8789
uv run signet serve-web --factory deployment.assembly:create_web_app \
  --host 127.0.0.1 --port 8790
```

Those example factories remain deployment responsibilities. The MCP command rejects
a non-loopback numeric host. Do not point an ad hoc factory at live credentials.

## Downstream-disabled deployment staging

Create private, persistent staging state without enrolling a human credential or
creating a downstream client:

```console
install -d -m 0700 "$HOME/.hermes/services/signet/config"
uv run signet deployment init \
  --config "$HOME/.hermes/services/signet/config/disabled.json" \
  --data-dir "$HOME/.hermes/services/signet/data" \
  --namespace profile:hermes
uv run signet deployment validate \
  --config "$HOME/.hermes/services/signet/config/disabled.json"
uv run signet deployment serve-mcp \
  --config "$HOME/.hermes/services/signet/config/disabled.json"
```

Issue a random MCP caller token with `signet deployment token issue`. The command
prints only the raw token, exactly once, so redirect it directly into the intended
new mode-`0600` secret mechanism with shell `noclobber`; do not overwrite the active
secret or paste it into a command argument, config file, shell history, log, or
documentation. `token list` returns metadata only. `token
revoke` takes effect on the next authentication check. `token rotate` stages and
prints a linked replacement while deliberately leaving the old token valid; install,
reload, and test the replacement before explicitly revoking the old token.

The optional `init` human-auth context flags validate only the exact HTTPS origin,
RP ID, and user ID. `deployment auth-status` reads counts, not credential material.
Neither command enrolls anything. A passkey requires a real browser/authenticator
ceremony at the final HTTPS origin and cannot be created by an offline CLI. See
[`docs/deployment.md`](docs/deployment.md).

## Fake-only operator path

[`docs/operator-runbook.md`](docs/operator-runbook.md) is the start-to-finish path
for a disposable local demo, Hermes profile wiring, verification, troubleshooting,
backup/restore drills, and rollback. The demo uses explicit fake identities and
network-disabled providers; it is not evidence of passkey/TOTP enrollment, live
schema review, provider readiness, or cutover authorization.

From the repository root, the minimal fake-only path is:

```console
export SIGNET_DEMO_DIR="$PWD/var/operator-demo"
test ! -e "$SIGNET_DEMO_DIR"
uv run signet demo init --data-dir "$SIGNET_DEMO_DIR"
uv run signet demo smoke --data-dir "$SIGNET_DEMO_DIR"
uv run signet demo serve --data-dir "$SIGNET_DEMO_DIR"
```

`demo init` refuses every existing path, `smoke` is offline unless `--live` is explicit,
and `serve` binds both demo apps to numeric loopback. The generic `serve-*` factory
interface remains deployment-owned. Hermes templates stay inert; the runbook uses a
new blank profile and a validated structured merge instead of editing an existing
profile.

## Offline onboarding

Operational helpers are available without adding another console entry point:

```console
uv run python -m signet.operations --help
```

They normalize a previously captured local `tools/list` fixture, add advisory
read/write hints, generate an all-deny policy, create and verify fake-adapter test
inputs, evaluate a caller-supplied names-and-locations-only bypass inventory, and
produce a fail-closed cutover readiness report. Output files are created once with
mode `0600`; existing files are never overwritten.
The readiness report is advisory: it always keeps `ready` and
`authorizes_live_changes` false, even when its supplied evidence packet is complete.

## Repository map

- `spec/` contains executable policy, provider-input, pending-result, and gateway
  tool schema fixtures.
- `src/signet/` contains canonicalization, encryption, persistence, authentication,
  MCP mirroring, gateway, adapters, web UI, notifications, backup, and operations.
- `tests/` contains contract, adversarial, durability, authentication, adapter,
  runtime, web, backup, and offline operations coverage.
- `docs/` contains the MCP tool reference, security model, deployment guide, and
  policy/onboarding guide.
- `deploy/` contains secret-free launchd, Homepage, Tailscale, Hermes, and readiness
  staging material. It changes nothing by itself.

## Documentation

- [MCP approval tools](docs/mcp-approval-tools.md)
- [Security model](docs/security-model.md)
- [Policy and adapter onboarding](docs/policy-guide.md)
- [Deployment, backup, restore, and rollback](docs/deployment.md)
- [No-live operator and Hermes runbook](docs/operator-runbook.md)

The implementation contract and deferred human-only ceremony are recorded in
[`2026-07-14-signet-approval-gateway-plan.md`](2026-07-14-signet-approval-gateway-plan.md).
