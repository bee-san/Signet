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

## Production quick start

The normal installation does not require a source checkout, `uv`, hand-edited YAML,
or a bearer token copied into a shell command. It requires Python 3.12, `pipx`, a
logged-in Tailscale node with MagicDNS, and Hermes Agent. Signet installs user
services: launchd on macOS or systemd on Linux.

Supported package targets are macOS arm64, Linux x86_64, and Linux arm64. Fastmail
is available on all three. WhatsApp is available only on Linux x86_64 through the
reviewed `wacli 0.12.0` artifact. See the [setup guide](docs/setup.md) for the full
prerequisite and storage checklist.

1. Install the reviewed package and confirm its version:

   ```console
   pipx install 'signet-gateway==0.1.0'
   signet --version
   ```

   This command names the stable release reviewed by this documentation. For a later
   release, substitute only the exact version named in its signed release notes; do not
   install an unreviewed latest build.

2. Run setup as the operating-system user who will own the services and secrets:

   ```console
   signet setup
   ```

   Signet prints a read-only plan before asking permission to apply it. It then prints
   the exact private HTTPS address, normally
   `https://<tailscale-node-name>:8443/setup`, and opens it. That address is clickable
   in capable terminals. If no browser opens, copy only the URL into a browser on the
   same tailnet; never copy the capability value into YAML, shell history, or chat.

3. **Human-only:** at that exact URL, unlock owner setup from the private capability
   file named by the CLI, create a password, and enroll a passkey or a fresh TOTP
   authenticator. Finish setup only after reviewing the owner, origin, and profiles.

   One user may manage multiple independently enrolled, named TOTP authenticators and
   multiple named passkeys. Do not scan one TOTP seed onto several devices and treat
   them as independent recovery factors. After first setup, use this command to reach
   authenticator management:

   ```console
   signet authenticators open
   ```

4. Review the generated MCP entries, then run `/reload-mcp` in each selected Hermes
   profile. Signet never restarts the Hermes gateway. Verify the installation:

   ```console
   signet status
   signet doctor
   signet provider status
   ```

`doctor` exits nonzero if a required check fails. Providers remain disabled until a
separate attended setup.

### Choose the owner and Hermes profiles

An installation has one owner identity. When options are omitted, Signet uses
`user:owner` and discovers the default and named Hermes profiles. To integrate only
selected profiles, repeat `--profile`:

```console
signet setup --owner user:owner --profile personal --profile work
```

Each profile receives a separate private caller credential and namespace, but this
packaged setup binds every selected profile to the same owner. Version 0.1 does not
ship a supported cross-user enrollment or role-management command; do not add users
by editing the database or generated configuration. Use a separate operating-system
account or host when people require a hard isolation boundary.

### Connect a provider

Provider setup is intentionally separate because it crosses a live-effect boundary:

```console
signet provider setup fastmail
signet provider status
```

**Human-only and live:** Fastmail setup prompts without echo for the API token, asks
for the sender and test recipient, performs one test send, installs reviewed schemas
and policy, and enables the provider rollout. On supported Linux x86_64 hosts,
`signet provider setup whatsapp` downloads the reviewed artifact, requires an
attended pairing ceremony, and sends one test message. Do not put provider tokens in
arguments, YAML, command history, logs, or chat. Read the
[provider setup guide](docs/provider-setup.md) before confirming either command.

### Understand approval results

The packaged provider policy is **transparent approval** for sends: the agent receives
an honest `pending_approval` result after durable queueing, and the provider mutation
does not occur until a human approves the frozen request. `approval_optimistic` is a
different, conditional contract in which a proven upstream-compatible success-shaped
acknowledgement may be returned while the real mutation remains pending. It is not a
selectable packaged-provider mode in 0.1. Unknown, dangerous, or dependency-heavy
tools must deny or use transparent approval. `virtualize_local` is separate and never
performs a provider effect. See the [plain-language security guide](docs/security.md)
and [policy guide](docs/policy-guide.md).

### User and operator guides

- [Documentation map](docs/README.md)
- [Install and first setup](docs/setup.md)
- [Resume interrupted setup](docs/setup-resume.md)
- [Provider connection and review](docs/provider-setup.md)
- [Status and doctor](docs/health-and-doctor.md)
- [Backup and restore](docs/backup-and-restore.md)
- [Upgrade and safe rollback boundaries](docs/upgrade-and-rollback.md)
- [Uninstall or purge](docs/uninstall.md)
- [Lost authenticators and recovery](docs/recovery.md)
- [Low disk and external state roots](docs/storage.md)
- [Security model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

The [expert operator runbook](docs/operator-runbook.md),
[production runtime contract](docs/production-runtime.md), and
[connector boundary](docs/production-connectors.md) remain available for audits and
incident work. Generic connectors remain staged behind the
[plugin integration contract](docs/plugin-integrations.md) and
[plugin readiness boundary](docs/plugin-readiness.md). None of these expert references
is a prerequisite for a normal package installation.

## Production guarantees

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
- Production retains exhausted unknown content indefinitely. The demo-only
  redaction drill is marker-guarded fake functionality, preserves "may have sent",
  and is not production human authorization.
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

The Python distribution is named `signet-gateway`; the import package and command
remain `signet`. The complete supported-platform runtime dependency closure and
build backend closure are pinned to the reviewed versions. The supported platforms
are Linux and macOS; the CLI fails closed elsewhere.

Stable version tags matching the project version must point to reviewed `main`
history with successful exact-commit CI, then trigger reproducible native Linux
x86_64, Linux arm64, and macOS arm64 wheel builds plus a source distribution. The
release workflow inspects the exact package and dependency closure, emits CycloneDX
runtime SBOM, license, build-evidence, and checksum artifacts, verifies Sigstore OIDC
signatures and GitHub provenance/SBOM attestations, and reaches PyPI trusted
publishing only through a protected environment. Release actions and tooling are
commit- or lock-pinned. Maintainers must follow the
[release procedure](docs/releasing.md); its dry run never publishes or consumes a
package-index version.

Signet requires Python 3.12 and exact `uv` version `0.11.28`. Install that version
with `pipx install 'uv==0.11.28'` or the official versioned
[`uv` installer](https://docs.astral.sh/uv/getting-started/installation/); inspect a
downloaded installer before executing it and do not substitute the unversioned
installer. The repository pins `uv`-managed Python 3.12.13 because its bundled
SQLite satisfies Signet's 3.51.3 safety floor.

Developers extending the provider-neutral onboarding path should start with the
[manifest, connector, discovery, review, and worker contracts](docs/plugin-integrations.md).
The companion [readiness report](docs/plugin-readiness.md) lists the capabilities
that remain intentionally absent and the prerequisites for any future live work.

```console
(
  set -e
  UV_VERSION="$(uv --version)"
  case "$UV_VERSION" in
    "uv 0.11.28"|"uv 0.11.28 "*) ;;
    *) printf 'expected uv 0.11.28, received %s\n' "$UV_VERSION" >&2; exit 1 ;;
  esac
  uv python install 3.12.13
  uv sync --frozen
  uv lock --check --project deploy/hermes/runtime
  uv run playwright install --with-deps chromium
  uv run pytest -q
  uv run ruff check .
  uv run mypy
)
```

The reviewed local stdio boundary requires Linux with `/proc/self/fd`. Guided
WhatsApp setup therefore supports Linux x86_64 and installs the pinned
`wacli 0.12.0` Linux artifact. macOS arm64 supports the packaged service and Fastmail,
but local WhatsApp activation remains unsupported.
On Linux, Signet also uses the kernel-owned `/proc/self/fd` view to change the mode
of an already-held mode-`000` directory without reopening an attacker-controlled
path. It fails closed if procfs is unavailable. macOS instead uses a verified
parent descriptor and a one-component, no-follow `fchmodat` operation, then opens
and revalidates the expected directory. It never retries an unanchored path.

The generic package entry point serves only an explicitly supplied application
factory. After creating the disabled state below, run its two shipped factories in
separate terminals. In terminal A:

```console
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
export SIGNET_DISABLED_CONFIG="$SIGNET_SERVICE_ROOT/config/disabled.json"
uv run signet serve-mcp --factory signet.deployment:create_mcp_app \
  --host 127.0.0.1 --port 8789
```

In terminal B:

```console
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
export SIGNET_DISABLED_CONFIG="$SIGNET_SERVICE_ROOT/config/disabled.json"
uv run signet serve-web --factory signet.deployment:create_web_app \
  --host 127.0.0.1 --port 8790
```

`SIGNET_DISABLED_CONFIG` is the absolute non-secret config path, not configuration
JSON or a credential. The dedicated `signet deployment serve-*` commands below are
preferred because they use the verified listener settings from that file. The MCP
command rejects a non-loopback numeric host. Do not point an ad hoc factory at live
credentials.

## Downstream-disabled deployment staging

Create private, persistent staging state without enrolling a human credential or
creating a downstream client:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
  export SIGNET_DISABLED_PROFILE=signet-disabled
  uv run signet deployment init \
    --config "$SIGNET_SERVICE_ROOT/config/disabled.json" \
    --data-dir "$SIGNET_SERVICE_ROOT/data" \
    --namespace "profile:$SIGNET_DISABLED_PROFILE"
  uv run signet deployment validate \
    --config "$SIGNET_SERVICE_ROOT/config/disabled.json"
  uv run signet deployment serve-mcp \
    --config "$SIGNET_SERVICE_ROOT/config/disabled.json"
)
```

One initialized disabled state supports exactly that one dedicated Hermes profile;
the CLI does not add principals to an existing config. Follow the tested
[`deploy/hermes/README.md`](deploy/hermes/README.md#persistent-downstream-disabled-profile)
sequence to create the blank profile and stream `token issue` directly into the
checked-in atomic configurator. The raw token is accepted only on stdin and is never
written to YAML or output by the helper. Do not paste it into an argument, shell
history, log, chat, or documentation. `token list` returns metadata only. `token
revoke --token-id=TOKEN_ID` takes effect on the next authentication check. `token
rotate --token-id=TOKEN_ID` stages and
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
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
  test ! -e "$SIGNET_DEMO_DIR" && test ! -L "$SIGNET_DEMO_DIR" || exit 1
  uv run signet demo init --data-dir "$SIGNET_DEMO_DIR"
  uv run signet demo smoke --data-dir "$SIGNET_DEMO_DIR"
  uv run signet demo seed-request --data-dir "$SIGNET_DEMO_DIR"
  uv run signet demo serve --data-dir "$SIGNET_DEMO_DIR"
)
```

The physical home path is required because private demo paths reject symlinked
ancestors. `demo init` refuses every existing destination and never creates parent
directories. `smoke` is offline unless `--live` is explicit, and
`serve` binds both demo apps to numeric loopback. The generic `serve-*` factory
interface remains deployment-owned. Hermes templates stay inert; the runbook uses a
new blank profile and a validated structured merge instead of editing an existing
profile. Agents other than Hermes should follow the
[provider-neutral MCP client guide](docs/mcp-client-integration.md); that guide does
not turn the fake or downstream-disabled assembly into a live deployment.
`seed-request` must run while the server is stopped. It admits a realistic fake
email through the real gateway pipeline, returns only safe request metadata, and
makes the complete context immediately reviewable without an LLM, Hermes profile,
provider credential, or network call.

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
- [Provider-neutral MCP agent integration](docs/mcp-client-integration.md)
- [Security model](docs/security-model.md)
- [Policy and adapter onboarding](docs/policy-guide.md)
- [Staged plugin integrations](docs/plugin-integrations.md)
- [Plugin readiness boundary](docs/plugin-readiness.md)
- [Deployment, backup, restore, and rollback](docs/deployment.md)
- [Production runtime and lifecycle architecture](docs/production-runtime.md)
- [Productionisation plan and acceptance matrix](docs/plans/2026-07-17-signet-productionization-plan.md)
- [No-live operator and Hermes runbook](docs/operator-runbook.md)

The current productionisation plan and acceptance matrix are recorded in
[`docs/plans/2026-07-17-signet-productionization-plan.md`](docs/plans/2026-07-17-signet-productionization-plan.md).
The earlier generic approval-gateway plan remains in
[`2026-07-14-signet-approval-gateway-plan.md`](2026-07-14-signet-approval-gateway-plan.md).
