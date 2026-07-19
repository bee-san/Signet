# Deployment guide

Signet runs two separately bound ASGI applications:

```text
Hermes / MCP client
  -> http://127.0.0.1:8789/mcp/<managed-alias>
  -> http://127.0.0.1:8789/mcp/approvals

Human browser
  -> private HTTPS reverse proxy
  -> http://127.0.0.1:8790 authenticated Signet web app
```

The MCP listener is always loopback-only and is never published to a LAN,
tailnet, or public Internet. The web listener is separate and performs its own
password/TOTP or passkey login, server-side session authorization, CSRF checks,
and fresh action confirmation. A proxy supplies TLS and reachability only.

## Current deployment status

This repository deliberately does not ship a live deployment factory or a
credential-enrollment command. It does ship a runnable, persistent
**downstream-disabled staging assembly** through `signet deployment`. That assembly
has no downstream transport, credential resolver, provider client, delivery worker,
or reconciliation worker. It publishes only the authenticated `approvals` MCP
namespace; all five normative tools return `deployment_disabled`, and downstream
paths such as `/mcp/fastmail` and `/mcp/whatsapp` do not exist. Its web process is a
loopback status page, not the authenticated approval application.

The same disabled apps are installed factories at
`signet.deployment:create_mcp_app` and `signet.deployment:create_web_app`. Factory
mode reads only the absolute non-secret config path from `SIGNET_DISABLED_CONFIG`.
The dedicated commands are preferred because they take their bind address and port
from the verified config instead of duplicating them on the command line.

Everything under `deploy/` is an inert, secret-free template. The launchd examples
contain nonexistent absolute-path placeholders and cannot start until the disabled
state and templates are reviewed. Nothing in the repository has:

- inspected a live Hermes, Tailscale, Homepage, launchd, Keychain, provider, or
  browser-session configuration;
- enrolled a passkey, password, or TOTP;
- captured or approved live provider schemas;
- installed or started a service;
- changed a Serve/Funnel route or Homepage card;
- replaced a Hermes route or removed a direct credential;
- sent a real email or WhatsApp message.

Those are deferred human-authorized cutover steps. Running the disabled staging
assembly or seeing a healthy process does not complete or authorize any of them.
Automated implementation and CI remain fake-provider/downstream-disabled.

For copy-pasteable fake-only startup, a disposable Hermes profile, command
verification, troubleshooting, and a restore drill, use
[`operator-runbook.md`](operator-runbook.md). Completing that runbook does not
satisfy any live prerequisite in this guide.
For another streamable-HTTP MCP agent, the
[provider-neutral client guide](mcp-client-integration.md) defines the route, token,
alias, tool-result, and status-polling contract without claiming a live assembly.

## Platform requirements

- macOS for the reference downstream-disabled launchd/Keychain deployment; local
  stdio and `wacli` activation are explicitly unsupported there and fail closed;
- Python `>=3.12,<3.13` and exact `uv` version `0.11.28` for the reviewed
  reproducible environment;
- SQLite `3.51.3` or newer (or a specifically verified fixed backport); startup
  rejects older versions because WAL durability is a security boundary;
- a local filesystem with reliable POSIX locking for the database and staging
  roots; known network filesystems are rejected;
- on Linux, a mounted kernel procfs at `/proc/self/fd` for descriptor-bound
  hardening of mode-`000` private directories; this is not required on macOS,
  which uses parent-descriptor-relative `fchmodat` with `AT_SYMLINK_NOFOLLOW` and
  fails closed rather than retrying an unanchored path;
- filesystem ownership that prevents other users from changing the code,
  virtualenv, policy, launchers, database, staging files, and deployment assembly;
- HTTPS at the browser-facing origin and an RP ID that is a registrable/exact host
  accepted by the chosen authenticator;
- an independently managed 32-byte backup encryption key and referenced secrets
  available through the deployment's secret broker, never argv or environment.

The default shared-user deployment does not isolate Signet from malicious code
running as that same user. Use a separate account or host when downstream
credentials must be protected from other local software; see `security-model.md`.

## Build and verify without deploying

Install `uv 0.11.28` with `pipx install 'uv==0.11.28'` or the official
versioned [`uv` installer](https://docs.astral.sh/uv/getting-started/installation/).
Inspect a downloaded installer before executing it and do not use the unversioned
installer. From a reviewed checkout:

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

The repository pins `uv`-managed Python `3.12.13` in `.python-version`; its bundled
SQLite satisfies the required floor. A different Python 3.12 build is acceptable
only when the version check below also passes. Record the reviewed commit and
lockfile. Do not let launchd invoke `uv sync` or an
unpinned package resolver. The staged plists execute the already-created
`.venv/bin/signet` entry point directly.

Before live assembly, verify the local runtime prerequisites without reading
secrets:

```console
uv run python -c 'import sqlite3; print(sqlite3.sqlite_version)'
uv run signet --help
uv run python -m signet.operations --help
```

`Database.initialize()` creates the data parent as `0700`, the SQLite file as
`0600`, verifies migration checksums, sets WAL and `synchronous=FULL`, enables
foreign keys on every connection, and refuses unknown/newer schemas. An upgrade
from an older supported schema requires a verified pre-migration backup callback.

## Run the persistent disabled staging assembly

Use absolute paths. The config parent and data directory must be owned by the
service user with exact mode `0700`; the config and SQLite database are exact mode
`0600`. Symbolic links, hard-linked config files, duplicate JSON keys, non-loopback
listeners, unknown fields, unknown namespaces, and alias expansion are rejected.

```console
SIGNET_REPO="$(pwd -P)" || exit 1
export SIGNET_REPO
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
export SIGNET_DISABLED_PROFILE=signet-disabled
uv run signet deployment init \
  --config "$SIGNET_SERVICE_ROOT/config/disabled.json" \
  --data-dir "$SIGNET_SERVICE_ROOT/data" \
  --namespace "profile:$SIGNET_DISABLED_PROFILE" || exit 1
uv run signet deployment validate \
  --config "$SIGNET_SERVICE_ROOT/config/disabled.json" || exit 1
```

`init` creates a new config and schema-13 database. It refuses an existing config
or database and does not create a password, TOTP secret, passkey, session key,
provider credential, policy, downstream alias, or queued request. `validate`
reports database integrity and the fixed disabled invariants without reporting
paths or verifier material. The initializer provisions exactly one caller namespace.
There is no principal-add command and no supported procedure for hand-editing the
private config; use a separate config/data directory and listener-port pair for a
second dedicated profile.

Start the two loopback processes in separate foreground terminals while staging.
In terminal A:

```console
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
uv run signet deployment serve-mcp \
  --config "$SIGNET_SERVICE_ROOT/config/disabled.json"
```

In terminal B:

```console
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
uv run signet deployment serve-web \
  --config "$SIGNET_SERVICE_ROOT/config/disabled.json"
```

Normal `SIGINT` and `SIGTERM` handling belongs to Uvicorn and drains the MCP session
manager before exit. Restart uses the same commands and persistent database. The
MCP listener exposes `/mcp/approvals` only. Every listed approval tool returns the
stable `deployment_disabled` domain error. The web root returns `503` with a fixed
disabled message; it has no login, session, queue, approval, denial, or enrollment
route. Both apps also reject non-loopback peer addresses if a factory is
accidentally bound more broadly than its config. Do not proxy that status app as
though it were the live authenticated UI.

### Persistent caller tokens

The disabled config declares one exact caller namespace and grants it only the
gateway-owned `approvals` alias. First prepare the dedicated blank Hermes profile
and private fragment exactly as described in
[`deploy/hermes/README.md`](../deploy/hermes/README.md#persistent-downstream-disabled-profile).
Confirm `token list` has no unexpected active record for the namespace, then issue
one high-entropy token directly into the checked-in configurator:

```console
uv run signet deployment token list \
  --config "$SIGNET_SERVICE_ROOT/config/disabled.json" || exit 1
(umask 077 && set -e && set -o pipefail && \
  uv run signet deployment token issue \
    --config "$SIGNET_SERVICE_ROOT/config/disabled.json" \
    --namespace "profile:$SIGNET_DISABLED_PROFILE" | \
  uv run python "$SIGNET_REPO/deploy/hermes/configure-disabled-profile.py" \
    --profile "$SIGNET_DISABLED_PROFILE" \
    --config "$SIGNET_DISABLED_HERMES_CONFIG" \
    --env-file "$SIGNET_DISABLED_HERMES_ENV" \
    --fragment "$SIGNET_DISABLED_HERMES_FRAGMENT") || exit 1
```

`token issue` writes the raw token and one newline to standard output exactly once.
It writes no label or metadata alongside it. The helper reads that exact value only
from stdin, validates the one reviewed loopback route, and uses identity-checked
atomic replacement for each mode-`0600` blank profile file without printing the
token or writing it to YAML. It syncs the environment replacement before attempting
the config replacement, so the pair is not one atomic filesystem operation.
It refuses existing MCP routes, unrelated environment assignments, symlinks,
hardlinks, unsafe modes, ambiguous YAML, and a noncanonical path. Never put the raw
value in argv, a normal config file, shell history, logs, chat, tickets, or
documentation. Signet persists only a SHA-256 verifier and non-secret metadata in
SQLite.

`pipefail` is required. If either side of the initial pipeline fails, do not issue
again immediately and do not start Hermes. Run `token list`, identify any new active
record by namespace and creation metadata, and revoke it by token ID. Because the
profile is dedicated and contains no other state, delete and recreate that profile
before retrying; do not inspect or hand-edit a possibly partial `.env`. This also
covers a broken stdout sink: the database record is committed before the one-time
raw value is written, and the CLI error directs the operator to list and revoke it.
The configurator's fixed error distinguishes no publication, an environment that
may already contain the token with no config publication, both requested files with
durability unknown, and cleanup that could not be confirmed. Never run initial
issue operations concurrently for one namespace.

```console
uv run signet deployment token list --config /ABSOLUTE/PATH/disabled.json
uv run signet deployment token revoke --config /ABSOLUTE/PATH/disabled.json \
  --token-id=TOKEN_ID
(umask 077 && set -o noclobber && \
  uv run signet deployment token rotate \
    --config /ABSOLUTE/PATH/disabled.json --token-id=TOKEN_ID \
    > /PRIVATE/NEW/SECRET/INGEST/PATH)
```

`list` never returns a raw token or verifier. Authentication reads SQLite on every
request, so revocation does not wait for a process restart. `rotate` inserts a
linked replacement and prints its raw token once, but deliberately leaves the old
token valid. Securely ingest the replacement, reload Hermes, and test the new route;
only then run `token revoke ... --token-id=OLD_TOKEN_ID`. This two-step distribution
prevents an output, storage, or reload failure from immediately taking the caller
offline.
A replacement destination must be new: never redirect rotation output over the
active token's secret file, because shell redirection truncates it before Signet
runs. The examples use `noclobber` to reject an existing destination.
A concurrent or repeated rotation of the old ID fails while its replacement is
active. If replacement output is lost, use `token list` to identify the linked
replacement, revoke that replacement ID, and retry; the old token remains valid.
Do not reuse a token across profile namespaces.

Legacy rows in the older unconstrained `caller_tokens` table are not loaded. The
`mcp_caller_tokens` table introduced by schema 12 accepts only the current exact
`sgt_` format and retains revoked records. To upgrade any supported older database,
including schema 11 or 12, stop both Signet services and every other database
writer, reserve space for the snapshot plus at least one additional database-sized
`VACUUM` copy, choose a new private snapshot path, and run:

```console
uv run signet deployment migrate --config /ABSOLUTE/PATH/disabled.json \
  --backup-snapshot /ABSOLUTE/PRIVATE/PATH/pre-schema-13.sqlite3
```

That snapshot is an unencrypted SQLite migration primitive, not a completed Signet
backup bundle. Keep it mode `0600` inside an owned directory, protect it under the
deployment backup policy, and do not retain it longer than that policy requires.
Schema 13 replaces legacy free-form approval/denial rationale with fixed reason
codes and records whether an attachment type came from a bounded byte signature or
an unverified legacy filename guess. It invalidates any unconsumed action draft
whose legacy rationale cannot be represented exactly. A pre-schema-13 snapshot can
therefore contain the removed free-form text. Treat it as sensitive, time-bound
migration material. The migration can take substantial time and temporary disk
space on a large database; do not interrupt it merely because `VACUUM` is quiet.
Malformed event-detail JSON, including duplicate or escaped duplicate keys, is
replaced wholesale with the fixed legacy decision sentinel or `NULL`; no arbitrary
legacy detail text is copied into the sanitized row.

When legacy rationale is present, startup sanitizes it transactionally, writes an
append-only migration event, checkpoints the WAL, and runs `VACUUM` under the
database maintenance lock before serving. An interrupted maintenance pass resumes
on the next startup without taking a second backup. Do not bypass that restart and
do not retain older backups beyond the reviewed backup policy; `VACUUM` cannot
remove sensitive text from snapshots or backup bundles that already exist.
This is a deliberate one-time exception to the normal append-only event contract:
schema 13 rewrites only affected historical `safe_details_json`, preserves each
event's identity and immutable request/version/hash fields, appends a sanitation
event naming the affected event ID, and reinstalls the no-update trigger in the same
migration transaction. The required pre-migration snapshot is the only retained
copy of the original free-form text.
After the command succeeds, run `deployment validate` before restarting either
service. Keep both services stopped if migration or validation fails.

### Human-auth context is validation, not enrollment

An operator may include the future exact HTTPS context at `init` time with all
three non-secret flags: `--human-user-id`, `--public-origin`, and `--rp-id`. Signet
requires an HTTPS origin with a lowercase host and an RP ID exactly equal to that
host. `deployment auth-status` reports active credential counts and always reports
that the disabled authenticated web app is not enabled. It does not read public
credential bytes, password verifiers, or TOTP references.

There is intentionally no password, TOTP seed, or passkey value accepted by these
commands, whether through argv, environment, stdin, or config. A passkey cannot be
pre-generated by an offline CLI: the human must complete a browser/authenticator
WebAuthn creation ceremony at the final HTTPS origin, with the intended RP ID and a
reviewed recovery path.

For a new owner, keep both services stopped and issue the one-use setup capability
locally on the production host immediately before starting the web service:

```console
.venv/bin/signet bootstrap issue --config /absolute/private/production.json --lifetime 600
```

The command prints the capability once and persists only its verifier. Treat the
printed value as a short-lived credential: do not put it in configuration,
environment variables, logs, shell tracing, tickets, or agent context. Start the
web service, open the final HTTPS `/setup` page, paste the capability into the claim
form, and complete password plus TOTP or passkey enrollment in that same claimed
browser. The capability expires within the selected 60–3600 second lifetime and one
successful browser claim consumes it atomically. Other browsers remain unable to
read or mutate staged setup state. If the configured owner already has a valid
password and active authenticator, startup reconciles bootstrap as complete and the
issue command aborts instead of reopening enrollment.

## Live deployment assembly responsibilities

Create a small deployment-owned module outside public source control that wires
the reviewed components. It must:

1. construct `Settings` from non-secret values and opaque `keychain://` references;
2. verify `data_dir`, policy, staging, backup, launcher, and log ownership/modes;
3. initialize the database with a verified pre-migration backup callback;
4. resolve high-entropy session, proof-capability, payload, TOTP, VAPID, downstream,
   and backup secrets at their narrow use sites without printing them;
5. persist the SHA-256 verifier records for random profile-scoped MCP caller tokens and
   load them into `TokenRegistry`; the raw token is returned once and belongs only
   in Hermes' reviewed secret mechanism;
6. load the exact policy and captured schema digests, leaving drifted/unreviewed
   tools disabled;
7. assemble supervised downstream clients and reviewed adapters without connecting
   during module import;
8. assemble `ApprovalStateMachine`, transactional notification outbox, gateway
   tools, alias surfaces, delivery/reconciliation workers, and authenticated web
   backend with the same durable database and proof-capability boundary;
9. wire and test `SQLitePolicyPromotionBoundary` against the deployment's exact
   policy path, shared engine/mirror, and list-change callback before enabling web
   policy actions, and call `DurableSchemaRegistry.restore()` before serving tools;
10. return one MCP ASGI app from `create_mcp_app()` and one web ASGI app from
   `create_web_app()`;
11. start bounded maintenance workers only inside ASGI lifespan and stop them on
   shutdown;
12. default to disabled/fake downstreams until the explicit cutover flag and every
    readiness prerequisite are independently satisfied.

MCP caller-token verifiers created before the SHA-256 machine-token format are
rejected without running their legacy password hash. Rotate and reissue those
random bearer tokens during the upgrade, then update Hermes' secret value before
retiring the old record. Human password verifiers remain Argon2id and are not
affected.

Do not retrieve secrets at import time, store them in global reprs, add them to
launchd `EnvironmentVariables`, or pass them in process arguments. Ordinary
settings reject literal secret fields. Downstream HTTP configuration accepts HTTPS
or loopback HTTP only; stdio uses an allowlisted argument vector without a shell.

The owned `wacli` launcher must pin the resolved, non-symlink Cellar executable,
its reviewed SHA-256 digest, and an owner/mode that is not group- or world-writable.
Do not configure `/opt/homebrew/bin/wacli`: Homebrew normally exposes that path as
a mutable symlink, and Signet intentionally rejects it. Re-review the resolved path,
version, and digest together after every upgrade.

The wrapper selects one exact descriptor-bound store with `--store`; it does not
resolve a named `--account` from the operator's normal HOME. Active configuration
requires a dedicated private runtime root with distinct HOME and store children.
The encrypted staging tree must be canonically disjoint from that child-visible
runtime tree in both directions. Existing linked-device state therefore needs an
explicit stopped-store migration or a human-authorized re-pair, never an implicit
HOME change. The full layout, migration decision, inherited-descriptor boundary,
and macOS local-process activation blocker are in
[`wacli-process-boundary.md`](wacli-process-boundary.md). The repository and CI do
not perform pairing, migration, provider contact, or sends, and the live assembly
remains disabled. The reviewed Homebrew artifact is macOS-only while the current
descriptor boundary is Linux-only, so this release has no valid `wacli`
host/artifact pair and blocks `wacli` activation everywhere.

The shipped persistent token CLI provisions only the `approvals` route in disabled
mode. A later live assembly must explicitly migrate the same namespace to the exact
reviewed downstream aliases (for example `fastmail` and `whatsapp`) and rotate the
token through a human-reviewed Hermes reload. Merely adding an alias string to a
token record does not create a route, approve a schema, or authorize cutover.

### Required web values

For a reference Serve URL such as
`https://signet-host.example-tailnet.ts.net:8443`:

```text
web_host       = 127.0.0.1
web_port       = 8790
public_origin  = https://signet-host.example-tailnet.ts.net:8443
rp_id          = signet-host.example-tailnet.ts.net
allowed_hosts  includes signet-host.example-tailnet.ts.net and loopback hosts
```

`public_origin` includes scheme and non-default port, has no path or trailing
slash, and must exactly match unsafe-request `Origin`. `rp_id` is the hostname only,
with no scheme or port. Passkey enrollment and use must occur at the same reviewed
RP ID/origin. Changing either can make existing credentials unusable and requires
a planned re-enrollment/recovery path.

The web app always emits secure session cookies and HSTS. Direct loopback HTTP is
for proxying and health checks, not human login. Do not weaken cookie or Origin
checks to make an HTTP-only LAN deployment work.

## launchd staging and authorized installation

Two user-agent templates are under `deploy/launchd/`:

- `ai.hermes.signet.mcp.plist.example` binds MCP to `127.0.0.1:8789`;
- `ai.hermes.signet.web.plist.example` binds web to `127.0.0.1:8790`.

Separate processes keep browser routes off the MCP listener. Both templates use
`Umask=077`, background process type, throttled restart, and distinct logs. Their
absolute executable, config, working-directory, and log paths are placeholders.
Their `ProgramArguments` already invoke the installed `signet deployment
serve-mcp` and `serve-web` commands. Do not edit or load a template directly. The
checked-in renderer parses the plists structurally, validates every supplied path,
refuses existing outputs, and creates mode-`0600` review files; it never copies them
to `~/Library/LaunchAgents` or calls `launchctl`.

During an authorized installation only:

1. Create and validate the downstream-disabled state as shown above. From the
   reviewed repository root, create a new private render directory and the log
   directory, then render both files from canonical absolute paths:

   ```console
   SIGNET_REPO="$(pwd -P)" || exit 1
   export SIGNET_REPO
   SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
   export SIGNET_HOME
   export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
   export SIGNET_LAUNCHD_REVIEW="$SIGNET_SERVICE_ROOT/launchd-review"
   install -d -m 0700 "$SIGNET_SERVICE_ROOT/logs" || exit 1
   test ! -e "$SIGNET_LAUNCHD_REVIEW" && \
     test ! -L "$SIGNET_LAUNCHD_REVIEW" || exit 1
   install -d -m 0700 "$SIGNET_LAUNCHD_REVIEW" || exit 1
   uv run python deploy/launchd/render-disabled-plists.py \
     --signet-executable "$SIGNET_REPO/.venv/bin/signet" \
     --config "$SIGNET_SERVICE_ROOT/config/disabled.json" \
     --working-directory "$SIGNET_REPO" \
     --logs-directory "$SIGNET_SERVICE_ROOT/logs" \
     --output-directory "$SIGNET_LAUNCHD_REVIEW" || exit 1
   ```

   The renderer rejects relative/noncanonical paths, symlinks, multiply linked
   files, wrong ownership or modes, a writable checkout/executable, changed template
   structure, and any existing output. Verify no credential value appears in either
   plist; the config path is non-secret. If rendering reports unknown publication or
   cleanup, install neither file. Inspect the exact private review directory, retain
   any unexpected or identity-changed entry for investigation, and retry only into a
   newly validated empty review directory.
2. Parse and inspect the exact rendered files:

   ```console
   plutil -lint "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.mcp.plist" || exit 1
   plutil -lint "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.web.plist" || exit 1
   plutil -p "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.mcp.plist" || exit 1
   plutil -p "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.web.plist" || exit 1
   ```

3. Refuse an existing destination, then place the reviewed files in the user-agent
   directory with mode `0600`:

   ```console
   (
     set -e
     umask 077
     SIGNET_REPO="$(pwd -P)"
     export SIGNET_REPO
     SIGNET_HOME="$(cd "$HOME" && pwd -P)"
     export SIGNET_HOME
     export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
     export SIGNET_LAUNCHD_REVIEW="$SIGNET_SERVICE_ROOT/launchd-review"
     "$SIGNET_REPO/.venv/bin/python" \
       "$SIGNET_REPO/deploy/validate-private-paths.py" \
       --directory "$SIGNET_LAUNCHD_REVIEW" \
       --private-file "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.mcp.plist" \
       --private-file "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.web.plist"
     SIGNET_LIBRARY="$SIGNET_HOME/Library"
     if ! test -d "$SIGNET_LIBRARY" || test -L "$SIGNET_LIBRARY" || \
        ! test -O "$SIGNET_LIBRARY"; then
       printf 'refusing missing, unowned, or linked physical Library directory: %s\n' \
         "$SIGNET_LIBRARY" >&2
       exit 1
     fi
     SIGNET_LIBRARY_CANONICAL="$(cd "$SIGNET_LIBRARY" && pwd -P)"
     if test "$SIGNET_LIBRARY_CANONICAL" != "$SIGNET_LIBRARY"; then
       printf 'refusing noncanonical physical Library directory: %s\n' \
         "$SIGNET_LIBRARY" >&2
       exit 1
     fi
     SIGNET_UNSAFE_LIBRARY="$(
       find "$SIGNET_LIBRARY" -prune \( -perm -020 -o -perm -002 \) -print
     )"
     if test -n "$SIGNET_UNSAFE_LIBRARY"; then
       printf 'refusing group/world-writable physical Library directory: %s\n' \
         "$SIGNET_LIBRARY" >&2
       exit 1
     fi
     "$SIGNET_REPO/.venv/bin/python" \
       "$SIGNET_REPO/deploy/validate-private-paths.py" \
       --directory "$SIGNET_LIBRARY"
     export SIGNET_LAUNCHD_DESTINATION="$SIGNET_LIBRARY/LaunchAgents"
     if test -L "$SIGNET_LAUNCHD_DESTINATION"; then
       printf 'refusing linked launchd directory: %s\n' \
         "$SIGNET_LAUNCHD_DESTINATION" >&2
       exit 1
     fi
     if test ! -e "$SIGNET_LAUNCHD_DESTINATION"; then
       install -d -m 0700 "$SIGNET_LAUNCHD_DESTINATION"
     elif ! test -d "$SIGNET_LAUNCHD_DESTINATION" || \
          ! test -O "$SIGNET_LAUNCHD_DESTINATION"; then
       printf 'refusing unowned or non-directory launchd destination: %s\n' \
         "$SIGNET_LAUNCHD_DESTINATION" >&2
       exit 1
     fi
     SIGNET_LAUNCHD_DESTINATION_CANONICAL="$(
       cd "$SIGNET_LAUNCHD_DESTINATION" && pwd -P
     )"
     if test "$SIGNET_LAUNCHD_DESTINATION_CANONICAL" != \
       "$SIGNET_LAUNCHD_DESTINATION"; then
       printf 'refusing noncanonical launchd directory: %s\n' \
         "$SIGNET_LAUNCHD_DESTINATION" >&2
       exit 1
     fi
     SIGNET_UNSAFE_LAUNCHD_DESTINATION="$(
       find "$SIGNET_LAUNCHD_DESTINATION" -prune \
         \( -perm -020 -o -perm -002 \) -print
     )"
     if test -n "$SIGNET_UNSAFE_LAUNCHD_DESTINATION"; then
       printf 'refusing group/world-writable launchd destination: %s\n' \
         "$SIGNET_LAUNCHD_DESTINATION" >&2
       exit 1
     fi
     "$SIGNET_REPO/.venv/bin/python" \
       "$SIGNET_REPO/deploy/validate-private-paths.py" \
       --directory "$SIGNET_LAUNCHD_DESTINATION"

     SIGNET_INSTALL_LOCK="$SIGNET_LAUNCHD_DESTINATION/.ai.hermes.signet.install.lock"
     SIGNET_INSTALL_LOCK_TOKEN="$(
       "$SIGNET_REPO/.venv/bin/python" -c \
         'import secrets; print(secrets.token_hex(32))'
     )"
     SIGNET_MCP_LAUNCHD_INSTALLED=0
     SIGNET_WEB_LAUNCHD_INSTALLED=0
     SIGNET_LAUNCHD_INSTALL_COMMITTED=0
     SIGNET_INSTALL_LOCK_HELD=0
     signet_remove_reviewed_launchd_copy() {
       copy_name="$1"
       copy_source="$SIGNET_LAUNCHD_REVIEW/$copy_name"
       copy_destination="$SIGNET_LAUNCHD_DESTINATION/$copy_name"
       if test ! -e "$copy_destination" && test ! -L "$copy_destination"; then
         return
       fi
       if test -f "$copy_destination" && test ! -L "$copy_destination" && \
          cmp -s "$copy_source" "$copy_destination"; then
         if ! rm -f "$copy_destination"; then
           printf 'could not remove reviewed launchd destination: %s\n' \
             "$copy_destination" >&2
           return 1
         fi
         if test -e "$copy_destination" || test -L "$copy_destination"; then
           printf 'reviewed launchd destination remains after removal: %s\n' \
             "$copy_destination" >&2
           return 1
         fi
         return
       fi
       printf 'refusing rollback of unexpected launchd destination: %s\n' \
         "$copy_destination" >&2
       return 1
     }
     signet_rollback_launchd_install() {
       rollback_failed=0
       if test "$SIGNET_WEB_LAUNCHD_INSTALLED" -eq 1; then
         signet_remove_reviewed_launchd_copy ai.hermes.signet.web.plist || \
           rollback_failed=1
       fi
       if test "$SIGNET_MCP_LAUNCHD_INSTALLED" -eq 1; then
         signet_remove_reviewed_launchd_copy ai.hermes.signet.mcp.plist || \
           rollback_failed=1
       fi
       return "$rollback_failed"
     }
     signet_release_launchd_install_lock() {
       if test ! -e "$SIGNET_INSTALL_LOCK" && test ! -L "$SIGNET_INSTALL_LOCK"; then
         if test "$SIGNET_INSTALL_LOCK_HELD" -eq 1; then
           printf 'launchd install lock disappeared; inspect: %s\n' \
             "$SIGNET_INSTALL_LOCK" >&2
           return 1
         fi
         return
       fi
       if test "$SIGNET_INSTALL_LOCK_HELD" -ne 1; then
         return
       fi
       if ! test -f "$SIGNET_INSTALL_LOCK" || test -L "$SIGNET_INSTALL_LOCK" || \
          ! test -O "$SIGNET_INSTALL_LOCK"; then
         printf 'refusing unexpected launchd install lock: %s\n' \
           "$SIGNET_INSTALL_LOCK" >&2
         return 1
       fi
       SIGNET_OBSERVED_INSTALL_LOCK_TOKEN=
       IFS= read -r SIGNET_OBSERVED_INSTALL_LOCK_TOKEN \
         < "$SIGNET_INSTALL_LOCK" || true
       if test "$SIGNET_OBSERVED_INSTALL_LOCK_TOKEN" != \
          "$SIGNET_INSTALL_LOCK_TOKEN"; then
         printf 'refusing changed launchd install lock: %s\n' \
           "$SIGNET_INSTALL_LOCK" >&2
         return 1
       fi
       if ! rm -f "$SIGNET_INSTALL_LOCK"; then
         printf 'could not remove launchd install lock: %s\n' \
           "$SIGNET_INSTALL_LOCK" >&2
         return 1
       fi
       if test -e "$SIGNET_INSTALL_LOCK" || test -L "$SIGNET_INSTALL_LOCK"; then
         printf 'launchd install lock remains after removal: %s\n' \
           "$SIGNET_INSTALL_LOCK" >&2
         return 1
       fi
       SIGNET_INSTALL_LOCK_HELD=0
     }
     signet_finish_launchd_install() {
       install_status="$1"
       trap - EXIT HUP INT TERM
       if test "$SIGNET_LAUNCHD_INSTALL_COMMITTED" -ne 1 && \
          ! signet_rollback_launchd_install; then
         printf 'launchd install and rollback both failed; inspect: %s\n' \
           "$SIGNET_LAUNCHD_DESTINATION" >&2
         install_status=1
       fi
       if ! signet_release_launchd_install_lock; then
         printf 'launchd install lock cleanup failed; inspect before retrying\n' >&2
         install_status=1
       fi
       exit "$install_status"
     }
     trap 'signet_finish_launchd_install $?' EXIT
     trap 'exit 129' HUP
     trap 'exit 130' INT
     trap 'exit 143' TERM

     set -o noclobber
     if ! printf '%s\n' "$SIGNET_INSTALL_LOCK_TOKEN" > "$SIGNET_INSTALL_LOCK"; then
       set +o noclobber
       printf 'refusing concurrent or stale launchd install lock: %s\n' \
         "$SIGNET_INSTALL_LOCK" >&2
       exit 1
     fi
     set +o noclobber
     SIGNET_INSTALL_LOCK_HELD=1

     for name in ai.hermes.signet.mcp.plist ai.hermes.signet.web.plist; do
       destination="$SIGNET_LAUNCHD_DESTINATION/$name"
       if test -e "$destination" || test -L "$destination"; then
         printf 'refusing existing launchd destination: %s\n' "$destination" >&2
         exit 1
       fi
     done

     SIGNET_MCP_LAUNCHD_INSTALLED=1
     if ! install -m 0600 \
       "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.mcp.plist" \
       "$SIGNET_LAUNCHD_DESTINATION/ai.hermes.signet.mcp.plist"; then
       exit 1
     fi
     SIGNET_WEB_LAUNCHD_INSTALLED=1
     if ! install -m 0600 \
       "$SIGNET_LAUNCHD_REVIEW/ai.hermes.signet.web.plist" \
       "$SIGNET_LAUNCHD_DESTINATION/ai.hermes.signet.web.plist"; then
       exit 1
     fi
     "$SIGNET_REPO/.venv/bin/python" \
       "$SIGNET_REPO/deploy/validate-private-paths.py" \
       --directory "$SIGNET_LAUNCHD_DESTINATION" \
       --private-file "$SIGNET_LAUNCHD_DESTINATION/ai.hermes.signet.mcp.plist" \
       --private-file "$SIGNET_LAUNCHD_DESTINATION/ai.hermes.signet.web.plist"
     SIGNET_LAUNCHD_INSTALL_COMMITTED=1
   )
   ```

   This is an initial-install procedure. The private token-owned lock serializes
   concurrent repetitions of this exact documented transaction. It does not control
   an arbitrary same-user process, which is outside Signet's operating-system
   isolation boundary. A stale lock is a refusal: inspect the lock and both exact
   destination paths instead of deleting it blindly. Updating an existing agent needs
   a separate reviewed replacement and rollback plan; do not bypass either refusal.
4. Only after the human authorizes service start, load them with the current macOS
   user domain:

   ```console
   (
     set -e
     umask 077
     SIGNET_REPO="$(pwd -P)"
     export SIGNET_REPO
     SIGNET_HOME="$(cd "$HOME" && pwd -P)"
     export SIGNET_HOME
     SIGNET_GUI_DOMAIN="gui/$(id -u)"
     SIGNET_MCP_LABEL="$SIGNET_GUI_DOMAIN/ai.hermes.signet.mcp"
     SIGNET_WEB_LABEL="$SIGNET_GUI_DOMAIN/ai.hermes.signet.web"
     SIGNET_MCP_PLIST="$SIGNET_HOME/Library/LaunchAgents/ai.hermes.signet.mcp.plist"
     SIGNET_WEB_PLIST="$SIGNET_HOME/Library/LaunchAgents/ai.hermes.signet.web.plist"
     SIGNET_LAUNCHD_DESTINATION="${SIGNET_MCP_PLIST%/*}"
     SIGNET_BOOTSTRAP_LOCK="$SIGNET_LAUNCHD_DESTINATION/.ai.hermes.signet.bootstrap.lock"
     SIGNET_BOOTSTRAP_LOCK_TOKEN="$(
       "$SIGNET_REPO/.venv/bin/python" -c \
         'import secrets; print(secrets.token_hex(32))'
     )"

     SIGNET_MCP_BOOTSTRAP_ATTEMPTED=0
     SIGNET_WEB_BOOTSTRAP_ATTEMPTED=0
     SIGNET_MCP_BOOTSTRAPPED=0
     SIGNET_WEB_BOOTSTRAPPED=0
     SIGNET_LAUNCHD_BOOTSTRAP_COMMITTED=0
     SIGNET_BOOTSTRAP_LOCK_HELD=0
     signet_rollback_launchd_bootstrap() {
       rollback_failed=0
       if test "$SIGNET_WEB_BOOTSTRAPPED" -eq 1; then
         launchctl bootout "$SIGNET_WEB_LABEL" || rollback_failed=1
       elif test "$SIGNET_WEB_BOOTSTRAP_ATTEMPTED" -eq 1 && \
            launchctl print "$SIGNET_WEB_LABEL" >/dev/null 2>&1; then
         launchctl bootout "$SIGNET_WEB_LABEL" || rollback_failed=1
       fi
       if test "$SIGNET_MCP_BOOTSTRAPPED" -eq 1; then
         launchctl bootout "$SIGNET_MCP_LABEL" || rollback_failed=1
       elif test "$SIGNET_MCP_BOOTSTRAP_ATTEMPTED" -eq 1 && \
            launchctl print "$SIGNET_MCP_LABEL" >/dev/null 2>&1; then
         launchctl bootout "$SIGNET_MCP_LABEL" || rollback_failed=1
       fi
       return "$rollback_failed"
     }
     signet_release_launchd_bootstrap_lock() {
       if test ! -e "$SIGNET_BOOTSTRAP_LOCK" && \
          test ! -L "$SIGNET_BOOTSTRAP_LOCK"; then
         if test "$SIGNET_BOOTSTRAP_LOCK_HELD" -eq 1; then
           printf 'launchd bootstrap lock disappeared; inspect: %s\n' \
             "$SIGNET_BOOTSTRAP_LOCK" >&2
           return 1
         fi
         return
       fi
       if test "$SIGNET_BOOTSTRAP_LOCK_HELD" -ne 1; then
         return
       fi
       if ! test -f "$SIGNET_BOOTSTRAP_LOCK" || \
          test -L "$SIGNET_BOOTSTRAP_LOCK" || \
          ! test -O "$SIGNET_BOOTSTRAP_LOCK"; then
         printf 'refusing unexpected launchd bootstrap lock: %s\n' \
           "$SIGNET_BOOTSTRAP_LOCK" >&2
         return 1
       fi
       SIGNET_OBSERVED_BOOTSTRAP_LOCK_TOKEN=
       IFS= read -r SIGNET_OBSERVED_BOOTSTRAP_LOCK_TOKEN \
         < "$SIGNET_BOOTSTRAP_LOCK" || true
       if test "$SIGNET_OBSERVED_BOOTSTRAP_LOCK_TOKEN" != \
          "$SIGNET_BOOTSTRAP_LOCK_TOKEN"; then
         printf 'refusing changed launchd bootstrap lock: %s\n' \
           "$SIGNET_BOOTSTRAP_LOCK" >&2
         return 1
       fi
       if ! rm -f "$SIGNET_BOOTSTRAP_LOCK"; then
         printf 'could not remove launchd bootstrap lock: %s\n' \
           "$SIGNET_BOOTSTRAP_LOCK" >&2
         return 1
       fi
       if test -e "$SIGNET_BOOTSTRAP_LOCK" || test -L "$SIGNET_BOOTSTRAP_LOCK"; then
         printf 'launchd bootstrap lock remains after removal: %s\n' \
           "$SIGNET_BOOTSTRAP_LOCK" >&2
         return 1
       fi
       SIGNET_BOOTSTRAP_LOCK_HELD=0
     }
     signet_finish_launchd_bootstrap() {
       bootstrap_status="$1"
       trap - EXIT HUP INT TERM
       if test "$SIGNET_LAUNCHD_BOOTSTRAP_COMMITTED" -ne 1 && \
          ! signet_rollback_launchd_bootstrap; then
         printf 'launchd bootstrap and rollback both failed; inspect both labels\n' >&2
         bootstrap_status=1
       fi
       if ! signet_release_launchd_bootstrap_lock; then
         printf 'launchd bootstrap lock cleanup failed; inspect before retrying\n' >&2
         bootstrap_status=1
       fi
       exit "$bootstrap_status"
     }
     trap 'signet_finish_launchd_bootstrap $?' EXIT
     trap 'exit 129' HUP
     trap 'exit 130' INT
     trap 'exit 143' TERM

     set -o noclobber
     if ! printf '%s\n' "$SIGNET_BOOTSTRAP_LOCK_TOKEN" \
       > "$SIGNET_BOOTSTRAP_LOCK"; then
       set +o noclobber
       printf 'refusing concurrent or stale launchd bootstrap lock: %s\n' \
         "$SIGNET_BOOTSTRAP_LOCK" >&2
       exit 1
     fi
     set +o noclobber
     SIGNET_BOOTSTRAP_LOCK_HELD=1

     for label in "$SIGNET_MCP_LABEL" "$SIGNET_WEB_LABEL"; do
       if launchctl print "$label" >/dev/null 2>&1; then
         printf 'refusing existing launchd label: %s\n' "$label" >&2
         exit 1
       fi
     done
     "$SIGNET_REPO/.venv/bin/python" \
       "$SIGNET_REPO/deploy/validate-private-paths.py" \
       --directory "$SIGNET_LAUNCHD_DESTINATION" \
       --private-file "$SIGNET_MCP_PLIST" \
       --private-file "$SIGNET_WEB_PLIST"

     SIGNET_MCP_BOOTSTRAP_ATTEMPTED=1
     if ! launchctl bootstrap "$SIGNET_GUI_DOMAIN" "$SIGNET_MCP_PLIST"; then
       printf 'MCP bootstrap failed; rolling back the absent-preflight label if present: %s\n' \
         "$SIGNET_MCP_LABEL" >&2
       exit 1
     fi
     SIGNET_MCP_BOOTSTRAPPED=1
     SIGNET_WEB_BOOTSTRAP_ATTEMPTED=1
     if ! launchctl bootstrap "$SIGNET_GUI_DOMAIN" "$SIGNET_WEB_PLIST"; then
       printf 'web bootstrap failed; rolling back transaction labels found after preflight\n' >&2
       exit 1
     fi
     SIGNET_WEB_BOOTSTRAPPED=1
     if ! launchctl print "$SIGNET_MCP_LABEL" || \
        ! launchctl print "$SIGNET_WEB_LABEL"; then
       exit 1
     fi
     SIGNET_LAUNCHD_BOOTSTRAP_COMMITTED=1
   )
   ```

   Run no other `launchctl` operation for these two exact labels while this block is
   active. The exclusive private lock serializes repetitions of this documented
   transaction; it cannot coordinate an arbitrary same-user process, which is
   outside Signet's operating-system isolation boundary. A stale lock is a refusal:
   inspect both labels and the exact lock file instead of deleting it blindly.

### Conservative stale-lock recovery

The transaction locks intentionally contain an unpredictable ownership token, not a
durable phase journal. They cannot prove whether a plist or label observed after an
interruption predates the transaction. Therefore, never delete a stale lock while an
install/bootstrap shell could still be active. Use the block below only immediately
after a reboot and before starting another Signet install, bootstrap, or launchd
operation. It validates and removes only the two exact advisory lock files; it never
changes a plist or label. Afterwards, inspect those service objects separately. The
install/bootstrap preflights will refuse any existing or partial state until it has a
separately reviewed reconciliation plan.

```console
(
  set -e
  umask 077
  SIGNET_REPO="$(pwd -P)"
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  SIGNET_LAUNCHD_DESTINATION="$SIGNET_HOME/Library/LaunchAgents"
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_LAUNCHD_DESTINATION"
  for SIGNET_LOCK_NAME in \
    .ai.hermes.signet.install.lock .ai.hermes.signet.bootstrap.lock; do
    SIGNET_STALE_LOCK="$SIGNET_LAUNCHD_DESTINATION/$SIGNET_LOCK_NAME"
    if test ! -e "$SIGNET_STALE_LOCK" && test ! -L "$SIGNET_STALE_LOCK"; then
      continue
    fi
    "$SIGNET_REPO/.venv/bin/python" \
      "$SIGNET_REPO/deploy/validate-private-paths.py" \
      --directory "$SIGNET_LAUNCHD_DESTINATION" \
      --private-file "$SIGNET_STALE_LOCK"
    SIGNET_STALE_LOCK_TOKEN=
    IFS= read -r SIGNET_STALE_LOCK_TOKEN < "$SIGNET_STALE_LOCK"
    case "$SIGNET_STALE_LOCK_TOKEN" in
      *[!0-9a-f]*|'')
        printf 'refusing malformed launchd transaction lock: %s\n' \
          "$SIGNET_STALE_LOCK" >&2
        exit 1
        ;;
    esac
    if test "${#SIGNET_STALE_LOCK_TOKEN}" -ne 64 || \
       test "$(wc -l < "$SIGNET_STALE_LOCK")" -ne 1 || \
       test "$(wc -c < "$SIGNET_STALE_LOCK")" -ne 65; then
      printf 'refusing malformed launchd transaction lock: %s\n' \
        "$SIGNET_STALE_LOCK" >&2
      exit 1
    fi
    SIGNET_OBSERVED_STALE_LOCK_TOKEN=
    IFS= read -r SIGNET_OBSERVED_STALE_LOCK_TOKEN < "$SIGNET_STALE_LOCK"
    if test "$SIGNET_OBSERVED_STALE_LOCK_TOKEN" != "$SIGNET_STALE_LOCK_TOKEN"; then
      printf 'refusing changed launchd transaction lock: %s\n' \
        "$SIGNET_STALE_LOCK" >&2
      exit 1
    fi
    "$SIGNET_REPO/.venv/bin/python" \
      "$SIGNET_REPO/deploy/validate-private-paths.py" \
      --directory "$SIGNET_LAUNCHD_DESTINATION" \
      --private-file "$SIGNET_STALE_LOCK"
    if ! rm -f "$SIGNET_STALE_LOCK"; then
      printf 'could not remove inert stale launchd lock: %s\n' \
        "$SIGNET_STALE_LOCK" >&2
      exit 1
    fi
    if test -e "$SIGNET_STALE_LOCK" || test -L "$SIGNET_STALE_LOCK"; then
      printf 'stale launchd lock remains after removal: %s\n' \
        "$SIGNET_STALE_LOCK" >&2
      exit 1
    fi
  done
)
```

After release, inspect both exact plist paths and run `launchctl print` for both exact
labels. Existing objects are not proof of failure or success; they are a refusal to
rerun the initial transaction until a human reconciles their provenance and intended
state. A future automatic recovery path would require a fsynced phase journal, not a
weaker guess based on the lock token.

5. Review the successful `launchctl print` output for both labels, then inspect only
   bounded, privacy-safe startup logs. Repeated restart is a hard failure, not a
   reason to bypass initialization.

To stop without deleting state:

```console
(
  SIGNET_GUI_DOMAIN="gui/$(id -u)" || exit 1
  SIGNET_BOOTOUT_FAILED=0
  launchctl bootout "$SIGNET_GUI_DOMAIN/ai.hermes.signet.web" || \
    SIGNET_BOOTOUT_FAILED=1
  launchctl bootout "$SIGNET_GUI_DOMAIN/ai.hermes.signet.mcp" || \
    SIGNET_BOOTOUT_FAILED=1
  if test "$SIGNET_BOOTOUT_FAILED" -ne 0; then
    printf 'one or more launchd bootouts failed; inspect both labels\n' >&2
    exit 1
  fi
)
```

Do not use `kickstart -k` casually; it is a controlled restart and needs explicit
approval when requests may be active. Prefer Hermes' MCP reload mechanism for
client route changes.

Apple's user-agent and `ProgramArguments` model is documented in
[Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

## Health and observability

Local health checks are intentionally static:

```console
(
  set -e
  curl --connect-timeout 5 --max-time 10 --fail --silent --show-error \
    http://127.0.0.1:8789/healthz
  curl --connect-timeout 5 --max-time 10 --fail --silent --show-error \
    http://127.0.0.1:8790/healthz
)
```

The MCP response contains only `{"status":"ok"}`. The disabled web response is
`{"status":"ok","service":"signet","mode":"disabled"}`. A later live web factory
may omit the fixed mode field. Neither endpoint reports queue contents, targets,
database or credential paths, policy, downstream connectivity, or user identity. A
healthy process does not prove that credentials, schemas, or providers are ready.

Metrics and logs may include bounded counts, state classes, ages, duration buckets,
safe error codes, reconciliation counts, disk capacity, and schema drift. They must
not include request payloads, full targets, filenames, raw IDs derived from personal
data, bearer tokens, provider results, WebAuthn challenges/assertions, TOTP values,
push endpoints/keys, or Keychain references. Disable framework debug mode and raw
HTTP/MCP body logging.

## Reference: localhost plus Tailscale Serve

Serve provides tailnet-only reachability and TLS. It is not an identity provider
for Signet. The app ignores Tailscale identity headers and still requires its own
login and fresh action confirmation.

Do not publish the disabled status-only web app through Serve; it has no human
authentication or action routes. After the separate live web assembly and human
authentication ceremony are complete, the staged packet
`deploy/tailscale/serve-merge.md` uses a previously free HTTPS
listener on `8443` and proxies its root to `http://127.0.0.1:8790`. Using a separate
listener avoids subpath rewriting and leaves an existing `443` root handler intact.
It also gives WebAuthn one stable origin.

The authorized merge procedure is:

1. Capture `tailscale serve get-config --all`, Serve status, and Funnel status into
   private change-record files.
2. Confirm that no existing Serve or Funnel handler uses `8443`. If there is a
   conflict, stop; never use `tailscale serve reset` or silently remove it.
3. Confirm local web health, exact `public_origin`/RP ID/Host allowlist, successful
   app login, and rejection of unauthenticated queue access.
4. With explicit approval, add only the free listener:

   ```console
   tailscale serve --bg --https=8443 http://127.0.0.1:8790
   ```

5. Capture status again. Verify prior handlers are unchanged, `8443` is Serve-only,
   Funnel has no selected listener, and the URL is available only inside the
   tailnet.

Exact route rollback removes only this listener:

```console
tailscale serve --https=8443 off
```

Do not routinely restore a whole saved Serve config; doing so can overwrite routes
changed after capture. Tailscale documents the current CLI at
[tailscale serve](https://tailscale.com/docs/reference/tailscale-cli/serve).
[Serve](https://tailscale.com/docs/features/tailscale-serve) is tailnet-only;
[Funnel](https://tailscale.com/docs/features/tailscale-funnel) is public and is not
supported for this MVP.

## Homepage card

`deploy/homepage/services.signet.yaml.example` contains one normal card named
**Signet**. Merge that service into the intended existing group without replacing
`services.yaml`, changing layout, or adding a credential-bearing widget. Copy the
committed raster icon `src/signet/static/icons/signet-1254.png` into Homepage's
mounted `/app/public/icons` directory as `signet.png`, and replace only the reviewed
tailnet hostname.

The card deliberately has no health widget or API key. Homepage's service format
and local icon path are documented in
[Homepage services](https://gethomepage.dev/configs/services/). Adding the card and
reloading Homepage are authorized cutover steps, not repository setup.

## LAN or reverse-proxy alternative

A private LAN deployment uses the same app authentication. Prefer keeping Signet
on `127.0.0.1:8790` behind a local Caddy/nginx listener with a valid private/public
certificate. Binding the web process directly to a LAN address expands the host
firewall and same-network threat surface and still requires HTTPS in front of the
browser origin.

The proxy must:

- terminate modern TLS and redirect plaintext HTTP without forwarding credentials;
- preserve the exact public Host and origin expected by Signet;
- proxy all web/PWA paths, including WebAuthn and push subscription endpoints;
- disable response caching and avoid request/response body logging;
- impose bounded header/body/time limits compatible with Signet;
- not inject or trust a user identity header for application authorization;
- never route `/mcp/*` or port `8789` off-host;
- expose no administrative/debug endpoint and no alternate unauthenticated origin.

Set `public_origin`, `rp_id`, and `allowed_hosts` to the LAN HTTPS name before
enrollment. Test with the proxy temporarily removed that direct access still
requires Signet authentication; only reachability/TLS should change.

Never expose Signet publicly without a new threat review, explicit human decision,
TLS, full application authentication, Internet-grade rate limiting, monitoring,
and recovery procedures. Tailscale Funnel remains disabled.

## Backup and restore

There is no general or live `signet backup` shell command. `signet demo backup` and
`signet demo restore` are deliberately restricted to state marked by the shipped
fake-only assembly; they are not deployment commands and must not be pointed at or
adapted for live state. Do not invent a live wrapper in an ops script or copy a WAL
database with `cp`. Deployment assembly must call the tested `BackupBundleManager`
API with a 32-byte key resolved outside argv/env.

`BackupBundleManager.create()`:

- uses SQLite's backup API for a consistent snapshot;
- derives attachment rows and key references from that snapshot, not a later live
  view;
- copies each gateway-owned attachment through a verified no-follow descriptor;
- records size/hash metadata and non-secret key references in a manifest;
- archives the snapshot and attachments, then encrypts/authenticates the bundle
  with AES-256-GCM;
- writes and verifies a uniquely named private mode-`0600` temporary file, releases
  source-retention pins, then publishes with a native atomic no-replace rename;
- verifies the published file identity, fsyncs the parent directory, and revalidates
  both the parent and destination before reporting durable success;
- refuses an existing destination and enforces a configured bundle-size bound.

Publication failures have explicit operator semantics:

- `BackupRetentionStateUnknown` occurs before the publication rename. This backup
  operation did not publish the destination. Inspect/recover abandoned retention
  pins and any private-artifact warning before retrying.
- `BackupCleanupStateUnknown` also occurs before publication, but means a private
  temporary file or plaintext workspace could not be removed safely. Do not ignore
  it: inspect the private backup parent and account for the retained artifact before
  retrying.
- `BackupPublicationUnknown` means a rename was observed or could have occurred,
  but destination identity and parent-directory durability were not fully
  confirmed. Inspect the exact destination and its private parent. Do not blindly
  retry or create another bundle until the existing destination is accounted for.
- `BackupPublishedWithWarnings` means the exact bundle is already durably
  published, but private workspace cleanup could not be confirmed. Retain that
  bundle; do not recreate it. Resolve the reported private artifacts before
  continuing.

These messages deliberately contain no key, payload, attachment name, or arbitrary
filesystem exception text. Catching a generic exception and replacing these states
with “failed safely” is incorrect because it can make an operator retry an already
published bundle.

The backup key must be independent of the bundle and recoverable under the site's
key-management policy. A key reference in the manifest is not the key. Losing
payload/downstream/backup keys can make a structurally valid backup unusable.

`BackupBundleManager.restore()` always targets a path that does not exist. It:

1. opens a bounded regular bundle without following symlinks;
2. verifies AES-GCM authentication before extraction;
3. rejects archive traversal, links, duplicate paths, oversized members, and
   unexpected files;
4. verifies the database hash and runs `integrity_check` and `foreign_key_check`;
5. copies attachments under the new restore root, rewrites storage paths in one
   transaction, checkpoints/fsyncs the restored database, and re-verifies every
   attachment;
6. removes only the originally captured restore-tree identity on failure, verifies
   absence, fsyncs its parent, and raises `BackupCleanupStateUnknown` if that
   private cleanup cannot be confirmed;
7. returns a `RestoredBundle` but never activates it.

The demo restore applies the same checked removal after rotating its fake secrets.
If cleanup fails, its fixed error says not to start the retained tree. The
pre-migration callback also checks removal of its private verification restore; a
cleanup failure raises `BackupPublishedWithWarnings` because the encrypted backup
bundle is already durable and must be retained rather than recreated.

A backup is operationally accepted only after restoring it into a separate private
path on the intended software version and verifying:

- manifest/schema version and migration checksums;
- database integrity and foreign keys;
- attachment hashes and key-reference availability;
- ability to decrypt representative retained fixture payloads without dispatch;
- queue/state/event/idempotency consistency;
- zero network/provider calls during the drill.

Activation is a separate, human-approved maintenance action. Stop writers, take a
new backup, preserve the failed live tree, and atomically select the verified
restored tree according to deployment-specific procedures. Never overwrite the
only live copy. Never restore a backup that predates a `pending_approval`
acknowledgement still known to a caller; repair forward instead.

Backups can retain data logically purged later. Apply retention and destruction
policy independently to backup generations, APFS snapshots, WAL remnants, and
backup keys. A shared wrapping key does not provide per-request cryptographic
erasure.

Production retains unresolved and exhausted `outcome_unknown` content indefinitely.
The `signet demo purge-unknown` command is marker-guarded fake-test functionality,
not an operator procedure for this assembly and not evidence of human authorization.
Do not enable its internal fake-only retention flag, copy its events, or perform an
equivalent SQL/file deletion in a provider-capable deployment.

## Staged Hermes routing

The redacted examples under `deploy/hermes/` preserve downstream aliases and
replace only their direct transport with local Signet paths:

```yaml
mcp_servers:
  fastmail:
    url: http://127.0.0.1:8789/mcp/fastmail
    headers:
      Authorization: "Bearer ${SIGNET_MCP_CALLER_TOKEN}"
    enabled: true
    connect_timeout: 10
    timeout: 120
    supports_parallel_tool_calls: false
    tools:
      resources: false
      prompts: false
    sampling:
      enabled: false
  whatsapp:
    url: http://127.0.0.1:8789/mcp/whatsapp
    headers:
      Authorization: "Bearer ${SIGNET_MCP_CALLER_TOKEN}"
    enabled: true
    connect_timeout: 10
    timeout: 120
    supports_parallel_tool_calls: false
    tools:
      resources: false
      prompts: false
    sampling:
      enabled: false
  signet_approvals:
    url: http://127.0.0.1:8789/mcp/approvals
    headers:
      Authorization: "Bearer ${SIGNET_MCP_CALLER_TOKEN}"
    enabled: true
    connect_timeout: 10
    timeout: 120
    supports_parallel_tool_calls: false
    tools:
      resources: false
      prompts: false
    sampling:
      enabled: false
```

They are illustrative and have not been generated from a live profile. During
authorized cutover, create timestamped redacted diffs from the current managed
profiles, check that active and disabled profiles have no alternate mutation path,
provision the profile-scoped token through a reviewed secret mechanism, and prefer
`/reload-mcp` or the client's supported MCP reload. A Hermes Gateway
restart needs separate explicit approval.

The token placeholder is resolved from the selected Hermes profile's mode-`0600`
`.env`; it is not a literal value and must not be stored in `config.yaml`. Explicitly
disabling parallel calls, resources, prompts, and sampling narrows the client side
of the integration as well as the Signet server. Use the scrubbed, locked
`signet_reviewed_live_hermes` invocation in `deploy/hermes/README.md` to test every
alias before `/reload-mcp` inside a Hermes session; never substitute a raw global
`hermes -p PROFILE` command. The fake configurator accepts only the blank
`signet-demo` profile and explicit fake credentials. The persistent configurator
accepts only a separate blank downstream-disabled profile, the one approval route,
and an exact real caller token on stdin. Neither is a live profile editor; the
helpers are not live profile editors or tools for changing the deferred three-alias
route.

Do not remove direct credentials before the local aliases, human authentication,
live schema digests, fake providers, backup restore, and rollback packet pass. Do
not leave direct credentials/routes enabled after successful cutover, because they
remain a bypass.

## Deferred human cutover packet

Automation may prepare commands and fake evidence but must not perform, simulate,
or wait on these steps. A human runs them later under an explicit change record:

1. Review and install a deployment assembly with downstreams still disabled.
2. Run an offline bootstrap ceremony to set the fallback password and enroll at
   least one passkey on the intended phone or physical authenticator. This
   repository currently has no enrollment CLI; supply and review that deployment
   procedure before proceeding. Optionally enroll TOTP without exposing its secret
   or any current code to logs/chat.
3. Enroll downstream credentials in the intended Keychain boundary. Store only the
   reference in policy; the runtime client configuration must also carry a non-secret
   credential-record generation digest. Replacing credential material at the same
   reference must atomically issue a new digest so queued requests fail closed.
4. Perform read-only live `tools/list` discovery through an authorized capture
   path, normalize the secret-free fixture offline, review every exact schema and
   digest, and keep sends denied.
5. Run fake-provider end-to-end tests proving zero calls before approval and one
   fenced call only after a test confirmation. No fake confirmation may be
   represented as a real human ceremony.
6. Complete and human-review the metadata-only bypass inventory. Resolve every
   active direct write path and unknown coverage item.
7. Create and verify an encrypted backup plus separate-path restore drill.
8. Review launchd, Serve/Funnel, Homepage, and timestamped Hermes diffs. Run
   `cutover-readiness`; missing evidence produces `disposition=blocked`. Even a
   syntactically complete packet produces `disposition=human_review_required`,
   `ready=false`, and `authorizes_live_changes=false`. The helper is advisory and
   cannot enable cutover.
9. Authorize service startup and the tailnet-only Serve listener. Verify login,
   exact RP/origin behavior, privacy-safe health/push, and that the app remains
   authenticated independent of Tailscale headers.
10. Authorize the Hermes MCP route reload. Do not restart the gateway unless reload
    cannot apply the reviewed change and a separate restart is approved.
11. Run the plan's human self-addressed email and harmless self-WhatsApp approve and
    deny checks. The human supplies real confirmations; implementation workers do
    not click, synthesize assertions, fabricate TOTP values, or send.
12. Verify status receipts, provider effects, approval push, denial no-send, access
    request plus `tools/list_changed`, and unknown-outcome handling.
13. After explicit acceptance, remove obsolete direct credentials and bypass
    routes. Run the inventory again and begin the planned soak.

The blocked examples in `deploy/operations/` intentionally make readiness fail.
Changing `present` to true is not evidence; each entry needs a non-secret reference
to the actual human-reviewed change record, and a human must independently verify
those records. No output of this offline helper authorizes a live operation.

## Rollback

Choose rollback based on what has already happened:

| Situation | Safe response |
| --- | --- |
| Before any pending acknowledgement | Stop staged jobs, remove only the Signet Serve listener, and leave direct routes unchanged. |
| Web proxy problem, MCP healthy | Remove only the Serve listener or repair TLS; keep MCP routes and database. No direct writes. |
| Client route reload failed before activation | Restore the reviewed client config diff; do not touch the Signet database. |
| Binary/config defect after pending acknowledgements | Keep the database, idempotency ledger, staging, and direct routes disabled. Stop dispatch if needed and repair forward with schema-compatible code. |
| Pending/executing/unknown requests exist | Never restore an older database or re-enable direct mutations. Preserve state and reconcile/repair forward. |
| Schema migration failed before acknowledgement | Use the verified pre-migration bundle only if the failure boundary and schema rules prove no acknowledged request would be forgotten. |
| Serve listener conflicts | Run the exact `tailscale serve --https=8443 off`; never reset unrelated handlers. |

Binary rollback is allowed only when the binary supports the current schema.
Configuration rollback must preserve policy versions and must not turn a gated send
into a direct send. A reverse Hermes diff is a last-resort reviewed change, not the
default response to a Signet incident.

After any rollback, rerun static health, database integrity, fake-provider tests,
schema digest comparison, bypass inventory, and readiness. Do not infer safety from
a process merely staying up.
