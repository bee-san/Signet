# No-live operator runbook

This runbook exercises Signet with repository-owned fake identities and in-process
fake providers only. It does not enroll human authentication, read a Keychain item,
inspect or change an existing Hermes profile, install a service, alter a proxy, or
contact Fastmail, WhatsApp, or `wacli`. The live deployment and cutover steps remain
deferred in [deployment.md](deployment.md).

Run the Signet commands from the repository root. Keep shell tracing disabled: it
can echo paths and command substitutions that ordinary logs intentionally omit.
The demo state, credentials, policy, schemas, web proof providers, and downstreams
are visibly fake and cannot be switched to a live provider through a demo flag.

## 1. Verify the checkout

Python 3.12 and exact `uv` version `0.11.28` are required. Install that `uv`
version with `pipx install 'uv==0.11.28'` or the official versioned
[`uv` installer](https://docs.astral.sh/uv/getting-started/installation/); inspect a
downloaded installer before executing it and do not use the unversioned installer.
The Playwright command below installs Chromium and, where supported, its operating-
system test dependencies; review any system-package changes it proposes. The SQLite
check must print `3.51.3` or newer.

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
  uv run python -c 'import sqlite3; print(sqlite3.sqlite_version)'
  uv run signet --help
  uv run signet demo --help
  uv run pytest -q
  uv run ruff check .
  uv run mypy
)
```

Do not proceed from an unreviewed dependency update or a failing check. Completing
this demo does not make a live deployment ready.

## 2. Initialize private fake state

Use one fixed destination under the physical home directory so every terminal can
derive the same absolute path without trusting a logical or symlinked working
directory. `demo init` never creates parents, accepts only a nonexistent
destination, rejects symlinked ancestors, and refuses to adopt or overwrite any
existing path, including an empty directory.

```console
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
test ! -e "$SIGNET_DEMO_DIR" && test ! -L "$SIGNET_DEMO_DIR" || exit 1
uv run signet demo init --data-dir "$SIGNET_DEMO_DIR" || exit 1
uv run signet demo smoke --data-dir "$SIGNET_DEMO_DIR" || exit 1
uv run signet demo seed-request --data-dir "$SIGNET_DEMO_DIR" || exit 1
```

The initializer creates a mode-`0700` tree, mode-`0600` state and secret files, an
initialized SQLite database, a deny-by-default fake policy, reviewed fake schemas,
and a profile-scoped fake MCP token. It never prints a credential. The default
`smoke` command is offline: it validates and assembles the saved state without
opening a listener or allowing a network/provider call.
The marker-guarded `seed-request` command acquires the serve lock and admits one
realistic fake email through the same gateway pipeline used by MCP. It prints only
safe request metadata. Re-running it while that request remains pending returns the
same request; after the request is resolved, a stopped-server run creates the next
one. It makes no Hermes, model, network, or provider call.

Credential retrieval emits exactly one explicitly fake value plus a newline. It is
separate from initialization and serve logs:

```console
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-user || exit 1
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-password || exit 1
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-login-proof || exit 1
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-action-proof || exit 1
```

`web-login-proof` and `web-action-proof` start with `fake:` and are deliberately
distinct. They are not authenticator codes and are not evidence of password, TOTP,
passkey, or recovery enrollment. Do not use a real address, phone number, message,
attachment, credential, or authentication proof in this tree.

## 3. Start and verify both apps

In terminal A, export the same absolute directory and start both loopback servers:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
  uv run signet demo serve --data-dir "$SIGNET_DEMO_DIR" \
    --mcp-port 8789 --web-port 8790
)
```

The only readiness lines are non-secret and have these forms:

```text
Signet fake-only demo MCP: http://127.0.0.1:8789/mcp/{fastmail,whatsapp,approvals}
Signet fake-only demo web: http://127.0.0.1:8790/login
```

In terminal B, run the explicit live-listener smoke probe and independent checks:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
  uv run signet demo smoke --data-dir "$SIGNET_DEMO_DIR" \
    --mcp-port 8789 --web-port 8790 --live
  curl --connect-timeout 5 --max-time 10 --fail --silent --show-error \
    http://127.0.0.1:8789/healthz
  curl --connect-timeout 5 --max-time 10 --fail --silent --show-error \
    http://127.0.0.1:8790/healthz
  SIGNET_UNAUTHENTICATED_STATUS="$(
    curl --connect-timeout 5 --max-time 10 --silent --show-error \
      --output /dev/null --write-out '%{http_code}' --request POST \
      http://127.0.0.1:8789/mcp/approvals
  )"
  if test "$SIGNET_UNAUTHENTICATED_STATUS" != 401; then
    printf 'expected unauthenticated MCP status 401, received %s\n' \
      "$SIGNET_UNAUTHENTICATED_STATUS" >&2
    exit 1
  fi
)
```

The health responses are `{"status":"ok"}` and
`{"status":"ok","service":"signet-web"}`. The unauthenticated MCP request must
return `401`. Health proves only that the processes are listening; it does not prove
live credential, schema, provider, policy, queue, or dispatch readiness.

Open `http://127.0.0.1:8790/login` in a local browser. Expand the fallback login and
enter the three values returned by `web-user`, `web-password`, and
`web-login-proof`. Demo HTTP cookies use narrowly validated loopback-only names and
settings. Production keeps secure `__Host-` cookies and a reviewed HTTPS origin;
never enable the demo cookie mode in a deployment or weaken Host, Origin, CSRF, or
WebAuthn checks to make plain HTTP work elsewhere.

## 4. Wire a disposable Hermes profile

Hermes is external software. The commands below use Signet's locked runtime and a
blank profile with no alias and no bundled skills; they never clone or select the
default profile. For another streamable-HTTP MCP agent, use the
[provider-neutral client guide](mcp-client-integration.md) to map the same local
routes, token boundary, alias names, and pending-result lifecycle into that client's
reviewed configuration. The remainder of this section is intentionally Hermes-
specific.

The checked-in runtime requests `hermes-agent[mcp]==0.18.2`; its file preflight is
also regression tested against the v0.16.0 profile layout. A bare Hermes package
does not include the MCP SDK, which is why no global command is used here. Never
repair this procedure by installing or upgrading a standalone `mcp` package.

The bounded integration below needs `uv`, but it does not depend on or reuse a
globally installed Hermes command. The checked-in `deploy/hermes/runtime/uv.lock`
pins the complete Python 3.12 dependency graph and artifact hashes. Each command
clears inherited environment variables and uses `uv run --locked --isolated` with
source builds disabled. Hermes 0.18.2 exactly pins three dependency versions with
published advisories; the runtime's explicit `tool.uv.override-dependencies` selects
their audited patched releases. This intentionally differs from a default Hermes
install and is exercised by real profile/MCP tests. CI checks lock freshness, runs
the locked command on Linux and macOS, and audits the fully hashed export. Do not
remove or change an override without repeating those checks. The upstream
[installation guide](https://github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/website/docs/getting-started/installation.md)
documents platform prerequisites; a global/source installation is outside this
procedure's security boundary and must not be substituted for the locked command.

```console
umask 077 || exit 1
SIGNET_REPO="$(pwd -P)" || exit 1
export SIGNET_REPO
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
SIGNET_DEMO_HERMES_HOME="$SIGNET_HOME/.signet-fake-hermes-home"
SIGNET_DEMO_HERMES_ROOT="$SIGNET_DEMO_HERMES_HOME/.hermes"
SIGNET_DEMO_HERMES_MANAGED_DIR="$SIGNET_DEMO_HERMES_HOME/.no-managed-scope"
SIGNET_HERMES_PROFILES_ROOT="$SIGNET_DEMO_HERMES_ROOT/profiles"
"$SIGNET_REPO/.venv/bin/python" \
  "$SIGNET_REPO/deploy/prepare-owned-directory.py" \
  --directory "$SIGNET_HERMES_PROFILES_ROOT" || exit 1
if test -L "$SIGNET_DEMO_HERMES_ROOT/.env"; then
  printf 'refusing linked disposable Hermes root environment\n' >&2
  exit 1
fi
if ! test -e "$SIGNET_DEMO_HERMES_ROOT/.env"; then
  (set -o noclobber && : > "$SIGNET_DEMO_HERMES_ROOT/.env") || exit 1
fi
"$SIGNET_REPO/.venv/bin/python" \
  "$SIGNET_REPO/deploy/validate-private-paths.py" \
  --directory "$SIGNET_DEMO_HERMES_ROOT" \
  --private-file "$SIGNET_DEMO_HERMES_ROOT/.env" || exit 1
if test -s "$SIGNET_DEMO_HERMES_ROOT/.env"; then
  printf 'refusing nonempty disposable Hermes root environment\n' >&2
  exit 1
fi
if test -e "$SIGNET_DEMO_HERMES_ROOT/.update_check" || \
   test -L "$SIGNET_DEMO_HERMES_ROOT/.update_check"; then
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_DEMO_HERMES_ROOT" \
    --private-file "$SIGNET_DEMO_HERMES_ROOT/.update_check" || exit 1
fi
if test -e "$SIGNET_DEMO_HERMES_ROOT/logs" || \
   test -L "$SIGNET_DEMO_HERMES_ROOT/logs"; then
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_DEMO_HERMES_ROOT/logs" || exit 1
  SIGNET_UNEXPECTED_HERMES_LOG="$(
    find "$SIGNET_DEMO_HERMES_ROOT/logs" -mindepth 1 -maxdepth 1 \
      ! -name agent.log ! -name errors.log -print -quit
  )" || exit 1
  if test -n "$SIGNET_UNEXPECTED_HERMES_LOG"; then
    printf 'refusing unexpected disposable Hermes log entry: %s\n' \
      "$SIGNET_UNEXPECTED_HERMES_LOG" >&2
    exit 1
  fi
  for name in agent.log errors.log; do
    SIGNET_HERMES_CANDIDATE="$SIGNET_DEMO_HERMES_ROOT/logs/$name"
    if test -e "$SIGNET_HERMES_CANDIDATE" || test -L "$SIGNET_HERMES_CANDIDATE"; then
      "$SIGNET_REPO/.venv/bin/python" \
        "$SIGNET_REPO/deploy/validate-private-paths.py" \
        --directory "$SIGNET_DEMO_HERMES_ROOT/logs" \
        --private-file "$SIGNET_HERMES_CANDIDATE" || exit 1
    fi
  done
  unset SIGNET_UNEXPECTED_HERMES_LOG
fi
SIGNET_UNEXPECTED_HERMES_ROOT_ENTRY="$(
  find "$SIGNET_DEMO_HERMES_ROOT" -mindepth 1 -maxdepth 1 \
    ! -name .env ! -name profiles ! -name .update_check ! -name logs -print -quit
)" || exit 1
if test -n "$SIGNET_UNEXPECTED_HERMES_ROOT_ENTRY"; then
  printf 'refusing unexpected disposable Hermes root entry: %s\n' \
    "$SIGNET_UNEXPECTED_HERMES_ROOT_ENTRY" >&2
  exit 1
fi
SIGNET_UNEXPECTED_HERMES_PROFILE="$(
  find "$SIGNET_HERMES_PROFILES_ROOT" -mindepth 1 -maxdepth 1 -print -quit
)" || exit 1
if test -n "$SIGNET_UNEXPECTED_HERMES_PROFILE"; then
  printf 'refusing nonempty disposable Hermes profiles root: %s\n' \
    "$SIGNET_UNEXPECTED_HERMES_PROFILE" >&2
  exit 1
fi
unset SIGNET_UNEXPECTED_HERMES_ROOT_ENTRY SIGNET_UNEXPECTED_HERMES_PROFILE
if test -e "$SIGNET_DEMO_HERMES_MANAGED_DIR" || \
   test -L "$SIGNET_DEMO_HERMES_MANAGED_DIR"; then
  printf 'refusing existing disposable Hermes managed-scope path: %s\n' \
    "$SIGNET_DEMO_HERMES_MANAGED_DIR" >&2
  exit 1
fi
signet_demo_hermes() {
  env -i PATH="$PATH" HOME="$SIGNET_DEMO_HERMES_HOME" \
    HERMES_HOME="$SIGNET_DEMO_HERMES_ROOT" \
    HERMES_MANAGED_DIR="$SIGNET_DEMO_HERMES_MANAGED_DIR" \
    uv run --locked --isolated --no-config \
      --exclude-newer 2026-07-09T00:00:00Z --no-env-file --no-sources --no-build \
      --project "$SIGNET_REPO/deploy/hermes/runtime" hermes "$@"
}
SIGNET_EXPECTED_HERMES_PROFILE="$SIGNET_HERMES_PROFILES_ROOT/signet-demo"
if test -e "$SIGNET_EXPECTED_HERMES_PROFILE" || \
   test -L "$SIGNET_EXPECTED_HERMES_PROFILE"; then
  printf 'refusing existing Hermes profile path: %s\n' \
    "$SIGNET_EXPECTED_HERMES_PROFILE" >&2
  exit 1
fi
signet_demo_hermes --version || exit 1
signet_demo_hermes mcp --help || exit 1
signet_demo_hermes profile list || exit 1
if ! signet_demo_hermes profile create signet-demo --no-alias --no-skills; then
  printf 'refusing existing or failed Hermes profile: signet-demo\n' >&2
  exit 1
fi
SIGNET_DEMO_HERMES_CONFIG="$(
  signet_demo_hermes -p signet-demo config path
)" || exit 1
case "$SIGNET_DEMO_HERMES_CONFIG" in
  /*) ;;
  *)
    printf 'refusing non-absolute Hermes config path\n' >&2
    exit 1
    ;;
esac
case "$SIGNET_DEMO_HERMES_CONFIG" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing Hermes config path outside physical HOME\n' >&2
    exit 1
    ;;
esac
SIGNET_DEMO_HERMES_CONFIG_PARENT="$(
  cd "$(dirname "$SIGNET_DEMO_HERMES_CONFIG")" && pwd -P
)" || exit 1
SIGNET_DEMO_HERMES_CONFIG="$SIGNET_DEMO_HERMES_CONFIG_PARENT/$(
  basename "$SIGNET_DEMO_HERMES_CONFIG"
)" || exit 1
export SIGNET_DEMO_HERMES_CONFIG
unset SIGNET_DEMO_HERMES_CONFIG_PARENT
SIGNET_DEMO_HERMES_ENV="$(
  signet_demo_hermes -p signet-demo config env-path
)" || exit 1
case "$SIGNET_DEMO_HERMES_ENV" in
  /*) ;;
  *)
    printf 'refusing non-absolute Hermes environment path\n' >&2
    exit 1
    ;;
esac
case "$SIGNET_DEMO_HERMES_ENV" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing Hermes environment path outside physical HOME\n' >&2
    exit 1
    ;;
esac
SIGNET_DEMO_HERMES_ENV_PARENT="$(
  cd "$(dirname "$SIGNET_DEMO_HERMES_ENV")" && pwd -P
)" || exit 1
SIGNET_DEMO_HERMES_ENV="$SIGNET_DEMO_HERMES_ENV_PARENT/$(
  basename "$SIGNET_DEMO_HERMES_ENV"
)" || exit 1
export SIGNET_DEMO_HERMES_ENV
unset SIGNET_DEMO_HERMES_ENV_PARENT
SIGNET_DEMO_HERMES_PARENT="${SIGNET_DEMO_HERMES_CONFIG%/*}"
if test "${SIGNET_DEMO_HERMES_CONFIG##*/}" != config.yaml || \
   test "${SIGNET_DEMO_HERMES_ENV##*/}" != .env || \
   test "${SIGNET_DEMO_HERMES_ENV%/*}" != "$SIGNET_DEMO_HERMES_PARENT" || \
   test "$SIGNET_DEMO_HERMES_PARENT" != "$SIGNET_EXPECTED_HERMES_PROFILE"; then
  printf 'refusing unexpected Hermes profile file paths\n' >&2
  exit 1
fi
case "$SIGNET_DEMO_HERMES_CONFIG" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing canonical Hermes config path outside physical HOME\n' >&2
    exit 1
    ;;
esac
case "$SIGNET_DEMO_HERMES_ENV" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing canonical Hermes environment path outside physical HOME\n' >&2
    exit 1
    ;;
esac
if ! test -d "$SIGNET_DEMO_HERMES_PARENT" || \
   test -L "$SIGNET_DEMO_HERMES_PARENT" || \
   ! test -O "$SIGNET_DEMO_HERMES_PARENT"; then
  printf 'refusing unowned or linked Hermes profile directory\n' >&2
  exit 1
fi
SIGNET_UNSAFE_HERMES_PARENT="$(
  find "$SIGNET_DEMO_HERMES_PARENT" -prune \
    \( -perm -020 -o -perm -002 \) -print
)" || exit 1
if test -n "$SIGNET_UNSAFE_HERMES_PARENT"; then
  printf 'refusing group/world-writable Hermes profile directory\n' >&2
  exit 1
fi
unset SIGNET_UNSAFE_HERMES_PARENT
"$SIGNET_REPO/.venv/bin/python" \
  "$SIGNET_REPO/deploy/validate-private-paths.py" \
  --directory "$SIGNET_DEMO_HERMES_PARENT" || exit 1
if test -e "$SIGNET_DEMO_HERMES_CONFIG" || test -L "$SIGNET_DEMO_HERMES_CONFIG"; then
  printf 'refusing existing Hermes config: %s\n' "$SIGNET_DEMO_HERMES_CONFIG" >&2
  exit 1
fi
(umask 077 && set -o noclobber && : > "$SIGNET_DEMO_HERMES_CONFIG") || exit 1
if test -L "$SIGNET_DEMO_HERMES_ENV"; then
  printf 'refusing linked Hermes environment: %s\n' "$SIGNET_DEMO_HERMES_ENV" >&2
  exit 1
fi
if ! test -e "$SIGNET_DEMO_HERMES_ENV"; then
  (umask 077 && set -o noclobber && : > "$SIGNET_DEMO_HERMES_ENV") || exit 1
fi
unset SIGNET_DEMO_HERMES_PARENT
```

Hermes profile operations and startup environment loading can use `HERMES_HOME`,
`HOME`, a root `.env`, and a machine managed scope. This demo never points Hermes at
the operator's existing state: it creates or validates a dedicated private home and
Hermes root under the physical home, requires an empty private root `.env`, an empty
`profiles` directory, and only validated private update/log metadata left by the
pinned CLI. It overrides any inherited `HERMES_HOME` and points managed-scope
discovery at a checked-absent path. The profile root is descriptor-validated before
the first Hermes command. That bounded invariant also makes a validated recovery or
later second demo run repeatable.

If a command fails after `profile create` succeeds, stop and do not rerun the
preparation block over that partial profile. Run the self-contained checked profile
deletion transaction in [step 8](#8-stop-and-roll-back-the-demo). It re-derives every
path, rejects unrelated sibling profiles, recursively validates every descendant in
the isolated profile, exact-compares both paths reported by Hermes, deletes only
`signet-demo`, and verifies absence. If any check refuses: do not invoke another Hermes command.
Stop and resolve the ownership, ancestry, or inventory problem.
After successful deletion, restart the whole preparation block. Never use a
recursive filesystem delete as recovery.

Stop if `signet-demo` already exists. Do not repurpose it or substitute another
profile path. Hermes Agent v0.16.0 reports the new profile paths without creating
either file. Version v0.18.2 leaves `config.yaml` absent, seeds a mode-`0600`,
comment-only `.env`, and creates its private no-skills profile skeleton. Later config
and MCP commands may add bounded private cache and log state. Every demo Hermes
command uses the dedicated isolated home and root, and each reported profile-file
parent is canonicalized before a file is inspected or created. The configurator then
verifies content, ownership, mode, link count, and identity. Generate the exact
current-port fragment into the private demo tree, then stream the token directly
into the checked-in structured merge helper:

```console
(
  set -e
  set -o pipefail
  umask 077
  set -o noclobber
  SIGNET_REPO="$(pwd -P)"
  export SIGNET_REPO
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
  export SIGNET_DEMO_HERMES_FRAGMENT="$SIGNET_DEMO_DIR/hermes-profile.yaml"
  uv run signet demo hermes-config --data-dir "$SIGNET_DEMO_DIR" \
    --mcp-port 8789 > "$SIGNET_DEMO_HERMES_FRAGMENT"
  uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field mcp-token | \
    uv run python "$SIGNET_REPO/deploy/hermes/configure-demo-profile.py" \
      --config "$SIGNET_DEMO_HERMES_CONFIG" \
      --env-file "$SIGNET_DEMO_HERMES_ENV" \
      --fragment "$SIGNET_DEMO_HERMES_FRAGMENT"
)
```

The helper accepts only the exact three `127.0.0.1` routes, the
`${SIGNET_DEMO_MCP_CALLER_TOKEN}` placeholder, disabled parallel calls/resources/
prompts/sampling, and bounded timeouts. It refuses a nonblank profile environment,
existing MCP routes, duplicate YAML keys, symlinks, unsafe modes, raw/non-fake
tokens, unknown fields, and non-loopback URLs. The raw token travels over the pipe;
it is never an argument, environment variable, generated YAML value, or log field.

Validate transport and authenticated discovery while the demo server is running:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  SIGNET_DEMO_HERMES_HOME="$SIGNET_HOME/.signet-fake-hermes-home"
  SIGNET_DEMO_HERMES_ROOT="$SIGNET_DEMO_HERMES_HOME/.hermes"
  SIGNET_DEMO_HERMES_MANAGED_DIR="$SIGNET_DEMO_HERMES_HOME/.no-managed-scope"
  signet_demo_hermes() {
    env -i PATH="$PATH" HOME="$SIGNET_DEMO_HERMES_HOME" \
      HERMES_HOME="$SIGNET_DEMO_HERMES_ROOT" \
      HERMES_MANAGED_DIR="$SIGNET_DEMO_HERMES_MANAGED_DIR" \
      uv run --locked --isolated --no-config \
        --exclude-newer 2026-07-09T00:00:00Z --no-env-file --no-sources --no-build \
        --project "$SIGNET_REPO/deploy/hermes/runtime" hermes "$@"
  }
  signet_demo_hermes -p signet-demo config check
  signet_demo_hermes -p signet-demo mcp test signet_demo_fastmail
  signet_demo_hermes -p signet-demo mcp test signet_demo_whatsapp
  signet_demo_hermes -p signet-demo mcp test signet_demo_approvals
  signet_demo_hermes -p signet-demo mcp list
)
```

For the intentionally minimal profile, Hermes may print a release-specific
`Config version: 0 -> N (update available)` advisory while `config check` exits `0`.
That advisory is expected here. Do not run `config migrate`: it interactively
expands the blank file into broad release defaults. The minimal file still inherits
Hermes' built-in defaults, so keep the profile disposable and keep its environment
free of live provider keys or other credentials.

The three tests are the MCP dependency preflight as well as transport/authenticated
discovery tests. They must connect and report `4`, `3`, and `4` tools respectively.
The approvals surface intentionally omits `approve_request`; demo automation cannot
manufacture a six-digit TOTP code. It still exposes caller-scoped list, status,
cancel, and access request tools. An MCP `401` means the selected profile/token is
wrong, not that auth should be disabled.

Connection testing does not need a model credential or make an LLM call. A Hermes
chat requires separately configuring a model in this blank profile and may contact
an external model provider or incur cost. That optional decision is outside the
automated no-live proof. Never clone a credentialed/default profile merely to run
the demo, and review/restrict Hermes' inherited tool defaults before adding any
model credential.

The commands follow the current official
[Hermes MCP guide](https://github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/website/docs/user-guide/features/mcp.md),
[CLI reference](https://github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/website/docs/reference/cli-commands.md),
and
[profile guide](https://github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/website/docs/user-guide/profiles.md).
Check the installed version's help before applying any later live diff.

## 5. Exercise fake workflows

The seeded request from step 2 is already pending, so the full web review needs no
Hermes model credential. Sign in at `http://127.0.0.1:8790/login`, expand that row,
and verify the complete frozen arguments, explicit reason, warnings,
policy/adapter/schema versions, full payload hash, attachments, origin, and event
timeline. Deny it with a specific reason and the fake action proof, then expand its
immutable audit event to verify that exact denied version and reasoning remain
available.

To exercise approval as a second independent request, stop the demo server cleanly,
run `uv run signet demo seed-request --data-dir "$SIGNET_DEMO_DIR"`, restart the
same serve command, and approve the newly returned request after reviewing it. The
bounded fake delivery worker makes exactly one in-process fake-provider call and
reaches `succeeded`; no network provider exists in this demo.

Optionally, if a human separately chooses to configure a model in `signet-demo`,
start a new session with `signet_demo_hermes -p signet-demo chat` after defining the
same pinned helper shown above. Give Hermes exact tool-call instructions; do not
rely on a natural-language guess. The expected prefixed tools and arguments are:

```text
Call mcp_signet_demo_fastmail_list_identities with {} and return its exact result.

Call mcp_signet_demo_fastmail_send_email with
{"from":"fake-sender@demo.invalid","to":["fake-recipient@demo.invalid"],
 "cc":[],"bcc":[],"subject":"Signet demo",
 "body":"This is a fake-only approval test.","attachments":[]}.

Call mcp_signet_demo_approvals_list_pending_approvals with {}.
```

The optional read returns only `fake:`/`.invalid` fixture data. The optional send returns a durable
`pending_approval` response and makes zero fake-provider calls. Record its
`request_id` and `version_hash_prefix`. In the web queue, expand the row and verify
the complete frozen arguments, reason, warnings, policy/adapter/schema versions,
hashes, attachments, origin, and event timeline.

When Hermes is configured, use the status surface to verify the first seeded
denial by its recorded ID:

```text
Call mcp_signet_demo_approvals_check_approval_status with
{"request_id":"REQUEST_ID_FROM_THE_DENIED_CALL"}.
```

It must return `denied`, and the expanded timeline must show zero provider calls.
The action proof is visibly constant, but every accepted use receives a distinct
durable fake-only use ID, including across restart. The approved seeded request
must reach `succeeded`; status returns only safe result metadata, not the frozen
private payload. Calling
`mcp_signet_demo_fastmail_delete_email` with
`{"message_id":"fake:message:never-delete"}` must return `policy_denied`.

Open **Audit**, find **Recent approvals and denials**, and expand both retained
decisions. For each, verify the decision actor, confirmation method and path, full
frozen request content, selected reason code and label, outcome, attachment metadata/content
references, and complete event timeline. The queue is for pending work; retained
approved and denied context remains discoverable from this audit section.

The WhatsApp path can be checked the same way:

```text
Call mcp_signet_demo_whatsapp_list_chats with {}.
Call mcp_signet_demo_whatsapp_send_text with
{"to":"15555550123@s.whatsapp.net",
 "message":"This is a fake-only approval test."}.
Call mcp_signet_demo_whatsapp_delete_chat with
{"jid":"15555550123@s.whatsapp.net"}.
```

After a config change during a Hermes session, use `/reload-mcp` inside that
session, then start a new session. `/reload-mcp` is not a shell command. Do not
restart a Hermes gateway for this demo.

To verify restart durability, interrupt terminal A once, wait for bounded workers
to stop, and run the same `demo serve` command again. Recheck the terminal request
by ID. Its state and timeline must persist, and the fake effect count must remain
one.

## 6. Redact an exhausted fake unknown

This command exists only for disposable fake-only fault-injection drills. It is not
production authorization. A normal demo should never need it. First stop the demo
server. In the expanded authenticated review, record the exact request ID, version,
and full payload hash before shutdown. Run the command only after the event timeline
shows that bounded reconciliation is exhausted:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
  uv run signet demo purge-unknown --data-dir "$SIGNET_DEMO_DIR" \
    --request-id 'REPLACE_WITH_EXACT_FAKE_REQUEST_ID' \
    --expected-version 'REPLACE_WITH_EXACT_VERSION' \
    --expected-payload-hash 'REPLACE_WITH_EXACT_64_CHARACTER_HASH' \
    --acknowledge-possible-delivery
)
```

The marker-guarded command acquires the demo serve lock, requires the exact current
revision and durable exhaustion, records authorization and completion events, and
redacts the fake payload and safe outcome metadata. It never changes
`outcome_unknown`: the external effect **may have happened**, reconciliation becomes
permanently unavailable, and the request/hash/timeline remain. Repeating the exact
command is idempotent. A stale hash, active backup pin, running server, non-exhausted
attempt, missing acknowledgement, or non-demo tree rejects before purge
authorization is recorded or work is queued.

A first successful run prints only this non-sensitive JSON (field order may differ):

```json
{"claimed":2,"completed":2,"failed":0,"scheduled":2,"state":"outcome_unknown","status":"fake_only_content_purged","uncertainty_preserved":true}
```

An exact replay succeeds with `scheduled`, `claimed`, and `completed` all set to
`0`. An active-backup rejection is not an incomplete purge: keep the server stopped,
wait for the verified backup operation to release its pin (or release it only
through that operation's reviewed normal procedure), then repeat the exact bound
command. Only an `incomplete` result indicates a storage or retention-worker failure
after authorization. Resolve that failure and repeat the same bound command; do not
edit queued jobs, backup pins, authorization events, or the timeline directly.

This is logical deletion in the bundled demo. Bytes may remain in SQLite free pages,
WAL history, APFS snapshots, swap, crash dumps, or prior encrypted backups. Apply
retention separately to those copies. Production keeps exhausted unknown content
indefinitely until a future release supplies schema-backed, request-bound human
authorization; never reproduce this operation with SQL or direct file deletion.

## 7. Back up and restore demo state

Stop the original demo server cleanly before this drill. Choose new output paths;
both commands refuse overwrite. The bundle parent must be a private, operator-owned
directory; `BackupBundleManager` intentionally refuses a shared parent such as
`/tmp` because it cannot harden that directory to mode `0700`.

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
  export SIGNET_DEMO_ARTIFACTS="$SIGNET_HOME/.signet-fake-demo-artifacts"
  if test -e "$SIGNET_DEMO_ARTIFACTS" || test -L "$SIGNET_DEMO_ARTIFACTS"; then
    printf 'refusing existing demo backup artifacts: %s\n' \
      "$SIGNET_DEMO_ARTIFACTS" >&2
    exit 1
  fi
  install -d -m 0700 "$SIGNET_DEMO_ARTIFACTS"
  export SIGNET_DEMO_BACKUP="$SIGNET_DEMO_ARTIFACTS/operator-demo.signet-backup"
  export SIGNET_DEMO_RESTORE="$SIGNET_DEMO_ARTIFACTS/restored"
  test ! -e "$SIGNET_DEMO_BACKUP" && \
    test ! -L "$SIGNET_DEMO_BACKUP" || exit 1
  test ! -e "$SIGNET_DEMO_RESTORE" && \
    test ! -L "$SIGNET_DEMO_RESTORE" || exit 1
  uv run signet demo backup --data-dir "$SIGNET_DEMO_DIR" \
    --output "$SIGNET_DEMO_BACKUP"
  uv run signet demo restore --data-dir "$SIGNET_DEMO_DIR" \
    --bundle "$SIGNET_DEMO_BACKUP" --destination "$SIGNET_DEMO_RESTORE"
  test "$SIGNET_DEMO_DIR" != "$SIGNET_DEMO_RESTORE"
  uv run signet demo smoke --data-dir "$SIGNET_DEMO_RESTORE"
)
```

The new artifacts directory is the transaction boundary for this drill. Any
failure leaves it in place, so the same block refuses to reuse a stale bundle or
partially restored tree. Inspect the failed directory, choose a separately reviewed
new artifacts path for a retry, and never remove it merely to make the check pass.
Interpret the bounded backup error literally: “was not published” requires retention
pin recovery before retry; “outcome is unknown” requires accounting for the exact
destination and forbids a blind retry; “published durably” means keep the existing
bundle and resolve the named private-artifact warning instead of recreating it. The
complete API contract is in [deployment.md](deployment.md#backup-and-restore).
If restore reports that its private tree could not be removed, treat that tree as
sensitive and incomplete: it can contain a database and newly rotated fake secrets.
Do not start, merge, or share it. Keep its parent private and resolve the exact tree
identity before selecting a new restore destination.

The demo wrapper resolves the backup key only from the source's mode-`0600` secret
file; no key enters argv or the environment. It uses `BackupBundleManager`, not
`cp`, and restore targets a nonexistent tree. Restore authenticates the encrypted
bundle, checks the manifest/database/foreign keys/attachment envelopes, retains only
the payload keys needed to read restored fake state, and rotates the MCP token, web
password, session/capability keys, and future backup key. Retrieve restored fake
credentials only through `demo credentials`; the original Hermes token must not
authenticate the restored instance.

All supported demo backup, restore, and pre-migration backup entry points share the
marker-guarded `.backup-maintenance.lock`. A clean operation releases its retention
pins automatically. If and only if a demo backup process was forcibly terminated,
stop the demo server and every backup, restore, and snapshot process, identify an
inclusive cutoff older than the terminated operation, and release those abandoned
fake-only pin rows with:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_DIR="$SIGNET_HOME/.signet-fake-demo"
  uv run signet demo release-abandoned-pins --data-dir "$SIGNET_DEMO_DIR" \
    --created-at-or-before UNIX_SECONDS \
    --acknowledge-no-backup-active
)
```

The command refuses a running server, an active backup-maintenance lock, an invalid
demo marker, a future cutoff, or a missing acknowledgement. Its JSON output reports
only the cutoff and released/remaining row counts. Never use the cutoff to release
pins for an operation that might still be running, and never edit `purge_jobs`
directly.

Start the restored tree on alternate ports in terminal A:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_RESTORE="$SIGNET_HOME/.signet-fake-demo-artifacts/restored"
  uv run signet demo serve --data-dir "$SIGNET_DEMO_RESTORE" \
    --mcp-port 8889 --web-port 8890
)
```

Then verify it from terminal B:

```console
(
  set -e
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  export SIGNET_DEMO_RESTORE="$SIGNET_HOME/.signet-fake-demo-artifacts/restored"
  uv run signet demo smoke --data-dir "$SIGNET_DEMO_RESTORE" \
    --mcp-port 8889 --web-port 8890 --live
)
```

Restore never activates or overwrites the source tree. For live state, follow the
stricter procedure in [deployment.md](deployment.md#backup-and-restore); never
restore an older database that could forget a pending acknowledgement or ambiguous
downstream outcome.

## 8. Stop and roll back the demo

Stop each demo process with one normal interrupt and wait for bounded workers to
exit. Do not use `kill -9` unless deliberately recording a crash-recovery test.
Delete only the disposable Hermes profile:

```console
(
  set -e
  umask 077
  SIGNET_REPO="$(pwd -P)"
  export SIGNET_REPO
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  SIGNET_DEMO_HERMES_HOME="$SIGNET_HOME/.signet-fake-hermes-home"
  SIGNET_DEMO_HERMES_ROOT="$SIGNET_DEMO_HERMES_HOME/.hermes"
  SIGNET_DEMO_HERMES_MANAGED_DIR="$SIGNET_DEMO_HERMES_HOME/.no-managed-scope"
  SIGNET_HERMES_PROFILES_ROOT="$SIGNET_DEMO_HERMES_ROOT/profiles"
  SIGNET_EXPECTED_HERMES_PROFILE="$SIGNET_DEMO_HERMES_ROOT/profiles/signet-demo"
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_DEMO_HERMES_ROOT" \
    --private-file "$SIGNET_DEMO_HERMES_ROOT/.env"
  if test -s "$SIGNET_DEMO_HERMES_ROOT/.env"; then
    printf 'refusing nonempty disposable Hermes root environment\n' >&2
    exit 1
  fi
  if test -e "$SIGNET_DEMO_HERMES_MANAGED_DIR" || \
     test -L "$SIGNET_DEMO_HERMES_MANAGED_DIR"; then
    printf 'refusing existing disposable Hermes managed-scope path: %s\n' \
      "$SIGNET_DEMO_HERMES_MANAGED_DIR" >&2
    exit 1
  fi
  if test -e "$SIGNET_DEMO_HERMES_ROOT/.update_check" || \
     test -L "$SIGNET_DEMO_HERMES_ROOT/.update_check"; then
    "$SIGNET_REPO/.venv/bin/python" \
      "$SIGNET_REPO/deploy/validate-private-paths.py" \
      --directory "$SIGNET_DEMO_HERMES_ROOT" \
      --private-file "$SIGNET_DEMO_HERMES_ROOT/.update_check"
  fi
  if test -e "$SIGNET_DEMO_HERMES_ROOT/logs" || \
     test -L "$SIGNET_DEMO_HERMES_ROOT/logs"; then
    "$SIGNET_REPO/.venv/bin/python" \
      "$SIGNET_REPO/deploy/validate-private-paths.py" \
      --directory "$SIGNET_DEMO_HERMES_ROOT/logs"
    SIGNET_UNEXPECTED_HERMES_LOG="$(
      find "$SIGNET_DEMO_HERMES_ROOT/logs" -mindepth 1 -maxdepth 1 \
        ! -name agent.log ! -name errors.log -print -quit
    )"
    if test -n "$SIGNET_UNEXPECTED_HERMES_LOG"; then
      printf 'refusing unexpected disposable Hermes log entry: %s\n' \
        "$SIGNET_UNEXPECTED_HERMES_LOG" >&2
      exit 1
    fi
    for name in agent.log errors.log; do
      SIGNET_HERMES_CANDIDATE="$SIGNET_DEMO_HERMES_ROOT/logs/$name"
      if test -e "$SIGNET_HERMES_CANDIDATE" || \
         test -L "$SIGNET_HERMES_CANDIDATE"; then
        "$SIGNET_REPO/.venv/bin/python" \
          "$SIGNET_REPO/deploy/validate-private-paths.py" \
          --directory "$SIGNET_DEMO_HERMES_ROOT/logs" \
          --private-file "$SIGNET_HERMES_CANDIDATE"
      fi
    done
  fi
  SIGNET_UNEXPECTED_HERMES_ROOT_ENTRY="$(
    find "$SIGNET_DEMO_HERMES_ROOT" -mindepth 1 -maxdepth 1 \
      ! -name .env ! -name profiles ! -name .update_check ! -name logs -print -quit
  )"
  if test -n "$SIGNET_UNEXPECTED_HERMES_ROOT_ENTRY"; then
    printf 'refusing unexpected disposable Hermes root entry: %s\n' \
      "$SIGNET_UNEXPECTED_HERMES_ROOT_ENTRY" >&2
    exit 1
  fi
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_HERMES_PROFILES_ROOT"
  SIGNET_UNEXPECTED_HERMES_PROFILE="$(
    find "$SIGNET_HERMES_PROFILES_ROOT" -mindepth 1 -maxdepth 1 \
      ! -name signet-demo -print -quit
  )"
  if test -n "$SIGNET_UNEXPECTED_HERMES_PROFILE"; then
    printf 'refusing unrelated disposable Hermes profile: %s\n' \
      "$SIGNET_UNEXPECTED_HERMES_PROFILE" >&2
    exit 1
  fi
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_EXPECTED_HERMES_PROFILE" \
    --private-tree
  signet_demo_hermes() {
    env -i PATH="$PATH" HOME="$SIGNET_DEMO_HERMES_HOME" \
      HERMES_HOME="$SIGNET_DEMO_HERMES_ROOT" \
      HERMES_MANAGED_DIR="$SIGNET_DEMO_HERMES_MANAGED_DIR" \
      uv run --locked --isolated --no-config \
        --exclude-newer 2026-07-09T00:00:00Z --no-env-file --no-sources --no-build \
        --project "$SIGNET_REPO/deploy/hermes/runtime" hermes "$@"
  }
  SIGNET_CLEANUP_HERMES_CONFIG="$(
    signet_demo_hermes -p signet-demo config path
  )"
  SIGNET_CLEANUP_HERMES_ENV="$(
    signet_demo_hermes -p signet-demo config env-path
  )"
  if test "$SIGNET_CLEANUP_HERMES_CONFIG" != \
       "$SIGNET_EXPECTED_HERMES_PROFILE/config.yaml" || \
     test "$SIGNET_CLEANUP_HERMES_ENV" != \
       "$SIGNET_EXPECTED_HERMES_PROFILE/.env"; then
    printf 'refusing cleanup of unexpected Hermes profile paths\n' >&2
    exit 1
  fi
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_EXPECTED_HERMES_PROFILE" \
    --private-tree
  signet_demo_hermes profile delete signet-demo -y
  if test -e "$SIGNET_EXPECTED_HERMES_PROFILE" || \
     test -L "$SIGNET_EXPECTED_HERMES_PROFILE"; then
    printf 'Hermes profile remains after reported deletion: %s\n' \
      "$SIGNET_EXPECTED_HERMES_PROFILE" >&2
    exit 1
  fi
  signet_demo_hermes profile list
)
```

The recursive profile preflight accepts names created inside only this dedicated
profile, but it does not trust their shape: the tree is limited to 16 levels, 1,024
entries, and 64 MiB. Every directory must be an owned mode-`0700` directory on the
same filesystem; every file must be an owned, single-link mode-`0600` regular file.
Links, special files, granting ACLs, cross-filesystem traversal, and identity changes
refuse before and again after the path-reporting commands. This covers the pinned
v0.18.2 no-skills/cache/log skeleton without deleting an unbounded or redirected
tree.

This preflight prevents accidental or other-user substitution beneath the owned
mode-`0700` root; it cannot make Hermes' path-based deletion descriptor-transactional.
A privileged mount change, including a same-filesystem bind mount, or a malicious
process running as the same UID could mutate the tree after the final check. Those
actors can already alter this account's private profile state and are outside this
recovery boundary. Do not run recovery concurrently with another process under that
UID. If deletion or either post-deletion check reports an anomaly, stop, resolve the
mutation, and retry the complete checked transaction from the beginning.

Before removing any state, fragment, restored tree, or bundle, inspect and confirm
each absolute path from this run. No recursive-delete command is provided because a
mistyped/substituted path is more dangerous than leftover fake state. Remember that
the encrypted bundle remains data-bearing and that deleting its source secrets can
make it unrecoverable.

Demo rollback does not modify Tailscale Serve, launchd, Homepage, a live Hermes
profile, or a direct provider route because the demo never touches them.

## Troubleshooting

| Symptom | Check | Safe response |
| --- | --- | --- |
| `demo init` refuses the directory | Exact `SIGNET_DEMO_DIR`, ownership, contents | Select a new reviewed private destination under the physical home directory, and use that exact path in every terminal. Never adopt or erase unknown state. |
| `connection refused` | Process terminal, exact port, `lsof -nP -iTCP:8789 -sTCP:LISTEN` and port `8790` | Start the demo or choose unused ports. Never bind MCP off loopback. |
| Health returns `421` | Request `Host` and configured numeric loopback/port | Use the exact loopback URL. Do not relax Host validation. |
| MCP returns `401` | Selected profile, profile `.env`, fake token scope, `Authorization` interpolation | Recreate the disposable profile. Never print or log a live token. |
| Hermes says `mcp.client.streamable_http` is unavailable | Locked runtime smoke, lock freshness, `uv` cache integrity | Stop. Re-run the documented lock check and locked smoke; repair the `uv` cache if diagnosed. Never substitute a global Hermes or independently upgrade the SDK. |
| MCP route returns `404` | Exact `/mcp/<alias>` path and absence of a trailing slash | Correct the profile URL. Do not add proxy rewrites. |
| Profile helper refuses files | Exact `signet-demo` path, blank `.env`, empty `mcp_servers`, modes and symlinks | Stop and inspect. Do not weaken or bypass a helper check. |
| Hermes reports no tools | `signet_demo_hermes -p signet-demo mcp test NAME`, demo server, fake policy/schema state | Keep tools disabled, repair fake state, reload MCP, and start a new session. |
| `approve_request` is absent | Approvals tool list | Expected in demo mode. Use the authenticated fake web form; never invent a numeric code. |
| Request stays `pending_approval` | Expanded web review and event timeline | It is not provider success. Deny/cancel it or complete the documented fake web action. |
| Fake action proof reports replay/stale | Current expanded revision and a freshly retrieved demo proof | Re-review the exact revision. Never retry an old production proof. |
| Request enters `outcome_unknown` | Event timeline and reconciliation status | Do not blind-retry. Preserve state and run only bounded fake reconciliation. |
| Web login loops | Exact loopback URL and the three current fake login fields | Rerun offline smoke. Do not disable CSRF, Origin, or production cookie checks. |
| Restored instance returns `401` to old profile | Restored credential rotation | Expected. Do not copy the old token into restored state. |
| SQLite startup rejection | SQLite version, filesystem type, ownership/mode, migration checksum | Stop. Upgrade the runtime or move fake state to a supported local filesystem. |
| `413` from MCP/web | Request size and configured bounded limits | Reduce fixture size. Do not raise production limits for a demo. |
| Repeated process restart | First bounded startup error and state permissions | Stop the supervisor. Repair the cause before retrying. |

Never attach raw request bodies, tokens, password/proof values, push endpoints,
provider results, Keychain references, or private filenames to a troubleshooting
report. Use fixed error codes, state classes, bounded counts, and redacted diffs.
