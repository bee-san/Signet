# Hermes Agent integration

These files have not been applied to a Hermes profile. The current Hermes Agent
configuration model uses `mcp_servers` entries in each profile's `config.yaml` and
resolves `${VAR}` placeholders from that profile's `.env`. Every bounded command
below checks the locked version and MCP surface; Hermes is external software and its
interface may change.

The checked-in runtime requests `hermes-agent[mcp]==0.18.2`; its file preflight is
also regression tested against the v0.16.0 profile layout. A bare Hermes package
does not include the MCP SDK, which is why these procedures never use a global
command. Do not install an arbitrary standalone `mcp` version around the locked
dependency contract. Revalidate this guide before using another release.

The bounded procedures below use the checked-in `runtime/uv.lock`, which pins the
complete Python 3.12 dependency graph and artifact hashes. They run it through
`uv run --locked --isolated` with source builds disabled and a scrubbed environment;
they do not depend on a globally installed `hermes` command. Hermes 0.18.2 exactly
pins three dependency versions with published advisories, so the runtime explicitly
overrides them to audited patched releases. The override set is exercised by real
profile/MCP tests; CI checks the lock, smokes it on Linux and macOS, and audits the
fully hashed export. Do not change it without repeating those checks. The upstream
[installation guide](https://github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/website/docs/getting-started/installation.md)
covers platform prerequisites. A global/source installation is outside this
procedure's security boundary and must not replace the locked runtime.

From the reviewed Signet checkout, verify that the checked-in runtime lock is
current before any profile command:

```console
uv lock --check --project deploy/hermes/runtime
```

## Disposable no-live demo

`demo-profile.mcp.yaml.example` is the reviewed default-port shape for a newly
created `signet-demo` profile only. `signet demo hermes-config` emits the same shape
for the selected demo MCP port. Both use distinct server names, exact loopback URLs,
and the `SIGNET_DEMO_MCP_CALLER_TOKEN` placeholder. Do not merge either into an
existing profile or replace the placeholder with a live token.

The example explicitly sets:

- `supports_parallel_tool_calls: false`, so Hermes does not batch consequential
  calls to one Signet surface;
- `tools.resources: false` and `tools.prompts: false`, because these Signet paths
  expose reviewed tools, not general MCP resource or prompt utilities;
- `sampling.enabled: false`, so the MCP server cannot ask Hermes for model output;
- bounded connection/tool timeouts; and
- one bearer placeholder shared only across the three paths for one profile.

Follow the full state/start sequence in
[`docs/operator-runbook.md`](../../docs/operator-runbook.md). Once the fake server
is running, create an isolated blank profile and locate its files:

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

Hermes startup can use `HERMES_HOME`, `HOME`, a root `.env`, and a machine managed
scope. This demo points none of those at the operator's existing Hermes state: it
creates or validates a dedicated private home and root under the physical home,
requires an empty root `.env`, an empty `profiles` directory, and only the pinned
CLI's validated private update/log metadata. It overrides inherited values and
points managed-scope discovery at a checked-absent path. If a command fails after
`profile create` succeeds, stop and do not rerun the block over the partial profile.
Run the self-contained checked deletion transaction in
[`docs/operator-runbook.md`, step 8](../../docs/operator-runbook.md#8-stop-and-roll-back-the-demo).
It re-derives the dedicated paths, validates the whole bounded inventory, verifies
both paths reported by Hermes, deletes only `signet-demo`, and verifies absence. If
any check refuses, do not invoke Hermes deletion; resolve the ownership, ancestry,
or inventory problem. Never recover with a recursive filesystem delete.

Hermes Agent v0.16.0 reports both paths without creating either file. Version
v0.18.2 still leaves `config.yaml` absent but creates a mode-`0600`, comment-only
`.env`. The branch above preserves that reviewed seed file; the configurator checks
its content, ownership, mode, link count, and identity before changing it. All demo
Hermes commands use the physical home directory, and both reported profile-file
parents are canonicalized before inspection or creation. Stop if the profile name
already existed or either check rejects its file.

Generate a mode-`0600` private fragment, then use
`configure-demo-profile.py`. The helper performs a structured merge only when the
profile has no MCP servers or environment assignments, validates every security
field, and reads one explicit fake token from stdin so it never appears in argv,
the process environment, config YAML, or output:

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

The configurator prepares and syncs both same-directory temporary files before it
publishes either one. It then replaces and syncs `.env` before it replaces and
syncs `config.yaml`; the two files cannot be published as one filesystem operation.
A fixed error therefore distinguishes no publication, an environment that may
already contain the token while the config was not published, and both requested
files potentially published with durability unknown. A cleanup-unknown error also
means a private temporary may remain. In every failure case, do not start Hermes or
rerun the pipeline. Use the checked profile recovery transaction instead of printing
or hand-editing `.env`.

Validate the disposable profile without starting a Hermes gateway:

```console
(
  set -e
  SIGNET_REPO="$(pwd -P)"
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

The deliberately minimal profile can produce a successful `config check` with a
`Config version: 0 -> N (update available)` advisory; `N` is release-specific. Do
not run `config migrate` for this demo: it expands the blank file into broad release
defaults. Keep the disposable profile's environment free of live provider keys and
other credentials because omitted settings inherit Hermes defaults.

The three connection tests also preflight streamable-HTTP support and must report
`4`, `3`, and `4` discovered tools respectively. If Hermes reports that
`mcp.client.streamable_http` is unavailable, stop and re-run the documented lock
check and locked-runtime smoke. Diagnose the checked-in runtime and `uv` cache; never
substitute a global Hermes installation or independently upgrade the SDK.

The demo approvals server intentionally omits `approve_request`, because automated
fixtures must not fabricate a six-digit TOTP code. Fake approve/deny actions are
available only in the authenticated loopback web demo with an unmistakable
`fake:` action proof. Connection tests do not require a Hermes model credential.

## Persistent downstream-disabled profile

`disabled-profile.mcp.yaml.example` is the only Hermes route that the shipped
persistent disabled assembly can serve. It contains `signet_disabled_approvals`
only. Do not add `fastmail`, `whatsapp`, or another downstream URL: those paths are
absent, not merely hidden. The disabled approval server lists the five normative
gateway schemas, but every call returns `deployment_disabled` and creates no local
request or external action.

Use one new dedicated profile with the default disabled MCP port `8789`. Set
`SIGNET_DISABLED_PROFILE=signet-disabled` before the `deployment init` sequence in
`docs/deployment.md`; that binds the one supported caller namespace to
`profile:signet-disabled`. Do not reuse or clone an existing Hermes profile. From
the repository root, prepare the profile and a private copy of the reviewed fragment:

```console
umask 077 || exit 1
SIGNET_REPO="$(pwd -P)" || exit 1
export SIGNET_REPO
export SIGNET_DISABLED_PROFILE=signet-disabled
SIGNET_HOME="$(cd "$HOME" && pwd -P)" || exit 1
export SIGNET_HOME
export SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
export SIGNET_DISABLED_CONFIG="$SIGNET_SERVICE_ROOT/config/disabled.json"
SIGNET_DISABLED_HERMES_HOME="$SIGNET_SERVICE_ROOT/hermes-home"
SIGNET_DISABLED_HERMES_ROOT="$SIGNET_DISABLED_HERMES_HOME/.hermes"
SIGNET_DISABLED_HERMES_MANAGED_DIR="$SIGNET_DISABLED_HERMES_HOME/.no-managed-scope"
SIGNET_HERMES_PROFILES_ROOT="$SIGNET_DISABLED_HERMES_ROOT/profiles"
"$SIGNET_REPO/.venv/bin/python" \
  "$SIGNET_REPO/deploy/prepare-owned-directory.py" \
  --directory "$SIGNET_HERMES_PROFILES_ROOT" || exit 1
if test -L "$SIGNET_DISABLED_HERMES_ROOT/.env"; then
  printf 'refusing linked disabled Hermes root environment\n' >&2
  exit 1
fi
if ! test -e "$SIGNET_DISABLED_HERMES_ROOT/.env"; then
  (set -o noclobber && : > "$SIGNET_DISABLED_HERMES_ROOT/.env") || exit 1
fi
"$SIGNET_REPO/.venv/bin/python" \
  "$SIGNET_REPO/deploy/validate-private-paths.py" \
  --directory "$SIGNET_DISABLED_HERMES_ROOT" \
  --private-file "$SIGNET_DISABLED_HERMES_ROOT/.env" || exit 1
if test -s "$SIGNET_DISABLED_HERMES_ROOT/.env"; then
  printf 'refusing nonempty disabled Hermes root environment\n' >&2
  exit 1
fi
if test -e "$SIGNET_DISABLED_HERMES_ROOT/.update_check" || \
   test -L "$SIGNET_DISABLED_HERMES_ROOT/.update_check"; then
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_DISABLED_HERMES_ROOT" \
    --private-file "$SIGNET_DISABLED_HERMES_ROOT/.update_check" || exit 1
fi
if test -e "$SIGNET_DISABLED_HERMES_ROOT/logs" || \
   test -L "$SIGNET_DISABLED_HERMES_ROOT/logs"; then
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_DISABLED_HERMES_ROOT/logs" || exit 1
  SIGNET_UNEXPECTED_DISABLED_HERMES_LOG="$(
    find "$SIGNET_DISABLED_HERMES_ROOT/logs" -mindepth 1 -maxdepth 1 \
      ! -name agent.log ! -name errors.log -print -quit
  )" || exit 1
  if test -n "$SIGNET_UNEXPECTED_DISABLED_HERMES_LOG"; then
    printf 'refusing unexpected disabled Hermes log entry: %s\n' \
      "$SIGNET_UNEXPECTED_DISABLED_HERMES_LOG" >&2
    exit 1
  fi
  for name in agent.log errors.log; do
    SIGNET_HERMES_CANDIDATE="$SIGNET_DISABLED_HERMES_ROOT/logs/$name"
    if test -e "$SIGNET_HERMES_CANDIDATE" || test -L "$SIGNET_HERMES_CANDIDATE"; then
      "$SIGNET_REPO/.venv/bin/python" \
        "$SIGNET_REPO/deploy/validate-private-paths.py" \
        --directory "$SIGNET_DISABLED_HERMES_ROOT/logs" \
        --private-file "$SIGNET_HERMES_CANDIDATE" || exit 1
    fi
  done
  unset SIGNET_UNEXPECTED_DISABLED_HERMES_LOG
fi
SIGNET_UNEXPECTED_DISABLED_HERMES_ROOT_ENTRY="$(
  find "$SIGNET_DISABLED_HERMES_ROOT" -mindepth 1 -maxdepth 1 \
    ! -name .env ! -name profiles ! -name .update_check ! -name logs -print -quit
)" || exit 1
if test -n "$SIGNET_UNEXPECTED_DISABLED_HERMES_ROOT_ENTRY"; then
  printf 'refusing unexpected disabled Hermes root entry: %s\n' \
    "$SIGNET_UNEXPECTED_DISABLED_HERMES_ROOT_ENTRY" >&2
  exit 1
fi
SIGNET_UNEXPECTED_DISABLED_HERMES_PROFILE="$(
  find "$SIGNET_HERMES_PROFILES_ROOT" -mindepth 1 -maxdepth 1 -print -quit
)" || exit 1
if test -n "$SIGNET_UNEXPECTED_DISABLED_HERMES_PROFILE"; then
  printf 'refusing nonempty disabled Hermes profiles root: %s\n' \
    "$SIGNET_UNEXPECTED_DISABLED_HERMES_PROFILE" >&2
  exit 1
fi
unset SIGNET_UNEXPECTED_DISABLED_HERMES_ROOT_ENTRY
unset SIGNET_UNEXPECTED_DISABLED_HERMES_PROFILE
if test -e "$SIGNET_DISABLED_HERMES_MANAGED_DIR" || \
   test -L "$SIGNET_DISABLED_HERMES_MANAGED_DIR"; then
  printf 'refusing existing disabled Hermes managed-scope path: %s\n' \
    "$SIGNET_DISABLED_HERMES_MANAGED_DIR" >&2
  exit 1
fi
signet_disabled_hermes() {
  env -i PATH="$PATH" HOME="$SIGNET_DISABLED_HERMES_HOME" \
    HERMES_HOME="$SIGNET_DISABLED_HERMES_ROOT" \
    HERMES_MANAGED_DIR="$SIGNET_DISABLED_HERMES_MANAGED_DIR" \
    uv run --locked --isolated --no-config \
      --exclude-newer 2026-07-09T00:00:00Z --no-env-file --no-sources --no-build \
      --project "$SIGNET_REPO/deploy/hermes/runtime" hermes "$@"
}
SIGNET_EXPECTED_DISABLED_HERMES_PROFILE="${SIGNET_HERMES_PROFILES_ROOT}/${SIGNET_DISABLED_PROFILE}"
if test -e "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE" || \
   test -L "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE"; then
  printf 'refusing existing Hermes profile path: %s\n' \
    "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE" >&2
  exit 1
fi
signet_disabled_hermes --version || exit 1
signet_disabled_hermes mcp --help || exit 1
signet_disabled_hermes profile list || exit 1
if ! signet_disabled_hermes profile create \
  "$SIGNET_DISABLED_PROFILE" --no-alias --no-skills; then
  printf 'refusing existing or failed Hermes profile: %s\n' \
    "$SIGNET_DISABLED_PROFILE" >&2
  exit 1
fi
SIGNET_DISABLED_HERMES_CONFIG="$(
  signet_disabled_hermes -p "$SIGNET_DISABLED_PROFILE" config path
)" || exit 1
case "$SIGNET_DISABLED_HERMES_CONFIG" in
  /*) ;;
  *)
    printf 'refusing non-absolute Hermes config path\n' >&2
    exit 1
    ;;
esac
case "$SIGNET_DISABLED_HERMES_CONFIG" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing Hermes config path outside physical HOME\n' >&2
    exit 1
    ;;
esac
SIGNET_DISABLED_HERMES_CONFIG_PARENT="$(
  cd "$(dirname "$SIGNET_DISABLED_HERMES_CONFIG")" && pwd -P
)" || exit 1
SIGNET_DISABLED_HERMES_CONFIG="$SIGNET_DISABLED_HERMES_CONFIG_PARENT/$(
  basename "$SIGNET_DISABLED_HERMES_CONFIG"
)" || exit 1
export SIGNET_DISABLED_HERMES_CONFIG
unset SIGNET_DISABLED_HERMES_CONFIG_PARENT
SIGNET_DISABLED_HERMES_ENV="$(
  signet_disabled_hermes -p "$SIGNET_DISABLED_PROFILE" config env-path
)" || exit 1
case "$SIGNET_DISABLED_HERMES_ENV" in
  /*) ;;
  *)
    printf 'refusing non-absolute Hermes environment path\n' >&2
    exit 1
    ;;
esac
case "$SIGNET_DISABLED_HERMES_ENV" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing Hermes environment path outside physical HOME\n' >&2
    exit 1
    ;;
esac
SIGNET_DISABLED_HERMES_ENV_PARENT="$(
  cd "$(dirname "$SIGNET_DISABLED_HERMES_ENV")" && pwd -P
)" || exit 1
SIGNET_DISABLED_HERMES_ENV="$SIGNET_DISABLED_HERMES_ENV_PARENT/$(
  basename "$SIGNET_DISABLED_HERMES_ENV"
)" || exit 1
export SIGNET_DISABLED_HERMES_ENV
unset SIGNET_DISABLED_HERMES_ENV_PARENT
SIGNET_DISABLED_HERMES_PARENT="${SIGNET_DISABLED_HERMES_CONFIG%/*}"
if test "${SIGNET_DISABLED_HERMES_CONFIG##*/}" != config.yaml || \
   test "${SIGNET_DISABLED_HERMES_ENV##*/}" != .env || \
   test "${SIGNET_DISABLED_HERMES_ENV%/*}" != "$SIGNET_DISABLED_HERMES_PARENT" || \
   test "$SIGNET_DISABLED_HERMES_PARENT" != \
     "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE"; then
  printf 'refusing unexpected Hermes profile file paths\n' >&2
  exit 1
fi
case "$SIGNET_DISABLED_HERMES_CONFIG" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing canonical Hermes config path outside physical HOME\n' >&2
    exit 1
    ;;
esac
case "$SIGNET_DISABLED_HERMES_ENV" in
  "$SIGNET_HOME"/*) ;;
  *)
    printf 'refusing canonical Hermes environment path outside physical HOME\n' >&2
    exit 1
    ;;
esac
if ! test -d "$SIGNET_DISABLED_HERMES_PARENT" || \
   test -L "$SIGNET_DISABLED_HERMES_PARENT" || \
   ! test -O "$SIGNET_DISABLED_HERMES_PARENT"; then
  printf 'refusing unowned or linked Hermes profile directory\n' >&2
  exit 1
fi
SIGNET_UNSAFE_HERMES_PARENT="$(
  find "$SIGNET_DISABLED_HERMES_PARENT" -prune \
    \( -perm -020 -o -perm -002 \) -print
)" || exit 1
if test -n "$SIGNET_UNSAFE_HERMES_PARENT"; then
  printf 'refusing group/world-writable Hermes profile directory\n' >&2
  exit 1
fi
unset SIGNET_UNSAFE_HERMES_PARENT
"$SIGNET_REPO/.venv/bin/python" \
  "$SIGNET_REPO/deploy/validate-private-paths.py" \
  --directory "$SIGNET_DISABLED_HERMES_PARENT" || exit 1
if test -e "$SIGNET_DISABLED_HERMES_CONFIG" || \
   test -L "$SIGNET_DISABLED_HERMES_CONFIG"; then
  printf 'refusing existing Hermes config: %s\n' \
    "$SIGNET_DISABLED_HERMES_CONFIG" >&2
  exit 1
fi
(umask 077 && set -o noclobber && : > "$SIGNET_DISABLED_HERMES_CONFIG") || exit 1
if test -L "$SIGNET_DISABLED_HERMES_ENV"; then
  printf 'refusing linked Hermes environment: %s\n' \
    "$SIGNET_DISABLED_HERMES_ENV" >&2
  exit 1
fi
if ! test -e "$SIGNET_DISABLED_HERMES_ENV"; then
  (umask 077 && set -o noclobber && : > "$SIGNET_DISABLED_HERMES_ENV") || exit 1
fi
unset SIGNET_DISABLED_HERMES_PARENT
export SIGNET_DISABLED_HERMES_FRAGMENT="$SIGNET_SERVICE_ROOT/config/disabled-profile.mcp.yaml"
if test -L "$SIGNET_DISABLED_HERMES_FRAGMENT"; then
  printf 'refusing linked private fragment: %s\n' \
    "$SIGNET_DISABLED_HERMES_FRAGMENT" >&2
  exit 1
fi
if ! test -e "$SIGNET_DISABLED_HERMES_FRAGMENT"; then
  install -m 0600 "$SIGNET_REPO/deploy/hermes/disabled-profile.mcp.yaml.example" \
    "$SIGNET_DISABLED_HERMES_FRAGMENT" || exit 1
fi
```

This downstream-disabled profile also uses a dedicated Hermes home and root inside
Signet's private service tree. Explicit `HOME`, `HERMES_HOME`, and
`HERMES_MANAGED_DIR` assignments keep it separate from the operator's default or
custom Hermes profiles and from a machine managed scope. The validated empty root
`.env`, empty profiles inventory, and bounded private update/log residue make
recovery and deliberate reuse deterministic.

If preparation fails after the dedicated profile is created, do not rerun that block
over its partial files. Use this self-contained recovery transaction. It accepts the
bounded private profile state created by either reviewed Hermes release, but refuses
every unrelated root or profile, unsafe tree, ownership, mode, ACL, or reported-path
condition before it invokes deletion:

```console
(
  set -e
  umask 077
  SIGNET_REPO="$(pwd -P)"
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
  SIGNET_DISABLED_HERMES_HOME="$SIGNET_SERVICE_ROOT/hermes-home"
  SIGNET_DISABLED_HERMES_ROOT="$SIGNET_DISABLED_HERMES_HOME/.hermes"
  SIGNET_DISABLED_HERMES_MANAGED_DIR="$SIGNET_DISABLED_HERMES_HOME/.no-managed-scope"
  SIGNET_HERMES_PROFILES_ROOT="$SIGNET_DISABLED_HERMES_ROOT/profiles"
  SIGNET_DISABLED_PROFILE=signet-disabled
  SIGNET_EXPECTED_DISABLED_HERMES_PROFILE="${SIGNET_HERMES_PROFILES_ROOT}/${SIGNET_DISABLED_PROFILE}"
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_DISABLED_HERMES_ROOT" \
    --private-file "$SIGNET_DISABLED_HERMES_ROOT/.env"
  if test -s "$SIGNET_DISABLED_HERMES_ROOT/.env"; then
    printf 'refusing nonempty disabled Hermes root environment\n' >&2
    exit 1
  fi
  if test -e "$SIGNET_DISABLED_HERMES_MANAGED_DIR" || \
     test -L "$SIGNET_DISABLED_HERMES_MANAGED_DIR"; then
    printf 'refusing existing disabled Hermes managed-scope path: %s\n' \
      "$SIGNET_DISABLED_HERMES_MANAGED_DIR" >&2
    exit 1
  fi
  if test -e "$SIGNET_DISABLED_HERMES_ROOT/.update_check" || \
     test -L "$SIGNET_DISABLED_HERMES_ROOT/.update_check"; then
    "$SIGNET_REPO/.venv/bin/python" \
      "$SIGNET_REPO/deploy/validate-private-paths.py" \
      --directory "$SIGNET_DISABLED_HERMES_ROOT" \
      --private-file "$SIGNET_DISABLED_HERMES_ROOT/.update_check"
  fi
  if test -e "$SIGNET_DISABLED_HERMES_ROOT/logs" || \
     test -L "$SIGNET_DISABLED_HERMES_ROOT/logs"; then
    "$SIGNET_REPO/.venv/bin/python" \
      "$SIGNET_REPO/deploy/validate-private-paths.py" \
      --directory "$SIGNET_DISABLED_HERMES_ROOT/logs"
    SIGNET_UNEXPECTED_DISABLED_HERMES_LOG="$(
      find "$SIGNET_DISABLED_HERMES_ROOT/logs" -mindepth 1 -maxdepth 1 \
        ! -name agent.log ! -name errors.log -print -quit
    )"
    if test -n "$SIGNET_UNEXPECTED_DISABLED_HERMES_LOG"; then
      printf 'refusing unexpected disabled Hermes log entry: %s\n' \
        "$SIGNET_UNEXPECTED_DISABLED_HERMES_LOG" >&2
      exit 1
    fi
    for name in agent.log errors.log; do
      SIGNET_HERMES_CANDIDATE="$SIGNET_DISABLED_HERMES_ROOT/logs/$name"
      if test -e "$SIGNET_HERMES_CANDIDATE" || \
         test -L "$SIGNET_HERMES_CANDIDATE"; then
        "$SIGNET_REPO/.venv/bin/python" \
          "$SIGNET_REPO/deploy/validate-private-paths.py" \
          --directory "$SIGNET_DISABLED_HERMES_ROOT/logs" \
          --private-file "$SIGNET_HERMES_CANDIDATE"
      fi
    done
  fi
  SIGNET_UNEXPECTED_DISABLED_HERMES_ROOT_ENTRY="$(
    find "$SIGNET_DISABLED_HERMES_ROOT" -mindepth 1 -maxdepth 1 \
      ! -name .env ! -name profiles ! -name .update_check ! -name logs -print -quit
  )"
  if test -n "$SIGNET_UNEXPECTED_DISABLED_HERMES_ROOT_ENTRY"; then
    printf 'refusing unexpected disabled Hermes root entry: %s\n' \
      "$SIGNET_UNEXPECTED_DISABLED_HERMES_ROOT_ENTRY" >&2
    exit 1
  fi
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_HERMES_PROFILES_ROOT"
  SIGNET_UNEXPECTED_DISABLED_HERMES_PROFILE="$(
    find "$SIGNET_HERMES_PROFILES_ROOT" -mindepth 1 -maxdepth 1 \
      ! -name "$SIGNET_DISABLED_PROFILE" -print -quit
  )"
  if test -n "$SIGNET_UNEXPECTED_DISABLED_HERMES_PROFILE"; then
    printf 'refusing unrelated disabled Hermes profile: %s\n' \
      "$SIGNET_UNEXPECTED_DISABLED_HERMES_PROFILE" >&2
    exit 1
  fi
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE" \
    --private-tree
  signet_disabled_hermes() {
    env -i PATH="$PATH" HOME="$SIGNET_DISABLED_HERMES_HOME" \
      HERMES_HOME="$SIGNET_DISABLED_HERMES_ROOT" \
      HERMES_MANAGED_DIR="$SIGNET_DISABLED_HERMES_MANAGED_DIR" \
      uv run --locked --isolated --no-config \
        --exclude-newer 2026-07-09T00:00:00Z --no-env-file --no-sources --no-build \
        --project "$SIGNET_REPO/deploy/hermes/runtime" hermes "$@"
  }
  SIGNET_RECOVERY_DISABLED_HERMES_CONFIG="$(
    signet_disabled_hermes -p "$SIGNET_DISABLED_PROFILE" config path
  )"
  SIGNET_RECOVERY_DISABLED_HERMES_ENV="$(
    signet_disabled_hermes -p "$SIGNET_DISABLED_PROFILE" config env-path
  )"
  if test "$SIGNET_RECOVERY_DISABLED_HERMES_CONFIG" != \
       "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE/config.yaml" || \
     test "$SIGNET_RECOVERY_DISABLED_HERMES_ENV" != \
       "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE/.env"; then
    printf 'refusing recovery of unexpected disabled Hermes profile paths\n' >&2
    exit 1
  fi
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE" \
    --private-tree
  signet_disabled_hermes profile delete "$SIGNET_DISABLED_PROFILE" -y
  if test -e "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE" || \
     test -L "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE"; then
    printf 'disabled Hermes profile remains after reported deletion: %s\n' \
      "$SIGNET_EXPECTED_DISABLED_HERMES_PROFILE" >&2
    exit 1
  fi
  signet_disabled_hermes profile list
)
```

If any check refuses, do not invoke Hermes deletion; resolve the ownership, ancestry,
or inventory problem. Successful deletion does not revoke a caller token that may
already have been issued: inspect `token list`, revoke the partial profile's token if
present, and only then restart preparation from the beginning. Do not recursively
remove Hermes directories.

Version 0.16.0 creates neither profile file. Version 0.18.2 seeds the comment-only
`.env` and a private no-skills profile skeleton; config and MCP commands can add
private cache and log state. The recursive recovery preflight permits names only
inside this exact isolated profile while limiting the tree to 16 levels, 1,024
entries, and 64 MiB. It requires owned mode-`0700` same-filesystem directories and
owned, single-link mode-`0600` regular files, and refuses links, special files,
granting ACLs, cross-filesystem traversal, or identity changes before and after the
CLI path checks. The configurator independently requires canonical absolute paths,
one owned non-writable profile directory, safe single-link mode-`0600` files, a blank
config, and an empty/comment-only environment. It rejects any pre-existing MCP route
or environment assignment, so the profile cannot silently retain a direct mutation
bypass.

The preflight prevents accidental or other-user substitution beneath the owned
mode-`0700` root; it cannot make Hermes' path-based deletion descriptor-transactional.
A privileged mount change, including a same-filesystem bind mount, or a malicious
process running as the same UID could mutate the tree after the last validation.
Those actors can already alter this account's private profile state and are outside
this recovery boundary. Do not run recovery concurrently with another process under
that UID. If deletion or either post-deletion check reports an anomaly, stop, resolve
the mutation, and retry the complete checked transaction from the beginning.

Confirm there is no unexpected active token for this new namespace. Then use one
pipeline with `pipefail`; the token never enters argv, the process environment,
YAML, terminal output, or the helper's fixed success message:

```console
uv run signet deployment token list --config "$SIGNET_DISABLED_CONFIG" || exit 1
(umask 077 && set -e && set -o pipefail && \
  uv run signet deployment token issue \
    --config "$SIGNET_DISABLED_CONFIG" \
    --namespace "profile:$SIGNET_DISABLED_PROFILE" | \
  uv run python "$SIGNET_REPO/deploy/hermes/configure-disabled-profile.py" \
    --profile "$SIGNET_DISABLED_PROFILE" \
    --config "$SIGNET_DISABLED_HERMES_CONFIG" \
    --env-file "$SIGNET_DISABLED_HERMES_ENV" \
    --fragment "$SIGNET_DISABLED_HERMES_FRAGMENT") || exit 1
```

The helper accepts only the exact current `sgt_` token on stdin and the exact
`signet_disabled_approvals` loopback fragment. It uses a private profile lock,
compare-before-replace snapshots, same-directory exclusive temporaries, fsync, and
identity-checked atomic replacement of each individual file. It publishes and
syncs the environment first, then publishes and syncs the config; those two
replacements are not one atomic filesystem operation. The raw token is stored only as
`SIGNET_DISABLED_MCP_CALLER_TOKEN` in the dedicated mode-`0600` `.env`; YAML retains
only its placeholder. On any pipeline failure, do not issue again or start Hermes.
The fixed failure text says whether no file was published, `.env` may already
contain the token while the config was not published, both requested files may be
present with durability unknown, or temporary/descriptor cleanup could not be
confirmed. Do not print or hand-edit either file to investigate.
Use `token list` to identify and revoke any new record, then run the complete checked
recovery transaction above. Only that transaction may invoke profile deletion. If it
refuses, do not invoke deletion. The already-validated private fragment may be
reused. See the precise recovery boundary in `docs/deployment.md` before retrying.

In terminal A, start the disabled MCP process:

```console
uv run signet deployment serve-mcp --config "$SIGNET_DISABLED_CONFIG"
```

In terminal B, validate the profile without a model call:

```console
(
  set -e
  SIGNET_REPO="$(pwd -P)"
  SIGNET_HOME="$(cd "$HOME" && pwd -P)"
  export SIGNET_HOME
  SIGNET_SERVICE_ROOT="$SIGNET_HOME/.hermes/services/signet"
  SIGNET_DISABLED_HERMES_HOME="$SIGNET_SERVICE_ROOT/hermes-home"
  SIGNET_DISABLED_HERMES_ROOT="$SIGNET_DISABLED_HERMES_HOME/.hermes"
  SIGNET_DISABLED_HERMES_MANAGED_DIR="$SIGNET_DISABLED_HERMES_HOME/.no-managed-scope"
  export SIGNET_DISABLED_PROFILE=signet-disabled
  signet_disabled_hermes() {
    env -i PATH="$PATH" HOME="$SIGNET_DISABLED_HERMES_HOME" \
      HERMES_HOME="$SIGNET_DISABLED_HERMES_ROOT" \
      HERMES_MANAGED_DIR="$SIGNET_DISABLED_HERMES_MANAGED_DIR" \
      uv run --locked --isolated --no-config \
        --exclude-newer 2026-07-09T00:00:00Z --no-env-file --no-sources --no-build \
        --project "$SIGNET_REPO/deploy/hermes/runtime" hermes "$@"
  }
  signet_disabled_hermes -p "$SIGNET_DISABLED_PROFILE" config check
  signet_disabled_hermes -p "$SIGNET_DISABLED_PROFILE" \
    mcp test signet_disabled_approvals
  signet_disabled_hermes -p "$SIGNET_DISABLED_PROFILE" mcp list
)
```

The connection test must discover exactly five tools. It proves only loopback MCP
transport and bearer authentication. It does not prove human authentication,
queue behavior, provider readiness, or live cutover. There is no reason to call an
approval tool during this check; if one is called, a `deployment_disabled` error is
the only acceptable result. Use Hermes' reviewed `/reload-mcp` workflow to activate
the profile change. `token revoke --token-id=TOKEN_ID` takes effect at the next
Signet authentication check. The bootstrap helper intentionally refuses to replace
an installed assignment. `token rotate --token-id=TOKEN_ID` stages a replacement
without revoking the old token; use a separately reviewed new secret destination,
reload and test Hermes, and only then explicitly revoke the old token. Never use
shell redirection over the active `.env`. If replacement output or ingestion fails,
revoke the linked replacement record and retry while the old route remains usable.

## Deferred live route change

The forward and reverse diff files show direction without reading or naming any
live profile. They are not patches and are not guaranteed to match a deployment's
current file. Regenerate both from a private, timestamped copy of the selected
profile during an authorized change.

The forward shape preserves the existing `fastmail` and `whatsapp` server names so
Hermes' `mcp_<server>_<tool>` names remain stable, then adds `signet_approvals`.
All three URLs stay on `127.0.0.1`; the MCP listener must never be proxied to a LAN
or tailnet.

Every path requires bearer authentication. `${SIGNET_MCP_CALLER_TOKEN}` refers to
one raw token issued for one Hermes profile whose durable Signet record permits
exactly `fastmail`, `whatsapp`, and `approvals`. Store the raw value in that
profile's mode-`0600` `.env`, not `config.yaml`, a diff, shell history, logs, or a
prompt. Each Hermes profile receives a different token and caller namespace.

Before applying a generated forward diff, require a clean metadata-only bypass
audit, matching reviewed schema digests, fake-provider acceptance, enrolled human
authentication, enrolled downstream credentials, a verified restore drill, and
explicit human authorization. Back up the selected profile's `config.yaml` and
`.env` privately and apply a structured YAML merge. Do not fall back to a global
`hermes` executable for this live-profile exception. From the reviewed checkout,
bind the locked runtime to the operator's explicitly reviewed default Hermes root,
exclude machine-managed scope, verify both reported profile paths, and then test:

```console
(
  set -e
  set -o pipefail
  umask 077
  SIGNET_REPO="$(pwd -P)"
  SIGNET_LIVE_HERMES_OS_HOME="$(cd "$HOME" && pwd -P)"
  SIGNET_LIVE_HERMES_ROOT="$SIGNET_LIVE_HERMES_OS_HOME/.hermes"
  SIGNET_LIVE_HERMES_MANAGED_DIR="$SIGNET_LIVE_HERMES_OS_HOME/.no-signet-managed-scope"
  SIGNET_LIVE_PROFILE=PROFILE
  if test "$SIGNET_LIVE_PROFILE" = PROFILE || \
     test -e "$SIGNET_LIVE_HERMES_MANAGED_DIR" || \
     test -L "$SIGNET_LIVE_HERMES_MANAGED_DIR"; then
    printf 'replace PROFILE and keep the reviewed managed-scope path absent\n' >&2
    exit 1
  fi
  SIGNET_LIVE_PROFILE_ROOT="$SIGNET_LIVE_HERMES_ROOT/profiles/$SIGNET_LIVE_PROFILE"
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_LIVE_HERMES_ROOT"
  "$SIGNET_REPO/.venv/bin/python" \
    "$SIGNET_REPO/deploy/validate-private-paths.py" \
    --directory "$SIGNET_LIVE_PROFILE_ROOT" \
    --private-file "$SIGNET_LIVE_PROFILE_ROOT/config.yaml" \
    --private-file "$SIGNET_LIVE_PROFILE_ROOT/.env"
  signet_reviewed_live_hermes() {
    env -i PATH="$PATH" HOME="$SIGNET_LIVE_HERMES_OS_HOME" \
      HERMES_HOME="$SIGNET_LIVE_HERMES_ROOT" \
      HERMES_MANAGED_DIR="$SIGNET_LIVE_HERMES_MANAGED_DIR" \
      uv run --locked --isolated --no-config \
        --exclude-newer 2026-07-09T00:00:00Z --no-env-file --no-sources --no-build \
        --project "$SIGNET_REPO/deploy/hermes/runtime" hermes "$@"
  }
  signet_reviewed_live_hermes --version | \
    grep -Fx 'Hermes Agent v0.18.2 (2026.7.7.2)' >/dev/null
  test "$(signet_reviewed_live_hermes -p "$SIGNET_LIVE_PROFILE" config path)" = \
    "$SIGNET_LIVE_PROFILE_ROOT/config.yaml"
  test "$(signet_reviewed_live_hermes -p "$SIGNET_LIVE_PROFILE" config env-path)" = \
    "$SIGNET_LIVE_PROFILE_ROOT/.env"
  signet_reviewed_live_hermes -p "$SIGNET_LIVE_PROFILE" config check
  signet_reviewed_live_hermes -p "$SIGNET_LIVE_PROFILE" mcp test fastmail
  signet_reviewed_live_hermes -p "$SIGNET_LIVE_PROFILE" mcp test whatsapp
  signet_reviewed_live_hermes -p "$SIGNET_LIVE_PROFILE" mcp test signet_approvals
  signet_reviewed_live_hermes -p "$SIGNET_LIVE_PROFILE" mcp list
)
```

`PROFILE` is a visible placeholder, not a literal command value. Use `/reload-mcp`
inside an interactive Hermes session after the tests pass, then start a new
session. Do not treat `/reload-mcp` as a shell command and do not restart a Hermes
gateway unless a separate change authorizes that disruption. The wrapper
deliberately ignores an inherited custom `HERMES_HOME`, global executable, provider
environment, and machine managed scope. A deployment that intentionally uses a
custom root or managed scope needs its own reviewed equivalent invocation; do not
silently substitute it into this block.

## Rollback boundary

The reverse example exists for review completeness, not as the normal response to
a Signet defect. If the forward config was not activated, restore only the private
profile files and rerun `config check`. Once Signet has acknowledged a pending
request, do not restore an older Signet database or re-enable direct provider
writes: either can forget or duplicate an acknowledged effect. Preserve the
database, idempotency ledger, and disabled direct routes; stop dispatch and repair
forward unless the reverse-route preconditions in `docs/deployment.md` are
independently satisfied.

Reference: the current official
[Hermes MCP guide](https://github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/website/docs/user-guide/features/mcp.md)
and
[MCP config reference](https://github.com/NousResearch/hermes-agent/blob/v2026.7.7.2/website/docs/reference/mcp-config-reference.md).
