# Hermes Agent integration

These files have not been applied to a Hermes profile. The current Hermes Agent
configuration model uses `mcp_servers` entries in each profile's `config.yaml` and
resolves `${VAR}` placeholders from that profile's `.env`. Confirm the installed
version with `hermes --version` and `hermes mcp --help` before a reviewed change;
Hermes is external software and its interface may change.

Hermes' official standard source installer includes its `mcp` extra. A PyPI
installation must request that extra explicitly. The procedures below were
independently exercised with `hermes-agent[mcp]==0.18.2` and retain compatibility
with `hermes-agent[mcp]==0.16.0`. A bare PyPI install lacks the MCP SDK. Do not
install an arbitrary standalone `mcp` version around Hermes' pinned dependency
contract. Revalidate this guide before using another release.

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
if ! hermes profile create signet-demo --no-alias --no-skills; then
  printf 'refusing existing or failed Hermes profile: signet-demo\n' >&2
  exit 1
fi
export SIGNET_DEMO_HERMES_CONFIG="$(hermes -p signet-demo config path)"
export SIGNET_DEMO_HERMES_ENV="$(hermes -p signet-demo config env-path)"
if test -e "$SIGNET_DEMO_HERMES_CONFIG" || test -L "$SIGNET_DEMO_HERMES_CONFIG"; then
  printf 'refusing existing Hermes config: %s\n' "$SIGNET_DEMO_HERMES_CONFIG" >&2
  exit 1
fi
install -m 0600 /dev/null "$SIGNET_DEMO_HERMES_CONFIG"
if test -L "$SIGNET_DEMO_HERMES_ENV"; then
  printf 'refusing linked Hermes environment: %s\n' "$SIGNET_DEMO_HERMES_ENV" >&2
  exit 1
fi
if ! test -e "$SIGNET_DEMO_HERMES_ENV"; then
  install -m 0600 /dev/null "$SIGNET_DEMO_HERMES_ENV"
fi
```

Hermes Agent v0.16.0 reports both paths without creating either file. Version
v0.18.2 still leaves `config.yaml` absent but creates a mode-`0600`, comment-only
`.env`. The branch above preserves that reviewed seed file; the configurator checks
its content, ownership, mode, link count, and identity before changing it. Stop if
the profile name already existed or either check rejects its file.

Generate a mode-`0600` private fragment, then use
`configure-demo-profile.py`. The helper performs a structured merge only when the
profile has no MCP servers or environment assignments, validates every security
field, and reads one explicit fake token from stdin so it never appears in argv,
the process environment, config YAML, or output:

```console
export SIGNET_DEMO_DIR="$PWD/var/operator-demo"
export SIGNET_DEMO_HERMES_FRAGMENT="$SIGNET_DEMO_DIR/hermes-profile.yaml"
(umask 077 && set -o noclobber && \
  uv run signet demo hermes-config --data-dir "$SIGNET_DEMO_DIR" \
    --mcp-port 8789 > "$SIGNET_DEMO_HERMES_FRAGMENT")
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field mcp-token | \
  uv run python deploy/hermes/configure-demo-profile.py \
    --config "$SIGNET_DEMO_HERMES_CONFIG" \
    --env-file "$SIGNET_DEMO_HERMES_ENV" \
    --fragment "$SIGNET_DEMO_HERMES_FRAGMENT"
```

Validate the disposable profile without starting a Hermes gateway:

```console
hermes -p signet-demo config check
hermes -p signet-demo mcp test signet_demo_fastmail
hermes -p signet-demo mcp test signet_demo_whatsapp
hermes -p signet-demo mcp test signet_demo_approvals
hermes -p signet-demo mcp list
```

The deliberately minimal profile can produce a successful `config check` with a
`Config version: 0 -> N (update available)` advisory; `N` is release-specific. Do
not run `config migrate` for this demo: it expands the blank file into broad release
defaults. Keep the disposable profile's environment free of live provider keys and
other credentials because omitted settings inherit Hermes defaults.

The three connection tests also preflight streamable-HTTP support and must report
`4`, `3`, and `4` discovered tools respectively. If Hermes reports that
`mcp.client.streamable_http` is unavailable, reinstall the reviewed Hermes release
with its `[mcp]` extra or use the official standard installer; do not independently
upgrade the SDK.

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
export SIGNET_DISABLED_PROFILE=signet-disabled
export SIGNET_DISABLED_CONFIG="$HOME/.hermes/services/signet/config/disabled.json"
hermes --version
hermes mcp --help
hermes profile list
if ! hermes profile create "$SIGNET_DISABLED_PROFILE" --no-alias --no-skills; then
  printf 'refusing existing or failed Hermes profile: %s\n' \
    "$SIGNET_DISABLED_PROFILE" >&2
  exit 1
fi
export SIGNET_DISABLED_HERMES_CONFIG="$(
  hermes -p "$SIGNET_DISABLED_PROFILE" config path
)"
export SIGNET_DISABLED_HERMES_ENV="$(
  hermes -p "$SIGNET_DISABLED_PROFILE" config env-path
)"
if test -e "$SIGNET_DISABLED_HERMES_CONFIG" || \
   test -L "$SIGNET_DISABLED_HERMES_CONFIG"; then
  printf 'refusing existing Hermes config: %s\n' \
    "$SIGNET_DISABLED_HERMES_CONFIG" >&2
  exit 1
fi
install -m 0600 /dev/null "$SIGNET_DISABLED_HERMES_CONFIG"
if test -L "$SIGNET_DISABLED_HERMES_ENV"; then
  printf 'refusing linked Hermes environment: %s\n' \
    "$SIGNET_DISABLED_HERMES_ENV" >&2
  exit 1
fi
if ! test -e "$SIGNET_DISABLED_HERMES_ENV"; then
  install -m 0600 /dev/null "$SIGNET_DISABLED_HERMES_ENV"
fi
export SIGNET_DISABLED_HERMES_FRAGMENT="$HOME/.hermes/services/signet/config/disabled-profile.mcp.yaml"
if test -L "$SIGNET_DISABLED_HERMES_FRAGMENT"; then
  printf 'refusing linked private fragment: %s\n' \
    "$SIGNET_DISABLED_HERMES_FRAGMENT" >&2
  exit 1
fi
if ! test -e "$SIGNET_DISABLED_HERMES_FRAGMENT"; then
  install -m 0600 "$PWD/deploy/hermes/disabled-profile.mcp.yaml.example" \
    "$SIGNET_DISABLED_HERMES_FRAGMENT"
fi
```

Version 0.16.0 creates neither profile file; version 0.18.2 seeds only the
comment-only `.env`. The branches handle both. The configurator independently
requires canonical absolute paths, one owned non-writable profile directory, safe
single-link mode-`0600` files, a blank config, and an empty/comment-only environment.
It rejects any pre-existing MCP route or environment assignment, so the profile
cannot silently retain a direct mutation bypass.

Confirm there is no unexpected active token for this new namespace. Then use one
pipeline with `pipefail`; the token never enters argv, the process environment,
YAML, terminal output, or the helper's fixed success message:

```console
uv run signet deployment token list --config "$SIGNET_DISABLED_CONFIG"
(umask 077 && set -o pipefail && \
  uv run signet deployment token issue \
    --config "$SIGNET_DISABLED_CONFIG" \
    --namespace "profile:$SIGNET_DISABLED_PROFILE" | \
  uv run python deploy/hermes/configure-disabled-profile.py \
    --profile "$SIGNET_DISABLED_PROFILE" \
    --config "$SIGNET_DISABLED_HERMES_CONFIG" \
    --env-file "$SIGNET_DISABLED_HERMES_ENV" \
    --fragment "$SIGNET_DISABLED_HERMES_FRAGMENT")
```

The helper accepts only the exact current `sgt_` token on stdin and the exact
`signet_disabled_approvals` loopback fragment. It uses a private profile lock,
compare-before-replace snapshots, same-directory exclusive temporaries, fsync, and
atomic replacement. The raw token is stored only as
`SIGNET_DISABLED_MCP_CALLER_TOKEN` in the dedicated mode-`0600` `.env`; YAML retains
only its placeholder. On any pipeline failure, do not issue again or start Hermes.
Use `token list` to identify and revoke any new record, then run
`hermes profile delete "$SIGNET_DISABLED_PROFILE" -y` and recreate only that
dedicated profile. The already-validated private fragment may be reused. See the
precise recovery boundary in `docs/deployment.md` before retrying.

In terminal A, start the disabled MCP process:

```console
uv run signet deployment serve-mcp --config "$SIGNET_DISABLED_CONFIG"
```

In terminal B, validate the profile without a model call:

```console
hermes -p "$SIGNET_DISABLED_PROFILE" config check
hermes -p "$SIGNET_DISABLED_PROFILE" mcp test signet_disabled_approvals
hermes -p "$SIGNET_DISABLED_PROFILE" mcp list
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
`.env` privately, apply a structured YAML merge, then run:

```console
hermes -p PROFILE config check
hermes -p PROFILE mcp test fastmail
hermes -p PROFILE mcp test whatsapp
hermes -p PROFILE mcp test signet_approvals
hermes -p PROFILE mcp list
```

`PROFILE` is a visible placeholder, not a literal command value. Use `/reload-mcp`
inside an interactive Hermes session after the tests pass, then start a new
session. Do not treat `/reload-mcp` as a shell command and do not restart a Hermes
gateway unless a separate change authorizes that disruption.

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
[Hermes MCP guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md)
and
[MCP config reference](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/reference/mcp-config-reference.md).
