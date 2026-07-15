# Hermes Agent integration

These files have not been applied to a Hermes profile. The current Hermes Agent
configuration model uses `mcp_servers` entries in each profile's `config.yaml` and
resolves `${VAR}` placeholders from that profile's `.env`. Confirm the installed
version with `hermes --version` and `hermes mcp --help` before a reviewed change;
Hermes is external software and its interface may change.

Hermes' official standard source installer includes its `mcp` extra. A PyPI
installation must request that extra explicitly; the integration was independently
validated with `hermes-agent[mcp]==0.16.0`. Bare `hermes-agent==0.16.0` lacks the
MCP SDK. Do not install an arbitrary standalone `mcp` version around Hermes' pinned
dependency contract.

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
hermes profile create signet-demo --no-alias --no-skills
export SIGNET_DEMO_HERMES_CONFIG="$(hermes -p signet-demo config path)"
export SIGNET_DEMO_HERMES_ENV="$(hermes -p signet-demo config env-path)"
for path in "$SIGNET_DEMO_HERMES_CONFIG" "$SIGNET_DEMO_HERMES_ENV"; do
  if test -e "$path"; then
    printf 'refusing to overwrite existing Hermes profile file: %s\n' "$path" >&2
    exit 1
  fi
done
install -m 0600 /dev/null "$SIGNET_DEMO_HERMES_CONFIG"
install -m 0600 /dev/null "$SIGNET_DEMO_HERMES_ENV"
```

Hermes Agent v0.16.0 reports the paths but does not create these files. The
preflight checks therefore stop on either existing path before `install` creates
the two blank mode-`0600` files.

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
config-version update advisory. Do not run `config migrate` for this demo: it
expands the blank file into broad release defaults. Keep the disposable profile's
environment free of live provider keys and other credentials because omitted
settings inherit Hermes defaults.

The three connection tests also preflight streamable-HTTP support and must report
`3`, `3`, and `4` discovered tools respectively. If Hermes reports that
`mcp.client.streamable_http` is unavailable, reinstall the reviewed Hermes release
with its `[mcp]` extra or use the official standard installer; do not independently
upgrade the SDK.

The demo approvals server intentionally omits `approve_request`, because automated
fixtures must not fabricate a six-digit TOTP code. Fake approve/deny actions are
available only in the authenticated loopback web demo with an unmistakable
`fake:` action proof. Connection tests do not require a Hermes model credential.

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
