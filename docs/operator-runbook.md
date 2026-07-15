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

Python 3.12 and `uv` are required. Install the repository-pinned managed build; the
SQLite check must print `3.51.3` or newer.

```console
uv python install 3.12.13
uv sync --frozen
uv run python -c 'import sqlite3; print(sqlite3.sqlite_version)'
uv run signet --help
uv run signet demo --help
uv run pytest -q
uv run ruff check .
uv run mypy
```

Do not proceed from an unreviewed dependency update or a failing check. Completing
this demo does not make a live deployment ready.

## 2. Initialize private fake state

Use the ignored `var/` tree in this checkout so every terminal can use the same
absolute path. `demo init` accepts only a nonexistent directory and refuses to
adopt or overwrite any existing path, including an empty directory.

```console
export SIGNET_DEMO_DIR="$PWD/var/operator-demo"
test ! -e "$SIGNET_DEMO_DIR"
uv run signet demo init --data-dir "$SIGNET_DEMO_DIR"
uv run signet demo smoke --data-dir "$SIGNET_DEMO_DIR"
```

The initializer creates a mode-`0700` tree, mode-`0600` state and secret files, an
initialized SQLite database, a deny-by-default fake policy, reviewed fake schemas,
and a profile-scoped fake MCP token. It never prints a credential. The default
`smoke` command is offline: it validates and assembles the saved state without
opening a listener or allowing a network/provider call.

Credential retrieval emits exactly one explicitly fake value plus a newline. It is
separate from initialization and serve logs:

```console
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-user
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-password
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-login-proof
uv run signet demo credentials --data-dir "$SIGNET_DEMO_DIR" --field web-action-proof
```

`web-login-proof` and `web-action-proof` start with `fake:` and are deliberately
distinct. They are not authenticator codes and are not evidence of password, TOTP,
passkey, or recovery enrollment. Do not use a real address, phone number, message,
attachment, credential, or authentication proof in this tree.

## 3. Start and verify both apps

In terminal A, export the same absolute directory and start both loopback servers:

```console
export SIGNET_DEMO_DIR="$PWD/var/operator-demo"
uv run signet demo serve --data-dir "$SIGNET_DEMO_DIR" \
  --mcp-port 8789 --web-port 8790
```

The only readiness lines are non-secret and have these forms:

```text
Signet fake-only demo MCP: http://127.0.0.1:8789/mcp/{fastmail,whatsapp,approvals}
Signet fake-only demo web: http://127.0.0.1:8790/login
```

In terminal B, run the explicit live-listener smoke probe and independent checks:

```console
export SIGNET_DEMO_DIR="$PWD/var/operator-demo"
uv run signet demo smoke --data-dir "$SIGNET_DEMO_DIR" \
  --mcp-port 8789 --web-port 8790 --live
curl --fail --silent --show-error http://127.0.0.1:8789/healthz
curl --fail --silent --show-error http://127.0.0.1:8790/healthz
curl --silent --output /dev/null --write-out '%{http_code}\n' \
  --request POST http://127.0.0.1:8789/mcp/approvals
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

Hermes is external software. Confirm the installed command surface first. The
commands below use a blank profile with no alias and no bundled skills; they never
clone or select the default profile.

Use an installation that includes Hermes' MCP extra. The official standard source
installer includes `.[all]`, which includes `.[mcp]`. The procedure is independently
validated with `hermes-agent[mcp]==0.18.2` and remains compatible with
`hermes-agent[mcp]==0.16.0`; a bare PyPI install does not include the MCP SDK. Do not
repair this by installing or upgrading the standalone `mcp` package to an arbitrary
version: Hermes pins the compatible SDK through its extra. Stop if the installed
Hermes version or installation method is not one you have reviewed.

```console
hermes --version
hermes mcp --help
hermes profile list
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

Stop if `signet-demo` already exists. Do not repurpose it or substitute another
profile path. Hermes Agent v0.16.0 reports the new profile paths without creating
either file. Version v0.18.2 leaves `config.yaml` absent and seeds a mode-`0600`,
comment-only `.env`; the branches preserve that reviewed seed. The configurator
then verifies content, ownership, mode, link count, and identity. Generate the exact
current-port fragment into the private demo tree, then stream the token directly
into the checked-in structured merge helper:

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

The helper accepts only the exact three `127.0.0.1` routes, the
`${SIGNET_DEMO_MCP_CALLER_TOKEN}` placeholder, disabled parallel calls/resources/
prompts/sampling, and bounded timeouts. It refuses a nonblank profile environment,
existing MCP routes, duplicate YAML keys, symlinks, unsafe modes, raw/non-fake
tokens, unknown fields, and non-loopback URLs. The raw token travels over the pipe;
it is never an argument, environment variable, generated YAML value, or log field.

Validate transport and authenticated discovery while the demo server is running:

```console
hermes -p signet-demo config check
hermes -p signet-demo mcp test signet_demo_fastmail
hermes -p signet-demo mcp test signet_demo_whatsapp
hermes -p signet-demo mcp test signet_demo_approvals
hermes -p signet-demo mcp list
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
[Hermes MCP guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md),
[CLI reference](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/reference/cli-commands.md),
and
[profile guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/profiles.md).
Check the installed version's help before applying any later live diff.

## 5. Exercise fake workflows

If a human separately chooses to configure a model in `signet-demo`, start a new
session with `hermes -p signet-demo chat`. Give Hermes exact tool-call instructions;
do not rely on a natural-language guess. The expected prefixed tools and arguments
are:

```text
Call mcp_signet_demo_fastmail_list_identities with {} and return its exact result.

Call mcp_signet_demo_fastmail_send_email with
{"from":"fake-sender@demo.invalid","to":["fake-recipient@demo.invalid"],
 "cc":[],"bcc":[],"subject":"Signet demo",
 "body":"This is a fake-only approval test.","attachments":[]}.

Call mcp_signet_demo_approvals_list_pending_approvals with {}.
```

The read returns only `fake:`/`.invalid` fixture data. The send returns a durable
`pending_approval` response and makes zero fake-provider calls. Record its
`request_id` and `version_hash_prefix`. In the web queue, expand the row and verify
the complete frozen arguments, reason, warnings, policy/adapter/schema versions,
hashes, attachments, origin, and event timeline.

First choose a specific denial reason and deny one fake request in the web form
with the value returned by `web-action-proof`. Then call the status tool with
its ID:

```text
Call mcp_signet_demo_approvals_check_approval_status with
{"request_id":"REQUEST_ID_FROM_THE_DENIED_CALL"}.
```

It must return `denied`, and the expanded timeline must show zero provider calls.
The action proof is visibly constant, but every accepted use receives a distinct
durable fake-only use ID, including across restart. Retrieve `web-action-proof`
again, then create a second identical fake send, review its full context, choose an
explicit approval reason, and approve it in the web form. The bounded
fake delivery worker must make exactly one in-process fake-provider call and reach
`succeeded`; status returns only safe result metadata, not the frozen private
payload. Calling
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
uv run signet demo purge-unknown --data-dir "$SIGNET_DEMO_DIR" \
  --request-id 'REPLACE_WITH_EXACT_FAKE_REQUEST_ID' \
  --expected-version 'REPLACE_WITH_EXACT_VERSION' \
  --expected-payload-hash 'REPLACE_WITH_EXACT_64_CHARACTER_HASH' \
  --acknowledge-possible-delivery
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
export SIGNET_DEMO_DIR="$PWD/var/operator-demo"
export SIGNET_DEMO_ARTIFACTS="$PWD/var/operator-demo-artifacts"
test ! -e "$SIGNET_DEMO_ARTIFACTS"
mkdir -m 0700 "$SIGNET_DEMO_ARTIFACTS"
export SIGNET_DEMO_BACKUP="$SIGNET_DEMO_ARTIFACTS/operator-demo.signet-backup"
export SIGNET_DEMO_RESTORE="$SIGNET_DEMO_ARTIFACTS/restored"
test ! -e "$SIGNET_DEMO_BACKUP"
test ! -e "$SIGNET_DEMO_RESTORE"
uv run signet demo backup --data-dir "$SIGNET_DEMO_DIR" \
  --output "$SIGNET_DEMO_BACKUP"
uv run signet demo restore --data-dir "$SIGNET_DEMO_DIR" \
  --bundle "$SIGNET_DEMO_BACKUP" --destination "$SIGNET_DEMO_RESTORE"
test "$SIGNET_DEMO_DIR" != "$SIGNET_DEMO_RESTORE"
uv run signet demo smoke --data-dir "$SIGNET_DEMO_RESTORE"
```

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
uv run signet demo release-abandoned-pins --data-dir "$SIGNET_DEMO_DIR" \
  --created-at-or-before UNIX_SECONDS \
  --acknowledge-no-backup-active
```

The command refuses a running server, an active backup-maintenance lock, an invalid
demo marker, a future cutoff, or a missing acknowledgement. Its JSON output reports
only the cutoff and released/remaining row counts. Never use the cutoff to release
pins for an operation that might still be running, and never edit `purge_jobs`
directly.

Start the restored tree on alternate ports in terminal A:

```console
export SIGNET_DEMO_RESTORE="$PWD/var/operator-demo-artifacts/restored"
uv run signet demo serve --data-dir "$SIGNET_DEMO_RESTORE" \
  --mcp-port 8889 --web-port 8890
```

Then verify it from terminal B:

```console
export SIGNET_DEMO_RESTORE="$PWD/var/operator-demo-artifacts/restored"
uv run signet demo smoke --data-dir "$SIGNET_DEMO_RESTORE" \
  --mcp-port 8889 --web-port 8890 --live
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
hermes profile delete signet-demo -y
```

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
| `demo init` refuses the directory | Exact `SIGNET_DEMO_DIR`, ownership, contents | Select a new ignored path. Never adopt or erase unknown state. |
| `connection refused` | Process terminal, exact port, `lsof -nP -iTCP:8789 -sTCP:LISTEN` and port `8790` | Start the demo or choose unused ports. Never bind MCP off loopback. |
| Health returns `421` | Request `Host` and configured numeric loopback/port | Use the exact loopback URL. Do not relax Host validation. |
| MCP returns `401` | Selected profile, profile `.env`, fake token scope, `Authorization` interpolation | Recreate the disposable profile. Never print or log a live token. |
| Hermes says `mcp.client.streamable_http` is unavailable | Hermes installation and MCP extra | Reinstall the same reviewed Hermes release with its `[mcp]` extra, or use the official standard installer. Do not independently upgrade the SDK. |
| MCP route returns `404` | Exact `/mcp/<alias>` path and absence of a trailing slash | Correct the profile URL. Do not add proxy rewrites. |
| Profile helper refuses files | Exact `signet-demo` path, blank `.env`, empty `mcp_servers`, modes and symlinks | Stop and inspect. Do not weaken or bypass a helper check. |
| Hermes reports no tools | `hermes -p signet-demo mcp test NAME`, demo server, fake policy/schema state | Keep tools disabled, repair fake state, reload MCP, and start a new session. |
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
