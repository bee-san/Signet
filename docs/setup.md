# Packaged setup and lifecycle guide

`signet setup` is the packaged, resumable installation path for macOS and Linux. It
creates production state with every provider disabled, installs two loopback-only
services, prepares one or more named Hermes profiles, and opens the authenticated
owner ceremony at the final private HTTPS origin. Provider setup is a separate guided
command, and Signet never restarts Hermes.

The setup path changes real user resources. Read the plan and this guide before
confirming it. For the repository-owned fake demo, use
[`operator-runbook.md`](operator-runbook.md) instead.
The cross-platform variants and their automated evidence are indexed in the
[`production platform lifecycle matrix`](platform-lifecycle-matrix.md).

## Prerequisites

- an installed `signet` entry point from a reviewed `signet-gateway` wheel;
- Python 3.12 with SQLite 3.51.3 or newer;
- macOS launchd or a Linux user systemd session;
- an available OS Keychain/keyring backend;
- every selected Hermes profile already present under
  `~/.hermes/profiles/PROFILE` and not group/world writable;
- for automatic private HTTPS, Tailscale logged in with MagicDNS and the intended
  `*.ts.net` node name. Signet manages HTTPS port 8443 only and refuses an existing
  Serve or Funnel listener there;
- for Fastmail, an API token and the sender address to test; or
- for WhatsApp, Linux x86_64 and a phone available to scan the pairing QR code.

A different canonical HTTPS origin can be supplied with `--origin`. Signet assumes
that its reverse proxy is independently configured and does not adopt it.

With Python 3.12 selected for `pipx`, install the reviewed package without a source
checkout or `uv`:

```console
pipx install signet-gateway
```

## Review the read-only plan

The normal happy path is simply `signet setup`; it prints this plan before asking for
confirmation. Use `--plan` when a separate review must finish before any apply.
The following example limits integration to two explicit profiles:

Select profiles explicitly when a host contains profiles that should not receive a
Signet entry:

```console
signet setup --plan \
  --profile personal \
  --profile work
```

Without `--origin`, Signet derives `https://NODE.ts.net:8443` from `tailscale status
--json`. Without `--profile`, it selects the Hermes default profile plus all
syntactically valid named profile directories.
The default owner is `user:owner`; use `--owner user:NAME` to choose another canonical
owner ID. The initial policy mode defaults to fail-closed `deny`; select `direct`,
`approval`, or `approval_with_edit` with `--policy-mode` when the reviewed deployment
requires a different baseline. The default root is `~/.local/share/signet`.

Data and backups default to `ROOT/data` and `ROOT/backups`. To put either on a
different local volume, create an empty directory owned by the service user with mode
`0700`, then include its absolute path in the plan. Data is additionally bound to the
reviewed filesystem device number; omit `--data-device` to have the plan read and
display the current number, or provide the exact reviewed value to detect a mount
replacement before setup writes anything:

```console
install -d -m 0700 /Volumes/PRIVATE/signet-data /Volumes/PRIVATE/signet-backups
signet setup --plan \
  --data-root /Volumes/PRIVATE/signet-data \
  --data-device "$(stat -f %d /Volumes/PRIVATE/signet-data)" \
  --backup-root /Volumes/PRIVATE/signet-backups
```

On Linux, use `stat -c %d`. External roots are not adopted: setup requires them to be
empty and private, writes matching ownership markers inside the external directory and
the main setup root, and validates both markers plus the data device on every resume.
Do not move, copy, or hand-edit these markers. The data and backup roots must remain
canonically disjoint from each other and from staging and restore roots.

Planning is read-only. The JSON plan names every step, effective data and backup roots,
the bound data device, profiles, final owner URL, disabled provider state, browser
behavior, and the fact that Hermes will not be restarted. It separates
`automatic_steps`, `human_ceremonies`,
`deferred_provider_proof`, and `destructive_actions` so manual authentication,
post-setup provider proof, and an empty destructive set are explicit before apply.

## Apply or resume

Run the same command without `--plan`. It prints the plan again before the confirmation
prompt, so the default `signet setup` remains a one-command workflow:

```console
signet setup \
  --profile personal \
  --profile work
```

For a reviewed non-interactive invocation, add `--yes`. Setup records an atomic,
mode-0600 journal at `ROOT/.setup-journal.json`. Re-running the same command resumes at
the first incomplete step; completed steps are not replayed. A different root,
origin, owner, executable, profile set, or policy mode is refused rather than adopted.

The ordered steps are:

1. verify the installed executable, platform, selected profiles, Tailscale node,
   configured storage identities, and write-space reserve;
2. create a marker-bound private root and private data directories;
3. generate high-entropy secrets directly into the OS keyring;
4. write the selected initial policy mode and a provider-disabled production config;
5. initialize and validate the hardened SQLite database;
6. render, install, start, and health-check installed-package launchd/systemd units;
7. claim an unused Tailscale Serve listener on HTTPS 8443 when using the derived
   `*.ts.net` origin;
8. issue separate profile-scoped MCP caller tokens and add disabled Hermes MCP
   entries; and
9. issue the one-time owner bootstrap capability and start the browser ceremony.

Setup refuses nonempty unmarked roots, symbolic links, hard-linked or changed owned
files, duplicate YAML keys, conflicting Hermes server/environment entries, changed
service units, occupied Tailscale listeners, and a Funnel listener on the managed
port. Generated service units execute the installed `signet` entry point; they do not
reference a source checkout, `uv run`, or a package resolver.

The launchd agents and systemd user units keep MCP and browser HTTP in separate
loopback processes. The web process owns the bounded delivery, reconciliation,
retention, storage-maintenance, and notification lifecycle workers. Generated units
set restart throttles, file-descriptor/task limits, and memory limits without placing
credentials in argv or environment. On launchd, worker maintenance copy-truncates each
owned log at 25 MiB and keeps one 25 MiB rotation; systemd uses the user journal.
Disposable cache files are pruned oldest-first above 1 GiB. Encrypted staging already
has its own 50 MiB admission limit. The aggregate owned-log and backup limits are
512 MiB and 8 GiB respectively; backup creation refuses to start when the reviewed
bundle estimate would cross the backup cap or the required write reserve.
The packaged setup leaves VAPID unset: the notification worker still drains
subscription-free outbox intents, but an unexpected live subscription fails closed and
is deferred rather than being reported as delivered. Browser push requires a later
reviewed credential, public-key, subject, and endpoint-origin configuration slice.

Storage preflight fails before mutation when less than 1 GiB plus one 100 MiB
attachment batch and one 25 MiB log rotation remains. It emits a warning below either
4 GiB free or 15 percent free, so an operator can expand or relocate storage before
the hard refusal. These checks are capacity guards, not quota isolation from other
processes on the same filesystem.

## Owner browser ceremony

Signet prints the exact non-secret `https://…/setup` URL before asking the operating
system to open the private capability URL. The capability is carried in a URL
fragment, removed from browser history before it is submitted, retained only in the
OS keyring for crash recovery, and never written to the setup journal or normal
output.

If browser opening is cancelled or unavailable, resume without opening it:

```console
signet setup --no-open-browser --yes
```

The command prints the public setup URL; continue in the browser that owns any
in-progress claimant cookie. Owner setup supports password plus multiple separately
named TOTP and passkey authenticators. Passkeys must be enrolled by a real browser and
authenticator at the final HTTPS origin. Do not try to generate or transfer a passkey
through the CLI.

After setup, print that final private management URL before reopening the authenticated
named passkey/TOTP ceremony:

```console
signet authenticators open
```

Use `--no-open-browser` to print only the URL. Enrollment, naming, fresh-factor
reauthentication, last-factor protection, and deletion remain browser actions;
credential material never crosses the CLI.

## Review and enable Hermes entries

Each selected profile receives a distinct caller token and disabled
`signet_approvals`, `signet_fastmail`, and `signet_whatsapp` MCP entries. The token
is written automatically to that profile's private `.env`; it is not printed, placed
in YAML, accepted on argv, or copied by the operator. Existing config and environment
text is preserved through marker-bounded edits, and rollback removes only those exact
edits.

Review the local URLs, `Authorization` environment reference, and profile scope.
Before enabling entries, use the reviewed Hermes executable bound to the selected
profile to validate configuration and inspect the disabled entries:

```console
hermes -p PROFILE config check
hermes -p PROFILE mcp list
```

`PROFILE` is a visible placeholder. Complete owner authentication and the provider's
separate live proof before enabling `signet_approvals` and only the provider entries
you configured. Then test each enabled server:

```console
hermes -p PROFILE mcp test signet_approvals
hermes -p PROFILE mcp test signet_fastmail
```

Omit `signet_fastmail` unless Fastmail passed its live proof; substitute
`signet_whatsapp` only after the WhatsApp proof. These connection tests prove only
configuration parsing, loopback transport, and caller authentication; they do not
replace human authentication, queue-behavior review, or the provider live send. If
production is bound to a version-locked Hermes wrapper, use that reviewed wrapper
instead of the bare command.
Source operators can follow the bounded wrapper procedure in
[`deploy/hermes/README.md`](../deploy/hermes/README.md); packaged setup itself does not
depend on that checkout or on `uv`.

After those tests, run `/reload-mcp` inside that interactive profile, then start a new
session before checking discovered tools.
Do not run `/reload-mcp` as a shell command. Signet never runs `hermes gateway restart`,
never edits gateway tokens, and never assumes that editing one profile reloads another.

## Configure a provider

Fastmail setup prompts for the API token, discovers the live MCP schemas, sends one
test email, saves the generated policy, and enables the provider:

```console
signet provider setup fastmail \
  --from you@example.com \
  --to you@example.com
```

For non-interactive secret-broker integration, pass one token line on standard input
with `--token-stdin`; do not put the token in an argument.

WhatsApp setup is available on Linux x86_64. It downloads the pinned
`wacli 0.12.0` archive, verifies its SHA-256, opens the pairing flow, sends one test
message, and enables the provider:

```console
signet provider setup whatsapp --to +447700900123
```

Inspect or control the rollout with:

```console
signet provider status
signet provider disable fastmail
signet provider enable fastmail
```

The rollout gate is shared by all configured providers; enable and disable output
lists every affected alias. If startup health verification fails, Signet restores the
disabled configuration. Re-running setup with the same provider is idempotent.
The lower-level connector contract remains documented in
[`production-connectors.md`](production-connectors.md).

## Lifecycle commands

All commands accept `--root`; examples below use the default root.

Mutation-capable lifecycle commands default to a read-only plan. Copy the emitted
`plan_id` only after reviewing the operation, exact root, targets, backup requirements,
and preconditions. Apply or roll back only that exact plan; changed state, changed
arguments, an expired plan, or a foreign owner marker is refused.

```console
signet manage stop
signet manage stop --apply PLAN_ID
signet manage stop --rollback PLAN_ID
```

`PLAN_ID` is the value emitted by the immediately preceding matching plan, not a
literal value. `manage status` is read-only and cannot apply or roll back a plan:

```console
signet status
signet doctor
signet manage status
```

`status` and `doctor` report metadata only. Their `storage` section reports each
effective root, existence, device number, used/free/total bytes, warning state, and
the fixed limits above. `doctor` fails the storage check at the write reserve or a
hard-cap breach and otherwise gives an actionable low-space warning. They do not print
caller tokens, keyring values, browser capabilities, encrypted payloads, or
authenticator material.

Plan an encrypted backup, then apply the exact reviewed plan:

```console
signet backup --destination /absolute/private/path/archive.signet-backup
signet backup --destination /absolute/private/path/archive.signet-backup --apply PLAN_ID
```

Omit `--destination` from both commands to use the configured private backup root
recorded in the plan. Backups are never silently deleted to make room; move a verified
older bundle under the reviewed retention policy, then rerun the plan so the new
capacity snapshot is explicit.

Restore verifies and decrypts into a new private staging directory; it never replaces
active state:

```console
signet restore /absolute/path/archive.signet-backup
signet restore /absolute/path/archive.signet-backup --apply PLAN_ID
```

After installing a reviewed newer wheel, back up and apply its schema migrations:

```console
signet upgrade
signet upgrade --apply PLAN_ID
```

The upgrade runs inside a maintenance window, creates and verifies an encrypted backup before the first schema mutation, and reports a durable `upgrade_receipt` beside that backup. The receipt records the backup hash, source schema, and live schema observed after migration; it remains available if later assembly or service restart fails, and retries inspect the live schema again.

A normal uninstall stops and removes exact service definitions and removes only the
owned Hermes blocks while preserving production data and keyring material:

```console
signet uninstall
signet uninstall --apply PLAN_ID
```

This records an `uninstalled` checkpoint. Running `signet setup` again with the same
specification reinstalls only the removed service, Hermes, and owner-bootstrap
integration steps; preserved data and configuration are not recreated.

`signet uninstall --purge` prints a destructive plan. Its exact `--apply PLAN_ID`
first creates a verified encrypted backup, removes owned active data and runtime
secrets, and intentionally retains the backup encryption key and backup directory. It
refuses changed or foreign resources. Apply purge only after recording and testing the
returned backup path.

```console
signet uninstall --purge
signet uninstall --purge --apply PLAN_ID
```

To reverse an incomplete installation in exact reverse order:

```console
signet setup --rollback
```

Rollback is resumable. For a completed setup, the CLI creates and verifies an
encrypted backup before removing active resources and retains its key. It records every
rollback failure, continues with independent owned steps, and can be run again after
the changed resource has been reviewed.

## Crash recovery and exit status

Setup and lifecycle applies write atomic journals or receipts before advancing. After
an interruption, do not edit or delete them. Inspect the recorded owner, specification,
completed or failed step, service state, and lifecycle receipt:

```console
signet status
signet doctor
```

Correct the reported condition and rerun the same `signet setup` command to resume.
For a lifecycle apply, rerun only the exact command and `PLAN_ID` shown by status.
Rerunning completed setup reconciles the owner ceremony without repeating completed
automatic steps. A conflicting specification or foreign marker is refused rather than
adopted or overwritten.

Exit status is stable for automation: `0` means the requested read-only operation,
plan, or apply completed; `2` means invalid input, declined confirmation, safety
refusal, conflict, or incomplete work. Stderr includes a redacted recovery command.
An interrupted process may use the shell's signal status. Never infer success from
partial stdout; inspect the exit status and `signet status`.

## Installed files and package data

The setup root contains the journal, owner marker, policy, production config,
provider resources, encrypted attachment staging, restore staging, cache, logs, and
reviewed service definitions. By default it also contains the database and backups;
with external roots it instead contains the matching external-storage receipts. Modes
are 0700 for private directories and 0600 for private files. Launchd definitions are installed under
`~/Library/LaunchAgents`; systemd user units are installed under
`~/.config/systemd/user`.

The wheel includes the `signet(1)` manual page. Depending on the installer, it is
available under the wheel shared-data `share/man/man1` location; `signet --help` and
each subcommand's `--help` remain authoritative for the installed version.
