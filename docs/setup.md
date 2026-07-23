# Packaged setup and lifecycle guide

`signet setup` is the packaged, resumable installation path for macOS and Linux. It
creates production state with every provider disabled, installs two loopback-only
services, prepares one or more named Hermes profiles, and opens the authenticated
owner ceremony at the final private HTTPS origin. Provider setup is a separate guided
command, and Signet never restarts Hermes.

The setup path changes real user resources. Read the plan and this guide before
confirming it. For the repository-owned fake demo, use
[`operator-runbook.md`](operator-runbook.md) instead.

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

## Review the read-only plan

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

Planning is read-only. The JSON plan names every step, the root, profiles, final owner
URL, disabled provider state, browser behavior, and the fact that Hermes will not be
restarted. It separates `automatic_steps`, `human_ceremonies`, and
`deferred_provider_proof` so manual authentication and post-setup provider proof are
explicit before apply.

## Apply or resume

Run the same command without `--plan` and review the confirmation prompt:

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

1. verify the installed executable, platform, selected profiles, and Tailscale node;
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

## Review and enable Hermes entries

Each selected profile receives a distinct caller token and disabled
`signet_approvals`, `signet_fastmail`, and `signet_whatsapp` MCP entries. The token
is written automatically to that profile's private `.env`; it is not printed, placed
in YAML, accepted on argv, or copied by the operator. Existing config and environment
text is preserved through marker-bounded edits, and rollback removes only those exact
edits.

Review the local URLs, `Authorization` environment reference, and profile scope.
Enable `signet_approvals` and only the provider entries you configure, then run
`/reload-mcp` in that profile. Signet never runs `hermes gateway restart`, never edits
gateway tokens, and never assumes that editing one profile reloads another.

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

```console
signet status
signet doctor
signet manage status
signet manage stop
signet manage start
signet manage restart
```

`status` and `doctor` report metadata only. They do not print caller tokens, keyring
values, browser capabilities, encrypted payloads, or authenticator material.

Create an encrypted backup before changes:

```console
signet backup
signet backup --destination /absolute/private/path/archive.signet-backup
```

Restore verifies and decrypts into a new private staging directory; it never replaces
active state:

```console
signet restore /absolute/path/archive.signet-backup
```

After installing a reviewed newer wheel, back up and apply its schema migrations:

```console
signet upgrade
```

The upgrade runs inside a maintenance window, creates and verifies an encrypted backup before the first schema mutation, and reports a durable `upgrade_receipt` beside that backup. The receipt records the backup hash, source schema, and live schema observed after migration; it remains available if later assembly or service restart fails, and retries inspect the live schema again.

A normal uninstall stops and removes exact service definitions and removes only the
owned Hermes blocks while preserving production data and keyring material:

```console
signet uninstall
```

This records an `uninstalled` checkpoint. Running `signet setup` again with the same
specification reinstalls only the removed service, Hermes, and owner-bootstrap
integration steps; preserved data and configuration are not recreated.

`signet uninstall --purge` first creates a verified encrypted backup, removes owned
active data and runtime secrets, and intentionally retains the backup encryption key
and backup directory. It refuses changed or foreign resources. Use purge only after
recording and testing the returned backup path.

To reverse an incomplete installation in exact reverse order:

```console
signet setup --rollback
```

Rollback is resumable. For a completed setup, the CLI creates and verifies an
encrypted backup before removing active resources and retains its key. It records every
rollback failure, continues with independent owned steps, and can be run again after
the changed resource has been reviewed.

## Installed files and package data

The setup root contains the journal, owner marker, policy, production config,
database, provider resources, encrypted attachment staging, restore staging, backups,
logs, and reviewed service definitions. Modes are 0700 for private directories and
0600 for private files. Launchd definitions are installed under
`~/Library/LaunchAgents`; systemd user units are installed under
`~/.config/systemd/user`.

The wheel includes the `signet(1)` manual page. Depending on the installer, it is
available under the wheel shared-data `share/man/man1` location; `signet --help` and
each subcommand's `--help` remain authoritative for the installed version.
