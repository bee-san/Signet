# Troubleshooting

Start with read-only evidence:

```console
signet --version
signet status
signet doctor
signet provider status
```

Do not paste the full output into a public issue without reviewing paths and account
metadata. These commands redact secret values, but operational metadata can still be
sensitive.

## `signet` is not found

Confirm `pipx` installed the expected distribution and that its binary directory is on
`PATH`:

```console
pipx list
pipx ensurepath
```

Open a new shell, then run `signet --version`. The distribution is
`signet-gateway`; the command is `signet`. Supported releases require Python 3.12.

## Tailscale origin cannot be discovered

Setup derives the private origin from the current node's MagicDNS name. Confirm the
intended user is logged into the intended tailnet:

```console
tailscale status --json
tailscale serve status --json
```

Setup manages only private HTTPS port 8443 and refuses an existing Serve handler or
Funnel listener there. Do not run a broad Tailscale reset. Remove or migrate a
conflicting listener only after reviewing who owns it. An advanced `--origin` must be
one canonical HTTPS origin backed by a separately configured trusted reverse proxy.

## Browser did not open

```console
signet setup --no-open-browser
```

Open the exact printed `/setup` URL from a browser on the same tailnet. The capability
is not in that URL. Read it from the private file only when the Signet form asks. If it
expired, rerun the same setup command to issue a replacement.

## Passkey or TOTP enrollment was cancelled

Reload the same setup page and start a new ceremony. Completed setup progress survives
reload and service restart. Do not reuse an abandoned TOTP manual key. Passkeys require
a browser and authenticator at the final exact HTTPS origin with user verification.

After setup, use `signet authenticators open`. If every authenticator is lost, there is
no self-service bypass; follow [Lost authenticators and recovery](recovery.md).

## Setup reports a changed plan, path, or foreign object

Stop. A setup option, executable, service file, profile block, route, device identity,
or owned path changed after review. Do not delete the journal/marker or use `--yes` to
bypass it. Inspect `status`, restore the exact reviewed state, or print and review a
new plan when the operation permits it.

## Hermes does not show Signet tools

Review each selected profile independently:

```console
hermes -p PROFILE config check
hermes -p PROFILE mcp list
```

`PROFILE` is a visible placeholder. Enable only the reviewed Signet entries, run
`/reload-mcp` inside that interactive profile, and start a new session. Signet never
restarts the Hermes gateway. Do not copy caller tokens from `.env` into YAML or chat.

## Provider setup fails

The provider remains or returns disabled when setup or health verification fails.
Run `signet provider status` and `signet doctor`, correct the credential/account,
platform, network, schema, certificate, or service issue, and rerun the guided command.
Do not hand-edit generated policy, schema digests, connector identity, or rollout
state. Remember that retrying provider setup can perform another real test message
after confirmation.

To stop new provider dispatch while preserving evidence:

```console
signet provider disable fastmail
```

The rollout gate is shared; review the command output for every affected alias.

## Low disk or backup cap

Use the storage section of `status` and `doctor`. Free space without deleting live
state, markers, receipts, or an unverified backup. Signet does not evict backups
silently. See [Low disk and external state roots](storage.md).

## Service is unhealthy

Do not start, stop, or replace unit files by hand. Print a reviewed service plan:

```console
signet manage restart
```

Apply only the exact emitted plan if its targets and state are correct. If an upgrade
is in progress, resume that exact upgrade apply instead; a service plan is not a
package/schema rollback.

## Interrupted backup, restore, upgrade, or uninstall

`signet status` reports the lifecycle operation and plan ID. Correct the reported
condition and rerun only its exact prior apply command. Keep receipts and partial
artifacts. See [Resume setup and lifecycle work](setup-resume.md).

For an unresolved security or provider-outcome incident, disable new rollout when safe,
preserve the current database, encrypted staging, logs, receipts, and backups, and use
the [expert operator runbook](operator-runbook.md). Never restore an older database
merely to make the service start.
