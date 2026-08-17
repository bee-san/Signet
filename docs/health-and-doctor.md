# Status, doctor, and verification

Use these commands before provider setup, after setup or upgrade, and when behavior is
unclear. They do not print caller tokens, provider credentials, browser capabilities,
TOTP seeds, passkey material, or decrypted request payloads.

## Read-only commands

```console
signet status
signet doctor
signet verify
signet provider status
```

All accept `--root` when the installation does not use the default
`~/.local/share/signet` root.

### `signet status`

`status` reports persisted facts:

- setup ID, setup state, and every setup step;
- current lifecycle operation and plan ID, if any;
- launchd/systemd service and Tailscale Serve state;
- effective data, backup, attachment, staging, cache, and log roots;
- capacity warnings, hard limits, device identities, and usage;
- production readiness and missing prerequisites;
- provider rollout state; and
- bounded queue, reconciliation, retention, and storage metrics when available.

A status value is an observation, not proof that an external provider effect did or
did not happen. Preserve `outcome_unknown` and reconciliation evidence.

### `signet doctor`

`doctor` checks the installed boundary, including journal and lifecycle consistency,
private path identity, runtime configuration, database integrity/schema, secret
references, service definitions and health, Tailscale route ownership, Hermes managed
blocks, and storage reserve. Each failed check includes a redacted remediation.

Exit status `0` means every required check passed. Exit status `1` means diagnostics
completed but at least one required check is unhealthy. Warnings such as approaching
the storage reserve remain actionable even when the required check still passes.

### `signet verify`

`verify` separates evidence into three groups:

- automatic safe checks from `doctor`;
- required human ceremonies, including owner authentication and Hermes review/reload;
- deferred live provider proof: credential configuration, read-only discovery, and
  the attended test send.

It never claims that a human ceremony or provider proof occurred merely because local
files exist.

### `signet provider status`

Provider status reports platform support, configuration, credential readiness, enabled
state, and the shared rollout state for Fastmail and WhatsApp. It does not contact a
provider or reveal credential values.

## Recommended checkpoints

```console
signet status
signet doctor
```

Run them:

- after completing owner setup and `/reload-mcp`;
- before and after provider setup;
- before backup, upgrade, uninstall, or storage maintenance;
- after reboot or service-manager changes; and
- after resuming any interrupted lifecycle apply.

If a required check fails, do not bypass it by editing managed files or deleting
receipts. Follow [Troubleshooting](troubleshooting.md), then rerun the read-only checks.
For incident-level interpretation, use the [expert operator runbook](operator-runbook.md).
