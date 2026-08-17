# Uninstall or purge

Uninstall is a reviewed lifecycle operation. Removing the `pipx` package first would
remove the command needed to stop owned services and remove managed routes, so run the
Signet lifecycle command first.

## Normal uninstall: preserve data

1. Inspect the installation:

   ```console
   signet status
   signet doctor
   ```

2. Print the **read-only uninstall plan**:

   ```console
   signet uninstall
   ```

3. Review the exact services, Tailscale listener, Hermes profile blocks, and the fact
   that production data is preserved. Run the emitted apply command:

   ```console
   signet uninstall --apply PLAN_ID
   ```

Normal uninstall stops and removes only setup-owned launchd/systemd definitions and
the owned Tailscale Serve listener, then removes only Signet-managed Hermes blocks and
caller tokens. It records an `uninstalled` checkpoint and preserves production data,
configuration, backups, and recovery-capable keyring material.

A later `signet setup` with the same specification can reinstall the removed service
and Hermes integration steps without recreating preserved data.

After Signet reports completion, remove the isolated package if desired:

```console
pipx uninstall signet-gateway
```

## Purge: remove owned production data

```console
signet uninstall --purge
signet uninstall --purge --apply PLAN_ID
```

**Human-only and destructive:** the first command is a plan. Review every destructive
action and run only its exact emitted apply command. Purge creates and verifies an
encrypted recovery backup, writes a durable external recovery receipt, removes owned
active production data, and removes non-backup runtime secrets. It retains the
recovery bundle and the material required to decrypt that bundle.

Do not treat successful backup creation as proof that off-host recovery works. Test a
staging restore first and preserve external keyring recovery. Do not purge while any
pending, executing, or `outcome_unknown` request still requires incident evidence.

## Safety refusals and retries

Signet refuses changed, foreign, symlinked, hard-linked, or unmarked resources rather
than deleting them. It does not reset unrelated Tailscale handlers, remove unrelated
Hermes configuration, or recursively delete an unverified path.

If apply is interrupted, run `signet status` and rerun only the exact prior apply
command. Do not manually delete journals, markers, receipts, or recovery files. For an
incomplete first setup, [setup rollback](setup-resume.md#reverse-an-incomplete-setup)
may be more appropriate.
