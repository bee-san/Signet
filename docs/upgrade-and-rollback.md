# Upgrade and safe rollback boundaries

Package replacement and state migration are separate steps. Upgrade only to a
reviewed Signet release whose notes cover your current version and platform.

## Upgrade

1. **Human-only:** read the release notes, verify the intended package provenance,
   confirm platform support, and schedule a maintenance window.
2. Create and verify an independent backup using
   [Backup and restore](backup-and-restore.md).
3. Enter the exact version from those signed release notes, replace the isolated
   package with that release, and confirm the installed version:

   ```console
   printf 'Reviewed Signet version: '
   read -r SIGNET_VERSION
   pipx install --force "signet-gateway==$SIGNET_VERSION"
   signet --version
   ```

   Confirm that the output is exactly `signet $SIGNET_VERSION`. Do not use an
   unqualified `pipx upgrade`, and do not migrate state if package identity is
   surprising.

4. Print the **read-only upgrade plan**:

   ```console
   signet upgrade
   ```

5. Review the setup identity, service state, current and target schema, unit
   generation, and exact `plan_id`. Run the emitted apply command, whose shape is:

   ```console
   signet upgrade --apply PLAN_ID
   ```

Upgrade re-runs preflight, quiesces active Signet services, creates and verifies a
pre-migration encrypted backup, applies schema migrations, restores the previous
service state, and verifies instance-bound health. It does not restart Hermes or
enable a disabled provider. Preserve the reported backup and durable upgrade receipt.

After apply:

```console
signet status
signet doctor
signet provider status
```

If the generated Hermes route surface changed, review it and run `/reload-mcp` in each
selected interactive profile. Signet never runs a Hermes gateway restart.

## Interrupted upgrade

Do not downgrade the package, restore a database, delete a receipt, or start services
by hand. Run `signet status`, correct the reported condition, and rerun the exact prior
`signet upgrade --apply` command. The receipt lets Signet distinguish a migration not
yet started, a migration applied, and a later assembly or service-start failure.

## There is no generic package rollback command

`signet manage ACTION --rollback PLAN_ID` rolls back only an exact reviewed service
start/stop/restart plan. It does **not** roll back a package, schema, provider effect,
or production database. `signet restore` creates a staging tree and does not replace
active state.

A binary or database rollback is allowed only when a reviewed release-specific
procedure proves all of these facts:

- the older binary supports the current on-disk schema and service-unit generation;
- no durable caller-visible acknowledgement would be forgotten;
- no downstream provider mutation or `outcome_unknown` evidence would be lost;
- policy versions, idempotency records, provider identities, and pending requests are
  preserved; and
- the exact pre-migration backup and required external key references were verified.

If any fact is unknown, leave providers disabled or services stopped as reported,
preserve both current and recovery state, and repair forward. Never infer safety from
a process merely starting. The [production runtime contract](production-runtime.md)
and [security model](security-model.md) define the expert rollback boundary.
