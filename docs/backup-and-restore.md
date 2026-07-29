# Backup and restore

Signet lifecycle mutations use a two-step plan/apply protocol. A plan is read-only and
binds the installation, private path identities, operation, and destination. Apply
accepts only the exact reviewed plan ID.

## Create a backup

1. Check the installation and available storage:

   ```console
   signet status
   signet doctor
   ```

2. Print a **read-only plan**:

   ```console
   signet backup
   ```

   The default destination is a new file in the configured private backup root. Use
   `--destination` only with a reviewed absolute path under a pre-created private
   local directory.

3. Review the root, destination, capacity estimate, and `plan_id`. Run the exact
   `next_commands` apply command printed by Signet. Its shape is:

   ```console
   signet backup --apply PLAN_ID
   ```

   `PLAN_ID` is a visible placeholder here, not a command to copy literally.

Apply creates a consistent SQLite snapshot plus managed state in an encrypted
`.signet-backup` bundle, publishes it without overwriting an existing path, and
verifies the resulting artifact. A changed destination or plan observation is refused.
Backups are not silently deleted to make space; review and move an older verified
bundle before planning again.

## What else recovery needs

The encrypted bundle is data-bearing but is not self-sufficient. Decryption and
runtime recovery also require the exact external key references and operating-system
keyring material recorded for the installation. Preserve those through a separately
reviewed host/keyring recovery procedure. Never export key values into YAML, shell
history, logs, or chat.

Keep at least one tested copy away from the active data filesystem. Restrict the
backup directory to the service user and treat bundle names, manifests, and receipts
as sensitive metadata even though payload contents are encrypted.

## Verify a restore into staging

Restore never overwrites active production state. It verifies and decrypts into a new
private staging directory.

1. Supply the absolute path of a reviewed bundle to print the plan:

   ```console
   signet restore /absolute/private/path/archive.signet-backup
   ```

2. Review the bundle identity, required external secret references, and new staging
   destination. Run the exact emitted apply command:

   ```console
   signet restore /absolute/private/path/archive.signet-backup --apply PLAN_ID
   ```

3. Inspect the reported restored tree and verification receipt. Restore does not
   switch the live root, start services, change Tailscale, reload Hermes, enable a
   provider, or authorize a send.

Promotion of restored data is a separate incident/recovery decision. Do not replace a
live database with an older backup if it could forget a caller-visible pending
acknowledgement, approval, dispatch attempt, or possible provider effect. Preserve the
current tree and repair forward unless a reviewed release-specific procedure proves
the rollback is safe.

## Interrupted operations

Run `signet status`, correct the reported condition, and rerun only the exact previous
apply command and plan ID. Do not delete lifecycle receipts or partially published
artifacts. See [Resume setup and lifecycle work](setup-resume.md) and
[upgrade rollback boundaries](upgrade-and-rollback.md).
