# Low disk and external state roots

Signet binds storage paths and device identities during setup. It refuses unsafe
capacity, symlinks, path substitution, and unexpected files instead of guessing.

## Default layout and limits

The default setup root is `~/.local/share/signet`. Data and backups use `ROOT/data`
and `ROOT/backups`; attachments, staging, restore, cache, logs, service definitions,
and lifecycle receipts are private siblings.

Current production guards include:

- warning below 4 GiB free or 15 percent free;
- setup refusal below 1 GiB plus one 100 MiB attachment batch and one 25 MiB log
  rotation;
- 50 MiB encrypted staging admission;
- 1 GiB disposable-cache pruning threshold;
- 512 MiB aggregate owned-log limit; and
- 8 GiB owned-backup limit.

These are Signet guards, not filesystem quotas against other processes.

## Inspect capacity

```console
signet status
signet doctor
```

The storage section reports effective roots, existence, filesystem device, usage,
free space, warning state, and policy limits. `doctor` exits `1` at a hard reserve or
hard-cap breach. Free space first; do not delete a live database, staging file,
receipt, marker, or unverified backup.

Backups are never silently evicted. Move only a verified older bundle according to
your retention policy, preserve its external key material, then print a new backup
plan so the capacity snapshot is current.

## Choose external roots before first apply

Use a local filesystem owned by the service user. Pre-create empty mode-0700
directories, then include them in the initial setup plan:

```console
install -d -m 0700 "$HOME/signet-data" "$HOME/signet-backups"
signet setup --plan \
  --data-root "$HOME/signet-data" \
  --backup-root "$HOME/signet-backups"
```

Signet reads and displays the data directory's `st_dev` identity. Advanced operators
may pass the exact reviewed value with `--data-device`; normal setup discovers it.
Review the emitted plan, then run its exact apply command.

External roots must be absolute, empty, private, canonically disjoint, local, and free
of symlinks. Setup writes matching ownership markers in the external root and main
setup root and validates them on every resume. It does not adopt existing data or a
network filesystem. Do not move or copy the markers.

## External media outage or replacement

If an external volume disconnects, remounts on a different device, or is replaced,
Signet fails closed. Do not edit the recorded device number or point the path at a
replacement tree. Keep services stopped, restore the exact reviewed filesystem
identity or follow a reviewed staging-restore procedure, then rerun `status` and
`doctor`.

Storage roots are part of the durable setup specification. Do not try to relocate an
installed root by rerunning setup with different options. Use a verified backup,
staging restore, and an incident-specific migration plan.

For detailed service and retention behavior, see the
[production platform lifecycle matrix](platform-lifecycle-matrix.md) and
[production runtime contract](production-runtime.md).
