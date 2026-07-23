# Reviewed wacli process boundary

This document describes the owned process contract used by the gated production
assembly. Configuration remains disabled by default, performs no store migration or
pairing, and cannot contact WhatsApp until every rollout prerequisite is satisfied.
The persistent `signet deployment` staging assembly remains downstream-disabled.
`signet provider setup whatsapp` supplies the reviewed Linux x86_64 artifact and
pairing flow described below.

## Exact reviewed invocation

The owned wrapper can pin a resolved, non-symlink `wacli` `0.12.0` executable,
its SHA-256 digest, version, owner, mode, argument grammar, timeout, output bound,
and native executable format. It never invokes a shell.
Production configuration cannot enable script execution; tests use an opaque
in-memory capability that cannot be represented in deployment configuration. The
generic reviewed local-process implementation activates only on Linux with a
mounted `/proc/self/fd`. Every other host fails with
`process_boundary_platform_unsupported` before creating an executable snapshot or
starting a child process.

Guided setup downloads the upstream
`wacli_0.12.0_linux_amd64.tar.gz` release asset and requires archive SHA-256
`49baa180fa7f0f4a694f683b8f7386ea64023ed79c0307037f0680bd21c116e0`.
It extracts exactly one native ELF `wacli` payload into the private setup root,
records the executable digest in configuration, and refuses any digest or archive
layout mismatch. The old macOS Homebrew fixture is not used for this path.

The wrapper does not combine named `--account` selection with the explicit store.
It opens one reviewed store directory without following a symbolic link, verifies
its identity immediately before every spawn, inherits that descriptor, and invokes:

```text
/proc/self/fd/EXECUTABLE_FD --store /proc/self/fd/STORE_FD --json --timeout 15s ...
```

The configured `account` remains the policy and adapter identity. Before every
send, the wrapper runs bounded read-only `accounts list` and `auth status`
preflights through the same descriptor-bound executable/store. It requires one
inventory entry whose name and configured/resolved store exactly match config,
then requires an authenticated `linked_jid` exactly equal to the configured JID.
It still uses `--store` for the send because the `v0.12.0` selection rule forbids
combining `--store` with `--account`.

## Required directory layout

Choose canonical absolute paths owned by the dedicated service user. The runtime
root, HOME, store, and encrypted staging root must already exist with exact mode
`0700`. HOME and store must be distinct direct children of one runtime root. The
staging tree must be disjoint from that runtime root in both directions: neither
path may equal, contain, or be contained by the other.

```text
/ABSOLUTE/PRIVATE/SIGNET/
  wacli-runtime/          mode 0700; parent-only descriptor
    home/                 mode 0700; inherited as cwd and HOME
    store/                mode 0700; inherited as --store
  encrypted-staging/      mode 0700; never inherited by the child
  executable-snapshots/   mode 0700; verified snapshots are unlinked before exec
```

One inert way to prepare empty directories is:

```console
export SIGNET_PRIVATE_ROOT=/ABSOLUTE/PRIVATE/SIGNET
install -d -m 0700 "$SIGNET_PRIVATE_ROOT"
install -d -m 0700 "$SIGNET_PRIVATE_ROOT/wacli-runtime"
install -d -m 0700 "$SIGNET_PRIVATE_ROOT/wacli-runtime/home"
install -d -m 0700 "$SIGNET_PRIVATE_ROOT/wacli-runtime/store"
install -d -m 0700 "$SIGNET_PRIVATE_ROOT/encrypted-staging"
install -d -m 0700 "$SIGNET_PRIVATE_ROOT/executable-snapshots"
```

Do not point HOME at the operator's login home. Doing so would give the reviewed
provider process descriptor access to unrelated files such as SSH, browser, and
agent state. Do not place encrypted staging below HOME, store, or their runtime
root. Signet rechecks all configured directory identities before every spawn and
binds cwd, HOME, and store to inherited descriptors so a last-moment path rename
cannot redirect the child.

For a file send, the parent opens and re-hashes only the approved staged object,
decrypts it into an anonymous file, and inherits that one file descriptor. The
encrypted staging-root descriptor is held and reverified only in the parent; it
is never inherited. Text sends inherit no attachment descriptor.

## Existing linked-device state

Changing HOME or store without a migration makes existing account state disappear
from `wacli`'s view. Before any later human-authorized activation, choose exactly
one path:

1. Re-pair into the new empty reviewed store using the pinned `wacli` build. Pairing
   contacts WhatsApp and is a live, interactive human step that this repository and
   CI never perform.
2. Use a version-specific, reviewed `wacli` store migration while every process
   that can access the source store is stopped. Preserve ownership and private
   modes, reject symbolic links, and validate the migrated store with the pinned
   binary before Signet can reference it. This repository intentionally provides
   no generic copy command or live-store migrator.

Never copy a running SQLite/device store and never fall back to the broad login
HOME merely to recover an old session. The upstream
[`v0.12.0` account documentation](https://github.com/openclaw/wacli/blob/v0.12.0/docs/accounts.md)
describes named stores, explicit `--store` selection, and re-authentication context.

## macOS local-process activation blocker

macOS exposes `/dev/fd`, but it does not provide the reviewed Linux semantics used
here for an unlinked executable snapshot and descriptor-bound `cwd`, HOME, and
store. Signet therefore refuses all reviewed local stdio and `wacli` process
activation on macOS with `process_boundary_platform_unsupported`. CI runs that
fail-closed assertion on macOS together with the portable backup-lock, configuration,
operator-documentation, and inert launchd checks.

The reference macOS deployment can stage the downstream-disabled services and can
later use separately reviewed HTTPS downstreams. It cannot activate a local stdio
provider or `wacli`. Do not work around the block with `/dev/fd`, configured path
names, a still-linked snapshot, a shell, or `preexec_fn`; each would weaken the
reviewed execution or directory-swap boundary. macOS local-process support requires
a separately reviewed native descriptor-exec/chdir implementation and target-host
characterization. On macOS, `must_not_dispatch` remains true and live local-process
activation is blocked. The supported alternative is the guided Linux x86_64 setup
with the pinned archive above; the macOS Homebrew digest cannot be reused.
