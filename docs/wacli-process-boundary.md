# Reviewed wacli process boundary

This document describes a deferred live-assembly contract. The repository does
not ship or activate a live WhatsApp downstream, migrate a linked-device store,
pair a device, contact WhatsApp, or send a message. The persistent deployment
assembly remains downstream-disabled.

## Exact reviewed invocation

The owned wrapper pins the resolved, non-symlink Homebrew Cellar executable for
`wacli` `0.12.0`, its SHA-256 digest, version, owner, mode, argument grammar,
timeout, output bound, and native executable format. It never invokes a shell.
Production configuration cannot enable script execution; tests use an opaque
in-memory capability that cannot be represented in deployment configuration.

The wrapper does not use a named `--account` lookup. It opens one reviewed store
directory without following a symbolic link, verifies its identity immediately
before every spawn, inherits that descriptor, and invokes:

```text
/dev/fd/EXECUTABLE_FD --store /dev/fd/STORE_FD --json --timeout 15s ...
```

On Linux the descriptor prefix is `/proc/self/fd`; on macOS it is `/dev/fd`.
The configured `account` remains the policy and adapter identity. It is not a
second filesystem lookup. This matches the `v0.12.0` selection rule that
`--store` chooses one exact store and cannot be combined with `--account`.

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

## macOS characterization gate

CI runs the process-boundary and inert launchd tests on macOS using repository-owned
fake executables. That proves Signet's `/dev/fd` cwd, HOME, store, executable, and
swap-race behavior on the runner. It does not prove that the pinned Homebrew
`wacli` `0.12.0` binary accepts the directory-descriptor store for every reviewed
command on the target host.

Before a live assembly can be proposed, a human must record the exact target macOS
version, resolved Cellar path, SHA-256 digest, `wacli version`, and successful
descriptor-store characterization for version preflight and the exact send command
shapes. Any real pairing or send remains a separate explicit authorization. Until
that evidence exists, `must_not_dispatch` remains true and live activation is
blocked.
