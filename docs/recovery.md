# Lost authenticators and recovery

Signet intentionally has no self-service bypass for a lost final authenticator. A
password alone cannot replace the required surviving factor. Prepare recovery before
a device is lost.

## Prepare before loss

After initial owner setup, open the exact private management URL:

```console
signet authenticators open
```

**Human-only:** enroll at least two independently usable factors when possible. A
single user may hold multiple named passkeys and multiple named TOTP authenticators.
Each TOTP enrollment creates its own secret and record; scanning one seed onto several
devices does not create independent factors.

Use labels that identify the device without exposing a credential. Verify the new
factor before relying on it. Adding, renaming, or removing a factor requires fresh
confirmation from one selected existing factor and signs out existing browser
sessions. Signet blocks removal of the final active owner authenticator.

Keep host/keyring recovery and tested encrypted backups separate from the devices that
hold authentication factors. A database bundle alone does not contain all required
secret material.

## One device is lost, another factor survives

1. Sign in at the exact private HTTPS origin with a surviving factor.
2. Run `signet authenticators open` on the owner host if you need the canonical URL.
3. **Human-only:** add and verify a replacement factor first when needed.
4. Mark the lost factor compromised and remove it using a fresh surviving-factor
   confirmation.
5. Review sessions and the audit trail, then create a new verified backup.

Do not rename the lost factor as a substitute for revocation. Do not clone an existing
TOTP seed to create the replacement.

## No factor survives

Stop and contact the deployment operator through an independently authenticated
channel. Version 0.1 exposes no browser or CLI command that bypasses the final-factor
floor, reopens bootstrap, or turns the password into a recovery factor. Repeated login
or setup attempts do not make recovery safer.

An operator-controlled backend break-glass capability exists only as an expert policy
hook and is disabled by default. Enabling it requires a separately reviewed external
identity-recovery procedure, explicit audit, and last-owner protection. Do not edit the
database, generated configuration, factor flags, or keyring records by hand.

Restoring an old backup is not an authentication reset. It can lose pending approvals,
dispatch evidence, provider outcomes, factor counters, and later factor revocations.
Preserve the current installation and follow an incident-specific reviewed procedure.

## Suspected host or same-UID compromise

A malicious process running as the same operating-system user may be able to read or
alter that user's files, memory, keyring access, browser session, or direct provider
routes. Factor revocation inside the possibly compromised account is not a complete
response. Disable provider rollout if safely possible, preserve evidence, rotate
provider credentials from a trusted device, and rebuild on a separate trusted account
or host. See [Security and approval semantics](security.md) and the
[expert security model](security-model.md).
