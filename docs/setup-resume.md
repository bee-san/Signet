# Resume or reverse setup

`signet setup` is journaled and resumable. Repeating the same command does not replay
completed automatic steps, duplicate factors, overwrite foreign files, or silently
adopt changed state.

## Resume the normal flow

1. Inspect the saved state. Both commands are **read-only**:

   ```console
   signet status
   signet doctor
   ```

2. Correct the reported prerequisite, such as Tailscale login, storage headroom, an
   unavailable keyring, a profile permission, or a service conflict.
3. Run the same setup command again:

   ```console
   signet setup
   ```

If you selected explicit options on the first run, repeat the same root, origin,
owner, profile set, policy, and storage roots. Signet refuses a conflicting
specification rather than rewriting the journal.

A separately reviewed `signet setup --plan` prints an exact command ending in
`--apply` and a 64-character plan ID. Run that exact emitted command. Do not type the
word `PLAN_ID` literally and do not reuse an ID after any bound observation changes.

## Resume the browser ceremony

The CLI prints the non-secret owner setup URL and the path of a private capability
file. The capability itself is not in the URL and expires after ten minutes.

- Reload the same exact HTTPS `/setup` address in the browser that began the ceremony.
- Password and completed authenticator enrollment progress is durable across reloads
  and service restarts.
- If the capability expired, rerun the same `signet setup` command. Signet issues a
  replacement without recreating completed resources or enrolled factors.
- If automatic browser opening is unavailable, run:

  ```console
  signet setup --no-open-browser
  ```

  Then open only the printed URL on a device in the same tailnet.

**Human-only:** read the capability from its private file and enter it only in the
Signet setup form at the reviewed final origin. Never place it in a URL, argument,
YAML, history, ticket, screenshot, or chat.

A cancelled or expired passkey/TOTP challenge does not cancel the overall setup.
Start that authenticator ceremony again from the resumed page. Do not reuse a TOTP
manual key from an abandoned enrollment.

## Interrupted lifecycle operation

`status` includes the current lifecycle operation and its plan ID. Correct the
reported condition, then rerun only the exact prior apply command. Backup, restore,
upgrade, uninstall, and service operations all reject changed targets or foreign
receipts.

Do not delete lock files, journals, markers, plans, or recovery receipts to force a
retry. They are the evidence that makes retry and recovery safe.

## Reverse an incomplete setup

Use rollback only when you intend to remove setup-owned resources:

```console
signet setup --rollback
```

**Human-only and destructive:** review the prompt. Rollback removes only marker-bound
objects in reverse order. For a completed setup it first creates and verifies an
encrypted backup. It is resumable after an independent cleanup step fails. Prefer
[normal uninstall](uninstall.md) for an installed service and read
[upgrade rollback boundaries](upgrade-and-rollback.md) before any version rollback.

## Exit status

- `0`: the requested read-only operation, plan, or apply completed.
- `1`: `doctor` completed and found an unhealthy required check.
- `2`: invalid input, declined confirmation, safety refusal, conflict, or incomplete
  work.

After any interrupted process, trust the exit status plus `signet status`, not partial
terminal output.
