# Security and approval semantics

Signet places a durable, authenticated human-approval boundary in selected MCP routes.
It does not make the whole host, Hermes, or provider account trusted.

## What a transparent approval means

Packaged provider sends use transparent `approval`:

1. Signet validates the caller namespace, exact captured schema, policy version, and
   request arguments.
2. It encrypts and durably records the frozen request.
3. The agent receives `pending_approval` with a request ID and expiry. This is not a
   provider success response.
4. A human signs in at the private HTTPS origin, reviews the complete effect, and uses
   a fresh selected passkey or TOTP factor for one exact request version and payload.
5. Only then may a fenced worker call the provider. Ambiguous delivery becomes
   `outcome_unknown`, never an automatic blind retry.

Deny, edit, cancellation, policy changes, and credential management have their own
fresh-confirmation boundaries. Login alone does not authorize a mutation.

## Transparent, optimistic, and local virtualization are different

- `approval` is transparent: the caller sees `pending_approval` and knows the provider
  action has not happened.
- `approval_optimistic` is a conditional architecture contract. After durable queueing
  it may return a captured upstream-compatible success-shaped acknowledgement while
  the real mutation remains pending. It is valid only for a reviewed low-risk leaf
  communication tool when exact output compatibility is proven. It is not selectable
  in packaged 0.1 provider setup.
- `virtualize_local` performs bounded local staging and has no provider effect.
- `passthrough` calls a reviewed read-only tool directly.
- `deny` exposes no callable tool. Unknown tools deny.

Never describe transparent pending as optimistic success. Dangerous, unknown,
dependency-heavy, or output-incompatible actions must deny or use transparent
approval. The [policy guide](policy-guide.md) contains the exact expert schema.

## Live-effect boundaries

- `signet setup`, status, doctor, planning, and authenticator management do not perform
  provider mutations.
- `signet provider setup` is **human-only and live**: it performs one attended test
  message before enabling rollout.
- An approved send is live. The web review must show the frozen recipients/account,
  content, attachments, version, and expiry.
- Provider disable blocks new dispatch but does not erase prior or uncertain effects.
- Direct provider scripts, browser sessions, webhooks, native integrations, and old
  Hermes routes bypass Signet.

## Authentication and recovery

One user may own multiple independent named TOTP factors and multiple named passkeys.
A TOTP seed copied to two devices is still one secret, not two recovery factors.
Adding, changing, and removing factors requires a fresh existing factor. Signet blocks
removal of the final active owner factor, and version 0.1 has no self-service final
factor bypass. See [Lost authenticators and recovery](recovery.md).

## Private transport and secrets

The MCP and web services listen on loopback. Tailscale Serve exposes the web origin on
the reviewed private HTTPS 8443 listener; Funnel is refused. Provider and caller
credentials are stored as operating-system keyring references, not plaintext config.
Owner capabilities and TOTP enrollment keys are human-only ceremony material.

Do not put any token, factor seed, capability, recovery key, or decrypted request in
arguments, YAML, history, logs, screenshots, tickets, or chat.

## Same-UID and host limitation

Signet does not claim protection from malicious code running as the same
operating-system user. Such a process may access that user's files, memory, keyring
requests, browser session, writable configuration, or direct provider routes. Use a
separate operating-system account or host, restrictive ACLs, and an independently
authenticated boundary when that threat matters.

Backups and restore do not erase this limitation. A database rollback can also forget
caller-visible pending acknowledgements or provider evidence, so unsafe rollback must
repair forward. Read the [full security model](security-model.md) for trust boundaries,
cryptographic details, bypass closure, reconciliation, retention, and incident rules.
