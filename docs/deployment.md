# Deployment guide

Signet runs two separately bound ASGI applications:

```text
Hermes / MCP client
  -> http://127.0.0.1:8789/mcp/<managed-alias>
  -> http://127.0.0.1:8789/mcp/approvals

Human browser
  -> private HTTPS reverse proxy
  -> http://127.0.0.1:8790 authenticated Signet web app
```

The MCP listener is always loopback-only and is never published to a LAN,
tailnet, or public Internet. The web listener is separate and performs its own
password/TOTP or passkey login, server-side session authorization, CSRF checks,
and fresh action confirmation. A proxy supplies TLS and reachability only.

## Current deployment status

This repository ships application components and dependency-injected assembly
functions, but it deliberately does not ship a live deployment factory or
credential-enrollment command. `signet serve-mcp` and `signet serve-web` require an
explicit `module:factory`; creating an ASGI app performs no discovery, credential
lookup, or downstream connection by itself.

Everything under `deploy/` is an inert, secret-free template. The launchd examples
contain nonexistent placeholders and cannot start until a deployment assembly is
reviewed. Nothing in the repository has:

- inspected a live Hermes, Tailscale, Homepage, launchd, Keychain, provider, or
  browser-session configuration;
- enrolled a passkey, password, or TOTP;
- captured or approved live provider schemas;
- installed or started a service;
- changed a Serve/Funnel route or Homepage card;
- replaced a Hermes route or removed a direct credential;
- sent a real email or WhatsApp message.

Those are deferred human-authorized cutover steps. Automated implementation and
CI must remain fake-provider/downstream-disabled.

## Platform requirements

- macOS for the reference launchd/Keychain deployment;
- Python `>=3.12,<3.13` and `uv` for a reproducible environment;
- SQLite `3.51.3` or newer (or a specifically verified fixed backport); startup
  rejects older versions because WAL durability is a security boundary;
- a local filesystem with reliable POSIX locking for the database and staging
  roots; known network filesystems are rejected;
- filesystem ownership that prevents other users from changing the code,
  virtualenv, policy, launchers, database, staging files, and deployment assembly;
- HTTPS at the browser-facing origin and an RP ID that is a registrable/exact host
  accepted by the chosen authenticator;
- an independently managed 32-byte backup encryption key and referenced secrets
  available through the deployment's secret broker, never argv or environment.

The default shared-user deployment does not isolate Signet from malicious code
running as that same user. Use a separate account or host when downstream
credentials must be protected from other local software; see `security-model.md`.

## Build and verify without deploying

From a reviewed checkout:

```console
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run mypy
```

Record the reviewed commit and lockfile. Do not let launchd invoke `uv sync` or an
unpinned package resolver. The staged plists execute the already-created
`.venv/bin/signet` entry point directly.

Before live assembly, verify the local runtime prerequisites without reading
secrets:

```console
uv run python -c 'import sqlite3; print(sqlite3.sqlite_version)'
uv run signet --help
uv run python -m signet.operations --help
```

`Database.initialize()` creates the data parent as `0700`, the SQLite file as
`0600`, verifies migration checksums, sets WAL and `synchronous=FULL`, enables
foreign keys on every connection, and refuses unknown/newer schemas. An upgrade
from an older supported schema requires a verified pre-migration backup callback.

## Deployment assembly responsibilities

Create a small deployment-owned module outside public source control that wires
the reviewed components. It must:

1. construct `Settings` from non-secret values and opaque `keychain://` references;
2. verify `data_dir`, policy, staging, backup, launcher, and log ownership/modes;
3. initialize the database with a verified pre-migration backup callback;
4. resolve high-entropy session, proof-capability, payload, TOTP, VAPID, downstream,
   and backup secrets at their narrow use sites without printing them;
5. persist the Argon2 verifier records for profile-scoped MCP caller tokens and
   load them into `TokenRegistry`; the raw token is returned once and belongs only
   in Hermes' reviewed secret mechanism;
6. load the exact policy and captured schema digests, leaving drifted/unreviewed
   tools disabled;
7. assemble supervised downstream clients and reviewed adapters without connecting
   during module import;
8. assemble `ApprovalStateMachine`, transactional notification outbox, gateway
   tools, alias surfaces, delivery/reconciliation workers, and authenticated web
   backend with the same durable database and proof-capability boundary;
9. provide and test a concrete durable policy-promotion coordinator before enabling
   web policy actions; the core currently exposes only injected boundaries;
10. return one MCP ASGI app from `create_mcp_app()` and one web ASGI app from
   `create_web_app()`;
11. start bounded maintenance workers only inside ASGI lifespan and stop them on
   shutdown;
12. default to disabled/fake downstreams until the explicit cutover flag and every
    readiness prerequisite are independently satisfied.

Do not retrieve secrets at import time, store them in global reprs, add them to
launchd `EnvironmentVariables`, or pass them in process arguments. Ordinary
settings reject literal secret fields. Downstream HTTP configuration accepts HTTPS
or loopback HTTP only; stdio uses an allowlisted argument vector without a shell.

The owned `wacli` launcher must pin the resolved, non-symlink Cellar executable,
its reviewed SHA-256 digest, and an owner/mode that is not group- or world-writable.
Do not configure `/opt/homebrew/bin/wacli`: Homebrew normally exposes that path as
a mutable symlink, and Signet intentionally rejects it. Re-review the resolved path,
version, and digest together after every upgrade.

`TokenRegistry.issue()` is an API, not a shipped enrollment CLI. During the later
human-authorized installation, issue one caller token per Hermes profile with the
exact allowed alias set (for example `fastmail`, `whatsapp`, and `approvals`). Store
the exported Argon2 verifier record in the private deployment state and place the
one-time raw value into Hermes' supported secret interpolation. Do not reuse it
across profiles, confuse it with a provider credential, or expose it to the web
app. Rotation issues a replacement, updates Hermes through a reviewed diff/reload,
then revokes the old token.

### Required web values

For a reference Serve URL such as
`https://signet-host.example-tailnet.ts.net:8443`:

```text
web_host       = 127.0.0.1
web_port       = 8790
public_origin  = https://signet-host.example-tailnet.ts.net:8443
rp_id          = signet-host.example-tailnet.ts.net
allowed_hosts  includes signet-host.example-tailnet.ts.net and loopback hosts
```

`public_origin` includes scheme and non-default port, has no path or trailing
slash, and must exactly match unsafe-request `Origin`. `rp_id` is the hostname only,
with no scheme or port. Passkey enrollment and use must occur at the same reviewed
RP ID/origin. Changing either can make existing credentials unusable and requires
a planned re-enrollment/recovery path.

The web app always emits secure session cookies and HSTS. Direct loopback HTTP is
for proxying and health checks, not human login. Do not weaken cookie or Origin
checks to make an HTTP-only LAN deployment work.

## launchd staging and authorized installation

Two user-agent templates are under `deploy/launchd/`:

- `ai.hermes.signet.mcp.plist.example` binds MCP to `127.0.0.1:8789`;
- `ai.hermes.signet.web.plist.example` binds web to `127.0.0.1:8790`.

Separate processes keep browser routes off the MCP listener. Both templates use
`Umask=077`, background process type, throttled restart, and distinct logs. Their
paths and factory names are placeholders. Do not load a template directly.

During an authorized installation only:

1. Replace every placeholder with an absolute reviewed path and real assembly
   module. Verify no credential value appears in the plist.
2. Create data, staging, backup, and log directories as the service user with mode
   `0700`. Create log files mode `0600`, or verify launchd creates them under the
   restrictive umask.
3. Validate both files:

   ```console
   plutil -lint ./ai.hermes.signet.mcp.plist
   plutil -lint ./ai.hermes.signet.web.plist
   ```

4. Place reviewed user-agent files in `~/Library/LaunchAgents/` mode `0600`.
5. Only after the human authorizes service start, load them with the current macOS
   user domain:

   ```console
   launchctl bootstrap gui/"$(id -u)" \
     "$HOME/Library/LaunchAgents/ai.hermes.signet.mcp.plist"
   launchctl bootstrap gui/"$(id -u)" \
     "$HOME/Library/LaunchAgents/ai.hermes.signet.web.plist"
   ```

6. Inspect `launchctl print gui/"$(id -u)"/ai.hermes.signet.mcp` and the web label,
   then inspect only bounded, privacy-safe startup logs. Repeated restart is a hard
   failure, not a reason to bypass initialization.

To stop without deleting state:

```console
launchctl bootout gui/"$(id -u)"/ai.hermes.signet.web
launchctl bootout gui/"$(id -u)"/ai.hermes.signet.mcp
```

Do not use `kickstart -k` casually; it is a controlled restart and needs explicit
approval when requests may be active. Prefer Hermes' MCP reload mechanism for
client route changes.

Apple's user-agent and `ProgramArguments` model is documented in
[Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

## Health and observability

Local health checks are intentionally static:

```console
curl --fail --silent http://127.0.0.1:8789/healthz
curl --fail --silent http://127.0.0.1:8790/healthz
```

The MCP response contains only `{"status":"ok"}`. The web response adds only the
fixed service name. Neither endpoint reports queue contents, targets, database or
credential paths, policy, downstream connectivity, or user identity. A healthy
process does not prove that credentials, schemas, or providers are ready.

Metrics and logs may include bounded counts, state classes, ages, duration buckets,
safe error codes, reconciliation counts, disk capacity, and schema drift. They must
not include request payloads, full targets, filenames, raw IDs derived from personal
data, bearer tokens, provider results, WebAuthn challenges/assertions, TOTP values,
push endpoints/keys, or Keychain references. Disable framework debug mode and raw
HTTP/MCP body logging.

## Reference: localhost plus Tailscale Serve

Serve provides tailnet-only reachability and TLS. It is not an identity provider
for Signet. The app ignores Tailscale identity headers and still requires its own
login and fresh action confirmation.

The staged packet `deploy/tailscale/serve-merge.md` uses a previously free HTTPS
listener on `8443` and proxies its root to `http://127.0.0.1:8790`. Using a separate
listener avoids subpath rewriting and leaves an existing `443` root handler intact.
It also gives WebAuthn one stable origin.

The authorized merge procedure is:

1. Capture `tailscale serve get-config --all`, Serve status, and Funnel status into
   private change-record files.
2. Confirm that no existing Serve or Funnel handler uses `8443`. If there is a
   conflict, stop; never use `tailscale serve reset` or silently remove it.
3. Confirm local web health, exact `public_origin`/RP ID/Host allowlist, successful
   app login, and rejection of unauthenticated queue access.
4. With explicit approval, add only the free listener:

   ```console
   tailscale serve --bg --https=8443 http://127.0.0.1:8790
   ```

5. Capture status again. Verify prior handlers are unchanged, `8443` is Serve-only,
   Funnel has no selected listener, and the URL is available only inside the
   tailnet.

Exact route rollback removes only this listener:

```console
tailscale serve --https=8443 off
```

Do not routinely restore a whole saved Serve config; doing so can overwrite routes
changed after capture. Tailscale documents the current CLI at
[tailscale serve](https://tailscale.com/docs/reference/tailscale-cli/serve).
[Serve](https://tailscale.com/docs/features/tailscale-serve) is tailnet-only;
[Funnel](https://tailscale.com/docs/features/tailscale-funnel) is public and is not
supported for this MVP.

## Homepage card

`deploy/homepage/services.signet.yaml.example` contains one normal card named
**Signet**. Merge that service into the intended existing group without replacing
`services.yaml`, changing layout, or adding a credential-bearing widget. Copy the
committed raster icon `src/signet/static/icons/signet-1254.png` into Homepage's
mounted `/app/public/icons` directory as `signet.png`, and replace only the reviewed
tailnet hostname.

The card deliberately has no health widget or API key. Homepage's service format
and local icon path are documented in
[Homepage services](https://gethomepage.dev/configs/services/). Adding the card and
reloading Homepage are authorized cutover steps, not repository setup.

## LAN or reverse-proxy alternative

A private LAN deployment uses the same app authentication. Prefer keeping Signet
on `127.0.0.1:8790` behind a local Caddy/nginx listener with a valid private/public
certificate. Binding the web process directly to a LAN address expands the host
firewall and same-network threat surface and still requires HTTPS in front of the
browser origin.

The proxy must:

- terminate modern TLS and redirect plaintext HTTP without forwarding credentials;
- preserve the exact public Host and origin expected by Signet;
- proxy all web/PWA paths, including WebAuthn and push subscription endpoints;
- disable response caching and avoid request/response body logging;
- impose bounded header/body/time limits compatible with Signet;
- not inject or trust a user identity header for application authorization;
- never route `/mcp/*` or port `8789` off-host;
- expose no administrative/debug endpoint and no alternate unauthenticated origin.

Set `public_origin`, `rp_id`, and `allowed_hosts` to the LAN HTTPS name before
enrollment. Test with the proxy temporarily removed that direct access still
requires Signet authentication; only reachability/TLS should change.

Never expose Signet publicly without a new threat review, explicit human decision,
TLS, full application authentication, Internet-grade rate limiting, monitoring,
and recovery procedures. Tailscale Funnel remains disabled.

## Backup and restore

There is currently no `signet backup` shell command. Do not invent one in an ops
script or copy a live WAL database with `cp`. Deployment assembly must call the
tested `BackupBundleManager` API with a 32-byte key resolved outside argv/env.

`BackupBundleManager.create()`:

- uses SQLite's backup API for a consistent snapshot;
- derives attachment rows and key references from that snapshot, not a later live
  view;
- copies each gateway-owned attachment through a verified no-follow descriptor;
- records size/hash metadata and non-secret key references in a manifest;
- archives the snapshot and attachments, then encrypts/authenticates the bundle
  with AES-256-GCM;
- writes a new mode-0600 file via fsync and atomic rename;
- refuses an existing destination and enforces a configured bundle-size bound.

The backup key must be independent of the bundle and recoverable under the site's
key-management policy. A key reference in the manifest is not the key. Losing
payload/downstream/backup keys can make a structurally valid backup unusable.

`BackupBundleManager.restore()` always targets a path that does not exist. It:

1. opens a bounded regular bundle without following symlinks;
2. verifies AES-GCM authentication before extraction;
3. rejects archive traversal, links, duplicate paths, oversized members, and
   unexpected files;
4. verifies the database hash and runs `integrity_check` and `foreign_key_check`;
5. copies attachments under the new restore root, rewrites storage paths in one
   transaction, checkpoints/fsyncs the restored database, and re-verifies every
   attachment;
6. deletes the whole restore destination on any failure;
7. returns a `RestoredBundle` but never activates it.

A backup is operationally accepted only after restoring it into a separate private
path on the intended software version and verifying:

- manifest/schema version and migration checksums;
- database integrity and foreign keys;
- attachment hashes and key-reference availability;
- ability to decrypt representative retained fixture payloads without dispatch;
- queue/state/event/idempotency consistency;
- zero network/provider calls during the drill.

Activation is a separate, human-approved maintenance action. Stop writers, take a
new backup, preserve the failed live tree, and atomically select the verified
restored tree according to deployment-specific procedures. Never overwrite the
only live copy. Never restore a backup that predates a `pending_approval`
acknowledgement still known to a caller; repair forward instead.

Backups can retain data logically purged later. Apply retention and destruction
policy independently to backup generations, APFS snapshots, WAL remnants, and
backup keys. A shared wrapping key does not provide per-request cryptographic
erasure.

## Staged Hermes routing

The redacted examples under `deploy/hermes/` preserve downstream aliases and
replace only their direct transport with local Signet paths:

```yaml
mcp_servers:
  fastmail:
    url: http://127.0.0.1:8789/mcp/fastmail
    headers:
      Authorization: Bearer ${SIGNET_MCP_CALLER_TOKEN}
    sampling:
      enabled: false
  whatsapp:
    url: http://127.0.0.1:8789/mcp/whatsapp
    headers:
      Authorization: Bearer ${SIGNET_MCP_CALLER_TOKEN}
    sampling:
      enabled: false
  signet_approvals:
    url: http://127.0.0.1:8789/mcp/approvals
    headers:
      Authorization: Bearer ${SIGNET_MCP_CALLER_TOKEN}
    sampling:
      enabled: false
```

They are illustrative and have not been generated from a live profile. During
authorized cutover, create timestamped redacted diffs from the current managed
profiles, check that active and disabled profiles have no alternate mutation path,
provision the profile-scoped token through a reviewed secret mechanism, and prefer
`/reload-mcp` or the client's supported MCP reload. A Hermes Gateway
restart needs separate explicit approval.

Do not remove direct credentials before the local aliases, human authentication,
live schema digests, fake providers, backup restore, and rollback packet pass. Do
not leave direct credentials/routes enabled after successful cutover, because they
remain a bypass.

## Deferred human cutover packet

Automation may prepare commands and fake evidence but must not perform, simulate,
or wait on these steps. A human runs them later under an explicit change record:

1. Review and install a deployment assembly with downstreams still disabled.
2. Run an offline bootstrap ceremony to set the fallback password and enroll at
   least one passkey on the intended phone or physical authenticator. This
   repository currently has no enrollment CLI; supply and review that deployment
   procedure before proceeding. Optionally enroll TOTP without exposing its secret
   or any current code to logs/chat.
3. Enroll downstream credentials in the intended Keychain boundary. Store only
   references in policy/configuration.
4. Perform read-only live `tools/list` discovery through an authorized capture
   path, normalize the secret-free fixture offline, review every exact schema and
   digest, and keep sends denied.
5. Run fake-provider end-to-end tests proving zero calls before approval and one
   fenced call only after a test confirmation. No fake confirmation may be
   represented as a real human ceremony.
6. Complete and human-review the metadata-only bypass inventory. Resolve every
   active direct write path and unknown coverage item.
7. Create and verify an encrypted backup plus separate-path restore drill.
8. Review launchd, Serve/Funnel, Homepage, and timestamped Hermes diffs. Run
   `cutover-readiness`; missing evidence produces `disposition=blocked`. Even a
   syntactically complete packet produces `disposition=human_review_required`,
   `ready=false`, and `authorizes_live_changes=false`. The helper is advisory and
   cannot enable cutover.
9. Authorize service startup and the tailnet-only Serve listener. Verify login,
   exact RP/origin behavior, privacy-safe health/push, and that the app remains
   authenticated independent of Tailscale headers.
10. Authorize the Hermes MCP route reload. Do not restart the gateway unless reload
    cannot apply the reviewed change and a separate restart is approved.
11. Run the plan's human self-addressed email and harmless self-WhatsApp approve and
    deny checks. The human supplies real confirmations; implementation workers do
    not click, synthesize assertions, fabricate TOTP values, or send.
12. Verify status receipts, provider effects, approval push, denial no-send, access
    request plus `tools/list_changed`, and unknown-outcome handling.
13. After explicit acceptance, remove obsolete direct credentials and bypass
    routes. Run the inventory again and begin the planned soak.

The blocked examples in `deploy/operations/` intentionally make readiness fail.
Changing `present` to true is not evidence; each entry needs a non-secret reference
to the actual human-reviewed change record, and a human must independently verify
those records. No output of this offline helper authorizes a live operation.

## Rollback

Choose rollback based on what has already happened:

| Situation | Safe response |
| --- | --- |
| Before any pending acknowledgement | Stop staged jobs, remove only the Signet Serve listener, and leave direct routes unchanged. |
| Web proxy problem, MCP healthy | Remove only the Serve listener or repair TLS; keep MCP routes and database. No direct writes. |
| Client route reload failed before activation | Restore the reviewed client config diff; do not touch the Signet database. |
| Binary/config defect after pending acknowledgements | Keep the database, idempotency ledger, staging, and direct routes disabled. Stop dispatch if needed and repair forward with schema-compatible code. |
| Pending/executing/unknown requests exist | Never restore an older database or re-enable direct mutations. Preserve state and reconcile/repair forward. |
| Schema migration failed before acknowledgement | Use the verified pre-migration bundle only if the failure boundary and schema rules prove no acknowledged request would be forgotten. |
| Serve listener conflicts | Run the exact `tailscale serve --https=8443 off`; never reset unrelated handlers. |

Binary rollback is allowed only when the binary supports the current schema.
Configuration rollback must preserve policy versions and must not turn a gated send
into a direct send. A reverse Hermes diff is a last-resort reviewed change, not the
default response to a Signet incident.

After any rollback, rerun static health, database integrity, fake-provider tests,
schema digest comparison, bypass inventory, and readiness. Do not infer safety from
a process merely staying up.
