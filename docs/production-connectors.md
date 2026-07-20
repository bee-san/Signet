# Production provider connectors

Signet can assemble the reviewed Fastmail MCP and owned `wacli` WhatsApp provider
boundaries, but live dispatch is an explicit, fail-closed cutover. A normal
production config remains provider-disabled:

```json
{
  "capabilities": {"live_providers_ready": false},
  "provider_rollout": {"state": "disabled"}
}
```

Both fields must be changed together. A partial change is rejected before the
database, network, or provider process is touched. Enabling also requires an
exact connector/policy alias inventory, encrypted attachment staging, an
attachment key reference, and all provider-specific prerequisites below.
Generic plugin review never changes these fields and cannot activate this path.

## Shared production boundary

Live clients are process-lifetime sessions shared by the MCP and web/worker
lifespans. Startup initializes each provider before readiness is published and
fails closed if initialization, credential resolution, version verification, or
reviewed schema discovery fails. Fastmail's complete live `initialize` identity
must match the connector `server_identity_digest`, and its complete `tools/list`
entries must match the policy `schema_digest` values exactly. Shutdown closes
every started session in reverse order, including rollback after partial startup.

Connector configuration contains only non-secret references and reviewed
identity digests. `credential_identity_digest` tracks the credential inventory
generation. For HTTP connectors, Signet recomputes it from the resolved credential
material using the deployment capability key before constructing a live client;
rotating material under an unchanged Keychain reference therefore fails closed
until the digest is deliberately updated. Generate the non-secret digest without
printing either secret (replace both references with values from the private
production config):

```console
uv run python -c 'from signet.credential_broker import KeychainSecretStore, SecretReference; from signet.production_connectors import provider_credential_identity_digest as d; s=KeychainSecretStore(); r="keychain://Signet/fastmail"; k="keychain://Signet/capability"; print(d(reference=r, secret=s.get(SecretReference.parse(r)).reveal(), identity_key=s.get(SecretReference.parse(k)).reveal().encode()))'
```

Run that command on the deployment host after each credential rotation, paste only
its 64-character output into `credential_identity_digest`, and re-review the
private config. Fastmail also requires `server_identity_digest` from reviewed
discovery. Fastmail resolves credential material inside the HTTP MCP
authorization boundary. The owned WhatsApp wrapper never receives the referenced
secret: its credential is the descriptor-bound linked-device store, while the
configured identity digest still binds approval payloads and policy.
Exceptions and client representations redact provider details and credential material.

Approval calls remain caller-compatible: the mirrored MCP tool advertises the
Signet `pending_approval` output schema, and the initial call durably returns that
shape. Provider results are available only after confirmed delivery; enabling a
live adapter does not leak the provider's output schema into the optimistic call.

## Fastmail prerequisites

The connector alias must be exactly `fastmail` and use HTTPS MCP. Its policy must
contain:

- `send_email` in `approval` mode with adapter `fastmail.send` and one exact
  account scope;
- `search_email` in reviewed read-only `passthrough` mode, on the same account,
  for bounded reconciliation;
- exact reviewed initialize-identity and schema digests for the complete tool set; and
- the same URL and Keychain reference as the production connector config.

The Fastmail connector must also set `tls_server_certificate` to an absolute,
owner-controlled file containing exactly one reviewed leaf certificate and set
`tls_server_certificate_sha256` to the lowercase SHA-256 of that certificate's
DER form. CA certificates and multi-certificate trust bundles are rejected: the
leaf pin must authenticate before the bearer header can be transmitted. Generate
the digest without printing credential material:

```console
openssl x509 -in /absolute/path/fastmail-server.pem -outform DER | shasum -a 256
```

Certificate rotation is a reviewed config change. Replace the file and digest
together, then re-run the wrong-peer and startup gates before enabling dispatch.

Attachments are read only from an allowed source root, encrypted at rest in the
private staging root, and re-opened and re-hashed at execution time. Missing,
changed, oversized, or unsafe attachments fail before provider dispatch. A crash
or transport loss after dispatch enters `outcome_unknown`; reconciliation uses
only reviewed `search_email` and never converts ambiguity into a blind retry.
Attachment upload failures and cancellations also enter `outcome_unknown` and
persist only bounded attempted/confirmed counts. Filenames and attachment contents
are never included in outcome metadata, and provider effects are never retried blindly.
The production maintenance worker applies the reviewed retention matrix: staged
attachments are purged immediately after success or denial, after 24 hours for
expired or cancelled requests, and after seven days for failures. Sensitive
payload rows are retained for seven days in terminal states; ambiguous outcomes
are not auto-purged.

## WhatsApp prerequisites and host blocker

The connector alias must be exactly `whatsapp` and use one hash-pinned stdio
executable with no configured arguments. `provider_rollout.wacli` supplies a
non-secret account name, exact `linked_jid`, exact expected version, dedicated
HOME, linked-device store, CLI timeout, and output bound. Immediately before each
send, the wrapper requires the read-only account inventory to contain that exact
single account/store and requires `auth status --read-only` to report the exact
linked JID. The connector working directory must be the
private parent shared by HOME and the store, and its `output_limit_bytes` must
equal the owned boundary's `max_output_bytes`; inconsistent or inapplicable
duplicate boundary fields fail startup rather than being ignored. The policy
account must be `account:<wacli-account>`, and every configured `send_text` or
`send_file` route must use that same account.

`send_file` receives only one anonymous descriptor containing decrypted approved
bytes. The child never inherits the encrypted staging tree, arbitrary source
paths, the agent environment, or a shell. A crash, timeout, malformed JSON, or
oversized output is classified as an unknown outcome and is not automatically
retried. WhatsApp has no reviewed remote lookup for reconciliation, so unknown
outcomes remain manual.

The local process boundary activates only on a supported Linux descriptor-exec
host with a separately reviewed native `wacli` artifact. The repository's current
macOS Homebrew artifact has no compatible reviewed host/artifact pair. macOS and
an unreviewed Linux binary therefore fail closed with
`process_boundary_platform_unsupported`; do not bypass that check. See
[`wacli-process-boundary.md`](wacli-process-boundary.md).

## Migration and cutover sequence

1. Keep `provider_rollout.state=disabled` and `live_providers_ready=false` while
   upgrading. Run the normal verified pre-migration backup and database migration.
   The new config fields have defaults and do not activate a connector.
2. Prepare mode-`0700`, owner-only attachment source/staging directories and an
   independent attachment key in the secret broker. Never copy a live WhatsApp
   store; follow the stopped-store migration or explicit re-pair choice in the
   process-boundary guide.
3. Capture the complete live Fastmail schemas using the bounded discovery path,
   review server identity and every raw schema, place the server identity digest
   in connector config, and place the exact tool digests in policy. Review the
   executable identity, version, paths, and digest for any Linux `wacli` artifact.
4. Validate config and policy while both rollout gates are still disabled. Confirm
   connector aliases, transports, account scopes, credential identities, and
   policy bindings are exact.
5. Stop MCP and web/worker processes. Change both gates in one private mode-`0600`
   config update, then start the processes. Startup must reach provider readiness
   without schema drift. If it fails, leave dispatch stopped and inspect only
   redacted diagnostics.
6. Exercise one separately authorized sandbox action and verify durable delivery,
   attachment cleanup, crash-to-unknown behavior, and reconciliation. Production
   provider tests and CI use fakes and must not create provider effects.
7. Remove any former direct provider credential or bypass only after the live
   Signet route has been independently verified and a rollback has been rehearsed.

Rollback is fail-closed: stop services, set `provider_rollout.state=disabled` and
`live_providers_ready=false`, and restart. Pending and unknown requests remain in
SQLite; retain their reviewed connector and policy definitions (and attachment
staging settings, when used) so the non-dispatching reviewer can still render,
deny, or cancel them. Rollback does not expose those adapters to the gateway or
delivery pipeline, never treats requests as delivered, and never retries them.
Restore direct routes or credentials only through a separately reviewed operator
change.

Credential generations, TLS leaf pins, reviewed MCP identities, and the reviewed
wacli binary/version and linked WhatsApp JID rotate through an explicit
compare-and-swap transition. First run
and stop the deployment with the current config in the disabled state shown
above. Prepare a second private config that changes only the reviewed identity
fields, then run the transition while all services remain stopped:

```bash
uv run --frozen python - "$CURRENT_CONFIG" "$NEXT_CONFIG" fastmail <<'PY'
import sys
import time
from pathlib import Path

from signet.db import Database
from signet.production import load_production_config
from signet.production_state import ProductionStateStore

current = load_production_config(Path(sys.argv[1]))
next_config = load_production_config(Path(sys.argv[2]))
state = ProductionStateStore(Database(current.storage.data_dir / "signet.db"))
state.rotate_connector_identity(
    current_config=current,
    next_config=next_config,
    alias=sys.argv[3],
    now=int(time.time()),
)
PY
```

The transition rejects enabled/provider-ready state, stale durable digests, and
changes outside the selected connector's identity fields. Replace the deployed
config with `NEXT_CONFIG` only after the command succeeds; then repeat the
disabled preflight before re-enabling rollout.
