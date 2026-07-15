# Reversible Hermes route examples

The two diff files show the intended direction without reading or naming any live
profile. They are not guaranteed to match a deployment's Hermes syntax and must
be regenerated against a redacted, current profile during the authorized change.

Forward cutover preserves each downstream alias but routes it to Signet's local
path. The approval tools use their own alias. The MCP listener is never proxied to
the LAN or tailnet.

Every local MCP path still requires bearer authentication. The example uses one
`${SIGNET_MCP_CALLER_TOKEN}` placeholder for a profile-scoped token whose durable
record allows exactly the three shown aliases. The raw token is issued once during
the human-authorized installation and resolved by Hermes' reviewed secret
mechanism; it is never committed to these diffs, ordinary YAML, or logs. A separate
Hermes profile receives a separate token and caller namespace.

Before applying a generated forward diff, require a clean metadata-only bypass
audit, matching reviewed schema digests, fake-provider acceptance, enrolled human
authentication, enrolled downstream credentials, a verified restore drill, and
explicit human authorization. Prefer Hermes' MCP reload mechanism. A gateway
restart is disruptive and requires separate approval.

The reverse example exists for review completeness, not as a default rollback.
Once Signet has acknowledged a pending request, restoring a database or direct
route that forgets it can strand the caller's `request_id`. Preserve the database
and idempotency ledger; repair forward unless the reverse-route preconditions are
independently satisfied.
