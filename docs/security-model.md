# Security Model

Signet protects managed MCP routes from accidental, autonomous, or
policy-disallowed writes. In shared-user mode it is not a hard boundary against a
malicious process with the same operating-system account. A separate account or
host is the future hard boundary.

The authoritative approval record is the authenticated web event timeline. A push
notification is the out-of-band signal for approval through chat. WebAuthn stays
web-only. TOTP approval is single-use and bound to one request version, but the
chat transport retains the documented request-swap and code-pretext risks. Policy
changes are therefore web-approval-only.

TODO: expand the threat actors, trust domains, WebAuthn guarantees, TOTP limits,
privacy retention, same-user residual risk, and tested mitigations.
