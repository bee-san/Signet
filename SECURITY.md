# Security policy

Signet is pre-alpha security-sensitive software. The checked-in demo is fake-only;
it is not authorization to connect live accounts or provider credentials.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/bee-san/Signet/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include the affected commit, a minimal reproduction using fake data, the expected
security boundary, and the observed result. Do not include live request content,
credentials, tokens, assertions, authenticator values, provider identifiers, or
private filenames.

No version currently carries a production-readiness guarantee. Until a report is
resolved, keep the affected route disabled and preserve relevant redacted audit
events.
