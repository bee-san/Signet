# Security policy

Signet is security-sensitive software. The checked-in demo is fake-only; it is not
authorization to connect live accounts or provider credentials.

## Supported versions

The latest `0.1.x` stable release receives security fixes. Prereleases, older patch
releases, source snapshots, and independently rebuilt artifacts are unsupported.
Verify release checksums, Sigstore identity, and GitHub attestations using
[`docs/releasing.md`](docs/releasing.md) before installation.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/bee-san/Signet/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include the affected commit, a minimal reproduction using fake data, the expected
security boundary, and the observed result. Do not include live request content,
credentials, tokens, assertions, authenticator values, provider identifiers, or
private filenames.

Until a report is resolved, keep the affected route disabled and preserve relevant
redacted audit events. A stable package version does not extend Signet's boundary to
same-UID processes or provider paths that bypass the gateway.
