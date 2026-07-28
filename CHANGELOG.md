# Changelog

All notable changes to Signet are documented here. Versions follow semantic versioning and
Python package versions follow PEP 440. A version remains `Unreleased` until the exact tag,
artifacts, attestations, and publication have completed.

## [0.1.0] - Unreleased

### Added

- Packaged `signet` command with resumable `signet setup`, read-only planning, status,
  doctor, backup, restore, rollback, and uninstall operations for macOS and Linux.
- Private browser setup and approval application with multiple independently named passkeys
  and TOTP authenticators, recovery controls, and request-bound fresh-factor confirmation.
- Provider-neutral MCP approval gateway, encrypted staged payloads, durable dispatch fencing,
  bounded reconciliation, retention, and honest `outcome_unknown` handling.
- Guided Fastmail and Linux WhatsApp provider setup with disabled-by-default rollout gates,
  exact schema review, credential references, and one explicit test effect.
- Platform-native service definitions, private Tailscale HTTPS setup, multi-profile Hermes
  configuration, storage preflight, backup compatibility, and fail-closed upgrade recovery.
- Reproducible platform wheels and source distribution, CycloneDX runtime SBOM, checksums,
  Sigstore signatures, GitHub provenance/SBOM attestations, and PyPI trusted publishing.

### Security

- Exact stable tag, project version, repository identity, main ancestry, and successful
  exact-commit CI are required before release artifacts can be built.
- Release artifacts are rebuilt byte-for-byte, inspected for the reviewed package contents
  and dependency closure, scanned, signed, attested, and re-verified before publication.
- PyPI publication uses short-lived GitHub OIDC in the protected `pypi` environment; no
  long-lived package index token is accepted by the release workflow.

### Compatibility

- Python `>=3.12,<3.13` and SQLite 3.51.3 or newer.
- Linux x86_64, Linux arm64, and macOS arm64 release wheels.
- Existing schema versions 1 through 20 migrate forward transactionally. Back up before an
  upgrade; rollback requires restoring the verified pre-upgrade data and matching package.

[0.1.0]: https://github.com/bee-san/Signet/releases/tag/v0.1.0
