# Signet documentation

Start with the package workflow. The expert contracts and source-checkout runbook are
available for audits and development, but they are not prerequisites for a normal
installation.

## First installation

1. [Install and first setup](setup.md)
2. [Resume interrupted setup](setup-resume.md)
3. [Connect and review a provider](provider-setup.md)
4. [Read status and doctor results](health-and-doctor.md)
5. [Understand the user-facing security model](security.md)

## Routine operation

- [Status and doctor](health-and-doctor.md)
- [Backup and restore](backup-and-restore.md)
- [Upgrade and safe rollback boundaries](upgrade-and-rollback.md)
- [Low disk and external state roots](storage.md)
- [Uninstall or purge](uninstall.md)
- [Troubleshooting](troubleshooting.md)

## Account safety

- [Named passkeys and TOTP authenticators](authenticator-management.md)
- [Lost authenticators and recovery](recovery.md)
- [Full security model](security-model.md)
- [Production authentication contract](reviews/02-security-contract.md)

## Labels used in these guides

- **Read-only**: inspects state and must not mutate it.
- **Plan**: records observations and prints an exact `plan_id`; it does not apply the
  operation.
- **Apply**: mutates only the objects bound by the reviewed plan.
- **Human-only**: requires the intended person to inspect or authenticate. Do not
  automate, delegate to an agent, or paste the ceremony material into chat.
- **Live provider effect**: can contact a real provider. Provider setup deliberately
  performs one attended test message; a later approved request can perform the frozen
  provider mutation.

No guide asks you to put a provider token, caller token, passkey, TOTP seed, owner
capability, or recovery key in YAML, an argument, shell history, logs, or chat.

## Expert and contributor references

- [Expert operator runbook](operator-runbook.md)
- [Production runtime contract](production-runtime.md)
- [Production connector boundary](production-connectors.md)
- [Policy guide](policy-guide.md)
- [MCP client integration](mcp-client-integration.md)
- [Plugin integration contract](plugin-integrations.md)
- [Plugin readiness boundary](plugin-readiness.md)
- [Deployment and threat-review material](deployment.md)
- [Production platform lifecycle matrix](platform-lifecycle-matrix.md)
- [Release procedure](releasing.md)
