# Signet

Signet is a provider-neutral MCP approval gateway. Configured write tools return an
honest `pending_approval` result after their exact payload has been durably queued.
The downstream action remains unsent until a human confirms it.

The repository is under active implementation. It defaults to fake or disabled
downstreams and must not be pointed at live send credentials yet.

## Development

Signet pins Python 3.12 and uses `uv` for dependency and environment management.

```console
uv lock
uv sync --frozen
uv run pytest -q
```

The planned service has two separate surfaces:

- Agent-facing MCP endpoints on `127.0.0.1:8789/mcp/<alias>` and
  `127.0.0.1:8789/mcp/approvals`.
- A separately bound, authenticated web application for full-content review and
  human confirmation.

No setup command changes Hermes configuration, starts a launchd service, enrolls a
credential, accepts a TOTP code, or sends a real message.

## Layout

- `spec/` contains the reviewed policy and executable JSON fixtures.
- `src/signet/` contains the gateway package and provider adapters.
- `tests/` contains contract and implementation tests.
- `docs/` contains the approval-tool, security, policy, and deployment guides.

The normative implementation plan is
`2026-07-14-signet-approval-gateway-plan.md`.
