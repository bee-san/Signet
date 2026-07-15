# MCP Approval Tools

This guide will document the stable schemas and behavior of Signet's gateway-owned
MCP surface:

- `check_approval_status`
- `list_pending_approvals`
- `approve_request`
- `cancel_request`
- `request_tool_access`

The executable v1 schema fixture is in
`spec/fixtures/gateway-tools-schemas.json`. Domain failures use
`CallToolResult(isError=true)` with stable error codes; malformed protocol requests
and unknown tool names use protocol errors.

TODO: add the tested chat flows, receipt and error examples, caller-namespace rules,
and the web-only policy-change flow after the MCP implementation lands.
