# Provider-neutral MCP client integration

Signet exposes streamable-HTTP MCP servers on numeric loopback. This guide maps
those servers into any agent that supports streamable HTTP plus fixed request
headers. Client configuration field names differ, so the mapping below is
illustrative rather than a file to paste into an unknown agent.

The shipped runnable choices are intentionally limited:

| Assembly | Available aliases | Effect boundary |
| --- | --- | --- |
| Fake demo | `fastmail`, `whatsapp`, `approvals` | In-process fake providers only |
| Persistent disabled staging | `approvals` only | Every tool call returns `deployment_disabled` |
| Packaged production | `approvals` plus configured providers | Guided Fastmail or Linux x86_64 WhatsApp setup |

Neither the fake demo nor disabled staging can be switched to a live provider by
changing a client route. Start and verify the fake assembly with the
[operator runbook](operator-runbook.md), or create the persistent disabled state
with the [deployment guide](deployment.md). For a packaged installation, use
[`signet setup` followed by `signet provider setup`](setup.md); the client route
alone never activates a provider.

## Route mapping

Configure one client-local MCP server for each exact Signet alias the caller is
allowed to use. With the default fake-demo port, the conceptual mapping is:

```yaml
# Illustrative only: translate these fields into the selected agent's schema.
servers:
  signet_fastmail:
    transport: streamable-http
    url: http://127.0.0.1:8789/mcp/fastmail
    headers:
      Authorization: "Bearer ${SIGNET_MCP_CALLER_TOKEN}"
  signet_whatsapp:
    transport: streamable-http
    url: http://127.0.0.1:8789/mcp/whatsapp
    headers:
      Authorization: "Bearer ${SIGNET_MCP_CALLER_TOKEN}"
  signet_approvals:
    transport: streamable-http
    url: http://127.0.0.1:8789/mcp/approvals
    headers:
      Authorization: "Bearer ${SIGNET_MCP_CALLER_TOKEN}"
```

Use `127.0.0.1`, the configured port, and the exact path with no trailing slash.
Never bind, proxy, tunnel, or publish the MCP listener to a LAN, tailnet, container
network, or public interface. The separately authenticated web application is the
only browser-facing surface.

`signet_fastmail`, `signet_whatsapp`, and `signet_approvals` above are client-local
server names. Signet owns the route aliases and the base tool names returned by
`tools/list`. An agent may display a tool as `<server>.<tool>`,
`mcp_<server>_<tool>`, or another client-specific prefix. Do not put that display
prefix into a Signet policy or request. For example, Hermes renders
`send_email` from client server `signet_demo_fastmail` as
`mcp_signet_demo_fastmail_send_email`; the executable Signet tool name remains
`send_email`.

## Bearer-token boundary

Each agent profile needs its own random Signet token, caller namespace, and exact
alias grant. Do not reuse a token across profiles or users. Store the raw token in
the agent's private secret mechanism and leave only a variable/secret reference in
its normal configuration. `${SIGNET_MCP_CALLER_TOKEN}` above is a placeholder; its
interpolation syntax is client-specific.

For the fake demo, the `mcp-token` field from `signet demo credentials` returns one
visibly fake token for the exact `--data-dir` demo namespace. For persistent disabled
staging, `signet deployment token issue` prints one real random token exactly once;
the deployment guide pipes it directly into the reviewed Hermes configurator. A
different client needs an equally reviewed stdin or secret-broker ingestion path
before token issue.
If the client accepts only a literal token in ordinary JSON/YAML, argv, or a global
process environment, do not use that client with a non-fake Signet token.

Never place the raw value in a URL, query string, prompt, checked-in file, shell
history, ticket, chat, screenshot, or body log. Disable client debug logging that
records request headers or MCP bodies. The client must not forward `Authorization`
across a redirect; the exact Signet routes do not require redirects. Token listing
returns metadata only. Revocation takes effect on the next authentication check;
rotation should install and test a linked replacement before the old token is
explicitly revoked.

## Discovery and client controls

Run authenticated `tools/list` independently for every configured server. The
default fake demo currently exposes 4 Fastmail tools, 3 WhatsApp tools, and 4
approval tools. Disabled staging exposes the 5 normative approval tools. Stop on an
unexpected server, tool set, schema, URL, or authentication result; do not weaken
authentication to make discovery pass.

Where the client supports these controls, configure:

- no parallel consequential tool calls to one Signet surface;
- MCP resources and prompts disabled for these tool-only routes;
- MCP sampling disabled;
- a bounded connection timeout and a tool timeout long enough to receive the
  durable pending acknowledgement.

A client timeout or disconnected response does not prove that no durable request
was created. Use the caller-scoped approval tools to list and identify pending work
before considering another consequential call.

## Pending and status lifecycle

An `approval`-mode downstream call returns a durable acknowledgement shaped like:

```json
{
  "status": "pending_approval",
  "request_id": "req_RECORDED_ID",
  "expires_at": "2026-07-22T09:00:00Z",
  "message": "This action requires human approval. Check status with check_approval_status."
}
```

This means the exact request is frozen and unsent. It does not mean the provider
action succeeded. The agent must retain `request_id`, present the result without
rewriting it, and make this conceptual tool call on the `approvals` server through
its normal MCP client API:

```json
{"name":"check_approval_status","arguments":{"request_id":"req_RECORDED_ID"}}
```

The wrapper above is not raw JSON-RPC; the selected MCP SDK constructs the
`tools/call` envelope and session metadata.

Treat `approved` and `executing` as nonterminal. Continue bounded status checks until
`succeeded`, `failed`, `outcome_unknown`, `denied`, `expired`, or `cancelled`.
Never automatically resubmit after `outcome_unknown`; an external effect may have
occurred. `list_pending_approvals` is the recovery path for caller-owned pending
requests when an acknowledgement was lost, and `cancel_request` can cancel only an
eligible pending request.

The authenticated web queue is the normal full-context decision surface. The fake
demo intentionally omits MCP `approve_request`; approve or deny there only through
the fake authenticated web form and its explicit fake action proof. A future live
assembly may expose MCP TOTP approval, but the human must supply a fresh current code
for the exact request and version. An agent must never invent, retain, replay, or ask
a model to fabricate an authentication proof.

The complete schemas, result meanings, pagination contract, and stable error codes
are in [MCP approval tools](mcp-approval-tools.md). Approval UI authentication,
network boundaries, and bypass limitations are in the
[security model](security-model.md).

## Acceptance checklist

Before enabling a client profile, verify all of the following:

- every URL is exact numeric loopback and every configured alias is intended;
- the token belongs to one caller namespace and only fixed Signet aliases are staged;
- unauthenticated MCP access returns `401` and authenticated discovery matches the
  reviewed schemas;
- the client does not expose headers, full tool arguments, or results in debug logs;
- one fake consequential call returns `pending_approval` with zero provider calls;
- denial produces no provider call, while an approved fake call reaches one bounded
  fake effect and a terminal status;
- the agent treats `pending_approval`, `approved`, `executing`, and
  `outcome_unknown` according to the lifecycle above;
- no direct provider MCP route or credential remains available as a bypass.

Passing this checklist against the fake or disabled assembly does not authorize live
provider credentials, human enrollment, proxy changes, service installation, or
cutover.
