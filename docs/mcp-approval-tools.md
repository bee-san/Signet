# MCP approval tools

Signet exposes one gateway-owned surface at `/mcp/approvals` in addition to each
managed downstream alias. The five tools on this surface report real durable state
and never manufacture provider success. Their executable source is
`GATEWAY_TOOL_DEFINITIONS` in `src/signet/gateway_tools.py`; the matching normative
fixture is `spec/fixtures/gateway-tools-schemas.json`.

Every call is scoped to an authenticated caller namespace. Listing returns only
that namespace's pending requests. Looking up, approving, or cancelling an unknown
request and a foreign request produces the same `request_not_found` result, so the
surface does not reveal whether another namespace owns an ID.

## Wire conventions

A successful tool call has MCP text content and matching `structuredContent`, with
`isError: false`. A domain rejection is still an MCP `CallToolResult`, but has
`isError: true` and this structured shape:

```json
{
  "error": {
    "code": "stable_machine_code",
    "message": "Human-readable explanation.",
    "details": {}
  }
}
```

`details` is omitted when empty. Unknown tool names, non-object arguments, and
arguments that fail the advertised JSON Schema are MCP protocol errors with
`INVALID_PARAMS`; they are not domain results. Callers must inspect `isError`, not
parse prose. A successful `approve_request` means the durable request is approved
and an approval notification is queued. It does **not** mean dispatch or provider
delivery has succeeded; follow with `check_approval_status`.

## Gated-tool acknowledgement

An `approval`-mode downstream tool replaces the provider output schema with this
exact output schema:

```json
{
  "$id": "https://signet.local/schemas/pending-result-v1.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["status", "request_id", "expires_at", "message"],
  "properties": {
    "status": {"const": "pending_approval"},
    "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
    "expires_at": {"type": "string", "format": "date-time"},
    "message": {"type": "string", "minLength": 1}
  }
}
```

Example fixture:

```json
{
  "status": "pending_approval",
  "request_id": "req_01J00000000000000000000000",
  "expires_at": "2026-07-22T09:00:00Z",
  "message": "This action requires human approval. Check status with check_approval_status."
}
```

The result is emitted only after Signet durably commits the frozen request and
the byte-identical acknowledgement. `pending_approval` explicitly means unsent.
Later MCP connection loss or protocol cancellation does not cancel this completed
request. Use `cancel_request` or the authenticated web app while it is pending.

## `check_approval_status`

Returns authoritative state for one caller-owned request. Result metadata is a
reviewed adapter projection and never a raw provider response.

```json
{
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["request_id"],
    "properties": {
      "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"}
    }
  },
  "outputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["request_id", "status", "version", "expires_at"],
    "properties": {
      "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
      "status": {
        "enum": [
          "pending_approval", "approved", "executing", "succeeded",
          "failed", "outcome_unknown", "denied", "expired", "cancelled"
        ]
      },
      "version": {"type": "integer", "minimum": 1},
      "expires_at": {"type": "string", "format": "date-time"},
      "safe_result_metadata": {"type": "object"},
      "failure_code": {"type": "string", "minLength": 1}
    }
  }
}
```

`safe_result_metadata` and `failure_code` are optional. Treat
`outcome_unknown` as a prominent unresolved state: an external effect may have
occurred, so the caller must not resubmit blindly. Signet performs only the
adapter's bounded read-only reconciliation and, where a reviewed stable provider
idempotency key exists, at most one proven-safe redispatch after confirmed no
effect.

## `list_pending_approvals`

Returns masked summaries of unexpired pending requests in the caller namespace.
It never returns message bodies, full targets, attachments, or credentials.

```json
{
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "maxProperties": 0
  },
  "outputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["requests"],
    "properties": {
      "requests": {
        "type": "array",
        "items": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "request_id", "service", "tool", "destination_summary",
            "age_seconds", "expires_at", "version_hash_prefix"
          ],
          "properties": {
            "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
            "service": {"type": "string", "minLength": 1},
            "tool": {"type": "string", "minLength": 1},
            "destination_summary": {"type": "string", "minLength": 1},
            "age_seconds": {"type": "integer", "minimum": 0},
            "expires_at": {"type": "string", "format": "date-time"},
            "version_hash_prefix": {
              "type": "string", "pattern": "^[a-f0-9]{8,64}$"
            }
          }
        }
      }
    }
  }
}
```

The version hash prefix is the review binding for chat approval. An edit creates a
new immutable version and hash; callers must list again rather than reuse a stale
prefix.

## `approve_request`

Approves one exact normal request with a current, human-supplied TOTP code. The
code must be six ASCII digits, is verified under the same durable rate-limit and
lockout ledger as web TOTP, and is consumed with the approval transition. Signet
binds the proof to caller user, namespace source, request ID, version, payload hash,
MCP path, and one attempt. A code cannot authorize two actions.

```json
{
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["request_id", "totp_code", "expected_version_hash"],
    "properties": {
      "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
      "totp_code": {"type": "string", "pattern": "^[0-9]{6}$"},
      "expected_version_hash": {
        "type": "string", "pattern": "^[a-f0-9]{8,64}$"
      }
    }
  },
  "outputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": [
      "status", "request_id", "tool", "destination_summary", "version",
      "version_hash_prefix", "approval_notification_queued"
    ],
    "properties": {
      "status": {"const": "approved"},
      "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
      "tool": {"type": "string", "minLength": 1},
      "destination_summary": {"type": "string", "minLength": 1},
      "version": {"type": "integer", "minimum": 1},
      "version_hash_prefix": {
        "type": "string", "pattern": "^[a-f0-9]{8,64}$"
      },
      "approval_notification_queued": {"const": true}
    }
  }
}
```

`expected_version_hash` may be the advertised 8-to-64 character lowercase prefix.
The response echoes the reviewed tool, masked destination summary, version, and
hash prefix. Confirm that echo before treating the approval as intended. The web
timeline is authoritative; the echo is trustworthy only if the chat client renders
the actual tool result without model rewriting.

### TOTP-in-chat flow

The following is a protocol transcript. `USER_SUPPLIED_CURRENT_CODE` is a runtime
value typed by the human and relayed verbatim; it is deliberately not a sample
code and must never be fabricated, logged, saved, guessed, or replayed.

1. Human: "What is waiting for my approval?"
2. AI calls `list_pending_approvals({})`.
3. Tool result includes `req_01J000...`, `send_email`, masked destination
   `a***@example.test`, and version hash prefix `4f82c119a0d3`.
4. AI repeats that masked summary and hash prefix. It does not request approval for
   a different request or claim that a send already happened.
5. Human: "Approve `req_01J000...`, hash `4f82c119a0d3`. My current code is
   `USER_SUPPLIED_CURRENT_CODE`."
6. AI immediately invokes the following conceptual call, substituting the exact
   human-entered digits only at call time:

   ```text
   approve_request(
     request_id="req_01J00000000000000000000000",
     totp_code=USER_SUPPLIED_CURRENT_CODE,
     expected_version_hash="4f82c119a0d3"
   )
   ```

7. The real tool receipt must echo the same request, tool, destination summary,
   version, and hash prefix, with `status=approved`. A privacy-safe push says only
   that an action was approved via chat; it does not say it was sent.
8. AI calls `check_approval_status` until it sees `succeeded`, a definite failure,
   or `outcome_unknown`. It never converts `approved` into "sent."

Prefer the web app whenever the displayed target or content needs full inspection.
A person should not provide a code in response to a vague pretext such as "security
check" or "unlock access"; the AI must first identify the exact pending request and
version. See the swap-risk analysis in `security-model.md`.

## `cancel_request`

Cancels only the caller's own request while it is still `pending_approval`. This is
the one code-free MCP state change. It is audited and cannot cancel execution after
the durable dispatch boundary.

```json
{
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["request_id"],
    "properties": {
      "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"}
    }
  },
  "outputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["status", "request_id"],
    "properties": {
      "status": {"const": "cancelled"},
      "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"}
    }
  }
}
```

Denial is intentionally absent from MCP. Denial, editing, human cancellation,
manual recovery, and credential management use the authenticated web app with a
fresh action confirmation.

## `request_tool_access`

Creates a gateway-internal approval request for a durable policy change. Creating
the request does not enable the tool. Approval is web-only. The authenticated web
backend accepts a fresh passkey or TOTP confirmation; the visible "always" shortcut
buttons currently start the passkey flow, while the request's authenticator fallback
can approve the bound proposal with TOTP. A communication send or a tool without a
reviewed read-only classification can never be promoted to `passthrough`.

```json
{
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["alias", "tool", "reason"],
    "properties": {
      "alias": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$"},
      "tool": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_.-]{0,127}$"},
      "reason": {"type": "string", "minLength": 1, "maxLength": 1000}
    }
  },
  "outputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": [
      "status", "request_id", "expires_at", "message", "approval_channel"
    ],
    "properties": {
      "status": {"const": "pending_approval"},
      "request_id": {"type": "string", "pattern": "^req_[A-Za-z0-9]+$"},
      "expires_at": {"type": "string", "format": "date-time"},
      "message": {"type": "string", "minLength": 1},
      "approval_channel": {"const": "web_only"}
    }
  }
}
```

Example flow:

1. AI calls `request_tool_access(alias="calendar", tool="list_events",
   reason="Read the next appointment")`.
2. Signet returns an honest pending result with `approval_channel="web_only"`.
3. The user opens the private queue, inspects the captured schema and proposed
   mode, and confirms the exact policy change with a fresh web passkey or TOTP proof.
4. The shipped `SQLitePolicyPromotionBoundary`, when explicitly injected with the
   deployment's policy path, shared engine/mirror, and publication callback,
   durably records the policy version and publishes
   `notifications/tools/list_changed` to affected MCP sessions. A deployment must
   keep policy approval disabled until that exact wiring and its human proof paths
   are reviewed; the class existing in the repository is not deployment readiness.
5. The client calls `tools/list` again. The tool appears only if its current schema
   digest is still reviewed and the applied policy permits exposure.

Calling `approve_request` for this gateway-internal request returns `web_only` and
performs no policy change.

## Stable domain errors

| Code | Meaning and exact runtime message |
| --- | --- |
| `request_not_found` | `No request with that ID exists in this caller namespace.` |
| `stale_version` | `The request changed after it was reviewed; list pending approvals again.` |
| `web_only` | `Policy-change requests can only be approved in the authenticated web app.` |
| `invalid_request_state` | `Only a pending request can be approved.` or `Only a pending request can be cancelled.` |
| `request_expired` | `This request has expired and cannot be approved.` |
| `totp_not_enrolled` | `TOTP is not enrolled; approve this request in the authenticated web app.` |
| `totp_locked` | `TOTP verification is temporarily locked; wait before retrying or use the web app.`; includes `details.retry_after` |
| `totp_invalid` | `The TOTP code is invalid or has already been consumed.` |
| `totp_unavailable` | `TOTP verification is unavailable; use the authenticated web app.` |
| `totp_binding_invalid` | `The TOTP proof was not bound to this exact request version.` |
| `totp_replayed` | `This TOTP code has already authorized another action.` |

For mirrored downstream aliases, relevant stable errors additionally include
`policy_denied`, `schema_unreviewed`, `schema_invalid`, `invalid_arguments`,
`task_execution_unsupported`, and adapter-specific validation failures. Exact
schemas and invalid argument shapes fail before any downstream call.

## Caller guidance

- Preserve the pending result and request ID in the conversation without calling
  it success.
- Use the latest version hash prefix from `list_pending_approvals`; never guess it.
- Relay a TOTP code only when the human supplied it for the identified request in
  the current conversation. Do not retain it after the tool call.
- On timeout after approval, check status. Do not submit another send.
- Treat `denied`, `expired`, and `cancelled` as confirmed no-send terminal states.
- Treat `failed` according to its failure code and `outcome_unknown` as possibly
  effected until Signet resolves it.
- Full bodies, targets, attachments, edits, denials, policy decisions, and the
  authoritative event timeline belong in the authenticated web app.
