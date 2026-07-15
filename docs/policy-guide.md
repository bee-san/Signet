# Policy Guide

Signet uses four exact per-tool modes:

- `passthrough` for explicitly reviewed read-only tools.
- `virtualize_local` for bounded local objects with no downstream call.
- `approval` for frozen writes that return an honest pending result.
- `deny` for reviewed disallowed tools; unconfigured tools remain unlisted and
  resolve to deny by default.

The executable v1 baseline is `spec/policy-v1.yaml`. Communication sends may never
be promoted to passthrough. Policy changes are versioned, audited, and approved in
the web app only.

TODO: document one-click promotion, access requests, `tools/list_changed`, schema
drift, rollback, and the reviewed adapter-onboarding checklist.
