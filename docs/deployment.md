# Deployment

Signet is currently scaffolded in downstream-disabled mode. Do not connect live
credentials or replace active Hermes routes during development.

The reference deployment will bind MCP to `127.0.0.1:8789`, bind the authenticated
web app to a separate localhost listener, and merge a tailnet-only Tailscale Serve
route without replacing existing handlers. Funnel and other public exposure stay
disabled. A TLS reverse proxy on a private LAN is the supported alternative.

TODO: add verified launchd installation, merge-safe Serve commands, TLS warnings,
health checks, backup/restore, rollback, and deferred human cutover steps.
