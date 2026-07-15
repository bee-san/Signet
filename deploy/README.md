# Signet deployment staging

Everything in this directory is inert source material. Nothing here has been
installed, loaded into `launchd`, merged into Tailscale Serve, or applied to a
Hermes profile. The placeholders deliberately prevent the launchd examples from
running until an operator reviews and replaces them during an authorized cutover.

- `launchd/` contains separate user-agent templates for the MCP and web listeners.
- `homepage/` contains one ordinary Signet service card and no widget credential.
- `tailscale/` documents a merge-safe tailnet-only Serve route and exact removal.
- `hermes/` contains redacted forward and reverse route-diff examples.
- `operations/` contains fail-closed inventory and human-evidence skeletons.

Follow `docs/deployment.md`. Do not apply a template merely because it parses.
Credential enrollment, proxy changes, service startup, live discovery, route
replacement, and provider calls require a separate human-authorized cutover.
