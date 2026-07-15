# Signet deployment staging

Everything in this directory is inert source material. Nothing here has been
installed, loaded into `launchd`, merged into Tailscale Serve, or applied to a
Hermes profile. The launchd examples use Signet's installed downstream-disabled
commands. Their absolute-path placeholders still prevent startup until an operator
creates private disabled state, reviews the files, and authorizes installation.
They cannot create a provider client or dispatch an action.

- `launchd/` contains separate user-agent templates and a no-install structural
  renderer for the MCP and web listeners.
- `homepage/` contains one ordinary Signet service card and no widget credential.
- `tailscale/` documents a merge-safe tailnet-only Serve route and exact removal.
- `hermes/` contains validated disposable and persistent disabled-profile
  configurators, reviewed route fragments, and redacted forward/reverse live
  route-diff examples.
- `operations/` contains fail-closed inventory and human-evidence skeletons.

Start with `docs/operator-runbook.md` for fake-only local verification, then use
`docs/deployment.md` for the deferred deployment review. Do not apply a template
merely because it parses.
Credential enrollment, proxy changes, service startup, live discovery, route
replacement, and provider calls require a separate human-authorized cutover.
