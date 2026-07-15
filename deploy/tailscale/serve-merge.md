# Tailnet-only Serve merge packet

This is a review packet, not an installer. No command in this file has been run.
The reference route uses a free HTTPS listener on port `8443`, leaving an existing
root handler on `443` untouched. If `8443` is already used by any Serve or Funnel
handler, stop: choose another reviewed HTTPS listener and update Signet's exact
`public_origin`, or obtain explicit authorization for the conflict. Never use
`tailscale serve reset`; it deletes unrelated handlers.

## Before the authorized change

Capture both machine-readable configuration and status into a private change
record. These outputs describe routes and must not be committed:

```console
umask 077
tailscale serve get-config --all ./tailscale-serve.before.json
tailscale serve status --json > ./tailscale-serve-status.before.json
tailscale funnel status --json > ./tailscale-funnel-status.before.json
```

Review all three files. Preconditions:

1. The Tailscale node and tailnet are the intended ones.
2. No Serve handler and no Funnel uses HTTPS `8443`.
3. `http://127.0.0.1:8790/healthz` is healthy, while queue routes still require
   Signet login.
4. Signet has `public_origin=https://REVIEWED_TAILNET_HOSTNAME:8443`,
   `rp_id=REVIEWED_TAILNET_HOSTNAME`, and an allowlist containing that exact Host.
5. A human approved this proxy change. Tailscale identity headers are not an
   authentication input to Signet.

Funnel is public exposure. An active Funnel on the selected port is a blocker; do
not silently turn off an unrelated public service. Once the review establishes
that `8443` is unused by Funnel, the absence captured above is the disabled-Funnel
evidence for this route.

## Authorized additive change

This command adds one root handler on the previously free listener. It does not
reset or replace other listener configurations:

```console
tailscale serve --bg --https=8443 http://127.0.0.1:8790
```

Then capture and compare status:

```console
tailscale serve status --json > ./tailscale-serve-status.after.json
tailscale funnel status --json > ./tailscale-funnel-status.after.json
```

Verify that the Signet URL is tailnet-only HTTPS, the previous handlers are
unchanged, Funnel still has no `8443` listener, unauthenticated queue access is
rejected, and the MCP listener remains reachable only on loopback.

## Exact route rollback

Remove only the listener added above, retaining every unrelated handler:

```console
tailscale serve --https=8443 off
tailscale serve status --json
tailscale funnel status --json
```

The saved `get-config --all` output is comparison and disaster-recovery material,
not a routine rollback command. Applying it wholesale could overwrite changes
made after capture.

References: [Tailscale Serve CLI](https://tailscale.com/docs/reference/tailscale-cli/serve),
[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve), and
[Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel).
