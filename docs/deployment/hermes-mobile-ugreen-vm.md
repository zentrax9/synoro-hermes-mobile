# Hermes Mobile on a UGREEN NAS VM

This runbook is intentionally coordinate-driven. It does not put a tunnel, Access
audience, relay credential, or release key in the repository. Fill in the values at
deployment time and keep them in the VM secret/configuration store.

## Required coordinates

- VM private address, SSH user, Hermes checkout path, and the exact release revision.
- A dedicated Cloudflare Access application and audience for this installation, plus
  the mobile hostname and tunnel ID.
- A non-empty host profile allowlist and mobile scope allowlist.
- A GCP project/region, Cloud Run relay service account, Firebase project, and an
  immutable relay image digest.
- Android application ID, release signing key location, and the Firebase configuration
  supplied by the release environment (never commit `google-services.json`).

## VM listener

Configure the host policy before starting the process. The mobile listener must bind to
loopback on the VM; Cloudflare Tunnel is the only public-facing process:

```text
hermes serve --skip-build --host 127.0.0.1 --port 9119 \
  --mobile-host 127.0.0.1 --mobile-port 9120
```

The ordinary dashboard stays on `9119`. The mobile app is isolated on `9120` and exposes
only `/mobile/v1/*`. Do not bind either listener to `0.0.0.0`. If a private VPN interface
is required, explicitly enable `mobile.allow_private_bind` and use the VM's private VPN
address; never use a wildcard bind.

Persist the process with the VM's service manager and run it as a dedicated non-root user.
The service account must be able to write the Hermes mobile state directory, but it must
not be able to read unrelated host credentials or arbitrary filesystem paths.

## Cloudflare Tunnel and Access

Create a separate Access application for the installation-specific mobile hostname. Set
its audience to the value in `mobile.cloudflare_access.audience`, and set the issuer to the
installation's Access issuer. The tunnel ingress must contain only the mobile hostname:

```yaml
ingress:
  - hostname: mobile.<installation-domain>
    service: http://127.0.0.1:9120
  - service: http_status:404
```

Do not route the dashboard, PTY, console, file browser, generic RPC, or another Hermes
installation through this hostname. The listener validates the Access JWT itself and does
not trust a forwarded identity header from an untrusted peer.

## First device enrollment

1. Open the mobile hostname in the Android app and complete Authorization Code + PKCE.
2. Keep the one-time enrollment code shown by the app private.
3. On the VM, approve only the intended profiles and scopes:

   ```text
   hermes mobile devices approve <enrollment-code> \
     --profiles <host-profile> \
     --scopes chat groups attachments settings:read settings:write:safe approvals routines:control
   ```

4. Confirm the device with `hermes mobile devices list` and verify that the profile and
   scope allowlists are minimal. The authenticated dashboard's **Mobile devices** page
   exposes the same registry and has an immediate **Revoke** action. Use either it or
   `hermes mobile devices revoke <device-id>` for a lost phone; local token revocation is
   durable even if push-relay cleanup is temporarily down.

## Push relay

Build `services/mobile_push_relay/Dockerfile` in a trusted CI environment, push it to
Artifact Registry, and deploy using an image reference pinned by `@sha256:<digest>`:

```text
services/mobile_push_relay/deploy.sh <project> <region> <service-account> \
  <artifact-registry-image>@sha256:<64-hex-digest>
```

Use Firestore with ADC/Workload Identity in Cloud Run. Do not put a Firebase service-account
file on the VM. Store only the relay-only credential on the Hermes host, and rotate it when
an installation or device is removed. FCM remains a wake hint; its fixed
`hermes_sync_wake=1` marker causes the app to schedule global reconciliation and perform
authenticated cursor sync after opening.

After `deploy.sh` completes, verify the live service before putting the relay URL in the VM
configuration:

```text
services/mobile_push_relay/check_cloud_run.sh <project> <region> hermes-mobile-push-relay \
  <artifact-registry-image>@sha256:<64-hex-digest>
```

The check must pass for the exact image digest being released. It verifies that Cloud Run is
using Firestore, the attached service account, restricted ingress, non-root/read-only
filesystem expectations, and the in-memory `/tmp` mount. If it fails, do not configure
`mobile.push_relay.url` or copy `HERMES_MOBILE_PUSH_RELAY_TOKEN` to the VM.

## Verification before opening access

- `GET /mobile/v1/capabilities` succeeds through Access; `/docs`, `/openapi.json`, `/api/ws`,
  `/api/pty`, `/api/files`, `/api/config`, and `/api/rpc` return `404` on the mobile port.
- The device receives a five-minute Hermes token and every mutation carries a unique
  idempotency key plus a DPoP proof bound to that token.
- A second installation with duplicate profile names cannot read the first installation's
  objects or events.
- Cursor expiry triggers a snapshot reconciliation; a process restart never resubmits an
  uncertain mutation automatically.
- Revoke a test device and confirm its token is rejected immediately and its SSE stream is
  terminated on the next heartbeat (the default check interval is 15 seconds).
- Run the Cloud Run immutable configuration check above and record its output with the release
  revision; do not treat a successful container start alone as deployment evidence.

Keep the exact VM, Cloudflare, GCP, and Android coordinates outside source control. They are
the remaining inputs needed for an operator-assisted deployment of this implementation.
