# Hermes mobile push relay

This service is a small Cloud Run relay. It accepts only opaque event enums and
opaque device handles, then emits fixed FCM notification text. It never accepts
or persists transcripts, message content, arbitrary notification text, or
client-provided object paths.
Each FCM message includes the fixed `hermes_sync_wake=1` data marker so opening a
system-rendered background notification forces authenticated cursor reconciliation;
the relay never selects a profile or carries profile scope.

## State and identity

Cloud Run must use Firestore. `RELAY_BACKEND=firestore` is explicit in the
deployment manifest, and the application also selects Firestore whenever
`K_SERVICE` or a production `RELAY_ENV` is present. A production request that
tries to select SQLite fails closed; SQLite is retained only for local tests and
explicit local development. The Firestore client uses Application Default
Credentials (ADC), so the Cloud Run service account must be attached through
Workload Identity/ADC rather than a credential file or secret in this tree.

Grant the runtime service account only the permissions needed for the relay:

* Firestore read/write access for the relay collections (for example,
  `roles/datastore.user`); and
* permission to send Firebase Cloud Messaging messages (for example,
  `roles/firebasecloudmessaging.admin`).

The Firestore implementation uses transactions for instance/device ownership,
token rotation, revocation, deduplication, and per-device rate limits. Event
deduplication records carry an `expires_at` timestamp for a 24-hour TTL. Enable
a Firestore TTL policy for `relay_events.expires_at` and
`relay_rate_limits.expires_at` in the target project; TTL deletion is cleanup,
not authorization, so expired records are also ignored transactionally.
The injectable SQLite backend keeps the same rate-limit expiry field and prunes
expired local rows on use; it is not a production durability substitute.

## Build and deploy

The Dockerfile's Python base is pinned by digest. Any CI override of
`PYTHON_IMAGE` must also use an immutable `@sha256:<64 hex>` reference. Build an
application image, push it to Artifact Registry, and pass the resulting digest
reference to the deployment script:

```text
services/mobile_push_relay/deploy.sh PROJECT_ID REGION SERVICE_ACCOUNT IMAGE_URI@sha256:DIGEST
```

The script rejects mutable runtime tags, renders the manifest to a temporary
file, and applies it with `gcloud run services replace`. It does not accept or
write secrets. Configure IAM invocation policy separately for the intended
authenticated caller set; the service is not designed for anonymous use.

After deployment, run the immutable configuration check against the same
service and digest:

```text
services/mobile_push_relay/check_cloud_run.sh PROJECT_ID REGION hermes-mobile-push-relay IMAGE_URI@sha256:DIGEST
```

This check reads only Cloud Run's exported service configuration and verifies the
digest, attached service account, Firestore backend, restricted ingress, non-root
and read-only container settings, and the in-memory `/tmp` mount. A passing check
does not replace the authenticated mobile verification in the VM runbook.

The manifest requests Cloud Run second-generation execution, a non-root UID,
read-only root filesystem, and an in-memory `/tmp` volume. Production state is
not stored in `/tmp`; the tmpfs only satisfies libraries that need a temporary
directory. Do not remove the service account or these filesystem constraints.

For local tests, install the locked requirements and inject a temporary SQLite
path or an in-memory fake Firestore client. When no `RELAY_DB_PATH` is supplied,
the explicit local SQLite fallback is cwd-local; do not point a production Cloud
Run deployment at `RELAY_DB_PATH`.
