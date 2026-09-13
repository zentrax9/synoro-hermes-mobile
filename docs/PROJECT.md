# Synoro Hermes Mobile — release dossier

> **Scope note.** This is the detailed docs-scoped project dossier prepared for the Synoro Hermes
> Mobile implementation. The Android Studio resume sequence is in
> [`ANDROID-STUDIO-HANDOFF.md`](ANDROID-STUDIO-HANDOFF.md). The repository-level release record is
> [`../PROJECT.md`](../PROJECT.md); it keeps
> the required ownership, risk, and live-coordinate fields explicit and unassigned until the
> operator supplies them.

## Status

- **Release state:** `INCOMPLETE — NOT READY`. The Python mobile implementation and its local
  contract tests are present, but Android toolchain, live Access/Tunnel, VM, push-relay, signing,
  enrollment, and independent-review gates are not evidenced in this checkout.
- **Evidence anchor:** `main` in `zentrax9/synoro-hermes-mobile`; verify the exact revision on any
  machine with `git rev-parse HEAD` and `git status --short`.
- **Working tree at last upload:** clean. The mobile implementation, Android client, relay, tests,
  dashboard changes, and handoff documentation are committed and pushed. This is source-control
  evidence, not release approval.
- **Latest recorded local gate:** 174 mobile/relay tests passed, 1 attachment symlink case skipped;
  Ruff, compileall, and `git diff --check` passed. Android compilation was not run because the
  publishing PC had no JDK 17 or Android SDK.
- **Deployment claim:** none. No VM, Cloudflare, GCP, Firebase, APK, release key, or live host
  coordinates are recorded in this dossier.

## Problem Being Solved

Hermes Mobile provides a typed Android client for selected Hermes profiles, conversations, agent
runs, groups, approvals, routines, settings, attachments, and durable synchronization. The mobile
surface is intentionally narrower than the dashboard and JSON-RPC surfaces: a separate FastAPI
application exposes only versioned `/mobile/v1/*` routes, authenticates Cloudflare Access plus an
approved device proof, and applies host-owned profile and scope allowlists.

The release objective is an operator-assisted, installation-specific deployment in which the
listener is loopback-bound behind Cloudflare Tunnel, Android uses installation coordinates supplied
at build time, and push delivery remains a generic wake hint followed by authenticated sync.

## Objectives and Non-goals

### Objectives

1. Preserve the mobile/dashboard trust boundary. Mobile clients must not reach dashboard, PTY,
   filesystem, configuration, or generic RPC routes.
2. Require both an installation-scoped Cloudflare Access identity and an approved device key proof
   for every mobile request, with host-owned scope/profile policy.
3. Make side-effecting mutations replay-safe and crash-safe: idempotency records are durable, and
   uncertain external effects become `indeterminate` rather than being resubmitted automatically.
4. Keep credentials, message content, attachment names, and tokens out of logs and push payloads.
5. Provide enough operator evidence to approve the Android build, host deployment, relay deployment,
   device enrollment, revocation path, and independent review.

### Non-goals for this release

- No invented VM address, SSH route, Cloudflare audience, hostname, tunnel ID, GCP project,
  Firebase project, relay image digest, Android application variant, or release-signing key.
- No claim that an APK was built, signed, installed, or exercised on a physical device.
- No claim that a Cloud Run service, Firestore database, FCM project, Cloudflare Access application,
  or UGREEN VM is healthy or release-ready.
- A read-only UGREEN UI probe on 2026-09-08 observed `ubuntu26` running deployed `main` at
  `f98f5e74`; the Hermes process exposed only its Unix gateway socket and no mobile HTTP listener.
  This does not substitute for the live deployment, Access, relay, enrollment, or revocation gates.
- No payment, wallet, ledger, balance, or other financial asset workflow is introduced by the
  mobile surface. Agent turns, approvals, routines, and group execution are operational side
  effects and still require integrity testing.

## Risk Level

**Formal risk classification: NOT RECORDED.** The root `PROJECT.md` records the field as
unassigned, and no owner interview/classification was run in this task. Code and docs do show security-sensitive
signals — conversation and attachment data, credential-bearing host profiles, public-edge
authentication, device enrollment, and external side effects — so a formal `assess-risk-level`
run is a release prerequisite. Do not infer Low risk from the size of the client.

## Project Owner and Support Contact

- **Project Owner:** ⚠️ not recorded as a GitHub username.
- **Support Contact:** ⚠️ not recorded as an individual email.

These missing identities block the machine independence check for a Medium/High review. They must
be supplied by the owner in the established root dossier before `/vibe-review` can establish
independence.

## Data Used and Handling

| Data class | Evidence and handling |
|---|---|
| Conversation text, drafts, transcripts, run/session metadata | The threat model lists these as assets (`docs/security/hermes-mobile-threat-model.md:14-20`). Android stores sensitive message/draft values in encrypted Room/DataStore blobs (`apps/android/README.md:42-60`). |
| Device identity, Access claims, device tokens, DPoP material | The listener binds Access subject to an approved device record and validates DPoP (`hermes_cli/mobile_request_auth.py:118-159`; `hermes_cli/mobile_auth.py:55-102`). The device store persists public JWKs, hashes, status, and allowlists (`hermes_cli/mobile_devices.py:495-531`). |
| Attachments | Uploads are opaque, bounded, scoped, hash/MIME checked, and staged under private UUID names (`hermes_cli/mobile_attachments.py:391-435`, `678-765`). |
| Push data | The host relay client sends only fixed event type, event ID, device handle, and expiry (`hermes_cli/mobile_push.py:84-103`). The relay README forbids transcripts, arbitrary text, URLs, and credentials (`services/mobile_push_relay/README.md:1-8`). |
| Secrets and coordinates | Cloudflare, OAuth, relay, VM, GCP, Firebase, and signing values are release-environment inputs; placeholders fail closed in the Android release task (`apps/android/app/build.gradle.kts:16-127`, `218-243`). |

## Access Status and Login Method

- **Intended entry:** Android → installation-specific HTTPS hostname → Cloudflare Access/Tunnel →
  loopback mobile listener. The deployment runbook requires a dedicated Access application and a
  tunnel ingress containing only the mobile hostname (`docs/deployment/hermes-mobile-ugreen-vm.md:37-52`).
- **API authentication:** Cloudflare Access JWT validated from a loopback tunnel peer, then a
  short-lived device token and DPoP proof bound to the pinned public origin (`hermes_cli/mobile_auth.py:55-102`;
  `hermes_cli/mobile_request_auth.py:39-159`).
- **Enrollment:** Android uses Authorization Code + PKCE and a host-approved enrollment code;
  the host chooses profiles and scopes (`docs/deployment/hermes-mobile-ugreen-vm.md:54-70`).
- **Current access state:** not live-verified. There is no recorded hostname, tunnel, Access
  audience, approved device, or successful end-to-end request in this checkout.

## Components

| Component | Responsibility | Current evidence |
|---|---|---|
| Android client | PKCE enrollment, DPoP/device proofs, encrypted local state, typed API, durable sync, attachments, voice staging, push wake, and typed same-instance group controls with restart-safe opaque group references | `apps/android/README.md:1-18`, `apps/android/README.md:42-93` |
| Mobile listener | Separate FastAPI app with `/mobile/v1/*` routes; no dashboard/RPC imports; auth, scopes, object ownership, mutations | `hermes_cli/mobile_server.py:1-5`, `hermes_cli/mobile_server.py:934-1000` |
| Host mobile state | SQLite/WAL stores for devices, opaque objects, events/idempotency, settings, approvals, routines, chat, groups, attachments, and rate limits; live-profile reconciliation removes stale opaque bindings on startup and request paths. Settings values are currently a mobile shadow store; a host-file-backed adapter is still required before settings writes are canonical Hermes profile changes. | `hermes_cli/mobile_startup.py:286-398`; `hermes_cli/mobile_objects.py:119-174`; `hermes_cli/mobile_event_store.py:551-594`; `hermes_cli/mobile_settings.py:246-412` |
| Hermes core/executor | Runs profile-scoped chat and group work after the mobile layer authorizes it; routine runs require the explicit host-owned worker seam and an operator-supplied executor binding | `hermes_cli/mobile_startup.py:375-398`; `hermes_cli/mobile_server.py:2103-2307`, `1450-1625`; `hermes_cli/mobile_routine_worker.py:1-310` |
| Push relay | Authenticated fixed-contract relay to FCM with Firestore/ADC in production | `services/mobile_push_relay/README.md:8-32`; `services/mobile_push_relay/cloud-run.service.yaml:3-38` |

## Go-Live Prerequisites

| Gate | Evidence required | Current status |
|---|---|---|
| Repository dossier and risk classification | Root `PROJECT.md` with owner, support email, risk tier, data, access, and approvals | **BLOCKED** — dossier exists, but owner/support/risk/approvals remain unassigned |
| Local Python contract/security tests | Canonical per-file isolation runner covering mobile listener and relay tests | **PASS with limitation** — latest recorded run: `174 passed, 1 skipped, 0 failed`; the skipped symlink test requires host capability (`docs/TEST-SCENARIO.md`) |
| Android unit tests | `gradle testDebugUnitTest` with JDK 17 and Android SDK API 36 | **NOT RUN** — this host has no `java`, Gradle, Android SDK, `adb`, or `kotlinc` (`apps/android/README.md:90-102`) |
| Android lint and release build | `gradle lintDebug`; `gradle assembleRelease`; release coordinates pass `verifyReleaseConfiguration` | **NOT RUN** — no Android toolchain or signing configuration evidenced |
| VM listener | Exact revision, dedicated non-root service, loopback bind, configured issuer/audience, HTTPS public URL, non-empty allowlists | **NOT RUN** — coordinates intentionally absent; runbook is coordinate-driven (`docs/deployment/hermes-mobile-ugreen-vm.md:7-35`) |
| Cloudflare boundary | Dedicated app/audience/hostname/tunnel, live route scan, forged-header and wrong-audience rejection | **NOT RUN** — no live Access/Tunnel evidence |
| Push relay | Immutable image deploy, Firestore/ADC, restricted ingress, non-root/read-only filesystem, exact-digest `check_cloud_run.sh` output | **NOT RUN** — no project, region, service account, digest, or `gcloud` evidence |
| Device enrollment and revocation | Operator approves minimal profile/scope policy, Android enrolls, token refresh works, revoke rejects token and stream | **NOT RUN** — requires operator and live host |
| Independent review | Reviewer identity, independence result, human checks, sealed proof commit | **INCOMPLETE** — `docs/REVIEW-PROOF.md` is an unsealed draft; no reviewer supplied |

## Operator Inputs Still Required

Provide these at deployment time, outside source control:

- Exact VM type, private address, SSH user/path, service manager, and source revision.
- Cloudflare team domain, installation-specific Access issuer/audience, hostname, and tunnel ID.
- Initial host profile allowlist, mobile scope allowlist, model/provider/skill/tool policies, and
  safe initial settings.
- Android application ID/version, supported test devices, Firebase configuration, and release-key
  custody.
- GCP project/region, Artifact Registry image digest, Cloud Run service account, Firestore TTL
  policy, Firebase project, FCM authority, and relay invocation policy.
- Named project owner and support contact in the required identity formats.
- Reviewer who is neither the project owner nor the support contact, plus any Architecture, SRE,
  Information Security, or other formal approvals required by the eventual risk tier.

## Review Evidence

No independent review or approval is recorded. The local Python test run is engineering evidence,
not a release approval. The companion [REVIEW-PROOF.md](REVIEW-PROOF.md) is deliberately marked
`INCOMPLETE` and `UNSEALED` because the tree is dirty, the risk tier and ownership fields are
missing, and the human/live gates were not executed.

## Evidence Index

- Architecture and boundary source: [`DESIGN.md`](DESIGN.md).
- Security objective, trust boundaries, threats, and fail-closed invariants:
  [`security/hermes-mobile-threat-model.md`](security/hermes-mobile-threat-model.md).
- Coordinate-driven VM, tunnel, enrollment, and relay runbook:
  [`deployment/hermes-mobile-ugreen-vm.md`](deployment/hermes-mobile-ugreen-vm.md).
- Test matrix and current local results: [`TEST-SCENARIO.md`](TEST-SCENARIO.md).
- Android Studio resume sequence: [`ANDROID-STUDIO-HANDOFF.md`](ANDROID-STUDIO-HANDOFF.md).
- Review status and blockers: [`REVIEW-PROOF.md`](REVIEW-PROOF.md).
