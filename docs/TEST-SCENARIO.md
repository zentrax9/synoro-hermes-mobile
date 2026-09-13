<!-- managed-by: golive-gate test-scenario v2 -->
# Test Scenarios — Hermes Mobile R1

Managed by `golive-gate:generate-test-scenarios`. IDs are stable and entries are not deleted.
Severity follows the policy mapping: `sensitive → High`, `important → Medium`, `core → Low`.
Existing hermetic Python tests were used as evidence; the mobile attachment lifecycle hardening
also added focused lifecycle coverage. Human, Android-toolchain, and live deployment checks remain
pending.

Last generated: **2026-09-08** · aligned to [`DESIGN.md`](DESIGN.md)

## Current repository snapshot

The canonical source is the `main` branch of
[`zentrax9/synoro-hermes-mobile`](https://github.com/zentrax9/synoro-hermes-mobile). The
implementation and handoff documentation are now committed and pushed. The latest recorded
host/relay run is **174 passed, 1 skipped, 0 failed**; Android, live deployment, and independent
review gates remain pending. The per-scenario commit IDs below are historical evidence from the
2026-09-08 implementation pass. Re-run the pending scenarios on the Android-enabled PC and record
the new revision and command output before treating them as current evidence.

## Summary

| Metric | Count |
|---|---:|
| Total | 14 |
| Passed | 8 |
| Failed | 0 |
| Failed — NEEDS-HUMAN | 0 |
| Pending | 6 |
| Stale | 0 |
| High severity not PASSED | 3 |
| Medium severity not PASSED | 3 |

### Verification run

On 2026-09-08, from the repository root, the following native-Windows equivalent of the
repository's per-file isolation runner completed with **169 passed, 1 skipped, 0 failed in
24.2s**:

```powershell
$mobileTests = Get-ChildItem tests/hermes_cli -Filter 'test_mobile_*.py' -File |
  Select-Object -ExpandProperty FullName
$relayTests = Get-ChildItem tests/mobile_push_relay -Filter 'test_*.py' -File |
  Select-Object -ExpandProperty FullName
$files = (($mobileTests + $relayTests) -join ';')
& .venv\Scripts\python.exe scripts/run_tests_parallel.py --files $files -q -rs
```

The one skip was `tests/hermes_cli/test_mobile_attachments.py:244`: symlink creation is
unavailable on this host. Because the working tree is dirty, passing rows use
`Last-verified-commit: 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`.

The Android README lists `gradle testDebugUnitTest`, `gradle lintDebug`, and `gradle assembleRelease`
as required checks (`apps/android/README.md:90-102`), but this host has none of `java`, `gradle`,
`kotlinc`, `adb`, or an Android SDK. No APK build, signing, device test, VM check, Cloudflare
check, or Cloud Run check is claimed.

## Scenarios

### TS-001 — Mobile route isolation  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Isolated mobile ASGI application and forbidden dashboard/RPC paths
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security
- Test-file: `tests/hermes_cli/test_mobile_server.py`
- Run-policy: auto
- Preconditions: Local FastAPI app or live listener test fixture
- Steps: Inspect the route table, exercise `/mobile/v1/*`, and request dashboard, docs, RPC, PTY, files, and config paths.
- Expected: Only versioned mobile routes are present; forbidden paths return 404 and the app does not mount dashboard/RPC routers.
- Covers: `hermes_cli/mobile_server.py:1-5`, `934-1000`, `3078-3115`; `tests/hermes_cli/test_mobile_server.py:26-84`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-002 — Cloudflare Access plus device proof  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Composed authentication at the listener boundary
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security
- Test-file: `tests/hermes_cli/test_mobile_auth.py`, `tests/hermes_cli/test_mobile_request_auth.py`, `tests/hermes_cli/test_mobile_devices.py`
- Run-policy: auto
- Preconditions: Local signing keys and fake JWKS/Access identity
- Steps: Submit forged proxy headers, wrong audience, stale DPoP, bad access hash, foreign device, and valid proof cases.
- Expected: Non-loopback or invalid Access assertions fail; valid Access identity still requires the matching approved device token and DPoP with method, URL, nonce, timestamp, and request-ID binding.
- Covers: `hermes_cli/mobile_auth.py:55-102`; `hermes_cli/mobile_request_auth.py:39-159`; `tests/hermes_cli/test_mobile_auth.py:45-90`, `test_mobile_request_auth.py:73-109`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-003 — Enrollment, token lifetime, replay, and revocation  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Host-approved device lifecycle
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security
- Test-file: `tests/hermes_cli/test_mobile_devices.py`, `tests/hermes_cli/test_mobile_server.py`
- Run-policy: auto
- Preconditions: Temporary device store and two distinct P-256 key pairs
- Steps: Enroll, approve minimal profiles/scopes, issue five-minute tokens, reuse a DPoP `jti`, submit malformed or mismatched nonce/request-ID claims, and revoke.
- Expected: Enrollment is single-use, tokens expire, proofs are bound to method, URL, nonce, timestamp, and request ID, replay checks are durable, scope checks fail closed, and revocation is immediate.
- Covers: `hermes_cli/mobile_devices.py:38-59`, `408-531`, `634-771`, `1110-1153`; `hermes_cli/mobile_server.py:1816-1970`; `tests/hermes_cli/test_mobile_devices.py:76-308`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-004 — Opaque IDs and profile/object isolation  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Cross-instance, cross-profile, and cross-device object authorization
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security
- Test-file: `tests/hermes_cli/test_mobile_objects.py`, `tests/hermes_cli/test_mobile_catalog.py`, `tests/hermes_cli/test_mobile_chat.py`, `tests/hermes_cli/test_mobile_server.py`
- Run-policy: auto
- Preconditions: Two installations or profiles with colliding human-readable names
- Steps: Resolve opaque profile, conversation, run, catalog, and attachment identifiers across scopes.
- Expected: IDs do not encode names or paths; foreign objects are hidden with 404; client allowlists cannot widen host policy; startup/request reconciliation invalidates deleted or renamed host profiles without remapping their old opaque IDs.
- Covers: `hermes_cli/mobile_objects.py:36-57`, `69-148`; `hermes_cli/mobile_server.py:619-751`, `2103-2307`; `tests/hermes_cli/test_mobile_objects.py:8-23`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-005 — Idempotent chat and indeterminate side effects  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Direct message, run cancel, and executor uncertainty
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, integration, security
- Test-file: `tests/hermes_cli/test_mobile_event_store.py`, `tests/hermes_cli/test_mobile_chat.py`, `tests/hermes_cli/test_mobile_server.py`
- Run-policy: auto
- Preconditions: Temporary WAL event/chat stores and fake executor
- Steps: Repeat a mutation with the same key and body, reuse the key with a different body, and fail the executor after claiming work.
- Expected: Same-key retries replay exactly, body conflicts return 409, and uncertain work is fenced as `indeterminate` without automatic resubmission.
- Covers: `hermes_cli/mobile_event_store.py:358-464`, `573-594`; `hermes_cli/mobile_server.py:2237-2307`, `2735-2859`; `tests/hermes_cli/test_mobile_event_store.py:87-187`, `test_mobile_chat.py:71-130`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-006 — Durable cursor sync and restart reconciliation  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Profile-scoped backlog, live event stream, cursor retention, and recovery
- Category: important
- Severity: Medium
- Verify: agent
- Test-type: unit, integration
- Test-file: `tests/hermes_cli/test_mobile_event_store.py`, `tests/hermes_cli/test_mobile_server.py`
- Run-policy: auto
- Preconditions: Temporary event store with retained-floor advancement
- Steps: Append concurrent events, reopen the stores, fence a queued direct run, resume from a retained cursor, request an expired cursor, and filter by profile.
- Expected: Cursors are monotonic and durable; restarted direct runs and pending mutations become `indeterminate` without replay; expired cursors trigger reconciliation; foreign profile events are not returned.
- Covers: `hermes_cli/mobile_event_store.py:195-205`, `551-611`, `685-740`; `hermes_cli/mobile_server.py:950-1015`; `tests/hermes_cli/test_mobile_event_store.py:30-86`, `test_mobile_server.py:288-407`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-007 — Attachment bounds, ownership, and atomic finalization  [PENDING]

- Feature / flow: Encrypted staging and resumable attachment upload
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security, integration
- Test-file: `tests/hermes_cli/test_mobile_attachments.py`, `tests/hermes_cli/test_mobile_attachment_lifecycle.py`, `tests/hermes_cli/test_mobile_server.py`
- Run-policy: auto
- Preconditions: Temporary upload root with a host capable of creating symlinks
- Steps: Declare, upload ordered chunks, finalize, try path traversal, MIME spoofing, hash/size mismatch, quota overflow, and symlink staging.
- Expected: Only bounded owned uploads finalize; unsafe paths, mismatched content, quota bypass, and symlink traversal fail closed.
- Covers: `hermes_cli/mobile_attachments.py:279-389`, `391-435`, `549-588`, `678-765`, `1202-1258`; `hermes_cli/mobile_server.py:555-578`, `2862-3078`, `3358-3387`; `tests/hermes_cli/test_mobile_attachments.py:63-351`, `tests/hermes_cli/test_mobile_attachment_lifecycle.py`
- Fix-attempts: 0/3
- Last-verified-commit: `—`
- Note: The mobile run passed all attachment assertions except the symlink subcase, which was skipped because this host cannot create symlinks. Re-run on a capable CI/Unix or privileged Windows host before release.

### TS-008 — Settings, approval, and step-up boundaries  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Safe settings writes, approval decisions, and sensitive step-up proofs
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security
- Test-file: `tests/hermes_cli/test_mobile_settings.py`, `tests/hermes_cli/test_mobile_approvals.py`, `tests/hermes_cli/test_mobile_step_up.py`
- Run-policy: auto
- Preconditions: Temporary settings/approval stores and single-use step-up challenge
- Steps: Update safe fields with exact ETag, attempt to weaken approval policy, alter step-up context, approve or deny an approval, and cross profiles.
- Expected: Writes are revision guarded and audited; authority can only tighten policy; sensitive mutations require exact single-use step-up; foreign objects are hidden.
- Covers: `hermes_cli/mobile_server.py:1042-1246`, `1522-1716`; `hermes_cli/mobile_settings.py:236-268`; `hermes_cli/mobile_step_up.py:1-110`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-009 — Group and routine execution fencing  [PENDING]

- Feature / flow: Multi-profile group turns, leases, cancellation, routines, and restart recovery
- Category: important
- Severity: Medium
- Verify: agent + human
- Test-type: unit, integration, security
- Test-file: `tests/hermes_cli/test_mobile_groups.py`, `tests/hermes_cli/test_mobile_group_server.py`, `tests/hermes_cli/test_mobile_routines.py`, `tests/hermes_cli/test_mobile_routine_worker.py`
- Run-policy: auto
- Preconditions: Temporary group/routine stores with fake profile-scoped executor
- Steps: Create groups, mutate membership during a turn, exceed round/response caps, expire leases, restart, cancel, pause, and resume routines.
- Expected: Authority epochs and leases fence duplicate execution; limits apply; restart marks uncertainty; peer content retains untrusted provenance. The host worker seam executes only an injected trusted callback, renews leases, fences stale completion, and marks executor, lease, or shutdown uncertainty without retry; production startup still requires an operator-owned executor binding.
- Covers: `hermes_cli/mobile_groups.py:304-323`, `556-914`, `1046-1118`; `hermes_cli/mobile_routines.py:197-213`, `262-305`, `482-532`; `hermes_cli/mobile_routine_worker.py:1-310`; `hermes_cli/mobile_server.py:2309-2639`, `1450-1625`; `tests/hermes_cli/test_mobile_routine_worker.py`
- Fix-attempts: 0/3
- Last-verified-commit: `—`

### TS-010 — Fixed-contract push relay and deduplication  [PASSED (2026-09-08, 693641aa8b4359c602283bdbbc14041e03bc47bc (dirty), agent)]

- Feature / flow: Host push registration, revocation, fixed wake payload, relay dedupe, and rate limits
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security, integration
- Test-file: `tests/hermes_cli/test_mobile_push.py`, `tests/mobile_push_relay/test_relay.py`, `tests/mobile_push_relay/test_firestore_registry.py`, `tests/mobile_push_relay/test_deployment.py`
- Run-policy: auto
- Preconditions: Fake HTTP/FCM and local SQLite or fake Firestore registry
- Steps: Send allowed and forbidden payload fields, repeat event IDs, rotate/revoke handles, simulate failed delivery, and inspect deployment manifest checks.
- Expected: Only fixed opaque fields reach the relay; dedupe is scoped to instance/device, failures can release delivery leases, and production configuration requires Firestore and immutable security settings.
- Covers: `hermes_cli/mobile_push.py:12-103`; `services/mobile_push_relay/app.py:104-131`, `247-300`, `418-723`; `services/mobile_push_relay/cloud-run.service.yaml:3-38`
- Fix-attempts: 0/3
- Last-verified-commit: `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`

### TS-011 — Android transport, PKCE, DPoP, storage, lock, and group-control tests  [PENDING]

- Feature / flow: Android client security primitives, typed transport, and group controls
- Category: sensitive
- Severity: High
- Verify: agent
- Test-type: unit, security
- Test-file: `apps/android/app/src/test/java/com/hermes/mobile/auth/PkceAuthTest.kt`, `apps/android/app/src/test/java/com/hermes/mobile/security/DpopJwtTest.kt`, `apps/android/app/src/test/java/com/hermes/mobile/security/DeviceProofTest.kt`, `apps/android/app/src/test/java/com/hermes/mobile/network/HermesRequestFactoryTest.kt`, `apps/android/app/src/test/java/com/hermes/mobile/network/GroupModelsTest.kt`, `apps/android/app/src/test/java/com/hermes/mobile/contract/ContractModelsTest.kt`, `apps/android/app/src/test/java/com/hermes/mobile/security/LocalLockStateTest.kt`
- Run-policy: ask
- Preconditions: JDK 17, Android SDK API 36, Gradle toolchain, and dependency verification metadata
- Steps: Run `gradle testDebugUnitTest` and inspect the Android test report.
- Expected: PKCE callback binding, DPoP normalization and proof, device proof, `/mobile/v1/*` request restriction, typed models, group cardinality/revision/mention/cache invariants, and local lock invariants pass. The full Android run remains pending until CI has JDK/SDK access.
- Covers: `apps/android/app/src/main/java/com/hermes/mobile/auth`, `security`, `network`, `contract`, and `data/MobileGroupRepository.kt`; `apps/android/README.md:42-88`
- Fix-attempts: 0/3
- Last-verified-commit: `—`

### TS-012 — Android release coordinates, lint, build, and signing  [PENDING]

- Feature / flow: Reproducible release build gate
- Category: important
- Severity: Medium
- Verify: human
- Test-type: manual
- Test-file: —
- Run-policy: ask
- Preconditions: JDK 17, Android SDK API 36, official Gradle distribution/wrapper, installation coordinates, signing custody, and supported test device
- Steps: Supply non-placeholder `MOBILE_BASE_URL`, Cloudflare issuer/resource, OAuth client/endpoints; run `gradle lintDebug`, `gradle testDebugUnitTest`, and `gradle assembleRelease`; verify signer and install on supported devices.
- Expected: `verifyReleaseConfiguration` passes, lint/tests/build pass, the APK is signed by the approved key, and the configured installation refuses placeholders.
- Covers: `apps/android/app/build.gradle.kts:20-49`, `82-135`; `apps/android/README.md:90-110`
- Fix-attempts: 0/3
- Last-verified-commit: `—`

### TS-013 — VM, Cloudflare, relay, enrollment, and revocation deployment  [PENDING]

- Feature / flow: Operator-assisted live release path
- Category: sensitive
- Severity: High
- Verify: human
- Test-type: integration, security, manual
- Test-file: —
- Run-policy: ask
- Preconditions: Exact VM and source revision, dedicated Access app/audience/hostname/tunnel, allowlists, GCP/Firestore/FCM coordinates, immutable relay image, and operator approval
- Steps: Start loopback listener, configure tunnel-only ingress, run `GET /mobile/v1/capabilities`, scan forbidden paths, deploy relay by digest, run `check_cloud_run.sh`, enroll a device, and revoke it during an active stream.
- Expected: Only mobile routes are reachable; invalid headers/audience/device proofs fail; Cloud Run checks pass for the exact digest; revoke rejects token and stream immediately; uncertain mutations are not resubmitted.
- Read-only note (2026-09-08): the UGREEN UI showed `ubuntu26` running deployed `main` at
  `f98f5e74`, but the Hermes process exposed only its Unix gateway socket and no mobile HTTP
  listener; the full scenario remains pending.
- Covers: `docs/deployment/hermes-mobile-ugreen-vm.md:7-119`; `services/mobile_push_relay/deploy.sh:1-44`; `services/mobile_push_relay/check_cloud_run.sh:1-72`
- Fix-attempts: 0/3
- Last-verified-commit: `—`

### TS-014 — Independent human review and realistic end-to-end use  [PENDING]

- Feature / flow: Release review, data correctness, least privilege, UX, recovery, and approvals
- Category: important
- Severity: Medium
- Verify: human
- Test-type: manual
- Test-file: —
- Run-policy: ask
- Preconditions: Formal risk tier, named owner/support contact, reviewer independent of both, Android test device, live installation, and representative non-production data
- Steps: Verify requirements, correct data source, least privilege, sensitive-data/log policy, enrollment UX, push wake plus sync, attachment recovery, approval step-up, and revoke/re-enroll behavior.
- Expected: Human reviewer records PASS/FAIL for each applicable review-checklist item and seals a commit-bound proof only after all High/Medium scenarios are passed or explicitly addressed.
- Covers: `docs/PROJECT.md:61-79`, `docs/REVIEW-PROOF.md`, `docs/security/hermes-mobile-threat-model.md:63-100`
- Fix-attempts: 0/3
- Last-verified-commit: `—`

## History

- 2026-09-08 · TS-001 through TS-006, TS-008 through TS-010 · re-verified PASSED by agent against `693641aa8b4359c602283bdbbc14041e03bc47bc (dirty)`.
- 2026-09-07 · TS-007 · created PENDING because the symlink security subcase was skipped on this host.
- 2026-09-07 · TS-011 through TS-014 · created PENDING because Android, live deployment, and human-review gates were not run.
