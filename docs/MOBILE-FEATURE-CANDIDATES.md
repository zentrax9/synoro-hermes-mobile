# Hermes Mobile feature candidates

This document is a handoff brief for a future planning session. It captures the
low-effort, high-value Android features identified after comparing our client
with [Hermes Go v2.0.0](https://github.com/shilp26/hermes-go/releases/tag/v2.0.0).

The next session should create an implementation plan from this brief first.
It must not modify code until that plan has been reviewed and explicitly
approved.

## Product context

We are building a secure Android companion for a self-hosted Hermes Agent:

- Android client: Kotlin/Compose, encrypted Room/DataStore state, WorkManager,
  loopback PKCE enrollment, approved-device authentication, DPoP request
  proofs, attachments, voice-note recording, and durable synchronization.
- Host: Python mobile listener exposing versioned `/mobile/v1/*` routes. The
  mobile surface is intended to remain separate from the dashboard/RPC surface.
- Authentication: Cloudflare Access identity plus an approved Hermes device
  token and per-request device-key proof.
- Current Android shell: `Chat`, `Groups`, and `Settings`.
- Existing typed client operations include profiles, conversations, history,
  chat sends, run status/events/cancellation, catalog, routines, approvals,
  attachments, groups, settings, push registration, and device enrollment.
- Current local gate: Python mobile/relay tests pass (`169 passed`, `1 skipped`,
  `0 failed`). The Android toolchain and physical-device enrollment have not
  yet been completed on the current workstation.

Authoritative project status is in [`PROJECT.md`](../PROJECT.md) and
[`docs/PROJECT.md`](PROJECT.md). Android implementation notes are in
[`apps/android/README.md`](../apps/android/README.md).

## Objective

Improve the first usable release's feature value and competitive parity without
widening the mobile trust boundary or turning it into an unrestricted Hermes
dashboard clone.

The strongest product position remains:

> An open-source, Cloudflare Access-native mobile companion for self-hosted
> Hermes Agent, with per-device approval and least-privilege access.

Hermes Go currently has an installable APK and broader features such as live
background execution, notifications, routines, groups, multi-server support,
checkpoints, and Git workflows. Feature claims should be checked against the
release materials before planning parity work.

## Prioritized feature candidates

Effort estimates are intentionally rough and assume the existing contracts are
kept. The planning session must verify them against the current checkout.

| Priority | Feature | Why it is low-hanging fruit | Existing foundation | Main risk/dependency |
| --- | --- | --- | --- | --- |
| P0 | Conversation picker and **New chat** | The server already lists conversations and returns history; the database already supports multiple conversations. This fixes the biggest visible limitation of the current single-conversation shell. | `ConversationWire`, `ConversationsResponse`, `listConversations`, history loading, encrypted Room conversation/message rows, canonical conversation creation. | Add profile-scoped conversation state and selection without exposing host identifiers or mixing instances. |
| P0 | Direct-run status and **Stop** button | Run status, events, and cancellation are already modeled. A user should be able to stop a long-running turn instead of waiting for the final response. | `RunState`, `RunWire`, `getRun`, `getRunEvents`, `cancelRun`, mobile cancellation route. | Track the active direct `run_id`; cancellation must remain idempotent and clearly report indeterminate side effects. |
| P0 | Explicit retry for failed/indeterminate sends | Network failures already preserve idempotency records and mark optimistic messages as failed. A retry action would turn an error message into a recoverable workflow. | `IdempotencyStore`, delivery states, durable mutation records, `MobileChatRepository.sendText`. | Preserve the exact original text and attachment IDs; never create a second agent turn accidentally. |
| P1 | Routines screen: list, pause, resume | Typed routine models and endpoints already exist. This provides useful parity with Hermes Go without implementing execution from the phone. | `RoutineWire`, `listRoutines`, `pauseRoutine`, `getRoutineRun`, routine UI-ready API. | Keep “Run now” disabled until the production `MobileRoutineWorker` is injected and bound to the host executor. |
| P1 | Read-only agent/catalog screen | A small screen showing available models, providers, reasoning modes, and skills improves transparency and helps users choose the right profile. | `CatalogResponse`, `getCatalog`, profile-scoped allowlists. | Catalog entries are currently generic JSON; render safely and do not add untyped settings writes. |
| P1 | Voice-note playback before upload | Recording and encrypted staging already exist; playback completes the review flow and prevents accidental uploads. | App-private AAC-LC/M4A recorder and existing Media3 dependency. | Stop/release playback cleanly on lifecycle changes; preserve the current discard and cleanup guarantees. |
| P1 | Local notification polish | Convert authenticated sync/wake results into “new response” or “approval needed” notifications. Keep relay payloads opaque and avoid putting transcript text in push payloads by default. | FCM wake hint, WorkManager reconciliation, notification channels, approvals API. | Requires a privacy decision, Android notification permission handling, and live relay/FCM validation. |
| P2 | Theme and display polish | System dark mode, compact/comfortable density, clearer status chips, and better empty/error states are cheap quality improvements. | Material 3 Compose shell and existing design tokens. | Do not hide transport/auth/approval states behind decorative UI. |

## Recommended first sprint

Plan these in order:

1. Conversation picker and New chat.
2. Direct-run status and Stop.
3. Explicit retry for failed/indeterminate sends.
4. Routines list/pause/resume, with execution visibly unavailable until the
   host worker blocker is resolved.

This sequence improves everyday usability and safety while requiring minimal
new host functionality. Notifications should follow once the relay is live.

## Defer for a later milestone

These are valuable but are not low-hanging fruit:

- Full Hermes Live foreground execution and token/tool streaming.
- Broad session/workspace dashboard parity.
- Multi-server switching with independent auth/session lifecycles.
- Checkpoints, rollback, Git stage/commit/push, and system/ops controls.
- Group consensus cards, deliverable export, and rich shared-room UX.
- Attachment download/preview until a secure, ownership-checked download
  contract exists.
- Routine execution until the canonical host executor and worker lifecycle are
  supplied.

## Non-negotiable constraints

- Keep the mobile API under `/mobile/v1/*`; do not import dashboard, PTY, or
  JSON-RPC routers into the mobile listener.
- Preserve Cloudflare Access validation, approved-device binding, short-lived
  device tokens, DPoP replay protection, profile/scope allowlists, and rate
  limits.
- Keep server identifiers opaque and instance/profile scoped. Never use display
  labels as routing or authorization identifiers.
- All side-effecting mutations need durable idempotency and explicit handling
  for uncertain or indeterminate outcomes.
- Sensitive settings and approvals continue to require host authorization and a
  local biometric/device-credential step-up.
- Do not put transcript text, credentials, URLs, profile scopes, or tokens in
  relay payloads or logs.
- Do not add real Cloudflare domains, VM addresses, OAuth client values, FCM
  values, signing keys, access tokens, or test conversations to a public
  repository.
- Preserve upstream and dependency license notices before any public release.

## Required output from the next planning session

The next session should return a plan, not implementation. The plan must:

1. Inspect the current checkout and verify each candidate's existing API,
   repository, state, and UI foundations.
2. Select a milestone order and explain trade-offs.
3. Name the expected files/classes/modules to change.
4. Define state transitions and failure/retry behavior for each mutation.
5. Define Android unit/UI/contract tests and host-side tests.
6. Identify features that need a backend change, live VM test, Firebase/relay
   setup, or Android-toolchain validation.
7. Include security, privacy, accessibility, offline/reconnect, and migration
   considerations.
8. Provide acceptance criteria and a release checklist for a debug APK and a
   later signed GitHub release.
9. Call out blockers explicitly, especially the routine worker, canonical
   settings adapter, Android build toolchain, live enrollment, and independent
   review.

## Copy/paste prompt for the planning session

```text
Read docs/MOBILE-FEATURE-CANDIDATES.md and the current repository before doing
anything else. Create an implementation plan only; do not edit code yet.

Verify the existing Android and Python mobile contracts, then rank and scope the
P0/P1 feature candidates. Prefer work that reuses existing typed APIs and Room
state. For every proposed change, include files/classes, API contract impact,
state transitions, idempotency/retry behavior, security and privacy controls,
tests, accessibility checks, live-environment dependencies, acceptance criteria,
and rollback notes. Keep the `/mobile/v1/*` least-privilege boundary and do not
expose dashboard/RPC functionality. Treat routine execution, canonical host
settings, Android build/signing, live enrollment, and independent review as
separate gates. Stop after presenting the plan for approval.
```
