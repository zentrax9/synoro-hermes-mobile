# Hermes Mobile threat model

Status: implementation gate for the mobile API. The listener must remain disabled until its
authentication and device-trust configuration is complete.

## Security objective

The Android client may reach only a typed, allowlisted mobile API. It must never gain network
access to the dashboard, JSON-RPC dispatch, PTY, console, raw configuration, credentials, or
filesystem APIs. A valid Cloudflare identity is necessary but insufficient: every request also
requires a host-approved device, an unrevoked profile allowlist and scope, and a proof made by the
device key.

## Assets

- Hermes credentials, tool permissions, approval policy, and profile configuration.
- Conversation text, attachments, drafts, transcripts, artifacts, and session metadata.
- Device enrollment records, token signing material, Cloudflare claims, and audit events.
- The integrity of agent turns and external side effects.
- Instance, profile, session, run, group, approval, and attachment isolation.

## Trust boundaries and controls

### 1. Android application

Untrusted inputs include shares, deep links, links, documents, OCR, transcripts, notification
payloads, cached database rows, and bot output. Tokens and message content are encrypted at rest
with Keystore-backed keys and excluded from backup and device transfer. Normal requests use a
non-exportable background P-256 key. Approvals and authority-expanding settings require a distinct
user-authenticated key. Losing either key invalidates the local cache and requires enrollment.

### 2. Cloudflare Access and Tunnel

Cloudflare authenticates the user and terminates the public connection, but its bearer credential
is replayable. The origin validates the Access JWT signature, exact issuer, installation-specific
audience, expiry, and identity against rotating JWKS. Forwarded and `Cf-Access-*` headers are
trusted only from the loopback tunnel peer. Every installation has a separate Access application
and audience. Cloudflare authentication never substitutes for device proof.

### 3. Mobile listener

The listener is a distinct FastAPI application on loopback port 9120. Its module does not import or
mount dashboard or JSON-RPC routers. It has no CORS or cookie authentication. Every route requires
Cloudflare identity plus an approved device token and proof, followed by route scope and object
authorization. Unknown or cross-scope opaque IDs return 404. Side-effecting mutations require an
idempotency key and bounded actor/action rate limits.

### 4. Hermes core

The API calls typed services; clients cannot supply method names, paths, working directories,
gateway URLs, tool names, or credential selectors. Profiles are state partitions, not security
sandboxes. Profiles with sensitive credentials require a separate terminal sandbox or OS/container
identity. Content originating outside the host remains data with provenance and is never promoted
to system or developer instructions.

### 5. Push relay

Hermes sends only a fixed event type, opaque event ID, registered device handle, and expiry to the
relay. The relay maps these to static generic text, deduplicates event IDs, and stores no prompts,
responses, URLs, file metadata, or credentials. Workload Identity obtains FCM authority. A push is
only a wake hint; authenticated synchronization is the source of truth.

## Principal threats and required mitigations

| Threat | Mitigation and verification |
| --- | --- |
| Dashboard/RPC exposure through a routing mistake | Separate ASGI app and port; enumerate the live route table and route-scan forbidden paths. Tunnel only to 9120. |
| Stolen Cloudflare bearer replay | Five-minute device token bound to a P-256 key; method/URL/per-proof nonce/time/request-ID proof (the request ID is the durable replay-keyed DPoP `jti`); replay cache; immediate token revocation and heartbeat-bounded SSE termination. |
| Forged proxy headers or wrong Access application | Accept proxy headers only from loopback; verify JWT signature, issuer, audience and expiry; test forged headers and cross-audience tokens. |
| Broken object-level authorization | Opaque random IDs and authorization on `{device, instance, profile}` for every lookup and mutation; fuzz cross-profile and cross-instance IDs. |
| Privilege expansion disguised as settings | Server-owned scope/profile/model/tool allowlists; mobile cannot weaken approval policy; biometric step-up for sensitive writes. |
| Duplicate or uncertain external side effects | Persist idempotency key and request digest before execution; transactional run states; crash uncertainty becomes `indeterminate`, never automatic resubmission. |
| SSE gaps or process-local replay loss | Persist semantic events with a monotonic cursor; backlog then live tail; 410 on expired cursor; full reconciliation. |
| File parser abuse and path traversal | Owned resumable uploads, fixed chunks and quotas, hash/MIME/size verification, no client paths/symlinks/archive extraction, bounded parsers. |
| SSRF or unsafe link dispatch | No server-side preview in v1; allow only HTTP(S) Custom Tabs; host egress blocks local, private, link-local, ULA, and metadata ranges unless explicitly allowed. |
| Prompt injection through external content or bot messages | Preserve server-generated provenance; keep content in data messages; never concatenate into privileged instructions. |
| Sensitive push or backup leakage | Generic fixed notifications; no transcript payloads; explicit Android backup/transfer exclusions; reconciliation after restore/token changes. |
| Resource exhaustion | Limits by authenticated user, device, profile, and action; bounded uploads, SSE connections, parser CPU/memory/time, and group rounds. |

## Fail-closed invariants

1. Missing or invalid Access configuration prevents an authenticated mobile request.
2. Missing device authorization returns 401; insufficient scope returns 403; foreign objects return 404.
3. Authentication, authorization, replay-store, and audit-store errors deny the request.
4. Revocation invalidates refresh and session tokens and terminates active streams.
5. A process restart does not submit, retry, or continue an externally effectful run unless its
   durable state proves that transition is safe.
6. Credentials, full identifiers, message bodies, attachment names, and tokens never enter logs or
   push payloads.

## Implementation status and release gate

The isolated application now includes the typed profile, conversation, group, run, attachment,
settings, routine, approval, device, durable-sync, and push-wake routes. Its test authorizer is
available only for local contract tests; production startup requires Cloudflare issuer/audience
configuration and a host-approved device proof. Android transport, encrypted persistence, sync,
push wake handling, voice staging, the Compose information architecture, bounded safe settings,
biometric step-up, and the PKCE/device-code enrollment hand-off are present. The authenticated
dashboard also exposes the host device registry and immediate revocation. The release gate still
requires an Android-enabled build, real Access/tunnel coordinates, host-specific schemas for
privacy/policy/model/routine controls that are intentionally not guessed by the client, and an
operator-approved device enrollment.

## Operator inputs still required

- Exact VM deployment type, source revision, and SSH route.
- Cloudflare team domain, per-installation Access application audience, hostname, and tunnel.
- Initial profile allowlist and `chat` scope policy.
- Android application ID, supported test devices, and release-signing custody.
- GCP/Firebase projects and workload identities for the central push relay.
