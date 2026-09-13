# Android Studio handoff — Synoro Hermes Mobile

This file is the resume point for the next PC. The canonical source is the `main` branch of
[`zentrax9/synoro-hermes-mobile`](https://github.com/zentrax9/synoro-hermes-mobile). The repository
contains the current host implementation, Android client, relay, tests, and release evidence.
The implementation is committed, but it is **not release-ready** until the checks below are run on
an Android-enabled machine and the remaining host/deployment gates are completed.

## What is already implemented

### Host and web

- A separate `/mobile/v1/*` FastAPI surface with route isolation from the dashboard, PTY, files,
  configuration, and generic RPC routes.
- Cloudflare Access JWT validation, host-approved device enrollment, short-lived device tokens,
  device revocation, DPoP/device proofs, scoped profiles, and rate limits.
- Durable SQLite/WAL state for conversations, cursor/SSE sync, operations, attachments, approvals,
  groups, routines, settings, and push-registration metadata.
- Idempotency and restart fencing for direct runs, Stop, retries, cancellation, groups, routines,
  settings, and attachments; uncertain external effects stay `indeterminate` instead of replaying
  automatically.
- Authenticated web **Mobile devices** administration with immediate revoke.
- Optional fixed-contract Cloud Run/Firestore push relay. FCM is only a wake hint and never an
  authorization decision or a carrier for transcript content.

### Android

- Jetpack Compose app under `apps/android/` with roster, conversations, drafts, groups, routines,
  approvals, settings, attachments, voice-note staging, and offline snapshot recovery.
- Authorization Code + PKCE through an external Custom Tab and a one-shot loopback callback.
- Encrypted Room/DataStore state, Android Keystore device keys, DPoP proofs, biometric/device-
  credential step-up, durable idempotency records, and WorkManager cursor reconciliation.
- Gradle wrapper and pinned dependency versions are checked in. The project uses min SDK 28,
  compile/target SDK 36, AGP 8.9.2, Gradle 8.11.1, and Kotlin 2.1.20.

## Start on another PC

1. Install Android Studio and use its bundled JDK, or install JDK 17 or newer. In Android Studio,
   set **Settings → Build Tools → Gradle → Gradle JDK** to that JDK.
2. In SDK Manager install **Android SDK Platform 36**, Android SDK Build-Tools, and Platform Tools.
   Create an emulator or enable USB debugging on a test phone. Do not commit `local.properties`.
3. Clone the standalone repository and open the Android Gradle project (open `apps/android`, not
   the repository's Python root):

   ```powershell
   git clone https://github.com/zentrax9/synoro-hermes-mobile.git
   cd synoro-hermes-mobile
   git switch main
   cd apps/android
   .\gradlew.bat --version
   ```

4. Let Android Studio sync. Dependency verification is intentionally strict. This checkout does
   not yet contain `gradle/verification-metadata.xml`; on the Android-enabled PC generate it once,
   review the diff, and commit it:

   ```powershell
   .\gradlew.bat --write-verification-metadata sha256 dependencies
   ```

5. Run the local Android checks:

   ```powershell
   .\gradlew.bat testDebugUnitTest
   .\gradlew.bat lintDebug
   ```

   Record the output and update the pending Android rows in
   [`TEST-SCENARIO.md`](TEST-SCENARIO.md). The publishing PC could not run these commands because
   it had no `java`, Gradle, Android SDK, `adb`, or `kotlinc`.

## Build and install a debug APK

Use real installation coordinates only on the local machine or a protected build environment. Do
not commit them, `google-services.json`, Firebase credentials, OAuth tokens, or signing material.
The debug helper validates HTTPS and origin relationships before invoking Gradle:

```powershell
.\build-debug.ps1 `
  -MobileBaseUrl "https://<mobile-host>" `
  -CloudflareIssuer "https://<team>.cloudflareaccess.com" `
  -CloudflareResource "https://<mobile-host>" `
  -OAuthClientId "<managed-oauth-client-id>" `
  -OAuthAuthorizationEndpoint "https://<team>.cloudflareaccess.com/cdn-cgi/access/oauth/authorization" `
  -OAuthTokenEndpoint "https://<team>.cloudflareaccess.com/cdn-cgi/access/oauth/token"
```

The script produces `app/build/outputs/apk/debug/app-debug.apk` and prints its SHA-256. Install it
on an attached test device after the build succeeds:

```powershell
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

For a local-only compile without live enrollment, use the Gradle wrapper directly. The app refuses
to begin enrollment when required coordinate placeholders remain, so the configured debug build
is the meaningful end-to-end check.

## First live enrollment test

1. Confirm the VM listener is loopback-bound on port 9120 and the Cloudflare Tunnel exposes only
   the dedicated mobile hostname. Follow [`deployment/hermes-mobile-ugreen-vm.md`](deployment/hermes-mobile-ugreen-vm.md);
   never expose the dashboard or mobile listener directly.
2. Launch the APK and start enrollment. Complete the Cloudflare Access managed OAuth flow in the
   Custom Tab. The app then calls the host enrollment endpoint and displays a one-time enrollment
   code.
3. On the VM approve that code with the smallest required profile/scope allowlist:

   ```text
   hermes mobile devices approve <enrollment-code> \
     --profiles <host-profile> \
     --scopes chat groups attachments settings:read settings:write:safe approvals routines:control
   ```

4. Return to the app, verify capabilities and profile loading, then test one non-production chat,
   one Stop/retry path, cursor reconnect, attachment cleanup, and device revoke. Revoke the test
   device from the web Mobile devices page or the CLI and verify the token and stream are rejected.
5. Record live results in `TEST-SCENARIO.md`; do not copy hostname, Access audience, client ID,
   Firebase values, relay tokens, or VM credentials into source control.

## Remaining implementation/release work

These are the current blockers, not Android Studio installation steps:

1. Bind the explicit routine-worker seam to the operator's trusted Hermes routine executor.
2. Implement the canonical host-backed profile-settings adapter and confirm profile lifecycle
   policy (create/clone/archive); the current settings store is a mobile shadow until then.
3. Validate the group three-round/ten-response contract against the real host executor and route.
4. Run Android unit tests, lint, debug build/install, the skipped attachment-symlink case on a
   capable host, and accessibility/recovery checks.
5. Generate and review `gradle/verification-metadata.xml`; for release, supply the approved
   Firebase coordinates and external signing keystore, then run `verifyReleaseGate assembleRelease`
   and record `apksigner` plus APK checksum evidence.
6. Execute the VM, Cloudflare Access/Tunnel, device enrollment/revocation, and (if used) immutable
   Cloud Run/Firestore relay checks with installation-specific coordinates kept out of Git.
7. Fill in the owner, support contact, formal risk tier, approvals, and independent reviewer;
   replace the draft [`REVIEW-PROOF.md`](REVIEW-PROOF.md) with a clean, reviewer-sealed proof.

The detailed status matrix is [`../PROJECT.md`](../PROJECT.md) and [`PROJECT.md`](PROJECT.md).
The threat model and deployment runbook are normative for security and operator setup.

## Definition of done for the Android PC

- Gradle sync succeeds with JDK 17+ and SDK API 36.
- `gradle/verification-metadata.xml` is generated, reviewed, and committed.
- `testDebugUnitTest` and `lintDebug` pass with captured output.
- A coordinate-configured debug APK builds, installs, and completes OAuth/enrollment/host approval.
- At least one direct chat, Stop/retry, reconnect, attachment, routine/group, and revoke flow is
  exercised against a non-production installation.
- Test evidence and any newly discovered failures are recorded before attempting a release build.
