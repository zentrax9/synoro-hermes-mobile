# Synoro Hermes Mobile Android client

This is the secure R1 Android client for Synoro Hermes Mobile. It contains the typed API transport,
durable profile-scoped cursor reconciliation, encrypted Room/DataStore state, resumable attachment
primitives, loopback PKCE, device-proof authentication, WorkManager wake handling, an app-private
AAC-LC/M4A voice recorder, and a Compose shell for the bot roster, transcript cards, groups,
settings, approvals, drafts, attachments, and voice-note affordances. The roster, durable sync,
canonical conversation loading, direct messages, encrypted resumable attachment upload, and
server-bound approval step-up cards now use the typed client with session restore and explicit
  idempotency records. The Settings screen includes the PKCE/host-approval enrollment hand-off;
  the release build must supply installation-specific OAuth/tunnel coordinates through `BuildConfig`.
  The settings transport uses revision/ETag guarded writes and encrypted idempotency records;
  persona changes require a fresh host step-up challenge and BiometricPrompt/device-credential
  authentication. The current checkout still needs the operator-owned host settings adapter
  before those writes can be treated as canonical Hermes profile state.
  The Groups screen now exposes typed create, refresh, add/remove, message, and stop controls with
  instance-origin labels and the same durable idempotency contract as direct chat. An opaque group
  reference is retained in Room so process restart can re-fetch server-owned membership; the
  direct composer draft is encrypted and persisted per instance/profile/conversation; the
  foreground chat now consumes the profile-scoped SSE stream and reopens it from the durable
  cursor after disconnect or cursor expiry, and renders the last encrypted conversation snapshot
  when a transient host failure prevents a refresh; group references are reconciled through the
  owner/device-scoped host group-list snapshot as well as the cached per-group fallback. The
  snapshot exposes `has_more` and an installation-bound `next_cursor` for bounded pages; Android
  follows every cursor and only reconciles its cache after the complete snapshot is assembled.
  Structured HTTP(S) links open only through a safe Custom Tab, and transcript approval chips route
  through the same biometric/device-credential step-up flow as the approvals panel.

## SDK and dependency choices

- `minSdk = 28` (Android 9).
- `compileSdk = 36` and `targetSdk = 36` (Android 16, current stable API at the time this
  foundation was created).
- Android Gradle Plugin `8.9.2`, Gradle wrapper distribution `8.11.1`, Kotlin `2.1.20`, and
  KSP `2.1.20-1.0.32`.
- Compose BOM `2025.05.00`, Hilt `2.56.2`, Room `2.7.1`, DataStore `1.1.7`, OkHttp `4.12.0`,
  AndroidX Browser `1.8.0`, AndroidX Biometric `1.1.0`, kotlinx.serialization `1.8.1`, coroutines
  `1.10.2`, WorkManager `2.10.1`, and Media3 `1.6.1`.
- All direct dependencies are exact versions in `gradle/libs.versions.toml`. Gradle dependency
  verification is strict (`org.gradle.dependency.verification=strict`), and release checks refuse
  to run until `gradle/verification-metadata.xml` contains SHA-256 entries for the resolved graph.
  On an Android-enabled host, generate and commit that file with:

  ```text
  .\gradlew.bat --write-verification-metadata sha256 dependencies
  ```

  The wrapper distribution is pinned by URL and SHA-256 in
  `gradle/wrapper/gradle-wrapper.properties`; the wrapper scripts and JAR are checked in so CI
  does not depend on a machine-global Gradle installation.

The API 36 choice follows the Android Developers setup guidance and target-API requirements:

- https://developer.android.com/about/versions/16/setup-sdk
- https://developer.android.com/google/play/requirements/target-sdk

The DPoP shape follows [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), including the
query/fragment-free `htu` target URI normalization and the `ath` hash of the short-lived Hermes
device token carried in `X-Hermes-Device-Token`.

## Security invariants

- Release network configuration rejects cleartext and trusts only system CAs. No debug CA override
  is present in the release configuration.
- Only `INTERNET`, `POST_NOTIFICATIONS`, and `RECORD_AUDIO` are declared. The microphone is
  requested at the explicit record tap; camera/storage permissions remain absent and the Photo
  Picker/SAF path is used for files.
- Room rows use instance/profile/conversation composite keys for conversation data. Message,
  draft, filename, attachment-reference, token-like, and OAuth transaction values are stored only
  as encrypted blobs; queryable IDs, revisions, timestamps, and delivery states remain
  non-sensitive metadata.
- AES-256-GCM values are backed by an Android Keystore key. Background and user-authenticated
  P-256 signing keys are non-exportable. A Keystore invalidation is surfaced as an unreadable
  cache condition for wipe-and-reauth handling.
- All backup and device-transfer domains are explicitly excluded. `FLAG_SECURE` is enabled before
  the first frame; the preference repository exposes the future user-configurable opt-out.
- Mutating typed mobile requests require an `Idempotency-Key`. The request factory permits only
  `/mobile/v1/*` paths, requires HTTPS, and binds Cloudflare, Hermes-device, and per-request DPoP
  headers when authenticated material is supplied.
- DPoP is generated as an ES256 JWT per request. Its public JWK comes from the non-exportable
  background P-256 Keystore key; `htm`, normalized `htu`, `iat`, unique `jti`, signed per-proof
  `nonce`, explicit `request_id` (equal to the replay-keyed `jti`), and the SHA-256 `ath` of the
  exact Hermes device token are all signed. Android DER ECDSA output is converted to JOSE
  fixed-width `R || S` bytes.
- Authorization Code + PKCE S256 starts in an external Custom Tab only after an OS-selected
  `127.0.0.1` loopback listener is bound. The listener accepts exactly one callback, validates the
  exact state/issuer/resource/redirect tuple and Host header, then closes. PKCE transactions are
  serialized and AES-GCM encrypted before launch.
- Picker-selected files can be streamed into `filesDir/staged_uploads` as AES-GCM ciphertext with
  an encrypted Room metadata row. Opaque upload IDs, atomic temp-to-final moves, process-death
  orphan cleanup, 25 MB bounds, no-follow symlink checks, full AES-GCM/tag plus SHA-256
  verification before plaintext reaches the network, and explicit completion/cancellation deletion
  are provided.
- Voice notes use AAC-LC/M4A, are capped at ten minutes, remain app-private while recording, and
  must be previewed or discarded before the encrypted attachment staging/upload flow.
- Sensitive approvals and settings prefer `BiometricPrompt` with `BIOMETRIC_STRONG` plus
  `DEVICE_CREDENTIAL`; if the platform reports no supported authenticator, the app falls back to
  the system Keyguard confirmation intent. The non-exportable user-authenticated P-256 key remains
  enforced by Keystore in either path.
- The Android editor currently exposes the bounded safe fields `display_name`, `title`, `avatar`,
  and the host-defined `notification_preferences.enabled` flag. `privacy_preferences` and
  `approval_policy` remain read-only because their object schemas and weakening rules belong to the
  host. Sensitive `model`, `provider`, `reasoning`, and `skills` are intentionally not edited until
  host allowlists have a schema-specific UI; routines are not a settings field.
- `SyncWorker` treats push as a wake hint and reconciles through the authenticated, profile-scoped
  cursor API. The central relay implementation is in `services/mobile_push_relay/`; Firebase
  token registration is intentionally kept out of the Hermes host. `HermesFirebaseMessagingService`
  stores token material encrypted and only schedules reconciliation. Background system-rendered
  notifications carry a fixed `hermes_sync_wake=1` marker; opening one triggers both WorkManager
  and an authenticated foreground cursor refresh because Android may bypass
  `onMessageReceived` for notification payloads. A Firebase project ID,
  Android application ID, API key, and sender ID are injected through `BuildConfig` by the release
  environment rather than committed to this repository; `FirebaseRuntime` disables push cleanly
  when those coordinates are absent or invalid. The relay payload
  intentionally carries no profile scope, and the client ignores any scope-looking FCM fields;
  every wake reconciles all locally approved targets through profile-scoped API calls. The wake
  hint is never an authorization decision. Devices without Google Play Services continue using
  foreground/in-app reconciliation.

## Local verification

From this directory, once JDK 17 and the Android SDK platform/build tools for API 36 are installed
(the checked-in wrapper supplies Gradle 8.11.1):

```text
.\gradlew.bat testDebugUnitTest
.\gradlew.bat lintDebug
```

For the first device build, `build-debug.ps1` performs the JDK/SDK and HTTPS-coordinate
preflight, bootstraps the missing SHA-256 dependency-verification metadata, invokes
`assembleDebug`, and prints the APK path plus SHA-256 checksum. Pass the installation-specific
public coordinates explicitly. The script does not persist those coordinates; it does create
`gradle/verification-metadata.xml` when needed, which must be reviewed and committed:

```powershell
.\build-debug.ps1 `
  -MobileBaseUrl "https://mobile.example" `
  -CloudflareIssuer "https://team.cloudflareaccess.com" `
  -CloudflareResource "https://mobile.example" `
  -OAuthClientId "managed-oauth-client-id" `
  -OAuthAuthorizationEndpoint "https://team.cloudflareaccess.com/cdn-cgi/access/oauth/authorization" `
  -OAuthTokenEndpoint "https://team.cloudflareaccess.com/cdn-cgi/access/oauth/token"
```

The debug helper is only a build convenience; it does not perform enrollment, host approval,
release signing, or push setup. Keep the OAuth client ID in local shell history or a protected
secret store according to the installation's policy, and never paste access or refresh tokens into
logs or support messages.

The release gate requires installation-specific coordinates and an external release keystore.
Pass the public coordinates as Gradle properties; they are build configuration, not Hermes
secrets and therefore are intentionally not new `HERMES_*` environment/config settings. Keep
the release keystore path/passwords in the CI secret store (or equivalent local environment)
without committing them:

```text
$env:HERMES_RELEASE_KEYSTORE = "<secret-store-path-to-keystore>"
$env:HERMES_RELEASE_STORE_PASSWORD = "<secret-store-value>"
$env:HERMES_RELEASE_KEY_ALIAS = "<secret-store-value>"
$env:HERMES_RELEASE_KEY_PASSWORD = "<secret-store-value>"
.\gradlew.bat verifyReleaseGate assembleRelease `
  -Phermes.mobileBaseUrl=https://mobile.example `
  -Phermes.cloudflareIssuer=https://example.cloudflareaccess.com `
  -Phermes.cloudflareResource=https://mobile.example `
  -Phermes.oauthClientId=installation-client-id `
  -Phermes.oauthAuthorizationEndpoint=https://example.cloudflareaccess.com/authorize `
  -Phermes.oauthTokenEndpoint=https://example.cloudflareaccess.com/oauth2/token `
  -Phermes.firebaseProjectId=firebase-project-id `
  -Phermes.firebaseApplicationId=1:123456789:android:abcdef0123456789 `
  -Phermes.firebaseApiKey='<firebase-api-key>' `
  -Phermes.firebaseSenderId=123456789
```

`verifyReleaseGate` checks the five HTTPS coordinates, the OAuth client ID, and the four Firebase
application coordinates (including their scalar formats), requires an origin-only mobile base URL,
a non-debuggable release build and
an explicitly configured non-debug keystore, verifies dependency metadata, emits a SHA-256 report
at `app/build/reports/dependencies/release-runtime.sha256`, and emits a deterministic CycloneDX
1.5 SBOM at `app/build/reports/sbom/release.cdx.json`. `assembleRelease` finalizes with
`verifyReleaseArtifact`, which runs Android SDK `apksigner verify --verbose --print-certs` and writes
`app/build/outputs/apk/release/app-release.apk.sha256`. Set the `-Phermes.apksigner=<path>` Gradle
property when the SDK is not under `ANDROID_SDK_ROOT`/`ANDROID_HOME`.

The current build host has none of `java`, `gradle`, `kotlinc`, `adb`, `sdkmanager`, `apksigner`,
or an Android SDK, so Android compilation, dependency resolution, metadata generation, SBOM
generation, and APK signature verification were not runnable here. The pure contract/security
tests remain under `app/src/test` and are ready for the first Android-enabled CI run. Do not claim
a reproducible release build until CI has generated and committed
`gradle/verification-metadata.xml`, supplied real installation coordinates and release-signing
custody, and recorded the `apksigner`/checksum output.

Before producing a release APK, replace the placeholder values for `MOBILE_BASE_URL`,
`CLOUDFLARE_ISSUER`, `CLOUDFLARE_RESOURCE`, `OAUTH_CLIENT_ID`,
`OAUTH_AUTHORIZATION_ENDPOINT`, `OAUTH_TOKEN_ENDPOINT`, `FIREBASE_PROJECT_ID`,
`FIREBASE_APPLICATION_ID`, `FIREBASE_API_KEY`, and `FIREBASE_SENDER_ID` in the release build
configuration.
The app deliberately refuses to begin enrollment while any placeholder remains, and
`verifyReleaseConfiguration` fails `preReleaseBuild` until all ten are supplied. Values can be
provided without committing them using the matching `-Phermes.*` Gradle properties. Only
release-signing secrets and the host push-relay credential use `HERMES_*` secret variables.
