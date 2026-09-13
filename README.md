# Synoro Hermes Mobile

Synoro Hermes Mobile is a standalone, self-hosted mobile control plane for a Hermes Agent
installation. It combines a profile-scoped host API, a secure Android client, and an optional
push relay so an approved phone can monitor and operate Hermes from anywhere.

This repository is an independent project built on the open-source
[Hermes Agent](https://github.com/NousResearch/hermes-agent) codebase. It is not an official
Nous Research distribution. The upstream MIT license and attribution are retained in
[`LICENSE`](LICENSE).

## What is included

- **Host mobile API** — a separate `/mobile/v1/*` surface for conversations, groups, routines,
  approvals, settings, attachments, and synchronization.
- **Android app** — Jetpack Compose UI with durable offline state, encrypted local storage,
  Authorization Code + PKCE enrollment, device-proof authentication, DPoP-bound requests,
  biometric step-up, resumable attachments, and voice-note support.
- **Web administration** — an authenticated Mobile devices page for listing and revoking devices.
- **Optional push relay** — a fixed-contract Cloud Run/Firestore service that delivers wake hints;
  push never grants access or carries conversation content.
- **Deployment and security evidence** — design, threat-model, test, review, and UGREEN VM
  runbooks under [`docs/`](docs/).

## Current status

The implementation is in active development and is **not release-ready**. The remaining release
gates, ownership fields, host integration seams, live deployment coordinates, Android toolchain
evidence, and independent review are tracked in [`PROJECT.md`](PROJECT.md) and
[`docs/REVIEW-PROOF.md`](docs/REVIEW-PROOF.md).

## Repository layout

```text
apps/android/             Android client and Gradle build
hermes_cli/mobile_*.py    Host mobile API and supporting services
services/mobile_push_relay/ Optional push relay
web/src/pages/             Web administration surface
tests/                     Host, relay, and Android contract tests
docs/                      Design, security, deployment, and release evidence
```

## Local host development

Run the mobile listener on loopback while developing:

```bash
python -m hermes_cli.main serve --skip-build \
  --host 127.0.0.1 --port 9119 \
  --mobile-host 127.0.0.1 --mobile-port 9120
```

Do not expose either listener directly to the internet. For the UGREEN VM, systemd and the
Cloudflare Tunnel configuration are documented in
[`docs/deployment/hermes-mobile-ugreen-vm.md`](docs/deployment/hermes-mobile-ugreen-vm.md).

## Android development

The Android project and its security invariants are documented in
[`apps/android/README.md`](apps/android/README.md). With JDK 17 and Android SDK API 36 installed:

```powershell
cd apps/android
.\gradlew.bat testDebugUnitTest
.\gradlew.bat lintDebug
```

Installation-specific OAuth, Cloudflare, Firebase, and signing values are supplied at build or
deployment time. They must not be committed to this repository.

## Verification

The host-side checks can be run from the repository root:

```bash
python -m compileall -q hermes_cli tests/hermes_cli
ruff check hermes_cli tests/hermes_cli
pytest -q tests/hermes_cli tests/mobile_push_relay
```

Android compilation, dependency verification, signing, and device tests require an Android-enabled
CI or development machine. The release checklist must be completed before distributing an APK.

## Security boundary

The mobile listener is intentionally separate from Hermes' dashboard and generic control routes.
Requests are constrained to `/mobile/v1/*`, require Cloudflare Access plus an enrolled device
token, and bind mutations to unique idempotency keys and DPoP proofs. Device revocation is durable;
push notifications are only reconciliation wake hints. Keep VM, Cloudflare, OAuth, Firebase,
relay, and signing coordinates in the deployment secret/configuration store rather than source
control.

## Contributing

Start with [`docs/DESIGN.md`](docs/DESIGN.md), [`docs/TEST-SCENARIO.md`](docs/TEST-SCENARIO.md),
and [`docs/PROJECT.md`](docs/PROJECT.md). Changes affecting the mobile contract should include
host and Android tests and update the relevant security or deployment evidence.

## License

MIT. See [`LICENSE`](LICENSE) and the upstream Hermes Agent project for the original project
license and attribution.
