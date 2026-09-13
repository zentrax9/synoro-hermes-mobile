# Hermes Mobile — release dossier

**Release status:** INCOMPLETE — NOT READY

This dossier is the repository-level release record for the Hermes Mobile R1 implementation.
The detailed design, threat model, test matrix, deployment runbook, and review proof remain in
[`docs/`](docs/).

## Required ownership and risk fields

These values are deliberately unassigned rather than inferred:

- **Project owner:** UNASSIGNED — supply the approved GitHub identity.
- **Support contact:** UNASSIGNED — supply the approved support email or identity.
- **Formal risk tier:** NOT RECORDED — run the applicable risk-classification review.
- **Independent reviewer:** UNASSIGNED — must be distinct from owner and support contact.
- **Approvals:** NOT RECORDED — obtain the approvals required by the eventual risk tier.

Until these fields are completed, this file does not grant release approval.

## Scope and data

Hermes Mobile is a typed Android client for operator-allowlisted Hermes profiles. The mobile
surface is a separate `/mobile/v1/*` FastAPI application with Cloudflare Access plus approved
device-proof authentication, opaque profile/object identifiers, durable synchronization, bounded
attachments, approvals, groups, routines, settings, and a fixed-contract push relay.

Conversation text, drafts, transcripts, attachments, device identity, Access claims, device
tokens, and audit metadata are sensitive data. The implementation and handling evidence is in
[`docs/PROJECT.md`](docs/PROJECT.md) and [`docs/security/hermes-mobile-threat-model.md`](docs/security/hermes-mobile-threat-model.md).

## Evidence anchor

- **Branch:** `codex/hermes-mobile-r1`
- **HEAD:** `693641aa8b4359c602283bdbbc14041e03bc47bc`
- **Working tree:** dirty; the implementation is not commit-sealed.
- **Local Python gate:** `169 passed, 1 skipped, 0 failed in 24.2s` on 2026-09-08. The skipped
  attachment symlink case requires host capability unavailable on this Windows machine.
- **Static checks:** Ruff, compileall, and `git diff --check` pass.

## Live deployment boundary

No UGREEN VM, Cloudflare Access/Tunnel, OAuth client, GCP/Firestore/FCM project, relay image,
Android signing key, hostname, audience, or device enrollment coordinates are recorded here.
A read-only UGREEN inspection on 2026-09-08 found VM `ubuntu26` running the deployed `main`
checkout at `f98f5e74`; Hermes exposed only its Unix gateway socket, with no mobile HTTP listener.
This is evidence of the current deployment boundary, not a passing deployment gate.
The coordinate-driven procedure is [`docs/deployment/hermes-mobile-ugreen-vm.md`](docs/deployment/hermes-mobile-ugreen-vm.md).
No live deployment, Android build/signing, device test, or independent review is claimed.

## Release blockers

1. Bind the explicit routine worker seam to the operator’s trusted host routine executor.
2. Define and implement the canonical host-backed profile settings adapter and confirm profile
   lifecycle policy (create/clone/archive).
3. Validate the implemented three-round/ten-response group contract against the operator's
   expected host executor behavior and live route.
4. Provide the live VM/Cloudflare/GCP/Firebase/signing coordinates and execute the deployment and
   revocation gates.
5. Run the Android toolchain, skipped symlink case, dependency/static checks, accessibility checks,
   and independent review; then seal the review proof from a clean commit.

See [`docs/PROJECT.md`](docs/PROJECT.md), [`docs/TEST-SCENARIO.md`](docs/TEST-SCENARIO.md), and
[`docs/REVIEW-PROOF.md`](docs/REVIEW-PROOF.md) for the full gate matrix and evidence.
