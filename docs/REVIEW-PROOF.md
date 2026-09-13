# Review Proof — Hermes Mobile R1  (tier UNSET, verdict INCOMPLETE, 2026-09-08)

> **UNSEALED DRAFT — not a reviewer approval.** This file records the evidence available during
> an agent-prepared implementation pass. The tree is dirty, the root `PROJECT.md` has unassigned
> risk and ownership fields, and no independent reviewer supplied an attestation. A real
> `/vibe-review` must overwrite this draft from the reviewer's own clean checkout and bind the
> result to a sealing commit.

## Summary

- **Tool / repo name:** Hermes Mobile R1 (`NousResearch/hermes-agent` checkout)
- **Risk tier:** `UNSET` — formal risk assessment was not run; root `PROJECT.md` records it as unassigned
- **Verdict:** `INCOMPLETE` — not approved for release
- **Sealed date:** `Not sealed`
- **Evidence date:** `2026-09-08`

The local Python mobile suite is evidence of implementation-level behavior only. It is not evidence
of Android build/signing, live Cloudflare/VM operation, Cloud Run/Firestore/FCM deployment, device
enrollment, or release approval.

## Reviewer

- **Reviewer name:** Not provided
- **Reviewer email:** Not provided
- **Independence basis:** Cannot be resolved. Root `PROJECT.md` has no assigned `Project Owner` or
  `Support Contact`, and no `vibe-release.json` was supplied. The detailed dossier also keeps both
  fields explicitly unresolved (`docs/PROJECT.md:61-70`).
- **Independence result:** `UNDETERMINED`
- **Observations:** This draft was prepared by an agent, not by an independent human reviewer. No
  `git config`/GitHub identity comparison was performed, and no reviewer may self-supply the missing
  exclusion set.

## Reviewed commit

- **Reviewed commit:** `693641aa8b4359c602283bdbbc14041e03bc47bc`
- **Commit date:** `2026-09-07T02:50:45+05:30`
- **Tree state:** dirty (`git status --short` lists mobile implementation, Android, relay, tests,
  dashboard, and documentation changes). This draft is not commit-bound.

## Checklist Results

| id | check | applies | result | verified-by | evidence / note |
|---|---|---|---|---|---|
| `requirements-met` | The tool meets the owner's requirements | Unknown tier | NEEDS-HUMAN | human | The implementation and pasted release requirements are documented, but no owner acceptance or PRD was supplied. See `docs/PROJECT.md:23-54`. |
| `main-function-tested` | Main functionality tested with realistic input | Unknown tier | NEEDS-HUMAN | agent + human | Python mobile/relay tests: 169 passed, 1 skipped. `docs/TEST-SCENARIO.md` still has three High and three Medium scenarios pending, including Android and live deployment. |
| `correct-data` | Correct intended data sources are used | Medium/High | NEEDS-HUMAN | agent + human | Code-level stores and host-owned allowlists are evidenced, but no production data source or live profile policy was supplied. |
| `no-sensitive-in-ai` | No sensitive data in prompts, samples, logs, or source | Any | NEEDS-HUMAN | agent + human | Threat-model invariants exist (`docs/security/hermes-mobile-threat-model.md:80-88`), but the full repository scan and reviewer confirmation were not run here. |
| `no-secrets` | No passwords, tokens, or secret keys in code/config | Any | NEEDS-HUMAN | agent + human | Coordinates use placeholders and deployment inputs, but a complete never-log/secret scan was not performed for this draft. |
| `access-restricted` | Access is restricted to intended users only | Medium/High | NEEDS-HUMAN | agent + human | Local tests cover Access/device proof and route isolation; live tunnel, audience, header, and enrollment checks were not run. |
| `approved-storage` | Code is in approved company storage | Medium/High | FAIL | agent | `git remote -v` is `https://github.com/NousResearch/hermes-agent.git`, not the checklist's required `github.com/gdncomm-ops` remote. Owner must resolve repository-storage policy before release. |
| `rollback-possible` | Previous working version can be restored | Medium/High | NEEDS-HUMAN | agent + human | Current branch/commit are known, but no release tag, saved release branch, or tested rollback procedure was evidenced. |
| `support-defined` | Owner and support contact are defined in required formats | Medium/High | FAIL | agent | Root `PROJECT.md` exists, but both owner and support fields remain unresolved (`PROJECT.md:9-14`; `docs/PROJECT.md:61-70`). |
| `approvals-complete` | Required formal approvals are complete | High | NEEDS-HUMAN | human | No risk tier or formal Architecture, SRE, Information Security, or owner approvals were supplied. |

### Engineering evidence captured

Command run from the repository root on 2026-09-08:

```powershell
$mobileTests = Get-ChildItem tests/hermes_cli -Filter 'test_mobile_*.py' -File |
  Select-Object -ExpandProperty FullName
$relayTests = Get-ChildItem tests/mobile_push_relay -Filter 'test_*.py' -File |
  Select-Object -ExpandProperty FullName
$files = (($mobileTests + $relayTests) -join ';')
& .venv\Scripts\python.exe scripts/run_tests_parallel.py --files $files -q -rs
```

Result: **169 passed, 1 skipped, 0 failed in 24.2s**. The skip is the attachment symlink case
(`tests/hermes_cli/test_mobile_attachments.py:244`) because symlink creation is unavailable on
this host.

Not run: Android `gradle testDebugUnitTest`, `gradle lintDebug`, `gradle assembleRelease`; VM and
Cloudflare verification; live forbidden-route scan; operator enrollment/revocation; relay
`deploy.sh`; relay `check_cloud_run.sh`; release signing; physical-device tests; and independent
human review. The Android README explicitly records the missing local toolchain
(`apps/android/README.md:90-110`).

A read-only UGREEN UI probe did find `ubuntu26` running deployed `main` at `f98f5e74`, but only
the Unix Hermes gateway socket was listening; no mobile HTTP listener or deployment proof was
available, so TS-013 remains pending.

## Outstanding Items

1. Bind the explicit host-owned routine worker seam to the operator's existing routine executor in
   startup; the worker/state-machine tests now prove lease renewal, trusted callback dispatch,
   fencing, and uncertainty handling, but no safe executor mapping was invented for this checkout.
2. Complete the repository-level `PROJECT.md` dossier with a formal risk tier, GitHub project owner,
   support email, access status, data sources, rollback point, and required approvals.
3. Re-run the High/Medium scenarios in [`TEST-SCENARIO.md`](TEST-SCENARIO.md), including the skipped
   symlink case on a capable host and all Android unit/security tests with the pinned toolchain.
4. Supply operator-only VM, Cloudflare, OAuth, GCP, Firebase, relay digest, and signing inputs; do
   not commit their secret values.
5. Execute the coordinate-driven deployment runbook and retain live route, Access, device revoke,
   and exact Cloud Run digest-check output (`docs/deployment/hermes-mobile-ugreen-vm.md:100-119`).
6. Resolve the approved-storage finding or obtain a documented exception for the observed
   `NousResearch` remote.
7. Have a reviewer who is neither the project owner nor support contact run `/vibe-review` from a
   clean checkout and seal the proof. For a High tier, record all additional formal approvals.

## Seal

- **Seal status:** Not sealed. No reviewer commit was created, no `vibe-release.json` was touched,
  and no release approval is granted by this draft.
- **Validity statement:** This draft must not be treated as valid for any commit. Once a reviewer
  seals a fresh proof, changing tracked source after its reviewed commit invalidates that proof and
  requires `/vibe-review` again.
- **Attestation limitation:** A real sealed proof is attestation-grade and role-based. It compares
  exact reviewer identity with the recorded project owner and support contact, but does not use
  signing keys or a directory lookup. This draft has no reviewer identity and therefore cannot claim
  independence.
