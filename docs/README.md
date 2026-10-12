# 0PSP Documentation Map and Maintenance Policy

**Last consistency check:** 2026-10-12  
**Release status:** **NO-GO**  
**Normative status:** research prototype; documentation and regression tests do not certify security.

This index is the entry point for maintainers. When a proposal, experiment or historical note conflicts with the current release decision, follow the current release register and the approved, versioned protocol specification. A research branch is not an approved protocol decision.

## Current source of truth

1. [Evidence-first RFC register and release gate](security/evidence-first-rfc-register.md) — mandatory production gate and change-control rules.
2. [RFC-01: user-committed issuance](security/rfc-01-user-committed-issuance.md) — issuer privacy, issuance/value/deposit binding and replay requirements.
3. [RFC-02: spend relation](theory/spend-relation-spec.md) — current V2 equations, shared witness and still-unspecified predicates.
4. [V2 protocol security argument](security/v2-protocol-security-argument.md) — conditional component-level arguments and limitations.
5. [CHp4.3 identity-invariant review](audit/chp4.3-identity-invariant-decision-review.md) — review proposal, not an approved change to identity semantics.
6. [CHp4.4 deterministic output-ID proposal review](audit/chp4.4-deterministic-output-id-proposal-review.md) — audits the friend's proposal; public nullifier-derived IDs and sample formulas are rejected for now pending privacy/protocol review.
7. [CHp4.5 hidden-witness output-identity proposal review](audit/chp4.5-hidden-witness-output-identity-proposal-review.md) — audits the revised proposal's field widths, collision bounds, privacy claims and sample tests; it remains unapproved.
8. [CHp4.6 output-identity candidate and tests](audit/chp4.6-output-identity-candidate-and-tests.md) — transfer reference candidate and hardcoded regressions; ZK enforcement remains open.
9. [CHp4.7 output-identity uniqueness and nullifier safety](audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md) — adopts the complete spend-identity policy and one-use-anchor/canonical-output-slot derivation contract, adds the issuance reference candidate, and states the exact proof/ledger obligations that remain.
10. [CHP4 construction-readiness](security/chp4-construction-readiness.md) — implementation evidence and open gates.
11. [Dependency minimization and construction roadmap](plan/dependency-minimization-and-construction-roadmap.md) — gated engineering sequence.

## Repository map

| Location | Purpose | Change rule |
|---|---|---|
| `src/primitives/` | Python reference encodings/primitives | Freeze V2 bytes unless separately versioned and approved |
| `native/` | Native C implementation, headers, vectors and diagnostic probes | Preserve ABI, KATs, failure behavior and reviewed boundaries |
| `src/protocol/reference_ledger.py` | In-memory state-transition reference model | Never describe as durable, consensus-safe or production ledger |
| `tests/unit/` | Unit tests for local components | Evidence for tested behavior only |
| `tests/property/` | Property-based test models | Not a proof over all protocol inputs |
| `tests/adversarial/` | Negative and adversarial regression cases | State fixtures and model boundaries in comments |
| `tests/fixtures/` | Stable, machine-readable deterministic regression fixtures | Version fixture schema; test-only secrets are public vectors |
| `scripts/` | Reproducibility, audit and integrity utilities | Diagnostics must describe what they do not prove |
| `docs/audit/` | Checkpoint decisions and evidence records | Do not silently rewrite historical results |
| `docs/theory/` | Formal targets and research constructions | Mark unresolved assumptions; do not call targets proofs |
| `docs/security/` | Security model, games, RFCs and release gate | Register is the canonical gate; approval must be explicit |
| `.github/workflows/` | CI and scheduled consistency checks | Watch jobs are evidence-producing, not automatic security certification |

## Identity policy: CHp4.7 decision boundary

CHp4.7 replaces the formerly open policy with a versioned candidate: `coin_id` alone is not a uniqueness key, and each accepted output identity is bound to a one-use creation anchor and canonical global output slot. Issuance uses a canonical authenticated deposit/event anchor; transfer derives from the exact consumed V3 nullifier and parent witness. The canonical recipient key bundle includes a commitment to a recipient-held per-note nullifier key. `CommitV3` binds that bundle to the note, while `NullifierV3` uses HMAC-SHA3-384 keyed by the recipient secret and binds the exact commitment, so knowing an output tuple, commitment and bundle does not let the sender directly compute its future nullifier under the PRF assumption. Different commitment salts do not deterministically reuse a V3 nullifier. The recipient must authenticate the exact bundle, and the actual output proof must enforce that authentication to prevent key-commitment substitution.

The CHp4.6 transfer candidate must not be paired with unkeyed V2 nullifiers when sender-unlinkability is required. V1/V2 formulas and vectors remain unchanged; V3 is additive and uses distinct result types. The spec and Python candidates do **not** enforce a ZK circuit or durable ledger. Address-authentication suite, circuit feasibility, key recovery, and independent review remain open; the full protocol remains **NO-GO**. See [CHp4.7](audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md).

## Continuous maintenance

- Every pull request and push to `main` runs the primary functional workflow.
- The Repository integrity watch checks local Markdown targets, selected canonical release-gate markers and deterministic identity-invariant fixtures on pull requests, main pushes, manual dispatch and a daily schedule.
- Dependency and GitHub Actions updates are reviewed deliberately in a single maintenance change; avoid automated update-PR churn, and never auto-merge cryptographic or toolchain changes blindly.
- A CI pass proves only that the executed checks passed. The integrity script is offline and does not validate external links, theorem validity, privacy, constant-time behavior or production readiness.
- Keep the mandatory release checklist in [the evidence-first register](security/evidence-first-rfc-register.md) current. Update the “Reviewed” date only when an actual human review takes place; do not auto-refresh dates to create the appearance of review.
- When a protocol invariant changes, update its specification, threat model, fixture(s), adversarial tests, relevant audit note and README in one reviewed change. If a harness does not yet exist, record the item as blocked instead of inventing a passing test.

## Historical research

CHP3/Phase 1 notes and earlier candidate constructions are retained as research history. They are not active authority for changing V2 byte formats, selecting the authorization mode, replacing a primitive or declaring the full protocol secure. Current status is always **NO-GO** until all release gates are closed with reviewable evidence.
