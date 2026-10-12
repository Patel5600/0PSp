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
9. [CHP4 construction-readiness](security/chp4-construction-readiness.md) — implementation evidence and open gates.
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

CHp4.7 supersedes the earlier unresolved policy question in CHp4.3: the protocol does **not** require global uniqueness of `coin_id` alone. The spend identity is the complete tuple `(namespace_id, coin_id, r_nf)`. Two distinct commitments that reuse this exact tuple but differ in commitment salt necessarily share a V2 nullifier; one would become unspendable. Accordingly, every accepted issuance/transfer output must have its complete identity derived and constrained inside the eventual proof from a one-use creation anchor plus a canonical output slot. Issuance uses an authenticated canonical deposit/event anchor; transfer uses the exact consumed input nullifier under the selected single-input relation. The ledger must enforce anchor/nullifier one-use atomically.

This is an adopted specification policy and candidate derivation, **not yet enforceable by the repository**, because no ZK backend or durable consensus ledger is integrated. Finite SHAKE outputs are not injective: hash collisions remain probabilistic, and 32-byte `coin_id` must not be mistaken for a mathematical uniqueness guarantee. See [CHp4.7](audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md). V2 formulas and KATs remain frozen; production remains **NO-GO**.

## Continuous maintenance

- Every pull request and push to `main` runs the primary functional workflow.
- The Repository integrity watch checks local Markdown targets, selected canonical release-gate markers and deterministic identity-invariant fixtures on pull requests, main pushes, manual dispatch and a daily schedule.
- Dependency and GitHub Actions updates are reviewed deliberately in a single maintenance change; avoid automated update-PR churn, and never auto-merge cryptographic or toolchain changes blindly.
- A CI pass proves only that the executed checks passed. The integrity script is offline and does not validate external links, theorem validity, privacy, constant-time behavior or production readiness.
- Keep the mandatory release checklist in [the evidence-first register](security/evidence-first-rfc-register.md) current. Update the “Reviewed” date only when an actual human review takes place; do not auto-refresh dates to create the appearance of review.
- When a protocol invariant changes, update its specification, threat model, fixture(s), adversarial tests, relevant audit note and README in one reviewed change. If a harness does not yet exist, record the item as blocked instead of inventing a passing test.

## Historical research

CHP3/Phase 1 notes and earlier candidate constructions are retained as research history. They are not active authority for changing V2 byte formats, selecting the authorization mode, replacing a primitive or declaring the full protocol secure. Current status is always **NO-GO** until all release gates are closed with reviewable evidence.
