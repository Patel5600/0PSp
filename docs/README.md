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
8. [CHP4 construction-readiness](security/chp4-construction-readiness.md) — implementation evidence and open gates.
9. [Dependency minimization and construction roadmap](plan/dependency-minimization-and-construction-roadmap.md) — gated engineering sequence.

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

## Identity-invariant review: current decision boundary

The global hidden `(namespace_id, coin_id)` uniqueness rule is **under review, not silently removed**. The [CHp4.4 proposal audit](audit/chp4.4-deterministic-output-id-proposal-review.md) finds the proposed public-nullifier-derived ID formula incompatible with the current hidden-ID privacy requirement and the submitted sample formulas incompatible with the frozen V2 byte contracts. A public deposit-derived `coin_id` is not adopted under the current issuer-privacy target. Single issuance per canonical deposit, issuance/value binding, same-witness spend binding and atomic nullifier rejection are separate obligations.

A reused `(coin_id, r_nf)` with a different commitment salt can create a different commitment but the same nullifier. A nullifier set prevents a second accepted spend; it cannot make both notes spendable. Recipient safety/output creation must be analyzed before declaring the identity-invariant reduction complete.

See [CHp4.3](audit/chp4.3-identity-invariant-decision-review.md). V2 formulas and KATs remain frozen.

## Continuous maintenance

- Every pull request and push to `main` runs the primary functional workflow.
- The Repository integrity watch checks local Markdown targets, selected canonical release-gate markers and deterministic identity-invariant fixtures on pull requests, main pushes, manual dispatch and a daily schedule.
- Dependabot proposes weekly dependency and GitHub Actions updates. Review those PRs; do not auto-merge cryptographic or toolchain changes blindly.
- A CI pass proves only that the executed checks passed. The integrity script is offline and does not validate external links, theorem validity, privacy, constant-time behavior or production readiness.
- Keep the mandatory release checklist in [the evidence-first register](security/evidence-first-rfc-register.md) current. Update the “Reviewed” date only when an actual human review takes place; do not auto-refresh dates to create the appearance of review.
- When a protocol invariant changes, update its specification, threat model, fixture(s), adversarial tests, relevant audit note and README in one reviewed change. If a harness does not yet exist, record the item as blocked instead of inventing a passing test.

## Historical research

CHP3/Phase 1 notes and earlier candidate constructions are retained as research history. They are not active authority for changing V2 byte formats, selecting the authorization mode, replacing a primitive or declaring the full protocol secure. Current status is always **NO-GO** until all release gates are closed with reviewable evidence.
