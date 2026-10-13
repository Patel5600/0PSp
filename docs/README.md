# 0PSP Documentation Map and Maintenance Policy

**Last consistency check:** 2026-10-13 (documentation consistency only; not a human security review).  
**Snapshot:** CHp4.25 candidate in PR #30; the PR is open and unmerged.  
**Release status:** **NO-GO**  
**Independent security review of CHp4.25:** NOT PERFORMED.  
**External cryptographic audit:** NOT PERFORMED.  
**Normative status:** research prototype; documentation and regression tests do not certify security.

This index is the entry point for maintainers. When a proposal, experiment or historical note conflicts with the current release decision, follow the current release register and the approved, versioned protocol specification. A research branch is not an approved protocol decision.

## Current source of truth

**Release decision:** NO-GO. **External cryptographic audit:** NOT PERFORMED. The index describes repository state; it is not a security review or deployment approval. PR #30 is an open, unmerged CHp4.25 candidate; main has not been changed by that PR.

### Release gates and core specifications

- [Evidence-first RFC register and release gate](security/evidence-first-rfc-register.md) — mandatory release conditions and evidence policy.
- [Binary Production Gate Matrix](security/production-gate-matrix.md) — scoped GO/NO-GO decisions with evidence and exit criteria.
- [RFC-01: user-committed issuance](security/rfc-01-user-committed-issuance.md) — issuer privacy, issuance/value/deposit binding and replay.
- [RFC-02: spend relation](theory/spend-relation-spec.md) — V2 equations, shared witness and unresolved predicates.
- [V2 protocol security argument](security/v2-protocol-security-argument.md) — conditional component arguments and limitations.
- [CHP4 construction-readiness](security/chp4-construction-readiness.md) — implementation evidence and open gates.
- [Dependency minimization and construction roadmap](plan/dependency-minimization-and-construction-roadmap.md) — gated engineering sequence.

### Identity and EVM evidence

- [CHp4.3 identity-invariant review](audit/chp4.3-identity-invariant-decision-review.md) — open policy decision, not an approved protocol change.
- [CHp4.4 deterministic output-ID proposal review](audit/chp4.4-deterministic-output-id-proposal-review.md) — rejects unsupported public nullifier-derived identity under the current privacy target.
- [CHp4.5 hidden-witness output-identity proposal review](audit/chp4.5-hidden-witness-output-identity-proposal-review.md) — revised proposal remains unapproved.
- [CHp4.6 output-identity candidate and tests](audit/chp4.6-output-identity-candidate-and-tests.md) — finite reference vectors; ZK enforcement remains open.
- [CHp4.8 Namespace V2 EVM adapter](audit/chp4.8-namespace-v2-evm-adapter.md) — historical initial mapping; superseded for new EVM identity by V3.
- [CHp4.9 Namespace V3 direct-hash remediation](audit/chp4.9-namespace-v3-direct-hash-remediation.md) — current EVM descriptor encoding, native/Python parity, and namespace typing.
- [CHp4.10 RPC quorum and durable finality journal](audit/chp4.10-namespace-rpc-finality-hardening.md) — strict-majority RPC corroboration and durable ancestry, not a consensus light client.
- [CHp4.11 EVM deposit evidence contract](audit/chp4.11-evm-deposit-evidence-contract.md) — canonical event observation and beneficiary binding; not mint authorization.
- [CHp4.12 EVM transaction/receipt trie inclusion](audit/chp4.12-evm-trie-inclusion-verifier.md) — Keccak/RLP/MPT inclusion against header roots; requires authenticated header trust.
- [CHp4.13 Ethereum Mainnet Helios integration](audit/chp4.13-helios-authenticated-finality.md) — concrete candidate light-client path; intended-chain smoke and independent review remain open.
- [CHp4.14 deposit asset-movement evidence](audit/chp4.14-asset-movement-evidence.md) — transaction-value/Transfer-log consistency; not proof of custody.
- [CHp4.15 authenticated EVM state proofs](audit/chp4.15-authenticated-evm-state-proofs.md) — EIP-1186 account/storage checks against an authenticated state root.
- [CHp4.16 Ethereum proof differential tests](audit/chp4.16-ethereum-proof-differential-tests.md) — test-only comparison with independent libraries.
- [CHp4.17 durable ledger and commitment Merkle tree](audit/chp4.17-durable-merkle-ledger.md) — single-node SQLite state transitions and tree reconciliation; trusted authorization/proof integration remain open.
- [CHp4.18 canonical V2 spend transaction/digest](audit/chp4.18-canonical-spend-transaction-v2.md) — frozen host/API encoding; the actual proof must constrain it.
- [CHp4.25 Namespace V2/V3 composite gate](audit/chp4.25-namespace-v2-v3-end-to-end-gate.md) — independent expected-namespace pin, exact-height Mainnet smoke harness, and code/state-root consistency tests. The live intended-deployment smoke has **not** been run; proof binding and independent review remain NO-GO.

**Separate workstream, not merged into this snapshot:** [CHp4.24 Aurora/libiop source-audit PR #28](https://github.com/Patel5600/0PSp/pull/28) is open and unmerged. It documents blockers in the pinned candidate; it does not certify Aurora or select an accepted production proof backend.

### Proof feasibility and cost evidence

- [CHp4.20 proof-backend feasibility](audit/chp4.20-zk-backend-feasibility.md) — backend acceptance criteria and complete relation requirements.
- [CHp4.21 static SHAKE arithmetization cost model](audit/chp4.21-keccak-zk-cost-model.md) — deterministic model, not a measured backend benchmark.
- [CHp4.22 SmallWood Python R1CS adapter scaling audit](audit/chp4.22-smallwood-r1cs-adapter-scaling.md) — the pinned dense generic adapter is NO-GO at the evaluated scale.
- [CHp4.23 binary-field Keccak feasibility](audit/chp4.23-binary-field-keccak-feasibility.md) — deterministic characteristic-two row model, not an instantiated circuit or proof.

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
- Dependency and GitHub Actions updates are reviewed deliberately in a single maintenance change; avoid automated update-PR churn, and never auto-merge cryptographic or toolchain changes blindly.
- A CI pass proves only that the executed checks passed. The integrity script is offline and does not validate external links, theorem validity, privacy, constant-time behavior or production readiness.
- Keep the mandatory release checklist in [the evidence-first register](security/evidence-first-rfc-register.md) current. Update the “Reviewed” date only when an actual human review takes place; do not auto-refresh dates to create the appearance of review.
- When a protocol invariant changes, update its specification, threat model, fixture(s), adversarial tests, relevant audit note and README in one reviewed change. If a harness does not yet exist, record the item as blocked instead of inventing a passing test.

## Historical research

CHP3/Phase 1 notes and earlier candidate constructions are retained as research history. They are not active authority for changing V2 byte formats, selecting the authorization mode, replacing a primitive or declaring the full protocol secure. Current status is always **NO-GO** until all release gates are closed with reviewable evidence.
