# 0PSP Documentation Map and Maintenance Policy

**Last consistency check:** 2026-10-13  
**Release status:** **NO-GO**  
**Normative status:** research prototype; documentation and regression tests do not certify security.

This index is the entry point for maintainers. When a proposal, experiment or historical note conflicts with the current release decision, follow the current release register and the approved, versioned protocol specification. A research branch is not an approved protocol decision.

## Current source of truth

1. [Evidence-first RFC register and release gate](security/evidence-first-rfc-register.md) — mandatory production gates and change-control rules.
2. [Binary Production Gate Matrix](security/production-gate-matrix.md) — every release gate, status, evidence, and condition for changing status.
3. [RFC-01: user-committed issuance](security/rfc-01-user-committed-issuance.md) — issuer privacy, issuance/value/deposit binding, and replay requirements.
4. [RFC-02: V2-only spend relation](theory/spend-relation-spec.md) — frozen V2 equations and unresolved predicates; this file is not a V3 specification.
5. [CHp4.7 V3 spend-relation candidate](theory/spend-relation-v3-candidate.md) — non-normative V3 candidate, provisional nullifier suite, recipient-authentication/authorization gaps, and release blockers.
6. [V2 protocol security argument](security/v2-protocol-security-argument.md) — conditional component-level arguments and limitations.
7. [CHp4.3 identity-invariant review](audit/chp4.3-identity-invariant-decision-review.md) — historical review of hidden identity policy.
8. [CHp4.4 deterministic output-ID proposal review](audit/chp4.4-deterministic-output-id-proposal-review.md) — explains why the public nullifier-derived ID proposal is not accepted.
9. [CHp4.5 hidden-witness output-identity proposal review](audit/chp4.5-hidden-witness-output-identity-proposal-review.md) — reviews field widths, collision bounds, privacy claims, and sample tests.
10. [CHp4.6 output-identity candidate and tests](audit/chp4.6-output-identity-candidate-and-tests.md) — transfer reference candidate and hardcoded regressions; ZK enforcement remains open.
11. [CHp4.7 output-identity uniqueness and nullifier safety](audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md) — additive V3 commitment, recipient-keyed nullifier, and anchor/slot identity candidates; proof enforcement and production gates remain open.
12. [CHp4.8 Namespace V2 EVM adapter — historical initial mapping](audit/chp4.8-namespace-v2-evm-adapter.md) — historical adapter retained for audit; its intermediate-hash identity mapping is superseded.
13. [CHp4.9 Namespace V3 direct-hash remediation](audit/chp4.9-namespace-v3-direct-hash-remediation.md) — current EVM identity encoding, collision model, native/Python parity, and ledger typing.
14. [CHp4.10 namespace RPC quorum and durable finality journal](audit/chp4.10-namespace-rpc-finality-hardening.md) — RPC policy, checkpoint-to-finalized ancestry, and remaining consensus/proof boundaries.
15. [CHp4.11 EVM deposit evidence contract](audit/chp4.11-evm-deposit-evidence-contract.md) — fixed event profile, canonical evidence, beneficiary binding, and trie-proof requirements.
16. [CHp4.12 EVM transaction/receipt trie verifier](audit/chp4.12-evm-trie-inclusion-verifier.md) — Keccak/RLP/MPT primitives and same-index transaction/receipt proofs.
17. [CHp4.13 Ethereum Mainnet light-client finality integration](audit/chp4.13-helios-authenticated-finality.md) — supervised pinned Helios candidate and durable checkpoint ancestry; no production authorization is claimed.
18. [CHp4.14 deposit asset-movement evidence](audit/chp4.14-asset-movement-evidence.md) — native value and ERC-20 Transfer matching; movement evidence is not custody authorization.
19. [CHp4.15 authenticated account/storage proofs](audit/chp4.15-authenticated-evm-state-proofs.md) — EIP-1186 account/storage proofs against authenticated finalized headers.
20. [CHp4.16 Ethereum proof differential tests](audit/chp4.16-ethereum-proof-differential-tests.md) — test-only comparison with independent Keccak/RLP/MPT libraries.
21. [CHp4.17 durable ledger and commitment Merkle tree](audit/chp4.17-durable-merkle-ledger.md) — transactional SQLite transitions and startup consistency checks, not consensus.
22. [CHp4.18 canonical V2 spend transaction and digest](audit/chp4.18-canonical-spend-transaction-v2.md) — canonical TxFieldsV2/TxDigestV2 host encoding; proof circuit binding remains open.
23. [CHp4.20 proof-backend feasibility](audit/chp4.20-zk-backend-feasibility.md) — backend selection criteria and the still-required shared-witness relation.
24. [CHp4.21 static SHAKE arithmetization cost model](audit/chp4.21-keccak-zk-cost-model.md) — scenario estimator and the need for measured backend results.
25. [CHp4.22 SmallWood R1CS adapter scaling audit](audit/chp4.22-smallwood-r1cs-adapter-scaling.md) — memory-scaling evidence and rejection of the dense generic adapter.
26. [CHp4.23 binary-field Keccak feasibility](audit/chp4.23-binary-field-keccak-feasibility.md) — circuit-row model and Aurora candidate screen.
27. [CHp4.27 authorization and proof-backend candidate screen](audit/chp4.27-authorization-and-backend-candidate-screen.md) — evidence against premature Ringtail/LoTRS selection and the current OpenVM/Aurora feasibility path.
28. [CHP4 construction-readiness](security/chp4-construction-readiness.md) — implementation evidence and open gates.
29. [Dependency minimization and construction roadmap](plan/dependency-minimization-and-construction-roadmap.md) — gated engineering sequence.

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

## Identity policy: separate CHp4.7 V3 candidate (non-normative)

CHp4.7 records a versioned V3 identity-policy candidate: `coin_id` alone is not the global identity/uniqueness key. An accepted output is intended to be bound to a canonical one-use creation anchor plus a canonical global output slot. Issuance uses an authenticated deposit/event identity; transfer uses the consumed input V3 nullifier and transaction output index. The recipient public-key bundle commits to a recipient-held nullifier-deriving key, `CommitV3` binds the canonical bundle into the note commitment, and `NullifierV3` uses HMAC-SHA3-384 keyed by that secret while binding the exact commitment, namespace, parameters, bundle, and hidden tuple. V1/V2 formats and known-answer vectors remain frozen.

This is a **reference construction candidate, not a verified security result**. A host-only `generate_nullifier_deriving_key_v3()` helper now uses the OS-backed CSPRNG, and `src/protocol/transaction_v3_candidate.py` defines a strict candidate encoding/digest that binds namespace, root, input nullifier, state head, policy, fee, public output entropy, and ordered V3 output commitments. Neither helper constrains a proof or provides production key management. The Python helpers do not enforce canonical chain anchors, recipient authentication, correct proof witness consistency, uniqueness constraints, or recipient spendability. The future proof must bind the same V3 note witness across commitment opening, recipient bundle/key-commitment opening, output derivation, global output slot, value conservation, authorization predicate, and public nullifier. The durable state transition must atomically consume each issuance anchor or spend nullifier and register outputs. The signature/key codec, encrypted note recovery/key delivery, complete shared-witness proof, circuit feasibility, and independent review remain open. A finite digest/PRF output is not mathematically injective, and changing the commitment salt removes V2's deterministic same-nullifier behavior for this candidate but does not eliminate the possibility of finite-output collisions.

The CHp4.6 sender-known tuple candidate must not be paired with unkeyed V2 nullifiers where sender-unlinkability is required. The [CHp4.7 audit record](audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md), [V2-only formal spend relation](theory/spend-relation-spec.md), [separate V3 candidate relation](theory/spend-relation-v3-candidate.md), [CHp4.27 authorization/backend candidate screen](audit/chp4.27-authorization-and-backend-candidate-screen.md), and [evidence-first release register](security/evidence-first-rfc-register.md) retain the remaining obligations. Overall protocol status remains **NO-GO**.

## Continuous maintenance

- Every pull request and push to `main` runs the primary functional workflow.
- The Repository integrity watch checks local Markdown targets, selected canonical release-gate markers and deterministic identity-invariant fixtures on pull requests, main pushes, manual dispatch and a daily schedule.
- Dependency and GitHub Actions updates are reviewed deliberately in a single maintenance change; avoid automated update-PR churn, and never auto-merge cryptographic or toolchain changes blindly.
- A CI pass proves only that the executed checks passed. The integrity script is offline and does not validate external links, theorem validity, privacy, constant-time behavior or production readiness.
- Keep the mandatory release checklist in [the evidence-first register](security/evidence-first-rfc-register.md) current. Update the “Reviewed” date only when an actual human review takes place; do not auto-refresh dates to create the appearance of review.
- When a protocol invariant changes, update its specification, threat model, fixture(s), adversarial tests, relevant audit note and README in one reviewed change. If a harness does not yet exist, record the item as blocked instead of inventing a passing test.

## Historical research

CHP3/Phase 1 notes and earlier candidate constructions are retained as research history. They are not active authority for changing V2 byte formats, selecting the authorization mode, replacing a primitive or declaring the full protocol secure. Current status is always **NO-GO** until all release gates are closed with reviewable evidence.
