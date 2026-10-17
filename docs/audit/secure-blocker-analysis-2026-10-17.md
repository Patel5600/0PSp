# 0PSP OpenVM blocker analysis and internal security review

**Review date:** 2026-10-17  
**Review type:** Internal source/CI evidence review; **not an external cryptographic audit**.  
**Release decision:** **NO-GO for production or live-value Mainnet transfers.** Production acceptance must remain disabled.  
**Baseline:** post-merge `main` commit `90dedabaec7a5b9a541aa3b77a4f13768de085c2` (PR #60 squash merge).  
**PR evidence reviewed:** candidate head `23e28594bcd3a399b9bdf750484db4e895d27e81`.

## Executive decision

PR #60 adds meaningful, repeatable evidence: an actual OpenVM application proof generated for a statement derived from a local SQLite candidate ledger anchor is submitted to the real Rust checker and then to `SQLiteV3CandidateLedger.accept_spend`. CI rejects a byte-mutated proof without changing state, accepts a valid proof and records its nullifier/output atomically, rejects replay, and reopens/audits the persisted ledger.

That result validates **one non-production proof-to-local-ledger integration path**. It does not establish an authenticated chain/finality source, a complete production spend relation, issuance/custody, the intended recipient, crash/reorg recovery, end-to-end witness hiding, or a composed >=128-bit post-quantum security bound. The test's bootstrap-state verifier is explicitly synthetic.

Do not promote V3 from candidate status or enable production spend acceptance based on this PR.

## Evidence ledger

### Exact-head CI for PR #60

| Check | Exact-head result | What it establishes |
|---|---|---|
| [Functional checks, run 38921488495](https://github.com/Patel5600/0PSp/actions/runs/38921488495) | Success | Repository test suite on candidate head `23e28594bcd3a399b9bdf750484db4e895d27e81`. |
| [Repository integrity watch, run 38921488512](https://github.com/Patel5600/0PSp/actions/runs/38921488512) | Success | Configured integrity checks on the same candidate head. |
| [OpenVM V3 proof stage, run 38921488520](https://github.com/Patel5600/0PSp/actions/runs/38921488520) | Success | Pinned OpenVM guest build, KAT/adversarial checks, application proof generation/verification, proof-to-SQLite transition, replay rejection, restart/integrity audit and evidence manifest. |

The workflow uploaded a metadata-only `manifest.json` artifact with 90-day retention. Raw proof and witness files were not uploaded. The evidence is traceable to the run but is not a published deployment release pin or a third-party attestation.

### Observed proof and profile measurements

From run 38921488520's generated manifest:

- One-input/one-output candidate spend proof: **660,320 bytes**, SHA-256 `861df18a0ccee6d94959e30300048becf73214025fd8d2c79f509f9ecb4620d2`.
- Proving time: **145.22168 seconds**; verification time: **0.734913 seconds**.
- Reported process high-water mark: **3,392,868 KiB**. The manifest explicitly says this is the combined SDK runner high-water mark shared across stage timings, not a per-stage memory measurement.
- The pinned upstream calculator reports **100.089831 app-only round-by-round soundness bits** for the stated conservative application bounds. This is not a composed post-quantum bound and is not a witness-hiding proof.
- `composite_post_quantum_soundness_bits` remains unknown/null; `composite_post_quantum_target_met=false`; `end_to_end_witness_hiding_established=false`; `trusted_finalized_state_established=false`; `production_acceptance_enabled=false`; the manifest status is `NO-GO`.

These figures are single-run CI observations, not target-device benchmarks or production performance guarantees.

### Post-merge status

At the time this review was written, the post-merge workflows for `main` commit `90dedabaec7a5b9a541aa3b77a4f13768de085c2` had started but were still in progress:

- [Functional checks, run 39016213729](https://github.com/Patel5600/0PSp/actions/runs/39016213729)
- [Repository integrity watch, run 39016213737](https://github.com/Patel5600/0PSp/actions/runs/39016213737)
- [OpenVM V3 proof stage, run 39016213793](https://github.com/Patel5600/0PSp/actions/runs/39016213793)

Do not describe the post-merge commit as fully green until these exact-SHA runs complete successfully.

## Internal review findings

### F-01 — The complete production spend relation is not established (**P0**)

The active OpenVM guest is a deliberately narrow one-input/one-output candidate. Proof generation and checker acceptance establish enforcement only of the relation encoded by that guest and its public digest. The repository still marks the V3 protocol contract and complete production relation NO-GO. The proof-to-ledger integration does not, by itself, prove every production invariant: complete value/asset semantics, all inputs/outputs, global identity uniqueness, approved authorization policy, or the full issuance/spend lifecycle.

**Required closure:** issue [#33](https://github.com/Patel5600/0PSp/issues/33) plus [#34](https://github.com/Patel5600/0PSp/issues/34): one backend-enforced, versioned relation must bind the same hidden note/bundle, commitment opening and membership, nullifier, canonical transaction, output/value constraints, authorization policy, namespace/params and trusted state. Mutate each field and require the proof or trusted-state boundary to reject.

### F-02 — State context is local candidate evidence, not authenticated finality (**P0**)

The new integration script builds a local candidate ledger, obtains its local root/head anchor, and creates a fresh proof for that statement. Its bootstrap state source, anchor and evidence are synthetic fixtures; the test verifier compares them against fixed local values. The SQLite transaction is real, but this is not evidence that an external chain or distributed ledger finalized the root.

**Required closure:** issue [#38](https://github.com/Patel5600/0PSp/issues/38) and [#34](https://github.com/Patel5600/0PSp/issues/34): define and implement an authenticated state adapter with pinned trust/checkpoint and fork/finality policy; bind chain/ledger identity, root and head into the verified statement; test stale/unfinalized roots, provider disagreement, equivocation, reorg, rollback, backup restore, crashes and interrupted writes. SQLite consistency and its 256-anchor window must never be treated as consensus finality.

### F-03 — Composed post-quantum soundness and end-to-end witness hiding remain unknown (**P0**)

The pinned OpenVM constructor targets a 100-bit application RBR profile; the runner calls the upstream app-only soundness calculator and records its components. That calculation is more defensible than the removed heuristic estimator, but it does not prove the protocol's composed >=128-bit post-quantum target. The field cardinality, individual component bits, preset name and proof generation are not substitutes for the composed theorem. Witness hiding for the exact compiled application and deployed proof transcript is also not established.

**Required closure:** issue [#36](https://github.com/Patel5600/0PSp/issues/36): pin exact backend/config/transcript parameters, bound every soundness and composition term under an explicit adversary model, document proved versus conjectured assumptions, and establish witness-hiding/zero-knowledge for the actual accepted profile. If this cannot be justified for the pinned backend, select another backend and repeat the evidence. Do not lower the required target or tune one term and call the whole protocol secure.

### F-04 — CI artifact hashes are same-run test metadata, not independent release pins (**P1, security-relevant**)

In the SQLite integration script, `checker_sha` and `vk_sha` are computed from the checker and verifying key produced/selected in the same test run, then supplied as their expected hashes to the adapter. This is appropriate for checking same-run byte consistency and the real checker path, but it is not an independently reviewed deployment pin. The executable commitment input is a repository file and is likewise not by itself a signed release statement.

**Required closure:** issue [#45](https://github.com/Patel5600/0PSp/issues/45): on the actual release path, pin the checker, VK, executable commitment, OpenVM SDK/toolchain, build provenance and configuration through a reviewed release manifest. Verify each staged artifact against externally reviewed release inputs; document key-generation and rotation rules. Do not treat CI-generated digests as trust roots.

### F-05 — Local SQLite transition tests do not establish distributed atomicity/recovery (**P0**)

The CI test covers mutated-proof rejection with no state change, one accepted local spend, duplicate-nullifier replay rejection, and restart integrity. It does not test distributed finality/reorg semantics, power-loss/disk-full recovery, cross-service issue/spend atomicity, or reconciliation to an external chain.

**Required closure:** issue [#38](https://github.com/Patel5600/0PSp/issues/38) and master gate [#42](https://github.com/Patel5600/0PSp/issues/42): test failpoints at every durable transition boundary, idempotent recovery, reorg rollback/reconciliation and backups/restores against authenticated chain state.

### F-06 — Production gate is not to be enabled by candidate success (**P0 release control**)

The previously merged release latch keeps `verify_production_proof_envelope()` fail-closed while `PRODUCTION_SPEND_VERIFICATION_ENABLED` is false. PR #60 does not justify changing this. The production gate matrix also explicitly records Mainnet NO-GO.

**Required closure:** preserve the disabled latch until every mandatory blocker is closed and independently reviewed internally on one exact release SHA. A green workflow, caller-supplied callback, candidate profile or issue closure is not sufficient.

### F-07 — Issuance/custody and intended-payee authenticity remain outside this proof path (**P0/P1**)

This spend-candidate test starts from a synthetic bootstrap commitment. It does not prove that an on-chain deposit was finalized and policy-compliant, that issuance created a legitimate note, or that a self-asserted key bundle belongs to the intended payee.

**Required closure:** [#35](https://github.com/Patel5600/0PSp/issues/35) must establish trusted deposit/finality/custody and atomic one-time issuance; [#39](https://github.com/Patel5600/0PSp/issues/39) must define the intended-payee anchor, note delivery and recovery model.

## Blocker sequence and acceptance gates

Do not parallelize the protocol into unrelated pieces and call the aggregate complete. Use the following dependency order:

1. **P0 relation and authorization — #33 + #34.** Freeze authorization semantics and the candidate V3 relation. Implement the actual verifier-enforced relation, then adversarial mutation tests for keys, policy, fields, outputs, value/range, namespace, root/head and replay.
2. **P0 trusted state, issuance and recovery — #35 + #38.** Pin intended chain/deployment trust; authenticate finalized chain/state evidence; consume deposits and nullifiers exactly once; implement fault-injected atomicity, reorg handling, rollback prevention and tested restore.
3. **P0 composed security/privacy — #36.** Produce a parameter-exact soundness analysis and witness-hiding evidence for the complete accepted construction, or reject this backend as not meeting the requirement.
4. **Cross-cutting correctness — #37, #39–#47.** Measure the complete relation on declared target hardware; prove integer range/field-wraparound constraints; define recipient delivery/recovery; produce bounded secret-lifecycle/side-channel evidence, cross-language KAT parity, sustained fuzz/differential tests, supply-chain controls, network/privacy/abuse limits and operational recovery.
5. **Final composition — #42.** Test finalized deposit → authorized issuance → spend → output spend → replay/double-spend rejection → restart/restore/reorg recovery using the same production composition and exact release SHA. All mandatory matrix rows need evidence and internal defect review before release approval.

## Release decision

- **Candidate proof-to-local-SQLite wiring:** PASS on PR #60 exact head, as limited above.
- **App-only pinned OpenVM RBR calculation:** reported at 100.089831 bits for the manifest's stated bounds; not a composed PQ claim.
- **Composed >=128-bit post-quantum security:** UNKNOWN / NO-GO.
- **End-to-end witness hiding:** NOT ESTABLISHED / NO-GO.
- **Trusted finalized state, complete authorization and issuance/custody:** NOT ESTABLISHED / NO-GO.
- **Production/Mainnet acceptance:** DISABLED / NO-GO.
- **External audit:** NOT PERFORMED. This document is an internal engineering evidence review, not a certification.

The only acceptable promotion is evidence-backed closure on one exact release SHA. No change in wording, profile metadata, green CI for a different SHA, or passing candidate integration test changes this decision.
