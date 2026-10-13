# 0PSP Evidence-First RFC Register and NO-GO Dashboard

**Last reviewed:** 2026-10-13 (pre-existing register metadata; this CHp4.25 status synchronization is not an independent security review).  
**Main baseline:** `13487d2f859460fc93fd2701023ce8f2cd60fd6a` (CHp4.23); CHp4.25 PR #30 is open and unmerged.  
**Independent security review of CHp4.25:** NOT PERFORMED.  
**External cryptographic audit:** NOT PERFORMED. No claim of external audit is made.  
**Current release decision: `NO-GO`**  
**Scope of this document:** engineering RFCs and evidence plan; it is not a cryptographic proof or approval to deploy.

## Executive decision

The V2 primitive layer has useful, testable components: namespace derivation, random coin-ID and secret/salt generation, a 48-byte SHAKE256 nullifier, a 48-byte SHAKE256 commitment, Python/native known-answer agreement, and native sanitizer/disassembly build checks. It does not yet provide the protocol that consumes these components safely.

The revised plan deliberately avoids (a) adding a second spend commitment without a demonstrated need, (b) claiming a generic proof-of-secret-key automatically replaces committee authorization, (c) replacing SHAKE based on invented constraint numbers, or (d) rewriting the C boundary merely because Rust is available.

No percentage-complete claim is used. A test pass, an RFC, or a benchmark is not a security theorem. CHp4.15 does not authorize minting; its block-state proof is supporting evidence only. CHp4.16 adds independent library differential tests but does not replace external review or the real-network smoke test. CHp4.17 adds persistent single-node state transitions and a stronger local consistency audit, but its injected verifier and deposit callbacks are not production implementations. CHp4.18 candidate freezes the host TxFieldsV2/TxDigestV2 codec and rejects duplicate-field mismatches before the callbacks; the proof backend must still constrain those exact bytes. See the [binary Production Gate Matrix](production-gate-matrix.md).

## Current implementation facts

| Area | Evidence present in repository | What that evidence does **not** establish |
|---|---|---|
| Namespace V2 frozen / Namespace V3 EVM mapping | V2 KAT unchanged; V3 direct-hash Python/native KAT parity; typed V3 ledger boundary; CHp4.10 quorum/journal; CHp4.13 Helios Mainnet candidate; CHp4.25 checks an independently pinned expected Namespace V3 ID and exact-height runtime code against an authenticated EIP-1186 account proof | Intended-deployment Mainnet smoke NOT RUN; Helios/checkpoint/deployment trust review; exact V3 bytes are not constrained by an accepted production proof; independent security review NOT PERFORMED; external cryptographic audit NOT PERFORMED |
| Deposit evidence / EVM event reader | CHp4.11 canonical event observation; CHp4.12 raw transaction/receipt MPT inclusion; CHp4.13 Helios finality candidate; CHp4.14 movement signals; CHp4.15 EIP-1186 proof primitive; CHp4.25 exact-height runtime-code/state-root smoke harness | No intended-deployment Mainnet smoke; state evidence is not custody authorization; proxy/token semantics and trusted DepositAuthorization conversion remain open |
| Coin commitment V2 | SHAKE256-384 includes `params_id`, key bytes, value, namespace, coin ID, `r_nf`, and independent salt; reference/native KAT | A hiding theorem, a complete binding proof over the eventual accepted key codec, issuer privacy, or proof-system soundness |
| Nullifier V2 | Deterministic 48-byte result over namespace, 32-byte coin ID and 36-byte secret; a 149-byte preimage | That the spend proof enforces the exact same committed opening or that a ledger rejects repeats atomically |
| Native memory handling | OpenSSL APIs and `OPENSSL_cleanse` calls in source; sanitizer and disassembly build targets | Whole-process zeroization, all-copy erasure, constant-time behavior, or leakage absence |
| Authorization | Ringtail adapter contract and research notes | A production adapter, final authorization mode, or signature-verification constraints in an actual ZK backend |
| ZK proof | Relation targets documented | An instantiated backend, knowledge soundness, zero knowledge, or a complete proof of the composed relation |
| Mint and ledger | CHp4.1 in-memory model; CHp4.17 candidate adds a depth-63 namespace-bound commitment tree, file-backed SQLite issue/spend transactions, unique deposit/commitment/nullifier constraints, state-head event chain, concurrency stale-state rejection and startup reconciliation of all Merkle nodes/records/events | The ledger still depends on injected deposit/proof callbacks; no production `DepositAuthorization` adapter or actual issuance/spend proof exists. This is single-node persistence, not distributed consensus; power-loss/backup/recovery and external state-head anchoring remain open |
| Canonical transaction fields / TxDigestV2 | CHp4.18 candidate defines one length-bounded TxFieldsV2 encoding, a 48-byte SHAKE256-384 digest, a known-answer vector, and ledger-boundary checks that duplicated public fields match decoded bytes | Exact-head CI; the real proof backend must enforce the same encoding/digest; transaction binding remains NO-GO until the proof relation is instantiated |
| Hidden coin-ID uniqueness | Protocol names (namespace, coin_id) as identity while issuer-private minting hides coin_id | Proof/registry mechanism that detects a reused hidden ID without disclosing it, or revised identity semantics |

## Four RFCs

| RFC | State | Allowed work now | Release blocker |
|---|---|---|---|
| [RFC-01: User-committed issuance](rfc-01-user-committed-issuance.md) | **Design candidate; BLOCKED** | Primitive-level invariant tests and protocol review | Issuance proof/verified mechanism tying ledger value and deposit to the hidden opening; full hiding/linkability analysis; durable atomic ledger |
| [RFC-02: Spend relation](../theory/spend-relation-spec.md) | **Formal specification draft; NOT PROVEN** | Freeze public statement, witness, common predicates, and authorization alternatives | Select one policy-compatible authorization mode and instantiate a proof backend that proves every predicate over one consistent witness |
| [RFC-03: Hash circuit comparison](../plan/rfc-03-hash-circuit-benchmark.md) | **Protocol only; NOT RUN** | Prepare reproducible data format and backend adapter boundary | Chosen, pinned backend; validated parameters and equivalent security targets; measured results on a declared machine |
| [RFC-04: Side-channel diagnostics](rfc-04-side-channel-diagnostics.md) | **Diagnostic plan; NOT CERTIFIED** | Manual non-blocking disassembly and timing diagnostics | Controlled target measurements, whole sensitive-path review, dependency/compiler/target evidence |

## CHp4.1 reference-model boundary

[CHp4.1](../audit/chp4.1-reference-state-transitions.md) adds an in-memory, single-process model that requires injected deposit and proof-verifier callbacks. Its tests exercise replay rejection, duplicate commitments/nullifiers, proof-rejection non-mutation, and concurrent duplicate submissions. Test callbacks are deliberately not cryptographic verifiers. This work models a local linearization point; it does not close the durable-ledger gate or establish issuance value-binding, spend soundness, zero knowledge, consensus safety, or reorg/recovery correctness.

## Namespace V2/V3 boundary and CHp4.25 candidate

Namespace V2 remains frozen, including its existing known-answer vector. The earlier CHp4.8 EVM adapter used intermediate 256-bit descriptor hashes and is retained only as historical evidence. The current EVM adapter hashes the full canonical ledger, deployment and asset descriptors directly into Namespace V3 using SHAKE256-384. The idealized generic quantum collision-query scale of a 384-bit output is about 2^128 under the stated model; this is not injectivity or a complete protocol theorem.

CHp4.10's strict-majority RPC policy and SQLite ancestry journal provide corroboration and durable conflict detection, not consensus authentication. CHp4.13 adds a candidate Ethereum Mainnet Helios light-client integration with a digest-pinned binary and out-of-band checkpoints. CHp4.12 covers transaction/receipt trie inclusion, CHp4.14 checks asset-movement signals, and CHp4.15 verifies account/storage proofs against authenticated header state roots. These components do not by themselves prove custody, authorize minting, or instantiate the issuance relation.

CHp4.25 adds a fail-closed smoke runner that checks the derived Namespace V3 ID against an independently approved 48-byte expected ID, resolves code at one exact finalized block height, and checks protocol (and configured token) runtime code against both an independently supplied fingerprint and an EIP-1186 account proof tied to that header's authenticated state root. Automated tests pass on the recorded implementation/test commit, but the intended-deployment Mainnet smoke has NOT BEEN RUN. CHp4.25 is still an open candidate PR, not a merged release. No production proof binds the exact 48-byte Namespace V3 value into the complete issuance/spend relation. Proxy upgrade/custody semantics, trusted DepositAuthorization conversion, operational trust-pin provenance, recovery, and independent security review remain open. External cryptographic audit is NOT PERFORMED.

See [CHp4.9](../audit/chp4.9-namespace-v3-direct-hash-remediation.md), [CHp4.10](../audit/chp4.10-namespace-rpc-finality-hardening.md), [CHp4.12](../audit/chp4.12-evm-trie-inclusion-verifier.md), [CHp4.13](../audit/chp4.13-helios-authenticated-finality.md), and [CHp4.25](../audit/chp4.25-namespace-v2-v3-end-to-end-gate.md).

## CHp4.2 formal relation and adversarial test boundary

[CHp4.2](../audit/chp4.2-formal-relations-adversarial-tests.md) records the exact current V2 commitment/nullifier preimages and formal R_mint/R_spend targets. `tests/adversarial/test_v2_witness_substitutions.py` uses real reference primitives for finite-vector substitution cases; `tests/adversarial/test_issuance_replay.py` uses a test-double verifier to check local deposit replay handling. Merkle-path/index tests remain blocked until the tree suite/encoding is frozen, and reorg tests remain blocked until real adapter/finality/recovery semantics exist. A further open decision is global hidden coin-ID uniqueness. CHp4.3 evaluates whether it is necessary for monetary soundness and separately records the same-(coin_id, r_nf) nullifier-collision/unspendability risk. Do not treat this policy as resolved until an approved identity decision and recipient/output analysis exist.

## P0: issuance privacy and state correctness

A wallet-side commitment can keep `coin_id`, `r_nf` and salt out of the mint's view. That is necessary but not sufficient:

1. The mint observes `C`, a claimed/public `v`, and deposit evidence.
2. Because it does not know the opening, it cannot independently recompute `C` to check that the opening's hidden value equals `v`.
3. A receipt signed over `(C, v, deposit_tx)` authenticates the mint's recorded fields. It does not, by itself, prove that the hidden commitment opening contains that same value.
4. The protocol therefore needs a verified issuance relation/proof (or a different reviewed construction) that binds `C` to the authorized value and deposit without disclosing the private opening. No such backend is implemented here.
5. The mint state transition must atomically check deposit replay, commitment uniqueness, accepted value, and receipt/state-root update. A future spend transition must atomically reject a previously spent public nullifier.
6. The global hidden (namespace_id, coin_id) uniqueness rule is under review in [CHp4.3](../audit/chp4.3-identity-invariant-decision-review.md). The visible-ID MintRegistryModel is not compatible with the private-issuer message flow as-is. Do not derive coin_id from public deposit data under the current issuer-privacy target. A proposed removal of global uniqueness must analyze same-nullifier output collisions, recipient spendability, wallet/output relations, leakage and malicious witness construction.

Until these conditions are specified and implemented, no live issuance or production mint claims are allowed.

## RFC-01 invariant model

The current candidate commitment already includes namespace, public key bytes, value, coin ID, nullifier secret, parameter ID and independent commitment salt. The primitive-level regression tests verify alternate-opening rejection and nullifier determinism. CHp4.1 adds state-transition-model tests, but these are still not end-to-end tests of a ZK relation or a durable ledger.

Required eventual protocol tests:

- For one valid coin opening, every accepted spend derives the same nullifier.
- A witness with substituted `coin_id` or `r_nf` cannot satisfy the same registered commitment in the spend relation.
- Ledger value and the value in the opening must be identical; the issuance transition must establish this without revealing the opening.
- Replaying a deposit cannot mint a second accepted record.
- Concurrent submissions of one nullifier admit at most one state transition in the local reference model, then in the actual durable/consensus ledger under concurrency, finality, recovery and documented fork/reorg rules.
- Any signed receipt is bound to the canonical namespace, commitment, value, deposit identifier, protocol version and state transition.

## RFC-02 acceptance boundary

The formal relation must include the same selected commitment, public key, value, namespace, coin ID, nullifier secret and transaction semantics. Merely presenting a valid proof of knowledge of an unrelated secret is not authorization.

The two authorization candidates have different policies:

- **Committee-signature mode:** the exact selected threshold-signature scheme is verified for the transaction under the same key bound into the coin commitment. Putting verification inside a circuit has an unknown cost until implemented and measured.
- **Self-spend key-knowledge mode:** the proof establishes the scheme-specific public/secret key relation and binds all transaction fields to the public statement. A generic `PoK(sk)` with no transaction-relation binding is insufficient. This mode does not replace a committee policy when committee approval is a required rule.

No C function-pointer API is being introduced before the relation and authorization semantics are stable.

## RFC-03 rules

- Do not change the production hash because of a guessed constraint count.
- Record exact source revision, proof backend and version, field/circuit model, hash parameters, compiler/runtime, CPU, memory and repetitions.
- Compare valid constructions with stated security targets. The candidate Poseidon2 tuple `t=16, R_F=8, R_P=22, x^7` is **unvalidated proposal data**, not a demonstrated 384-bit capacity or 384-bit security claim.
- Save machine-readable raw runs as CSV/JSON; report median, spread, peak RSS, trace/constraint measure, proof size and verifier time. Do not invent results when the backend adapter is absent.
- Performance budgets are decision aids only, never security acceptance criteria.

## RFC-04 rules

- The current native code uses `OPENSSL_cleanse`; this is not a claim that every process copy is erased.
- Prefer a verified platform API such as `memset_explicit` or `explicit_bzero` only after checking actual target availability and semantics. Do not silently treat a volatile-pointer loop as equivalent certification.
- A disassembly script may report expected wipe call sites in the built wrapper. It cannot prove that every secret copy is cleared or inspect OpenSSL provider internals.
- Welch's t-test / dudect-style timing output is a diagnostic for its test distribution, binary and host. `|t| < 4.5` is not proof of constant-time behavior. Shared-runner timing is non-blocking and must not be interpreted as a release certificate.

## CHp4.3 identity-invariant review

[CHp4.3](../audit/chp4.3-identity-invariant-decision-review.md) is a documentation/test proposal only. It does not change V2 formulas, KATs, production APIs, authorization, ledger behavior or default CI gates. The decision being reviewed is whether global hidden coin-ID uniqueness is a necessary monetary-soundness invariant or a separate identity/spendability policy. Single issuance, issuance/value binding and same-witness nullifier binding are necessary but do not by themselves prove recipient safety when distinct outputs share the same (coin_id, r_nf).

A deterministic fixture at `tests/fixtures/hidden_tuple_reuse.json` and `tests/adversarial/test_hidden_tuple_reuse.py` captures the finite-vector behavior. It is regression evidence only; it is not a proof of collision resistance, a ZK theorem or a production-ledger guarantee.

## Repository maintenance watch

The non-certifying [Repository integrity watch](../../.github/workflows/repo-integrity-watch.yml) runs on pull requests, pushes to `main`, manual dispatch and daily schedule. It checks repository-local Markdown targets, active release-gate markers and invariant fixtures. Dependency updates are reviewed deliberately in consolidated maintenance changes; automated update-PR generation is disabled to avoid branch/PR churn. No cryptographic or toolchain change is auto-merged. The watch does not verify external URLs or cryptographic claims.

## Release gate (all mandatory)

Production remains **NO-GO** until all of these have affirmative, reviewable evidence:

- [ ] Threat model, leakage function and issuer/trustee collusion model frozen.
- [ ] Canonical real-chain namespace mapping and protocol/parameter versioning specified.
- [ ] Issuance protocol proves hidden commitment/value/deposit consistency; no issuer learns `coin_id` or `r_nf` in the stated privacy model.
- [ ] The hidden coin-ID uniqueness invariant is either enforced by a reviewed privacy-preserving mechanism or explicitly revised with an analysis of consequences and leakage.
- [ ] Commitment hiding and binding claims have formal definitions, concrete bounds and independent review.
- [ ] A single instantiated proof proves membership, opening, authorization, nullifier and transaction policy over one witness.
- [ ] Scheme-specific key/authorization relation selected; committee policy is not accidentally dropped.
- [ ] Durable ledger prevents duplicate issuance and atomically rejects repeated nullifiers under concurrency, reorg and recovery.
- [ ] Proof-system soundness, zero knowledge, Fiat–Shamir/QROM assumptions and composed quantum-security loss are analyzed.
- [ ] Reproducible end-to-end performance profile and negative tests pass.
- [ ] Controlled side-channel work and complete implementation/dependency/binary review are complete.
- [ ] Independent cryptographic review has no unresolved critical/high findings.
- [ ] Run and archive the intended-deployment Mainnet smoke with independently sourced trust pins; report a failed/unrun result as NO-GO, never as passed by CI.

**Audit disclosure:** External cryptographic audit is NOT PERFORMED. This is not represented as an audited system. The internal independent review gate is separate and also NOT PERFORMED for CHp4.25.

## Change-control rule

Tests and documentation may be added in an isolated branch. No production API, hash, ledger behavior, authorization mode, or default CI gate changes under these RFCs until its specification is approved and the corresponding test harness exists. Passing CI only confirms executed tests. The base `main` status is unchanged and remains **NO-GO**. The integrity workflow is not a cryptographic release gate; change-control still requires approved specification and an appropriate harness before production semantics or mandatory gates change.
