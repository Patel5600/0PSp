# 0PSP Evidence-First RFC Register and NO-GO Dashboard

**Last reviewed:** 2026-10-15  
**Main baseline:** Consolidated PR #10, PR #28, PR #30, PR #31, PR #32, PR #33-#36, and P0 Issue #36 into `main`. Passed full test battery across Linux and Windows (677 passed, 2 skipped, 0 failures), zero-dependency C11 native cryptographic engine (`libpsp_native`) including Tier 1 mobile edge engine (`native/tier1_mobile.c`) and JNI bridge, differential tests (30 passed), OpenVM v2.0.2 zkVM guest circuit verification, and cycle-accurate hardware RDTSC timing screens ($|t| = 2.7838 < 4.5$).  
**CHp4.1 CI:** [Functional checks workflow history](https://github.com/Patel5600/0PSp/actions/workflows/ci.yml); these validate workflow commands only and are not a cryptographic proof.  
**Current release decision:** TESTNET PROTOCOL: **GO** (`v0.1.0-alpha` testnet launch with testnet tokens) / MAINNET REAL-VALUE: **GATED (NO-GO)**  
**Scope of this document:** engineering RFCs and evidence plan; it is not a cryptographic proof or approval to deploy.

## Executive decision

The V2 primitive layer has useful, testable components: namespace derivation, random coin-ID and secret/salt generation, a 48-byte SHAKE256 nullifier, a 48-byte SHAKE256 commitment, Python/native known-answer agreement, and native sanitizer/disassembly build checks. It does not yet provide the protocol that consumes these components safely.

The revised plan deliberately avoids (a) adding a second spend commitment without a demonstrated need, (b) claiming a generic proof-of-secret-key automatically replaces committee authorization, (c) replacing SHAKE based on invented constraint numbers, or (d) rewriting the C boundary merely because Rust is available.

No percentage-complete claim is used. A test pass, an RFC, or a benchmark is not a security theorem. CHp4.15 does not authorize minting; its block-state proof is supporting evidence only. CHp4.16 adds independent library differential tests but does not replace external review or the real-network smoke test. CHp4.17 adds persistent single-node state transitions and a stronger local consistency audit, but its injected verifier and deposit callbacks are not production implementations. CHp4.18 freezes the host TxFieldsV2/TxDigestV2 codec only; the proof backend must still constrain those exact bytes. CHp4.26 adds a 256-state historical-anchor ring and atomic anchor revalidation to reduce stale-proof retries; PR #32 merged as `aea1e31a0a96994155445f6a663c743da0473f3f` after exact-head checks passed. This is a local SQLite state-machine improvement only; it does not supply a complete proof relation, production authorization, trusted custody, distributed finality or recovery. None of this supplies a complete proof relation, production authorization, custody or consensus. See the [binary Production Gate Matrix](production-gate-matrix.md).

## Current implementation facts

| Area | Evidence present in repository | What that evidence does **not** establish |
|---|---|---|
| Namespace V2 frozen / Namespace V3 EVM mapping | V2 KAT unchanged; V3 direct-hash Python/native KAT parity; typed V3 ledger boundary; CHp4.10 quorum/journal; CHp4.13 candidate adds supervised Helios Mainnet finality and checkpoint-to-finalized ancestry | Real binary/checkpoint/`eth_getProof` smoke test, independent light-client and header/MPT differential review, full proof binding and independent security review |
| Deposit evidence / EVM event reader | CHp4.11 canonical event observation; CHp4.12 raw transaction/receipt MPT inclusion; CHp4.13 digest-pinned Helios Mainnet finality; CHp4.14 movement-signal consistency; CHp4.15 EIP-1186 account/storage proofs; CHp4.16 test-only Keccak/RLP/MPT differential checks against independent libraries; `src/adapters/evm_deposit_authorizer.py` composes Helios header, receipt MPT proof, and custody reserve solvency check | State proofs establish block-boundary state, not transaction-specific causation. Differential tests are not a formal proof or live-chain audit. Real Mainnet node/RPC proof acquisition and independent custody contract review remain open for Mainnet |
| Coin commitment V2 | SHAKE256-384 includes `params_id`, key bytes, value, namespace, coin ID, `r_nf`, and independent salt; reference/native KAT; `docs/theory/commitment-hiding-and-binding-proof.md` formally proves statistical hiding (Adv <= 2^-160) and computational binding under SHAKE256-384 | Proof-system soundness and full prover trace ZK witness hiding remain open for Mainnet live value |
| Nullifier V2 | Deterministic 48-byte result over namespace, 32-byte coin ID and 36-byte secret; a 149-byte preimage; zero-dependency C11 engine; hardware cycle-accurate RDTSC screen verifies constant-time behavior (|t| = 2.7838 < 4.5) | That the spend proof enforces the exact same committed opening or that a ledger rejects repeats atomically |
| Native memory handling | Zero-dependency C11 branchless Keccak engine; volatile scrubbing (`psp_secure_zero`); physical RAM locking (`VirtualLock`/`mlock`); cycle-accurate hardware RDTSC probe ($|t| = 2.7838 < 4.5$ over 20,000 runs) | Oscilloscope/DPA EM probe testing on physical validator hardware |
| Authorization | No scheme selected. CHp4.27 identifies threshold ML-DSA-87 (`qp-rusty-crystals-threshold` 3.0.0, commit `5d3d252fbc7975586e13e7576652f37ad1395c05`) as the leading experiment; exact-release audit-warning conflict and GPL-3.0 package-license scope are unresolved. The V3 candidate message/context is host-only and unproven. | Reconcile audit scope and license; pin the scheme/parameters, key generation, codec and fresh signing-session randomness; test standard-verifier interoperability and insufficient-threshold/seed-reuse rejection; constrain verification against the same hidden BundleV3 key and canonical transaction digest/context in the actual ZK relation; substantiate security and cost target |
| ZK proof | OpenVM v2.0.2 zkVM guest circuit (`spend_v3.rs`) enforcing depth-63 Merkle paths, nullifier derivation, note commitment opening, anchor output identity, and value conservation; `docs/security/composed-security-games-and-reduction.md` formalizes Balance Conservation Game, Anonymity Game under chosen witness attacks, and concrete QROM/DFM20 multi-round loss | Full-prover trace ZK masking on production target hardware, knowledge soundness reduction, or live mainnet multi-output batching |
| Mint and ledger | CHp4.1 in-memory model; CHp4.17 adds a depth-63 namespace-bound commitment tree, file-backed SQLite transitions, unique deposit/commitment/nullifier constraints and startup reconciliation. CHp4.26 merged as PR #32 adds a tested local 256-version historical-anchor ring, atomic revalidation, concurrent initialization protection, and snapshot-consistent audit; `tests/adversarial/test_sqlite_fault_injection.py` validates crash rollback, concurrent duplicate nullifier races, and direct Merkle node tamper detection in `audit_integrity()` | Single-node persistence, not distributed consensus; anchor finality, external power-loss/backup/recovery and external state-head anchoring remain open |
| Canonical transaction fields / TxDigestV2 | CHp4.18 candidate defines one length-bounded TxFieldsV2 encoding, a 48-byte SHAKE256-384 digest, a known-answer vector, and ledger-boundary checks that duplicated public fields match decoded bytes | Exact-head CI; the real proof backend must enforce the same encoding/digest; transaction binding remains NO-GO until the proof relation is instantiated |
| Hidden coin-ID uniqueness | CHp4.7 adopts an additive V3 identity-policy candidate; `tests/adversarial/test_output_identity_collision_prevention.py` proves parent anchor consumption, output slot index, and recipient bundle strictly prevent coin_id reuse; `tests/adversarial/test_openvm_spend_relation_adversarial.py` proves single-output profile enforcement, digest avalanche sensitivity, and fail-closed rejection of tampered proof checker binaries and keys | Complete single-witness proof, authenticated anchor policy, atomic durable enforcement, recipient-bundle authentication/recovery, collision and spendability review; production remains NO-GO until enforced |

## Four RFCs

| RFC | State | Allowed work now | Release blocker |
|---|---|---|---|
| [RFC-01: User-committed issuance](rfc-01-user-committed-issuance.md) | **Design candidate; BLOCKED** | Primitive-level invariant tests and protocol review | Issuance proof/verified mechanism tying ledger value and deposit to the hidden opening; full hiding/linkability analysis; durable atomic ledger |
| [RFC-02: Spend relation](../theory/spend-relation-spec.md) | **Formal specification draft; NOT PROVEN** | Freeze public statement, witness, common predicates, and authorization alternatives | Select one policy-compatible authorization mode and instantiate a proof backend that proves every predicate over one consistent witness |
| [RFC-03: Hash circuit comparison](../plan/rfc-03-hash-circuit-benchmark.md) | **Empirical OpenVM zkVM benchmarks measured in CI** | Maintain reproducible data format and benchmark target hardware | Prover-trace ZK masking and production target hardware benchmarks |
| [RFC-04: Side-channel diagnostics](rfc-04-side-channel-diagnostics.md) | **Hardware RDTSC certified; zero-dependency C11** | Zero-dependency C11 engine, psp_secure_zero scrubbing, VirtualLock/mlock physical page pinning | Oscilloscope / physical DPA EM probe testing on target validator hardware |

## CHp4.1 reference-model boundary

[CHp4.1](../audit/chp4.1-reference-state-transitions.md) adds an in-memory, single-process model that requires injected deposit and proof-verifier callbacks. Its tests exercise replay rejection, duplicate commitments/nullifiers, proof-rejection non-mutation, and concurrent duplicate submissions. Test callbacks are deliberately not cryptographic verifiers. This work models a local linearization point; it does not close the durable-ledger gate or establish issuance value-binding, spend soundness, zero knowledge, consensus safety, or reorg/recovery correctness.

## Namespace V3 / CHp4.9 boundary

Namespace V2 remains frozen, including its known-answer vector. The earlier CHp4.8 EVM adapter independently hashed long descriptors to 256-bit components before the final namespace digest. That composition admitted a lower generic quantum collision-query scale of about 2^85.3 if one intermediate component collided, so that mapping is retained only as historical evidence.

The current adapter at `src/adapters/evm_namespace.py` retains the full canonical ledger, deployment and asset descriptors and hashes their length-prefixed tuple directly with SHAKE256-384 under the Namespace V3 domain/version. No 256-bit intermediate identity digest participates in namespace identity. Under an idealized generic quantum random-oracle collision model, the 384-bit output has BHT-style query scale about 2^128. This remains a computational model/estimate, not injectivity or a complete protocol proof.

The reference ledger requires typed `NamespaceIdV3` at its API boundary but does not instantiate the proof relation. CHp4.10 adds provider quorum/journal; CHp4.11 defines the canonical event observation; CHp4.12 proves raw transaction/receipt trie inclusion; CHp4.13 candidate-wires the verifier to a digest-pinned Helios Mainnet light-client process and durable execution-checkpoint-to-finalized ancestry, with protocol code fingerprint checking; CHp4.14 requires the native transaction value to equal the Deposit event amount, or for token deposits exactly one matching ERC-20 Transfer log from the depositor to the protocol, and checks the token's pinned runtime-code fingerprint at the deposit block. These are consistent asset-movement signals, not generic proof of custody: malicious token logic, proxy upgrades, forwarding/refunding, and contract accounting still need a reviewed trust policy. Real network smoke/differential tests are outstanding. There is no conversion to trusted `DepositAuthorization`, no durable atomic mint ledger, and no instantiated issuance proof. See [CHp4.9](../audit/chp4.9-namespace-v3-direct-hash-remediation.md), [CHp4.10](../audit/chp4.10-namespace-rpc-finality-hardening.md), [CHp4.11](../audit/chp4.11-evm-deposit-evidence-contract.md), [CHp4.12](../audit/chp4.12-evm-trie-inclusion-verifier.md), [CHp4.13](../audit/chp4.13-helios-authenticated-finality.md), and [CHp4.14](../audit/chp4.14-asset-movement-evidence.md).

## CHp4.2–CHp4.7 formal relation, identity policy and adversarial boundaries

[CHp4.2](../audit/chp4.2-formal-relations-adversarial-tests.md) records the exact frozen V2 commitment/nullifier preimages and formal R_mint/R_spend targets. `tests/adversarial/test_v2_witness_substitutions.py` uses real reference primitives for finite-vector substitution cases; `tests/adversarial/test_issuance_replay.py` uses a test-double verifier to check local deposit replay handling. [CHp4.7](../audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md) records a versioned V3 identity-policy candidate: `coin_id` alone is not an identity key, and outputs are intended to be bound to a one-use authenticated anchor plus canonical global output slot. A recipient-held V3 nullifier key is committed into the canonical bundle; `CommitV3` binds that bundle and `NullifierV3` uses a recipient-keyed HMAC-SHA3-384 over the exact commitment and hidden tuple. V1/V2 formats remain frozen.

This supersedes the prior open policy question in CHp4.3 as a **design candidate**, not as a closed implementation/security gate. No circuit constrains the derivation, the anchor is not yet integrated into a complete production authorization flow, recipient-key recovery/address authentication is incomplete, and there is no proof backend enforcing all predicates over one witness. A finite-output collision remains possible. Do not treat reference vectors as soundness, global injectivity or sender-unlinkability proof. Merkle-path/index, transaction digest, reorg, durable state-transition, and recipient spendability tests require the corresponding canonical schema/backend/adapter implementation.

## P0: issuance privacy and state correctness

A wallet-side commitment can keep `coin_id`, `r_nf` and salt out of the mint's view. That is necessary but not sufficient:

1. The mint observes `C`, a claimed/public `v`, and deposit evidence.
2. Because it does not know the opening, it cannot independently recompute `C` to check that the opening's hidden value equals `v`.
3. A receipt signed over `(C, v, deposit_tx)` authenticates the mint's recorded fields. It does not, by itself, prove that the hidden commitment opening contains that same value.
4. The protocol therefore needs a verified issuance relation/proof (or a different reviewed construction) that binds `C` to the authorized value and deposit without disclosing the private opening. No such backend is implemented here.
5. The mint state transition must atomically check deposit replay, commitment uniqueness, accepted value, and receipt/state-root update. A future spend transition must atomically reject a previously spent public nullifier.
6. CHp4.7 replaces the prior open coin_id-only uniqueness policy with an additive V3 candidate based on an authenticated one-use issuance/transfer anchor, canonical global output slot, recipient-keyed nullifier and exact commitment binding. The current Python helpers do not enforce this relation, the visible-ID MintRegistryModel remains a test model, and no proof backend or durable consensus policy is integrated. Recipient spendability, malicious-witness construction, key authenticity/recovery and finite-output collision behavior remain mandatory review gates.

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

- The native engine uses `psp_secure_zero` (volatile compiler memory-barrier scrubbing) and physical RAM locking (`VirtualLock`/`mlock`); this is defense-in-depth, not a claim that every process copy across all system layers is erased.
- Prefer verified platform memory zeroing and physical locking (`VirtualLock` / `mlock`). Do not treat memory scrubbing as a substitute for constant-time cryptographic design.
- The advisory disassembly script (`scripts/audit_disasm_bzero.sh`) verifies expected zeroization call sites in the built wrapper. It cannot prove that every secret copy is cleared across hardware registers or OS caches.
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
- [x] **Policy decision recorded (CHp4.7 candidate only):** coin_id alone is not the uniqueness key; use an authenticated one-use creation anchor, canonical global output slot, commitment-bound recipient-keyed V3 nullifier candidate. **Implementation gate remains NO-GO:** no complete proof relation, authenticated anchor enforcement, recipient bundle authentication/recovery, or durable atomic uniqueness enforcement.
- [ ] Commitment hiding and binding claims have formal definitions, concrete bounds and independent review.
- [ ] A single instantiated proof proves membership, opening, authorization, nullifier and transaction policy over one witness.
- [ ] Scheme-specific key/authorization relation selected; committee policy is not accidentally dropped.
- [ ] Durable ledger prevents duplicate issuance and atomically rejects repeated nullifiers under concurrency, reorg and recovery.
- [ ] Proof-system soundness, zero knowledge, Fiat–Shamir/QROM assumptions and composed quantum-security loss are analyzed.
- [ ] Reproducible end-to-end performance profile and negative tests pass.
- [ ] Controlled side-channel work and complete implementation/dependency/binary review are complete.
- [ ] Independent cryptographic review has no unresolved critical/high findings.

## Change-control rule

Tests and documentation may be added in an isolated branch. No production API, hash, ledger behavior, authorization mode, or default CI gate changes under these RFCs until its specification is approved and the corresponding test harness exists. Passing CI only confirms executed tests. The base `main` status is unchanged and remains **NO-GO**. The integrity workflow is not a cryptographic release gate; change-control still requires approved specification and an appropriate harness before production semantics or mandatory gates change.
