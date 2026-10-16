# 0PSP — Post-Quantum Private Spend Primitive

> **Release Status: TESTNET / SYNTHETIC TESTING ONLY. MAINNET LIVE-VALUE TRANSFERS: NO-GO.**
> Testnet readiness and green unit tests do not establish production proof soundness, authorization, zero knowledge, custody, finalized state, or recovery readiness.
> External audit is deferred as a separate milestone; internal implementation and cryptographic gates remain mandatory.
0PSP is a research-stage private-spend protocol candidate. It contains C11 cryptographic primitives, a single-node SQLite candidate ledger, EVM proof components, and an experimental OpenVM guest. These components are not yet composed into a complete production spend verifier with proven authorization, trusted finalized state, end-to-end zero knowledge, custody, and recovery.

## Current security gate (2026-10-16; Release Candidate v0.1.0)

- **Local / synthetic candidate validation:** The latest checked Functional Checks run for proof-verifier hardening commit [`216b85f`](https://github.com/Patel5600/0PSp/commit/216b85f5f9013c4329232d71631db89fb863c54f) reports **730 collected, 729 passed, 1 skipped, 0 failures** ([CI run](https://github.com/Patel5600/0PSp/actions/runs/38905101365)). This is a commit-scoped unit/native/invariant result, not evidence of a live testnet deployment or production protocol readiness. The OpenVM workflow covers an experimental one-input/one-output candidate, not the complete accepted spend protocol.
  - *Allowed scope:* deterministic fixtures, local simulation, and testnet-token experiments after verifying the exact deployed configuration. This README does not claim that a live testnet issuance-to-spend-to-recovery flow has been demonstrated.
- **Mainnet Release: NO-GO for all live-value transfers.**
  - `verify_production_proof_envelope()` is hard release-latched off (`PRODUCTION_SPEND_VERIFICATION_ENABLED = False`); the canonical profile declares 0 established composite security bits. Candidate verification helpers are not production acceptance.
  - The complete shared-witness spend relation, production authorization, authenticated root/finality, issuance/custody, reorg/recovery, and end-to-end witness hiding remain mandatory.
  - External audit remains deferred, but that does not waive internal cryptographic and end-to-end evidence.

## Engineering Doctrine (The 5 Pillars)

0PSP adheres strictly to the uncompromising Engineering Doctrine:

1. **Pillar 1: Attacking (Red-Team):** Adversarial suites ([`tests/adversarial/`](tests/adversarial/)) enforcing SQLite fault injection simulating power loss / uncommitted aborts, duplicate-nullifier concurrency races, parent anchor replay prevention, and OpenVM public-statement manipulation.
2. **Pillar 2: Evidence (Empirical):** Fixed cryptographic known-answer tests, differential primitive tests, adversarial/unit suites, and hardware timing diagnostics. Exact counts are commit-specific: the cited proof-verifier hardening CI head reports 729 passed and 1 skipped. A timing screen is a diagnostic, not a constant-time proof.
3. **Pillar 3: Proof (Mathematical):** Theory documents describe conditional primitive reductions and security-game models ([`docs/theory/commitment-hiding-and-binding-proof.md`](docs/theory/commitment-hiding-and-binding-proof.md), [`docs/security/composed-security-games-and-reduction.md`](docs/security/composed-security-games-and-reduction.md)). They do not prove that the current guest, verifier, state adapter, and ledger composition satisfies those assumptions. The composed production soundness bound and end-to-end zero-knowledge guarantee remain unestablished.
4. **Pillar 4: Structures (Rigid Data Models):** Strictly domain-separated binary serialization with fixed little/big-endian lengths, a depth-63/u64 active host-and-OpenVM candidate Merkle profile, typed descriptors (`NamespaceIdV3`), and domain-separated transaction candidate fields (`TxFieldsV3Candidate`). The separate depth-32 Rust helper is experimental and is not the active guest entrypoint.
5. **Pillar 5: Code (Clean & Fail-Closed):** Zero-dependency C11 cryptographic implementation ([`native/`](native/)), explicit memory-cleansing calls (`psp_secure_zero`), optional OS page-locking APIs (`VirtualLock`/`mlock`), an experimental OpenVM guest ([`proof/openvm/`](proof/openvm/)), and native/API fixtures ([`tests/conftest.py`](tests/conftest.py)). These mechanisms do not prove whole-process zeroization, constant-time behavior, or end-to-end protocol security; see open internal gate [#40](https://github.com/Patel5600/0PSp/issues/40).
6. **Pillar 6: Honest Limits (Zero Hype):** Testnet/synthetic testing may proceed within its stated limits. All Mainnet live-value transfers, both capped and uncapped, remain **NO-GO** until implementation, proof, authorization, custody, state, recovery, and integration gates pass on one exact release commit. External audit is deferred separately and is not a substitute for these internal gates.

Canonical review trackers: [Evidence-first RFC register and NO-GO dashboard](docs/security/evidence-first-rfc-register.md), the [Binary Production Gate Matrix](docs/security/production-gate-matrix.md), and the [27-Gate Production Verification Dossier](docs/security/27-gate-verification-dossier.md). Mainnet remains NO-GO until all internal mandatory criteria are evidenced closed on one exact release commit. External audit is deferred and not claimed.

## Architecture and Core Subsystems

0PSP currently contains the following research-stage components; their presence does not imply a production-ready end-to-end protocol:

### 1. Zero-Dependency C11 Cryptographic Engine (`libpsp_native`)
- **Primitive implementation:** Native C11 Keccak-f[1600], SHAKE256-384 and HMAC-SHA3-384 with known-answer and differential tests; claim the exact tested primitives and vectors, not whole-protocol security.
- **Side-channel posture:** The implementation is intended to avoid secret-dependent branches and data-dependent lookups. The RDTSC timing screen is a noisy diagnostic and does not certify constant-time behavior; the broader evidence task remains open in [#40](https://github.com/Patel5600/0PSp/issues/40).
- **Memory handling:** `psp_secure_zero` and platform page-locking calls are present. They do not establish that every secret copy is erased or that all operating-system paging/crash-dump paths are prevented.
- **Cross-Platform:** Compiles cleanly with GCC, Clang, and MSVC across Linux, macOS, and Windows.

### 2. Experimental OpenVM Spend Candidate (`OpenVM v2.0.2`)
- **Status:** non-production candidate only; merged `main` uses a depth-63 Merkle path and u64 leaf index in the active guest. A separate depth-32 Rust helper exists but is not the active entrypoint.
- Candidate fixtures exercise a one-input/one-output predicate, but this is not evidence for complete authorization, authenticated finalized state, issuance/custody, atomic spend composition, or end-to-end zero knowledge.
- Historical proof-size and verification-time measurements apply only to the exact cited experimental guest/configuration; they are not target-device or complete-relation benchmarks.
- **Production requirement:** a pinned real proof verifier must enforce the full accepted relation and be integrated with trusted state and atomic ledger transitions before any live-value release.
### 3. Durable SQLite Ledger & Historical Anchor Ring
- **Atomic State Transitions:** SQLite WAL mode with immediate transactions enforcing unique deposit anchors, unique output commitments, and single-use nullifiers.
- **Historical Anchor Ring:** The current candidate configuration defaults to 4,096 local root/head snapshots; earlier PR #32 evidence used 256. This is local history, not distributed consensus, finalized-state authentication, or external rollback protection.
- **Crash & Fault Injection Resilience:** Tested against uncommitted process aborts, power-loss simulations, concurrent duplicate nullifier races, and direct Merkle node corruption via `audit_integrity()`.

### 4. EVM Light-Client Deposit Evidence & Authorizer
- **Light-Client Finality:** Pinned Helios 0.12.0 light-client integration tracking authenticated execution headers and checkpoint ancestry.
- **Trie Inclusion Proofs:** Strict Ethereum Keccak-256, RLP, and Modified Patricia Trie (MPT) inclusion verifier for transactions and receipts. Verified by 30 differential tests against independent implementations (`pycryptodome`, `rlp`, `HexaryTrie`).
- **Custody Reserve Solvency:** `src/adapters/evm_deposit_authorizer.py` enforces vault reserve solvency (`contract_balance >= total_minted + amount`) before authorizing mint issuance.

## Mathematical Reductions & Formal Security

The theory documents contain conditional reductions and security-game models for selected primitives. These do not establish that the current OpenVM candidate or whole deployed protocol satisfies the assumptions, soundness target, authorization policy, or end-to-end zero-knowledge property:

- **Commitment-binding theory model:** The cited reduction relates SHAKE256-384 binding to collision resistance under the document's quantum-adversary assumptions. It is a conditional primitive argument, not a proof that the current deployed protocol satisfies a composed post-quantum security target.
- **Statistical-hiding theory model:** The cited document states a bound under its formal assumptions and entropy model. That bound has not been established for the active OpenVM proof transcript, verifier, and production state/authorization composition.
- **Composed Security-Game Models:** Defined in [`docs/security/composed-security-games-and-reduction.md`](docs/security/composed-security-games-and-reduction.md). The model claims need to be matched to an accepted implementation and complete proof relation before being treated as production guarantees:
  - **Balance Conservation Game:** Proves no polynomial-time adversary can inflate protocol supply without violating either MPT inclusion, hash collision resistance, or range-bound arithmetic.
  - **Recipient Unlinkability Game (Anonymity):** Formalizes indistinguishability under chosen-witness attacks, ensuring note spends cannot be linked to the recipient or creator.
  - **Double-Spend Replay Prevention Game:** Proves that an accepted spend transition irrevocably consumes the nullifier, preventing any subsequent spend of the same coin.

## Status: The 27-Gate Production Verification Matrix

Every release gate has an explicit status for **Testnet Launch (`v0.1.0-alpha`)** and **Mainnet Real-Value Transfer**. Detailed technical documentation and evidence are recorded in the [27-Gate Production Verification Dossier](docs/security/27-gate-verification-dossier.md) and [Binary Production Gate Matrix](docs/security/production-gate-matrix.md).

The matrix below is formatted as individual gate entries rather than a six-column Markdown table. This keeps statuses, evidence, and outstanding obligations readable on narrow/mobile screens. The same 27 gate records are retained.

### 1. Namespace V2 Frozen Core

- **Testnet:** **GO** · **Mainnet:** **GO (Frozen)**
- **Evidence:** Fixed KATs; [`src/primitives/namespace.py`](src/primitives/namespace.py), [`native/nullifier_v2.c`](native/nullifier_v2.c)
- **Mainnet obligation:** Preserved for historical compatibility

### 2. Namespace V3 Direct-Hash EVM Codec

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Direct SHAKE256-384 hashing; [`native/namespace_v3.c`](native/namespace_v3.c), 40 tests passed
- **Mainnet obligation:** Pinned live mainnet contract deployment manifest

### 3. CommitV2 / NullifierV2 Host & Native APIs

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Zero-dependency C11 constant-time engine; 13 unit tests passed
- **Mainnet obligation:** Full in-circuit spend relation proof binding

### 4. Ethereum Keccak/RLP/MPT Reference Implementation

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Strict Yellow Paper conformance; 30 differential tests passed (`pycryptodome`, `rlp`, `HexaryTrie`)
- **Mainnet obligation:** Live RPC node proof acquisition

### 5. EIP-1186 Account & Storage Proof Verifier

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** MPT inclusion/exclusion against state roots; [`src/adapters/evm_state_proof.py`](src/adapters/evm_state_proof.py)
- **Mainnet obligation:** Authenticated light-client consensus integration

### 6. Durable SQLite Issue & Spend Transitions

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Atomic WAL transactions; fault injection & crash recovery tests passing
- **Mainnet obligation:** Multi-node distributed consensus / L1 sequencing

### 7. Canonical TxFieldsV2 / TxDigestV2 Codec

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Canonical serialization & 48-byte digest; [`src/protocol/transaction_v2.py`](src/protocol/transaction_v2.py)
- **Mainnet obligation:** Proof circuit binding of decoded fields to witness

### 8. Static SHAKE Arithmetization Estimator

- **Testnet:** **GO** · **Mainnet:** **Superseded**
- **Evidence:** 153,600 bit-sliced arithmetic equivalents model; [`scripts/estimate_keccak_zk_cost.py`](scripts/estimate_keccak_zk_cost.py)
- **Mainnet obligation:** Superseded by empirical OpenVM zkVM cycle benchmarks

### 9. Binary-Field Keccak Circuit Model

- **Testnet:** **GO** · **Mainnet:** **Superseded**
- **Evidence:** GF(2) chi-relation constraint model (38,400 rows/perm); [`scripts/estimate_binary_field_keccak.py`](scripts/estimate_binary_field_keccak.py)
- **Mainnet obligation:** Superseded by OpenVM STARK backend

### 10. Durable Replay Protection (Single Node)

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** SQLite primary key constraints & 256-state historical anchor ring (PR #32)
- **Mainnet obligation:** Distributed reorg recovery

### 11. SmallWood Python R1CS Dense Adapter

- **Testnet:** **NO-GO** · **Mainnet:** **NO-GO**
- **Evidence:** Audited in [`CHp4.22`](docs/audit/chp4.22-smallwood-r1cs-adapter-scaling.md); materializes $\ge 2.082\text{ TiB}$ RAM
- **Mainnet obligation:** Screened out and rejected as infeasible

### 12. Aurora/libiop Binary-Extension Backend

- **Testnet:** **NO-GO** · **Mainnet:** **NO-GO**
- **Evidence:** Audited in [`CHp4.20`](docs/audit/chp4.20-zk-backend-feasibility.md); pristine build failure and PoW gap
- **Mainnet obligation:** Screened out and rejected

### 13. RISC Zero zkVM Zero-Knowledge Guarantee

- **Testnet:** **NO-GO** · **Mainnet:** **NO-GO**
- **Evidence:** Screened out due to maintainer security advisory GHSA-5xgj-pmjj-gw49
- **Mainnet obligation:** Screened out and rejected

### 14. Proof-Backend Selection (OpenVM v2.0.2)

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** OpenVM v2.0.2 Rust zkVM guest circuit (`spend_v3.rs`); 5 adversarial suites pass
- **Mainnet obligation:** Full-prover trace ZK masking on production target hardware

### 15. ZK Transaction-Digest Binding

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Host encoding bound inside `spend_v3.rs` to public statement digest
- **Mainnet obligation:** Production prover trace ZK masking

### 16. Commit Opening Inside Proof

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** SHAKE256-384 commitment opening verified over private witness in `spend_v3.rs`
- **Mainnet obligation:** Production prover trace ZK masking

### 17. Same-Witness Nullifier Binding

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** HMAC-SHA3-384 nullifier proven with identical note key $nk$ in `spend_v3.rs`
- **Mainnet obligation:** Production prover trace ZK masking

### 18. Value Conservation & Output Opening

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** $v_{in} = v_{out} + fee$ strictly checked with range safety in `spend_v3.rs`
- **Mainnet obligation:** Production prover trace ZK masking

### 19. Authorization Predicate in Spend Relation

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Spend authorized via knowledge of note nullifier key $nk$ bound to recipient bundle
- **Mainnet obligation:** Production prover trace ZK masking

### 20. Trusted EVM DepositAuthorization

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** [`src/adapters/evm_deposit_authorizer.py`](src/adapters/evm_deposit_authorizer.py) composes Helios, MPT, and solvency checks
- **Mainnet obligation:** Live Mainnet RPC node proof acquisition

### 21. Contract/Token Custody Semantics

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Pinned bytecode fingerprint and ERC-20 transfer matching verified
- **Mainnet obligation:** Live Ethereum smart contract audit & deployment

### 22. Coin-ID Reuse & Output Collision Prevention

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Output identity derived from parent anchor + slot index; collision prevention proven
- **Mainnet obligation:** Live Ethereum smart contract audit & deployment

### 23. Issuer Privacy & Commitment Hiding

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** Conditional primitive/theory model only; end-to-end witness hiding for the active proof path remains NO-GO until backend-level trace/quotient and transcript evidence is provided.
- **Mainnet obligation:** Full prover trace ZK masking for Mainnet

### 24. Real Ethereum Mainnet Smoke Test

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** 24 tests in [`tests/unit/test_namespace_mainnet_smoke.py`](tests/unit/test_namespace_mainnet_smoke.py) pass on synthetic data
- **Mainnet obligation:** Live-network proof acquisition & execution

### 25. Whole-Protocol Internally Audited Composition

- **Testnet:** **GO** · **Mainnet:** **Gated**
- **Evidence:** 650 automated tests passing with zero failures across Linux and Windows
- **Mainnet obligation:** Independent third-party audit

### 26. External Cryptographic Audit

- **Testnet:** **DEFERRED** · **Mainnet:** **DEFERRED**
- **Evidence:** Deliberately scheduled post-launch milestone prior to real-value transfer
- **Mainnet obligation:** Third-party external audit completion

### 27. **Complete 0PSP Production Release**

- **Testnet:** **GO** · **Mainnet:** **NO-GO**
- **Evidence:** **v0.1.0-alpha Testnet Launch is GO**; Mainnet live-value transfer is gated
- **Mainnet obligation:** All mandatory external criteria evidenced closed

## Increment & Audit Registry

0PSP's development is tracked across foundational RFCs and chronological Checkpoint (CHp) audit increments:

- [RFC-01: user-committed issuance](docs/security/rfc-01-user-committed-issuance.md) — Hiding and binding formal proof in QROM, deposit evidence normalizer, and authorizer adapter.
- [RFC-02: V2-only spend relation](docs/theory/spend-relation-spec.md) — Frozen V2 equations and component specifications.
- [CHp4.7: V3 candidate relation](docs/theory/spend-relation-v3-candidate.md) — Recipient-keyed nullifier and output identity candidate, instantiated in OpenVM `spend_v3.rs`.
- [RFC-03: hash/circuit benchmark](docs/plan/rfc-03-hash-circuit-benchmark.md) — Empirical OpenVM v2.0.2 prover and verifier benchmark metrics.
- [RFC-04: side-channel diagnostics](docs/security/rfc-04-side-channel-diagnostics.md) — Zero-dependency C11 constant-time engine, `psp_secure_zero` memory barrier scrubbing, physical RAM pinning, and cycle-accurate hardware RDTSC timing screens.
- [CHp4.1: reference state transitions](docs/audit/chp4.1-reference-state-transitions.md) — Reference state model and linearizability checks.
- [CHp4.2: formal relations and adversarial tests](docs/audit/chp4.2-formal-relations-adversarial-tests.md) — Exact V2 component equations and finite primitive regressions.
- [CHp4.3: identity-invariant review](docs/audit/chp4.3-identity-invariant-decision-review.md) — Hidden identity uniqueness decision review.
- [CHp4.4: deterministic output-ID review](docs/audit/chp4.4-deterministic-output-id-proposal-review.md) — Adversarial review rejecting public-derived output IDs.
- [CHp4.5: hidden-witness output-identity review](docs/audit/chp4.5-hidden-witness-output-identity-proposal-review.md) — Adversarial specification review of field widths and collision claims.
- [CHp4.6: output-identity candidate and tests](docs/audit/chp4.6-output-identity-candidate-and-tests.md) — Reference candidate implemented with hardcoded regressions.
- [CHp4.7: identity uniqueness and nullifier safety](docs/audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md) — Complete spend-identity policy, recipient-keyed nullifier, and anchor output derivation.
- [CHp4.8: Namespace V2 EVM adapter](docs/audit/chp4.8-namespace-v2-evm-adapter.md) — Historical EVM adapter mapping retained for audit.
- [CHp4.9: Namespace V3 direct-hash remediation](docs/audit/chp4.9-namespace-v3-direct-hash-remediation.md) — Single SHAKE256-384 direct hashing of canonical EVM descriptors.
- [CHp4.10: namespace RPC quorum and durable finality journal](docs/audit/chp4.10-namespace-rpc-finality-hardening.md) — Strict-majority read-only RPC policy and SQLite finalized header journal.
- [CHp4.11: EVM deposit evidence contract](docs/audit/chp4.11-evm-deposit-evidence-contract.md) — Canonical receipt/event observation, log identity, and beneficiary binding.
- [CHp4.12: EVM transaction and receipt trie inclusion verifier](docs/audit/chp4.12-evm-trie-inclusion-verifier.md) — Strict Ethereum Keccak/RLP/MPT primitives and receipt trie inclusion.
- [CHp4.13: Ethereum Mainnet light-client finality integration](docs/audit/chp4.13-helios-authenticated-finality.md) — Supervised pinned Helios 0.12.0 light-client process with checkpoint ancestry.
- [CHp4.14: deposit asset-movement evidence](docs/audit/chp4.14-asset-movement-evidence.md) — Native value and ERC-20 Transfer log matching with code fingerprinting.
- [CHp4.15: authenticated EVM state proofs](docs/audit/chp4.15-authenticated-evm-state-proofs.md) — EIP-1186 account and storage proofs against authenticated block headers.
- [CHp4.16: Ethereum proof differential tests](docs/audit/chp4.16-ethereum-proof-differential-tests.md) — Differential conformance tests against `pycryptodome`, `rlp`, and `HexaryTrie`.
- [CHp4.17: durable ledger and commitment Merkle tree](docs/audit/chp4.17-durable-merkle-ledger.md) — Depth-63 namespace-bound Merkle tree with transactional SQLite ledger.
- [CHp4.18: canonical V2 transaction and digest](docs/audit/chp4.18-canonical-spend-transaction-v2.md) — Canonical TxFieldsV2 serialization and 48-byte TxDigestV2 computation.
- [CHp4.20: proof-backend feasibility](docs/audit/chp4.20-zk-backend-feasibility.md) — Audit and evaluation of post-quantum ZK backends.
- [CHp4.21: static SHAKE arithmetization cost model](docs/audit/chp4.21-keccak-zk-cost-model.md) — Parameterized cost model for bit-sliced Keccak arithmetization.
- [CHp4.22: SmallWood Python R1CS adapter scaling audit](docs/audit/chp4.22-smallwood-r1cs-adapter-scaling.md) — Audit finding dense generic adapter requires $\ge 2.082$ TiB RAM (rejected).
- [CHp4.23: binary-field Keccak feasibility](docs/audit/chp4.23-binary-field-keccak-feasibility.md) — Characteristic-two circuit-row model for Keccak-f[1600].
- [CHp4.26: historical-anchor concurrency remediation](docs/audit/chp4.26-historical-anchor-concurrency-remediation.md) — Merged 256-state historical anchor ring (PR #32) allowing concurrent spends.
- [CHp4.27: authorization and proof-backend candidate screen](docs/audit/chp4.27-authorization-and-backend-candidate-screen.md) — Screen establishing OpenVM v2.0.2 zkVM guest circuit adoption.

## Build and verification

### Prerequisites
- Python 3.11+
- C Compiler (GCC, Clang, or MSVC) and `make`
- Binutils (optional, for disassembly checks)
- *Note: OpenSSL development headers are no longer required (zero-dependency native engine).*

### 1. Build and Run Full Test Suite

```bash
# Install Python development dependencies
python -m pip install -e ".[dev]"

# Build and test zero-dependency C11 native engine
make -C native test

# Run the complete test suite (650 tests)
python -m pytest tests/ -q
```

### 2. Microarchitectural Hardware Timing Probes

Run cycle-accurate hardware RDTSC timing screens locally on a quiet machine:

```bash
make -C native timing-v2-probe-build
make -C native timing-v2
make -C native timing-commitment-v2-probe-build
make -C native timing-commitment-v2
```

### 3. Repository Integrity Watch

Verify local Markdown documentation targets, release-gate markers, and invariant fixtures:

```bash
python scripts/check_repo_integrity.py
python -m pytest tests/adversarial/test_hidden_tuple_reuse.py -q
```

## Security Specifications and Technical Records

- [Documentation Map and Maintenance Policy](docs/README.md)
- [Evidence-First RFC Register and NO-GO Dashboard](docs/security/evidence-first-rfc-register.md)
- [Binary Production Gate Matrix](docs/security/production-gate-matrix.md)
- [27-Gate Production Verification Dossier](docs/security/27-gate-verification-dossier.md)
- [Commitment Hiding and Binding Formal Reduction in QROM](docs/theory/commitment-hiding-and-binding-proof.md)
- [Composed Security Games and Concrete Reduction](docs/security/composed-security-games-and-reduction.md)
- [Side-Channel and Constant-Time Release Gates](docs/security/chp4-constant-time-and-side-channel-spec.md)
- [V2 Namespace, Commitment and Security Argument](docs/security/v2-protocol-security-argument.md)
- [Constructionable V0 Target](docs/theory/constructionable-v0.md)
- [Spend Relation and Proof Binding](docs/theory/spend-relation-and-proof-binding.md)
- [Nullifier-Bound Spend Soundness](docs/theory/nullifier-bound-spend-soundness.md)
- [Proof-System Feasibility Study](docs/theory/proof-system-feasibility-study.md)
- [Ringtail Adapter Contract](docs/theory/ringtail-adapter-contract.md)
- [RFC-01 User-Committed Issuance](docs/security/rfc-01-user-committed-issuance.md)
- [RFC-02 Spend Relation Specification](docs/theory/spend-relation-spec.md)
- [RFC-03 Hash/Circuit Benchmark Protocol](docs/plan/rfc-03-hash-circuit-benchmark.md)
- [RFC-04 Native Memory/Side-Channel Diagnostics](docs/security/rfc-04-side-channel-diagnostics.md)
- [CHP4 Construction-Readiness Record](docs/security/chp4-construction-readiness.md)
- [Dependency-Minimization and Construction Roadmap](docs/plan/dependency-minimization-and-construction-roadmap.md)
- [Mobile-First Prover Architecture and Memory Budget](docs/theory/mobile-first-prover-architecture-and-memory-budget.md)
