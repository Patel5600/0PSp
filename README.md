# 0PSP ? Private Spend Protocol

> **Production-1 local synthetic test value: GO** | **Public testnet value: NO-GO** | **Mainnet live value: NO-GO**

Production-1 freezes a one-input/one-output OpenVM spend relation and uses the same pinned proof verifier and SQLite state transition for local test value. The single-tenant Phase A worker receives plaintext witness over authenticated TLS; the operator can read it. The OpenVM profile is below the 128-bit target and does not establish end-to-end witness hiding. This status does not authorize public-chain deployment or real-value transfers. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md), [the accepted relation](docs/security/ACCEPTED_SPEND_RELATION_V3.md), and [the gate matrix](docs/security/production-gate-matrix.md).

The Production-1 check builds the OpenVM guest and verifier, runs the repository tests, then exercises a synthetic local note through worker proving, client verification, ledger acceptance, and duplicate-spend rejection. Follow [Production-1 setup](proof/openvm/v3-nullifier-spike/README.md#clean-machine-production-1-check) from a clean Linux machine.

Threshold multi-party authorization, Monero ring signatures/RingCT, mobile proving, and public-chain issuance are not implemented. External audit remains deferred; mainnet live value stays NO-GO.

## Engineering Doctrine (The 5 Pillars)

0PSP adheres strictly to the uncompromising Engineering Doctrine:

1. **Pillar 1: Attacking (Red-Team):** Adversarial suites ([`tests/adversarial/`](tests/adversarial/)) enforcing SQLite fault injection simulating power loss / uncommitted aborts, duplicate-nullifier concurrency races, parent anchor replay prevention, and OpenVM public-statement manipulation.
2. **Pillar 2: Evidence (Empirical):** Fixed cryptographic known-answer tests, differential primitive tests, adversarial/unit suites, and hardware timing diagnostics. Exact counts are commit-specific: the cited proof-verifier hardening CI head reports 729 passed and 1 skipped. A timing screen is a diagnostic, not a constant-time proof.
3. **Pillar 3: Proof (Mathematical):** Theory documents describe conditional primitive reductions and security-game models ([`docs/theory/commitment-hiding-and-binding-proof.md`](docs/theory/commitment-hiding-and-binding-proof.md), [`docs/security/composed-security-games-and-reduction.md`](docs/security/composed-security-games-and-reduction.md)). They do not prove that the current guest, verifier, state adapter, and ledger composition satisfies those assumptions. The composed production soundness bound and end-to-end zero-knowledge guarantee remain unestablished.
4. **Pillar 4: Structures (Rigid Data Models):** Strictly domain-separated binary serialization with fixed little/big-endian lengths, a depth-63/u64 active Production-1 host-and-OpenVM Merkle relation, typed descriptors (`NamespaceIdV3`), and domain-separated transaction fields. The separate depth-32 Rust helper is not the active guest entrypoint.
5. **Pillar 5: Code (Clean & Fail-Closed):** Zero-dependency C11 cryptographic implementation ([`native/`](native/)), explicit memory-cleansing calls (`psp_secure_zero`), optional OS page-locking APIs (`VirtualLock`/`mlock`), a pinned OpenVM Production-1 spend guest ([`proof/openvm/`](proof/openvm/)), and native/API fixtures ([`tests/conftest.py`](tests/conftest.py)). These mechanisms do not prove whole-process zeroization, constant-time behavior, or end-to-end witness hiding; see [LIMITATIONS.md](docs/LIMITATIONS.md).
6. **Pillar 6: Honest Limits (Zero Hype):** Testnet/synthetic testing may proceed within its stated limits. All Mainnet live-value transfers, both capped and uncapped, remain **NO-GO** until implementation, proof, authorization, custody, state, recovery, integration, and independent external-audit gates pass on one exact release commit.

Canonical review trackers: [Evidence-first RFC register and NO-GO dashboard](docs/security/evidence-first-rfc-register.md), the [Binary Production Gate Matrix](docs/security/production-gate-matrix.md), and the [27-Gate Production Verification Dossier](docs/security/27-gate-verification-dossier.md). Mainnet remains NO-GO until all internal mandatory criteria are evidenced closed on one exact release commit and an independent external audit is completed. No audit is claimed.

## Architecture and Core Subsystems

Production-1 provides the scoped local test-value spend path described above. Other components below remain research or integration-stage; their presence does not imply a complete Mainnet protocol:

### 1. Zero-Dependency C11 Cryptographic Engine (`libpsp_native`)
- **Primitive implementation:** Native C11 Keccak-f[1600], SHAKE256-384 and HMAC-SHA3-384 with known-answer and differential tests; claim the exact tested primitives and vectors, not whole-protocol security.
- **Side-channel posture:** The implementation is intended to avoid secret-dependent branches and data-dependent lookups. The RDTSC timing screen is a noisy diagnostic and does not certify constant-time behavior; the broader evidence task remains open in [#40](https://github.com/Patel5600/0PSp/issues/40).
- **Memory handling:** `psp_secure_zero` and platform page-locking calls are present. They do not establish that every secret copy is erased or that all operating-system paging/crash-dump paths are prevented.
- **Cross-Platform:** Compiles cleanly with GCC, Clang, and MSVC across Linux, macOS, and Windows.

### 2. OpenVM spend_v3 (`OpenVM v2.0.2`)
- Production-1 freezes the active guest to one input, one output, and a namespace-scoped depth-63 path. It constrains NK possession, CommitV3 opening, same-witness NullifierV3, value conservation, and anchor/slot-bound output identity.
- The pinned upstream profile targets 100 bits; the measured parameter analysis is below 128 bits. The proof does not establish end-to-end witness hiding or masked prover traces. See [BENCH.md](BENCH.md) and [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
### 3. Durable SQLite Ledger & Historical Anchor Ring
- **Atomic State Transitions:** SQLite WAL mode with immediate transactions enforcing unique deposit anchors, unique output commitments, and single-use nullifiers.
- **Historical Anchor Ring:** The current candidate configuration defaults to a 256-anchor local root/head window. This is local history, not distributed consensus, finalized-state authentication, or external rollback protection.
- **Crash & Fault Injection Resilience:** Tested against uncommitted process aborts, power-loss simulations, concurrent duplicate nullifier races, and direct Merkle node corruption via `audit_integrity()`.

### 4. Single-tenant OpenVM proof worker (Phase A)
- The worker exposes `POST /v1/prove` over TLS with bearer authentication, a fixed circuit ID, bounded JSON witness payload, concurrency one, and no request-body logs. It wipes mutable witness buffers and reports prove time and child peak RSS.
- Phase A sends plaintext witness bytes to the operator-controlled worker. The operator can read them; this does not provide witness confidentiality from the service. No attested TEE Phase B exists.
- The Production-1 CLI verifies the proof locally, then the ledger independently verifies and atomically accepts it. Its faucet/bootstrap data is synthetic and carries no external finality claim. See the [relation specification](SPEC.md) and [limitations](docs/LIMITATIONS.md).
- Run `make production-check` for the local mint-note, worker prove, client verify, ledger accept, and duplicate-spend rejection path.

### 5. EVM Light-Client Deposit Evidence & Authorizer
- **Light-Client Finality:** Pinned Helios 0.12.0 light-client integration tracking authenticated execution headers and checkpoint ancestry.
- **Trie Inclusion Proofs:** Strict Ethereum Keccak-256, RLP, and Modified Patricia Trie (MPT) inclusion verifier for transactions and receipts. Verified by 30 differential tests against independent implementations (`pycryptodome`, `rlp`, `HexaryTrie`).
- **Custody Reserve Solvency:** `src/adapters/evm_deposit_authorizer.py` enforces vault reserve solvency (`contract_balance >= total_minted + amount`) before authorizing mint issuance.

## Mathematical Reductions & Formal Security

The theory documents contain conditional reductions and security-game models for selected primitives. These do not establish that the current OpenVM candidate or whole deployed protocol satisfies the assumptions, soundness target, authorization policy, or end-to-end zero-knowledge property:

- **Commitment-binding theory model:** The cited reduction relates SHAKE256-384 binding to collision resistance under the document's quantum-adversary assumptions. It is a conditional primitive argument, not a proof that the current deployed protocol satisfies a composed post-quantum security target.
- **Statistical-hiding theory model:** The cited document states a bound under its formal assumptions and entropy model. That bound has not been established for the active OpenVM proof transcript, verifier, and production state/authorization composition.
- **Composed Security-Game Models:** Defined in [`docs/security/composed-security-games-and-reduction.md`](docs/security/composed-security-games-and-reduction.md). The model claims need to be matched to an accepted implementation and complete proof relation before being treated as production guarantees:
  - **Balance Conservation Game:** A conditional formal model; it is not evidence that deployed issuance, proof verification, and ledger composition satisfy its assumptions.
  - **Recipient Unlinkability Game:** A formal privacy model; the current candidate proof profile does not establish its witness-hiding guarantee.
  - **Double-Spend Replay Prevention Game:** A formal model supported by local SQLite uniqueness tests; this does not establish distributed consensus or cross-deployment replay protection.

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

- **Testnet:** **DEFERRED** · **Mainnet:** **REQUIRED BEFORE LAUNCH; NOT PERFORMED**
- **Evidence:** Not performed; required before any Mainnet real-value transfer
- **Mainnet obligation:** Third-party external audit completion

### 27. **Complete 0PSP Production Release**

- **Local synthetic test value:** **GO when `make production-check` passes** | **Public testnet value:** **NO-GO** | **Mainnet live value:** **NO-GO**
- **Evidence:** Production-1 E2E uses pinned OpenVM verification and local SQLite with synthetic note issuance; public contracts, issuance, and authenticated finality are absent
- **Mainnet obligation:** All mandatory external criteria evidenced closed

## Increment & Audit Registry

0PSP's development is tracked across foundational RFCs and chronological Checkpoint (CHp) audit increments:

- [RFC-01: user-committed issuance](docs/security/rfc-01-user-committed-issuance.md) — Hiding and binding formal proof in QROM, deposit evidence normalizer, and authorizer adapter.
- [RFC-02: V2-only spend relation](docs/theory/spend-relation-spec.md) — Frozen V2 equations and component specifications.
- [Accepted spend relation v3](docs/security/ACCEPTED_SPEND_RELATION_V3.md) — Production-1's frozen 1-in/1-out relation. The broader CHp4.7 research relation remains distinct.
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
