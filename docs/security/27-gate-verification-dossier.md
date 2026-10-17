# 0PSP 27-Gate Production Verification Dossier

> **Historical snapshot:** This dossier describes an earlier review baseline (`43e2751`, dated 2026-10-14) and is not the current release decision or evidence for current cryptographic claims. Current status: local synthetic Production-1 test-value path only; public testnet and Mainnet live value are **NO-GO**. The active OpenVM proof label is “proof of knowledge under pinned verifier assumptions; zero-knowledge NOT established.” See the current README, SPEC, LIMITATIONS, and gate matrix.

**Status Date:** 2026-10-14  
**Historical Baseline Git Commit:** `43e2751`

This dossier records the historical audit notes for 27 gates defined in the [Production Gate Matrix](production-gate-matrix.md). Its claims must be read under the historical-snapshot limitation above; it does not establish current implementation soundness or witness hiding.

---

## Exhaustive Gate Audit

### 1. Namespace V2 Frozen Core
- **Status:** **GO**
- **Specification:** Domain-separated 48-byte SHAKE256 digest over frozen 32-byte component descriptors.
- **Code Reference:** [`src/primitives/namespace.py`](../../src/primitives/namespace.py), [`native/nullifier_v2.c`](../../native/nullifier_v2.c).
- **Test Evidence:** [`tests/unit/test_namespace.py`](../../tests/unit/test_namespace.py) passing Known Answer Tests.
- **Residual Mainnet Obligation:** None for V2; frozen legacy target preserved for historical compatibility.

### 2. Namespace V3 Direct-Hash EVM Codec
- **Status:** **GO (Codec & Native Parity)**
- **Specification:** Directly hashes canonical EVM chain descriptors (`uint64_le(chain_id) || address[20] || address[20]`) into a 48-byte SHAKE256-384 digest without 256-bit intermediate identity hashes.
- **Code Reference:** [`native/namespace_v3.c`](../../native/namespace_v3.c), [`src/primitives/namespace_v3.py`](../../src/primitives/namespace_v3.py).
- **Test Evidence:** [`tests/unit/test_namespace_v3.py`](../../tests/unit/test_namespace_v3.py) (16 passed), [`tests/unit/test_namespace_mainnet_smoke.py`](../../tests/unit/test_namespace_mainnet_smoke.py) (24 passed).
- **Residual Mainnet Obligation:** Live mainnet contract deployment manifest pinning.

### 3. CommitV2 / NullifierV2 Host & Native APIs
- **Status:** **GO (Primitives)**
- **Specification:** V2 commitment binding opening fields; Nullifier V2 over namespace, coin ID, and secret.
- **Code Reference:** [`native/coin_commitment_v2.c`](../../native/coin_commitment_v2.c), [`native/nullifier_v2.c`](../../native/nullifier_v2.c), [`native/keccak_f1600.c`](../../native/keccak_f1600.c).
- **Test Evidence:** [`tests/unit/test_coin_commitment_v2.py`](../../tests/unit/test_coin_commitment_v2.py) (6 passed), [`tests/unit/test_nullifier_v2.py`](../../tests/unit/test_nullifier_v2.py) (7 passed).
- **Residual Mainnet Obligation:** Full in-circuit spend relation proof binding.

### 4. Ethereum Keccak/RLP/MPT Reference Implementation
- **Status:** **GO (Conformance-Tested)**
- **Specification:** Strict Ethereum Yellow Paper RLP serialization, Keccak-256 state hashing, and Modified Patricia Trie (MPT) inclusion proofs.
- **Code Reference:** [`src/adapters/evm_trie.py`](../../src/adapters/evm_trie.py), [`src/adapters/evm_deposit_proof.py`](../../src/adapters/evm_deposit_proof.py).
- **Test Evidence:** [`tests/unit/test_evm_proof_differential.py`](../../tests/unit/test_evm_proof_differential.py) (30 differential tests passed against `pycryptodome`, `rlp`, and `HexaryTrie`).
- **Residual Mainnet Obligation:** Live RPC node proof acquisition.

### 5. EIP-1186 Account & Storage Proof Verifier
- **Status:** **GO (Tested Verifier)**
- **Specification:** Verification of raw EIP-1186 account state and storage trie proofs against authenticated block header state roots.
- **Code Reference:** [`src/adapters/evm_state_proof.py`](../../src/adapters/evm_state_proof.py).
- **Test Evidence:** [`tests/unit/test_evm_state_proof.py`](../../tests/unit/test_evm_state_proof.py) (14 passed).
- **Residual Mainnet Obligation:** Authenticated light-client consensus integration.

### 6. Durable SQLite Issue & Spend Transitions
- **Status:** **GO (Single-Node Engine)**
- **Specification:** Atomic WAL-mode transitions enforcing unique deposit anchors, unique commitment registrations, and unique nullifiers.
- **Code Reference:** [`src/protocol/sqlite_v3_candidate_ledger.py`](../../src/protocol/sqlite_v3_candidate_ledger.py), [`src/protocol/sqlite_ledger.py`](../../src/protocol/sqlite_ledger.py).
- **Test Evidence:** [`tests/adversarial/test_sqlite_fault_injection.py`](../../tests/adversarial/test_sqlite_fault_injection.py) (crash abort, power-loss simulation, uncommitted rollback recovery).
- **Residual Mainnet Obligation:** Multi-node distributed consensus / L1 sequencing.

### 7. Canonical TxFieldsV2 / TxDigestV2 Codec
- **Status:** **GO (Host API)**
- **Specification:** Canonical length-prefixed serialization and 48-byte SHAKE256-384 digest computation.
- **Code Reference:** [`src/protocol/transaction_v2.py`](../../src/protocol/transaction_v2.py).
- **Test Evidence:** [`tests/unit/test_transaction_v2.py`](../../tests/unit/test_transaction_v2.py) (15 passed).
- **Residual Mainnet Obligation:** Proof circuit binding of decoded fields to witness values.

### 8. Static SHAKE Arithmetization Estimator
- **Status:** **GO (Model Logic)**
- **Specification:** Parameterized model estimating 153,600 bit-sliced arithmetic equivalents per Keccak-f[1600] permutation.
- **Code Reference:** [`scripts/estimate_keccak_zk_cost.py`](../../scripts/estimate_keccak_zk_cost.py).
- **Test Evidence:** [`tests/unit/test_keccak_zk_cost_model.py`](../../tests/unit/test_keccak_zk_cost_model.py) (15 passed).
- **Residual Mainnet Obligation:** Replaced by empirical zkVM cycle benchmarks.

### 9. Binary-Field Keccak Circuit Model
- **Status:** **GO (Model Logic)**
- **Specification:** Characteristic-two GF(2) chi-relation constraint model (38,400 rows per permutation).
- **Code Reference:** [`scripts/estimate_binary_field_keccak.py`](../../scripts/estimate_binary_field_keccak.py).
- **Test Evidence:** [`tests/unit/test_binary_field_keccak_model.py`](../../tests/unit/test_binary_field_keccak_model.py) (13 passed).
- **Residual Mainnet Obligation:** Superseded by OpenVM STARK backend.

### 10. Durable Replay Protection (Single Node)
- **Status:** **GO (Local State Machine)**
- **Specification:** Primary key constraints and historical anchor ring (256 states) preventing duplicate nullifier or commitment submission.
- **Code Reference:** [`src/protocol/sqlite_v3_candidate_ledger.py`](../../src/protocol/sqlite_v3_candidate_ledger.py).
- **Test Evidence:** [`tests/unit/test_sqlite_v3_candidate_ledger.py`](../../tests/unit/test_sqlite_v3_candidate_ledger.py) (13 passed).
- **Residual Mainnet Obligation:** Distributed reorg recovery.

---

### 11–13. Screened-Out Proof Backends (Audited & Rejected)
- **11. SmallWood Python R1CS Dense Adapter:** **⛔ NO-GO**. Audited in [`docs/audit/chp4.22-smallwood-r1cs-adapter-scaling.md`](../audit/chp4.22-smallwood-r1cs-adapter-scaling.md); materializes $\ge 2.082\text{ TiB}$ RAM. Rejected.
- **12. Aurora/libiop Backend:** **⛔ NO-GO**. Audited in [`docs/audit/chp4.20-zk-backend-feasibility.md`](../audit/chp4.20-zk-backend-feasibility.md); pristine build failure and missing proof-of-work transcript field. Rejected.
- **13. RISC Zero zkVM:** **⛔ NO-GO**. Screened out due to maintainer advisory GHSA-5xgj-pmjj-gw49 regarding provable zero-knowledge properties. Rejected.

---

### 14–19. OpenVM Spend-Relation Gates (candidate; composed PQ bound and transcript zero-knowledge not established)
- **14. Proof-Backend Selection:** **GO for OpenVM v2.0.2 Candidate / NO-GO for Mainnet Live Value**. Rust guest circuit [`proof/openvm/v3-nullifier-spike/src/spend_v3.rs`](../../proof/openvm/v3-nullifier-spike/src/spend_v3.rs) compiles and executes; 5 adversarial tests pass.
- **15. ZK Transaction-Digest Binding:** **GO for Candidate / NO-GO for Mainnet**. Host encoding bound inside `spend_v3.rs` to public statement digest.
- **16. Commit Opening Inside Proof:** **GO for Candidate / NO-GO for Mainnet**. SHAKE256-384 commitment opening verified over witness values.
- **17. Same-Witness Nullifier Binding:** **GO for Candidate / NO-GO for Mainnet**. HMAC-SHA3-384 nullifier proven with same private key $nk$, coin ID, and commitment.
- **18. Value Conservation & Output Opening:** **GO for Candidate / NO-GO for Mainnet**. $v_{in} = v_{out} + fee$ strictly checked with range safety in `spend_v3.rs`.
- **19. Authorization Predicate in Spend Relation:** **GO for Candidate / NO-GO for Mainnet**. Spend authorized via knowledge of note nullifier key $nk$ bound to recipient bundle.
- **Residual Mainnet Obligation for Gates 14–19:** Generating full STARK proofs with prover-trace ZK row masking enabled, benchmarking proving time/RSS, and formalizing the composed post-quantum soundness bound.

---

### 20–22. Deposit Authorization & Spend Identity
- **20. Trusted EVM DepositAuthorization:** **GO for Local Adapter / NO-GO for Mainnet**. [`src/adapters/evm_deposit_authorizer.py`](../../src/adapters/evm_deposit_authorizer.py) composes Helios light-client header, receipt MPT proof, and vault solvency check.
- **21. Contract/Token Custody Semantics:** **GO for Observation / NO-GO for Mainnet**. Pinned bytecode fingerprint and ERC-20 transfer matching verified in [`tests/unit/test_evm_deposit_authorizer.py`](../../tests/unit/test_evm_deposit_authorizer.py).
- **22. Coin-ID Reuse & Output Collision Prevention:** **GO for Candidate / NO-GO for Mainnet**. Deterministic output identity derivation from creation anchor and slot index verified in [`tests/adversarial/test_output_identity_collision_prevention.py`](../../tests/adversarial/test_output_identity_collision_prevention.py).
- **Residual Mainnet Obligation:** Live Ethereum smart contract audit and deployment.

---

### 23–25. Cryptographic Security, Composition & Smoke Verification
- **23. Issuer Privacy & Commitment Hiding:** **GO for Formal Model / NO-GO for Mainnet**. Formally proven in [`docs/theory/commitment-hiding-and-binding-proof.md`](../theory/commitment-hiding-and-binding-proof.md) and [`docs/security/composed-security-games-and-reduction.md`](composed-security-games-and-reduction.md).
- **24. Real Ethereum Mainnet Smoke Test:** **GO for Synthetic / NO-GO for Mainnet**. 24 tests in [`tests/unit/test_namespace_mainnet_smoke.py`](../../tests/unit/test_namespace_mainnet_smoke.py) exercise full light-client pipeline against synthetic Ethereum headers.
- **25. Whole-Protocol Internally Audited Composition:** **GO for Testnet / NO-GO for Mainnet**. 650 automated tests passing with zero failures across Linux and Windows.
- **Residual Mainnet Obligation:** Live-network proof acquisition and third-party penetration testing.

---

### 26–27. External Audit & Release Decision
- **26. External Audit:** **REQUIRED BEFORE MAINNET; NOT STARTED / NOT PERFORMED**. Commission an independent third-party review after the complete relation, verifier, security parameters, and release composition are frozen; close findings and rerun evidence on the audited release commit. No audit or certification is claimed.
- **27. Complete 0PSP Production Release:**
  - **Testnet Release (`v0.1.0-alpha`):** **GO**. Full protocol operational for testnet token issuance, transfer, nullifier consumption, and verifiable state transitions.
  - **Mainnet Real-Value Transfer:** **Strictly Gated (NO-GO)** until external third-party cryptographic audits and prover-trace zero-knowledge masking are completed.
