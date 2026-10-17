# Production-1 gap report

**Baseline:** current rebased worktree, descended from remote `origin/main` `d9e1cf2` plus the local Production-1 implementation. **Release SHA:** this report and implementation are committed atomically; see the release commit in Git. **Decision:** local synthetic test-value demonstration only; public testnet value and Mainnet live value remain **NO-GO**.

The remote internal review at [`docs/audit/secure-blocker-analysis-2026-10-17.md`](../audit/secure-blocker-analysis-2026-10-17.md) remains authoritative for the inherited protocol blockers. Production-1 adds a pinned OpenVM proof/checker path and local SQLite spend transition; it does not close finality, issuance/custody, payee authenticity, reorg/recovery, witness hiding, composed security, or audit requirements.

## Primitive inventory

| Spend-relation gate | Status | Evidence and exact boundary |
|---|---|---|
| Fixed 1-input/1-output and canonical V3 statement | IMPLEMENTED | The active OpenVM entrypoint dispatches `spend_v3::verify_v3_spend_witness`; it requires one output, canonical encoding and the NK-possession policy. The legacy host reference is broader, so the explicit Production-1 host predicate now rejects non-1-output and non-depth-63 inputs. |
| Namespace-scoped Merkle membership, depth 63, u64 index | IMPLEMENTED | Guest hashes namespace and u64 index into the leaf and folds 63 ordered, level-separated siblings against the statement root. It proves membership under the supplied root; it does not authenticate that root. Guest mutation tests flip each sibling and reject. |
| CommitV3 opening and same-witness NullifierV3 | IMPLEMENTED | One parsed witness supplies the bundle, value, coin ID, `r_nf`, `rho`, and `nk`; guest recomputes the commitment, opens the bundle's NK commitment, and derives HMAC-SHA3-384 NullifierV3 from those same fields. Host and guest mutation tests reject changes to each corresponding field. |
| Authorization predicate | IMPLEMENTED (NK possession only) | The exact policy is fixed to knowledge of `nk` opening the key commitment in the spent note bundle. It does not authenticate a third-party intended recipient, and threshold/MPC is absent. |
| Value conservation and integer range | IMPLEMENTED (u64 1-out profile) | Input/output/fee are decoded from fixed-width u64 encodings; guest computes output plus fee in u128 and requires equality. Broader multi-output range semantics are outside the accepted profile. Python boundary tests cover 0, max-u64, and overflow; per-boundary OpenVM proof vectors remain to add. |
| Output identity and anti-reuse | IMPLEMENTED (slot 0, local state) | The guest derives output coin ID and `r_nf` from parent-note identity, bundles, entropy, namespace and the root/head/context anchor, then checks the output CommitV3. SQLite enforces output commitment uniqueness. It does not establish intended payee authenticity or global uniqueness across deployments. |
| Public statement binding | IMPLEMENTED (digest-bound) | Canonical TxFields bind params ID, namespace, root, nullifier, state head/context, policy, fee, entropy, one output and its commitment into the public digest. These are digest-bound, not individually revealed. `params_id` is in the statement. |
| `relation_id` binding | PARTIAL | The verifier selects the exact `PRODUCTION1_CIRCUIT_ID` with a source-controlled pin manifest and matching VK/app commitment. The relation ID is not separately serialized into TxFields; changing that would require a new relation/version and regenerated OpenVM artifacts. |
| Host/guest mutation parity | IMPLEMENTED for field mutation rejection; broader semantics PARTIAL | Rust guest tests execute the active guest predicate against the fixed valid vector and reject a one-bit mutation of every public/private field and each Merkle sibling. Python Production-1 host-reference tests reject each field mutation and enforce the profile arity/depth. This is predicate-level evidence, not a proof for every invalid mutation or a full cross-language differential corpus. |
| Domain separation and versioning | PARTIAL | V3 byte layouts have explicit domains, version bytes and fixed vectors. The active domain strings retain `CANDIDATE` naming and mixed-profile legacy APIs remain in the repository; a clean normative V3 codec/domain migration is not complete. |
| Soundness profile | NOT DONE for >=128-bit composed PQ | The pinned active profile declares 100-bit app RBR; the release calculator reproduces 100.089831 app-RBR bits under the upstream trace/AIR ceilings. This is not a Fiat–Shamir/QROM composition bound. No composed post-quantum bound of at least 128 bits is established. Exact resolved app/aggregation FRI/STARK parameters and transcript are in `production1-pins.json` and checked by the Rust release test. |
| Witness hiding / prover trace | CRYPTOGRAPHIC FIX NOT DONE; accidental-use guard IMPLEMENTED | Pinned OpenVM/STARK prover commits generated traces directly and exposes trace-derived openings; no supported trace-masking/zero-knowledge mode is exposed by the active API. The client now refuses non-ZK proofs by default, permits explicit opt-in only for `production1_testnet`, and requires the worker's `witness_hiding_not_established` status. This guard is not a ZK fix. Phase A operator can see plaintext witness. |
| Secret lifecycle / side channels | PARTIAL | Worker wipes the mutable request buffer on success and failure; OpenVM and Python/runtime copies, swap, crash dumps, and all secret paths are not proven wiped. Constant-time behavior is not certified. |
| Pure verifier vs state application | IMPLEMENTED (API boundary) | `verify_production1_spend` is a pure verifier returning relation ID, params, anchor, nullifier, outputs and fee; SQLite performs the separate atomic Apply transition and rechecks state/uniqueness. Root acceptance remains caller/state policy, not proof semantics. |
| Issuance binding | NOT DONE | Current mint is deterministic local synthetic bootstrap data. No verified public-chain deposit or one-time issuance authorization is composed with the spend primitive. |
| Intended recipient / recovery | NOT DONE | NK possession authorizes spending the input note only. Recipient address binding, encrypted note delivery, key backup/recovery and substitution/replay policy are not specified as an accepted primitive. |
| Multi-output spends | NOT IMPLEMENTED in accepted profile | The accepted guest and Production-1 pure verifier accept exactly 1-in/1-out. Historical reference APIs may represent multi-output candidates; those are not accepted by the pinned profile. |
| Pure verifier artifact / release identity | IMPLEMENTED for local pin integrity; independent release attestation NOT DONE | Source-controlled manifest pins circuit ID, app VK, checker and executable commitment; adapter stages and rechecks files. This is not a signed, independently reviewed release manifest or reproducible build attestation. |

## Composition and deployment gaps

| Gate | Status | Evidence / remaining work |
|---|---|---|
| Exact OpenVM proof verification | IMPLEMENTED for local Production-1 profile | The pinned checker verifies the OpenVM proof against the pinned VK, executable commitment and expected public digest. No mock verifier is used in the Production-1 CLI/ledger path. |
| Local atomic nullifier/output transition | IMPLEMENTED for single SQLite database | The proof is checked in the write transaction; unique constraints, concurrent double-spend rejection, historical anchors and rollback tests cover local state. This is not distributed consensus or crash/reorg reconciliation to an external chain. |
| Authenticated finalized state | NOT DONE | Production-1 bootstrap root/head is synthetic. There is no authenticated public testnet state adapter, checkpoint pin, or reorg/finality policy in the active path. |
| Public testnet issuance/contracts | NOT DONE (`CONTRACTS_MISSING`) | No pool contract or shielded faucet is in the release path. Current E2E uses synthetic local note issuance only. |
| Worker and client | IMPLEMENTED for Phase A local deployment | TLS, bearer auth, concurrency one, request limits, timeout, no witness-body logs, buffer wipe, client verification and ledger re-verification. The worker/operator can observe plaintext; no TEE attestation exists. |
| Clean-machine E2E | IMPLEMENTED for local synthetic value, conditional on `make production-check` | The script proves, locally verifies, applies one spend, then rejects replay with the pinned backend. It does not establish public-chain deposit, finality, payee delivery or real public testnet value. |
| Measured cost | IMPLEMENTED as single-host observation | [`BENCH.md`](../../BENCH.md) records 660,320-byte proof, ~676 s end-to-end proving, ~337 ms client verify and ~3.0 GiB peak RSS on the named host. These are not capacity guarantees. |
| External audit | DEFERRED / NOT PERFORMED | Audit is not a substitute for the remaining internal proof, state, issuance, privacy and recovery requirements. |
| Public testnet value | NO-GO | Contracts, issuance, authenticated finality and recovery are missing. |
| Mainnet live value | NO-GO | Mainnet verification remains hard-disabled. No mainnet value, audit, composed >=128-bit PQ, or witness-hiding claim is made. |

## Verification call sites

| Symbol | Definition/call site | Behavior |
|---|---|---|
| `PRODUCTION_SPEND_VERIFICATION_ENABLED` | `src/protocol/proof_backend_v3.py`; asserted in `tests/unit/test_proof_backend_v3.py` and `scripts/production_check.py` | Compatibility name for Mainnet/live verification; remains `False`. |
| `PRODUCTION1_TESTNET_SPEND_VERIFICATION_ENABLED` | `src/protocol/proof_backend_v3.py`; consumed by `verify_production_proof_envelope()` | Enables only the local synthetic Production-1 test-value profile. It is not an authorization to handle public testnet deposits. |
| `verify_production_proof_envelope()` | `src/protocol/proof_backend_v3.py`; called by `src/protocol/production1_ledger.py::verify_production1_spend` | Fails closed on wrong profile or non-pinned verifier, and verifies the exact statement digest through the OpenVM adapter. |
| `verify_production1_spend()` | `src/protocol/production1_ledger.py`; called from the ledger proof callback | Pure verification result. State transition is a separate SQLite operation with anchor and uniqueness rechecks. |

## Current decision

README, this report and the gate matrix must describe the same scope: **local synthetic Production-1 test-value path only; public testnet value NO-GO; Mainnet live value NO-GO**. The candidate proof-to-SQLite result is real local integration evidence, not a complete public-value protocol. Do not promote the public testnet or Mainnet release gates until their missing items have exact-SHA evidence.
