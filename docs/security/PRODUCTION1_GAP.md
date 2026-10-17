# Production-1 gap report

**Baseline:** current `main` worktree, Phase 0 inventory, 2026-10-17. This file and the Production-1 overlay in `production-gate-matrix.md` use the same gate names and statuses. The worktree contains uncommitted implementation and documentation changes; this is a code inventory, not release evidence for a SHA.

**Decision at baseline:** Production-1 testnet-value path is **NO-GO**. Mainnet live value is **NO-GO**. The only guest dispatched by `proof/openvm/v3-nullifier-spike/src/main.rs` is the 1-input/1-output `spend_v3::verify_v3_spend_witness` path. The separate depth-32 helper later in `spend_v3.rs` is not dispatched by that guest.

## Relation inventory

| Gate | Baseline status | Evidence and exact boundary |
|---|---|---|
| Canonical statement parser and frozen 1-in/1-out profile | IMPLEMENTED | `parse_tx` checks domain, version, canonical re-encoding, fixed NK-possession policy, exactly one output, and bounded lengths. The active guest returns one 64-byte digest of the full transaction statement. |
| Namespace-scoped Merkle membership, depth 63, u64 index | IMPLEMENTED | `verify_membership` bounds the u64 index to 63 bits, requires 63 siblings, hashes namespace/index into the leaf, and domain-separates each level. It checks against the root supplied in the statement; it does not authenticate that root. |
| CommitV3 opening for the input | IMPLEMENTED | Active guest recomputes the commitment from the same input bundle, value, namespace, coin ID, nullifier randomness, and commitment randomness before membership. |
| NullifierV3 HMAC-SHA3-384 same-witness binding | IMPLEMENTED | Active guest opens the input bundle's NK commitment, then uses that same `input_nk`, bundle, commitment, coin ID, and nullifier randomness to recompute the public nullifier. |
| Value conservation and range safety | IMPLEMENTED | Values and fee parse as u64; `input = output + fee` is computed in u128, rejecting overflow-equivalent mismatches. This is the active one-output relation only. |
| NK-possession authorization predicate | IMPLEMENTED | The witness proves knowledge of `nk` opening the key commitment in the input BundleV3. This does not implement threshold signing or an independent recipient-intent signature. |
| Public statement binding | IMPLEMENTED | The guest emits a 64-byte digest over canonical TxFieldsV3, which includes nullifier, namespace, root, state head/context digest, fee, entropy, and the single output commitment. These fields are digest-bound rather than individually exposed as OpenVM public values. |
| Anchor- and slot-bound output anti-reuse | PARTIAL | The active relation fixes the output slot to zero and derives output coin ID/randomness from the parent note, bundles, namespace, and transaction entropy. It does not include the statement root, state head, or state-context/finalized-anchor identifier in that derivation. |
| Host/reference relation parity with the active guest | PARTIAL | Python reference code supports 32- and 63-level paths and multi-output witnesses; the active guest is only the fixed one-output 63-level profile. Production-1 must select and test only the exact guest profile. |

## Production integration inventory

| Gate | Baseline status | Evidence and exact boundary |
|---|---|---|
| Pinned OpenVM artifact verifier exists | IMPLEMENTED | `OpenVMV3CandidateProofVerifier` pins checker/VK file hashes and app executable commitment, stages and rechecks exact bytes, invokes the Rust OpenVM checker, and checks the expected public digest. This is a real proof verifier. |
| Production envelope uses the pinned verifier without injected callbacks | MISSING | `verify_production_proof_envelope()` takes a caller-supplied `proof_verifier`; its module-level latch is `False`. The local worker CLI bypasses this envelope and injects the checker callback directly into `SQLiteV3CandidateLedger`. |
| Explicit `production1_testnet` and `mainnet_live` profiles | MISSING | One global boolean exists. There is no profile-bound enablement policy, and no fail-closed rule proving `mainnet_live` cannot be enabled by this milestone. |
| Ledger preflight, proof verification, and spend mutation are composed atomically | PARTIAL | SQLite candidate ledger provides unique nullifier/output constraints, anchor-ring validation, and transactional mutation. The verifier is an injected callback, and the current local CLI uses synthetic bootstrap evidence. |
| Duplicate spend and historical anchor behavior | IMPLEMENTED | SQLite unit/integration tests cover duplicate nullifiers, a 256-anchor ring, historical anchors, concurrent duplicate races, rollback/fault injection, and integrity rebuild. These tests do not turn the callback-based ledger into a production profile. |
| Authenticated finality/reorg recovery | MISSING | The active guest binds root/head/context fields but cannot authenticate consensus. The local test path bootstraps deterministic synthetic state; there is no Production-1 recovery/finality adapter. |
| Single-tenant worker transport and witness handling | PARTIAL | The existing worker has TLS, bearer auth, request size limits, one request at a time, timeout, no body logging, mutable-buffer wipe, and an stdin prover. Its request is raw witness bytes and response is a binary envelope; circuit ID, explicit public inputs, request ID, and prove time are not part of the API contract. Phase A operator plaintext access is intentional and must remain disclosed. |
| Client verifies locally before ledger submission | IMPLEMENTED | The local client validates the TLS certificate, binds the public digest to its statement, verifies the proof locally, wipes the mutable witness, then submits to the SQLite ledger library. |
| Clean-machine mint → spend → replay-reject using one production profile | PARTIAL | Local scripts construct a deterministic synthetic input note, prove and verify an OpenVM spend, then a separate integration script verifies once and rejects replay. They are not yet wired into `make production-check` as one profile-aware e2e path. |
| Fixed golden vectors under `tests/vectors/` | MISSING | Existing fixtures are generated by scripts under the spike directory; the requested versioned test-vector set is absent. |
| Named-machine proof measurements | IMPLEMENTED | `BENCH.md` records a 660,320-byte spend proof, 484.119 s proving, 2.852 s verifying, and 3,375,840 KiB combined runner peak RSS on a named WSL2/Ryzen 5 7530U machine. The local guest commitment differed from the pinned CI toolchain output; that caveat is recorded. |
| Testnet profile release decision | MISSING | README and gate matrix describe synthetic/local tests only; there is no testnet-value GO profile. |
| Mainnet live-value release decision | NO-GO | Mainnet remains disabled and out of scope. No soundness, privacy, finality, recovery, custody, or external-audit claim is inferred from Production-1 testnet work. |

## Production-1 target after Phase 0

The next phases must close the anchor-bound output identity, bind the exact pinned checker/VK/circuit configuration to an explicit `production1_testnet` profile, keep `mainnet_live` unconditionally disabled, and route both client and ledger verification through that same production verifier. The ledger must verify and mutate under its atomic transaction without production callback injection. The service contract and clean-machine e2e must then be frozen and covered by vectors and adversarial tests. Mainnet remains NO-GO independently of the testnet profile.

This baseline makes no claim of full witness zero knowledge, a composed 128-bit post-quantum bound, Monero ring signatures, threshold MPC, or mainnet live value.

## After Phase 0–5 implementation status

The table below mirrors the Production-1 overlay gate names and decision statuses in `production-gate-matrix.md`. The constraint-level inventory above uses `IMPLEMENTED | PARTIAL | MISSING`; an implemented gate maps to scoped `GO` only when its listed end-to-end evidence passes. `GO` is limited to the local synthetic test-value profile and is conditional on `make production-check` passing on this release SHA. It does not change any Mainnet gate.

| Gate | Current status | Evidence / boundary |
|---|---|---|
| Active spend_v3 relation and anchor-bound output identity | GO | Frozen 1-in/1-out guest + matching host relation, anchor-bound slot 0, fixed vectors, and actual proof. |
| Exact OpenVM verifier artifact pinning | GO | Source-controlled checker/VK/circuit pins verified by the actual client and ledger path. |
| `production1_testnet` enabled / `mainnet_live` disabled | GO | Testnet verification is enabled; Mainnet and legacy Mainnet latch remain false. |
| Atomic proof/anchor/nullifier/output transition | GO for local SQLite | Verification runs inside `BEGIN IMMEDIATE`; unique constraints, replay, concurrency and rollback tests pass. |
| Historical anchor and replay policy | GO for local 256-anchor ring | Retained non-tip anchor accepted; duplicate spend rejected. |
| Authenticated external finality and chain reorg recovery | MISSING | Synthetic local mint/bootstrap only; no external chain anchor or recovery adapter. |
| Single-tenant prove API and client verification | GO for Phase A | TLS, bearer auth, request limits, concurrency one, RAM-only mutable witness, client + ledger verification; operator may see plaintext. |
| Clean-machine mint-fixture → prove → verify → accept → replay reject | GO when `make production-check` passes | Actual OpenVM worker and pinned checker, no mock verifier. |
| Fixed vectors and named-machine cost evidence | GO | Three fixtures and current proof costs in `BENCH.md`. |
| Production-1 local test-value decision | GO | Conditional on `make production-check` on this exact release SHA. |
| Mainnet live-value decision | NO-GO | Security target, full witness hiding, external finality/recovery and external audit are not established. |

## Verification call-site inventory

`PRODUCTION_SPEND_VERIFICATION_ENABLED` is retained as a compatibility name for the Mainnet/live profile and remains `False`. Production-1 testnet enablement is controlled separately by `PRODUCTION1_TESTNET_SPEND_VERIFICATION_ENABLED=True`.

Repository-wide call-site inventory at implementation:

| Symbol | Definition / call site | Use |
|---|---|---|
| `PRODUCTION_SPEND_VERIFICATION_ENABLED` | `src/protocol/proof_backend_v3.py:54` | Alias of the Mainnet flag; false. Test assertions: `tests/unit/test_proof_backend_v3.py:179`; release assertion: `scripts/production_check.py:32`. |
| `verify_production_proof_envelope` | Definition `src/protocol/proof_backend_v3.py:264`; production call `src/protocol/production1_ledger.py:28` | Performs profile check, checks preflight bindings and invokes only the privately constructed pinned verifier. |
| `verify_production_proof_envelope` tests | `tests/unit/test_proof_backend_v3.py:184,191,206` | Exercise accepted testnet proof and rejection on mainnet/profile/verifier mismatch. |

| Call site | Role |
|---|---|
| `src/protocol/proof_backend_v3.py::verify_production_proof_envelope` | Profile gate and exact pinned verifier dispatch; fails closed for Mainnet or wrong verifier/profile. |
| `src/protocol/production1_ledger.py::SQLiteV3Production1TestnetLedger._verify_spend_proof` | Ledger re-verification with pinned profile and preflight fields while the atomic ledger transaction is held. |
| `scripts/production_check.py` | Asserts the profile/latch values and executes the no-mock end-to-end proof path. |
| `tests/unit/test_proof_backend_v3.py` | Tests enabled testnet, disabled Mainnet, and fail-closed mismatches. |

The active worker/client path is `scripts/production1_e2e.py` → `src/protocol/v3_proof_worker.py` → `src/protocol/v3_proof_client.py` → `SQLiteV3Production1TestnetLedger`. The `mainnet_live` profile is not enabled by any Production-1 configuration.
