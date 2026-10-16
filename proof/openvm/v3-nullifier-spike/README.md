# OpenVM V3 nullifier and spend feasibility spikes

**Status: experimental, non-production.** The guest has two explicit witness formats.

- `V3 nullifier slice`: proves a canonical BundleV3 key-commitment opening, the CommitV3 opening, and the candidate HMAC-SHA3-384 NullifierV3 equation.
- `one-input/one-output V3 spend candidate`: additionally enforces canonical TxFieldsV3Candidate bytes, the exact `0PSP-V3-NK-POSSESSION-CANDIDATE-v1` policy identifier, a depth-63 namespace-bound membership path against the transaction's root, an output identity derived from the consumed input's nullifier/commitment/witness plus the ordered output slot and entropy, the output's CommitV3 opening, and `input_value = output_value + fee` without u64 overflow.

The spend profile is deliberately limited to one input and exactly one output. Candidate encoding revision v2 includes a 64-byte state-context digest derived from the authenticated adapter's source ID, exact finalized-anchor bytes, and finality-policy ID. Its public result is the full 64-byte SHAKE256-512 digest of the canonical V3 candidate statement. OpenVM 2.0.2 defaults its public-value memory region to 32 bytes; the stock CLI keygen path rejects a custom value count, so this spike uses a pinned OpenVM SDK runner that calls `SystemConfig::with_public_values(64)` to update both public-value count and memory region. The fixture generator pins both the narrow nullifier and full-spend public statement digest to fixed 64-byte known-answer tests (KATs), so the reference code cannot silently redefine expected output. The guest calls the high-level `openvm::io::reveal_u32` with word indexes `0..15`; that API multiplies each index by four, yielding contiguous little-endian words at byte offsets `0, 4, ..., 60`. The runner supplies raw witness bytes via `StdIn::from_bytes` because `read_vec()` consumes a length-prefixed raw-byte hint stream, not a serde-encoded `Vec<u8>`. The runner independently checks the result is exactly 64 bytes and byte-for-byte equal to the expected digest. Passing a word index instead of a byte offset causes overlapping writes and is explicitly avoided. Two calls to `reveal_bytes32` would overwrite the same first 32 output bytes. The input commitment and nullifier key remain witness data; they are not emitted as public output. The application proof is checked against the pinned executable commitment and exact expected 64-byte public digest.

## Real-proof integration test

CI sends an application proof produced by the pinned OpenVM SDK through the Python verifier adapter and the transaction-to-state preflight. It requires the exact typed statement and fixture state binding to pass, then checks that the same proof is rejected after (1) changing the public transaction fee, (2) corrupting serialized proof bytes, and (3) substituting the pinned application executable commitment. Each negative case must fail closed through the actual Rust proof checker, not a mock verifier.

The state-evidence verifier in this integration test is deliberately synthetic fixture code. The test proves cross-language wiring and statement/proof binding for this candidate; it does **not** authenticate an external chain, test a production finality source, execute the durable SQLite transition, prove end-to-end zero knowledge, or establish the required composed soundness bound. The per-run artifact hashes are also not a substitute for published deployment release pins.

## Security-parameter reality check

The pinned runner uses upstream `app_params_with_100_bits_security`. The backend's own `SystemParams::new` documentation warns that a requested security target does not guarantee the overall protocol's security. This candidate therefore emits `security-profile.json` with the upstream 100-bit RBR target, required 128-bit composite PQ target, explicit `NO-GO`, and false values for end-to-end witness hiding and production acceptance. The manifest is reproducibility/claim-control metadata, not a proof.

The former `scripts/verify_composite_soundness.py` invented a degree-5 field model and unsupported per-query error terms that were not derived from the pinned backend. It has been replaced with a fail-closed evidence report: composed PQ security is recorded as **UNKNOWN**, not an estimated bit count, and the command exits nonzero. See [the security-claim correction record](../../../docs/audit/chp4.23-openvm-security-claim-correction.md) for upstream source references and the release gate.

## What this establishes

CI runs valid and adversarial fixtures through the OpenVM guest, generates and verifies real application-level proofs, and checks the Python-to-Rust verifier/preflight integration against the exact spend statement. This is evidence for the checked-in one-input/one-output predicate slice, not a complete 0PSP release. The dependency graph and cargo-openvm v2.0.2 binary are pinned/locked for this experiment.

## Real proof through the SQLite candidate ledger

A second CI integration path now constructs the initial SQLite commitment tree, reads its exact retained root/head anchor, builds the transaction state-context digest for that local anchor, and generates a **new OpenVM application proof for that exact statement**. The same serialized proof is then submitted through `OpenVMV3CandidateProofVerifier` to `SQLiteV3CandidateLedger.accept_spend`.

The check requires all of the following on the actual ledger path:

- A mutated serialized proof is rejected, with no nullifier or output commitment written.
- The valid SDK-generated proof is accepted and the output commitment plus consumed nullifier are committed in one SQLite state transition.
- Replaying the same proof/nullifier is rejected as a duplicate and leaves the state unchanged.
- Restarting the ledger reconstructs and audits the persisted tree/event history after acceptance.

The runner's `prove-one` command creates a new proof for the dynamically derived ledger statement and verifies it against the exact pinned application executable commitment and expected public digest. The CI evidence reports the checker/VK hashes and the real proof result. The synthetic bootstrap evidence is deliberately test-only. The ledger's own state policy remains **local and non-final**, so this is real proof-to-ledger integration evidence for the candidate state machine, not production finality or Mainnet authorization.

## Still not established

- The transaction root/state head is not made trusted by the guest. An independently reviewed state-evidence adapter must authenticate a finalized root/head and return its explicit finality-policy ID. Host acceptance recomputes the 64-byte state-context digest from the source ID, exact finalized-anchor bytes, and policy ID, then compares that digest along with namespace, params ID, root and state head before invoking the candidate proof verifier. The current local SQLite policy is explicitly nonfinal and cannot stand in for an external consensus trust source.
- The guest has no production durable atomic transition. The local candidate ledger has atomic SQLite semantics, but acceptance does not yet couple the exact deployed proof backend to authenticated external finality and crash/reorg recovery as one reviewed release path.
- Only one output is supported by this proved profile. Issuance, multiple outputs, globally anchored identity uniqueness, and all asset/custody/deposit paths are outside it.
- The NK-possession equation is the candidate core-spend authorization. It authenticates control of the bundled nullifier key, not that the bundle belongs to an intended payee. Any required payee/address authenticity needs an independent authenticated anchor.
- Witness-hiding/zero-knowledge for this exact guest/proof configuration has not been independently established. The project's 128-bit post-quantum composite soundness target is not satisfied by the current OpenVM v2.0.2 profile alone.
- This is not an external cryptographic audit. No production scheme or V3 byte contract is frozen by this spike.

A passing guest build or application proof cannot promote V3 to production on its own. Keep the release gate **NO-GO** until trusted state, durable atomic state transition, full relation scope, witness-hiding evidence, a composed >=128-bit PQ bound, performance limits, and independent review all pass on one exact release SHA.
