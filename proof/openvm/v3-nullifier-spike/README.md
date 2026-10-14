# OpenVM V3 nullifier and spend feasibility spikes

**Status: experimental, non-production.** The guest has two explicit witness formats.

- `V3 nullifier slice`: proves a canonical BundleV3 key-commitment opening, the CommitV3 opening, and the candidate HMAC-SHA3-384 NullifierV3 equation.
- `one-input/one-output V3 spend candidate`: additionally enforces canonical TxFieldsV3Candidate bytes, the exact `0PSP-V3-NK-POSSESSION-CANDIDATE-v1` policy identifier, a depth-63 namespace-bound membership path against the transaction's root, an output identity derived from the consumed input's nullifier/commitment/witness plus the ordered output slot and entropy, the output's CommitV3 opening, and `input_value = output_value + fee` without u64 overflow.

The spend profile is deliberately limited to one input and exactly one output. Candidate encoding revision v2 includes a 64-byte state-context digest derived from the authenticated adapter's source ID, exact finalized-anchor bytes, and finality-policy ID. Its public result is the full 64-byte SHAKE256-512 digest of the canonical V3 candidate statement. OpenVM 2.0.2 defaults its public-value memory region to 32 bytes; the stock CLI keygen path rejects a custom value count, so this spike uses a pinned OpenVM SDK runner that calls `SystemConfig::with_public_values(64)` to update both public-value count and memory region. The guest reveals 16 indexed little-endian words; two calls to `reveal_bytes32` would overwrite the same first 32 output bytes. The input commitment and nullifier key remain witness data; they are not emitted as public output. The application proof is checked against the pinned executable commitment and exact expected 64-byte public digest.

## What this establishes

CI now runs a valid fixture and adversarial mutations through the OpenVM guest, then generates and verifies an application-level proof. This is evidence for the exact checked-in one-input/one-output predicate slice, not a complete 0PSP release. The dependency graph and cargo-openvm v2.0.2 binary are pinned/locked for this experiment.

## Still not established

- The transaction root/state head is not made trusted by the guest. An independently reviewed state-evidence adapter must authenticate a finalized root/head and return its explicit finality-policy ID. Host acceptance recomputes the 64-byte state-context digest from the source ID, exact finalized-anchor bytes, and policy ID, then compares that digest along with namespace, params ID, root and state head before invoking the candidate proof verifier. The current local SQLite policy is explicitly nonfinal and cannot stand in for an external consensus trust source.
- The guest has no durable atomic transition. Ledger acceptance must atomically consume the input nullifier and append the output commitment, reject duplicate commitments/nullifiers, and recover correctly across crash/reorg.
- Only one output is supported by this proved profile. Issuance, multiple outputs, globally anchored identity uniqueness, and all asset/custody/deposit paths are outside it.
- The NK-possession equation is the candidate core-spend authorization. It authenticates control of the bundled nullifier key, not that the bundle belongs to an intended payee. Any required payee/address authenticity needs an independent authenticated anchor.
- Witness-hiding/zero-knowledge for this exact guest/proof configuration has not been independently established. The project's 128-bit post-quantum composite soundness target is not satisfied by the current OpenVM v2.0.2 profile alone.
- This is not an external cryptographic audit. No production scheme or V3 byte contract is frozen by this spike.

A passing guest build or application proof cannot promote V3 to production on its own. Keep the release gate **NO-GO** until trusted state, durable atomic state transition, full relation scope, witness-hiding evidence, a composed >=128-bit PQ bound, performance limits, and independent review all pass on one exact release SHA.
