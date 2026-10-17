# Accepted Spend Relation v3 Production-1

## Frozen profile

Production-1 freezes exactly one input and one output, a namespace-scoped depth-63 Merkle tree, a u64 leaf index, CommitV3, NullifierV3 with HMAC-SHA3-384, and NK-possession authorization. Threshold signatures, multi-output spends, mobile proving, full witness-zero-knowledge claims, and mainnet live value are outside this profile.

The active OpenVM entrypoint dispatches only `spend_v3::verify_v3_spend_witness`. The legacy depth-32 host helper in the Rust module is not part of this relation. Host acceptance must reject any transaction with an output count other than one or a path other than 63 siblings.

## Public inputs

OpenVM receives the private witness and reveals exactly 64 public bytes: `public_digest = SHAKE256-512(PUBLIC_STATEMENT_DOMAIN || version || SHAKE256-512(TxFieldsV3))`. Canonical `TxFieldsV3` binds:

- parameter ID and namespace ID;
- commitment root, input nullifier, ledger state head, and 64-byte state-context digest;
- fixed NK-possession policy ID and u64 fee;
- 32-byte output entropy, output count fixed to 1, and output commitment in canonical slot 0.

The verifier recomputes the digest from the host-parsed statement and requires exact equality with the proof's 64 public bytes. The statement's `anchor_context` for output derivation is the exact fixed concatenation `commitment_root[48] || ledger_state_head[48] || state_context_digest[64]`.

## Private inputs

The witness contains the exact canonical TxFieldsV3 bytes; input BundleV3; u64 input value; input coin ID, nullifier randomness, commitment randomness and nullifier key; u64 leaf index and 63 ordered 48-byte Merkle siblings; output BundleV3, u64 output value and output commitment randomness. The worker receives the serialized witness in RAM over TLS. In Phase A the operator and prover process can see plaintext.

## Constraints

1. Parse bounded, canonical witness and transaction encodings; require version 3, the fixed NK-possession policy, exactly one output, and no trailing bytes.
2. Recompute the input BundleV3 nullifier-key commitment and require the private NK to open it.
3. Recompute CommitV3 from the input bundle, value, namespace, coin ID, nullifier randomness, and commitment randomness.
4. Compute the namespace-scoped leaf hash from the u64 index and input commitment; fold exactly 63 ordered siblings with level-separated node hashes; require equality to the public statement root. The guest does not authenticate consensus finality.
5. Recompute the NullifierV3 message from the same input bundle, commitment, coin ID and nullifier randomness; compute HMAC-SHA3-384 with that same private NK; require equality to the statement nullifier.
6. Derive output coin ID and nullifier randomness with separate SHAKE domains over parameter ID, namespace, the 160-byte anchor context, parent nullifier/commitment/coin ID/nullifier randomness, parent and recipient bundles, public entropy, and canonical output slot 0.
7. Recompute output CommitV3 from the recipient bundle, output value, derived output identity, namespace and output randomness; require equality to the sole public output commitment.
8. Require `input_value = output_value + fee`; parse each as u64 and compute the sum in u128 before equality, so u64 wraparound cannot satisfy the relation.
9. Reveal only the 64-byte digest of canonical TxFieldsV3; the host compares it against its own statement and authenticated ledger preflight.

## Host acceptance predicates

The host accepts only the exact Production-1 profile ID, OpenVM circuit/app commitment, and pinned verifier artifacts. It checks that the statement namespace/parameters/policy match the ledger, the statement root/head/context identify an anchor in the retained ring, the nullifier is unused, and output commitments are unique. The fixed OpenVM verifier re-verifies the proof and public digest; the ledger repeats the anchor and uniqueness checks under its write transaction before appending the output and nullifier.

This host composition is local SQLite state for test value. It is not a consensus light client and does not establish a public-chain finalized anchor. Mainnet live value remains disabled.

## Security scope

OpenVM's current measured profile does not establish a composed 128-bit post-quantum bound. This document makes no full witness-ZK or prover-trace-masking claim. Phase A trusts one operator with plaintext witness. The proof checker and ledger establish relation satisfaction and local replay protection for the stated profile; they do not authenticate issuance, recipient intent, external finality, or reorg recovery.
