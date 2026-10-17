# Accepted Spend Relation v3 Production-1

## Frozen profile

Production-1 freezes exactly one input and one output, a namespace-scoped depth-63 Merkle tree, a u64 leaf index, CommitV3, NullifierV3 with HMAC-SHA3-384, and NK-possession authorization. Threshold signatures, multi-output spends, mobile proving, full witness-zero-knowledge claims, and mainnet live value are outside this profile.

The active OpenVM entrypoint dispatches only `spend_v3::verify_v3_spend_witness`. The legacy depth-32 host helper in the Rust module is not part of this relation. Host acceptance must reject any transaction with an output count other than one or a path other than 63 siblings.

The verifier-selected relation identity is `openvm-spend-v3-p1-depth63-1in1out-v1` (`PRODUCTION1_CIRCUIT_ID`) and is pinned alongside the OpenVM app commitment, VK, and checker in `production1-pins.json`. `params_id` is serialized in TxFields and included in the public digest. The current TxFields schema does **not** serialize a separate `relation_id`; its identity is enforced by selecting the exact pinned VK/circuit. If the protocol requires the relation ID as an explicit public field, that requires a new TxFields/relation version, regenerated guest, VK and proofs. Do not infer that the human-readable circuit ID alone cryptographically selects a different relation.

## Public inputs

OpenVM receives the private witness and reveals exactly 64 public bytes: `public_digest = SHAKE256-512(PUBLIC_STATEMENT_DOMAIN || version || SHAKE256-512(TxFieldsV3))`. Canonical `TxFieldsV3` binds:

- parameter ID and namespace ID;
- commitment root, input nullifier, ledger state head, and 64-byte state-context digest;
- fixed NK-possession policy ID and u64 fee;
- 32-byte output entropy, output count fixed to 1, and output commitment in canonical slot 0.

The verifier recomputes the digest from the host-parsed statement and requires exact equality with the proof's 64 public bytes. The statement's `anchor_context` for output derivation is the exact fixed concatenation `commitment_root[48] || ledger_state_head[48] || state_context_digest[64]`.

The relation's pure verification API returns the selected relation ID, parameters, namespace, root/head/context, nullifier, output commitments, and fee after proof verification. It does not consult or mutate ledger state. A caller must apply its root-acceptance policy separately; the Production-1 SQLite ledger rechecks the anchor and nullifier/output uniqueness inside its write transaction.

The root in the statement is a claim proved against by the guest, not an authenticated-finality assertion. The API contract is `Verify(vk, public_including_root, proof) -> verified public fields | reject`; callers must provide the authenticated-root policy and then separately apply state. Production-1's local ring is a synthetic local state policy only. Wrong and expired roots are rejected by that composition, but no consensus or public-chain finality adapter is implemented.

Issuance is a separate composition predicate. For the local-only profile, `I_local(c)` is true exactly for a commitment present in the authorized synthetic bootstrap evidence used to initialize the tree. The spend guest enforces membership under the supplied root; therefore a leaf absent from the authorized tree cannot satisfy membership. This is not a public deposit/mint predicate, and the demo faucet creates no public-chain asset claim.

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

The active manifest pins the upstream `app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT)` profile, which declares 100-bit application RBR. Separate proposed-parameter calculations in `BENCH.md` are not active release parameters. The active composed bound is unknown; composed ≥128-bit post-quantum security is **NOT CLAIMED**. Security label: **proof of knowledge under the pinned OpenVM verifier assumptions; zero-knowledge / witness hiding NOT established**. No prover-trace masking or independent Fiat–Shamir/QROM composition bound is claimed. Phase A trusts one operator with plaintext witness. The proof checker and ledger establish relation satisfaction and local replay protection for the stated profile; they do not authenticate public issuance, recipient intent, external finality, or reorg recovery.

The Rust guest predicate has a fixed-vector test that flips a byte in every public and private field and each of the 63 Merkle siblings; all mutations reject. Python host-reference mutation tests cover every typed statement and witness field and enforce only the Production-1 1-in/1-out depth-63 profile. These tests are regression evidence for the implementation boundary and are not a proof of the cryptographic soundness of OpenVM or the protocol.
