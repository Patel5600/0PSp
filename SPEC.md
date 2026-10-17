# spend_v3 relation and single-tenant proving

## Accepted Spend Relation v3 Production-1

The normative Production-1 testnet relation, exact public/private inputs, anchor-bound output-identity encoding, and constraints are specified in [`docs/security/ACCEPTED_SPEND_RELATION_V3.md`](docs/security/ACCEPTED_SPEND_RELATION_V3.md). Production-1 freezes 1-in/1-out and depth-63 membership. The earlier depth-32 and multi-output host-only helpers are excluded from accepted verification.

## Relation boundary

The active experimental backend is the OpenVM guest at `proof/openvm/v3-nullifier-spike/src/main.rs`, which dispatches spend witnesses to `spend_v3::verify_v3_spend_witness` in `src/spend_v3.rs`. Its exact current profile is one input, one output, 63 Merkle levels, and the NK-possession policy. It is an executable candidate relation; the OpenVM proof security profile is not production-approved.

### Public inputs

The guest reveals one 64-byte digest of canonical `TxFieldsV3Candidate` bytes. Those fields bind the parameter ID, namespace, commitment root, input nullifier, ledger state head, state-context digest, authorization policy ID, fee, output entropy, and exactly one output commitment. The worker returns the 64-byte guest output and serialized application proof. The client must compare the digest to its locally constructed statement and verify the proof against a pinned app verifying key and executable commitment before ledger submission.

### Private inputs

The witness contains the canonical transaction fields; input and output BundleV3 encodings and openings; input value, coin ID, nullifier randomness, commitment randomness, and nullifier key; leaf index and 63 Merkle siblings; output value and commitment randomness. No private witness field is intentionally revealed by the guest's public output.

### Enforced constraints

1. Canonical, bounded witness/transaction parsing; fixed transaction version, exactly one output, and exact NK-possession policy.
2. The input nullifier key opens the key commitment encoded in the input BundleV3.
3. CommitV3 recomputation binds the input bundle, value, namespace, coin ID, nullifier randomness, and commitment randomness.
4. The namespace-scoped leaf hash uses the private leaf index and input commitment; all 63 ordered siblings are folded with level-separated node hashes and must equal the public root.
5. HMAC-SHA3-384 NullifierV3 is recomputed using that same private key and exact input commitment; it must equal the public nullifier.
6. Output identity is derived from the input nullifier/commitment, parent note data, recipient bundle, public entropy, the exact `root || state_head || state_context_digest` anchor context, and canonical output slot zero. The output CommitV3 opening must equal the exact public output commitment.
7. Checked wide arithmetic enforces `input_value = output_value + fee` without overflow.
8. The public output digest binds the complete canonical transaction encoding.

The guest does not authenticate consensus finality or the truth of the root/state head. The verifier/ledger deployment must independently authenticate its bootstrap state and append-only state transitions. A valid proof alone does not establish external finality, issuance correctness, recipient intent, or reorg recovery.

## Worker and client deployment

The implemented worker is Phase A: one operator-controlled process, HTTPS with TLS 1.2 minimum, bearer API key, per-peer in-memory request throttling, bounded request/response sizes, serialized requests, no request-body logging, and a one-shot prover child receiving witness bytes on stdin. It binds to loopback by default. Public exposure requires an operator-managed TLS endpoint and network restriction. The worker holds plaintext witness in process memory and passes it to the OpenVM child; the operator and prover can inspect it. Python and OpenVM internal copies cannot be reliably zeroized by the current implementation. This is not witness-hiding.

The client sends its witness only over authenticated TLS, locally verifies the returned proof using the pinned verifier adapter, compares the public digest against its statement, wipes its mutable witness buffer, and only then submits to the SQLite ledger API/library. This is a local synthetic demonstration path; the bootstrap evidence in the fixture is deliberately not chain-finality evidence. There is no Phase B attested TEE or circuit-side decryption implementation yet.

## State transition

SQLite retains a configurable rolling anchor window (default 256), appends accepted nullifiers and commitments in a transaction, rejects duplicate nullifiers atomically, and can validate proofs against retained historical anchors. Bootstrap evidence is independently checked and integrity auditing rechecks persisted proof/state bindings. This does not by itself provide external consensus finality, crash-safe issuance coordination with an external custodian, or consensus reorg recovery.

## Cryptographic status

The only proof backend wired to this relation is the pinned OpenVM SDK candidate. The runner uses upstream OpenVM 2.0.2 / stark-backend v2.0.1 defaults, whose documented preset targets 100 bits. The in-repository parameter experiment does not reach 128 bits under the declared soundness bounds. Do not treat the guest's complete predicate as proof of production soundness, witness hiding, or prover-trace masking. Release remains gated on those properties and independent review.
