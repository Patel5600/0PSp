# 0PSP Spend Relation Specification — RFC-02

**Status:** formal reference relation target; no ZK backend instantiated and no security theorem claimed.  
**Production:** **NO-GO**.  
**Protocol version:** V2 only. This document does not authorize changing V2 byte formats.

## 1. Public statement and private witness

The public statement is:

~~~text
x_spend = (
  version = 2,
  params_id,
  namespace_id[48],
  commitment_root,
  public_nullifier[48],
  canonical_transaction_fields,
  transaction_digest,
  authenticated_ledger_state,
  authorization_policy_id
)
~~~

The namespace-derivation version is distinct from the V2 commitment/spend-relation version. For the current EVM adapter, namespace_id is the exact 48-byte output of typed NamespaceIdV3. The configured params_id/protocol configuration and eventual proof statement must pin this namespace scheme and constrain the exact same namespace_id bytes across commitment opening, nullifier derivation, transaction digest and ledger context. Do not take a V2 namespace ID or any independently hashed 256-bit identity components and relabel them as NamespaceIdV3. The current reference ledger checks the typed NamespaceIdV3 boundary, but there is no instantiated proof backend to constrain this requirement yet.

The private witness is:

~~~text
w_spend = (
  leaf_index j,
  commitment C[48],
  canonical_public_key pk,
  value v in [0, 2^64 - 1],
  coin_id[32],
  r_nf[36],
  rho_C[36],
  membership_path,
  output_openings_and_value_witnesses,
  authorization_witness
)
~~~

CHp4.18 freezes a canonical host-side TxFieldsV2 encoding and TxDigestV2 formula, while the public-key codec and authorization policy are still not frozen. CHp4.17 freezes the reference Merkle tree suite/path encoding, but the relation below remains unbound in any ZK circuit. The relation names these predicates explicitly; it does not pretend that host validation instantiates the cryptographic proof.

## 2. Frozen V2 component equations

All lengths and outputs below are bytes. LE16, LE32 and LE64 mean unsigned little-endian encodings of the specified length or value. SHAKE256-384 means SHAKE256 with exactly 48 output bytes; it does not mean 384-bit sponge capacity.

### V2 coin commitment

~~~text
CommitV2(params_id, pk, v, ns, coin_id, r_nf, rho_C) =
  SHAKE256-384(
    "0PSP-COIN-COMMIT-v2-SHAKE256" || 0x02 ||
    LE16(len(params_id)) || params_id ||
    LE32(len(pk))        || pk ||
    LE64(v) ||
    LE16(48) || ns[48] ||
    LE16(32) || coin_id[32] ||
    LE16(36) || r_nf[36] ||
    LE16(36) || rho_C[36]
  )
~~~

This is the current candidate byte contract in the Python reference and native implementation. The public key bytes must be canonical for the selected signature scheme; the scheme/codec is not yet frozen. Output length is 48 bytes.

### V2 nullifier

~~~text
NullifierV2(ns, coin_id, r_nf) =
  SHAKE256-384(
    "0PSP-NULLIFIER-v2-SHAKE256" || 0x02 ||
    LE16(48) || ns[48] ||
    LE16(32) || coin_id[32] ||
    LE16(36) || r_nf[36]
  )
~~~

The absorbed preimage is 149 bytes and output is 48 bytes. Do not add nk, pos, or any new field under the V2 identifier. Do not remove value from CommitV2. A change to either encoding requires a new protocol version and independent review.

## 3. Reference relation R_spend

Define R_spend(x_spend, w_spend) = 1 iff every predicate below holds.

1. **Canonical encoding and range.** The protocol version is exactly 2; params_id and public-key encodings are valid for the selected suite; namespace, commitment, coin ID, r_nf and rho_C have the specified lengths; v is an unsigned 64-bit integer; all public fields have their canonical encoding.
2. **Commitment opening.** C equals CommitV2(params_id, pk, v, namespace_id, coin_id, r_nf, rho_C), with no substituted field and no second opening supplied to another predicate.
3. **Membership.** MerkleMemberV1(params_id, namespace_id, commitment_root, C, j, membership_path) = 1, where `commitment_root` is the historical anchor root named by the transaction, not necessarily the latest root at acceptance. CHp4.17 freezes the candidate tree as a depth-63 append-only tree: H is SHAKE256-384; Z[0] = H(EMPTY_LEAF_DOMAIN || 0x01 || namespace_id); L(j,C) = H(LEAF_DOMAIN || 0x01 || namespace_id || BE64(j) || C[48]); N(l,a,b) = H(NODE_DOMAIN || 0x01 || BE32(l) || namespace_id || a[48] || b[48]); Z[l+1] = N(l,Z[l],Z[l]); and the membership path is exactly 63 bottom-up siblings. Index bit l selects left/right ordering. Issuance appends one commitment; spend outputs append in canonical transaction order. Indices are in [0, 2^63-1]. params_id must pin this exact suite and implementation version. Python tree/path tests and SQLite state checks define the reference behavior, but the proof backend must constrain these exact equations; no ZK circuit currently does so.
4. **Nullifier binding.** NullifierV2(namespace_id, coin_id, r_nf) equals public_nullifier. The exact same coin_id and r_nf values from predicate 2 must be used here.
5. **Transaction binding.** TxDigestV2 is recomputed from the exact canonical `TxFieldsV2` bytes and must equal `transaction_digest`. Every duplicated public field (params ID, namespace, commitment root, nullifier, state head, authorization policy, and output commitments) must match the decoded bytes exactly. The host codec rejects mismatches before proof-verifier callbacks, but the ZK relation must recompute/constrain the same encoding and digest over the same public values; the host check is not a substitute for that constraint.
6. **Value conservation and output consistency.** The input value v equals the sum of all authorized output values plus the fee, under the selected asset/rounding policy. Every output value must be bound to the corresponding output commitment using output witnesses or an explicitly public value. Range, overflow, fee and asset rules must be enforced. No output-opening relation is instantiated yet.
7. **Authorization.** AuthVerify(authorization_policy_id, pk, transaction_digest, authorization_witness) = 1 under the exact policy committed in the public statement. Self-spend is a candidate relation requiring a scheme-specific valid secret-key witness sk and pk = DerivePK(params_id, sk); the same proof statement binds the authorized transaction. Threshold mode requires a specific post-quantum threshold scheme and verifier. No such verifier is integrated, and the policy has not been selected. FROST/RFC 9591 is discrete-log based and is not a post-quantum threshold solution.
8. **Authenticated state eligibility.** The anchor pair (commitment_root, authenticated_ledger_state) must be present in the trusted ledger's retained anchor history. The reference SQLite candidate retains the last 256 committed state versions, including the current one. Membership alone does not establish anchor eligibility or establish that public_nullifier is unspent. The local anchor ring is not a distributed consensus or external-finality proof.
9. **Ledger uniqueness.** Outside the proof relation, the state transition must check and consume (namespace_id, public_nullifier) atomically with output append. Exactly one concurrent transaction using that pair may commit. This property must be implemented in durable consensus/ledger state; a local set is not sufficient.

### Historical anchor contract (CHp4.26 candidate)

The tuple (`commitment_root`, `authenticated_ledger_state`) in TxFieldsV2 identifies one published historical state. It is an anchor pair and must match an entry in the ledger's anchor ring buffer. For the reference SQLite implementation, the ring buffer holds at most 256 consecutive state versions, with version (v) retained iff (v \ge \max(0, current\_version - 255)). The anchor check is made both before expensive proof verification and again inside the final `BEGIN IMMEDIATE` transaction. The second check rejects an anchor that expired during proof generation/verification, but an unrelated accepted transaction no longer invalidates a proof merely because the current head advanced.

On acceptance, the transaction is serialized against the latest ledger state: duplicate nullifiers and duplicate output commitments are checked against current durable tables, outputs are appended to the current Merkle tree, and the state event/head/anchor are updated atomically. A transaction proved against historical root (R_v) does not append outputs to (R_v); it appends them to the then-current root. The proof backend must prove input membership against (R_v), and a reviewed protocol/consensus layer must ensure (R_v) is an authorized anchor. Because the commitment tree is append-only, an existing leaf remains a member of later roots too, but the exact statement root must be tied to the corresponding membership witness.

`SQLiteLedger.spend_context(commitment)` returns a consistent snapshot and membership path from one read transaction. Callers should use this instead of separately reading a snapshot and path, which could otherwise pair a root from one state with a path from another.

**Safety boundary:** the 256-version ring is a bounded local-ledger policy, not a block-height rule or a finality guarantee. It introduces an explicit expiry condition: after an anchor ages out, a client must construct a fresh proof using a retained root. Durable nullifier uniqueness is still necessary to reject concurrent double spends. These semantics are a reference-model implementation candidate, not an approved production protocol until the proof backend and consensus contract consume them identically.

The desired proving system must prove this single conjunction over one consistent witness. Component hash helpers do not establish proof completeness, knowledge soundness, zero knowledge, or the conjunction above.

### Canonical TxFieldsV2 encoding (CHp4.18)

The public spend transaction wire format is now fixed for the host/API boundary. Domain constants are exact ASCII bytes:

- `TX_FIELDS_DOMAIN = "0PSP-TX-FIELDS-v2-SHAKE256"`
- `TX_DIGEST_DOMAIN = "0PSP-TX-DIGEST-v2-SHAKE256"`

The fields are concatenated in exactly this order:

~~~text
TxFieldsV2 =
  TX_FIELDS_DOMAIN || 0x02 ||
  LE16(len(params_id)) || params_id ||
  namespace_id[48] ||
  commitment_root[48] ||
  public_nullifier[48] ||
  ledger_state_head[48] ||
  LE16(len(authorization_policy_id)) || authorization_policy_id ||
  LE64(fee) ||
  LE32(output_count) ||
  output_commitments[output_count][48]
~~~

Requirements: `params_id` and `authorization_policy_id` are each 1..65535 bytes; `fee` is an unsigned 64-bit integer; output count is 1..1024; every output commitment is exactly 48 bytes and no output commitment may repeat in one transaction. All integer encodings above are little-endian. No optional fields, maps, JSON, implicit defaults, unknown extensions, or trailing bytes are accepted. Output values/openings are intentionally not serialized as plaintext; the proof must tie every output commitment to its hidden value and prove value conservation.

The transaction digest is exactly:

~~~text
TxDigestV2(fields) =
  SHAKE256-384(
    TX_DIGEST_DOMAIN || 0x02 ||
    LE32(len(fields)) || fields
  )
~~~

The host implementation is `src/protocol/transaction_v2.py`. It provides a canonical decoder that round-trips the entire byte string, checks bounds and unique encoding, and recomputes the 48-byte digest. Both `ReferenceLedger.accept_spend` and `SQLiteLedger.accept_spend` reject the statement before invoking their verifier callback unless the decoded fields match every duplicated statement field and the digest matches. Known-answer and adversarial tests live in `tests/unit/test_transaction_v2.py`.

**Security boundary:** CHp4.18 closes the previously unspecified host/API encoding gap only. It does not constrain TxDigestV2 in a zero-knowledge relation, prove value conservation, authenticate the authorization policy, or prove the relation sound. Until a concrete proof backend implements the identical equations, transaction binding remains **Production: NO-GO**.

## 4. Reference issuance relation R_mint

The public issuance statement is:

~~~text
x_mint = (
  version = 2,
  params_id,
  namespace_id,
  commitment C,
  deposit_authorized_value v_deposit,
  canonical_deposit_id,
  finalized_deposit_anchor,
  beneficiary_address,
  authenticated_ledger_state,
  issuance_policy_id
)
~~~

The hidden witness is:

~~~text
w_mint = (canonical_public_key pk, coin_id, r_nf, rho_C,
          beneficiary-authorization witness,
          any scheme-specific ownership witness)
~~~

Define R_mint(x_mint, w_mint) = 1 only if:

~~~text
C = CommitV2(params_id, pk, v_deposit,
             namespace_id, coin_id, r_nf, rho_C)
AND BeneficiaryAuthorized(beneficiary_address, w_mint, issuance_policy_id) = 1
AND CanonicalWitnessAndPolicy(params_id, pk, w_mint, issuance_policy_id) = 1
~~~

Separately, the trusted deposit adapter must authenticate the chain/asset and verify:

~~~text
DepositVerify(authenticated_ledger_state, canonical_deposit_id)
  = (namespace_id, v_deposit, finalized_deposit_anchor, beneficiary_address)
~~~

The adapter's verified namespace, value, finalized anchor and beneficiary must match the public statement exactly. The beneficiary is not decorative event metadata: the selected issuance policy must prove that the claimant is authorized for that address, and the proof verifier must bind it into the public statement. The mint atomically checks that the canonical deposit ID has not been consumed and that the commitment has not already been registered. CHp4.11's EVM reader only creates a provider-quorum observation, not a DepositVerify result: it does not yet verify transaction/receipt trie inclusion or authenticate the execution header through consensus. The actual proof verifier, authenticated deposit adapter, durable transaction and finality/reorg recovery remain unimplemented.

A signed receipt over (C, v_deposit, deposit ID) alone does not establish R_mint.

## 5. Version boundary: V3 is specified separately

RFC-02 is normative only for the V2 spend relation. The former CHp4.7 V3 appendix has been moved to the [separate V3 candidate relation](spend-relation-v3-candidate.md) so implementers cannot mistake it for a change to the frozen V2 relation.

That V3 document is **research-only and non-normative**. It does not authorize V3 spends, select an authorization scheme, freeze HMAC-SHA3-384 as a production contract, or claim that a complete proof relation exists. V1/V2 byte formats and known-answer vectors remain frozen.

V3 remains **Production: NO-GO** pending recipient-address authentication and key recovery semantics, a selected authorization policy/verifier, a complete shared-witness proof, pinned backend feasibility measurements, durable anchor/output enforcement, and independent cryptographic review. The canonical [Production Gate Matrix](../security/production-gate-matrix.md) tracks those blockers.
