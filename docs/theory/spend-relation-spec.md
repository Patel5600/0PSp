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

The exact public-key codec, tree suite/path encoding, transaction serialization/digest and authorization policy are not frozen. The relation below names these predicates explicitly; it does not pretend an unspecified component is implemented.

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
3. **Membership.** MerkleMember(merkle_suite_id, commitment_root, C, j, membership_path) = 1. The tree hash, leaf/node domain separation, empty-tree rule, index endianness and path encoding remain **UNSPECIFIED**. This predicate is not implementation-ready until that suite is frozen.
4. **Nullifier binding.** NullifierV2(namespace_id, coin_id, r_nf) equals public_nullifier. The exact same coin_id and r_nf values from predicate 2 must be used here.
5. **Transaction binding.** TxDigestV2(params_id, namespace_id, public_nullifier, canonical_transaction_fields, authenticated_ledger_state, authorization_policy_id) equals transaction_digest. The canonical transaction field schema and TxDigestV2 encoding remain **UNSPECIFIED** and are release blockers; a caller-supplied digest that is not recomputed/constrained is invalid.
6. **Value conservation and output consistency.** The input value v equals the sum of all authorized output values plus the fee, under the selected asset/rounding policy. Every output value must be bound to the corresponding output commitment using output witnesses or an explicitly public value. Range, overflow, fee and asset rules must be enforced. No output-opening relation is instantiated yet.
7. **Authorization.** AuthVerify(authorization_policy_id, pk, transaction_digest, authorization_witness) = 1 under the exact policy committed in the public statement. Self-spend is a candidate relation requiring a scheme-specific valid secret-key witness sk and pk = DerivePK(params_id, sk); the same proof statement binds the authorized transaction. Threshold mode requires a specific post-quantum threshold scheme and verifier. No such verifier is integrated, and the policy has not been selected. FROST/RFC 9591 is discrete-log based and is not a post-quantum threshold solution.
8. **Authenticated state eligibility.** The commitment belongs to the authenticated eligible state and satisfies the protocol's spend policy. Membership alone does not establish that public_nullifier is unspent.
9. **Ledger uniqueness.** Outside the proof relation, the state transition must check and consume (namespace_id, public_nullifier) atomically with output append. Exactly one concurrent transaction using that pair may commit. This property must be implemented in durable consensus/ledger state; a local set is not sufficient.

The desired proving system must prove this single conjunction over one consistent witness. Component hash helpers do not establish proof completeness, knowledge soundness, zero knowledge, or the conjunction above.

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
  authenticated_ledger_state,
  issuance_policy_id
)
~~~

The hidden witness is:

~~~text
w_mint = (canonical_public_key pk, coin_id, r_nf, rho_C,
          any scheme-specific ownership witness)
~~~

Define R_mint(x_mint, w_mint) = 1 only if:

~~~text
C = CommitV2(params_id, pk, v_deposit,
             namespace_id, coin_id, r_nf, rho_C)
AND CanonicalWitnessAndPolicy(params_id, pk, w_mint, issuance_policy_id) = 1
~~~

Separately, the trusted deposit adapter must authenticate the chain/asset and verify:

~~~text
DepositVerify(authenticated_ledger_state, canonical_deposit_id)
  = (namespace_id, v_deposit, finalized_deposit_anchor)
~~~

The adapter's verified namespace, value and finalized anchor must match the public statement exactly. The mint verifies the issuance proof and deposit evidence, then atomically checks that the deposit ID has not been consumed and that the commitment has not already been registered before recording the canonical issuance state. The actual proof verifier, deposit adapter, durable transaction and finality/reorg behavior are not implemented.

A signed receipt over (C, v_deposit, deposit ID) alone does not establish R_mint.

## 5. CHp4.7 identity-policy decision

CHp4.7 adopts this policy for the V3 candidate: global uniqueness of the 32-byte `coin_id` alone is **not** a protocol invariant. The V3 note identity is anchored by `params_id`, namespace, canonical recipient key bundle, the exact registered commitment `C`, and its hidden opening fields `coin_id/r_nf`. An issuer-private design must not expose the hidden tuple to an issuer merely to populate a plaintext uniqueness registry.

The V2 reuse issue remains true: distinct commitments with the same tuple and different `rho_C` deterministically share a V2 nullifier. The other defect is privacy: a sender who knows the tuple can compute the unkeyed `NullifierV2` and later identify the spend. CHp4.6's sender-known derivation must not be deployed with V2 when sender-unlinkability is required.

CHp4.7 therefore specifies a **new V3 suite**, without modifying any V1/V2 formula or KAT:
- BundleV3 canonically binds an authorization scheme/public key to a commitment to the recipient-held nullifier key `nk`.
- The recipient must authenticate the exact domain-separated tuple (namespace, params ID, BundleV3) with the selected address-authorization key. The output proof must verify this signature/authentication token against the exact bundle; otherwise a sender could substitute an unknown key commitment and construct an unspendable output. The address signature codec is blocked on the authorization scheme/codec selection.
- CommitV3 binds that bundle, value, namespace, tuple and independent commitment salt; V3 uses a separate result type from V2 to prevent accidental type/ledger mixing.
- NullifierV3 is HMAC-SHA3-384 under `nk`, over a domain/version, `params_id`, namespace, canonical bundle, exact note commitment `C`, and hidden tuple. The sender may know the output tuple, commitment and bundle but not `nk`; under the PRF assumption, they cannot calculate the future nullifier from those values alone. Including `C` means changing `rho_C` changes the PRF input, so the V2 deterministic same-nullifier salt-reuse behavior is not inherited by V3. V3 uses a separate nullifier type from V2.
- Issuance identity derivation is anchored to an authenticated canonical deposit/event ID and unique global output slot. Transfer identity derivation is anchored to the exact consumed input V3 nullifier, parent witness, recipient bundle and unique global output slot.
- The proof must constrain the complete derivation, recipient address authentication and output commitment opening over one consistent witness. Durable ledger state must consume the source anchor/nullifier atomically and reject replay.

The detailed encodings, conditional argument, reference code and adversarial vectors are in [CHp4.7](../audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md). Hash outputs remain finite: no global mathematical injectivity or zero-collision guarantee is claimed.

## 5.1 V3 reference relation target

For each V3 note, require:

```text
BundleV3 = CanonicalBundle(auth_scheme_id, auth_public_key,
                           KeyCommitV3(nk))
C3 = CommitV3(params_id, BundleV3, v, ns, coin_id, r_nf, rho_C)
nu3 = HMAC-SHA3-384(
  key = nk,
  message = "0PSP-NULLIFIER-v3-HMAC-SHA3-384" || 0x03 ||
            LE16(len(params_id)) || params_id ||
            LE16(48) || ns[48] ||
            LE32(len(BundleV3)) || BundleV3 ||
            LE16(48) || C3[48] ||
            LE16(32) || coin_id[32] ||
            LE16(36) || r_nf[36]
)
```

The circuit must enforce the recipient address signature over the exact bundle, `KeyCommitV3(nk)` equals the commitment encoded in that bundle, `C3` opens under the same bundle and tuple, and `nu3` equals the public nullifier using that exact `C3` as an input. Changing `rho_C` changes `C3), and therefore changes the HMAC input; a same-nullifier result for different commitments is only a finite-output PRF collision, not deterministic reuse. Use separate version-typed values for `CoinCommitmentV3` and `NullifierV3`; do not pass V2 objects to V3 APIs or accept a V2 nullifier in a V3 ledger transition. All outputs must be derived from a one-use anchor plus canonical output index and the complete output list must be bound to the transaction digest. A second output with the same source anchor/output slot must fail the output-derivation/state-transition relation. Commitment-binding also means different commitments do not deterministically share a V3 nullifier even if their other hidden fields are repeated. A nullifier collision across distinct identities remains a computational failure event that consensus prevents from being spent twice, not an impossible event.

This is a formal target and Python reference, not an implemented circuit. The proof backend, address-signature scheme/codec, canonical transaction schema, authenticated chain adapter, encrypted note recovery, durable ledger, native V3 implementation, circuit-cost measurements and independent review remain open. Production remains **NO-GO**.

## 6. Test status and adversarial boundaries

Executable tests under tests/adversarial exercise the real V2 reference primitives for value, secret and namespace substitution, plus the CHp4.1 state model for deposit replay. These tests are finite regression tests over selected vectors. They are not general collision proofs and do not implement a ZK verifier.

The following requested fixtures are deliberately **blocked**, rather than represented by fake security tests:

- **Merkle path/index tamper:** blocked until the canonical tree hash, path encoding, leaf/node domains and index encoding are specified.
- **Deposit reorg:** blocked until a real chain adapter, finality policy and rollback/recovery state machine exist. The in-memory model can test repeat consumption, not simulate consensus reorganization safely.
- **Transaction digest/output tamper:** blocked until the canonical transaction schema and digest encoding are frozen.
- **Privacy-preserving duplicate hidden coin ID:** blocked by the open issue in Section 5.

## 7. Security and implementation status

Required but unimplemented: a selected ZK backend that supports the relation, a sound R_mint proof, a complete R_spend proof, chosen authorization policy, Merkle suite, transaction digest schema, durable ledger, real chain adapter, reorg recovery, concrete classical/quantum security bounds and independent cryptographic review.

**Release: NO-GO.** The equations above specify targets for the fixed V2 component encodings and clearly name the uninstantiated predicates. They do not constitute a proof or a production implementation.
