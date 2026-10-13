# 0PSP Spend Relation V3 Candidate — CHp4.7

**Status:** research-only, non-normative candidate.  
**Production:** **NO-GO**.  
**Protocol boundary:** this file is separate from [RFC-02, the V2-only spend relation](spend-relation-spec.md). It does not amend V1/V2 formulas, encodings, APIs or known-answer tests. Production code and ledgers must not accept these V3 candidate types as authorized spends.

This file isolates the V3 identity/nullifier material that was previously appended to the V2-only RFC-02. It is not an approved wire protocol or cryptographic specification. BundleV3, CommitV3, NullifierV3 and anchored output derivation are reference candidates only. The authorization/key codec, recipient authentication scheme, encrypted note delivery and recovery lifecycle, complete shared-witness proof, backend, circuit cost and independent cryptographic review remain unselected or unimplemented. A host helper now generates the 48-byte nullifier-deriving key from Python's OS-backed CSPRNG, but this is key-byte generation only: it does not provide storage, encryption, backup, recovery, or reliable zeroization.

**Primitive decision constraint:** HMAC-SHA3-384 is a provisional research candidate, not a frozen production byte contract. Do not select or replace the PRF based on intuition; first pin a candidate proof backend that passes its own privacy/soundness feasibility gate, measure the complete candidate relations and compare alternatives at stated security levels. Any primitive or encoding change requires a separately reviewed protocol version and new vectors.

**Prior-art warning:** the design borrows property-level ideas from anonymous-payment systems; it makes no claim that recipient-keyed nullifiers or anchored output identity are novel. See the prior-art record in [CHp4.7 audit](../audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md).

## 1. CHp4.7 V3 identity-policy candidate

CHp4.7 adopts this policy for the V3 candidate: global uniqueness of the 32-byte `coin_id` alone is **not** a protocol invariant. The V3 note identity is anchored by `params_id`, namespace, canonical recipient key bundle, the exact registered commitment `C`, and its hidden opening fields `coin_id/r_nf`. An issuer-private design must not expose the hidden tuple to an issuer merely to populate a plaintext uniqueness registry.

The V2 reuse issue remains true: distinct commitments with the same tuple and different `rho_C` deterministically share a V2 nullifier. The other defect is privacy: a sender who knows the tuple can compute the unkeyed `NullifierV2` and later identify the spend. CHp4.6's sender-known derivation must not be deployed with V2 when sender-unlinkability is required.

CHp4.7 therefore records a **new V3 research candidate**, without modifying any V1/V2 formula or KAT:
- BundleV3 canonically binds an authorization scheme/public key to a commitment to the recipient-held nullifier key `nk`.
- **Separate spend authority from intended-payee identity.** The leading zero-dependency core-spend policy candidate is possession of the recipient-generated `nk`: the eventual knowledge-sound proof must bind `KeyCommitV3(nk)` to the exact bundle, use the same `nk` to derive the public `NullifierV3`, and bind that relation to the authenticated input note and complete transaction. This can make a signature verifier unnecessary for the core spend predicate, but only if the proof system is knowledge-sound and actually hides `nk`; neither property is established for a production 0PSP relation yet. The transaction's `authorization_policy_id` must explicitly select `0PSP-V3-NK-POSSESSION-CANDIDATE-v1`; arbitrary/unknown policies fail closed. The existing `auth_scheme_id` and `auth_public_key` fields do **not** become proof of intended-payee identity by being self-asserted. If intended-payee authentication is required, a separate independently authenticated address/invoice/recovery-key anchor must bind to the exact namespace, params ID, BundleV3 and output commitment. That address-authentication and anti-substitution gate remains **NO-GO**.
- CommitV3 binds that bundle, value, namespace, tuple and independent commitment salt; V3 uses a separate result type from V2 to prevent accidental type/ledger mixing.
- NullifierV3 is HMAC-SHA3-384 under `nk`, over a domain/version, `params_id`, namespace, canonical bundle, exact note commitment `C`, and hidden tuple. The sender may know the output tuple, commitment and bundle but not `nk`; under the PRF assumption, they cannot calculate the future nullifier from those values alone. Including `C` means changing `rho_C` changes the PRF input, so the V2 deterministic same-nullifier salt-reuse behavior is not inherited by V3. V3 uses a separate nullifier type from V2.
The reference API exposes `generate_nullifier_deriving_key_v3()`, which requests exactly 48 bytes from `secrets.token_bytes` and constructs the fixed-width secret type. Tests validate the requested length, redacted representation, invalid source-output rejection, and fail-closed propagation if the entropy source raises. This checks API behavior, not entropy quality or key-management security. Python immutable `bytes` cannot be reliably zeroized by this interface; secret storage, note encryption, backup/restore, rotation/recovery, and recipient address authentication remain separate NO-GO gates.

- Issuance identity derivation is anchored to an authenticated canonical deposit/event ID and unique global output slot. Transfer identity derivation is anchored to the exact consumed input V3 nullifier, parent witness, recipient bundle and unique global output slot.
- The proof must constrain the complete derivation, the chosen recipient-identity semantics, any independent payee anchor/authentication, and output commitment opening over one consistent witness. A signature proving control of a key is not a substitute for binding that key to the intended payee. Durable ledger state must consume the source anchor/nullifier atomically and reject replay.

The detailed encodings, conditional argument, reference code and adversarial vectors are in [CHp4.7](../audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md). Hash outputs remain finite: no global mathematical injectivity or zero-collision guarantee is claimed.

The proposed core spend-authorization policy for the next V3 relation experiment is the following *proof-of-knowledge/capability-key* construction, not a detached host signature check:

```text
authorization_policy_id = "0PSP-V3-NK-POSSESSION-CANDIDATE-v1"
KeyCommitV3(nk) = BundleV3.nullifier_key_commitment
C3 = CommitV3(params_id, BundleV3, v, ns, coin_id, r_nf, rho_C)
nu3 = HMAC-SHA3-384(nk, exact_NullifierV3_message(params_id, ns, BundleV3, C3, coin_id, r_nf))
TxDigestV3 = TxDigestV3Candidate(exact canonical TxFieldsV3Candidate)
```

Under this policy, spend authority is knowledge of the same 48-byte recipient-held `nk` that opens the note bundle's key commitment and derives the public nullifier. A sound proof of the complete predicate is the authorization; the public nullifier alone or a host-side HMAC computation is not. The complete relation must bind the above equations to the exact registered input commitment, authenticated membership path/root/state head, output list/identities, range-safe value conservation, transaction digest and this policy ID. A proof system that leaks the `nk` witness is not acceptable. The current OpenVM spike enforces only the key-commitment, commitment-opening and HMAC slice; it does **not** enforce the policy ID, membership, trusted state, full transaction or value/output relation. Consequently, the policy is a selected *experiment target*, not production authorization.

This policy avoids adding a threshold-signature dependency to every core spend and fits the recipient-generated secret already required by NullifierV3. It does not authenticate that a self-asserted bundle belongs to an intended payee. The existing `authorization_input_v3_candidate()` and ML-DSA-87 threshold path remain an optional separate authentication/authorization experiment, not the default policy and not a selected production suite.

The ML-DSA-87 path still requires a canonical key/signature codec, private-witness/public-input exposure decision, threshold DKG/key lifecycle, license reconciliation and an exact-release audit-scope decision. The tagged upstream release has conflicting audit-status statements and a subcrate license-scope conflict. If the protocol elects to use ML-DSA for a separate policy later, the proof must verify it under the exact key bound to the same BundleV3 and exact transaction digest/context. A standalone signature verifier is insufficient if it checks a different or public key.

## 2. V3 reference relation target

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

The circuit must enforce the key-commitment opening and the exact `BundleV3`/`C3`/tuple/`nu3` relations under one witness. If intended-payee authenticity is required, it must also verify an independently anchored recipient-authorization or authenticated recovery-key statement over this exact bundle; a self-signature alone is insufficient. `KeyCommitV3(nk)` must equal the commitment encoded in that bundle, `C3` must open under the same bundle and tuple, and `nu3` must equal the public nullifier using that exact `C3` as an input. Changing `rho_C` changes `C3`, and therefore changes the HMAC input; a same-nullifier result for different commitments is only a finite-output PRF collision, not deterministic reuse. Use separate version-typed values for `CoinCommitmentV3` and `NullifierV3`; do not pass V2 objects to V3 APIs or accept a V2 nullifier in a V3 ledger transition. All outputs must be derived from a one-use anchor plus canonical output index and the complete output list must be bound to the transaction digest. A second output with the same source anchor/output slot must fail the output-derivation/state-transition relation. Commitment-binding also means different commitments do not deterministically share a V3 nullifier even if their other hidden fields are repeated. A nullifier collision across distinct identities remains a computational failure event that consensus prevents from being spent twice, not an impossible event.

This is a formal target and Python reference, not an implemented circuit. The host-only candidate transaction codec lives in `src/protocol/transaction_v3_candidate.py`; it binds params, namespace, prior commitment root, input V3 nullifier, state head, authorization policy, fee, public output entropy, ordered V3 output commitments, and a domain-separated digest. The host candidate validator now recognizes the exact `0PSP-V3-NK-POSSESSION-CANDIDATE-v1` policy ID, but this is not a proof-enforced policy selector. For the ML-DSA-87 threshold experiment only, `authorization_input_v3_candidate(fields, bundle)` requires the canonical BundleV3 and returns `(m_auth, ctx_auth)`. Here `m_auth = TxDigestV3Candidate(fields)` and `ctx_auth = b"0PSP-TX-AUTH-v3-CANDIDATE" || LE16(len(bundle.auth_scheme_id)) || bundle.auth_scheme_id`, with a final context length no greater than 255 bytes. The context binds the declared scheme identifier; the relation must still decode the authorization public key from that same bundle and prove that the bundle is committed by the spent note. The candidate relation must require `MLDSA87.Verify(pk_auth, m_auth, ctx_auth, sigma_auth) = 1`, with `pk_auth` decoded from the exact `BundleV3.auth_public_key` and `sigma_auth` produced by the threshold protocol. Whether the signature is public or kept as a private witness must be decided explicitly; the default research assumption is a private witness so the proof can hide it, but this has not been analyzed for transcript leakage. This equation is a feasibility target, not an approved scheme or proof. The backend must constrain the exact transaction bytes and verify the signature against the same hidden authorization key committed in the same V3 note. The public key/signature codec, audit-scope discrepancy, license scope, key-generation/DKG model, intended-payee authentication anchor, authenticated chain adapter, encrypted note recovery, durable consensus ledger, native V3 implementation, circuit-cost measurements and independent review remain open. Production remains **NO-GO**.

The host preflight contract in `src/protocol/trusted_state_v3.py` now requires an injected state-evidence adapter to return a canonical snapshot and rejects mismatched namespace, params ID, commitment root, ledger state head, source ID or finalized anchor before invoking a candidate proof-verifier callback. Tests exercise those boundaries. This is not an authenticated state provider, consensus protocol, ZK constraint, or atomic ledger transition; those gates remain **NO-GO**.

## 3. Test status and adversarial boundaries

Unit/adversarial tests cover selected V3 reference vectors and malformed-input/substitution cases, alongside V2 primitive regressions and the local state-model replay checks. These are finite reference-code tests over selected inputs; they do not prove collision resistance, address authenticity, global uniqueness, privacy, or correct behavior of an actual ZK verifier.

The host-level candidate codec tests round-trip canonical bytes, include a fixed digest known-answer vector, mutate every public transaction dimension (including output ordering and public output entropy), and reject wrong domains/versions, trailing data, duplicate outputs and V2 typed objects. They validate only serialization/digest behavior; they are not circuit tamper tests.

The following V3 proof/security fixtures remain deliberately **blocked**, rather than represented by fake security tests:

- **Merkle path/index tamper in a proof:** the reference depth-63 tree and host tests exist, but no selected ZK backend constrains the exact path, direction bits, root and leaf/index relation.
- **Deposit reorg/finality:** helper and evidence components exist, but there is no accepted end-to-end consensus-authenticated deposit-to-issuance path or production recovery/reorg proof.
- **V3 transaction/output tamper:** a versioned host codec/digest candidate and adversarial tests now exist. They do not prove that a ZK relation constrains the same bytes, that output identity derivation uses the canonical output slot/entropy, or that the host ledger binds root/head/policy to trusted state.
- **Anchored output replay/aliasing:** test duplicate source-anchor/global-slot substitutions, repeated commitments and atomic state conflicts against the eventual proof plus durable ledger. Plaintext global uniqueness of hidden `coin_id` is intentionally not required.

## 4. Security and implementation status

Required but unimplemented: a selected ZK backend that supports the complete relation in reviewed zero-knowledge mode; sound R_mint and complete V3 spend proofs; a chosen post-quantum authorization/address-authentication policy and canonical codecs; proof-constrained membership and V3 transaction encoding; durable consensus ledger enforcement; authenticated chain/custody composition; reorg/recovery; concrete classical/quantum security bounds; and independent cryptographic review.

**Release: NO-GO.** This document specifies V3 research predicates and names the uninstantiated gates; it is not a proof or production implementation. HMAC-SHA3-384 remains provisional. Do not freeze it as a production byte contract until a pinned backend feasibility experiment measures the actual V3 relation and a separately reviewed versioned decision approves the construction.
