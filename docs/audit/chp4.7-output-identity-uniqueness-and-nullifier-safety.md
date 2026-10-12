# CHp4.7 — Output identity uniqueness and nullifier safety

**Decision:** adopt a recipient-keyed, versioned V3 nullifier candidate and anchor every output identity to a one-use creation anchor plus a canonical global output slot.  
**Reference implementation:** V3 nullifier, recipient key bundle, V3 commitment and issuance/transfer identity candidates plus known-answer/adversarial tests.  
**Proof/backend status:** NOT IMPLEMENTED.  
**Production:** **NO-GO**.  
**Compatibility rule:** frozen V1/V2 functions and vectors are unchanged. V3 is additive and must not be silently treated as V2.

## 1. Exact problem

The active V2 component functions are:

```text
C2 = CommitV2(params_id, pk, v, ns, coin_id, r_nf, rho_C)
nu2 = NullifierV2(ns, coin_id, r_nf)
```

`C2` binds an independent 36-byte commitment salt `rho_C`; `nu2` does not. Thus the same `(ns, coin_id, r_nf)` and different `rho_C` may produce different commitment bytes but exactly the same public nullifier. It is deterministic identity reuse, not a SHAKE collision. A ledger can reject the second nullifier, but cannot make both notes spendable. The test `tests/adversarial/test_hidden_tuple_reuse.py` records this behavior and must remain in the suite.

A 32-byte `coin_id` is also not a globally unique identifier in a mathematical sense. Generic collision search against 256 bits has about a 128-bit classical birthday scale and about a 2^85-query quantum collision-search scale in an idealized oracle model. The protocol must not treat `(namespace, coin_id)` alone as a unique accepted note, and must not transfer the longer nullifier's collision bound to `coin_id`.

## 2. Why the CHp4.6 candidate is not the complete solution

CHp4.6 derives outputs from the input tuple, a sender-known spend-key witness, transaction entropy and output index. It is a useful identity-derivation reference and distinguishes selected output slots. It is not an enforceable relation.

More importantly, its output `coin_id` and `r_nf` are known to the transaction creator/prover. Under V2, that creator can evaluate the unkeyed deterministic `NullifierV2(ns, coin_id, r_nf)` and match the future public nullifier. If sender-unlinkability is a requirement, using the CHp4.6 candidate with V2 creates a note-linkability defect. We do not approve that pairing for a production privacy protocol.

The fix cannot merely change the output hash or add another commitment. It needs both (a) an anchored, circuit-constrained rule against exact identity reuse and (b) a nullifier derivation the recipient can compute but an output creator cannot compute from the values used to construct the output.

## 3. Adopted V3 protocol candidate

### 3.1 Identity is the complete note identity, not coin_id by itself

For V3, the candidate note identity is:

```text
NoteIdentityV3 =
    (namespace_id, canonical_note_public_key_bundle,
     coin_id[32], r_nf[36])
```

The canonical key bundle binds the authorization scheme and public key to a commitment to the recipient's per-note nullifier-deriving key. This bundle participates in both the V3 commitment opening and V3 nullifier message. Reusing `coin_id` alone is not prohibited and is not proof of a collision. Reusing an accepted source anchor/output slot or reusing the same complete note identity is prohibited by the construction and ledger rules.

**Recipient-address authenticity is also mandatory.** The recipient must create `nk`, verify locally that `KeyCommitV3(nk)` matches the bundle, and authenticate the exact domain-separated bundle with the selected address-authorization key. Every output proof must validate that authentication against the exact bundle committed in the note; the sender must not be able to substitute a new key commitment while retaining the intended recipient's authorization key. Otherwise, the sender could build an output around a key commitment whose opening the recipient does not know, causing an unspendable note without any hash collision. The exact address-signature scheme and canonical signature encoding are blocked on the repository's still-unselected authorization codec; no fake verifier is introduced.

The V3 identity policy intentionally does not require the issuer to receive or compare hidden `coin_id` values in plaintext. It does not claim all hash outputs are injective.

### 3.2 Recipient-keyed nullifier

V3 introduces an additive 48-byte recipient secret `nk` (384 bits), which is generated and retained by the recipient for one note. The candidate nullifier is:

```text
KeyCommitV3(nk) =
  SHAKE256-384(
    "0PSP-NULLIFIER-KEY-COMMIT-v3-SHAKE256" || 0x03 ||
    LE16(48) || nk[48]
  )

BundleV3 =
  "0PSP-NOTE-PK-BUNDLE-v3" || 0x03 ||
  LE16(len(auth_scheme_id)) || auth_scheme_id ||
  LE32(len(auth_public_key)) || canonical_auth_public_key ||
  LE16(48) || KeyCommitV3(nk)

NullifierV3(ns, BundleV3, coin_id, r_nf, nk) =
  HMAC-SHA3-384(
    key = nk,
    message =
      "0PSP-NULLIFIER-v3-HMAC-SHA3-384" || 0x03 ||
      LE16(48) || ns[48] ||
      LE32(len(BundleV3)) || BundleV3 ||
      LE16(32) || coin_id[32] ||
      LE16(36) || r_nf[36]
  )
```

The recipient needs the private `nk` to compute the nullifier. Knowing the output identity tuple and public bundle is not sufficient to compute it under the HMAC-PRF assumption. The key commitment is not a replacement for key secrecy; it is the value that lets a proof bind the recipient's secret key to the exact canonical bundle inside the note commitment.

This is a new V3 suite, not a change to `NullifierV2`. All existing V1/V2 formulas and known-answer vectors remain byte-for-byte unchanged. The reference API uses distinct `NullifierV3` and `CoinCommitmentV3` result types to prevent accidental version mixing; the durable transaction schema must also carry and enforce the protocol version.

**Primitive-selection caveat:** HMAC-SHA3-384 is the current reference candidate, not a final post-quantum PRF certification. NIST SP 800-185 also defines KMAC as a SHA-3-derived MAC that can be used as a PRF. Before freezing a production circuit, compare the selected keyed-hash candidate under the intended classical/quantum security model and measure its actual proof cost. Do not silently swap HMAC for KMAC within a deployed version; primitive changes require a separately reviewed version and new vectors.

### 3.3 Versioned V3 note commitment

V3 adds `CommitV3` as a new domain/version; it does not alter `CommitV2`:

```text
CommitV3(params_id, BundleV3, v, ns, coin_id, r_nf, rho_C) =
  SHAKE256-384(
    "0PSP-COIN-COMMIT-v3-SHAKE256" || 0x03 ||
    LE16(len(params_id)) || params_id ||
    LE32(len(BundleV3)) || BundleV3 ||
    LE64(v) ||
    LE16(48) || ns[48] ||
    LE16(32) || coin_id[32] ||
    LE16(36) || r_nf[36] ||
    LE16(36) || rho_C[36]
  )
```

The independent commitment salt remains independent and is not a uniqueness anchor. The V3 public-key bundle encoding is strict and canonical; decoding rejects truncated or trailing bytes. The production authorization scheme and its public-key codec still must be pinned.

Reference modules added in this branch:
- `src/primitives/nullifier_v3.py`
- `src/primitives/coin_commitment_v3.py`
- `src/protocol/note_public_key_bundle_v3.py`

### 3.4 One-use anchor and canonical output slot

A recipient-keyed nullifier fixes the creator's ability to calculate the later nullifier; it does not alone prevent a creator from submitting two commitments to the same complete note identity with different commitment salts. Output identity must also be constrained by the actual proof.

**Issuance:** the source anchor is the authenticated, canonical deposit/event identity, scoped to `namespace_id`. The trusted chain adapter must form that identifier from a ledger/network identity, transaction identifier, event/log or output index, and asset/deployment fields as needed. The adapter, not the requester, supplies the canonical ID. The durable ledger atomically consumes it once. Derivation also binds the recipient's canonical key bundle, private issuance entropy, params ID and a unique zero-based output index.

Candidate relation:

```text
(coin_id, r_nf) =
  DeriveIssuanceIdentityV3(
    namespace_id, canonical_deposit_event_id, BundleV3,
    private_issuance_entropy, global_output_index, params_id
  )
```

**Transfer:** the source anchor is the exact V3 public nullifier of the input being consumed. Derivation additionally binds the exact parent tuple, parent bundle, parent key witness, recipient BundleV3, transaction entropy, params ID, and canonical output index.

Candidate relation:

```text
(coin_id_out, r_nf_out) =
  DeriveTransferIdentityV3(
    namespace_id, parent BundleV3, parent coin_id, parent r_nf,
    parent nk, parent spend-key witness, recipient BundleV3,
    transaction_entropy, global_output_index, params_id
  )
```

The complete canonical output list owns one zero-based global output index space. Recipient-local indices, caller-selected alternate encodings, duplicate indices and unbound side lists are forbidden. The current candidate uses uint16 indices (0 through 65535), which caps each canonical output list at 65,536 slots. Changing that is a new derivation version.

V3 reference functions live in `src/protocol/output_identity.py`. They use SHAKE256 with separate domains for `coin_id` and `r_nf`. They do not check whether the deposit anchor is canonical, prove a witness statement, ensure entropy was sampled correctly, or stop an arbitrary API client from bypassing a future circuit. The proof and ledger must enforce the relation and one-use state.

### 3.5 Why the two mechanisms are both necessary

- **Keyed nullifier only:** keeps the future nullifier secret from an output creator but does not prevent the creator from registering duplicate commitments that share the same tuple/key bundle.
- **Anchor/index only with V2:** helps make repeated derivations difficult to accept, but if the sender sees the output tuple then V2 exposes the future nullifier deterministically to that sender.
- **V3 keyed nullifier + anchored identity relation + durable one-use ledger:** blocks direct tuple selection/reuse in accepted proofs and stops an output creator from computing the recipient's nullifier from the public output data, conditional on the keyed-PRF and proof-soundness assumptions.

The sender may know the derivation inputs, including the output tuple, and still must not know `nk`. The recipient's `nk` must be generated on the recipient side and delivered to the sender only via the key commitment in BundleV3, never as plaintext. The receiving address must authenticate the exact namespace, params ID, authorization key, and nullifier-key commitment; the output proof must enforce this authentication. A note protocol still has to encrypt the recovery payload and prevent a sender from substituting another bundle. Reusing one `nk` across notes is disallowed by this candidate unless a future proof and privacy review explicitly approves it.

### 3.6 Same-salt and cross-identity cases

- Same complete V3 note identity, different `rho_C`: `CommitV3` can differ but `NullifierV3` is the same. The proof must reject a second output identity because the source anchor/output slot was already used.
- Same `coin_id`, different `r_nf`: not the same identity tuple. This is not inherently a duplicate; the full relation and anchor derivation apply.
- Same tuple, different `nk` and distinct key-bundle commitments: different V3 nullifier inputs and different note identities. Global `coin_id` uniqueness is not a requirement.
- Distinct identity derivation inputs: hashes can still collide. These functions are not mathematically injective. The joint identity collision bound must be analyzed under the actual adversarial and quantum-query model; no combined bit-strength claim is made here.
- Equal V3 public nullifiers for distinct notes: the ledger must reject the later spend. That finite-output collision may still make the later note unspendable; it is a negligible-probability cryptographic risk only after the concrete construction is analyzed, not an impossible event.

## 4. Required V3 proof relation

The actual circuit or proof relation must establish a single consistent witness across all of the following. A Python reference check is not an alternative.

1. **Canonical bundle:** the encoded BundleV3 has exactly one valid decode and binds the selected authorization scheme, the canonical authorization public key and the key commitment.
2. **Recipient-address authenticity:** verify a domain-separated recipient signature/authentication token over the exact namespace, params ID and BundleV3 using the selected address-auth suite. The proof must bind this verified statement to the output bundle; signature bytes/encoding and suite must be frozen before implementation.
3. **Commitment opening:** `C = CommitV3(params_id, BundleV3, v, ns, coin_id, r_nf, rho_C)`.
4. **Recipient key:** the private 48-byte `nk` hashes to the exact `KeyCommitV3(nk)` inside that same BundleV3.
5. **Nullifier:** `public_nullifier = NullifierV3(ns, BundleV3, coin_id, r_nf, nk)`.
6. **Input membership/eligibility:** the exact input commitment is in the authenticated state/root and is not already spent under the ledger state being proved.
7. **Transfer output derivation:** every output `coin_id/r_nf` is derived from the exact consumed input V3 nullifier and parent witness, recipient BundleV3, transaction entropy, global output index and params ID.
8. **Issuance derivation:** every issuance output identity is derived from the canonical authenticated one-use deposit event, recipient BundleV3, output index and params ID.
9. **Output binding:** each output tuple, BundleV3, value and salt is bound to exactly one CommitV3; no output may be omitted from the list proved by the transaction digest.
10. **Authorization and accounting:** the canonical authorization public key approves this transaction; all output values, fee, range/overflow and asset rules satisfy the policy.
11. **Transaction binding:** the digest is recomputed from the canonical transaction bytes, V3 version, params ID, input nullifier(s), anchors, entropy, output ordering, and every output commitment. The schema must be frozen before implementation.
12. **No aliasing from alternate encoding:** all lengths and indices are range-checked; no duplicate output indices, duplicate output records or trailing bytes.
13. **Ledger transition:** the durable ledger atomically consumes each deposit/input anchor and appends the new commitments. Concurrency, process crash, reorg, rollback and recovery preserve exactly the same one-use rules.

A one-input relation is the only currently scoped transfer candidate; multi-input semantics are not implied. If multiple input/output sections are eventually supported, the protocol needs one canonical global output index and one unambiguous anchor-selection rule.

## 5. Adversarial tests and evidence

The branch adds tests for:
- V3 recipient key commitment, exact BundleV3 encoding and decoding;
- hardcoded V3 nullifier and V3 commitment vectors;
- same tuple/same bundle/same key producing one nullifier when `rho_C` changes;
- different recipient key or authorization bundle yielding a different keyed nullifier in selected vectors;
- strict malformed/truncated/trailing bundle rejection and wrong key rejection;
- the frozen V2 nullifier known-answer vector (unchanged);
- V3 issuance identity with a fixed vector and variations in anchor, recipient bundle, index, entropy, namespace and params;
- V3 transfer identity with a fixed vector and variations in parent anchor, recipient bundle, index, entropy and params;
- the original hidden-tuple-reuse regression.

These are byte-level reference regressions over finite inputs. They do **not** test an actual zero-knowledge circuit, prove HMAC/ SHAKE collision resistance, prove protocol privacy, or establish global uniqueness. A correct production proof must include negative proof tests for substituted `coin_id`, `r_nf`, `nk`, key commitment, public-key bundle, parent nullifier, transaction entropy, index, recipient, value, commitment opening, and digest. Duplicate deposit/input-nullifier and racing transaction tests must use the real durable ledger adapter when it exists.

## 6. Conditional security argument

The intended safety claim is conditional on all of the following:
- canonical authenticated creation anchors cannot be forged or ambiguously encoded;
- an anchor is consumed at most once by consensus state;
- each output index is unique and bound to the canonical output list;
- the V3 proof is knowledge-sound and enforces the exact identity derivation, BundleV3/key commitment, commitment opening and keyed nullifier over a single witness;
- `nk` is high-entropy, recipient-controlled, per-note secret material, never disclosed to the sender/issuer and not recoverable from its commitment;
- HMAC-SHA3-384 is used as a keyed PRF under an appropriate classical/quantum security model, and SHAKE-based key commitments/identity derivations meet their stated assumptions;
- V3 public nullifiers are rejected atomically on the canonical ledger, including consensus recovery and reorg handling.

Under these assumptions, changing `rho_C` cannot produce a second accepted note with the same identity/anchor/slot, while a sender who knows the output tuple and key bundle lacks `nk` and cannot directly compute its future V3 nullifier under the PRF assumption. This is not a claim that all distinct hash inputs must yield distinct outputs. It also does not hide transaction amounts, timestamps, network metadata, or public transaction structure on its own.

The proof system's actual hash costs matter. HMAC-SHA3-384 may be expensive inside the chosen ZK backend; we have no circuit constraint counts or full prover/verifier measurements. Do not claim feasibility until a pinned backend compiles the relation and benchmarks equivalent security parameters. Alternative keyed PRF candidates can be assessed only as a new versioned design decision, not swapped into this byte contract silently.

## 7. Literature and implementation prior art

This decision borrows a property-level architecture from well-reviewed anonymous-payment protocols, not their entire primitives/circuits:

1. **Zcash Orchard Book — Nullifiers:** explains that each note's nullifier must be tied to its hidden note fields and describes the use of a recipient nullifier deriving key: <https://zcash.github.io/orchard/design/nullifiers.html>.
2. **Zcash Orchard circuit source:** the circuit constrains newly created note `rho` from the consumed input nullifier in its one-spend/one-output action model: <https://github.com/zcash/orchard/blob/main/src/circuit.rs>.
3. **ZIP 227 — Computation of `rho` for issuance notes:** uses a unique input nullifier plus canonical action and note indices to anchor issued-note `rho`: <https://zips.z.cash/zip-0227>.
4. **Zcash issue #955:** documents an attack against spendability when issued-note `rho` might not be unique and discusses consensus enforcement: <https://github.com/zcash/zips/issues/955>. The issue is a historical discussion, not proof that 0PSp's distinct assumptions are automatically solved.
5. **Sapling protocol specification:** describes recipient-keyed nullifier derivation and the desired unlinkability constraints for notes: <https://zips.z.cash/protocol/sapling.pdf>.
6. **Formal Zerocash Quint specification:** models vulnerable Faerie Gold and a Sapling-style anchored fix side by side. Its symbolic injective hash abstraction is not a concrete hash collision proof: <https://github.com/informalsystems/Zerocash-spec>.
7. **Ben-Sasson et al., Zerocash (IEEE S&P 2014):** foundational private decentralized payments protocol and proof relations: <https://eprint.iacr.org/2014/349.pdf>.
8. **NIST FIPS 198-1 — HMAC:** definition of the keyed-hash construction used in this V3 candidate: <https://csrc.nist.gov/pubs/fips/198-1/final>.
9. **NIST FIPS 202 — SHA-3 and SHAKE:** normative definitions for SHAKE-based key commitment, identity derivation and V3 commitment candidate: <https://csrc.nist.gov/pubs/fips/202/final>.
10. **Brassard, Høyer and Tapp — Quantum Algorithm for the Collision Problem:** basis for the warning that quantum collision search is faster than classical birthday search under the generic oracle model: <https://arxiv.org/abs/quant-ph/9705002>.

Orchard/Sapling use different curves, PRFs and circuit constructions; do not transplant their Pallas/Poseidon/Sinsemilla details into 0PSp's SHAKE-based implementation. A literature analogy is not a security reduction.

## 8. Final status / release gate

**Resolved by this change:** the identity policy ambiguity is replaced by a concrete versioned candidate: do not require uniqueness of `coin_id` alone; use a complete note identity, anchor every output to a one-use creation source and canonical slot, and use recipient-keyed V3 nullifiers so the creator cannot compute the future nullifier from the output tuple.

**Still blocked:** no real proof backend/circuit is integrated, no production issuance/spend verifier exists, no canonical chain adapter or durable consensus ledger exists, no note encryption/recovery payload is specified, the authorization-key codec and HMAC-SHA3-384 circuit feasibility are not selected/measured, native V3 constant-time behavior is not implemented/audited, and no independent cryptographic audit has been performed. V3 reference tests do not prove the relation. V2 code stays unchanged.

**Release decision: NO-GO.** The policy and reference candidate are ready for adversarial review in a pull request; protocol-level enforcement is not complete until the listed backend/ledger gates are implemented and verified.
