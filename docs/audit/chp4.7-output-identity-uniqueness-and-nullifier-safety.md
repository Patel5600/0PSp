# CHp4.7 — Output identity uniqueness and nullifier safety

**Decision:** the protocol-level identity policy is now specified for review.  
**Implementation status:** reference derivations and vectors only; no proof backend enforces them yet.  
**Production:** **NO-GO**.  
**Scope:** the same-hidden-identity/different-commitment-salt spendability failure. V2 commitment and nullifier formulas, encodings, and known-answer vectors remain frozen.

## 1. Decision

The protocol will **not** require global uniqueness of the 32-byte `coin_id` field by itself. Under V2, a spend is identified by the complete tuple:

```text
SpendIdentity = (namespace_id[48], coin_id[32], r_nf[36])
Nullifier     = NullifierV2(namespace_id, coin_id, r_nf)
Commitment    = CommitV2(params_id, pk, value, namespace_id,
                         coin_id, r_nf, rho_C)
```

The `coin_id` field is not a globally unique ledger primary key. No consensus, wallet, mint, or API component may treat `(namespace_id, coin_id)` alone as a unique spendable note. Two outputs with the same coin_id but different r_nf are distinct spend identities; they are not an identity-reuse attack by themselves. Value conservation and exact commitment opening remain mandatory.

The prohibited condition is **two distinct accepted note commitments with the same complete SpendIdentity**. In that case V2 deterministically gives both notes the same nullifier, irrespective of their independent `rho_C` commitment salts. Consensus can accept at most one of those spends, leaving the other note unspendable.

This decision avoids requiring an issuer to compare a hidden 32-byte coin_id in plaintext, avoids a public identity registry that would expose it, and does not pretend that a 32-byte hash output is injective. It is a specific identity-policy decision, not a claim that global ID collisions are mathematically impossible.

## 2. Root cause

The existing V2 primitives correctly implement these separate functions:

- `commit_coin_v2` binds namespace, public key, value, coin_id, r_nf, parameters and the independent 36-byte `rho_C`.
- `compute_nullifier_v2` hashes namespace, coin_id and r_nf, but excludes `rho_C`.
- The in-memory reference ledger rejects duplicate public nullifiers atomically within one process; it cannot inspect hidden opening fields or prove that a new output identity was derived correctly.

Consequently, changing only `rho_C` can create a different commitment with the same nullifier. The existing `tests/adversarial/test_hidden_tuple_reuse.py` is a valid demonstration of this failure mode. It must remain as a regression test.

## 3. Chosen construction: a one-use creation anchor plus canonical output slot

Every accepted note identity must be derived inside the eventual proof relation from a creation anchor that the ledger guarantees is single-use, the canonical output index, and private witness material. A prover must not be free to supply arbitrary `coin_id` and `r_nf` values.

### Issuance note

For an issuance, the anchor is the authenticated canonical deposit/event identifier scoped by the namespace. The issuance relation must constrain:

```text
(coin_id, r_nf) =
  DeriveIssuanceIdentityV1(namespace_id, canonical_deposit_id,
                           private_issuance_entropy, output_index,
                           params_id)
```

The deposit/event identifier must be produced by the verified chain adapter, not copied from caller-controlled request data. The ledger atomically consumes that deposit identifier. The output index is the canonical index inside the issuance output list; the same index cannot identify two outputs. The private entropy is hidden witness material and is **not** itself the uniqueness argument.

A reference helper was added as `derive_issuance_output_identity_candidate` in `src/protocol/output_identity.py`. It fixes candidate widths and encoding, and has a hardcoded known-answer test. This helper does not verify a deposit or enforce a ZK constraint.

### Transfer output

For a transfer output, the anchor is the exact public nullifier of the canonical input note being spent. The same hidden `(namespace_id, coin_id, r_nf)` used to open the input commitment must compute that nullifier. The transfer relation constrains:

```text
(coin_id_out, r_nf_out) =
  DeriveTransferIdentityV1(namespace_id, input_spend_identity,
                           input_nullifier, canonical_tx_entropy,
                           canonical_output_index, spend_key_witness,
                           params_id)
```

The current CHp4.6 helper is the transfer reference candidate. The canonical output index is the zero-based index in the *complete canonical transaction output list*, never a recipient-local index or a prover-selected alias. Output indices must be unique and part of the transaction encoding bound by the proof. The current candidate uses uint16 indices, so it supports at most 65,536 slots per list; changing that limit requires a new derivation version, not silent truncation.

Because a spent nullifier can be accepted only once, two accepted transactions cannot reuse the same transfer anchor. Within one transaction, distinct output indices give distinct encoded derivation inputs. If an implementation supports multiple input notes or multiple output sections, it must define one canonical anchor-selection rule and a single global output-index space before circuit construction. The current public `SpendStatement` has one input nullifier; no multi-input semantics are inferred here.

### Domain separation and commitment binding

Issuance and transfer use separate identity-derivation domains. For each path, coin_id and r_nf use separate domain labels. The encoding includes the version, namespace, parameter ID, canonical anchor, and canonical output index with the candidate field widths. The private entropy/witness is part of the preimage so the identity is not publicly computable from the anchor alone.

`rho_C`, recipient public key and value are **not** uniqueness anchors. They remain bound to the output commitment by the existing frozen V2 commitment relation. The proof must require that the exact derived tuple is used in that same commitment opening. A second commitment made by changing `rho_C` must not be accepted as a second output using an arbitrary repeated tuple.

## 4. Conditional uniqueness argument

Assume all of the following are enforced:

1. The verified ledger provides canonical, namespace-scoped issuance anchors and atomically rejects deposit/event replay.
2. The ledger rejects repeated input nullifiers atomically and across reorg/recovery boundaries.
3. Every output is assigned exactly one canonical output index, and duplicate indices or duplicate output entries are rejected.
4. The issuance/spend proof constrains the exact identity derivation, its anchor, its index, and the corresponding V2 commitment opening.
5. The two domain-separated derivation functions and V2 nullifier are collision resistant under the selected threat model.

Then two accepted outputs can share the complete SpendIdentity only if one of the enforced source/index rules was bypassed or the joint identity derivation collides. Reusing the same source anchor and slot in another accepted state transition is prohibited by the ledger; using another slot changes the encoded input. A repeated commitment salt is irrelevant to this identity argument.

This is a **computational** uniqueness argument, not mathematical injectivity. Domain separation and distinct indices do not prove that finite hashes cannot collide. A sender may choose entropy adversarially, so security cannot rely on entropy uniqueness or honesty. The unique source anchor and canonical slot prevent direct reuse; the hash assumptions bound collisions among different derivation inputs.

The full 32-byte coin_id has a generic classical birthday collision scale of about (2^{128}), and a generic quantum collision-search scale of about (2^{85}) queries under the Brassard–Høyer–Tapp model. That is why coin_id alone is explicitly **not** the uniqueness key. A 48-byte nullifier has generic random-function birthday scales of about (2^{192}) classically and (2^{128}) quantumly. Those are idealized bounds, not a proof of this construction or its composition. The complete two-output derivation needs its own review; do not silently transfer a bound from one output to another.

If two *different* spend identities nevertheless produce the same 48-byte nullifier, the ledger must reject the later spend. That rare hash-collision case can still render the later note unspendable; no finite nullifier hash eliminates this probability. Collision recovery/reissuance would require a separately specified protocol rule and cannot be improvised after a commitment is accepted.

## 5. Adversarial cases and required outcomes

| Case | Required behavior |
|---|---|
| Same complete SpendIdentity, different `rho_C` | Only one output identity may be derived for its accepted anchor/slot. An unconstrained tuple substitution must fail proof verification. |
| Same anchor, different canonical output indices | Derivation preimages differ; the resulting pair is computationally distinct except for a joint hash collision. |
| Same anchor and same index in a second transaction | Reject the second transition through consumed-deposit or spent-nullifier state. |
| Two distinct deposit IDs or input nullifiers | Distinct anchors yield distinct preimages; tuple collisions remain a cryptographic probability, not a logical impossibility. |
| Same coin_id but different r_nf | Different SpendIdentity values; allowed by the adopted policy unless the resulting public nullifiers collide. coin_id alone is not a uniqueness key. |
| Same complete tuple created intentionally by a malicious sender | The proof must reject arbitrary tuple selection; output generation must be anchored and index-bound. |
| Repeated public nullifier | Ledger consensus rejects it atomically, including concurrent transactions and canonical reorg/recovery handling. |
| Malformed deposit ID, entropy, index or field length | Reject before proof construction/verification; encodings are canonical and bounded. |
| Intentional references to the same note | Reuse the existing commitment and identity; do not register a second note commitment pretending to be a fresh output. |

The ledger cannot inspect or globally compare hidden identity tuples directly without additional leakage. The adopted design does not claim such plaintext inspection; it prevents arbitrary tuple selection in the proof relation and relies on reviewed computational collision bounds.

## 6. Exact proof-system contract

For each issuance output, the real proof must establish all of:

- the authenticated namespace, canonical deposit/event ID, finalized anchor and authorized value;
- `C = CommitV2(params_id, canonical_pk, authorized_value, namespace_id, coin_id, r_nf, rho_C)`;
- `(coin_id, r_nf) = DeriveIssuanceIdentityV1(...)` for the same output index;
- the canonical issuance output list binds every commitment to exactly one index;
- the proof and ledger state transition consume the deposit/event ID once.

For each transfer output, the real proof must establish all of:

- membership and opening of the exact input commitment;
- the same input `coin_id` and `r_nf` are used in both the opening and `NullifierV2`;
- each output identity is derived from that exact input identity/nullifier, canonical transaction context, output index and parameter ID;
- each output commitment opens with exactly that derived tuple, output recipient, value and independent salt;
- output values plus fee satisfy the transfer's value-conservation/range rules;
- the transaction digest is recomputed from the canonical encoded fields and commits to the output list, entropy and ordering.

The ledger must atomically append output commitments and consume the input nullifier/deposit anchor. A lock-protected in-memory Python model does not meet durable consensus, reorg or crash-recovery requirements.

### Mandatory negative proof tests

A real prover/verifier integration must reject, with the same public statement where applicable:

- a substituted output coin_id or r_nf;
- a repeated complete identity with a different commitment salt;
- a mismatched output index or transaction entropy;
- a mismatched namespace or params_id;
- an identity derived from a different input nullifier/deposit ID;
- duplicate output indices or an output omitted from identity constraints;
- altered recipient/value/commitment openings;
- duplicated deposit anchors, duplicated spend nullifiers, stale roots and racing commits.

Tests of Python equality predicates are not substitutes for these negative proof tests. The repository currently has no instantiated ZK backend, so those tests cannot yet run.

## 7. Research and source basis

The construction follows the *architecture* of established faerie-gold defenses, not their exact cryptographic formulas:

1. **Zcash Orchard Book, Nullifiers** — explains that output `rho` must be unique and derives it from a unique spent-note nullifier in its one-spend/one-output action model: <https://zcash.github.io/orchard/design/nullifiers.html>.
2. **ZIP 227, Computation of rho for issuance notes** — derives issued-note `rho` from a unique input nullifier plus canonical action/note indices using a domain-separated PRF: <https://zips.z.cash/zip-0227>.
3. **Zcash ZIP issue #955** — documents a spendability attack caused by potentially duplicate `rho` values for issued notes and explains why the issuance uniqueness anchor has to be enforced by consensus: <https://github.com/zcash/zips/issues/955>.
4. **Orchard circuit implementation** — checks that output-note `rho` equals the old nullifier and constrains the output commitment in the circuit: <https://github.com/zcash/orchard/blob/main/src/circuit.rs>.
5. **Zerocash formal Quint specification** — models the faerie-gold attack and the Sapling-style fix side by side; its symbolic injective encoding is a model abstraction, not a real hash collision proof: <https://github.com/informalsystems/Zerocash-spec>.
6. **Zerocash paper (Ben-Sasson et al., IEEE S&P 2014)** — foundational anonymous-payment construction and security model: <https://eprint.iacr.org/2014/349.pdf>.
7. **Brassard, Høyer and Tapp, Quantum Algorithm for the Collision Problem** — generic quantum collision-finding scale used for the caveat above: <https://arxiv.org/abs/quant-ph/9705002>.
8. **NIST FIPS 202** — normative SHA-3/SHAKE definitions; it does not by itself prove this protocol's derivation or composition: <https://csrc.nist.gov/pubs/fips/202/final>.

Do not copy Orchard's Pallas/Poseidon relation or its public `rho` model into 0PSp. This protocol has different frozen SHAKE256 V2 primitives, identity visibility goals, output arity and proof-system requirements.

## 8. Decision status and remaining boundary

**Resolved at design-policy level:** standalone global uniqueness of `coin_id` is not a required invariant; the spend identity is the complete tuple, and every accepted issuance/transfer output must derive that tuple from a one-use source anchor and canonical output slot. V2 commitment/nullifier formulas are unchanged.

**Not yet enforced:** the repository still lacks a real issuance/spend proof backend that can constrain this relation. Until it exists and passes the negative proof tests above, the implementation must not claim protocol-level uniqueness, recipient safety, privacy, or production readiness. That is an implementation/release blocker, not permission to keep the identity policy ambiguous.

Production remains **NO-GO**.
