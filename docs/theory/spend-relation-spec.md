# 0PSP Spend Relation Specification — RFC-02

**Status:** formal design draft; no ZK backend instantiated; no theorem claimed.  
**Production:** **NO-GO**.  
**This file is the current source of truth for the candidate relation.** Older spend-relation documents describe an earlier target and must be read with the status note added to them.

## 1. Design principles

The protocol must use one proof statement and one consistent hidden witness for membership, commitment opening, nullifier derivation, transaction semantics, and whichever authorization policy the protocol actually requires. Separate passing component checks do not prove cross-component consistency.

No C function-pointer interface is frozen by this RFC. An interface may follow only after the mathematical relation, public policy and authorization semantics are approved.

## 2. Canonical public statement

The candidate public statement is:

```text
x = (version, params_id, namespace_id, commitment_root,
     public_nullifier, transaction_fields, transaction_digest,
     ledger_state, authorization_policy)
```

- `version`: protocol and encoding version; no silent V1/V2 fallback.
- `params_id`: frozen primitive/proof/signature parameter suite.
- `namespace_id`: the 48-byte V2 namespace identifier.
- `commitment_root`: authenticated root of the eligible coin set; exact tree construction and path encoding must be specified.
- `public_nullifier`: the 48-byte V2 nullifier for the selected coin.
- `transaction_fields`: canonical public inputs that affect recipient/output commitments, input references, fee, value conservation and policy.
- `transaction_digest`: computed from the canonical version, namespace, nullifier, transaction fields and required ledger context. It must not be an unchecked caller-supplied label.
- `ledger_state`: the authenticated state/anchor against which membership and eligibility are evaluated.
- `authorization_policy`: selects the policy-defined mode and any public committee/key identifiers; it may not be silently downgraded by the prover.

Exact serialization, amount representation, tree/hash function, transaction fields, and state-transition rules remain parameterization tasks.

## 3. Hidden witness

```text
w = (j, C_j, pk_j, value, coin_id, r_nf, rho_C,
     membership_path, key_relation_witness,
     authorization_witness)
```

Where:

- `j` is the hidden member index if the selected anonymity construction hides it.
- `C_j` is the selected registered commitment.
- `pk_j` is the canonical scheme-specific public key bound in that commitment.
- `value`, `coin_id`, `r_nf`, and `rho_C` are the exact commitment opening.
- `membership_path` proves `C_j` belongs to the public authenticated root under the frozen tree relation.
- `key_relation_witness` contains whatever scheme-specific witness is needed to express key-generation/ownership consistently; do not assume a generic string preimage.
- `authorization_witness` is mode-specific.

## 4. Common relation predicates

An accepting proof must establish all common predicates:

1. **Canonical statement:** reject noncanonical encodings, invalid values, inconsistent versions, unknown parameter IDs and malformed state roots.
2. **Membership:** the selected `C_j` is a valid member of `commitment_root`; the hidden index/path and leaf refer to that same commitment.
3. **Commitment opening:** recompute the V2 commitment using the exact `namespace_id`, scheme-canonical `pk_j`, value, `coin_id`, `r_nf`, `rho_C`, and `params_id`. The result must equal `C_j`.
4. **Nullifier consistency:** recompute V2 nullifier from the same public namespace, `coin_id`, and `r_nf`; it must equal `public_nullifier`.
5. **Transaction binding:** constrain all fields that define the transaction, value conservation, fees, recipients/outputs and policy. Recompute or constrain `transaction_digest` to the canonical transaction fields. Adding the digest as an unused public input is not sufficient.
6. **State/policy eligibility:** the coin satisfies the rules of the authenticated state and spend policy. Membership proof alone does not prove unspent status; the ledger must reject duplicate public nullifiers atomically.
7. **Privacy:** the proof/transcript reveals no more than the explicitly allowed leakage. Repeated spends of the same coin are intentionally linkable by nullifier equality; distinct-coin unlinkability is a separate game.
8. **Authorization:** satisfy exactly the selected authorization policy below, with key/coin/transaction binding.

This relation is a design target. None of these eight predicates has yet been proved together by an instantiated 0PSP ZK backend.

## 5. Authorization modes: unresolved design choice

### Mode A — committee/threshold-signature authorization

Witness includes the committee signature `sigma_th`. The relation must establish:

```text
Verify_ChosenThresholdScheme(pk_j, transaction_digest, sigma_th) = 1
```

The exact scheme, parameters, public-key codec, key-generation model, threshold policy and signature encoding must be pinned. The verification must use the very same `pk_j` committed by `C_j`, and it must authenticate the exact canonical transaction digest.

If committee approval is a protocol requirement, this authorization predicate cannot be dropped merely to reduce circuit cost. Verifying a lattice signature inside the selected proof system may be expensive; its actual cost is unknown until the exact circuit/backend is implemented and measured.

### Mode B — self-spend key-knowledge authorization

A candidate relation proves that the wallet knows a scheme-specific secret-key witness related to `pk_j`, while the same proof constrains the exact transaction fields and state transition being authorized.

The key relation must be defined for the chosen scheme, for example as a relation over valid key-generation/secret-key encodings. It is **not** a generic assertion that an arbitrary byte string is a preimage of `pk_j`.

A bare `PoK(sk)` with no transaction relation is insufficient: if the public transaction fields or digest are not constrained by the proof relation, a proof may be replayed or detached from the transaction it is supposed to authorize. The proof statement must bind the canonical transaction fields and policy. Fiat–Shamir transcript binding is not a substitute for omitting the fields from the relation.

This mode does not replace a committee requirement when the protocol policy requires independent committee approval. It is only a candidate for a policy whose authorization semantics are genuinely self-spend key possession.

### Decision rule

Do not select Mode A or Mode B for implementation based only on expected constraint cost. First freeze the protocol policy and adversary model. Then compare:
- what authorization each mode actually guarantees;
- whether issuer/committee parties are allowed to learn the coin key or spend metadata;
- key/transaction binding and replay behavior;
- post-quantum security assumptions and proof-system compatibility;
- circuit/trace cost once measured against the chosen backend;
- malicious-party and availability properties.

## 6. Issuance and ledger relations are outside the spend proof's automatic scope

A spend proof cannot repair a mint protocol that registers an arbitrary `(C, v)` pair without proving that `C` opens to that exact value. RFC-01 defines the missing issuance relation.

The ledger, outside the ZK relation, must:
- verify authenticated issuance/receipt state;
- reject duplicate deposit consumption;
- atomically check that a public nullifier has not already been spent;
- commit the state transition so concurrent spends cannot both succeed;
- specify finality, fork/reorg, rollback and recovery behavior.

Do not claim consensus-level double-spend safety from an in-memory test model.

## 7. Required security statements

A future paper must separately define and prove, under pinned assumptions and concrete parameters:

- completeness and knowledge soundness/extractability of the selected proof;
- zero knowledge and the exact leakage permitted by public inputs;
- commitment binding and hiding, including QROM treatment for quantum adversaries;
- authorization unforgeability or key-knowledge semantics, depending on policy;
- same-witness binding across membership, commitment, nullifier and transaction fields;
- issuance correctness and value/deposit binding;
- nullifier uniqueness for a valid coin and ledger-level replay prevention;
- distinct-coin unlinkability under explicit issuer, observer and trustee corruption models;
- composed quantum-security loss and the assumptions behind every subargument.

Listing assumptions is not a composition theorem. No proof backend, formal reduction or independent review has completed these obligations.

## 8. Negative-test matrix before backend integration

| Mutation | Expected result |
|---|---|
| Change namespace in only one predicate | Reject |
| Change `coin_id` or `r_nf` while retaining `C_j` | Reject |
| Change `value` while retaining `C_j` and issuance-record value | Reject |
| Use a different `pk` for authorization than the committed key | Reject |
| Change outputs/fee/recipient but retain old transaction digest/proof | Reject |
| Supply an invalid, replayed or wrong-policy authorization witness | Reject |
| Use stale/wrong commitment root or ineligible state | Reject |
| Submit the same nullifier twice | Ledger admits at most one atomic transition |
| Submit same deposit twice | Ledger admits at most one issuance transition |
| Use unversioned/legacy nullifier as V2 | Reject |

The tests for the current hash primitives cover only opening recomputation and deterministic nullifier behavior. CHp4.1 adds an in-memory reference transition model with injected test doubles; its replay/concurrency tests are not end-to-end negative proof tests and do not establish durable ledger safety. End-to-end negative proof and durable-ledger tests remain blocked until those components exist; they must not be replaced with fake/mock “security proof” tests.

## 9. Implementation status

Implemented: component hash/encoding functions and native/reference known-answer tests.  
Not implemented: cryptographic issuance verifier/relation backend, instantiated spend proof relation/backend, selected authorization policy/adapter, durable ledger, and composed proof. The CHp4.1 in-memory reference transition model is not a production ledger.

**Decision: specification work may continue; production implementation remains NO-GO.**
