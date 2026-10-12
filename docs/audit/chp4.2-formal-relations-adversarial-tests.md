# CHp4.2 — Formal Relations and Adversarial Reference Tests

**Decision:** preserve the V2 byte contracts, formalize their use in R_mint/R_spend, add executable tests over current primitives, and keep protocol release **NO-GO**.

## Deliverables

1. **Canonical V2 preservation.** No changes to the native/Python commitment or nullifier preimages, function signatures, parameter bytes or known-answer vectors.
2. **Formal relation target.** RFC-02 defines a public statement, private witness, exact current V2 commitment/nullifier equations and a conjunction of predicates. Unspecified Merkle and transaction encodings remain explicit blockers rather than fabricated implementation details.
3. **Issuance relation.** RFC-01 defines public deposit-authorized value binding to the hidden commitment opening and the separate atomic deposit replay rule.
4. **Adversarial reference tests.** Tests mutate the value, namespace, coin ID and nullifier secret using the real Python V2 reference primitives and exercise duplicate-deposit rejection in the existing in-memory state model.

## Exact equations

The two byte-level equations are in RFC-02, Section 2. Commitment V2 retains value inside the commitment; Nullifier V2 remains a 48-byte SHAKE256 output over namespace, coin_id and r_nf. No nk or pos was added.

## Critical limitation discovered

The stated coin identity is (namespace_id, coin_id), but coin_id must remain hidden from the issuer. Reusing the same coin_id with a different r_nf or salt yields another candidate opening, commitment and nullifier. A mint that never sees coin_id cannot directly reject duplicate hidden IDs using a raw equality check.

The current MintRegistryModel can deduplicate raw IDs only because it receives them in plaintext. It must not be mistaken for a component of the intended issuer-private flow. A privacy-preserving hidden-ID uniqueness proof/registry or a separately reviewed change to the identity invariant is still needed. No format change is made in CHp4.2.

## Why two requested tests are not fabricated

- **Merkle path/index tamper:** blocked until the canonical tree hash, path encoding, leaf/node domains and index encoding are specified. Implementing an arbitrary tree now would silently choose protocol semantics.
- **Deposit reorg:** blocked until a real chain adapter, finality policy and rollback/recovery state machine exist. The in-memory model can test repeat consumption, not simulate consensus reorganization safely.
- **Transaction digest/output tamper:** blocked until the canonical transaction schema and digest encoding are frozen.
- **Privacy-preserving duplicate hidden coin ID:** blocked by the open issue above.

The tests are finite reference regressions, not a collision proof, ZK proof, durable-ledger guarantee, reorg simulation or unlinkability game. Test names use “witness substitution” rather than “unlinkability”: changing an input and observing a different hash is not a privacy proof.

## Validation target

Run the full existing GitHub Actions workflow after adding the tests. Release remains **NO-GO** until the proof backend, canonical tree/transaction suite, privacy-preserving coin-ID uniqueness, durable ledger, real chain adapter, finality/reorg behavior and independent review are complete.
