# CHp4.1 — Issuance/Spend State-Transition Reference Model

**Decision:** add an executable reference model for replay and in-process atomicity tests. Keep the protocol release decision **NO-GO**.

## What this increment establishes

- The issuance API accepts deposit evidence, a commitment, a parameter identifier and a proof; it does **not** accept a caller-claimed value. An injected deposit adapter returns the authenticated value, deposit identity, namespace and finality anchor.
- The issuance-proof verifier receives that authorized value in the public statement. The actual verifier must prove that the V2 commitment opens to that exact value and satisfies the full RFC-01 issuance relation.
- One deposit identity cannot create more than one accepted issuance in the model. A commitment cannot be registered twice in the same namespace.
- The spend transition checks nullifier uniqueness and new-commitment uniqueness under one lock. Concurrent attempts for one nullifier or one deposit have at most one accepted transition in this model.
- Rejected proof calls do not mutate model state.

## Why this is not the production ledger

The module at src/protocol/reference_ledger.py deliberately requires externally injected deposit and proof verifiers. The tests use test doubles. The module does not implement SHAKE commitments, a zero-knowledge proof, a Merkle tree, a chain adapter, persistence, distributed consensus, finality tracking, crash recovery, fork/reorg behavior, or cross-process atomicity. It does not prove value-binding or spend soundness.

The model is single-process and stores state in memory. Its lock is a reference for the required linearization point, not a production database transaction. Real ledger implementation must enforce uniqueness with durable database constraints/transactions or the target chain's consensus state transition, and must define rollback/reorg semantics.

## V2 compatibility decision

This increment does not change any V2 primitive, byte encoding, commitment formula, nullifier formula, API, or known-answer vector. In particular:

- Keep the current V2 commitment preimage, including value.
- Keep the nullifier as SHAKE256-384 over the existing namespace, coin_id and r_nf fields; do not add nk or pos.
- Do not adopt a public-value ledger leaf that removes value from the commitment under the V2 identifier. That is a protocol-format change and would require a separately versioned design/review.
- Never infer coin-ID uniqueness from CSPRNG output alone. A trusted durable issuance state must reject duplicate deposit consumption and define the canonical identity/uniqueness policy it can actually observe.

## RFC-01 issuance gate

For public statement

~~~text
x_issue = (version, params_id, namespace_id, C, v_authorized,
           deposit_id, deposit_anchor, ledger_state)
~~~

and hidden witness

~~~text
w_issue = (canonical_pk, coin_id, r_nf, rho_C, private_ownership_witness?)
~~~

an eventual proof must establish at least:

~~~text
C = CommitV2(params_id, canonical_pk, v_authorized,
             namespace_id, coin_id, r_nf, rho_C)
DepositAuthorizes(deposit_id, namespace_id, v_authorized, deposit_anchor) = 1
PolicyAllowsIssue(x_issue, w_issue) = 1
~~~

The proof and deposit adapter must bind to the same canonical namespace, asset and value. Replay protection remains a state-transition rule, not a theorem supplied by the commitment hash. This relation is a target specification only; no proof backend is integrated here.

## RFC-02 spend gate

The selected spend proof must use one witness across:

1. membership of the exact registered V2 commitment;
2. exact V2 commitment opening with the same namespace, public key, value, coin_id, r_nf, rho_C and params_id;
3. exact V2 nullifier derivation from the same namespace, coin_id and r_nf;
4. canonical transaction digest and all transaction fields;
5. value conservation, fee/range rules and output commitments;
6. the policy-selected authorization relation and authenticated state anchor.

The ledger rejects repeated public nullifiers atomically. Repeated nullifier equality intentionally links repeated attempts for the same coin; it is not a proof of distinct-coin anonymity.

## Tests and interpretation

The test file tests/unit/test_reference_ledger_state_machine.py exercises accepted/rejected transitions, deposit replay, duplicate commitments, nullifier replay, proof-rejection non-mutation, and concurrent duplicate submissions. Verifier callbacks in these tests are stubs by design. Passing these tests establishes only the model's state-transition behavior. It does not validate any real ZK proof or cryptographic assumption.

## Remaining NO-GO items

- Select and pin the actual proof backend and security parameters.
- Implement/review issuance relation verification and demonstrate the V2 hidden-value/deposit binding.
- Implement the full RFC-02 relation over a single witness.
- Choose a policy-compatible authorization scheme; Shamir sharing alone is not threshold authorization, and FROST-style discrete-log signatures cannot be labelled post-quantum.
- Replace the reference lock/in-memory sets with a durable, transactional ledger and define consensus finality, replay, recovery and reorg behavior.
- Add end-to-end adversarial proof tests, concrete quantum-security analysis, full-path side-channel review and independent cryptographic audit.

**Release remains NO-GO.**
