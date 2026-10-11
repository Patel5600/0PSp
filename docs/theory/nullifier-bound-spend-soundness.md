# Nullifier-Bound Spend Soundness — V2 Target

**Status: Component equation and test models exist. Full spend-soundness theorem remains OPEN.**

## Objective

Commitment opening, threshold authorization, namespace, coin ID and nullifier must all refer to the same hidden coin. Separate standalone checks do not guarantee witness consistency. The active design requires one proof relation with a shared witness.

## Public statement and witness

    Public = (namespace_id, R_C, nu, M, state, params_id)
    Witness = (j, C_j, pk_j, value, coin_id, r_nf, rho_C, sigma_th)

namespace_id is a 48-byte SHAKE256-384 digest of canonical 32-byte ledger, deployment and asset identifiers. coin_id is a fresh 32-byte opaque identifier. The full identity is (namespace_id, coin_id), and the mint ledger must atomically reject duplicate pairs.

## Active V2 relation

The same proof must establish:
1. C_j = R_C[j] for a hidden valid j.
2. The namespace-bound V2 commitment opens to pk_j, value, coin_id, r_nf and rho_C using canonical encodings.
3. The Ringtail threshold signature verifies under that same pk_j for transaction digest M.
4. nu equals the V2 nullifier equation over namespace_id, coin_id and r_nf.
5. The coin is eligible in the authenticated state, not already spent, and satisfies transaction/value/fee policy.
6. The proof reveals no more about j/opening/signature than allowed by the anonymity definition.

M binds the version, namespace, nullifier, inputs, outputs, fees and required ledger context. The ledger verifies the state and commits the nullifier atomically. V1 nullifiers are legacy only; no unversioned fallback is allowed.

## Required games and reductions

### Mint uniqueness and namespace separation
The chain adapter must canonically map ledger/deployment/asset identifiers. The mint state machine rejects duplicate (namespace_id, coin_id) pairs atomically. Namespace hash collisions are a separate cryptographic failure event. Local tests do not prove a durable ledger invariant.

### Spend soundness
An adversary wins by producing an accepted proof without a witness satisfying every predicate. The reduction must identify which assumption is broken: proof-system knowledge soundness, Ringtail unforgeability, commitment binding, canonical encoding, or ledger-state soundness. The current repository lacks the instantiated proof and therefore cannot complete this reduction.

### Double-spend resistance
An adversary wins if a single valid coin is accepted twice under distinct nullifiers or an accepted nullifier is inconsistent with its committed witness. The proof must tie nu to the exact opening, and the ledger must atomically prevent replay across concurrent transactions, forks/reorgs and state recovery. A thread-safe in-memory set is not sufficient evidence for consensus safety.

### Commitment hiding and unlinkability
A commitment-hiding theorem requires an explicit random-oracle model, a query bound and account of all visible data. For the quantum setting, a classical salt-guess estimate is not enough. Unlinkability must be phrased as a left/right game over the full transaction/proof transcript and must explicitly permit repeated nullifier equality for the same coin.

### Full quantum composition
The final theorem must state concrete parameters, query budgets, reduction loss, proof backend setup assumptions, hash/Fiat-Shamir model, Ringtail key-generation assumptions and which public leakage is permitted. It must combine these results rather than merely list them.

## Status

Implemented: V2 namespace and nullifier byte contracts, functional reference/native agreement vectors, namespace/coin substitution tests, commitment V2 helper, and a local mint-uniqueness model.

Open: durable mint/ledger adapter, formal commitment hiding theorem, Ringtail proof-relation integration, full post-quantum ZK argument, knowledge soundness, unlinkability reduction, consensus replay/reorg proof, independent review and full-path side-channel evidence.

See ../security/v2-protocol-security-argument.md for the normative byte contracts and security-game checklist.
