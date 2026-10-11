# 0PSP Spend Relation — Namespace-Bound V2 Target

**Status: Formal target relation, not an implemented or proven ZK protocol. Production: NO-GO.**

## Public statement

    x = (namespace_id, R_C, nu, M, state, params_id)

- namespace_id is a 48-byte V2 identifier derived from the canonical ledger, deployment and asset identifiers.
- R_C is the public eligible commitment set.
- nu is the 48-byte public V2 nullifier.
- M is the transaction digest, which binds the protocol version, namespace, nullifier, inputs, outputs, fees and required ledger context.
- state identifies the authenticated ledger snapshot/commitment root.
- params_id identifies the canonical parameter/encoding suite.

## Hidden witness

    w = (j, C_j, pk_j, value, coin_id, r_nf, rho_C, sigma_th)

Here j is the hidden selected member, coin_id is a 32-byte opaque per-namespace ID, r_nf is an independent 36-byte per-coin secret, rho_C is independent 36-byte commitment randomness, and sigma_th is the Ringtail threshold signature.

The complete coin identity is (namespace_id, coin_id). The durable mint ledger must atomically reject duplicate pairs. The current in-memory registry is not consensus code.

## Exact V2 predicates

1. **Membership:** j is in range and C_j = R_C[j].
2. **V2 commitment opening:** C_j is the SHAKE256-384 output for the exact namespace-bound commitment preimage specified in docs/security/v2-protocol-security-argument.md.
3. **Threshold authorization:** Verify_Ringtail(pk_j, M, sigma_th) = 1, using the same pk_j bound into C_j.
4. **V2 nullifier:** nu is the SHAKE256-384 output of the V2 domain/version, namespace_id, coin_id and r_nf encoding specified in the security argument.
5. **Eligibility and policy:** the coin belongs to the authenticated state, is eligible and unspent, and value, output, fee and policy rules hold.
6. **Privacy:** the transcript does not disclose j, the opening or signature beyond formally permitted leakage.

The verifier must not accept a proof in which the commitment uses one key and the threshold signature uses another, or in which the namespace in one predicate differs from the public namespace. The namespace is an explicit public statement input and is separately bound into both commitment and nullifier.

## Security targets, not proven results

- **Spend soundness:** accepted proof without a valid witness implies a break of the exact proof system or a predicate's underlying assumption.
- **Mint uniqueness:** no two accepted mint transitions register the same (namespace_id, coin_id).
- **Double-spend resistance:** the valid opening fixes nu, and durable ledger state atomically rejects repeats, including applicable fork/reorg cases.
- **Commitment binding:** distinct canonical openings with equal commitment output give a SHAKE256-384 collision, provided the canonical encoding is injective.
- **Commitment hiding:** needs a complete classical-RO or QROM game and concrete query-dependent bound. The 288-bit salt alone is not a proof.
- **Threshold authorization:** requires the actual Ringtail parameter/key-generation model and a proof that signature verification refers to the same hidden key.
- **Anonymity/unlinkability:** must allow intentional linkability of repeated nullifiers for the same coin, while proving the requested privacy for distinct coins under explicit leakage.
- **Quantum security:** must include the proof backend, signature scheme, SHAKE model, Fiat-Shamir/QROM treatment and concrete security loss.

## Implementation state

Implemented: namespace derivation, scoped coin-ID generation, a local duplicate-mint model, V2 nullifier reference/native implementations and vectors, V2 commitment helper and vectors, and a local V2 timing screen.

Open: live chain adapters and durable mint ledger, commitment hiding theorem, pinned Ringtail adapter, full single-relation proof, knowledge soundness/zero knowledge, composed security reduction, end-to-end benchmarks, independent review, and full-path side-channel review.

References:
- V2 byte contracts and games: ../security/v2-protocol-security-argument.md
- Construction target and gates: constructionable-v0.md
- Ringtail: https://eprint.iacr.org/2024/1113
- SmallWood: https://eprint.iacr.org/2025/1085
- SHAKE: https://csrc.nist.gov/pubs/fips/202/final
