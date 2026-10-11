# Nullifier-Bound Spend Soundness — Active V0 Target

**Status: Formal target definition. No end-to-end security reduction is complete.**

## Goal

Authorization, hidden coin membership, commitment opening and nullifier correctness must refer to the same asset. Separate proofs without a shared witness relation can allow attempted substitution of a coin ID, key, nullifier, or signature.

## Public statement and witness

\[
\mathsf{Public}=(R_C,\nu,M,\mathsf{state},\mathsf{params\_id})
\]
\[
w=(j,C_j,pk_j,v,\mathsf{coin\_id},r_{\mathrm{nf}},\rho_C,\sigma_{\mathrm{th}})
\]

The selected member is \(C_j=R_C[j]\). The verifier sees the public anonymity set but must not learn which element was selected from the full transcript, beyond explicitly permitted leakage.

## Active single-proof relation

The one proof must establish:
1. hidden selected-commitment membership;
2. the canonical coin-commitment opening using the same key, value, coin ID, nullifier secret and commitment salt;
3. validity of the concrete threshold signature under that same key on \(M\);
4. correct derivation of public \(\nu\) from the same committed coin ID and nullifier secret;
5. coin eligibility, value conservation and state validity.

The previous bridge commitment and separate Layer 1/Layer 2 composition are retired from the active path. A single proof removes the cross-proof equality obligation; it does not solve the full proof-system problem.

## Required security experiments

### Spend soundness
An adversary wins if a spend is accepted without a witness satisfying the entire relation and wallet policy. The reduction must use the selected proof system's actual soundness/knowledge property, concrete threshold-signature security theorem, and commitment relation.

### Double-spend resistance
An adversary wins if the same committed coin is accepted twice with different nullifiers, or if an accepted nullifier is inconsistent with the committed witness. The argument needs commitment binding, proof soundness, minting uniqueness, correct state transitions, and atomic duplicate-nullifier rejection.

### Nullifier collision safety
Two distinct valid coins producing the same nullifier is a separate event that can cause false conflict. Analyze it under the chosen encoding and hash model. It does not establish authorization or anonymity.

### Unlinkability
Define a left/right game over the whole transaction and proof transcript. The challenger controls valid openings, amounts, state, allowed leaks and corrupted participants. A QROM argument must state the exact theorem, oracle interface, challenge input, query limit, and conditional entropy premise. Computational hiding alone does not establish a statistical conditional-min-entropy bound.

## Functional tests versus proof evidence

Current tests cover deterministic output, length checks, sample domain separation, functional opening recomputation and in-memory duplicate-nullifier behavior. They do not establish collision resistance, quantum security, commitment hiding/binding, proof extractability, zero knowledge or unlinkability.

## Sources and status

- Ringtail: https://eprint.iacr.org/2024/1113
- PQ SoK/LRS research scaffold: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature
- NIST FIPS 202: https://csrc.nist.gov/pubs/fips/202/final
- Prior-art comparison: ../related-work/nullifier-prior-art.md

Current status is candidate construction under falsification. The proof and all end-to-end security claims remain OPEN.
