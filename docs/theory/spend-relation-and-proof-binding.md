# 0PSP Spend Relation — Current Candidate Statement

**Status:** Formal relation target; no composed proof has been implemented or proven secure.

## Public statement

\[
x_{\mathrm{pub}}=(R_C,\nu,B,M,\mathsf{state})
\]

- \(R_C=\{C_1,\ldots,C_N\}\): public set of eligible coin commitments.
- \(\nu\in\{0,1\}^{384}\): public nullifier.
- \(B\): fresh per-spend bridge commitment to the nullifier input.
- \(M\): transaction digest binding chain ID, transaction version, inputs/outputs, fees, \(\nu\), and \(B\).
- \(\mathsf{state}\): current accepted state/root, eligible-set context, and spent-nullifier state.

Neither \(j\) nor the selected \(C_j\) is a separate public argument. Each \(C_i\) is already visible as a member of \(R_C\); privacy means hiding **which member is selected**, not hiding the entire public set.

## Hidden witness

\[
w=(j,C_j,pk_j,v,coin\_id,r_{\mathrm{nf}},\rho,\tau_B,\mathsf{auth})
\]

The same hidden \(j\), \(pk_j\), commitment opening, coin identity and nullifier secret must connect every predicate.

## Required predicates

1. **Selection:** \(j\in[N]\) and \(C_j=R_C[j]\), without revealing \(j\).
2. **Coin opening:** \(C_j=\operatorname{Com}_{\mathrm{coin}}(pk_j,v,coin\_id,r_{\mathrm{nf}};\rho)\).
3. **Bridge opening:** \(B=\operatorname{Com}_{\mathrm{bridge}}(\operatorname{Encode}(\mathsf{version},coin\_id,r_{\mathrm{nf}});\tau_B)\).
4. **Nullifier:** \(\nu=\operatorname{SHAKE256}_{384}(\mathsf{domain}_{\mathrm{null}}\parallel\mathsf{version}\parallel\operatorname{Encode}(coin\_id)\parallel r_{\mathrm{nf}})\).
5. **Authorization:** \(\mathsf{AuthVerify}(pk_j,M,\mathsf{auth})=1\), where AuthVerify is an actually specified \(t\)-of-\(n\) protocol and \(pk_j\) is the same key bound into \(C_j\).
6. **State:** the coin is a valid, unspent asset under the selected ledger state; the transaction conserves value and satisfies protocol rules.

The domain tag and encoding version are fixed public constants; every variable-length encoding must have an unambiguous length encoding. The nullifier secret is distinct from the coin commitment randomness and must be fixed by the committed coin data.

## Composition requirement

The two proofs cannot merely be individually valid: they must reference the exact same \(B\), protocol version and public transaction digest. A concrete commitment with proved hiding/binding and a complete proof relation in both layers is necessary. The current formula \(A_1m_x+A_2\tau_B\bmod q\) is not an instantiated secure commitment.

## Security properties to prove

- **Spend soundness:** theft or invalid authorization implies a proof soundness/extractability failure, commitment failure, or threshold-authentication forgery under the concrete scheme assumptions.
- **Double-spend resistance:** two accepted spends of one committed coin use the same committed nullifier input and therefore the same deterministic \(\nu\); the ledger atomically rejects the repeat.
- **Collision safety:** distinct coins colliding under the nullifier function is a separate hash-security event.
- **Unlinkability:** the selected member cannot be distinguished in the stated game, accounting for commitment hiding, both proofs' full zero knowledge, public transaction leakage, and the precise QROM/hash assumption.

No reduction is claimed complete until the concrete schemes and adversary model are fixed.
