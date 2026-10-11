# 0PSP Spend Relation — Active Single-Proof Target

**Status: Formal target relation. No end-to-end proof or complete reduction exists.**

## Public statement

\[
x_{\mathrm{pub}}=(R_C,\nu,M,\mathsf{state},\mathsf{params\_id})
\]

\(R_C=\{C_1,\ldots,C_N\}\) is the public eligible commitment set; \(\nu\in\{0,1\}^{384}\) is the public nullifier; \(M\) binds version, chain ID, inputs, outputs, fees and \(\nu\); state identifies the ledger snapshot; params_id pins cryptographic parameters and encodings.

The set is public, but the selected index \(j\) and selected opening are not public arguments. Privacy means hiding which member was selected in the complete transcript, subject to permitted leakage.

## Hidden witness

\[
w=(j,C_j,pk_j,v,\mathsf{coin\_id},r_{\mathrm{nf}},\rho_C,\sigma_{\mathrm{th}})
\]

\(r_{\mathrm{nf}}\) is a dedicated 36-byte per-coin secret. \(\rho_C\) is independent commitment randomness. The threshold signature remains a hidden witness.

## Required predicates

1. **Membership:** \(j\in[N]\) and \(C_j=R_C[j]\).
2. **Coin commitment:** \(C_j=\operatorname{SHAKE256}_{384}(D_C\parallel\operatorname{Encode}(\mathsf{version},\mathsf{params\_id},pk_j,v,\mathsf{coin\_id},r_{\mathrm{nf}},\rho_C))\).
3. **Threshold authorization:** the concrete threshold signature verifies under the same \(pk_j\) bound into \(C_j\) on transaction digest \(M\).
4. **Nullifier:** \(\nu=\operatorname{SHAKE256}_{384}(D_N\parallel\mathsf{version}\parallel\operatorname{LenEncode}(\mathsf{coin\_id})\parallel\mathsf{coin\_id}\parallel\operatorname{LenEncode}(r_{\mathrm{nf}})\parallel r_{\mathrm{nf}})\).
5. **State and transaction:** the selected coin is valid and unspent; state is current; outputs/fees satisfy policy and value-conservation rules; the ledger records \(\nu\) atomically.

The encoding and public-key serialization must be canonical and versioned. The public transcript must not expose \(j\), the selected opening or the threshold signature if doing so identifies the selected member.

## Security targets (not established results)

- **Spend soundness:** acceptance without a valid witness implies a failure of the concrete proof system, commitment, or threshold-authentication property.
- **Double-spend resistance:** commitment binding and proof soundness fix the nullifier input; deterministic derivation fixes \(\nu\) per coin, and the ledger rejects repeats.
- **Collision safety:** two distinct valid coins yielding the same nullifier is a separate collision event.
- **Unlinkability:** must be proved in a left/right game over the full transcript, including amounts, timing, state, signature/proof messages, corruption and permitted leakage.
- **Quantum security:** reductions must match the actual hash model, threshold scheme, proof system and parameters; naming MLWE/MSIS or a QROM lemma is insufficient.

## Architecture decision

The old two-proof relation with public bridge commitment \(B\) is historical. V0 targets one proof over this relation; the bridge value and separate Layer 2 proof are not in the active path. This is a constructionability decision, not an impossibility theorem for hybrid proofs.

## Evidence status

Current code supplies functional hash/opening helpers and an in-memory replay model. It does not implement the relation or an anonymous proof. All previous 60–120 KiB combined proof figures are unverified projections, not measurements.

## Sources

- Ringtail: https://eprint.iacr.org/2024/1113
- Experimental PQ SoK/LRS scaffold: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature
- NIST FIPS 202: https://csrc.nist.gov/pubs/fips/202/final
- LoTRS comparator: https://eprint.iacr.org/2026/974 and https://zenodo.org/records/22807126
