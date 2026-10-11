# Nullifier-Bound Spend Soundness — Target Relation and Open Proof Obligations

**Status:** Formal target definition. No end-to-end security reduction is complete.

## 1. Threat being addressed

Authorization and coin-membership must be bound to the same hidden asset. If the protocol only proves membership and separately publishes a nullifier, an attacker may attempt to substitute a dummy nullifier, bind it to another coin ID, or exploit duplicate minting. If nullifier computation requires the full threshold secret, reconstructing that secret would defeat the custody policy.

## 2. Public statement and witness target

The candidate public statement is:

\[
\mathsf{Public}=(R_C,\nu,B,M,\mathsf{state})
\]

where \(R_C\) is the public set of eligible coin commitments, \(\nu\) is the 384-bit nullifier, \(B\) is a fresh per-spend bridge commitment, \(M\) binds the transaction context, and \(\mathsf{state}\) binds the relevant ledger state.

The hidden witness contains the selected index \(j\), selected commitment \(C_j\), wallet public key, coin value, coin ID, nullifier secret, coin opening, bridge opening, and threshold authorization. Neither the selected index nor an additional public copy of the selected commitment may leak which member was spent.

## 3. Relations that must hold simultaneously

1. **Membership:** \(j\in[N]\) and \(C_j=R_C[j]\).
2. **Coin opening:** \(C_j=\operatorname{Com}_{\mathrm{coin}}(pk_j,v,coin\_id,r_{\mathrm{nf}};\rho)\).
3. **Bridge opening:** \(B=\operatorname{Com}_{\mathrm{bridge}}(\operatorname{Encode}(\mathsf{version},coin\_id,r_{\mathrm{nf}});\tau_B)\).
4. **Nullifier derivation:** \(\nu=\operatorname{SHAKE256}_{384}(\mathsf{domain}\parallel\mathsf{version}\parallel\operatorname{Encode}(coin\_id)\parallel r_{\mathrm{nf}})\).
5. **Authorization:** the specified threshold authorization is valid for \(M\) under the same key \(pk_j\) bound in the coin commitment.
6. **State validity:** the coin is eligible and unspent, transaction outputs satisfy value-conservation rules, and consensus records the nullifier atomically.

The commitment and proof system for items 2 and 3 are not yet instantiated with demonstrated hiding/binding properties. A named Module-LWE or Module-SIS assumption does not automatically supply those properties.

## 4. Security games still required

### Spend soundness

An adversary wins by causing acceptance of a spend for which the extracted witness does not satisfy the full relation, including threshold authorization and eligible coin membership.

### Double-spend resistance

An adversary wins by obtaining acceptance for the same committed asset twice with distinct nullifiers. A proof must show the commitment fixes the nullifier input and deterministic derivation therefore fixes the nullifier; the ledger rejects reuse. This requires extraction/soundness, commitment binding, valid minting uniqueness, and state correctness.

### Nullifier collision safety

A separate event occurs if distinct legitimate assets yield the same nullifier, causing an accidental conflict. This is a hash/encoding security question and is not the mechanism that prevents a repeated spend of one asset.

### Unlinkability

A left-or-right game must include the full public transcript, ledger state, transaction timing, amounts, anonymity set, and corruption/quantum-query model. Computational hiding does not by itself prove a statistical conditional-min-entropy lower bound. Any QROM reduction must state and satisfy the exact theorem hypotheses.

## 5. What numerical checks can and cannot show

Functional scripts can test canonical encoding, deterministic output, domain separation, basic length handling, and arithmetic identities. They cannot establish collision resistance, zero knowledge, knowledge soundness, Module-LWE/Module-SIS hardness, or spend unlinkability.

## 6. Sources and status

- LoTRS: https://eprint.iacr.org/2026/974 and https://github.com/lotrs-sig/lotrs
- NIST SHAKE: https://csrc.nist.gov/pubs/fips/202/final
- NIST ML-DSA: https://csrc.nist.gov/pubs/fips/204/final
- Plonky3 backend caveats: https://github.com/Plonky3/Plonky3/blob/main/README.md

This document specifies the problem that must be solved. It does not state that 0PSP currently solves it.
