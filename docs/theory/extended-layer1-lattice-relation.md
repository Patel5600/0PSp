# Extended Layer 1 Lattice Relation — Candidate, Not Instantiated

**Status:** Algebraic design target. No working LoTRS extension or formal security proof currently exists in this repository.

## 1. Modulus separation

LoTRS v2 uses:
- main ring modulus \(q=2^{43}-67\);
- binary-proof modulus \(\hat q=2^{35}-451\);
- degree \(n=256\).

The two moduli play distinct roles in the construction. The existing 0PSP Python RingElem/ModuleMatrix code instead uses \(q=8{,}380{,}417\) from ML-DSA-like parameters. It must not be represented as the LoTRS ring implementation.

Source: https://github.com/lotrs-sig/lotrs/blob/main/lotrs-py/params.py

## 2. Desired hidden relation

Public statement (illustrative):

\[
x_{\mathrm{pub}}=(R_C,\nu,B,M,\mathsf{state})
\]

Witness:

\[
w=(j,C_j,pk_j,v,coin\_id,r_{\mathrm{nf}},\rho,\tau_B,\mathsf{auth})
\]

Required predicates:
1. \(j\in[N]\) and \(C_j=R_C[j]\), with \(j\) hidden.
2. \(C_j=\operatorname{Com}_{\mathrm{coin}}(pk_j,v,coin\_id,r_{\mathrm{nf}};\rho)\).
3. \(B=\operatorname{Com}_{\mathrm{bridge}}(\operatorname{Encode}(\mathsf{version},coin\_id,r_{\mathrm{nf}});\tau_B)\).
4. \(\nu=\operatorname{SHAKE256}_{384}(\mathsf{domain}\parallel\mathsf{version}\parallel coin\_id\parallel r_{\mathrm{nf}})\).
5. The same hidden \(pk_j\) is authorized for \(M\) by the defined \(t\)-of-\(n\) custody protocol.

The current equations are relation requirements, not a demonstrated lattice Sigma protocol. Existing LoTRS's row/column structure is not automatically a general-purpose \(t\)-of-\(n\) wallet protocol.

## 3. Commitment-opening caveat

The earlier proposed coin commitment combined \(pk_j\), value, encoded nullifier input, and short randomness. Its claimed Module-SIS reduction assumed a short difference for \(pk_j-pk'_j\). The coefficients of a public key \(t=A s+e\bmod q\) are not automatically bounded by the norm of \(s\). Consequently that reduction is not established.

The bridge equation \(B=A_1m_x+A_2\tau_B\bmod q\) also does not, by itself, prove hiding. A concrete commitment scheme, parameter distribution, binding reduction, hiding argument, full norm accounting, and independent estimator output must be supplied before it can be used in a security theorem.

## 4. Response expansion

The previously reported +6.75 KiB / +7.88 KiB figures assume an encoding and response width extrapolated from the LoTRS artifact. They are estimates only. A valid size claim requires the extended protocol's real response distributions, rejection sampling, packing format, and exact serialization. Do not add these estimates to the upstream LoTRS signature as if they were measured.

## 5. Gate for Layer 1

The Layer 1 research gate is satisfied only after:
- an actual relation proof binds the hidden coin, wallet key, bridge commitment and transaction context;
- custody threshold semantics are defined independently from anonymity size;
- every shortness bound is proved for the concrete sampler and representatives;
- proof soundness/zero-knowledge definitions and reductions match the implemented protocol;
- selected LoTRS and bridge parameter sets are evaluated with reproducible estimators.
