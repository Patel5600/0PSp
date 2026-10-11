# Bridge Commitment Instantiation — Open Research Gate

> **HISTORICAL / NOT ACTIVE V0:** no secure commitment was instantiated for the retired bridge architecture. This candidate is not proof evidence. See [Constructionable V0](constructionable-v0.md).

**Status:** No secure commitment instantiation selected. The algebraic formula below is a candidate, not a proved commitment.

## 1. Required interface

For hidden nullifier input \(x=\operatorname{Encode}(\mathsf{version},coin\_id,r_{\mathrm{nf}})\), Layer 1 and Layer 2 need to reference a public, fresh bridge value:

\[
B=\operatorname{Com}_{\mathrm{bridge}}(x;\tau_B).
\]

A sound composition requires both proofs to establish opening of the same \(B\), under byte-for-byte identical parameters and encoding. At minimum, the candidate must have:
- computational binding under an explicitly defined post-quantum assumption;
- hiding appropriate to the unlinkability theorem;
- a concrete sampler and canonical encoding;
- an opening relation efficient to prove in each layer;
- quantified security and statistical error;
- a concrete parameter set and independent estimator run.

## 2. Candidate currently present in the notes

\[
B=A_1m_x+A_2\tau_B\pmod q.
\]

This formula is not yet accepted as a secure commitment. The earlier assertion that \(A_2\tau_B\) is indistinguishable from uniform under Module-LWE omitted a specified LWE error term and did not give a reduction for the actual small-\(\tau_B\) distribution. The formula alone therefore establishes neither hiding nor statistical hiding.

The difference-vector outline for binding is conditional too. It needs the exact public matrix distribution, complete witness vector, coefficient representatives, a proved norm bound, and a concrete Module-SIS parameter estimate. The current security-budget script's root-Hermite/Core-SVP heuristic is not a proof of hardness.

## 3. Cross-field complication

Layer 1's candidate ring has a 43-bit modulus \(q=2^{43}-67\), while a proposed BabyBear STARK uses a roughly 31-bit field. Equality modulo \(q\) cannot be tested simply by a congruence in BabyBear. A limb/carry construction must prove canonical integer equality, including every limb range, signed representative, carry, quotient bound and terminal condition. That AIR has not been compiled or independently checked.

## 4. Research options, not decisions

Investigate and compare:
1. A well-defined lattice commitment with explicit hiding and binding reductions and a practical relation proof in both layers.
2. A different bridge that can be verified efficiently in both proof systems, with post-quantum security analyzed independently.
3. Abandoning the two-layer architecture if no compact, sound cross-layer relation can be obtained.

Do not describe the algebraic candidate as “adopted”, “secure”, “Module-LWE hiding”, or “Module-SIS binding” until the associated proofs exist.
