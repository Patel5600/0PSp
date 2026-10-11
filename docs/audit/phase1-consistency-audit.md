# 0PSP Phase 1 Consistency Audit — CHP3

**Status: OPEN.** This audit supersedes earlier “final”, “closed”, or “all blockers resolved” descriptions in revisions 1–3. The repository contains useful design work and functional helpers, but not a fully instantiated secure primitive.

## Executive result

The source and mathematics review found several false inferences that must not be carried into security claims:

1. LoTRS uses distinct main and binary-proof moduli, while the current 0PSP ring code uses the ML-DSA modulus.
2. The candidate linear bridge expression has no established hiding theorem under the assumptions cited so far.
3. The proposed coin-commitment reduction treats public-key differences as short without demonstrating such a bound.
4. The QROM query/entropy arithmetic can be evaluated, but conditional min-entropy does not follow merely from computational hiding.
5. The proposed Layer 2 mixes Boolean/bit relations with a BabyBear AIR without a compiled, fully constrained field-switching construction.
6. Plonky3's binary PCS example is explicitly not zero knowledge; use of a hiding PCS at one layer is insufficient to prove application-level zero knowledge.
7. Proof sizes and runtimes are analytical estimates, not measurements.
8. The diagnostic script previously labeled heuristic estimates “PASS” and reported overall audit success. CHP3 removes that misleading interpretation.

## Pass 1 — Parameter domains

The LoTRS v2 artifact documents main modulus \(q=2^{43}-67=8{,}796{,}093{,}022{,}141\), binary-proof modulus \(\hat q=2^{35}-451=34{,}359{,}737{,}917\), and degree \(n=256\).

The current 0PSP Python parameter and bridge-encoding modules instead use the ML-DSA modulus \(q=8{,}380{,}417\). This is appropriate for their toy arithmetic and tests, but it is not a LoTRS instantiation. LoTRS's modulus roles must remain separate; its implementation also uses auxiliary-prime CRT-NTT techniques.

Sources:
- https://github.com/lotrs-sig/lotrs/blob/main/lotrs-py/params.py
- https://zenodo.org/records/22807126
- https://csrc.nist.gov/pubs/fips/204/final

The previous 128/192 “security bits” metadata confused NIST security categories with precise attack-cost estimates. CHP3 renames it to security_category and stores categories 2 and 3 for ML-DSA-44 and ML-DSA-65. This is metadata, not a proof of exact 128- or 192-bit security.

## Pass 2 — Commitment and Module-SIS claims

The proposed bridge expression is

\[
B=A_1m_x+A_2\tau_B\pmod q.
\]

This is a candidate relation, not by itself a commitment scheme with established hiding and binding. The current text invoked Module-LWE hiding without specifying the required LWE error term, a validated commitment construction, or a reduction for the actual distribution. That claim is withdrawn.

Likewise, the coin-commitment reduction bounded the difference of public keys as if it were a short secret. Public key coefficients obtained as \(A s+e\bmod q\) are not automatically bounded by the norm of \(s\). The claimed Module-SIS reduction therefore does not follow from the listed bounds.

A difference-vector argument requires the exact matrix distribution, full witness encoding, coefficient representatives, shortness bounds, non-zero condition, norm conversion, concrete SIS instance, and a reproducible estimator run. BKZ/Core-SVP heuristics are attack-cost estimates, not mathematical proofs of hardness.

## Pass 3 — QROM and nullifier

For the illustrative compressed-oracle expression

\[
\operatorname{Adv}\le \frac{2\pi^2(q_H+1)^2}{2^h},
\]

the arithmetic is:
- \(h=256\), \(q_H=2^{64}\): approximately \(2^{-123.7}\), not 128-bit.
- \(h=288\), \(q_H=2^{64}\): approximately \(2^{-155.7}\).
- A 256-bit entropy input reaches approximately 128 bits only under a smaller query budget near \(2^{61.8}\), subject to the exact theorem and constants.

These are conditional arithmetic results for a stated bound. The protocol has **not** established \(H_\infty(r_{\mathrm{nf}}\mid\mathrm{public\ view})=h\). Computational hiding does not, by itself, imply a statistical conditional-min-entropy lower bound.

The rule of thumb \(2^{384/3}=2^{128}\) is a generic quantum collision-query work scale for a 384-bit ideal hash output. It must not be restated as an unconditional collision probability of at most \(2^{-128}\), or as a proof of protocol unlinkability.

Source: https://csrc.nist.gov/pubs/fips/202/final

## Pass 4 — STARK/AIR and zero knowledge

The 90-byte candidate input (26-byte domain string plus 32-byte coin ID and 32-byte secret) fits within SHAKE256's 136-byte rate, so one Keccak-f[1600] permutation is sufficient for the nullifier computation under this exact encoding. The 24-round \(\chi\)-layer has \(24\times1600=38{,}400\) bit-level nonlinear operations. That is **not** the total AIR constraint count, proof size, or runtime.

LoTRS coefficients modulo a 43-bit modulus cannot be verified in BabyBear by a bare field congruence. A carry/range gadget must constrain every limb and signed carry canonically, and all intermediate integer residual bounds must be independently checked. The current carry equations and residual figures are not treated as verified until a script checks them against the exact AIR constraints.

Plonky3 documentation states that BinaryPcs exposes query symbols and the final codeword and is not zero knowledge. A hiding PCS is only one part of a zero-knowledge proof; the complete trace, auxiliary arguments, transcript, and application statement require analysis. Four blinding rows alone do not prove ZK.

Sources:
- https://github.com/Plonky3/Plonky3/blob/main/README.md
- https://github.com/Plonky3/Plonky3/blob/main/docs/architecture.md

## Pass 5 — LoTRS baseline provenance

Public LoTRS material contains figures from different artifacts/configurations: July 2026 preview slides around 35 KB, a current GitHub README headline around 35.06 KB and earlier estimates, a checked-in estimator log reporting around 52.6574 KiB analytically, and a Zenodo v2 artifact reference output of 53.53 KiB measured. The included v2 estimator does not substantiate 128-bit PQ security for its displayed configurations.

These figures are not interchangeable. Freeze artifact/version, parameters, output encoding, measurement method, and command before a like-for-like reproduction.

Sources:
- https://github.com/lotrs-sig/lotrs
- https://github.com/lotrs-sig/lotrs/blob/main/estimator/LoTRS-Estimate-Output-N100T50.txt
- https://zenodo.org/records/22807126
- https://csrc.nist.gov/Presentations/2026/tcpt2-2a3

## Decision gates

| Gate | Status | Required evidence |
|---|---|---|
| Functional byte encoding | Functional tests exist | CI pass; does not imply cryptographic security |
| LoTRS-compatible parameters | Not implemented | Separate q and q-hat types; arithmetic tests against LoTRS artifact |
| Coin commitment | OPEN | Concrete PQ commitment with correct hiding and binding reductions |
| Bridge commitment | OPEN | Concrete scheme, same encoding in both layers, binding/hiding proof and parameter analysis |
| Extended Layer 1 | OPEN | Complete threshold wallet relation; same hidden coin/key; correct response distribution and serialization |
| Layer 2 STARK | OPEN | Compiled AIR, fully enforced bit/range/limb constraints, actual ZK backend and soundness analysis |
| QROM unlinkability | OPEN | Correct quantum game, hidden-point bound, valid hybrids and query budget |
| 128-bit PQ target | OPEN | End-to-end attack analysis; no heuristic-only claim |
| Combined size/runtime | UNMEASURED | Compiled end-to-end implementation and reproducible benchmarks |

## Audit conclusion

CHP3 fixes terminology, source provenance, build/test automation, and misleading “PASS/security closed” claims. It does not claim unsolved cryptographic obligations have vanished. Phase 1 remains open until the commitment construction, extended threshold-selection relation, complete ZK AIR, and composition proof are instantiated and independently checked.
