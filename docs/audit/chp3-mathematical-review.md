# CHP3 Mathematical Consistency Review

**Review date:** 2026-10-11  
**Scope:** arithmetic and protocol claims in the latest Phase 1 proposal, checked against the repository's current specifications and primary upstream documentation.  
**Status:** consistency findings recorded; cryptographic construction remains open. This is not an independent cryptographic audit.

## Executive result

The latest proposal improves the separation of parameter families and makes a useful effort to state explicit bounds. However, it does **not** justify a "no blockers" or "all proofs complete" status. This review found several concrete consistency issues that must be fixed before the numerical projections can be reused.

## 1. LoTRS coefficient widths and Layer 1 size

LoTRS v2 documents the main modulus
\[
q=2^{43}-67=8{,}796{,}093{,}022{,}141
\]
and the separate binary-proof modulus
\[
\hat q=2^{35}-451=34{,}359{,}737{,}917.
\]

The main modulus needs 43 bits for an arbitrary canonical residue in \([0,q-1]\); \(2^{36}<q\). The binary-proof modulus needs 35 bits for an arbitrary canonical residue. Therefore, "36 bits per coefficient" is not a valid generic encoding width for arbitrary coefficients modulo the main LoTRS modulus.

For six vectors of 256 coefficients each:
- 36-bit packed coefficients: \(6\cdot256\cdot36/8=6{,}912\) bytes = **6.75 KiB**.
- 43-bit packed coefficients: \(6\cdot256\cdot43/8=8{,}256\) bytes = **8.0625 KiB**.

This does **not** prove that either figure is the true signature-size delta. A bounded response may use a smaller signed encoding, and LoTRS uses its own packing/Rice encoding. The specification must state whether the six elements are arbitrary residues, short response values, or another representation, prove the relevant range, and define the actual serialization. Until then, the +6.75 KiB / +8.0625 KiB values are raw arithmetic comparisons, not a Layer 1 size estimate.

## 2. Deterministic truncation and tail probability

For 3,584 independent Gaussian coordinates and a cutoff at 14 standard deviations, the union-bound arithmetic is
\[
p_{\mathrm{tail}}\le 3584\cdot2e^{-14^2/2}
\approx 1.97\times10^{-39}
\approx 2^{-128.5}.
\]
This arithmetic is consistent with a tail bound below \(2^{-128}\), assuming the stated Gaussian tail model and coordinate count.

It does not by itself specify a secure sampler. The implementation must say whether out-of-range samples are rejected and resampled, or clipped. Rejection sampling gives a truncated/conditional distribution whose statistical distance from the intended target must be bounded; clipping changes the distribution differently. The exact sampler and its statistical-distance argument are required before this tail calculation can be used in a security proof.

## 3. BabyBear limb recurrence: carry signs

For base \(W=2^{14}\), with nonnegative carries defined conventionally by
\[
\sum_{j=0}^{i} k_jq_{i-j}+b_i+c_{i-1}=v_i+Wc_i,
\]
the recurrence to constrain is
\[
v_i-\sum_{j=0}^{i}k_jq_{i-j}-b_i-c_{i-1}+Wc_i=0.
\]
The signs of the incoming and outgoing carry terms matter. The alternate expression
\[
v_i-\left(\sum_{j=0}^{i}k_jq_{i-j}+b_i\right)+c_{i-1}-Wc_i=0
\]
does not encode the same recurrence for nonnegative conventional carries. For example, when the limb sum equals \(W\), the output limb is 0 and the outgoing carry is 1; the latter expression fails that case.

The claimed absolute residual bound should be recomputed against the corrected recurrence and every declared range. With the stated caps, the rough magnitude
\[
W+3W^2+2^{16}+2^{16}W=1{,}879{,}130{,}112
\]
is below BabyBear's \(p=2{,}013{,}265{,}921\), but this comparison alone does not validate all AIR constraints. The exact per-limb equations, carry domains, canonical top-limb constraints, terminal carry, and range-check implementation must be checked together.

## 4. QROM budget is conditional, not a generic "standard NIST budget"

For the illustrative bound
\[
\operatorname{Adv}\le 2\pi^2(q_H+1)^2/2^h,
\]
the log-base-2 arithmetic at \(q_H=2^{64}\) is:
- \(h=256\): approximately \(-123.7\) bits;
- \(h=288\): approximately \(-155.7\) bits.

Thus, the 256-bit-input case does **not** meet a strict 128-bit advantage target under this bound and query budget. The 288-bit result is only conditional arithmetic; the protocol must actually use a 288-bit secret and prove the necessary entropy premise. The current 32-byte \(r_{\mathrm{nf}}\) has 256 bits of raw entropy at generation, but that does not prove 256 bits of conditional min-entropy given the complete public view. Do not call \(2^{64}\) a NIST-mandated query budget unless a specific standard says so.

## 5. Merkle path units and proof-size projections

For 74 queries, 8 siblings per authentication path:
- At 32 bytes per digest: \(74\cdot8\cdot32=18{,}944\) bytes = **18.5 KiB**.
- At 48 bytes per digest: \(74\cdot8\cdot48=28{,}416\) bytes = **27.75 KiB**.
- Difference: 9,472 bytes = **9.25 KiB**.

The figures 18.94 and 28.42 correspond approximately to decimal kilobytes, not kibibytes. Any total proof projection that mixes those values with KiB must be recalculated from bytes. These path sizes are only one component; they do not establish a STARK's complete serialized proof size, soundness, zero knowledge, or runtime.

## 6. Research-source reconciliation

Primary sources checked for this review:
- LoTRS v2 artifact and parameter/estimator provenance: https://zenodo.org/records/22807126
- LoTRS upstream implementation: https://github.com/lotrs-sig/lotrs
- NIST FIPS 202 (SHA-3/SHAKE): https://csrc.nist.gov/pubs/fips/202/final
- Plonky3 architecture: https://github.com/Plonky3/Plonky3/blob/main/docs/architecture.md
- Plonky3 README and binary-field example: https://github.com/Plonky3/Plonky3/blob/main/README.md

The current Plonky3 documentation distinguishes backends with hiding support from ones without it; the documented BinaryPcs example is explicitly not zero knowledge. Any selected backend needs a complete application-level ZK and soundness argument, not merely a hiding PCS.

LoTRS v2's reference estimator outputs do not substantiate 128-bit post-quantum security for the displayed profile. The 53.53 KiB figure is an artifact measurement for that profile, not a 128-bit security-matched 0PSP baseline. The ~35 KB headline, analytic estimate, and measured artifact size must remain separate with provenance.

## Decision and required next steps

**GO:** keep mathematical falsification, source reconciliation, functional tests, and parameter/encoding diagnostics moving.

**HOLD:** do not describe the full 0PSP construction as complete, secure, or blocker-free. The bridge commitment, extended threshold-selection proof, complete zero-knowledge AIR, valid QROM game/reduction, and end-to-end parameters remain uninstantiated.

Before using any updated size figure:
1. Correct the carry recurrence and add exhaustive small-range tests for it.
2. Specify the actual bounded-response encoding and prove its bounds before using 36-bit coefficients.
3. Recalculate all Merkle and proof-size accounting in integer bytes.
4. Reconcile the chosen secret length and query budget with the actual QROM theorem and security target.
5. Keep the audit status open until concrete proof systems and independent checks discharge the cryptographic obligations.
