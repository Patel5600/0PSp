# Layer 2 STARK AIR — Constraints to Be Instantiated

**Status:** Design target only. No compiled 0PSP AIR or measured zero-knowledge proof exists in this repository.

## 1. Intended statement and witness

Public inputs are the canonical bridge commitment \(B\), published nullifier \(\nu\), transaction digest \(M\), and protocol/version identifiers. The private witness contains coin_id, r_nf, the bridge opening randomness, and any limb/bit witnesses needed by the chosen commitment.

The intended constraints are:
1. canonical input encoding;
2. correct opening of the exact public bridge commitment \(B\);
3. correct SHAKE256-384 output \(\nu\);
4. canonical integer/range constraints for every encoding and cross-modulus relation;
5. transaction/version/domain separation and transcript binding.

This list is not yet an implemented AIR.

## 2. Hash operation count is not proof cost

With the fixed domain string 0PSP-NULLIFIER-v1-SHAKE256 (26 bytes), a 32-byte coin_id and a 32-byte r_nf form a 90-byte input. This fits in SHAKE256's 136-byte rate and, for a 48-byte output, uses one Keccak-f[1600] permutation under this exact encoding.

That permutation contains 24 rounds and 1,600 bit-level \(\chi\) operations per round, or 38,400 \(\chi\)-layer nonlinear bit operations. This is **not** the total number of AIR constraints. The trace must also represent state bits, linear Keccak steps, padding, byte/bit packing, public-output equality, commitment opening, range checks, field switching, and every limb/carry relation. Proof size cannot be inferred from the \(\chi\)-count alone.

NIST SHAKE specification: https://csrc.nist.gov/pubs/fips/202/final

## 3. Field and integer soundness

The proposed cross-layer design places a 43-bit LoTRS modulus relation into a smaller STARK base field such as BabyBear. A base-field congruence is not the same as integer equality. A valid AIR needs:
- canonical limb decomposition and reconstruction;
- range checks on every limb;
- signed representation constraints where negative representatives are used;
- bounded carries and a verified recurrence;
- bounds on every intermediate product/sum smaller than the base-field modulus when a field equality is used to imply integer equality;
- explicit public-input constraints and terminal conditions.

The carry equations and maximum residual in prior drafts are not considered verified until the actual constraints, allowed ranges and maximum absolute residual have been independently recomputed. A Python assertion over a claimed final number is not enough.

## 4. Backend zero knowledge and soundness

Plonky3 is a toolkit with multiple PCS and STARK compositions, not one fixed security profile. Its current documentation explicitly says the BinaryPcs example is not zero knowledge and reveals query symbols/final codeword. A hiding PCS is only one component of a full zero-knowledge protocol.

Sources:
- https://github.com/Plonky3/Plonky3/blob/main/README.md
- https://github.com/Plonky3/Plonky3/blob/main/docs/architecture.md

Before a security claim, freeze the exact backend/commit, AIR, trace layout/width, field/extension, FRI rate and query count, transcript hash, grinding, polynomial commitment mode, blinding, and soundness model. Prove or cite a concrete bound for that exact system. The expression \((1/8)^{N_{\mathrm{queries}}/2}\) is not by itself evidence that the selected Plonky3 composition provides that bound in the quantum Fiat–Shamir setting.

Do not use BLAKE3 with an output longer than 256 bits as a way to claim stronger collision security: the BLAKE3 security notes say longer outputs add no security. If a 384-bit generic quantum collision-work target is used, select and analyze a suitable hash such as SHAKE256-384, while treating the estimate as a generic attack scale rather than an unconditional collision probability.

Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/c/README.md

## 5. Proof-size status

The 58.34 KiB Layer 2 value and 118.62/119.75 KiB combined values remain **unverified analytical projections**. Merkle paths alone do not determine proof size. Measurement must serialize a complete proof from a selected zero-knowledge backend and include all trace openings, FRI/PCS data, public inputs, bridge opening constraints, masking, transcript and transaction overhead. Proving/verification time and peak memory must also be measured.


## CHP3 arithmetic correction (2026-10-11)

The signed carry recurrence must match the chosen carry convention. For nonnegative conventional carries in base \(W=2^{14}\), use
\[
\sum_{j=0}^{i}k_jq_{i-j}+b_i+c_{i-1}=v_i+Wc_i,
\]
or equivalently
\[
v_i-\sum_{j=0}^{i}k_jq_{i-j}-b_i-c_{i-1}+Wc_i=0.
\]
Do not use the opposite signs for \(c_{i-1}\) and \(c_i\) with nonnegative carries. A simple test case where the limb sum is \(W\) must yield output limb 0 and outgoing carry 1.

With \(W=16{,}384\), three products each below \(W^2\), and carries bounded by \(2^{16}\), the stated rough absolute residual cap is
\[
W+3W^2+2^{16}+2^{16}W=1{,}879{,}130{,}112
\]
which is below \(p_{\mathrm{BabyBear}}=2{,}013{,}265{,}921\). This is only a field-aliasing check for that declared cap; the full AIR still needs exact limb ranges, signed/canonical representation, carry bounds, top-limb constraints, and terminal carry checks.

Use byte-accurate KiB accounting. For 74 paths with 8 sibling digests each, 32-byte digests occupy 18,944 bytes = 18.5 KiB; 48-byte digests occupy 28,416 bytes = 27.75 KiB. Values 18.94 and 28.42 are decimal kB, not KiB. The complete proof-size projection must be recomputed from serialized byte counts.

The 14-sigma union-tail calculation is approximately \(2^{-128.5}\) for 3,584 coordinates under the stated Gaussian model. The sampler must specify rejection/resampling versus clipping and bound the distributional effect of truncation. This arithmetic alone does not validate a sampler or its security proof.
