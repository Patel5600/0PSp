# CHP3 Research Corrections and Source Ledger

This document records corrections made after checking the live 0PSP repository against primary public specifications and upstream implementations. It is a source ledger and engineering checklist, not a cryptographic certificate.

## Primary sources checked

1. LoTRS repository and README: https://github.com/lotrs-sig/lotrs
2. LoTRS parameter source: https://github.com/lotrs-sig/lotrs/blob/main/lotrs-py/params.py
3. LoTRS estimator output for N=100, T=50: https://github.com/lotrs-sig/lotrs/blob/main/estimator/LoTRS-Estimate-Output-N100T50.txt
4. LoTRS v2 artifact, DOI 10.5281/zenodo.22807126: https://zenodo.org/records/22807126
5. NIST FIPS 202 (SHA-3/SHAKE): https://csrc.nist.gov/pubs/fips/202/final
6. NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
7. Plonky3 backend/security documentation: https://github.com/Plonky3/Plonky3/blob/main/README.md and https://github.com/Plonky3/Plonky3/blob/main/docs/architecture.md
8. BLAKE3 security notes: https://github.com/BLAKE3-team/BLAKE3/blob/master/c/README.md
9. Ringtail: https://eprint.iacr.org/2024/1113
10. Zcash Orchard nullifier design and protocol specification: https://zcash.github.io/orchard/design/nullifiers.html and https://zips.z.cash/protocol/nu6.pdf
11. Obscura-PQ preprint: https://arxiv.org/abs/2608.22645

## Corrections applied

### A. Parameter-domain separation

The old text sometimes described \(q=8{,}380{,}417\) as “ML-DSA / LoTRS”. This is false. ML-DSA uses \(q=8{,}380{,}417\). LoTRS v2 uses main modulus \(q=2^{43}-67\) and binary-proof modulus \(\hat q=2^{35}-451\). Current Python ring operations and bridge helper remain ML-DSA-modulus toy arithmetic; this checkpoint does not pretend they implement LoTRS arithmetic.

### B. NIST category versus estimated bits

ML-DSA-44 and ML-DSA-65 are associated with NIST security categories 2 and 3. Values 128 and 192 are not an automatically proven attack-cost output for this project. The API field is renamed to security_category.

### C. LoTRS version/measurement provenance

The 35 KB preview, current GitHub README headline, estimator-output size, and Zenodo v2 measured size differ. They are recorded as separately sourced data, not reconciled by silently preferring one. An apples-to-apples measurement requires the exact artifact/version, parameters, output encoding, command, and measurement method. The estimator output includes variant-specific costs around 100.80 / 94.17 / 88.86 / 86.21 bits; the artifact cautions that those reference outputs do not substantiate 128-bit PQ security.

### D. No BLAKE3-384 security claim

BLAKE3 permits extendable output, but its own security notes state that outputs longer than 256 bits do not provide extra security. It must not be designated “BLAKE3-384 with 128-bit generic quantum collision resistance”. SHAKE256-384 is retained as a candidate only, with a protocol-level proof still required.

### E. Commitment hiding/binding

The current algebraic formula \(B=A_1m_x+A_2\tau_B \bmod q\) is not automatically an LWE commitment. Without a properly specified error distribution, commitment construction, and reductions, the formula does not justify computational or statistical hiding. A Module-SIS binding claim also requires the full short-difference vector and actual parameter security analysis. The same issue applies to the proposed coin commitment; public-key coefficient differences cannot be assumed short from the secret-key norm.

### F. QROM bounds

The expression \(2\pi^2(q_H+1)^2/2^h\), where applicable, is a conditional bound under explicit hypotheses. Its arithmetic gives approximately \(2^{-123.7}\) for \(h=256,q_H=2^{64}\), and \(2^{-155.7}\) for \(h=288,q_H=2^{64}\). It does not establish that the actual protocol transcript leaves 256 or 288 bits of conditional min-entropy. Computational hiding and statistical min-entropy are different claims. The exact game and theorem assumptions must be written before calling the result an unlinkability theorem.

### G. AIR soundness and zero knowledge

Counting the Keccak \(\chi\)-layer operations is not a complete AIR constraint count. BabyBear integer arithmetic needs explicit bit/limb/range constraints, and the exact mixed-field relation must be implemented and verified. Plonky3's BinaryPcs example is expressly not zero knowledge. Hiding PCS support does not alone establish protocol ZK, and FRI/Fiat–Shamir security needs backend-specific analysis.

### H. Status of numeric estimates

The Layer 1 + Layer 2 sizes (including 118.62/119.75 KiB estimates) are unverified projections. They are not benchmark results and do not include a reproduced compiled 0PSP implementation. A rough Core-SVP estimate is not a proof of hardness. Use upstream lattice estimators and document the exact model/input/output.

## Required evidence before the next GO decision

- Concrete coin and bridge commitment schemes with fully stated hiding/binding games and reductions.
- Actual LoTRS modulus profiles represented by separate types, not by the ML-DSA parameter object.
- A Layer 1 protocol that proves threshold authorization and coin ownership for the same hidden selection index.
- A complete Layer 2 AIR/trace/backend implementation, including all field-switch, range, hash, and transcript constraints.
- A valid knowledge-soundness/zero-knowledge composition argument with explicit assumptions and advantage terms.
- Reproducible lattice estimator and FRI/Fiat–Shamir parameter outputs for the exact implementation.
- CI results and byte-accurate proof benchmarks.

Until then, the honest project status is “candidate construction under falsification”, not “cryptographic audit passed”.
