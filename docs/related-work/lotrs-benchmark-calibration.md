# LoTRS Benchmark Calibration — Versioned Evidence, Not a Security Baseline

**Status:** Source and artifact figures are preserved separately. No 0PSP security-matched benchmark has been run.

## 1. Parameter roles from LoTRS v2

The official LoTRS source and Zenodo v2 artifact specify \(n=256\), main modulus \(q=2^{43}-67\), and binary-proof modulus \(\hat q=2^{35}-451\). These are distinct roles and must not be substituted for ML-DSA's \(q=8{,}380{,}417\).

Sources:
- https://github.com/lotrs-sig/lotrs/blob/main/lotrs-py/params.py
- https://github.com/lotrs-sig/lotrs/blob/main/parameters.json
- https://github.com/lotrs-sig/lotrs/blob/main/estimator/LoTRS-Estimate-Output-N100T50.txt
- https://zenodo.org/records/22807126

## 2. Preserve version/method differences

| Source | Figure | Interpretation |
|---|---:|---|
| July 2026 preview | ~35 KB | Preview/presentation figure; not a substitute for the v2 artifact measurement |
| Current GitHub README headline | ~35.06 KB plus earlier estimator headline values | Treat as README/paper headline with its own version/method |
| Current checked-in estimator output | 52.6574 KiB analytic signature-size estimate | Model estimate, not a measured serialized signature |
| Zenodo v2 reference output | 53.53 KiB / 54,815 bytes measured | Artifact measurement for its specified configuration and method |

These figures cannot be called “reconciled” merely by selecting one. The upstream README and estimator output contain distinct figures. To reproduce a reference, freeze artifact version/commit, parameters, implementation mode, output encoding and measurement command, then run the estimator and Rust benchmark on that exact release.

## 3. Reference estimator outputs

For the checked-in estimator output for \(N=100,T=50\), reported attack-cost entries include:
- Binary-proof ASIS, variant 0: about 100.80 bits.
- DualMS ASIS, variant 0: about 94.17 bits.
- Binary-proof ASIS, variants 1 and 2: about 88.86 bits.
- DualMS ASIS, variants 1 and 2: about 86.21 bits.

The corresponding artifact says these reference outputs do **not substantiate 128-bit post-quantum security**. These are model-specific attack estimates, not mathematical hardness proofs. See the exact log before relying on any number.

The July presentation, current repository README and Zenodo v2 artifact may represent different versions or measurement methods. Record source hashes and command output for any final comparison.

## 4. What 0PSP must compare

A fair comparison needs the same:
- post-quantum security target and estimator assumptions;
- anonymity set size \(N\) and threshold structure;
- byte-accurate serialized proof/transaction size;
- sign/prove and verify time, memory and communication rounds;
- hardware, software commit and repetition/measurement methodology.

LoTRS's \(T=50,N=100\) structured signing profile must not be equated automatically with a \(t\)-of-\(n\) custody wallet plus an independent set of \(N\) coin commitments.

## 5. 0PSP projection status

The figures +6.75/+7.88 KiB for Layer 1, 58.34 KiB for Layer 2, and 118.62/119.75 KiB total remain unverified analytical projections. LoTRS serialization/packing widths cannot simply be assumed for a changed response distribution. The STARK projection must include the actual zero-knowledge backend, bridge opening, all range/carry constraints, transcript, public inputs, FRI/PCS messages and chosen hash. End-to-end measurements have not yet been made.

## 6. Separate ML-DSA parameters

FIPS 204 ML-DSA parameters belong in a separate namespace and test suite. ML-DSA-44/65 NIST category labels are not exact measured security-bit estimates for 0PSP or LoTRS.

Source: https://csrc.nist.gov/pubs/fips/204/final


## CHP3 byte-accounting correction (2026-10-11)

All earlier 0PSP Layer 1/Layer 2 total-size figures in this document remain unverified projections. The Merkle-path terms in prior drafts mixed decimal kB and KiB: 74×8×32 bytes is 18,944 bytes = 18.5 KiB, while 74×8×48 bytes is 28,416 bytes = 27.75 KiB. Recompute complete totals from exact serialized byte counts; do not preserve a total by adding unit-mismatched components. The 53.53 KiB LoTRS v2 figure remains an artifact measurement for its stated profile, not a security-matched 0PSP benchmark. See [CHP3 mathematical review](../audit/chp3-mathematical-review.md).
