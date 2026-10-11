# LoTRS Baseline Calibration & Empirical Parameter Manifest

**Document Version:** 2.0 (Artifact Citation & Precision Calibration)  
**Phase:** 1 (Empirical Baseline Calibration)  
**Date:** October 2026

---

## 1. Motivation: Calibrating the State-of-the-Art Baseline

In early discussions of post-quantum threshold ring signatures, 0PSP cited a signature size of **~35 KB** for **LoTRS** (*Practical Post-Quantum Structured Threshold Ring Signatures from Lattices*, Jagganath et al., ACM CCS 2026 / ePrint 2026/974).

A careful audit of public research materials demonstrates that this figure was a preliminary estimate presented in a **July 2026 CSRC/NIST conference preview**. The subsequent **September 2026 Zenodo artifact release** (Report 2026/974, DOI: 10.5281/zenodo.22807126) reports concrete measurements under an explicit test harness that must be carefully interpreted:
* Measured signature size: **53.53 KiB** for the $N=100, T=50$ artifact configuration.
* Lattice estimator calculations: displayed parameter variants exhibit attack costs below 128-bit post-quantum security.

To ensure that 0PSP does not benchmark against an unstable baseline or compare unequal primitives, this document records the exact artifact manifests, parameters, attack-cost estimates, and calibration requirements.

---

## 2. Separate Measurement Histories: Preview vs. Artifact

We maintain these two figures as separate measurements with their respective methodologies:

| Measurement Source | Version / Date | Setting ($N \times T$) | Measured Signature Size | Timing Latency (Median) | Methodological Note |
|---|---|---|---|---|---|
| **CSRC / NIST Preview** | July 2026 (Conference Slides) | $100 \times 50$ Structured Grid | **~35 KB** | Sign: $\approx 789\text{ ms}$<br>Verify: $\approx 250\text{ ms}$ | Preliminary analytical/benchmark estimate presented at NIST PQC workshop. |
| **Zenodo Artifact Release** | September 2026 (Zenodo 22807126) | $N=100, T=50$ Artifact Profile | **53.53 KiB** (54,815 bytes) | Sign: $\approx 850\text{--}920\text{ ms}$<br>Verify: $\approx 280\text{--}310\text{ ms}$ | Measured output from the automated benchmark suite (`lotrs-sig/lotrs`, Rust release build). **Not a production deployment result.** |

---

## 3. Lattice Estimator Analysis & Security Caveats

The official September 2026 LoTRS Zenodo v2 artifact (`lotrs-sig/lotrs`, DOI: 10.5281/zenodo.22807126) includes automated benchmark and estimator test harnesses. The reference output for the $N=100, T=50$ production profile records:

### 3.1 Exact Reference Output (Zenodo v2 Artifact Reference Run)
* **Measured Signature Size:** **53.53 KiB** (54,815 bytes)
* **Analytic Size Estimate:** **52.66 KiB**
* **Attack Cost Estimates (Lattice Estimator):**
  * **Variant 0 (Binary-proof ASIS cost):** **100.80 bits**
  * **Variant 0 (DualMS ASIS cost):** **94.17 bits**
  * **Variant 1 (ASIS cost):** **88.86 bits**
  * **Variant 2 (ASIS cost):** **86.21 bits**
* **Authors' Security Statement:** The artifact authors explicitly acknowledge in documentation and stdout notices that these reference estimates **do not substantiate 128-bit post-quantum security**.

> [!CAUTION]
> **Reconciliation Note:** Earlier drafts cited an informal estimate of 112–118 bits. That figure was derived from an unverified alternative estimator configuration and is superseded by the official Zenodo v2 reference figures above (86.21 to 100.80 bits).

### 3.2 Non-Linear Parameter Scaling & Hypothesis Status
To achieve a true 128-bit post-quantum security target under the Lattice Estimator:
* Modulus $q$, module ranks $(k, \ell)$, and Gaussian widths must be expanded.
* **Status of the 65–75 KiB Figure:** The projected size expansion to 65–75 KiB is an **unverified hypothesis**, not an established result. Non-linear interactions among NTT factorization, rejection sampling slack, and lattice basis dimensions mean the required expansion can only be determined through a dedicated empirical parameter sweep and fresh estimator execution.

---

## 4. Separation of Parameter Manifests: ML-DSA vs. LoTRS

NIST FIPS 204 parameters describe the **ML-DSA** signature standard. They are **not universal constants** for all lattice constructions and must not be conflated with LoTRS parameters.

### 4.1 ML-DSA (NIST FIPS 204) Parameter Baseline
* **Purpose:** Single-signer post-quantum digital signature.
* **ML-DSA-44 (Level 2):** $n=256, q=8,380,417, k=4, \ell=4, \eta=2, \tau=39, \beta=78, \gamma_1=2^{17}, \omega=80$.
* **ML-DSA-65 (Level 3):** $n=256, q=8,380,417, k=6, \ell=5, \eta=4, \tau=49, \beta=196, \gamma_1=2^{19}, \omega=55$.

### 4.2 LoTRS Parameter Manifest (Artifact Profile)
* **Purpose:** Structured threshold ring signatures combining 2-round multisignatures with a 1-out-of-$N$ proof.
* **Moduli:**
  * Primary Modulus: $q = 2^{43} - 67$ (approx 43 bits, prime).
  * Auxiliary Modulus: $\widehat{q} = 2^{35} - 451$ (approx 35 bits, prime).
* **Lattice Dimensions:** Evaluated over module lattices with $n=256, k=14, \ell=20, \ell'=21, \widehat{n}=12, \widehat{k}=11$, tailored to decompose $T$ multisigners across $N$ candidate organizations.
* **Algebraic Structure:** Uses $\Sigma$-protocols with rejection sampling bounds specifically calibrated for selection vectors over $R_q$ rather than single-signer Fiat-Shamir responses. Does not use power-of-two cyclotomic NTT over $\mathbb{Z}_q$.

---

## 5. Equivalent Functionality & Threshold Dimension Rules

To perform a scientifically valid comparison between 0PSP and LoTRS, benchmarks must satisfy three equivalence criteria:

### Criterion 1: Distinct Threshold Dimensions
LoTRS evaluates a structured profile of $N=100, T=50$, meaning 50 signers from 100 organizations participate in an aggregated signature. In 0PSP, the threshold dimensions represent two completely different architectural concepts:
1. **Wallet Custody Threshold $(t, n)$:** e.g., $t=3, n=5$ signers in a threshold custody wallet.
2. **Anonymity Set Size $N$:** e.g., $N=64$ or $100$ candidate coin commitments in the ring $R_C$.
Any benchmark comparison must specify both $(t, n)$ and $N$ independently.

### Criterion 2: Equivalent Functionality Attribution
LoTRS provides **authentication only** (it hides which organization signed, but contains no asset value, no balance check, and no nullifier). 0PSP provides a **complete private spend transaction**. When comparing transaction sizes, report explicit component attribution:
$$\text{Size}_{\text{total}} = \text{Size}_{\text{auth}} + \text{Size}_{\text{select}} + \text{Size}_{\text{commit}} + \text{Size}_{\text{null}}$$
* $\text{Size}_{\text{auth}} + \text{Size}_{\text{select}}$ is comparable to LoTRS.
* $\text{Size}_{\text{commit}} + \text{Size}_{\text{null}}$ represents the spend-privacy and double-spend prevention delta.

### Criterion 3: Verified 128-Bit PQ Security
Every compared parameter profile must be verified using the Lattice Estimator under the quantum sieve model to confirm:
$$\min\left( \text{CoreSieve}_{\text{primal}}, \; \text{CoreSieve}_{\text{dual}} \right) \ge 128\text{ bits}$$
