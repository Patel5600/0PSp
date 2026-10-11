# Related Work Survey and Systematic Construction Comparison

**Status:** Living research document  
**Document Version:** 0.3 (Updated with systematic LoTRS, Raccoon, and Ringtail analysis)

---

## 1. Summary Comparison Table

| Scheme | Year | Venue | Primitive Type | PQ Security | Anonymity Mechanism | Key Rerandomization | Double-Spend Nullifier | Threshold Wallet | Concrete Size / Efficiency |
|---|---|---|---|---|---|---|---|---|---|
| **ML-DSA** (FIPS 204) | 2024 | NIST | Single signature | Module-LWE / MSIS | None | None | None | None | Sig: ~2.4–4.6 KB |
| **Threshold Raccoon** | 2024 | ePrint 2024/184 | Threshold signature | Module-LWE / MSIS | None | None | None | Additive mask (non-Shamir) | Sig: ~11–13 KB (2-of-3) |
| **Ringtail** | 2024 | ePrint 2024/1113 | 2-round threshold sig | Plain LWE | None | None | None | Preprocessing OT / additive | Scales to 1024 parties |
| **LoTRS** | 2026 | ACM CCS 2026 | Structured threshold ring signature | Module-LWE / MSIS | 1-out-of-$N$ lattice proof | None | None | Multi-sig aggregated layer | **53.53 KiB** (Sept 2026 artifact; ~35 KB preview) |
| **Zcash Orchard** | 2021 | Production | Spend protocol | ✗ Classical (DLog / Halo2) | Note commitment tree | Rerandomizable Jubjub | Deterministic PRF nullifier | ✗ No native threshold | Tx: ~2–3 KB |
| **Monero / CLSAG** | 2020 | ACM CCS | Linkable ring signature | ✗ Classical (Ed25519) | 1-out-of-$R$ ring signature | Stealth addresses (one-time) | Key image $I = x \mathcal{H}_p(P)$ | ✗ Multi-sig exists, but fragile | Ring size 16: ~2.5 KB |
| **0PSP (Research Hypothesis)** | — | — | Private spend primitive | Target: MLWE / MSIS | Anonymity over spenders | *Under investigation (Design A vs B)* | Lattice-bound nullifier $\nu$ | $t$-of-$n$ wallet compatible | Target: competitive with LoTRS (**53.53 KiB**) |

---

## 2. In-Depth Comparison: 0PSP vs. LoTRS (ACM CCS 2026)

LoTRS (*Practical Post-Quantum Structured Threshold Ring Signatures from Lattices*, Jagganath et al., ACM CCS 2026, ePrint 2026/974) is the primary state-of-the-art post-quantum threshold ring signature. Any claim of novelty or differentiation by 0PSP must be established against LoTRS across five foundational criteria:

| Dimension | Question | Current State in LoTRS | What 0PSP Must Establish |
|---|---|---|---|
| **Threshold Authorization** | What does 0PSP do that LoTRS cannot? | LoTRS targets *structured* threshold ring signatures (sTRS): it decomposes the signature into an aggregated multisignature layer among $T$ known participants, coupled with a 1-out-of-$N$ proof hiding *which* organization / ring member approved. The internal approval structure within the chosen organization is public to the verifier. | 0PSP must decide whether it requires *unstructured* threshold ring signatures (where even the specific $t$-of-$n$ subset inside the spender wallet is hidden from everyone), or whether structured spend authorization is sufficient. |
| **Spend-Specific Rerandomization** | Is this a new security property, a new construction, or an unnecessary constraint? | LoTRS does *not* rerandomize public keys per transaction. Keys remain fixed across signing instances. | 0PSP must prove whether per-transaction key rerandomization (Design A) is strictly necessary for unlinkability, or whether anonymous membership proofs over fixed keys with one-time nullifiers (Design B / Experiment 2A) achieve identical privacy guarantees with fewer related-key attack surfaces. |
| **Nullifiers** | Can double spending be prevented without linking distinct spends? | LoTRS contains **no nullifier mechanism**. It is a signature scheme, not an anonymous spend/e-cash protocol. Replaying a LoTRS signature is detected only if the message is identical; spending the same underlying credential on different transactions cannot be detected. | 0PSP must introduce a provably secure, quantum-resistant deterministic nullifier that binds to the authorized asset without exposing the signing threshold subset or linking distinct transactions. |
| **Quantum Security** | Are all components and their composition supported by reductions? | LoTRS proves security under standard Module-LWE and Module-SIS in the random oracle model (ROM / QROM). | The September 2026 artifact estimates attack costs below 128 bits for certain parameter variants; parameter expansion is needed for true 128-bit PQ security. 0PSP must verify that its reductions to standard lattice assumptions are tight and verifiable via the Lattice Estimator. |
| **Practicality** | Does 0PSP improve a meaningful metric or enable new capabilities? | The September 2026 production artifact reports **53.53 KiB** for $N=100, T=50$ (the July 2026 preview estimated ~35 KB). See `docs/related-work/lotrs-benchmark-calibration.md`. | 0PSP cannot ignore this baseline: any spend proof that adds nullifiers or ZK circuits must evaluate bandwidth and verification time against this **53.53 KiB** benchmark. |

---

## 3. Analysis of Lattice Threshold Sharing: Raccoon and Ringtail

A central mathematical finding in Phase 1 is that **naive Shamir response interpolation over polynomial rings $R_q$ fails due to modular wrap probability $2^{-3840}$**. How do modern lattice threshold schemes handle threshold keys?

### 3.1 Threshold Raccoon (ePrint 2024/184)
*Del Pino, Lyubashevsky, Pilaram, Polyntseva, Sedaghat, Seiler*

* **Approach to Secrets:** Raccoon does **not** split the secret key $s$ using Shamir secret sharing. Instead, it utilizes **additive secret sharing** or independent partial keys with **one-time additive masks**.
* **Rejection Sampling:** In Dilithium-style signatures, signing leaks $s$ unless masked by a large random vector $y$ followed by rejection sampling. In a threshold setting, partial signatures $z_i = y_i + c s_i$ cannot be individually checked by standard rejection sampling without leaking $s_i$. Raccoon solves this by having parties exchange masked commitments and adding collaborative one-time masks that cancel out upon aggregation, allowing a single combined rejection sampling step.
* **Implication for 0PSP:** Raccoon proves that additive masking with zero-sum cancellation avoids Lagrange norm amplification entirely. If 0PSP uses additive masking, rejection sampling proceeds identically to single-signer ML-DSA.

### 3.2 Ringtail (ePrint 2024/1113)
*Beullens, Duman, Fleischhacker, Günther, Seiler*

* **Approach to Scalability:** Achieves 2-round threshold signatures from plain LWE supporting up to 1024 parties.
* **Setup & Key Generation:** Avoids trusted setup or heavy interactive distributed key generation (DKG) via a non-interactive preprocessing phase using oblivious transfer (OT) style techniques.
* **Absence of Privacy:** Ringtail targets authenticated threshold governance, not transactional spend privacy. It does not provide signer anonymity, public key rerandomization, or asset nullification.

---

## 4. Synthesis of Literature Gaps

1. **Threshold + Privacy + Nullifiers:** LoTRS provides threshold ring signatures without nullifiers. Raccoon and Ringtail provide threshold signatures without ring anonymity or nullifiers. Zcash provides ring/tree spend privacy with nullifiers, but lacks post-quantum security and threshold wallet integration.
2. **The Rerandomization Question:** No existing post-quantum scheme demonstrates threshold-compatible key rerandomization. Phase 1 must answer: **Is this an unbuilt primitive that deserves construction, or is it an antipattern that should be replaced with anonymous membership proofs over static threshold keys?**
