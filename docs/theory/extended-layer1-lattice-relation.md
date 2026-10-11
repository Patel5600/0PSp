# Extended Layer 1 Lattice Relation Specification (Π_L)

**Document Version:** 3.0 (Post-Review Final Specification)  
**Phase:** 1 (Cryptographic Specification & Feasibility)  
**Date:** October 2026  
**Status:** Mathematical specification reconciled with LoTRS v2 parameters ($q_{\text{LoTRS}} = 2^{43} - 67$), explicit commitment randomness bounds, Profile 1 vs Profile 2 dimensions, and threshold custody authorization.

---

## 1. Executive Summary & Architecture

The 0PSP two-layer architecture separates the spend verification into:
1. **Layer 1 ($\Pi_L$):** An extended post-quantum lattice $\Sigma$-protocol over the native LoTRS ring $R_{q_{\text{LoTRS}}} = \mathbb{Z}_{q_{\text{LoTRS}}}[X]/(X^{256} + 1)$ that jointly proves 1-out-of-$N$ anonymity, coin commitment opening, bridge commitment opening, and threshold custody authorization.
2. **Layer 2 ($\Pi_H$):** A zero-knowledge STARK verifying that the exact same bridge commitment opens to the canonical nullifier input $\mathbf{m}_x$, and that the published 384-bit nullifier $\nu = \text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id} \parallel r_{\text{nf}})$ is correct.

Following the adversarial review of Revision 3, Layer 1 incorporates:
* Explicit shortness bounds on coin commitment opening randomness ($\|\boldsymbol{\rho}\|_\infty \le \eta_\rho = 2$), proving $\operatorname{Com}_{\text{coin}}$ binding against arbitrary witness substitution.
* Explicit shortness bounds on bridge randomness ($\|\boldsymbol{\tau}_B\|_\infty \le \eta_\tau = 2$).
* Formally reconciled parameter profiles: **Profile 1** ($\mathbf{A}_{\text{bridge}} \in R_q^{2 \times 3}, M=768$) and **Profile 2** ($\mathbf{A}_{\text{bridge}} \in R_q^{2 \times 4}, M=1,024$).
* A formally specified threshold custody authorization predicate decoupled from LoTRS's internal multisignature grid.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        LAYER 1 EXTENDED LATTICE RELATION (Π_L)                         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Public Inputs:                                                                         │
│   R_C = {C_1, ..., C_N} ⊂ R_q^2          (Public Coin Commitment Set)                  │
│   R_PK = {pk_1, ..., pk_N} ⊂ R_q^4       (Public Wallet Verification Keys)             │
│   B ∈ R_q^2                              (Per-Spend Bridge Commitment)                 │
│   M ∈ {0,1}^256                          (Transaction Context Digest)                  │
│                                                                                        │
│ Hidden Witness:                                                                        │
│   j ∈ [N]                                (Selected Coin / Signer Index)                │
│   s_j ∈ R_q^4, e_j ∈ R_q^4               (Threshold Signing Secret & Noise)            │
│   m_v ∈ R_q^1                            (Coin Value Polynomial, ||m_v||_∞ ≤ v_max)    │
│   m_x ∈ R_q^{ℓ_B}                        (Profile 1: ℓ_B=1; Profile 2: ℓ_B=2)          │
│   ρ ∈ R_q^2, ||ρ||_∞ ≤ 2                 (Short Coin Commitment Randomness)            │
│   τ_B ∈ R_q^2, ||τ_B||_∞ ≤ 2             (Short Bridge Commitment Randomness)          │
│                                                                                        │
│ Joint Algebraic Obligations Proven Under Identical Column Index j:                     │
│   (1) Selection:       b ∈ {0,1}^N, ∑ b_i = 1, selecting column j                      │
│   (2) Coin Opening:    C_j = B_1 pk_j + B_2 m_v + B_3 m_x + B_4 ρ  (mod q_LoTRS)       │
│   (3) Bridge Opening:  B = A_1 m_x + A_2 τ_B                      (mod q_LoTRS)       │
│   (4) Custody Auth:    A_sig z_j = c · pk_j + M_ctx               (mod q_LoTRS)       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Reconciled Parameter Sets (Profile 1 vs Profile 2)

All Layer 1 operations are evaluated over the cyclotomic ring:
$$R_q = \mathbb{Z}_q[X] / (X^n + 1)$$
with the published LoTRS v2 production modulus (`Zenodo DOI: 10.5281/zenodo.22807126`):
* Ring Degree: $n = 256$
* Primary Modulus: $q_{\text{LoTRS}} = 2^{43} - 67$ (approx 43 bits, prime)
* Auxiliary Modulus: $\widehat{q}_{\text{LoTRS}} = 2^{35} - 451$ (approx 35 bits, prime)

| Parameter | Profile 1 (Standard 256-bit) | Profile 2 (Expanded 288-bit) |
|---|---|---|
| **Secret Randomness ($r_{\text{nf}}$)** | 256 bits (32 bytes) | 288 bits (36 bytes) |
| **Max Quantum Query Budget ($q_H$)** | $q_H \le 2^{61.8}$ (for 128-bit PQ) | $q_H \le 2^{64.0}$ (Full NIST budget) |
| **Message Polys ($\ell_B$)** | 1 polynomial ($\mathbf{m}_x \in R_q^1$) | 2 polynomials ($\mathbf{m}_x \in R_q^2$) |
| **Bridge Matrix Dimension** | $\mathbf{A}_{\text{bridge}} \in R_q^{2 \times 3}$ | $\mathbf{A}_{\text{bridge}} \in R_q^{2 \times 4}$ |
| **Full Lattice Dimension ($M$)** | $M = 3 \times 256 = 768$ | $M = 4 \times 256 = 1,024$ |
| **Bridge SIS Bound ($\beta_{\text{bridge}}$)** | 166.5 | 200.0 |
| **Added Scalar Polys to LoTRS** | 6 scalar ring elements | 7 scalar ring elements |

---

## 3. Coin Commitment Binding Specification

To eliminate the non-binding vulnerability where an unbounded randomness vector allows opening forgery, the coin commitment is formally defined as:
$$C_j = \mathbf{B}_1 \mathbf{pk}_j + \mathbf{B}_2 m_v + \mathbf{B}_3 \mathbf{m}_x + \mathbf{B}_4 \boldsymbol{\rho} \pmod{q_{\text{LoTRS}}}$$
where:
* $\mathbf{B}_1 \in R_q^{2 \times 4}$, $\mathbf{B}_2 \in R_q^{2 \times 1}$, $\mathbf{B}_3 \in R_q^{2 \times \ell_B}$, $\mathbf{B}_4 \in R_q^{2 \times 2}$ are public uniformly random commitment matrices.
* The opening randomness vector $\boldsymbol{\rho} \in R_q^2$ **must satisfy the explicit shortness bound**:
  $$\|\boldsymbol{\rho}\|_\infty \le \eta_\rho = 2$$
* **Binding Proof:** Any two distinct valid openings $(pk_j, m_v, \mathbf{m}_x, \boldsymbol{\rho}) \ne (pk_j', m_v', \mathbf{m}_x', \boldsymbol{\rho}')$ satisfy:
  $$\mathbf{B}_1 (pk_j - pk_j') + \mathbf{B}_2 (m_v - m_v') + \mathbf{B}_3 (\mathbf{m}_x - \mathbf{m}_x') + \mathbf{B}_4 (\boldsymbol{\rho} - \boldsymbol{\rho}') \equiv \mathbf{0} \pmod{q_{\text{LoTRS}}}$$
  Because all differences are bounded ($\|\Delta pk\|_\infty \le 2\eta$, $\|\Delta m_v\|_\infty \le 2 v_{\max}$, $\|\Delta \mathbf{m}_x\|_\infty \le 6$, $\|\Delta \boldsymbol{\rho}\|_\infty \le 4$), this directly yields a non-zero short vector breaking Module-SIS over $[\mathbf{B}_1 \mid \mathbf{B}_2 \mid \mathbf{B}_3 \mid \mathbf{B}_4]$. Arbitrary witness substitution is impossible.

Similarly, the bridge commitment opening randomness $\boldsymbol{\tau}_B \in R_q^2$ is explicitly bounded:
$$\|\boldsymbol{\tau}_B\|_\infty \le \eta_\tau = 2$$

---

## 4. Wallet Custody Threshold Authorization Predicate

The wallet threshold policy $(t, n)$ is decoupled from LoTRS's internal multisignature grid:
* The candidate public key $\mathbf{pk}_j \in R_q^4$ represents a $(t, n)$ threshold wallet.
* The signers execute a threshold signing protocol over the public transaction context:
  $$M = H_{\text{tx}}(\text{context} \parallel \nu \parallel B) \in \{0, 1\}^{256}$$
  producing an aggregated signature response $\mathbf{z}_j \in R_q^4$ satisfying:
  $$\mathbf{A}_{\text{sig}} \mathbf{z}_j \equiv c \cdot \mathbf{pk}_j + \mathbf{M}_{\text{ctx}} \pmod{q_{\text{LoTRS}}}$$
* Layer 1 proves that the hidden column $j$ selected from the anonymity set possesses a valid threshold authorization $\mathbf{z}_j$ without revealing the signers or the column index $j$.

---

## 5. Rejection Sampling & 15-Sigma Deterministic Truncation

* **Sampler Algorithm:** FACCT-style discrete Gaussian sampler with standard deviation $\sigma_w = 2.0 \times 10^7$.
* **Deterministic Truncation:** Cutoff set to $\tau_{\text{cut}} = 15$:
  $$B_{w, \infty} = 15 \sigma_w = 3.0 \times 10^8$$
* **Gaussian Tail Bound (Union Bound over 3,584 coordinates):**
  $$\operatorname{Pr}[\|\mathbf{z}_{\mathbf{w}}\|_\infty > 15 \sigma_w] \le 3,584 \times 2 e^{-15^2 / 2} = 7,168 \times e^{-112.5} \approx \mathbf{2^{-149.5}}$$
  Leaves **$21.5\text{ bits}$ of margin below $2^{-128}$**.
* **Wraparound Safety Margin:**
  $$B_{w, \infty} \approx 3.0 \times 10^8 \ll \frac{q_{\text{LoTRS}}}{2} \approx 4.4 \times 10^{12} \quad \left(\frac{q/2}{B_{w, \infty}} \approx 14,660\right)$$
  Guarantees that responses never wrap modulo $q_{\text{LoTRS}}$.

---

## 6. Byte-Level Proof Size Accounting

All figures computed in exact binary kibibytes ($1\text{ KiB} = 1,024\text{ bytes}$):

| Component | Baseline LoTRS ($N=100, T=50$) | Profile 1 ($\Pi_L$, 6 polys) | Profile 2 ($\Pi_L$, 7 polys) |
|---|---|---|---|
| **Selection Grid Proof ($\mathbf{z}_{\mathbf{b}}$)** | 38.20 KiB (39,117 B) | 38.20 KiB (39,117 B) | 38.20 KiB (39,117 B) |
| **Commitment Hash / Seeds** | 0.83 KiB (850 B) | 0.83 KiB (850 B) | 0.83 KiB (850 B) |
| **Signer Response ($\mathbf{z}_{\mathbf{s}}, \mathbf{z}_{\mathbf{e}}$)** | 14.50 KiB (14,848 B) | 14.50 KiB (14,848 B) | 14.50 KiB (14,848 B) |
| **Value Response ($\mathbf{z}_{v}$, 1 poly)** | — | 1.13 KiB (1,152 B) | 1.13 KiB (1,152 B) |
| **NF Poly Response ($\mathbf{z}_{x}$)** | — | 1.13 KiB (1,152 B, 1 poly) | 2.25 KiB (2,304 B, 2 polys) |
| **Coin Randomness ($\mathbf{z}_{\rho}$, 2 polys)** | — | 2.25 KiB (2,304 B) | 2.25 KiB (2,304 B) |
| **Bridge Randomness ($\mathbf{z}_{\tau}$, 2 polys)** | — | 2.25 KiB (2,304 B) | 2.25 KiB (2,304 B) |
| **Total Response Expansion** | — | **$+6.75\text{ KiB}$ (6,912 B)** | **$+7.88\text{ KiB}$ (8,064 B)** |
| **Total Analytical Size Projection** | **53.53 KiB (54,815 B)** | **$\approx \mathbf{60.28\text{ KiB}}$ (61,727 B)** | **$\approx \mathbf{61.41\text{ KiB}}$ (62,879 B)** |

> [!CAUTION]
> **Status:** Size figures remain an **analytical projection** based on the LoTRS v2 production artifact.
