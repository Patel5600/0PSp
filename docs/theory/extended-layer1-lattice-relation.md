# Extended Layer 1 Lattice Relation Specification (Π_L)

**Document Version:** 2.1 (Post-Review Reconciled)  
**Phase:** 1 (Cryptographic Specification & Feasibility)  
**Date:** October 2026  
**Status:** Mathematical specification reconciled with LoTRS v2 parameters ($q_{\text{LoTRS}} = 2^{43} - 67$), 15-sigma truncation, and explicit witness dimensions.

---

## 1. Executive Summary & Architecture

The 0PSP two-layer architecture separates the spend verification into:
1. **Layer 1 ($\Pi_L$):** An extended post-quantum lattice $\Sigma$-protocol over the native LoTRS ring $R_{q_{\text{LoTRS}}} = \mathbb{Z}_{q_{\text{LoTRS}}}[X]/(X^{256} + 1)$ that jointly proves 1-out-of-$N$ anonymity, coin commitment opening, bridge commitment opening, and threshold custody authorization.
2. **Layer 2 ($\Pi_H$):** A zero-knowledge STARK verifying that the exact same bridge commitment opens to the canonical nullifier input $\mathbf{m}_x$, and that the published 384-bit nullifier $\nu = \text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id} \parallel r_{\text{nf}})$ is correct.

Following the Phase 1 Consistency Audit Revision 2 (`docs/audit/phase1-consistency-audit.md`), Layer 1 incorporates:
* Disambiguated witness dimensions ($1 + 1 + 2 + 2 = 6$ scalar ring elements over $R_{q_{\text{LoTRS}}}$).
* A **15-sigma deterministic truncation bound** ($B_{w, \infty} = 15 \sigma_w$), bounding tail failure probability to $< 2^{-149.5}$.
* Separation of the **wallet custody threshold $(t, n)$** from LoTRS's $T$-row multisignature grid.

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
│   m_v ∈ R_q^1                            (1 Scalar Ring Element: Coin Value)           │
│   m_x ∈ R_q^1                            (1 Scalar Ring Element: NF Poly, ||m_x||_∞≤3) │
│   ρ ∈ R_q^2                              (2 Scalar Ring Elements: Coin Randomness)     │
│   τ_B ∈ R_q^2                            (2 Scalar Ring Elements: Bridge Randomness)   │
│                                                                                        │
│ Joint Algebraic Obligations Proven Under Identical Column Index j:                     │
│   (1) Selection:       b ∈ {0,1}^N, ∑ b_i = 1, selecting column j                      │
│   (2) Coin Opening:    C_j = B_1 pk_j + B_2 m_v + B_3 m_x + ρ  (mod q_LoTRS)           │
│   (3) Bridge Opening:  B = A_1 m_x + A_2 τ_B                  (mod q_LoTRS)           │
│   (4) Custody Auth:    A_sig z_j = c · pk_j + M_ctx           (mod q_LoTRS)           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Reconciled Parameter Set (LoTRS v2 Baseline)

All Layer 1 operations are evaluated over the cyclotomic ring:
$$R_q = \mathbb{Z}_q[X] / (X^n + 1)$$
with the published LoTRS v2 production parameters (`Zenodo DOI: 10.5281/zenodo.22807126`):
* Ring Degree: $n = 256$
* Primary Modulus: $q_{\text{LoTRS}} = 2^{43} - 67$ (approx 43 bits, prime)
* Auxiliary Modulus: $\widehat{q}_{\text{LoTRS}} = 2^{35} - 451$ (approx 35 bits, prime)
* Module Dimensions: $k = 14, \ell = 20, \ell' = 21, \widehat{n} = 12, \widehat{k} = 11$

---

## 3. Disambiguated Witness Sizing & Unified Spend System

### 3.1 Exact Witness Sizing
The extended spend witness $\mathbf{w}$ consists of:
* Baseline LoTRS signing secret: $\mathbf{s}_j \in R_q^4$, $\mathbf{e}_j \in R_q^4$ ($4 + 4 = 8$ scalar ring elements)
* Spend extension witness:
  * $m_v \in R_q^1$ (1 scalar ring element)
  * $m_x \in R_q^1$ (1 scalar ring element)
  * $\boldsymbol{\rho} \in R_q^2$ (2 scalar ring elements)
  * $\boldsymbol{\tau}_B \in R_q^2$ (2 scalar ring elements)
* **Total Witness Dimension:** $d_w = 8 + (1 + 1 + 2 + 2) = 14$ scalar ring elements ($3,584$ integer coefficients).
* **Added Spend Dimension:** Exactly **6 scalar ring elements**.

### 3.2 Matrix Relation
Define the public block matrix $\mathbf{M}_{\text{spend}} \in R_q^{(k_{\text{PK}} + k_C + k_B) \times d_w}$:
$$\mathbf{M}_{\text{spend}} = \begin{pmatrix}
\mathbf{A}_{\text{sig}} & \mathbf{I}_4 & \mathbf{0} & \mathbf{0} & \mathbf{0} & \mathbf{0} \\
\mathbf{0} & \mathbf{0} & \mathbf{B}_2 & \mathbf{B}_3 & \mathbf{I}_2 & \mathbf{0} \\
\mathbf{0} & \mathbf{0} & \mathbf{0} & \mathbf{A}_1 & \mathbf{0} & \mathbf{A}_2
\end{pmatrix}$$

The spend condition is the exact linear system:
$$\mathbf{M}_{\text{spend}} \cdot \mathbf{w} = \begin{pmatrix} \mathbf{pk}_j \\ \mathbf{C}_j - \mathbf{B}_1 \mathbf{pk}_j \\ B \end{pmatrix} \pmod{q_{\text{LoTRS}}}$$

---

## 4. Rejection Sampling & 15-Sigma Deterministic Truncation

### 4.1 Gaussian Rejection Sampling
Prover computes candidate responses $\mathbf{z}_{\mathbf{w}} = \mathbf{y}_{\mathbf{w}} + c \cdot \mathbf{w}$ with standard deviation $\sigma_w \approx 2 \times 10^7$.

### 4.2 15-Sigma Truncation Bound
We set the truncation cutoff at $\tau_{\text{cut}} = 15$:
$$B_{w, \infty} = 15 \sigma_w \approx 3.0 \times 10^8$$
* **Gaussian Tail Bound (Union Bound over $3,584$ coordinates):**
  $$\operatorname{Pr}[\|\mathbf{z}_{\mathbf{w}}\|_\infty > 15 \sigma_w] \le 3,584 \times 2 e^{-15^2 / 2} = 7,168 \times e^{-112.5} \approx \mathbf{2^{-149.5}}$$
  This leaves **$21.5\text{ bits}$ of margin below $2^{-128}$**, absorbing statistical and reduction errors.
* **Wraparound Safety Margin:**
  $$B_{w, \infty} \approx 3.0 \times 10^8 \ll \frac{q_{\text{LoTRS}}}{2} \approx 4.4 \times 10^{12} \quad \left(\frac{q/2}{B_{w, \infty}} \approx 14,660\right)$$
  Proves that responses never wrap modulo $q_{\text{LoTRS}}$.

---

## 5. Wallet Custody Threshold vs Selection Grid

LoTRS evaluates a structured profile where $T$ signers from $N$ organizations sign rows in a grid.  
In 0PSP:
* **The Wallet Threshold $(t, n)$ is decoupled from $N$:** The wallet public key $pk_j$ is an aggregated or threshold key held by a $t$-of-$n$ custody group.
* Spender authorization is executed via a threshold signing protocol producing an aggregate signature $z_j$ verifying under $pk_j$ against transaction context $M = H_{\text{tx}}(\text{context} \parallel \nu \parallel B)$.
* The LoTRS 1-out-of-$N$ proof hides which column $j$ was authorized, while the threshold signature proves that the authorized wallet met its internal custody policy.

---

## 6. Byte-Level Proof Size Accounting

All calculations derived in exact bytes ($1\text{ KiB} = 1,024\text{ bytes}$):

| Component | Baseline LoTRS ($N=100, T=50$) | Extended Relation ($\Pi_L$) | Delta ($\Delta$) |
|---|---|---|---|
| **Selection Grid Proof ($\mathbf{z}_{\mathbf{b}}$)** | 38.20 KiB (39,117 B) | 38.20 KiB (39,117 B) | $0\text{ KiB}$ |
| **Commitment Hash / Seeds** | 0.83 KiB (850 B) | 0.83 KiB (850 B) | $0\text{ KiB}$ |
| **Signer Response ($\mathbf{z}_{\mathbf{s}}, \mathbf{z}_{\mathbf{e}}$)** | 14.50 KiB (14,848 B) | 14.50 KiB (14,848 B) | $0\text{ KiB}$ |
| **Value Response ($\mathbf{z}_{v}$, 1 poly)** | — | 1.13 KiB (1,152 B packed) | $+1.13\text{ KiB}$ |
| **NF Poly Response ($\mathbf{z}_{x}$, 1 poly)** | — | 1.13 KiB (1,152 B packed) | $+1.13\text{ KiB}$ |
| **Coin Randomness ($\mathbf{z}_{\rho}$, 2 polys)** | — | 2.25 KiB (2,304 B packed) | $+2.25\text{ KiB}$ |
| **Bridge Randomness ($\mathbf{z}_{\tau}$, 2 polys)** | — | 2.25 KiB (2,304 B packed) | $+2.25\text{ KiB}$ |
| **Total Response Expansion** | — | — | **$+6.75\text{ KiB}$ (6,912 B)** |
| **Total Analytical Size Projection** | **53.53 KiB (54,815 B)** | **$\approx \mathbf{60.28\text{ KiB}}$ (61,727 B)** | **$+6.75\text{ KiB}$ (+12.6%)** |
| *(Uncompressed 43-bit fixed-width alternative)* | *53.53 KiB* | *$\approx 61.59\text{ KiB}$ (63,071 B)* | *+8.06 KiB (+15.1%)* |

> [!WARNING]
> **Analytical Projection Notice:**  
> The $\approx 60.28\text{ KiB}$ figure is an analytical projection based on extending the 53.53 KiB LoTRS v2 artifact profile ($N=100, T=50$).  
> It does not include non-linear parameter increases if LoTRS is re-parameterized to substantiate true 128-bit PQ security.
