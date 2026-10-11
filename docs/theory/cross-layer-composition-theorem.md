# Cross-Layer Composition Theorem & Security Reductions

**Document Version:** 2.2 (Post-Review Final Reductions)  
**Phase:** 1 (Formal Security Reductions)  
**Date:** October 2026  
**Status:** Cryptographic reduction theorem featuring dedicated bridge Module-SIS parameters, causally decoupled double-spend theorems, and QROM entropy profiles.

---

## 1. Executive Summary

This document formalizes the central mathematical theorem of the 0PSP primitive: **The Cross-Layer Composition Theorem**.

Following Audit Revision 3 (`docs/audit/phase1-consistency-audit.md`), this specification:
1. Formulates the dedicated bridge Module-SIS parameters ($\text{MSIS}_{\text{bridge}}$ with $\beta_{\text{bridge}} = 166.5$, dimension $M = 768$).
2. Formulates the two QROM unlinkability profiles (Profile 1: $h=256, q_H \le 2^{61.8}$ vs Profile 2: $h=288, q_H \le 2^{64}$).
3. Decouples the **Double-Spend Resistance Theorem** (coin and bridge binding failure) from the **Collision Safety Theorem** (hash collision failure).
4. Records the byte-level combined analytical proof projection at **$\approx 118.62\text{ KiB}$**.

---

## 2. Formal Protocol Statement and Definitions

Let the public statement be:
$$S = (R_C, \nu, M, B)$$
where:
* $R_C = \{C_1, \dots, C_N\} \subset R_q^2$ is the public set of unspent coin commitments.
* $\nu \in \{0, 1\}^{384}$ is the public nullifier.
* $M = H_{\text{tx}}(\text{context} \parallel \nu \parallel B) \in \{0, 1\}^{256}$ is the transaction context digest.
* $B \in R_q^2$ is the fresh public bridge commitment over $R_{q_{\text{LoTRS}}}$.

The spend transaction publishes $\Pi = (\Pi_L, \Pi_H)$. Verification succeeds if and only if:
$$\mathsf{Verify}_L(R_C, M, B, \Pi_L) = 1 \quad \wedge \quad \mathsf{Verify}_H(B, \nu, \Pi_H) = 1$$

---

## 3. Dedicated Bridge Module-SIS Reduction

### Definition ($\text{MSIS}_{\text{bridge}}$ Instance)
Let $\mathbf{A}_{\text{bridge}} = [\mathbf{A}_1 \mid \mathbf{A}_2] \in R_{q_{\text{LoTRS}}}^{2 \times 3}$ be a uniformly random module matrix where:
* $k_B = 2$, $m_B = 3$.
* Modulus: $q_{\text{LoTRS}} = 2^{43} - 67$.
* Ring Degree: $n = 256$.
* Full Lattice Dimension: $M = 3 \times 256 = 768$.
* Norm Bound: $\beta_{\text{bridge}} = 166.5$.

### Theorem 1 (Cross-Layer Witness Extraction & Binding)
*Assume $\Pi_L$ has special soundness error $\epsilon_L$ with extractor $\mathcal{E}_L$, $\Pi_H$ has composite knowledge error $\epsilon_{\text{STARK}} \le 2^{-128.7}$ with extractor $\mathcal{E}_H$, and $\operatorname{Com}_{\text{bridge}}$ is secure under $\text{MSIS}_{2, 3, q_{\text{LoTRS}}, \beta_{\text{bridge}}}$.*

*For any quantum polynomial-time adversary $\mathcal{A}$ producing a valid tuple $(S, \Pi_L, \Pi_H)$, there exists a polynomial-time extractor $\mathcal{E}$ that extracts:*
$$w = (j, C_j, pk_j, v, \text{coin\_id}, r_{\text{nf}}, \rho, \boldsymbol{\tau}_B)$$
*such that with probability at least $\epsilon - \epsilon_L - \epsilon_{\text{STARK}} - \mathbf{Adv}^{\text{MSIS}_{\text{bridge}}}(\mathcal{B})$:*
1. $j \in [N]$ and $C_j \in R_C$.
2. $C_j = \operatorname{Com}_{\text{coin}}(pk_j, v, \text{coin\_id}, r_{\text{nf}}; \rho) \pmod{q_{\text{LoTRS}}}$.
3. $\nu = \text{SHAKE256}_{384}(\mathsf{domain}_{\text{null}} \parallel \text{coin\_id} \parallel r_{\text{nf}})$.
4. $pk_j$ has valid threshold custody authorization over $M$.

### Proof:
1. **Extraction from Layer 1 ($\Pi_L$):**
   By special soundness of the $\Sigma$-protocol (with 15-sigma deterministic truncation $B_{w, \infty} = 15 \sigma_w$), extractor $\mathcal{E}_L$ extracts:
   $$w_L = (j, C_j, pk_j, v, \text{coin\_id}_L, r_{\text{nf}, L}, \rho_L, \boldsymbol{\tau}_{B, L})$$
   satisfying $C_j \in R_C$ and $B \equiv \mathbf{A}_1 m_{x, L} + \mathbf{A}_2 \boldsymbol{\tau}_{B, L} \pmod{q_{\text{LoTRS}}}$.

2. **Extraction from Layer 2 ($\Pi_H$):**
   By composite soundness of the zero-knowledge STARK and the **shifted multi-limb carry chain** ($v_i - s_i - c_{i-1}' + W c_i' + C_{\text{shift}}(1-W) = 0$, $|\Delta_{\max}| < p$, proving zero modular wraparound), extractor $\mathcal{E}_H$ extracts:
   $$w_H = (\text{coin\_id}_H, r_{\text{nf}, H}, \boldsymbol{\tau}_{B, H})$$
   satisfying $\nu = \text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id}_H \parallel r_{\text{nf}, H})$ and $B \equiv \mathbf{A}_1 m_{x, H} + \mathbf{A}_2 \boldsymbol{\tau}_{B, H} \pmod{q_{\text{LoTRS}}}$.

3. **Binding to $\text{MSIS}_{\text{bridge}}$:**
   Suppose $m_{x, L} \ne m_{x, H}$. Subtracting the extracted bridge equations:
   $$\mathbf{A}_1 (m_{x, L} - m_{x, H}) + \mathbf{A}_2 (\boldsymbol{\tau}_{B, L} - \boldsymbol{\tau}_{B, H}) \equiv \mathbf{0} \pmod{q_{\text{LoTRS}}}$$
   Define $\mathbf{v}_{\text{diff}} = (\Delta \mathbf{m}, \Delta \boldsymbol{\tau}) \in R_{q_{\text{LoTRS}}}^3$.
   * Non-zeroness: $m_{x, L} \ne m_{x, H} \implies \mathbf{v}_{\text{diff}} \ne \mathbf{0}$.
   * Exact Euclidean Norm:
     $$\|\mathbf{v}_{\text{diff}}\|_2 \le \sqrt{6^2 \cdot 256 + 4^2 \cdot (2 \cdot 256)} \approx 131.94 \le \beta_{\text{bridge}} = 166.5$$
   * Because $q_{\text{LoTRS}} \approx 8.79 \times 10^{12} \gg 166.5$, $\mathbf{v}_{\text{diff}}$ is a non-trivial short SIS vector.
   * Therefore, $\operatorname{Pr}[m_{x, L} \ne m_{x, H}] \le \mathbf{Adv}^{\text{MSIS}_{\text{bridge}}}(\mathcal{B})$.

4. **Bijective Encoding:**
   Since $\operatorname{EncodeNF}$ is strictly injective, $m_{x, L} = m_{x, H}$ implies $(\text{coin\_id}_L, r_{\text{nf}, L}) = (\text{coin\_id}_H, r_{\text{nf}, H})$. $\blacksquare$

---

## 4. Causally Decoupled Double-Spend & Collision Theorems

### Theorem 2A (Double-Spend Resistance)
*No polynomial-time adversary $\mathcal{A}$ can spend the same coin commitment $C \in R_C$ twice with distinct nullifiers $\nu^{(1)} \ne \nu^{(2)}$, except with probability bounded by:*
$$\mathbf{Adv}^{\text{DoubleSpend}}(\mathcal{A}) \le 2 \epsilon_{\text{sound}} + 2 \mathbf{Adv}^{\text{MSIS}_{\text{bridge}}}(\mathcal{B}) + \mathbf{Adv}^{\text{CoinBind}}(\mathcal{B})$$

*Proof:*
1. Let $T^{(1)}$ and $T^{(2)}$ be two valid transactions accepted by the ledger opening the same coin commitment $C \in R_C$.
2. By Theorem 1, extractor extracts $(C, \text{coin\_id}^{(1)}, r_{\text{nf}}^{(1)})$ from $T^{(1)}$ and $(C, \text{coin\_id}^{(2)}, r_{\text{nf}}^{(2)})$ from $T^{(2)}$.
3. **Case 1:** $(\text{coin\_id}^{(1)}, r_{\text{nf}}^{(1)}) = (\text{coin\_id}^{(2)}, r_{\text{nf}}^{(2)})$.  
   Because SHAKE-256 is a deterministic function, identical inputs produce identical digests:
   $$\nu^{(1)} = \text{SHAKE256}_{384}(\text{Input}) = \nu^{(2)}$$
   This contradicts $\nu^{(1)} \ne \nu^{(2)}$.
4. **Case 2:** $(\text{coin\_id}^{(1)}, r_{\text{nf}}^{(1)}) \ne (\text{coin\_id}^{(2)}, r_{\text{nf}}^{(2)})$.  
   Both witnesses open the same coin commitment $C$:
   $$C = \mathbf{B}_1 pk^{(1)} + \mathbf{B}_2 m_v^{(1)} + \mathbf{B}_3 m_x^{(1)} + \rho^{(1)} \equiv \mathbf{B}_1 pk^{(2)} + \mathbf{B}_2 m_v^{(2)} + \mathbf{B}_3 m_x^{(2)} + \rho^{(2)} \pmod{q_{\text{LoTRS}}}$$
   Subtracting yields a non-zero short vector breaking the binding of $\operatorname{Com}_{\text{coin}}$ under Module-SIS.
5. Therefore, double-spending of the same coin commitment requires breaking commitment binding. A hash collision does not enable this attack. $\blacksquare$

---

### Theorem 2B (Collision Safety & Non-Denial)
*No polynomial-time adversary can find two distinct coins $C_a \ne C_b$ producing identical nullifiers $\nu_a = \nu_b$, except by finding a collision in SHAKE-256:*
$$\mathbf{Adv}^{\text{Collision}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Coll}}_{\text{SHAKE256}} \le 2^{-128}$$

*Proof:*
Distinct coins satisfy $(\text{coin\_id}_a, r_{\text{nf}, a}) \ne (\text{coin\_id}_b, r_{\text{nf}, b})$. If $\nu_a = \nu_b$, then:
$$\text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id}_a \parallel r_{\text{nf}, a}) = \text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id}_b \parallel r_{\text{nf}, b})$$
This directly finds a collision in SHAKE-256-384, which requires at least $2^{128}$ quantum operations under BHT search. $\blacksquare$

---

## 5. Spender Unlinkability in the QROM

We formulate $\text{Game}_{\mathcal{A}}^{\text{UNLINK}}(b)$ with challenge bit $b \in \{0, 1\}$.

### Sequence of Games:
* **$\text{Game}_0$:** Real spend game with coin $C_b$.
* **$\text{Game}_1$:** Replace $\Pi_H^*$ with STARK zero-knowledge simulator $\mathcal{S}_H$ (computational ZK via 4 blinding rows and `HidingFriPcs`).
* **$\text{Game}_2$:** Replace $\Pi_L^*$ with lattice $\Sigma$-protocol simulator $\mathcal{S}_L$ (statistical ZK via 15-sigma FACCT rejection sampling, $\Delta < 2^{-149.5}$).
* **$\text{Game}_3$:** Replace bridge commitment $B^*$ with uniform random polynomial vector in $R_{q_{\text{LoTRS}}}^2$ (under Module-LWE).
* **$\text{Game}_4$:** Replace nullifier $\nu^*$ with uniform random 384-bit string.

### Zhandry Compressed Oracle Reduction:
By the Compressed Oracle Theorem (Zhandry 2019):
$$|\operatorname{Pr}[S_4] - \operatorname{Pr}[S_3]| \le \frac{2 \pi^2 (q_H + 1)^2}{2^{h}}$$

* **Profile 1 ($h = 256\text{ bits}$):**
  * For $q_H \le 2^{61.8}$: $\mathbf{Adv}^{\text{QROM}} \le \mathbf{2^{-128.0}}$ (**128-bit PQ security**).
  * For $q_H = 2^{64.0}$: $\mathbf{Adv}^{\text{QROM}} \le \mathbf{2^{-123.7}}$ (**123.7 bits min-entropy**).
* **Profile 2 ($h = 288\text{ bits}$, $\mathbf{m}_x \in R_q^2$):**
  * For $q_H = 2^{64.0}$: $\mathbf{Adv}^{\text{QROM}} \le \mathbf{2^{-155.7}} \ll \mathbf{2^{-128}}$ (**128+ bit PQ security**).

### Theorem 3 (Unlinkability Bound)
$$\mathbf{Adv}^{\text{UNLINK}}(\mathcal{A}) \le \mathbf{Adv}^{\text{ZK-STARK}} + \mathbf{Adv}^{\text{ZK-}\Sigma} + 2 \mathbf{Adv}^{\text{MLWE}} + \frac{2 \pi^2 (q_H + 1)^2}{2^{h}}$$
$\blacksquare$

---

## 6. Byte-Level Performance Summary & Analytical Projection

```
┌────────────────────────────────────────────────────────────────────────┐
│               0PSP POST-AUDIT ANALYTICAL SIZE PROJECTION               │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 1: Extended Lattice Signature (Π_L)                              │
│   - Baseline LoTRS (N=100, T=50):                   54,815 B (53.53 KiB)│
│   - 6 Added Scalar Polys (Profile 1, packed):        6,912 B  (6.75 KiB)│
│   - Layer 1 Total (Profile 1, Packed):              61,727 B (60.28 KiB)│
│   - [Layer 1 Total (Profile 2, 7 polys packed):     62,879 B (61.41 KiB)]│
│                                                                        │
│ Layer 2: STARK (Π_H, N_q=86, SHAKE-256-384, 4 ZK rows)                │
│   - 86 queries × 8 layers × 48 B Merkle paths:      33,024 B (32.25 KiB)│
│   - Trace Openings at query points (ZK blinded):    22,880 B (22.34 KiB)│
│   - Commitment Roots, Final Poly, Public Inputs:     3,840 B  (3.75 KiB)│
│   - Layer 2 Total:                                  59,744 B (58.34 KiB)│
├────────────────────────────────────────────────────────────────────────┤
│ TOTAL COMBINED PROJECTION (Profile 1, Packed):     121,471 B (118.62 KiB)│
│ TOTAL COMBINED PROJECTION (Profile 2, Packed):     122,623 B (119.75 KiB)│
└────────────────────────────────────────────────────────────────────────┘
```

> [!CAUTION]
> **Analytical Projection Notice:**  
> The $\approx 118.62\text{ KiB}$ size is strictly an analytical projection based on LoTRS v2 parameters ($N=100, T=50$) and conservative Plonky3 FRI parameters ($N_q = 86$). It does not constitute a measured benchmark until an end-to-end compiled prototype is evaluated.
