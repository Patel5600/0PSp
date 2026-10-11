# Cross-Layer Composition Theorem & Security Reductions

**Document Version:** 2.1 (Post-Review Reconciled)  
**Phase:** 1 (Formal Security Reductions)  
**Date:** October 2026  
**Status:** Cryptographic reduction theorem with Zhandry Compressed Oracle QROM bound, explicit Module-SIS witness bounds, and byte-level size accounting.

---

## 1. Executive Summary

This document formalizes the central mathematical theorem of the 0PSP primitive: **The Cross-Layer Composition Theorem**.

Following the Phase 1 Consistency Audit Revision 2 (`docs/audit/phase1-consistency-audit.md`), this revision:
1. Formulates the exact Module-SIS witness bounds under the native LoTRS modulus $q_{\text{LoTRS}} = 2^{43} - 67$.
2. Formulates the 15-sigma deterministic truncation bound $B_{w, \infty} = 15 \sigma_w$ with Gaussian tail failure probability $< 2^{-149.5}$.
3. Clarifies the QROM advantage bound: $\mathbf{Adv}^{\text{QROM}} \le 2^{-123.7}$ under $q_H = 2^{64}$, establishing strict $\le 2^{-128}$ advantage for $q_H \le 2^{61.8}$ or via secret expansion.
4. Derives the combined analytical proof projection at **$\approx 118.12\text{ KiB}$** (compressed) / **$\approx 119.43\text{ KiB}$** (uncompressed).

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

## 3. The Cross-Layer Composition Theorem

### Theorem 1 (Cross-Layer Witness Extraction & Binding)
*Assume $\Pi_L$ has special soundness error $\epsilon_L$ with extractor $\mathcal{E}_L$, $\Pi_H$ has knowledge error $\epsilon_H$ with extractor $\mathcal{E}_H$, and $\operatorname{Com}_{\text{bridge}}$ is secure under $\text{Module-SIS}_{2, 3, q_{\text{LoTRS}}, \beta}$ with bound $\beta = 6 \sqrt{3 n} \approx 166.5$.*

*For any quantum polynomial-time adversary $\mathcal{A}$ that outputs a valid tuple $(S, \Pi_L, \Pi_H)$ with probability $\epsilon > \max(\epsilon_L, \epsilon_H)$, there exists a polynomial-time extractor $\mathcal{E}$ that extracts:*
$$w = (j, C_j, pk_j, v, \text{coin\_id}, r_{\text{nf}}, \rho, \boldsymbol{\tau}_B)$$
*such that with probability at least $\epsilon - \epsilon_L - \epsilon_H - \mathbf{Adv}^{\text{MSIS}}(\mathcal{B})$:*
1. $j \in [N]$ and $C_j \in R_C$.
2. $C_j = \operatorname{Com}_{\text{coin}}(pk_j, v, \text{coin\_id}, r_{\text{nf}}; \rho) \pmod{q_{\text{LoTRS}}}$.
3. $\nu = \text{SHAKE256}_{384}(\mathsf{domain}_{\text{null}} \parallel \text{coin\_id} \parallel r_{\text{nf}})$.
4. $pk_j$ has valid threshold custody authorization over $M$.

### Proof:
1. **Extraction from Layer 1 ($\Pi_L$):**
   By special soundness of the $\Sigma$-protocol (with 15-sigma deterministic truncation $B_{w, \infty} = 15 \sigma_w$), extractor $\mathcal{E}_L$ runs $\mathcal{A}$ with rewound challenges to obtain two accepting transcripts, extracting a witness:
   $$w_L = (j, C_j, pk_j, v, \text{coin\_id}_L, r_{\text{nf}, L}, \rho_L, \boldsymbol{\tau}_{B, L})$$
   satisfying $C_j \in R_C$ and $B \equiv \mathbf{A}_1 m_{x, L} + \mathbf{A}_2 \boldsymbol{\tau}_{B, L} \pmod{q_{\text{LoTRS}}}$, where $m_{x, L} = \operatorname{EncodeNF}(\text{coin\_id}_L, r_{\text{nf}, L})$.

2. **Extraction from Layer 2 ($\Pi_H$):**
   By the knowledge soundness of the zero-knowledge STARK and the **14-bit multi-limb integer equality proof** ($v_i - s_i - c_{i-1} + W c_i = 0$, $|\Delta_{\max}| < p$, proving zero modular wraparound), extractor $\mathcal{E}_H$ extracts from the trace:
   $$w_H = (\text{coin\_id}_H, r_{\text{nf}, H}, \boldsymbol{\tau}_{B, H})$$
   satisfying:
   * $\nu = \text{SHAKE256}_{384}(\mathsf{domain}_{\text{null}} \parallel \text{coin\_id}_H \parallel r_{\text{nf}, H})$.
   * $B \equiv \mathbf{A}_1 m_{x, H} + \mathbf{A}_2 \boldsymbol{\tau}_{B, H} \pmod{q_{\text{LoTRS}}}$.
   * Range bounds: $\|m_{x, H}\|_\infty \le 3$ and $\|\boldsymbol{\tau}_{B, H}\|_\infty \le \eta = 2$.

3. **Explicit Module-SIS Difference Vector Bound:**
   Suppose $m_{x, L} \ne m_{x, H}$. Subtracting the two extracted bridge equations:
   $$\mathbf{A}_1 (m_{x, L} - m_{x, H}) + \mathbf{A}_2 (\boldsymbol{\tau}_{B, L} - \boldsymbol{\tau}_{B, H}) \equiv \mathbf{0} \pmod{q_{\text{LoTRS}}}$$
   Define $\mathbf{v}_{\text{diff}} = (\Delta \mathbf{m}, \Delta \boldsymbol{\tau}) \in R_{q_{\text{LoTRS}}}^{1 + 2} = R_q^3$.
   * Non-zeroness: $m_{x, L} \ne m_{x, H} \implies \Delta \mathbf{m} \ne 0 \implies \mathbf{v}_{\text{diff}} \ne \mathbf{0}$.
   * Exact Norm Bounds:
     * Message difference: $\|\Delta \mathbf{m}\|_\infty \le \|m_{x, L}\|_\infty + \|m_{x, H}\|_\infty \le 3 + 3 = 6$.
     * Randomness difference: For CBD noise with parameter $\eta = 2$, $\|\Delta \boldsymbol{\tau}\|_\infty \le 2 + 2 = 4$.  
       *(If discrete Gaussian noise with $\tau_{\text{cut}}=15, \sigma=2$ is used, $\|\Delta \boldsymbol{\tau}\|_\infty \le 60$.)*
     * Euclidean norm bound:
       $$\|\mathbf{v}_{\text{diff}}\|_2 \le \sqrt{6^2 \cdot 256 + 4^2 \cdot (2 \cdot 256)} = \sqrt{9,216 + 8,192} \approx 131.9 \le \beta = 166.5$$
   * Since $q_{\text{LoTRS}} = 2^{43} - 67 \approx 8.79 \times 10^{12} \gg 166.5$, $\mathbf{v}_{\text{diff}}$ is a non-trivial short SIS vector.
   * Therefore, $\operatorname{Pr}[m_{x, L} \ne m_{x, H}] \le \mathbf{Adv}^{\text{MSIS}}(\mathcal{B})$.

4. **Bijective Encoding:**
   Since $\operatorname{EncodeNF}$ is strictly injective, $m_{x, L} = m_{x, H}$ implies $(\text{coin\_id}_L, r_{\text{nf}, L}) = (\text{coin\_id}_H, r_{\text{nf}, H})$. $\blacksquare$

---

## 4. Double-Spend Resistance Reduction

### Theorem 2 (Double-Spend Resistance)
*No polynomial-time adversary $\mathcal{A}$ can produce two valid spending transactions $T^{(1)}$ and $T^{(2)}$ for the same coin commitment $C \in R_C$ with different nullifiers $\nu^{(1)} \ne \nu^{(2)}$, except with probability bounded by:*
$$\mathbf{Adv}^{\text{DoubleSpend}}(\mathcal{A}) \le 2 \epsilon_{\text{sound}} + 2 \mathbf{Adv}^{\text{MSIS}}(\mathcal{B}) + \mathbf{Adv}^{\text{CoinBind}}(\mathcal{B}) + \mathbf{Adv}^{\text{Coll}}_{\text{SHAKE256}}$$

---

## 5. Spender Anonymity & Unlinkability in the QROM

We formulate the game $\text{Game}_{\mathcal{A}}^{\text{UNLINK}}(b)$ with challenge bit $b \in \{0, 1\}$.

### Sequence of Games:
* **$\text{Game}_0$:** Real spend game with coin $C_b$.
* **$\text{Game}_1$:** Replace $\Pi_H^*$ with STARK zero-knowledge simulator $\mathcal{S}_H$.
* **$\text{Game}_2$:** Replace $\Pi_L^*$ with lattice $\Sigma$-protocol simulator $\mathcal{S}_L$.
* **$\text{Game}_3$:** Replace bridge commitment $B^*$ with uniform random polynomial vector in $R_{q_{\text{LoTRS}}}^2$ (under Module-LWE).
* **$\text{Game}_4$:** Replace nullifier $\nu^*$ with uniform random 384-bit string.

### Rigorous QROM Reduction via Compressed Oracle:
In $\text{Game}_4$, the secret $r_{\text{nf}, b} \leftarrow \{0, 1\}^{256}$ is uniformly distributed and unrevealed.  
By the **Compressed Oracle Theorem** (Zhandry 2019, Czajkowski et al. 2019):
$$|\operatorname{Pr}[S_4] - \operatorname{Pr}[S_3]| \le \frac{2 \pi^2 (q_H + 1)^2}{2^{|r_{\text{nf}}|}}$$

* **Evaluation under 256-bit secret and $q_H = 2^{64}$:**
  $$\frac{2 \pi^2 (2^{64} + 1)^2}{2^{256}} \approx \frac{19.74 \times 2^{128}}{2^{256}} \approx \mathbf{2^{-123.7}}$$
* **Query Budget for Strict $2^{-128}$ Soundness:**
  $$q_H \le \frac{2^{64}}{\sqrt{2 \pi^2}} \approx \mathbf{2^{61.8}\text{ queries}}$$
* **Alternative Secret Expansion:** Expanding $r_{\text{nf}}$ to 264 bits achieves $\le 2^{-131.7} \ll 2^{-128}$ for full $q_H = 2^{64}$.

### Theorem 3 (Unlinkability Bound)
$$\mathbf{Adv}^{\text{UNLINK}}(\mathcal{A}) \le \mathbf{Adv}^{\text{ZK-STARK}} + \mathbf{Adv}^{\text{ZK-}\Sigma} + 2 \mathbf{Adv}^{\text{MLWE}} + \frac{2 \pi^2 (q_H + 1)^2}{2^{256}}$$

For $q_H \le 2^{61.8}$, the reduction establishes **128-bit quantum unlinkability**; for $q_H \le 2^{64}$, it establishes **123.7 bits of quantum min-entropy security**. $\blacksquare$

---

## 6. Byte-Level Performance Summary & Analytical Projection

```
┌────────────────────────────────────────────────────────────────────────┐
│               0PSP POST-AUDIT ANALYTICAL SIZE PROJECTION               │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 1 Extended Lattice Signature (Π_L):                              │
│   - Baseline LoTRS (N=100, T=50):                   54,815 B (53.53 KiB)│
│   - 6 Added Scalar Polys (36-bit packed):            6,912 B  (6.75 KiB)│
│   - Layer 1 Total (Packed):                         61,727 B (60.28 KiB)│
│   - [Layer 1 Total (43-bit uncompressed):           63,071 B (61.59 KiB)]│
│                                                                        │
│ Layer 2 STARK (Π_H, N_q=86, SHAKE-256-384 Merkle):                    │
│   - 86 queries × 8 layers × 48 B Merkle paths:      33,024 B (32.25 KiB)│
│   - Trace Openings at query points:                 22,360 B (21.84 KiB)│
│   - Commitment Roots, Final Poly, Public Inputs:     3,840 B  (3.75 KiB)│
│   - Layer 2 Total:                                  59,224 B (57.84 KiB)│
├────────────────────────────────────────────────────────────────────────┤
│ TOTAL COMBINED PROJECTION (Packed):                120,951 B (118.12 KiB)│
│ TOTAL COMBINED PROJECTION (Uncompressed):          122,295 B (119.43 KiB)│
└────────────────────────────────────────────────────────────────────────┘
```

> [!CAUTION]
> **Analytical Projection Notice:**  
> The $\approx 118.12\text{ KiB}$ size is strictly an analytical projection pending empirical compilation and measurement on a reference implementation.
