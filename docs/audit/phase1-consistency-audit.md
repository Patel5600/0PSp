# 0PSP Phase 1: Mathematical Consistency Audit (Revision 2)

**Document Version:** 2.0 (Post-Review Reconciled)  
**Phase:** 1 (Formal Adversarial Audit & Soundness Closure)  
**Date:** October 2026  
**Status:** Focused audit closing the algebraic, probabilistic, and cryptographic findings from the independent review.

---

## Executive Summary & Review Findings Addressed

Following an independent adversarial review of Audit Revision 1, six specific mathematical, cryptographic, and accounting corrections have been implemented:

1. **BabyBear AIR Recurrence Sign Error Fixed:** The carry-chain recurrence relation for base-$W$ limb accumulation was inverted in Revision 1. The corrected column recurrence $v_i - s_i - c_{i-1} + W c_i = 0$ is proven, and the residual bound is recomputed.
2. **QROM Unlinkability Budget Clarified:** The Zhandry bound $\mathbf{Adv}^{\text{QROM}} \le 2 \pi^2 (q_H+1)^2 / 2^{256} \approx 2^{-123.7}$ under $q_H = 2^{64}$ is formally bounded. We specify the query cap $q_H \le 2^{61.8}$ for achieving strict $2^{-128}$ advantage, and document the entropy expansion requirement for $q_H = 2^{64}$.
3. **Conservative FRI Soundness Enforced:** Under the proven conservative bound $(1/8)^{N_{\text{queries}}/2}$, 74 queries yield only $2^{-111}$. We expand query rounds to $N_{\text{queries}} = 86$ to achieve provable $(1/8)^{43} = 2^{-129} \le 2^{-128}$ soundness.
4. **Merkle Hash Function Corrected:** BLAKE3's internal 256-bit chaining state caps its quantum collision search at $O(2^{256/3}) \approx 2^{85.3}$. We mandate **SHAKE-256 with 384-bit output (capacity 512 bits)**, achieving genuine $T_{\text{BHT}} = 2^{384/3} = 2^{128}$ quantum collision resistance.
5. **Exact Witness Dimensions & 15-Sigma Truncation:** We disambiguate the Layer 1 witness ($1 + 1 + 2 + 2 = 6$ scalar ring elements over $R_{q_{\text{LoTRS}}}$) and raise Gaussian truncation to $\tau_{\text{cut}} = 15\sigma_w$, reducing tail failure probability to $< 2^{-149.5}$.
6. **Byte-Level Proof Size Accounting:** Corrected unit errors (decimal kB vs binary KiB) and re-derived the total analytical proof size projection at **$\approx 118.12\text{ KiB}$** (compressed) / **$\approx 119.43\text{ KiB}$** (uncompressed).

---

## Pass 1: Layer 1 Dimensions, Response Encoding & 15-Sigma Truncation

### 1.1 Disambiguated Witness Dimensions
In the extended relation $\mathbf{M}_{\text{spend}} \mathbf{w} \equiv \mathbf{u}_j \pmod{q_{\text{LoTRS}}}$, the additional spend witness consists of:
* $m_v \in R_{q_{\text{LoTRS}}}^1$: 1 scalar ring element (coin value polynomial)
* $m_x \in R_{q_{\text{LoTRS}}}^1$: 1 scalar ring element (canonical nullifier polynomial, $\|m_x\|_\infty \le 3$)
* $\boldsymbol{\rho} \in R_{q_{\text{LoTRS}}}^{k_\rho}$: $k_\rho = 2$ scalar ring elements (coin commitment randomness vector)
* $\boldsymbol{\tau}_B \in R_{q_{\text{LoTRS}}}^{k_\tau}$: $k_\tau = 2$ scalar ring elements (bridge commitment randomness vector)

**Total Added Witness Dimension:** Exactly $1 + 1 + 2 + 2 = \mathbf{6\text{ scalar ring elements}}$ in $R_{q_{\text{LoTRS}}}$.

### 1.2 Response Size Accounting: Fixed-Width vs Bounded Packing
For 6 scalar ring elements of degree $n = 256$:
* **Dense Fixed-Width (43 bits/coeff):**
  $$\text{Bytes} = \frac{6 \times 256 \times 43}{8} = 8,256\text{ bytes} = \mathbf{8.0625\text{ KiB}}$$
* **Bounded Canonical Packing (36 bits/coeff):**
  Under rejection sampling, responses satisfy $\|\mathbf{z}_{\mathbf{w}}\|_\infty \le B_{w, \infty} = 15 \sigma_w \approx 3.0 \times 10^8 < 2^{29}$.
  Centering responses into $[-B_{w, \infty}, B_{w, \infty}]$ enables packed serialization at $\le 36\text{ bits}$ per coefficient:
  $$\text{Bytes} = \frac{6 \times 256 \times 36}{8} = 6,912\text{ bytes} = \mathbf{6.75\text{ KiB}}$$
* Adding to the LoTRS v2 baseline signature ($54,815\text{ bytes} = 53.53\text{ KiB}$):
  * **Compressed Projected Size:** $54,815 + 6,912 = 61,727\text{ bytes} = \mathbf{60.28\text{ KiB}}$
  * **Uncompressed Projected Size:** $54,815 + 8,256 = 63,071\text{ bytes} = \mathbf{61.59\text{ KiB}}$

### 1.3 15-Sigma Deterministic Truncation & Soundness Margin
To eliminate Gaussian tail failure while maintaining a robust security margin:
* We enforce a cut-off bound at $\tau_{\text{cut}} = 15$:
  $$B_{w, \infty} = 15 \sigma_w$$
* **Gaussian Tail Bound (Union Bound over $3,584$ coordinates):**
  $$\operatorname{Pr}[\|\mathbf{z}_{\mathbf{w}}\|_\infty > 15 \sigma_w] \le 3,584 \times 2 e^{-15^2/2} = 7,168 \times e^{-112.5} \approx 7,168 \times 2^{-162.3} \approx \mathbf{2^{-149.5}}$$
  This leaves **$21.5\text{ bits}$ of margin below $2^{-128}$**, absorbing reduction losses and composite protocol errors.
* **Wraparound Safety Margin:**
  For $\sigma_w \approx 2 \times 10^7$:
  $$B_{w, \infty} \approx 3.0 \times 10^8 \ll \frac{q_{\text{LoTRS}}}{2} \approx 4.4 \times 10^{12}$$
  The response bound is smaller than $q_{\text{LoTRS}}/2$ by a factor of $> 14,000$, proving that responses never wrap modulo $q_{\text{LoTRS}}$.

---

## Pass 2: Corrected Integer Carry Recurrence in BabyBear AIR

### 2.1 The Algebraic Recurrence Derivation
We verify the integer identity:
$$V_{k, d} = K_{k, d} \cdot q_{\text{LoTRS}} + B_{k, d}$$
over radix $W = 2^{14} = 16,384$.

Let the right-hand column sum at limb index $i$ be:
$$s_i = \sum_{j=0}^{\min(i, 2)} k_j q_{i-j} + b_i \in \mathbb{Z}$$
In standard base-$W$ column addition, the sum of incoming carry $c_{i-1}$ and column value $s_i$ must equal the output limb $v_i$ plus the outgoing carry $W \cdot c_i$:
$$s_i + c_{i-1} = v_i + W \cdot c_i$$
with boundary conditions $c_{-1} = 0$, $c_4 = 0$.

Rearranging to the canonical AIR transition constraint:
$$\boxed{v_i - s_i - c_{i-1} + W \cdot c_i = 0}$$

> [!NOTE]
> **Sign Correction:** Revision 1 erroneously reported $v_i - s_i + c_{i-1} - W c_i = 0$, inverting the carry signs. The corrected formula reflects canonical base-$W$ addition.

### 2.2 Quotient Bound Enforcement & Carry Sizing
1. **Quotient Bounds:**
   Negacyclic polynomial products satisfy $|V_{k, d}| \le 1,792 q_{\text{LoTRS}}$.
   Thus $|K_{k, d}| \le 1,792$.
   We shift the quotient:
   $$K' = K + 1,792 \in [0, 3,584]$$
   Because $3,584 < 4,096 = 2^{12} < W = 2^{14}$, $K'$ is represented by **a single 14-bit limb**:
   $$k_0 = K' - 1,792 \in [-1,792, 1,792], \quad k_1 = k_2 = k_3 = 0$$
   The AIR strictly enforces $K' \in [0, 3,584]$ via a 12-bit range lookup.
2. **Carry Bounds:**
   Maximum column sum:
   $$s_i \le 1,792 \times (W - 1) + (W - 1) = 1,793 \times 16,383 \approx 2.937 \times 10^7$$
   Outgoing carry:
   $$c_i = \left\lfloor \frac{s_i + c_{i-1} - v_i}{W} \right\rfloor \le \left\lfloor \frac{2.937 \times 10^7 + 1,793}{16,384} \right\rfloor \le 1,793 < 2^{11}$$
   Every carry $c_i$ satisfies $0 \le c_i \le 1,793 \ll W = 16,384$.
3. **Maximum Residual Calculation:**
   The maximum possible absolute value of the left-hand constraint expression in $\mathbb{Z}$ is:
   $$\Delta_{\max} = \max |v_i - s_i - c_{i-1} + W \cdot c_i| < W + s_{\max} + c_{\max} + W \cdot c_{\max}$$
   $$\Delta_{\max} < 16,384 + 2.937 \times 10^7 + 1,793 + (16,384 \times 1,793) \approx 5.88 \times 10^7$$
   Comparing with the BabyBear prime $p = 2^{31} - 2^{27} + 1 = 2,013,265,921$:
   $$\Delta_{\max} \approx 5.88 \times 10^7 \ll p = 2.01 \times 10^9 \quad \left(\frac{p}{\Delta_{\max}} \approx 34.2\right)$$
   Because $|\Delta_{\max}| < p$, any field equality $\Delta \equiv 0 \pmod p$ forces $\Delta = 0$ **identically in $\mathbb{Z}$**. Modular wraparound is mathematically impossible.

---

## Pass 3: Quantum Soundness, FRI Parameters & Corrected Merkle Hash

### 3.1 QROM Unlinkability Reduction
By the Zhandry Compressed Oracle Theorem:
$$\mathbf{Adv}^{\text{QROM}}(\mathcal{A}) \le \frac{2 \pi^2 (q_H + 1)^2}{2^{|r_{\text{nf}}|}}$$

For standard 256-bit secret randomness ($|r_{\text{nf}}| = 256$):
* At $q_H = 2^{64}$:
  $$\mathbf{Adv}^{\text{QROM}}(\mathcal{A}) \le \frac{2 \pi^2 (2^{64} + 1)^2}{2^{256}} \approx \frac{19.74 \times 2^{128}}{2^{256}} \approx 20 \times 2^{-128} \approx \mathbf{2^{-123.7}}$$
* To achieve strict $\mathbf{Adv}^{\text{QROM}} \le 2^{-128}$, the quantum query budget must satisfy:
  $$q_H \le \sqrt{\frac{2^{256} \cdot 2^{-128}}{2 \pi^2}} = \frac{2^{64}}{\sqrt{2 \pi^2}} \approx \frac{2^{64}}{4.44} \approx \mathbf{2^{61.8}\text{ queries}}$$
* Alternatively, to support $q_H = 2^{64}$ with strict $\le 2^{-128}$ advantage, the secret must be expanded to $|r_{\text{nf}}| \ge 261\text{ bits}$ (e.g. 264 bits across two message polynomials).
* **Audit Mandate:** We explicitly record that for 256-bit secrets under $q_H = 2^{64}$, the advantage bound is **$2^{-123.7}$** (representing 123.7 bits of quantum min-entropy), and not $2^{-128}$.

### 3.2 Conservative FRI Soundness Calculation
Under Plonky3's proven conservative soundness bound for code rate $R = 1/\rho = 1/8$:
$$\epsilon_{\text{FRI}} \le R^{N_{\text{queries}} / 2} = (1/8)^{N_{\text{queries}} / 2} = 2^{-3 \cdot (N_{\text{queries}} / 2)}$$
* For 74 queries: $\epsilon_{\text{FRI}} \le 2^{-3 \cdot 37} = 2^{-111}$ (**Fails 128-bit soundness**).
* To achieve $\epsilon_{\text{FRI}} \le 2^{-128}$:
  $$\frac{3 \cdot N_{\text{queries}}}{2} \ge 128 \implies N_{\text{queries}} \ge \frac{256}{3} \approx 85.33 \implies \mathbf{N_{\text{queries}} = 86\text{ queries}}$$
* For $N_{\text{queries}} = 86$:
  $$\epsilon_{\text{FRI}} \le (1/8)^{43} = \mathbf{2^{-129} \le 2^{-128}}$$
* Combined with $e_{\text{grind}} = 16$ bits of proof-of-work grinding, conservative soundness reaches $129 + 16 = 145$ bits.

### 3.3 Hash Function Correction: SHAKE-256-384 vs BLAKE3
* BLAKE3 uses a 256-bit internal chaining state. Squeezing longer output does not increase collision resistance beyond 256 bits ($T_{\text{BHT}} \approx 2^{85.3}$).
* **Mandated Primitive:** **SHAKE-256 with 384-bit output (48 bytes)**.
  * Capacity: $c = 512\text{ bits}$.
  * Quantum collision query complexity: $\min(2^{c/2}, 2^{b/3}) = \min(2^{256}, 2^{384/3}) = \mathbf{2^{128}\text{ operations}}$.
  * Satisfies genuine 128-bit post-quantum collision resistance.

---

## Pass 4: Byte-Level Proof Size Accounting

All calculations are derived in exact byte counts ($1\text{ KiB} = 1,024\text{ bytes}$):

### Layer 2 STARK ($\Pi_H$) Byte Breakdown ($N_{\text{queries}} = 86$, 8 layers, 48-byte digests):
1. **Merkle Query Paths:**
   $$86 \text{ queries} \times 8 \text{ layers} \times 48 \text{ bytes} = 33,024\text{ bytes} = \mathbf{32.25\text{ KiB}}$$
2. **Trace Openings at Query Points:**
   $$86 \text{ queries} \times \approx 260\text{ bytes/query} = 22,360\text{ bytes} = \mathbf{21.84\text{ KiB}}$$
3. **Commitment Roots:**
   $$13 \text{ roots} \times 48\text{ bytes} = 624\text{ bytes} = \mathbf{0.61\text{ KiB}}$$
4. **FRI Final Polynomial:**
   $$64\text{ bytes} = \mathbf{0.06\text{ KiB}}$$
5. **Public Inputs ($B, \nu, M$):**
   $$3,152\text{ bytes} = \mathbf{3.08\text{ KiB}}$$
* **Total Layer 2 STARK Size:**
  $$33,024 + 22,360 + 624 + 64 + 3,152 = 59,224\text{ bytes} = \mathbf{57.84\text{ KiB}}$$

### Layer 1 Extended Lattice Signature ($\Pi_L$):
* LoTRS v2 Baseline ($N=100, T=50$): $54,815\text{ bytes} = \mathbf{53.53\text{ KiB}}$
* 6 Added Scalar Ring Elements ($m_v, m_x, \boldsymbol{\rho}, \boldsymbol{\tau}_B$):
  * Packed (36 bits/coeff): $6,912\text{ bytes} = \mathbf{6.75\text{ KiB}}$
  * Fixed-width (43 bits/coeff): $8,256\text{ bytes} = \mathbf{8.06\text{ KiB}}$
* **Total Layer 1 Size:**
  * Packed: $54,815 + 6,912 = 61,727\text{ bytes} = \mathbf{60.28\text{ KiB}}$
  * Fixed-width: $54,815 + 8,256 = 63,071\text{ bytes} = \mathbf{61.59\text{ KiB}}$

### Combined Proof Package Analytical Projection:
$$\text{Size}_{\text{total}} = 60.28\text{ KiB} + 57.84\text{ KiB} = \mathbf{118.12\text{ KiB}} \quad (\text{Packed})$$
$$\text{Size}_{\text{total}} = 61.59\text{ KiB} + 57.84\text{ KiB} = \mathbf{119.43\text{ KiB}} \quad (\text{Fixed-width})$$

> [!CAUTION]
> **Analytical Projection Notice:**  
> The $\approx 118\text{--}119\text{ KiB}$ size is strictly an analytical projection based on LoTRS v2 parameters ($N=100, T=50$) and conservative Plonky3 FRI parameters ($N_q = 86$).  
> It does not constitute a measured benchmark until an end-to-end compiled prototype is evaluated.
