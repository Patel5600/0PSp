# Layer 2 (STARK) AIR Constraint & Soundness Specification (Π_H)

**Document Version:** 2.1 (Post-Review Reconciled)  
**Phase:** 1 (Cryptographic Specification & Feasibility)  
**Date:** October 2026  
**Status:** Reconciled AIR constraint specification featuring verified multi-limb carry chains, conservative FRI parameters, and SHAKE-256-384 Merkle commitments.

---

## 1. Executive Summary

Layer 2 ($\Pi_H$) is a **zero-knowledge STARK** that proves:
1. Canonical bit-to-polynomial chunking: $\mathbf{m}_x = \operatorname{EncodeNF}(\text{coin\_id}, r_{\text{nf}})$ with $c_i \in \{0, 1, 2, 3\}$.
2. Bridge commitment consistency: $\mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B \equiv B \pmod{q_{\text{LoTRS}}}$ over $R_q$ via **zero-wraparound multi-limb carry chains**.
3. Nullifier correctness: $\nu = \text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id} \parallel r_{\text{nf}})$ via exactly 1 Keccak-$f[1600]$ permutation.

Following the adversarial review of Audit Revision 1, this specification incorporates:
* A corrected **canonical base-$W$ carry-chain recurrence** ($v_i - s_i - c_{i-1} + W c_i = 0$).
* Conservative FRI query sizing ($N_{\text{queries}} = 86$) establishing $\epsilon_{\text{FRI}} \le (1/8)^{43} = 2^{-129} \le 2^{-128}$.
* **SHAKE-256-384** Merkle tree commitments providing genuine $T_{\text{BHT}} = 2^{128}$ quantum collision resistance.

---

## 2. Base Field & Arithmetic Embedding

* **Primary STARK Base Field:** **BabyBear** ($\mathbb{F}_p$)
  $$p = 2^{31} - 2^{27} + 1 = 2,013,265,921 \quad (\approx 2^{30.9})$$
* **Ring Modulus:** LoTRS production modulus $q_{\text{LoTRS}} = 2^{43} - 67$.
* **Arithmetic Challenge:** Since $q_{\text{LoTRS}} > p$ and unreduced negacyclic integer products reach $\approx 1.57 \times 10^{16} \gg p$, arithmetic modulo $q$ is verified via bounded 14-bit integer limbs to prevent modular wraparound.

---

## 3. AIR Constraint System Specification

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PLONKY3 AIR TRACE ARCHITECTURE                  │
├────────────────────────────────────────────────────────────────────────┤
│  Trace Segment 1: Keccak-f[1600] Engine (24 rows)                      │
│    - 1,600 state bit columns                                           │
│    - Degree-2 χ-step transition constraints: 38,400 total gates        │
│                                                                        │
│  Trace Segment 2: Canonical 2-Bit Chunking Engine (256 rows)           │
│    - Unpacks 512-bit secret x into 256 coefficients c_i ∈ {0,1,2,3}    │
│    - Degree-2 boolean decomposition: c_i = b_{2i} + 2·b_{2i+1}         │
│                                                                        │
│  Trace Segment 3: 14-Bit Multi-Limb Integer Equality Engine (256 rows) │
│    - Evaluates V_{k,d} = K_{k,d} · q + B_{k,d} via 4-limb carry chains │
│    - Verified zero modular wraparound (|Δ_max| < p)                    │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 3.1 Sub-System 1: Keccak-f[1600] AIR Constraints
* **Preimage:** Exactly 90 bytes ($\mathsf{domain}_{\text{null}} \parallel \text{coin\_id} \parallel r_{\text{nf}}$). Fits within the 136-byte SHAKE-256 rate block.
* **Permutations:** **Exactly 1 Keccak-$f[1600]$ permutation**.
* **Non-Linear Constraints:** 24 rounds $\times$ 1,600 quadratic $\chi$-gates $= \mathbf{38,400\text{ constraints}}$.

---

### 3.2 Sub-System 2: Canonical 2-Bit Chunking Constraints
For each $i \in [0, 255]$:
$$b_{2i} \cdot (1 - b_{2i}) = 0 \quad (\text{degree 2})$$
$$b_{2i+1} \cdot (1 - b_{2i+1}) = 0 \quad (\text{degree 2})$$
$$c_i - (b_{2i} + 2 \cdot b_{2i+1}) = 0 \quad (\text{degree 1})$$
Enforces $c_i \in \{0, 1, 2, 3\}$, guaranteeing $\|m_x\|_\infty \le 3$.

---

### 3.3 Sub-System 3: Verified Multi-Limb Quotient Engine

To prove:
$$V_{k, d} = K_{k, d} \cdot q_{\text{LoTRS}} + B_{k, d} \quad \text{identically in } \mathbb{Z}$$

#### Limb Parameterization:
* Radix: $W = 2^{14} = 16,384$.
* Decompose quantities into 14-bit integer limbs:
  $$V_{k, d} = \sum_{i=0}^3 v_i W^i, \quad q = \sum_{i=0}^3 q_i W^i, \quad B_{k, d} = \sum_{i=0}^3 b_i W^i$$
  where each limb is range-checked to $[0, W-1]$.

#### Quotient Bounds:
Because $|V_{k, d}| \le 1,792 q$, the quotient satisfies $|K_{k, d}| \le 1,792$.  
We shift $K' = K + 1,792 \in [0, 3,584]$.  
Because $3,584 < W = 16,384$, $K'$ is represented by **a single 14-bit limb**:
$$k_0 = K' - 1,792 \in [-1,792, 1,792], \quad k_1 = k_2 = k_3 = 0$$
The AIR enforces $K' \in [0, 3,584]$ via a 12-bit range check.

#### Column Addition & Corrected Carry Recurrence:
Define the right-hand column sum at limb index $i$:
$$s_i = \sum_{j=0}^{\min(i, 2)} k_j q_{i-j} + b_i \in \mathbb{Z}$$
In base-$W$ column addition:
$$s_i + c_{i-1} = v_i + W \cdot c_i$$
with boundary conditions $c_{-1} = 0$, $c_4 = 0$.

Rearranging to the canonical transition constraint enforced in $\mathbb{F}_p$:
$$\boxed{v_i - s_i - c_{i-1} + W \cdot c_i = 0 \pmod p}$$

#### Carry Bounds & Zero Wraparound Proof:
* Maximum column sum: $s_i \le 1,792 \times (W - 1) + (W - 1) \approx 2.937 \times 10^7$.
* Carry bound: $c_i = \lfloor (s_i + c_{i-1} - v_i) / W \rfloor \le 1,793 < 2^{11} \ll W$.
* Maximum residual in $\mathbb{Z}$:
  $$\Delta_{\max} = \max |v_i - s_i - c_{i-1} + W \cdot c_i| \approx 5.88 \times 10^7$$
* Comparing with BabyBear prime:
  $$\Delta_{\max} \approx 5.88 \times 10^7 \ll p = 2,013,265,921 \quad \left(\frac{p}{\Delta_{\max}} \approx 34.2\right)$$

> [!IMPORTANT]
> **Soundness Theorem:**  
> Because $|\Delta_{\max}| < p$, any field equality $\Delta \equiv 0 \pmod p$ forces $\Delta = 0$ **identically in $\mathbb{Z}$**.  
> Modular wraparound is mathematically impossible.

---

## 4. Post-Quantum Soundness: Conservative FRI & SHAKE-256-384

### 4.1 Merkle Hash Selection: Why SHAKE-256-384 is Required
* **BLAKE3 Inadequacy:** BLAKE3 uses a 256-bit internal chaining state. Squeezing longer output does not increase collision resistance beyond 256 bits, leaving quantum collision complexity capped at $T_{\text{BHT}} \approx 2^{256/3} \approx 2^{85.3}$.
* **Mandated Primitive:** **SHAKE-256 with 384-bit output (48 bytes)** (FIPS 202).
  * Capacity: $c = 512\text{ bits}$.
  * Quantum collision search complexity: $\min(2^{c/2}, 2^{b/3}) = \min(2^{256}, 2^{384/3}) = \mathbf{2^{128}\text{ operations}}$.
  * Satisfies genuine 128-bit post-quantum collision resistance.

### 4.2 Conservative FRI Parameterization
Under Plonky3's proven conservative soundness bound for code rate $R = 1/8$:
$$\epsilon_{\text{FRI}} \le (1/8)^{N_{\text{queries}} / 2} = 2^{-3 \cdot (N_{\text{queries}} / 2)}$$
To guarantee $\epsilon_{\text{FRI}} \le 2^{-128}$:
$$N_{\text{queries}} \ge \frac{256}{3} \approx 85.33 \implies \mathbf{N_{\text{queries}} = 86\text{ queries}}$$
For $N_{\text{queries}} = 86$:
$$\epsilon_{\text{FRI}} \le (1/8)^{43} = \mathbf{2^{-129} \le 2^{-128}}$$
Combined with $e_{\text{grind}} = 16$ bits of proof-of-work grinding, conservative soundness reaches $129 + 16 = 145$ bits.

---

## 5. Byte-Level Proof Size Accounting

All figures computed in exact binary kibibytes ($1\text{ KiB} = 1,024\text{ bytes}$):

```
┌────────────────────────────────────────────────────────────────────────┐
│                   LAYER 2 STARK (Π_H) PROOF SIZE (KiB)                 │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Trace Commitment Roots (3 Merkle roots × 48 bytes):       0.14 KiB  │
│ 2. Quotient Poly Commitments (2 roots × 48 bytes):            0.10 KiB  │
│ 3. FRI Commitments (8 layers × 48 bytes):                    0.38 KiB  │
│ 4. FRI Final Poly (degree < 4):                              0.06 KiB  │
│ 5. FRI Query Paths:                                                    │
│    - 86 queries × 8 layers × (48 bytes auth path):          32.25 KiB  │
│ 6. Trace Openings at Query Points:                                     │
│    - 86 queries × ~260 bytes opening data:                  21.84 KiB  │
│ 7. Public Inputs (B, nu, M):                                 3.08 KiB  │
├────────────────────────────────────────────────────────────────────────┤
│ TOTAL LAYER 2 STARK (Π_H) SIZE:                             ~57.84 KiB │
│ (59,224 bytes)                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

> [!CAUTION]
> **Performance Caveat:**  
> The $\approx 57.84\text{ KiB}$ size is an **analytical projection** based on conservative AIR parameters ($N_q = 86$, SHAKE-256-384).  
> It must be empirically measured on a compiled prototype before being cited as a confirmed benchmark.
