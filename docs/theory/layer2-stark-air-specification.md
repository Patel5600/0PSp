# Layer 2 (STARK) AIR Constraint & Soundness Specification (Π_H)

**Document Version:** 2.3 (Post-Review Final Specification)  
**Phase:** 1 (Cryptographic Specification & Feasibility)  
**Date:** October 2026  
**Status:** Reconciled AIR constraint specification featuring shifted signed carry constraints, composite STARK soundness over quintic extension, and post-September 2026 Plonky3 ZK architecture.

---

## 1. Executive Summary

Layer 2 ($\Pi_H$) is a **zero-knowledge STARK** that proves:
1. Canonical bit-to-polynomial chunking: $\mathbf{m}_x = \operatorname{EncodeNF}(\text{coin\_id}, r_{\text{nf}})$ with $c_i \in \{0, 1, 2, 3\}$.
2. Bridge commitment consistency: $\mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B \equiv B \pmod{q_{\text{LoTRS}}}$ over $R_q$ via **zero-wraparound shifted multi-limb carry chains**.
3. Nullifier correctness: $\nu = \text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id} \parallel r_{\text{nf}})$ via exactly 1 Keccak-$f[1600]$ permutation.

Following the adversarial review of Revision 3, this specification incorporates:
* A canonical **shifted carry recurrence** ($v_i - s_i - c_{i-1}' + W c_i' + C_{\text{shift}}(1-W) = 0$) strictly enforcing signed bounds $c_i \in [-1,793, 1,793]$.
* Field extension formulation: **Quintic Extension $\mathbb{F}_{p^5}$** ($p^5 \approx 2^{154.54}$) providing unconditional statistical quotient soundness ($\epsilon_{\text{quotient}} \le 2^{-144.93} \ll 2^{-128}$), alongside the Quartic Extension $\mathbb{F}_{p^4}$ computational grinding model.
* Alignment with post-September 2026 Plonky3 security fixes, incorporating 4 randomized blinding rows and `HidingFriPcs`.

---

## 2. Base Field & Field Extension Parameterization

* **Base Field:** **BabyBear** ($\mathbb{F}_p$)
  $$p = 2^{31} - 2^{27} + 1 = 2,013,265,921 \quad (\approx 2^{30.9077})$$
* **Field Extension Options for Soundness:**
  * **Primary (Quintic Extension $\mathbb{F}_{p^5}$):**
    $$|\mathbb{F}_{p^5}| = p^5 \approx 2^{154.54}$$
    Evaluates challenges and quotient polynomials over $\mathbb{F}_{p^5}$, achieving proven statistical soundness without relying on grinding heuristics:
    $$\epsilon_{\text{quotient}} \le \frac{d_{\max} \cdot |H|}{|\mathbb{F}_{p^5}|} = \frac{3 \times 260}{2^{154.54}} \approx \mathbf{2^{-144.93} \ll 2^{-128}}$$
  * **Alternative (Quartic Extension $\mathbb{F}_{p^4}$ with Computational Grinding):**
    $$|\mathbb{F}_{p^4}| = p^4 \approx 2^{123.63} \implies \epsilon_{\text{quotient}} \le \frac{3 \times 260}{2^{123.63}} \approx 2^{-114.02}$$
    Under the standard Fiat-Shamir adversary budget model with $e_{\text{grind}} = 16$ bits of batch challenge grinding, an adversary expending $T_{\text{adv}}$ work succeeds with probability $\le T_{\text{adv}} \cdot 2^{-16} \cdot \epsilon_{\text{quotient}}$.
* **Ring Modulus:** LoTRS production modulus $q_{\text{LoTRS}} = 2^{43} - 67$.

---

## 3. Shifted Multi-Limb Carry Chain Engine

To prove $V_{k, d} = K_{k, d} \cdot q_{\text{LoTRS}} + B_{k, d}$ in base $W = 2^{14} = 16,384$ over $\mathbb{Z}$:

### 3.1 Quotient & Signed Carry Bounds
* Because $|V_{k, d}| \le 1,792 q_{\text{LoTRS}}$, the quotient satisfies $|K_{k, d}| \le 1,792$.  
  We shift $K' = K + 1,792 \in [0, 3,584]$, constrained via a 12-bit range check.
* Column sums $s_i = k_0 q_i + b_i$ satisfy $|s_i| \le 2.937 \times 10^7$.
* Carry variables satisfy $c_i \in [-1,793, 1,793]$.

### 3.2 Shifted Carry Sizing & AIR Transition Constraint
Define shifted non-negative carry registers:
$$c_i' = c_i + C_{\text{shift}} \quad \text{where} \quad C_{\text{shift}} = 1,793$$
For all valid witnesses:
$$c_i \in [-1,793, 1,793] \iff c_i' \in [0, 3,586] \subset [0, 4,095]$$
The AIR enforces $c_i' \in [0, 3,586]$ via a standard 12-bit range check.

The canonical transition constraint enforced in $\mathbb{F}_p$ is:
$$\boxed{v_i - s_i - c_{i-1}' + W \cdot c_i' + C_{\text{shift}} (1 - W) = 0 \pmod p}$$
with boundary conditions:
* $c_{-1}' = C_{\text{shift}} = 1,793$
* $c_4' = C_{\text{shift}} = 1,793$

### 3.3 Zero Wraparound Soundness Proof
Maximum possible integer residual in $\mathbb{Z}$:
$$|\Delta_{\max}| \approx 5.88 \times 10^7 \ll p = 2,013,265,921 \quad \left(\frac{p}{\Delta_{\max}} \approx 34.2\right)$$
Because $|\Delta_{\max}| < p$, any field equality $\Delta \equiv 0 \pmod p$ forces $\Delta = 0$ **identically in $\mathbb{Z}$**. Modular aliasing is mathematically impossible.

---

## 4. Post-Quantum Soundness: Conservative FRI & SHAKE-256-384

### 4.1 Conservative FRI Parameterization
Under Plonky3's proven conservative soundness bound for code rate $R = 1/8$:
$$\epsilon_{\text{FRI}} \le (1/8)^{N_{\text{queries}} / 2} = 2^{-3 \cdot (N_{\text{queries}} / 2)}$$
To guarantee $\epsilon_{\text{FRI}} \le 2^{-128}$, the query count is set to:
$$N_{\text{queries}} = 86 \implies \epsilon_{\text{FRI}} \le (1/8)^{43} = \mathbf{2^{-129.0} \le 2^{-128}}$$

### 4.2 Merkle Hash Collision Resistance
SHAKE-256 with 384-bit output (capacity 512 bits) satisfies:
$$T_{\text{BHT}} = 2^{384/3} = \mathbf{2^{128}\text{ operations}}$$
Defeats BHT quantum collision attacks.

---

## 5. Zero-Knowledge Blinding & Byte-Level Sizing

Following Plonky3's post-September 2026 security architecture:
1. **Trace Blinding Rows:** 4 randomized blinding rows are appended to the execution trace ($H = 256 + 4 = 260 \le 512 = 2^9$).
2. **Hiding FRI Polynomial Commitment:** Plonky3's `HidingFriPcs` randomizes polynomial commitments and evaluation points.

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
│ 6. Trace Openings at Query Points (with ZK blinding rows):  22.34 KiB  │
│ 7. Public Inputs (B, nu, M):                                 3.08 KiB  │
├────────────────────────────────────────────────────────────────────────┤
│ TOTAL LAYER 2 STARK (Π_H) SIZE:                             ~58.34 KiB │
│ (59,744 bytes)                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

> [!CAUTION]
> **Performance Caveat:**  
> The $\approx 58.34\text{ KiB}$ size is an **analytical projection** based on conservative AIR parameters ($N_q = 86$, SHAKE-256-384, 4 ZK blinding rows).  
> It must be empirically measured on a compiled prototype before being cited as a confirmed benchmark.
