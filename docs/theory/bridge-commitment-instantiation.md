# Bridge Commitment Instantiation: Cross-Layer Mathematical Feasibility

**Document Version:** 1.0  
**Phase:** 1 (Primitive Instantiation & Cross-Layer Analysis)  
**Date:** October 2026

---

## 1. The Cross-Layer Instantiation Dilemma

The 0PSP Inter-Layer Binding Protocol (`docs/theory/inter-layer-binding-protocol.md`) introduces a per-spend bridge commitment:
$$B = \operatorname{Com}_{\text{bridge}}\left(\operatorname{EncodeNF}(\text{coin\_id}, r_{\text{nf}}); \; \tau_B\right)$$
whose opening must be proved in **two fundamentally different mathematical environments**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        THE CROSS-LAYER ALGEBRAIC GAP                   │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 1 (Extended Lattice Selection Proof Π_L):                       │
│    - Algebraic Domain: Cyclotomic polynomial ring R_q                  │
│      R_q = Z_q[x]/(x^256 + 1) with q = 8,380,417 (ML-DSA / LoTRS)      │
│    - Proof Language: Linear Σ-protocols over module lattices           │
│    - Efficiency Requirement: Must be linear over R_q                   │
│                                                                        │
│  LAYER 2 (Zero-Knowledge STARK Π_H):                                   │
│    - Algebraic Domain: Finite field F_p (e.g., BabyBear, Mersenne31)   │
│      or binary extension fields (Binius)                               │
│    - Proof Language: Algebraic Intermediate Representation (AIR)       │
│    - Efficiency Requirement: Small circuit degree & permutation checks │
└────────────────────────────────────────────────────────────────────────┘
```

If $\operatorname{Com}_{\text{bridge}}$ is chosen to be optimal for Layer 2 (e.g., a hash-based commitment like Keccak or Poseidon), Layer 1 cannot prove it without hitting the algebraic category barrier. Conversely, if $\operatorname{Com}_{\text{bridge}}$ is a lattice commitment over $R_q$, Layer 2 must verify arithmetic modulo $q = 8,380,417$.

---

## 2. Evaluation of Candidate Instantiations

We analyze three concrete candidates for $\operatorname{Com}_{\text{bridge}}$:

### 2.1 Candidate A: Module-SIS / Module-LWE Commitment over $R_q$ (Lattice-Native)
* **Construction:**
  Let $\mathbf{A}_1 \in R_q^{k_B \times \ell_B}$ and $\mathbf{A}_2 \in R_q^{k_B \times m_B}$ be public random module matrices.
  Encode $x = \operatorname{EncodeNF}(\text{coin\_id}, r_{\text{nf}})$ (65 bytes = 520 bits) into a vector of short polynomials $\mathbf{m}_x \in R_q^{\ell_B}$ with $\|\mathbf{m}_x\|_\infty \le \beta_x$.
  Sample fresh short randomness $\boldsymbol{\tau}_B \leftarrow S_\eta^{m_B}$.
  $$B = \mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B \pmod q$$
* **Layer 1 Verification (Extended Lattice Selection):**
  * **Feasibility:** **Natively supported.**
  * The relation is purely linear in $R_q$: $\mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B - B \equiv 0 \pmod q$.
  * It directly appends to the LoTRS linear relation system without introducing non-linear gates.
* **Layer 2 Verification (STARK over $\mathbb{F}_p$):**
  * **Feasibility:** Requires proving the negacyclic matrix product modulo $q_{\text{LoTRS}} = 2^{43} - 67$ inside the STARK AIR over BabyBear $\mathbb{F}_p$ ($p \approx 2^{31}$).
  * Since $q_{\text{LoTRS}} > p$, unreduced field checks would permit modular wraparound.
  * Instead, equality in $\mathbb{Z}$ is proven using a **14-bit multi-limb carry chain** ($W = 2^{14} = 16,384$) across 4 limbs with bounded carries $c_i \in [0, 2^{16}]$.
  * Because $|\Delta_{\max}| \approx 1.88 \times 10^9 < p = 2,013,265,921$, zero modular wraparound is guaranteed, proving integer equality identically in $\mathbb{Z}$.
  * Adds modest overhead ($\approx 4,096$ simple degree-2 constraints) to Layer 2.
  * **Assessment:** Highly feasible. Keeps Layer 1 completely linear, while proving sound integer equality in Layer 2.

---

### 2.2 Candidate B: Hash-Based Commitment (STARK-Native)
* **Construction:**
  $$B = \text{SHAKE256}\left(\text{domain}_B \,\|\, x \,\|\, \tau_B\right) \in \{0,1\}^{256}$$
* **Layer 2 Verification:** Native (handled within the existing Keccak trace).
* **Layer 1 Verification:** **Catastrophic.**
  * Layer 1 must verify a Keccak hash preimage over a secret witness.
  * As established in `docs/theory/proof-system-feasibility-study.md`, verifying Keccak inside a linear lattice $\Sigma$-protocol is impossible without complete bit-decomposition.
  * **Verdict: REJECTED.** Candidate B destroys the feasibility of Layer 1.

---

### 2.3 Candidate C: Pedersen-Style Chunked Linear Commitment over $\mathbb{F}_q$
* **Construction:**
  Instead of using full polynomial ring elements, treat $x$ as an integer vector $(x_1, \dots, x_m) \in \mathbb{F}_q^m$ and commit using scalar generators:
  $$B = \sum_{i=1}^m g_i x_i + h \cdot \tau_B \pmod q$$
* **Layer 1 Verification:** Linear over $\mathbb{F}_q$, but requires scalar-to-ring embedding.
* **Layer 2 Verification:** Simple linear combination with a single modular reduction modulo $q$.
* **Security Consideration:** To ensure post-quantum binding under Module-SIS, the dimension $m$ and modulus $q$ must satisfy standard SIS hardness bounds. For $q = 8,380,417$, scalar SIS requires large vectors ($m \ge 1024$), making Candidate A (Module-SIS over $R_q$) significantly more compact.

---

## 3. Concrete Recommendation & Encoding Specification for Candidate A

We adopt **Candidate A (Module-SIS Commitment over $R_q$)** as the primary research instantiation:

### 3.1 Encoding Specification (`EncodeNF` to Polynomial)
* Input: $\text{coin\_id} \in \{0,1\}^{256}$ (32 bytes) and $r_{\text{nf}} \in \{0,1\}^{256}$ (32 bytes), total 64 bytes = 512 bits.
* Representation: Split the 512 bits into 256 two-bit coefficients:
  $$m_x(X) = \sum_{i=0}^{255} c_i X^i \in R_q \quad \text{where} \quad c_i \in \{0, 1, 2, 3\}$$
* Infinity Norm Bound: $\|\mathbf{m}_x\|_\infty \le 3 \ll q$.
* Security Advantage: Bounded coefficients ensure that range checks in the STARK require only 2-bit lookups ($c_i \in [0, 3]$), which are virtually free in an AIR trace!

### 3.2 Formal Security Reduction
* **Computational Binding:** Any adversary opening $B$ to two distinct messages $(\mathbf{m}_x, \boldsymbol{\tau}_B) \ne (\mathbf{m}_x', \boldsymbol{\tau}_B')$ directly finds a non-zero short vector:
  $$\mathbf{A}_1 (\mathbf{m}_x - \mathbf{m}_x') + \mathbf{A}_2 (\boldsymbol{\tau}_B - \boldsymbol{\tau}_B') \equiv \mathbf{0} \pmod q$$
  with infinity norm bounded by $2\beta_x + 2\eta$, which directly breaks $\text{Module-SIS}_{k_B, \ell_B + m_B, q, \beta}$.
* **Statistical / Computational Hiding:** For $\boldsymbol{\tau}_B \leftarrow S_\eta^{m_B}$, the distribution of $B = \mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B$ is pseudorandom under $\text{Module-LWE}_{k_B, m_B, q, \eta}$, completely hiding $\mathbf{m}_x$.

---

## 4. Next Experimental Milestone

Before claiming concrete performance figures for the Two-Layer Hybrid:
1. Implement the 2-bit chunk polynomial encoding `EncodeNF` in Python.
2. Formulate the exact quotient-remainder AIR constraints for checking $\mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B \equiv B \pmod q$ in a Plonky3 prototype.
3. Measure the empirical trace width and proving overhead of these constraints alongside the 1-block Keccak trace.
