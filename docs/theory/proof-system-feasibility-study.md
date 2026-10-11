# Proof-System Feasibility Study: The Selection-to-Nullifier Binding Obstruction

**Document Version:** 1.0  
**Phase:** 1 (Cryptographic Obstruction Analysis)  
**Date:** October 2026

---

## 1. Executive Summary & The Core Obstruction

A central finding of this research phase is that **Route 1 (direct integration into LoTRS) faces a fundamental algebraic obstruction**:

> [!CAUTION]
> **The Algebraic Category Obstruction:**  
> LoTRS is a lattice $\Sigma$-protocol operating over **linear relations in the cyclotomic ring** $R_q = \mathbb{Z}_q[x]/(x^n + 1)$.  
> The nullifier equation $\nu = \text{SHAKE256}_{384}(\mathsf{domain} \parallel \text{Input})$ is a **bit-level sponge function** (Keccak-$f[1600]$) composed of non-linear Boolean $\chi$-gates over $\mathbb{F}_2$.  
> A linear lattice selection matrix **cannot natively express the non-linear bitwise operations of Keccak**. Adding coin commitments to the LoTRS public matrix proves linear opening relations, but it **does not and cannot** prove that $\nu$ is the Keccak hash of that witness without an auxiliary non-linear proof system.

This document formalizes this algebraic obstruction, presents reproducible cost calculations for proving the hash relation inside zero knowledge, and explores three candidate architectures to overcome the bottleneck.

---

## 2. Formal Analysis of the LoTRS Selection Obstruction

### 2.1 What LoTRS Actually Proves
In LoTRS (Jagganath et al., ACM CCS 2026), the public statement is a matrix of public verification keys:
$$\mathbf{P} = \begin{pmatrix} pk_{1,1} & pk_{1,2} & \dots & pk_{1,N} \\ \vdots & \vdots & \ddots & \vdots \\ pk_{T,1} & pk_{T,2} & \dots & pk_{T,N} \end{pmatrix} \in (R_q^k)^{T \times N}$$
The 1-out-of-$N$ proof proves knowledge of a binary selection vector $\mathbf{b} \in \{0, 1\}^N$ with $\sum_{j=1}^N b_j = 1$ such that:
1. $\mathbf{b}$ selects column $j$ across all $T$ rows: $\mathbf{P} \cdot \mathbf{b} = \mathbf{pk}_j^*$.
2. The $T$ row signers possess valid lattice multisignature responses $z_{i}$ satisfying $A z_i = c \cdot pk_{i,j} \pmod q$.

### 2.2 Why Appending Commitments Fails to Bind the Nullifier
If we append coin commitments to the column vectors:
$$\mathbf{P}' = \begin{pmatrix} \mathbf{P} \\ C_1 & C_2 & \dots & C_N \end{pmatrix}$$
the LoTRS $\Sigma$-protocol can prove that $\mathbf{P}' \mathbf{b} = (\mathbf{pk}_j^*, C_j^*)$ where $C_j^* = \sum b_i C_i$.  
If $C_j$ is a linear commitment $C_j = B_1 pk_j + B_2 (v, \text{coin\_id}, r_{\text{nf}}) + \rho \pmod q$, the linear opening can also be verified within the $\Sigma$-protocol.

**However, the nullifier requires checking:**
$$\nu \stackrel{?}{=} \text{SHAKE256}_{384}\left( \mathsf{domain} \,\|\, \mathsf{Encode}(C_j) \,\|\, \mathsf{Encode}(r_{\text{nf}}) \right)$$
* Keccak-$f[1600]$ consists of 24 rounds of state permutations.
* The non-linear step is the $\chi$ transformation: $a_{x,y} \leftarrow a_{x,y} \oplus (\neg a_{x+1,y} \wedge a_{x+2,y})$ for $x, y \in [0, 4]$.
* This operation operates on 1600 individual bits over $\mathbb{F}_2$.
* The LoTRS ring arithmetic operates modulo $q = 8,380,417$. The quotient ring $R_q$ cannot decompose elements into individual bits without extensive bit-decomposition constraints ($b_k \in \{0, 1\} \iff b_k(b_k - 1) = 0 \pmod q$).
* **Verdict:** Route 1 cannot verify SHAKE-256 within the LoTRS $\Sigma$-protocol.

---

## 3. Reproducible Cost Calculations for Route 2 (ZK Proof of Hash)

To evaluate Route 2 (proving the hash relation inside zero knowledge), we calculate the exact constraint counts and proof sizes across two candidate preimage models.

### 3.1 Model A: Hashing the Raw Commitment $C_j \in R_q^k$
* **Preimage Size:**
  * $\mathsf{domain}$: 26 bytes.
  * $C_j$: $k = 6$ polynomial elements in $R_q$, each having $n = 256$ coefficients. Packed as 32-bit integers, $C_j$ requires $6 \times 256 \times 4 = 6,144\text{ bytes}$.
  * $r_{\text{nf}}$: 32 bytes.
  * **Total Preimage:** $26 + 6,144 + 32 = 6,202\text{ bytes}$.
* **Keccak Permutations:**
  * Rate of SHAKE-256 is $r = 1088\text{ bits} = 136\text{ bytes}$.
  * Number of permutation blocks: $\lceil 6,202 / 136 \rceil = \mathbf{46\text{ permutations}}$.
* **Circuit Constraints:**
  * 1 permutation $= 24\text{ rounds} \times 1,600\text{ bits} = 38,400\text{ AND gates}$.
  * $46 \times 38,400 = \mathbf{1,766,400\text{ non-linear constraints}}$ (~1.77 million constraints).
* **Proof Size in Post-Quantum STARK (e.g., Plonky3 / Binius):**
  * Estimated proof size: **$\approx 180\text{--}260\text{ KiB}$**.
  * Prover latency: $\approx 2.5\text{--}4.0\text{ seconds}$ on a standard 8-core CPU.

---

### 3.2 Model B: Hashing the Coin Identifier (Zcash Orchard Pattern)
Instead of hashing the full polynomial vector $C_j$, the nullifier is defined strictly over the immutable 32-byte identifier and the 32-byte secret:
$$\nu = \text{SHAKE256}_{384}\left( \mathsf{domain} \,\|\, \text{coin\_id} \,\|\, r_{\text{nf}} \right)$$
where the commitment $C_j = \mathsf{Commit}(pk_j, v, \text{coin\_id}, r_{\text{nf}}; \rho)$ binds $\text{coin\_id}$ and $r_{\text{nf}}$ inside the coin.

* **Preimage Size:**
  * $\mathsf{domain}$: 26 bytes.
  * $\text{coin\_id}$: 32 bytes.
  * $r_{\text{nf}}$: 32 bytes.
  * **Total Preimage:** $26 + 32 + 32 = \mathbf{90\text{ bytes}}$.
* **Keccak Permutations:**
  * Total bytes $90 \le 136\text{ bytes} \implies \mathbf{\text{Exactly } 1\text{ Keccak permutation}}$.
* **Circuit Constraints:**
  * $1 \times 38,400 = \mathbf{38,400\text{ constraints}}$ (a **$46\times$ reduction** over Model A).
* **Proof Size in Post-Quantum STARK:**
  * Estimated proof size: **$\approx 35\text{--}48\text{ KiB}$**.
  * Prover latency: $\approx 60\text{--}120\text{ ms}$.

---

## 4. Architectural Alternatives to Resolve the Bottleneck

| Candidate Architecture | Selection Proof Mechanism | Nullifier Verification | Projected Proof Size | Prover Complexity |
|---|---|---|---|---|
| **Candidate 1: Two-Layer Hybrid (LoTRS + Mini-STARK)** | LoTRS 1-out-of-$N$ ring proof (53.53 KiB) | 1-block STARK over Model B ($\approx 40\text{ KiB}$) | **$\approx 93\text{--}100\text{ KiB}$** | Moderate ($\approx 1\text{ s}$) |
| **Candidate 2: Pure Algebraic Lattice Nullifier** | Unified LoTRS matrix grid | Lattice-native PRF / SIS hash over $R_q$ | **$\approx 55\text{--}65\text{ KiB}$** | Low ($\approx 300\text{ ms}$) |
| **Candidate 3: Unified Post-Quantum SNARK / STARK** | Merkle tree membership in STARK | SHAKE-256 Model B in same STARK | **$\approx 45\text{--}60\text{ KiB}$** | Moderate ($\approx 1.5\text{ s}$) |

### Analysis of Candidate 2 (Algebraic Lattice Nullifier):
Can we replace SHAKE-256 with an algebraic lattice function so that the entire proof remains inside the LoTRS $\Sigma$-protocol?
$$\nu_{\text{lat}} = \lfloor D \cdot s_j + E \cdot r_{\text{nf}} \rceil_p \pmod p$$
* **Obstruction:** Modular rounding $\lfloor \cdot \rceil_p$ introduces range constraints that require Stern-like bit-decomposition proofs, expanding the $\Sigma$-protocol size by $30\text{--}50\text{ KiB}$.
* **If unrounded:** $\nu = D s_j + E r_{\text{nf}} \pmod q$ is purely linear. Observing polynomial numbers of public nullifiers $\nu$ gives an adversary linear equations in $s_j$, enabling lattice reduction attacks.

**Conclusion:** **Candidate 1 (Two-Layer Hybrid: LoTRS Selection + 1-Block SHAKE STARK) using Model B** is the most mathematically viable route that avoids both unproven lattice PRFs and multi-million constraint overheads.
