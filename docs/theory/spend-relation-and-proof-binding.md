# The 0PSP Spend Relation: Multi-Statement Binding & Privacy Proof

**Document Version:** 2.0 (Corrected Privacy Boundary & QROM Model)  
**Phase:** 1 (Mathematical Core Formulation)  
**Date:** October 2026

---

## 1. Executive Summary

A critical privacy requirement of 0PSP is that a transaction must **never disclose the selected coin commitment $C_j$ or its index $j$**. In an anonymous spend protocol, the public ledger sees only the eligible anonymity set of coin commitments $R_C = \{C_1, \dots, C_N\}$, a deterministic nullifier $\nu \in \{0,1\}^{384}$, and the transaction context $M$.

This document formalizes the unified cryptographic relation $\mathcal{R}_{\text{spend}}$, establishes the binding between the hidden wallet key and the hidden coin commitment, resolves the composition between threshold custody and anonymity (comparing **Route 1** and **Route 2**), formalizes the nullifier hash under the Quantum Random Oracle Model (QROM), and provides multi-hybrid security reductions.

---

## 2. Cryptographic Syntax: Public Statement vs. Hidden Witness

```
┌────────────────────────────────────────────────────────────────────────┐
│                        0PSP SPEND PROOF BOUNDARY                       │
├────────────────────────────────────────────────────────────────────────┤
│  PUBLIC STATEMENT (Known to Verifiers & Ledger):                       │
│    - R_C = {C_1, ..., C_N}   : Public set of unspent coin commitments │
│    - ν ∈ {0,1}^384           : Deterministic post-quantum nullifier    │
│    - M ∈ {0,1}^256           : Public transaction context hash         │
│                                (M = H_msg(m_tx || chain_id || ν))      │
│                                                                        │
│  HIDDEN WITNESS (Known only to Authorized Prover):                     │
│    - j ∈ [N]                 : Index of the spent coin in R_C          │
│    - C_j ∈ R_q^k             : The selected coin commitment            │
│    - pk_j = (A, t_j)         : The selected wallet public key          │
│    - s_j ∈ R_q^ℓ, e_j ∈ R_q^k: Lattice secret and error (t_j = A s_j+e)│
│    - v ∈ Z                   : Transferred asset balance               │
│    - coin_id ∈ {0,1}^256     : Unique immutable coin identifier        │
│    - r_nf ∈ {0,1}^256        : Dedicated nullifier secret              │
│    - ρ ∈ S_η^k               : Commitment opening trapdoor             │
│    - auth                    : Threshold authorization witness under pk│
└────────────────────────────────────────────────────────────────────────┘
```

> **Critical Privacy Invariant:**  
> The selected coin commitment $C_j$ is **strictly a witness element**. Exposing $C_j$ as a public argument would allow any verifier to look up $C_j \in R_C$, directly revealing the index $j$ and destroying spender anonymity. Furthermore, the transaction context $M$ commits to the public nullifier $\nu$ and transaction payload $m_{\text{tx}}$, but explicitly **omits $C_j$**.

---

## 3. The Four Constituent Relations of $\mathcal{R}_{\text{spend}}$

The spend proof $\pi$ proves knowledge of the witness $w = (j, C_j, pk_j, s_j, e_j, v, \text{coin\_id}, r_{\text{nf}}, \rho, \mathsf{auth})$ satisfying:

$$\mathcal{R}_{\text{spend}}\left( (R_C, \nu, M), \; w \right) = 1 \iff \bigwedge_{k=1}^4 \mathcal{R}_k = 1$$

### Relation 1: Anonymous Ring Selection ($\mathcal{R}_{\text{select}}$)
The prover proves that the hidden commitment $C_j$ is an authentic element of the public commitment set $R_C$ at a hidden index $j \in [N]$:
$$\mathcal{R}_{\text{select}}(R_C, j, C_j) = 1 \iff C_j = R_C[j] \quad \wedge \quad j \in [N]$$
*(In a ring architecture, this is proven via a 1-out-of-$N$ selection proof; in a tree architecture, via a zero-knowledge Merkle membership proof).*

### Relation 2: Coin Commitment Opening ($\mathcal{R}_{\text{commit}}$)
The prover proves that $C_j$ is a valid computationally binding and statistically hiding commitment opening to $(pk_j, v, \text{coin\_id}, r_{\text{nf}})$ under trapdoor $\rho$:
$$\mathcal{R}_{\text{commit}}(C_j, pk_j, v, \text{coin\_id}, r_{\text{nf}}, \rho) = 1 \iff C_j = \mathsf{Commit}(pk_j, v, \text{coin\_id}, r_{\text{nf}}; \rho)$$
where:
* $pk_j = (A, t_j) \in R_q^{k \times \ell} \times R_q^k$ satisfies $t_j = A s_j + e_j$ with $\|s_j\|_\infty \le \eta, \|e_j\|_\infty \le \eta$.
* $v \ge v_{\text{spend}} + \text{fee}$ (range proof ensuring non-negative balance).
* $\|\rho\|_\infty \le \eta$.

### Relation 3: Deterministic Nullifier Derivation ($\mathcal{R}_{\text{null}}$)
The prover proves that the public nullifier $\nu$ is derived deterministically from the canonical encoding of $C_j$ and the dedicated secret $r_{\text{nf}}$:
$$\mathcal{R}_{\text{null}}(\nu, C_j, r_{\text{nf}}) = 1 \iff \nu = H_{\text{nf}}\left( \mathsf{domain}_{\text{null}} \,\|\, \mathsf{Encode}(C_j) \,\|\, \mathsf{Encode}(r_{\text{nf}}) \right) \in \{0,1\}^{384}$$
where:
* $\mathsf{domain}_{\text{null}} = \text{"0PSP-NULLIFIER-v1-SHAKE256"}$.
* $\mathsf{Encode}(C_j)$ is the canonical 256-coefficient polynomial vector encoding over $\mathbb{Z}_q$.
* $\mathsf{Encode}(r_{\text{nf}})$ is the 32-byte secret encoding.

### Relation 4: Hidden-Key Threshold Authorization ($\mathcal{R}_{\text{auth}}$)
The prover proves that the threshold authorization $\mathsf{auth}$ is valid for the public transaction context $M$ under the **exact same public key $pk_j$** embedded in $C_j$:
$$\mathcal{R}_{\text{auth}}(pk_j, M, \mathsf{auth}) = 1 \iff \mathsf{VerifyAuth}(pk_j, M, \mathsf{auth}) = 1$$
This relation links the authorized spending capability to the asset commitment without leaking $pk_j$.

---

## 4. Threshold Composition: Route 1 vs. Route 2

We distinguish between two fundamentally different threshold dimensions:
1. **Wallet Custody Threshold $(t, n)$:** A single wallet's signing key $sk_j$ is split among $n$ participants (e.g., $2$-of-$3$ or $3$-of-$5$), where any $t$ participants can authorize spending.
2. **Spender Anonymity Set $N$:** The number of candidate coin commitments in the ring $R_C$ (e.g., $N = 64$ or $100$).

How does a $t$-of-$n$ threshold signature compose with an $N$-element anonymity proof? We evaluate two distinct routes:

```
┌────────────────────────────────────────────────────────────────────────┐
│ ROUTE 1: Direct Integration into LoTRS Selection Layer (Preferred)     │
│                                                                        │
│   Public Matrix Grid:                                                  │
│   Each column j contains:                                              │
│     - Row 1: Aggregated Verification Key vk_j                          │
│     - Row 2: Coin Commitment C_j                                       │
│                                                                        │
│   The 1-out-of-N selection proof natively proves that the same hidden  │
│   column index j satisfies BOTH the multisignature verification AND    │
│   the commitment opening and nullifier hash.                           │
│   => Zero SNARK overhead; unified lattice zero-knowledge argument.     │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ ROUTE 2: External Threshold Signature Proven in Auxiliary ZK           │
│                                                                        │
│   1. Threshold key holders run Threshold Raccoon / Ringtail to         │
│      produce an explicit threshold signature σ_thresh on M.            │
│   2. Spender client generates an auxiliary lattice ZK proof (SNARK)    │
│      proving knowledge of (pk_j, σ_thresh) such that:                  │
│      - Verify(pk_j, M, σ_thresh) = 1                                   │
│      - pk_j opens C_j ∈ R_C                                            │
│   => Requires generic ZK proof of lattice signature verification.      │
│   => Circuit size is massive (millions of constraints for ML-DSA).    │
└────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Route 1 Obstruction: The Algebraic Category Barrier
In earlier discussions, Route 1 was hypothesized to integrate the nullifier hash directly into the LoTRS matrix grid. **This hypothesis is blocked by a fundamental algebraic obstruction:**
* LoTRS operates as a lattice $\Sigma$-protocol over **linear relations in the polynomial ring** $R_q = \mathbb{Z}_q[x]/(x^n + 1)$.
* The nullifier function $\nu = \text{SHAKE256}_{384}(\dots)$ is composed of non-linear Boolean $\chi$-gates over $\mathbb{F}_2$ ($a \oplus (\neg b \wedge c)$).
* A linear lattice $\Sigma$-protocol **cannot evaluate Keccak bitwise permutations** without decomposing every ring element into binary bits and proving non-linear bit constraints modulo $q$.
* **Conclusion on Direct Route 1:** The LoTRS one-out-of-many proof cannot natively prove the SHAKE-256 nullifier relation. See `docs/theory/proof-system-feasibility-study.md` for the formal obstruction proof.

### 4.2 Candidate Resolution: Two-Layer Hybrid Architecture (Model B)
To bridge this obstruction without incurring multi-million constraint penalties, the inter-layer binding protocol (`docs/theory/inter-layer-binding-protocol.md`) investigates a per-spend bridge commitment $B = \operatorname{Com}_{\text{bridge}}(\text{Encode}(coin\_id, r_{\text{nf}}); \tau_B)$:
1. **Model B Identifier Hashing:** Define the nullifier over the compact 32-byte identifier:
   $$\nu = \text{SHAKE256}_{384}\left( \mathsf{domain} \,\|\, \text{coin\_id} \,\|\, r_{\text{nf}} \right)$$
   Total preimage length is $26 + 32 + 32 = 90\text{ bytes} \le 136\text{ bytes}$ (rate of SHAKE-256), requiring **exactly 1 Keccak permutation (38,400 $\chi$-step AND operations)**.
2. **Two-Layer Composition:**
   * **Layer 1 (Extended Lattice Selection $\Pi_L$):** Proves threshold authorization, coin selection, and that $B$ and $C_j$ open consistently to $(pk_j, \text{coin\_id}, r_{\text{nf}})$.
   * **Layer 2 (ZK-Enabled STARK $\Pi_H$):** Proves in zero-knowledge that the same $B$ opens to the nullifier input and that $\nu = \text{SHAKE256}_{384}(\text{domain} \parallel \text{coin\_id} \parallel r_{\text{nf}})$.
   * **Hypothesis Status:** The earlier projected combined proof size of **$\approx 90\text{--}100\text{ KiB}$ is an unverified hypothesis**. It excludes the bridge commitment opening constraints, FRI query parameter expansion, trace layout/lookup arguments, zero-knowledge masking mode, and any larger parameters required to meet true 128-bit quantum security.

---

## 5. Security Analysis of the Nullifier Function $H_{\text{nf}}$

To establish a defensible security argument, we explicitly structure the nullifier properties into four distinct tiers:

### 5.1 Tier 1: Primitive Assumption (Standard Model)
* **Underlying Primitive:** SHAKE-256 eXtendable-Output Function (XOF) specified in NIST FIPS 202.
* **Output Length:** Squeezed to 48 bytes (384 bits).
* **Cryptographic Assumptions:**
  * **128-Bit Preimage Resistance:** Against quantum search algorithms (Grover), finding a preimage for a fixed output requires $\Omega(2^{384/2}) \ge 2^{128}$ evaluations.
  * **128-Bit Quantum Collision Resistance:** Against quantum collision algorithms (BHT), finding collisions requires $\Omega(2^{384/3}) = \Omega(2^{128})$ quantum queries.

### 5.2 Tier 2: Idealized Model (Quantum Random Oracle Model - QROM)
For transaction unlinkability proofs, $H_{\text{nf}}$ is modeled as a quantum-accessible random oracle $\mathcal{H}: \{0,1\}^* \to \{0,1\}^{384}$, supporting superposition queries $|\psi\rangle = \sum_{x, y} \alpha_{x, y} |x, y \oplus \mathcal{H}(x)\rangle$. SHAKE-256 is treated as an instantiation heuristic for this idealized model.

### 5.3 Tier 3: Protocol Theorem (Spend Unlinkability under Quantum Query Budget)
> **Theorem (Spend Unlinkability).** *Let $\mathcal{A}$ be a QPT adversary making at most $q_H$ quantum superposition queries to $\mathcal{H}$. If the commitment scheme $\mathsf{Commit}$ is statistically hiding, the bridge commitment $\operatorname{Com}_{\text{bridge}}$ is statistically hiding, and the spend proofs $(\Pi_L, \Pi_H)$ are computational zero-knowledge, then for any two spent coins $C_0, C_1$ with independent 256-bit secrets $r_{\text{nf}, 0}, r_{\text{nf}, 1}$, the distinguishing advantage of $\mathcal{A}$ in guessing the spend bit $b \in \{0, 1\}$ is bounded by:*
> $$\mathbf{Adv}^{\text{UNLINK}}(\mathcal{A}) \le \mathbf{Adv}^{\text{ZK}}(\mathcal{A}) + \mathbf{Adv}^{\text{MLWE}}(\mathcal{A}) + O\left(\frac{q_H^2}{2^{128}}\right) \le \mathsf{negl}(\lambda)$$

*Formal Game Sequence & Quantum Query Bound Analysis:*
1. **Game 0:** Real spend anonymity game with nullifier $\nu_b = \mathcal{H}(\mathsf{domain} \parallel \text{coin\_id}_b \parallel r_{\text{nf}, b})$.
2. **Game 1:** Challenger simulates the zero-knowledge proofs $(\Pi_{L, \text{sim}}, \Pi_{H, \text{sim}})$ without the witnesses. The transition bound is $\mathbf{Adv}^{\text{ZK}}(\mathcal{A})$.
3. **Game 2:** Challenger replaces the committed coin $C_b$ and bridge commitment $B$ with dummy commitments. The transition bound is $\mathbf{Adv}^{\text{MLWE}}(\mathcal{A})$ via commitment hiding.
4. **Game 3:** Challenger punctures the quantum random oracle at the challenge input $x^* = (\mathsf{domain} \parallel \text{coin\_id}_b \parallel r_{\text{nf}, b})$ and programs $\nu_b \stackrel{\$}{\leftarrow} \{0,1\}^{384}$ as an independent uniform random string.
   * **Quantum Search Probability:** By the Bennett-Bernstein-Brassard-Vazirani (BBBV) optimality theorem for quantum search, for a secret $r_{\text{nf}, b}$ sampled with 256 bits of conditional min-entropy ($H_\infty(r_{\text{nf}, b} \mid \text{view}) = 256$), the probability that an adversary making $q_H$ quantum queries finds or queries the secret input is bounded by:
     $$p_{\text{find}} \le C \cdot \frac{(q_H + 1)^2}{2^{256}}$$
   * **Semi-Classical O2H Lemma:** Applying the semi-classical One-Way to Hiding (O2H) lemma (Ambainis, Hampel, Unruh 2019 / ePrint 2017/1005), the distinguishing penalty between the original and punctured oracle is bounded by:
     $$2 q_H \sqrt{p_{\text{find}}} \le 2 q_H \sqrt{C \frac{(q_H + 1)^2}{2^{256}}} \approx O\left(\frac{q_H^2}{2^{128}}\right)$$
   * For any polynomial quantum query budget $q_H = \text{poly}(\lambda) \ll 2^{64}$, this advantage is strictly negligible. If side-channel leakage degrades the conditional min-entropy below 256 bits, this bound scales as $O(q_H^2 / 2^{H_\infty/2})$.
5. In Game 3, $\nu_b$ is statistically independent of choice bit $b$, so $\Pr[\mathcal{A} \text{ wins}] = 1/2$. $\blacksquare$

### 5.4 Tier 4: Construction Evidence (Distinction from Proofs)
* **What Has Been Tested:** `scripts/verify_nullifier_relation.py` executes **functional smoke tests only**, confirming little-endian byte packaging, functional determinism, 384-bit output length, and domain separation.
* **What Remains Unproven:** Functional smoke tests do **not** demonstrate cryptographic soundness, quantum collision resistance, or zero-knowledge extractability. Those guarantees depend strictly on the formal reductions in Tier 3 and subsequent Phase 4 independent cryptanalysis.

### 5.5 Double-Spend Prevention vs. Collision Safety

We strictly separate these two properties, which are frequently conflated:

| Property | Threat Prevented | Underlying Cryptographic Mechanism |
|---|---|---|
| **Double-Spend Prevention** | An attacker spending the **same coin $C$ twice** without detection. | **Commitment Binding + Proof Soundness + Determinism:** For a fixed coin $C_j$, the computational binding of $\mathsf{Commit}$ forces the unique secret $r_{\text{nf}}$. Because $H_{\text{nf}}$ is deterministic, any valid spend of $C_j$ **must produce the exact same nullifier $\nu$**. The ledger duplicate check rejects $\nu \in \mathcal{N}$. |
| **Collision Safety** | An honest user being prevented from spending coin $C_b$ because its nullifier accidentally collides with an earlier spend of distinct coin $C_a$ ($\nu_b = \nu_a$). | **Quantum Collision Resistance of $H_{\text{nf}}$:** Under the BHT algorithm, quantum collision finding on an output of length $b$ bits requires $O(2^{b/3})$ queries. Squeezing SHAKE-256 to 48 bytes (384 bits) ensures collision probability across independent coins is $< 2^{-128}$. |

---

## 6. Multi-Hybrid Security Reductions

We formalize the reductions connecting the primary security games to underlying post-quantum hardness assumptions.

### 6.1 Spend Soundness Reduction
```
Game G_0: Standard Spend Soundness Game (Game SPEND-SOUND)
Game G_1: Same as G_0, but Challenger uses Knowledge Extractor to extract witness 
          w* = (j*, C_j*, pk_j*, s_j*, e_j*, v*, coin_id*, r_nf*, ρ*, auth*) from π*.
          If extraction fails, Challenger aborts.
          |Pr[G_0] - Pr[G_1]| ≤ Adv_extract(λ) ≤ negl(λ) (Knowledge Soundness).

Game G_2: Same as G_1, but Challenger aborts if C_j* is not in R_C at index j*.
          |Pr[G_1] - G_2| = 0 (Enforced by R_select extraction).

Game G_3: Same as G_2, but Challenger aborts if C_j* opens to two distinct keys 
          pk ≠ pk' or two distinct secrets r_nf ≠ r_nf'.
          |Pr[G_2] - Pr[G_3]| ≤ Adv_MSIS_bind(λ) (Computational Binding of Commit).

Game G_4: Challenger aborts if auth* is valid under pk_j* without corrupting t key holders.
          Since adversary controls at most t - 1 shares of sk_j*, producing valid auth* 
          implies a threshold signature forgery under Module-SIS.
          Pr[G_4] ≤ Adv_MSIS_forge(λ) ≤ negl(λ).
```
**Conclusion:** Any adversary breaking Spend Soundness implies an extractor failure, an MSIS commitment collision, or an MSIS threshold signature forgery.

---

### 6.2 Double-Spend Resistance Reduction
Suppose an adversary $\mathcal{A}$ outputs two valid spend proofs $\pi_1^*, \pi_2^*$ for the same coin commitment $C_j \in R_C$ such that $\nu_1 \ne \nu_2$ and both are accepted by the ledger.
1. Challenger runs the extractor to obtain $(r_{\text{nf}, 1}, \rho_1)$ from $\pi_1^*$ and $(r_{\text{nf}, 2}, \rho_2)$ from $\pi_2^*$.
2. Both openings satisfy $C_j = \mathsf{Commit}(pk, v, \text{coin\_id}, r_{\text{nf}, 1}; \rho_1) = \mathsf{Commit}(pk, v, \text{coin\_id}, r_{\text{nf}, 2}; \rho_2)$.
3. If $r_{\text{nf}, 1} \ne r_{\text{nf}, 2}$, Challenger immediately solves the $\text{MSIS}_{k, \ell, q, 2\eta}$ problem by subtracting the two openings.
4. If $r_{\text{nf}, 1} = r_{\text{nf}, 2}$, then the inputs to $H_{\text{nf}}$ are identical:
   $$\mathsf{domain} \,\|\, \mathsf{Encode}(C_j) \,\|\, \mathsf{Encode}(r_{\text{nf}, 1}) = \mathsf{domain} \,\|\, \mathsf{Encode}(C_j) \,\|\, \mathsf{Encode}(r_{\text{nf}, 2})$$
   By functional determinism, $\nu_1 = H_{\text{nf}}(\dots) = \nu_2$, contradicting the assumption that $\nu_1 \ne \nu_2$.
5. Therefore, double-spend resistance holds unconditionally under the computational binding of $\mathsf{Commit}$.

---

### 6.3 Spend Unlinkability Reduction
```
Game H_0: Real Anonymity Game where Challenger spends coin C_b (b ∈ {0, 1}) in R_C.
Game H_1: Replace the zero-knowledge proof π* with a simulated proof π_sim using 
          the zero-knowledge simulator.
          |Pr[H_0] - Pr[H_1]| ≤ Adv_ZK(λ) ≤ negl(λ).

Game H_2: Replace the commitment C_b with a commitment to dummy values 
          using the hiding property of Commit.
          |Pr[H_1] - Pr[H_2]| ≤ Adv_MLWE_hide(λ) ≤ negl(λ).

Game H_3: Replace the nullifier ν_b = H_nf(C_b, r_nf, b) with a fresh uniform 
          random string ν_rand ∈ {0, 1}^384.
          By the One-Way to Hiding (O2H) Lemma in QROM, since r_nf,b has 256 bits of 
          min-entropy and is never exposed in H_2:
          |Pr[H_2] - Pr[H_3]| ≤ 2 q_H · 2^(-128) ≤ negl(λ).
```
In Game $H_3$, the adversary's view $(R_C, \nu_{\text{rand}}, M, \pi_{\text{sim}})$ contains zero information regarding the choice bit $b$. Thus, $\Pr[H_3 = 1] = 1/2$, establishing full spend unlinkability.
