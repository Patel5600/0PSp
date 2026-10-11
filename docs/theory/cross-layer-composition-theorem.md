# Cross-Layer Composition Theorem & Security Reductions

**Document Version:** 2.3 (Post-Audit Closure & Decoupled Reductions)  
**Phase:** 1 (Formal Security Reductions)  
**Date:** October 2026  
**Status:** Closed mathematical specification featuring dedicated bridge Module-SIS instances, causally decoupled double-spend theorems, consensus minting invariant, MLWE conditional min-entropy proof, and QROM entropy profiles.

---

## 1. Executive Summary

This document formalizes the central mathematical foundation of the 0PSP primitive: **The Cross-Layer Composition Theorem**.

The hybrid 0PSP architecture binds a post-quantum lattice ring proof ($\Pi_L$) to an algebraic zero-knowledge STARK ($\Pi_H$) via an intermediate linear bridge commitment $B \in R_{q_{\text{LoTRS}}}^2$. Following Audit Revision 3 (`docs/audit/phase1-consistency-audit.md`), this document establishes:

1. **Dedicated Bridge Module-SIS Hardness:** Decouples the bridge commitment parameterization from LoTRS's internal signing norm bound ($\beta = 100$). Formulates explicit instances $\text{MSIS}_{2, 3, q_{\text{LoTRS}}, 166.5}$ (Profile 1) and $\text{MSIS}_{2, 4, q_{\text{LoTRS}}, 200}$ (Profile 2), both provably yielding $\ge 198\text{ bits}$ of quantum Core-SVP hardness.
2. **Causally Decoupled Security Theorems:**
   - **Theorem 2A (Double-Spend Resistance):** Proves that spending the same coin twice with distinct nullifiers reduces strictly to breaking the binding of $\operatorname{Com}_{\text{coin}}$ or $\operatorname{Com}_{\text{bridge}}$ under Module-SIS. Hash collisions in SHAKE-256 do not enable double-spending.
   - **Theorem 2B (Collision Safety & Denial Resilience):** Proves that distinct coins producing colliding nullifiers reduces strictly to finding collisions in SHAKE-256-384 ($\ge 128\text{ bits}$ under quantum BHT search).
3. **Ledger Consensus Minting Invariant:** Enforces $\text{coin\_id} = H_{\text{mint}}(\text{tx\_id} \parallel \text{idx})$, guaranteeing that distinct coins on ledger possess unique coin identities.
4. **Conditional Min-Entropy of Spent Secrets:** Formally proves $H_\infty(r_{\text{nf}} \mid \text{Public View}) \ge h - \operatorname{negl}(\lambda)$ via the computational hiding (Module-LWE) of $C_j$ and $B$, validating the Zhandry Compressed Oracle reduction in the QROM.
5. **Byte-Level Performance Baseline:** Formulates exact byte-level size accounting, projecting $\mathbf{118.62\text{ KiB}}$ (Profile 1) and $\mathbf{119.75\text{ KiB}}$ (Profile 2) as analytical baselines.

---

## 2. Formal Protocol Statement and Relations

Let the public spend statement be:
$$S = (R_C, \nu, M, B)$$
where:
* $R_C = \{C_1, \dots, C_N\} \subset R_{q_{\text{LoTRS}}}^2$ is the public anonymity set of unspent coin commitments.
* $\nu \in \{0, 1\}^{384}$ is the published public nullifier.
* $M = H_{\text{tx}}(\text{context} \parallel \nu \parallel B) \in \{0, 1\}^{256}$ is the transaction context digest.
* $B \in R_{q_{\text{LoTRS}}}^2$ is the public bridge commitment opening the spent secret.

### Layer 1 Relation ($\mathcal{R}_L$):
A statement $(R_C, M, B)$ and witness $w_L = (j, C_j, \mathbf{pk}_j, v, \text{coin\_id}, r_{\text{nf}}, \boldsymbol{\rho}, \boldsymbol{\tau}_B, \mathbf{z}_j)$ satisfy $\mathcal{R}_L$ if and only if:
1. $j \in [N]$ and $C_j \in R_C$.
2. $C_j \equiv \mathbf{B}_1 \mathbf{pk}_j + \mathbf{B}_2 m_v + \mathbf{B}_3 \mathbf{m}_x + \boldsymbol{\rho} \pmod{q_{\text{LoTRS}}}$ with $\|\boldsymbol{\rho}\|_\infty \le \eta_\rho = 2$.
3. $B \equiv \mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B \pmod{q_{\text{LoTRS}}}$ with $\|\boldsymbol{\tau}_B\|_\infty \le \eta_\tau = 2$.
4. $\mathbf{m}_x = \operatorname{EncodeNF}(\text{coin\_id}, r_{\text{nf}}) \in R_{q_{\text{LoTRS}}}^k$ with coefficients in $\{0, 1, 2, 3\}$.
5. $\mathbf{A}_{\text{sig}} \mathbf{z}_j \equiv c \cdot \mathbf{pk}_j + \mathbf{M}_{\text{ctx}} \pmod{q_{\text{LoTRS}}}$ with $\|\mathbf{z}_j\|_\infty \le B_{z, \infty}$ (valid $(t, n)$ threshold authorization).

### Layer 2 Relation ($\mathcal{R}_H$):
A statement $(B, \nu)$ and witness $w_H = (\text{coin\_id}, r_{\text{nf}}, \boldsymbol{\tau}_B)$ satisfy $\mathcal{R}_H$ if and only if:
1. $\nu = \text{SHAKE256}_{384}(\mathsf{domain}_{\text{null}} \parallel \text{coin\_id} \parallel r_{\text{nf}})$.
2. $\mathbf{m}_x = \operatorname{EncodeNF}(\text{coin\_id}, r_{\text{nf}})$.
3. The multi-limb integer evaluation $V = \mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B$ satisfies:
   $$V \equiv B \pmod{q_{\text{LoTRS}}}$$
   proven over the BabyBear field $\mathbb{F}_p$ via shifted carry chain constraints:
   $$v_i - s_i - c_{i-1}' + W c_i' + C_{\text{shift}}(1 - W) = 0 \pmod p, \quad c_i' \in [0, 3586]$$
   with maximum integer residual $|\Delta_{\max}| \approx 5.88 \times 10^7 < p = 2.01 \times 10^9$.

The transaction proof is $\Pi = (\Pi_L, \Pi_H)$. Ledger verification accepts if and only if:
$$\mathsf{Verify}_L(R_C, M, B, \Pi_L) = 1 \quad \wedge \quad \mathsf{Verify}_H(B, \nu, \Pi_H) = 1 \quad \wedge \quad \nu \notin \mathcal{S}_{\text{spent}}$$

---

## 3. Dedicated Bridge Module-SIS Hardness & Extraction

### Definition (Dedicated Bridge Parameter Profiles)
The bridge commitment matrix $\mathbf{A}_{\text{bridge}} = [\mathbf{A}_1 \mid \mathbf{A}_2] \in R_{q_{\text{LoTRS}}}^{2 \times m_B}$ operates under two parameter profiles:

* **Profile 1 (LoTRS Baseline / 256-bit Secret):**
  - Dimensions: $k_B = 2$, $m_B = 3$, matrix $\mathbf{A}_1 \in R_q^{2 \times 1}$, $\mathbf{A}_2 \in R_q^{2 \times 2}$.
  - Full lattice dimension: $M = 3 \times 256 = 768$.
  - Euclidean difference norm bound:
    $$\|\mathbf{v}_{\text{diff}}\|_2 \le \sqrt{6^2 \cdot 256 + 4^2 \cdot (2 \cdot 256)} = \sqrt{9216 + 8192} \approx 131.94 \le \beta_{\text{bridge}} = 166.5$$
  - BKZ block size: $\beta_{\text{BKZ}} \approx 840 \implies \text{Core-SVP} \approx 222.6\text{ bits}$ quantum.

* **Profile 2 (Expanded / 288-bit Secret / Full $q_H = 2^{64}$ Budget):**
  - Dimensions: $k_B = 2$, $m_B = 4$, matrix $\mathbf{A}_1 \in R_q^{2 \times 2}$, $\mathbf{A}_2 \in R_q^{2 \times 2}$.
  - Full lattice dimension: $M = 4 \times 256 = 1,024$.
  - Euclidean difference norm bound:
    $$\|\mathbf{v}_{\text{diff}}\|_2 \le \sqrt{6^2 \cdot (2 \cdot 256) + 4^2 \cdot (2 \cdot 256)} = \sqrt{18432 + 8192} \approx 163.17 \le \beta_{\text{bridge}} = 200.0$$
  - BKZ block size: $\beta_{\text{BKZ}} \approx 750 \implies \text{Core-SVP} \approx 198.8\text{ bits}$ quantum.

> [!NOTE]
> In both profiles, the dedicated bridge instance satisfies $\text{Core-SVP} \ge 198\text{ bits} \gg 128\text{ bits}$. This is strictly independent of LoTRS v2's internal signature key ($\beta = 100$), ensuring that cross-layer binding cannot be compromised by lower signature security.

### Theorem 1 (Cross-Layer Witness Extraction & Binding)
*Assume $\Pi_L$ has special soundness error $\epsilon_L$ with knowledge extractor $\mathcal{E}_L$, $\Pi_H$ has composite knowledge error $\epsilon_{\text{STARK}} \le 2^{-128.7}$ with knowledge extractor $\mathcal{E}_H$, and $\operatorname{Com}_{\text{bridge}}$ is binding under $\text{MSIS}_{2, m_B, q_{\text{LoTRS}}, \beta_{\text{bridge}}}$.*

*For any quantum polynomial-time adversary $\mathcal{A}$ producing a valid proof tuple $(S, \Pi_L, \Pi_H)$, there exists a polynomial-time extractor $\mathcal{E}$ that outputs a witness:*
$$w = (j, C_j, \mathbf{pk}_j, v, \text{coin\_id}, r_{\text{nf}}, \boldsymbol{\rho}, \boldsymbol{\tau}_B)$$
*such that with probability at least $\epsilon - \epsilon_L - \epsilon_{\text{STARK}} - \mathbf{Adv}^{\text{MSIS}_{\text{bridge}}}(\mathcal{B})$:*
1. $j \in [N]$ and $C_j \in R_C$.
2. $C_j \equiv \operatorname{Com}_{\text{coin}}(\mathbf{pk}_j, v, \text{coin\_id}, r_{\text{nf}}; \boldsymbol{\rho}) \pmod{q_{\text{LoTRS}}}$ with $\|\boldsymbol{\rho}\|_\infty \le 2$.
3. $\nu = \text{SHAKE256}_{384}(\mathsf{domain}_{\text{null}} \parallel \text{coin\_id} \parallel r_{\text{nf}})$.
4. $\mathbf{pk}_j$ satisfies valid $(t, n)$ threshold custody authorization over transaction context $M$.

### Proof:
1. **Extraction from Layer 1 ($\Pi_L$):**
   By special soundness of the lattice $\Sigma$-protocol (with 15-sigma deterministic truncation bound $B_{w, \infty} = 15 \sigma_w$), extractor $\mathcal{E}_L$ rewinds $\mathcal{A}$ and extracts:
   $$w_L = (j, C_j, \mathbf{pk}_j, v, \text{coin\_id}_L, r_{\text{nf}, L}, \boldsymbol{\rho}_L, \boldsymbol{\tau}_{B, L})$$
   satisfying $C_j \in R_C$, $\|\boldsymbol{\rho}_L\|_\infty \le \eta_\rho = 2$, $\|\boldsymbol{\tau}_{B, L}\|_\infty \le \eta_\tau = 2$, and:
   $$B \equiv \mathbf{A}_1 \mathbf{m}_{x, L} + \mathbf{A}_2 \boldsymbol{\tau}_{B, L} \pmod{q_{\text{LoTRS}}}$$

2. **Extraction from Layer 2 ($\Pi_H$):**
   By composite soundness of the zero-knowledge STARK (verified over the quintic extension $\mathbb{F}_{p^5}$ with $\epsilon_{\text{quotient}} \le 2^{-144.93}$ and conservative FRI $N_q = 86$ with $\epsilon_{\text{FRI}} \le 2^{-129.0}$) and the shifted multi-limb carry chain guaranteeing integer equality without wraparound, extractor $\mathcal{E}_H$ extracts:
   $$w_H = (\text{coin\_id}_H, r_{\text{nf}, H}, \boldsymbol{\tau}_{B, H})$$
   satisfying $\nu = \text{SHAKE256}_{384}(\mathsf{domain}_{\text{null}} \parallel \text{coin\_id}_H \parallel r_{\text{nf}, H})$, $\|\boldsymbol{\tau}_{B, H}\|_\infty \le \eta_\tau = 2$, and:
   $$B \equiv \mathbf{A}_1 \mathbf{m}_{x, H} + \mathbf{A}_2 \boldsymbol{\tau}_{B, H} \pmod{q_{\text{LoTRS}}}$$

3. **Binding via Difference Vector:**
   Suppose $\mathbf{m}_{x, L} \ne \mathbf{m}_{x, H}$. Subtracting the two extracted equations for $B$:
   $$\mathbf{A}_1 (\mathbf{m}_{x, L} - \mathbf{m}_{x, H}) + \mathbf{A}_2 (\boldsymbol{\tau}_{B, L} - \boldsymbol{\tau}_{B, H}) \equiv \mathbf{0} \pmod{q_{\text{LoTRS}}}$$
   Define $\mathbf{v}_{\text{diff}} = (\Delta \mathbf{m}_x, \Delta \boldsymbol{\tau}_B) \in R_{q_{\text{LoTRS}}}^{m_B}$.
   - **Non-zeroness:** $\mathbf{m}_{x, L} \ne \mathbf{m}_{x, H} \implies \Delta \mathbf{m}_x \ne \mathbf{0} \implies \mathbf{v}_{\text{diff}} \ne \mathbf{0}$.
   - **Shortness:** The coefficients of $\mathbf{m}_x$ lie in $\{0, 1, 2, 3\}$, so $\|\Delta \mathbf{m}_x\|_\infty \le 3$. Because $\|\boldsymbol{\tau}_B\|_\infty \le 2$, $\|\Delta \boldsymbol{\tau}_B\|_\infty \le 4$.  
     - For Profile 1: $\|\mathbf{v}_{\text{diff}}\|_2 \le 131.94 \le \beta_{\text{bridge}} = 166.5$.
     - For Profile 2: $\|\mathbf{v}_{\text{diff}}\|_2 \le 163.17 \le \beta_{\text{bridge}} = 200.0$.
   - **Modulus Separation:** Since $q_{\text{LoTRS}} = 2^{43} - 67 \approx 8.79 \times 10^{12} \gg 200.0$, $\mathbf{v}_{\text{diff}}$ cannot wrap around modulo $q_{\text{LoTRS}}$ and constitutes a genuine non-zero short Module-SIS vector.
   - Therefore, $\operatorname{Pr}[\mathbf{m}_{x, L} \ne \mathbf{m}_{x, H}] \le \mathbf{Adv}^{\text{MSIS}_{\text{bridge}}}(\mathcal{B})$.

4. **Bijective Nullifier Decoding:**
   Since $\operatorname{EncodeNF}$ is a strictly injective function from raw bitstrings to polynomial limbs, $\mathbf{m}_{x, L} = \mathbf{m}_{x, H}$ implies:
   $$(\text{coin\_id}_L, r_{\text{nf}, L}) = (\text{coin\_id}_H, r_{\text{nf}, H})$$
   Thus, extractor $\mathcal{E}$ outputs the unified consistent witness $w$. $\blacksquare$

---

## 4. Causally Decoupled Double-Spend & Collision Theorems

### Consensus Minting Invariant
The ledger consensus rules enforce that every valid minted coin commitment $C$ is uniquely derived via:
$$\text{coin\_id} = H_{\text{mint}}(\text{tx\_id} \parallel \text{output\_index})$$
where $H_{\text{mint}}$ is a preimage-resistant cryptographic hash function. Consequently, distinct coins produced on the ledger have strictly distinct coin identities:
$$\text{Coin}_a \ne \text{Coin}_b \implies \text{coin\_id}_a \ne \text{coin\_id}_b$$

---

### Theorem 2A (Double-Spend Resistance)
*No polynomial-time adversary $\mathcal{A}$ can spend the same coin commitment $C \in R_C$ twice with distinct nullifiers $\nu^{(1)} \ne \nu^{(2)}$, except with probability bounded by:*
$$\mathbf{Adv}^{\text{DoubleSpend}}(\mathcal{A}) \le 2 \epsilon_{\text{sound}} + 2 \mathbf{Adv}^{\text{MSIS}_{\text{bridge}}}(\mathcal{B}) + \mathbf{Adv}^{\text{CoinBind}}(\mathcal{B})$$
*where $\mathbf{Adv}^{\text{CoinBind}}$ is the binding advantage of $\operatorname{Com}_{\text{coin}}$ under $\text{MSIS}_{2, m_{\text{coin}}, q_{\text{LoTRS}}, \beta_{\text{coin}}}$. In particular, finding collisions in SHAKE-256 does NOT enable double-spending.*

### Proof:
1. Let $T^{(1)}$ and $T^{(2)}$ be two valid transactions accepted by the ledger opening the same coin commitment $C \in R_C$.
2. By Theorem 1, extractor $\mathcal{E}$ extracts witness $(\text{coin\_id}^{(1)}, r_{\text{nf}}^{(1)})$ from $T^{(1)}$ and $(\text{coin\_id}^{(2)}, r_{\text{nf}}^{(2)})$ from $T^{(2)}$.
3. **Case 1: $(\text{coin\_id}^{(1)}, r_{\text{nf}}^{(1)}) = (\text{coin\_id}^{(2)}, r_{\text{nf}}^{(2)})$.**  
   Because SHAKE-256-384 is a deterministic public algorithm:
   $$\nu^{(1)} = \text{SHAKE256}_{384}(\mathsf{domain} \parallel \text{coin\_id}^{(1)} \parallel r_{\text{nf}}^{(1)}) = \text{SHAKE256}_{384}(\mathsf{domain} \parallel \text{coin\_id}^{(2)} \parallel r_{\text{nf}}^{(2)}) = \nu^{(2)}$$
   This contradicts the premise that $\nu^{(1)} \ne \nu^{(2)}$.
4. **Case 2: $(\text{coin\_id}^{(1)}, r_{\text{nf}}^{(1)}) \ne (\text{coin\_id}^{(2)}, r_{\text{nf}}^{(2)})$.**  
   Both extracted witnesses open the identical commitment $C \in R_C$:
   $$C \equiv \mathbf{B}_1 \mathbf{pk}^{(1)} + \mathbf{B}_2 m_v^{(1)} + \mathbf{B}_3 \mathbf{m}_x^{(1)} + \boldsymbol{\rho}^{(1)} \equiv \mathbf{B}_1 \mathbf{pk}^{(2)} + \mathbf{B}_2 m_v^{(2)} + \mathbf{B}_3 \mathbf{m}_x^{(2)} + \boldsymbol{\rho}^{(2)} \pmod{q_{\text{LoTRS}}}$$
   Subtracting the two equations yields:
   $$\mathbf{B}_1 (\mathbf{pk}^{(1)} - \mathbf{pk}^{(2)}) + \mathbf{B}_2 (m_v^{(1)} - m_v^{(2)}) + \mathbf{B}_3 (\mathbf{m}_x^{(1)} - \mathbf{m}_x^{(2)}) + (\boldsymbol{\rho}^{(1)} - \boldsymbol{\rho}^{(2)}) \equiv \mathbf{0} \pmod{q_{\text{LoTRS}}}$$
   Define the difference vector $\Delta \mathbf{w}_{\text{coin}} = (\Delta \mathbf{pk}, \Delta m_v, \Delta \mathbf{m}_x, \Delta \boldsymbol{\rho})$.
   - Since $(\text{coin\_id}^{(1)}, r_{\text{nf}}^{(1)}) \ne (\text{coin\_id}^{(2)}, r_{\text{nf}}^{(2)})$, injectivity of $\operatorname{EncodeNF}$ ensures $\Delta \mathbf{m}_x \ne \mathbf{0}$, hence $\Delta \mathbf{w}_{\text{coin}} \ne \mathbf{0}$.
   - Because $\|\boldsymbol{\rho}\|_\infty \le \eta_\rho = 2$, $\|\Delta \boldsymbol{\rho}\|_\infty \le 4$.
   - The Euclidean norm is bounded by:
     - Profile 1: $\|\Delta \mathbf{w}_{\text{coin}}\|_2 \le \sqrt{4^2 \cdot 256 + 6^2 \cdot 256 + 6^2 \cdot 256 + 4^2 \cdot 2 \cdot 256} \approx 175.27 \le \beta_{\text{coin}} = 220$.
     - Profile 2: $\|\Delta \mathbf{w}_{\text{coin}}\|_2 \le \sqrt{4^2 \cdot 256 + 6^2 \cdot 256 + 6^2 \cdot 2 \cdot 256 + 4^2 \cdot 2 \cdot 256} \approx 199.84 \le \beta_{\text{coin}} = 220$.
   - This directly breaks the binding of $\operatorname{Com}_{\text{coin}}$ under $\text{MSIS}_{\text{coin}}$.
5. Therefore, spending the same coin commitment twice requires breaking commitment binding. Hash collisions do not enable double-spending. $\blacksquare$

---

### Theorem 2B (Collision Safety & Denial Resilience)
*No polynomial-time adversary can find two distinct coins $C_a \ne C_b$ producing identical nullifiers $\nu_a = \nu_b$, except by finding a collision in SHAKE-256-384:*
$$\mathbf{Adv}^{\text{Collision}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Coll}}_{\text{SHAKE256}} \le 2^{-128}$$

### Proof:
1. By the Consensus Minting Invariant, distinct coins $C_a \ne C_b$ strictly have distinct identifiers: $\text{coin\_id}_a \ne \text{coin\_id}_b$.
2. Consequently, their preimage inputs to SHAKE-256-384 are strictly distinct:
   $$(\mathsf{domain} \parallel \text{coin\_id}_a \parallel r_{\text{nf}, a}) \ne (\mathsf{domain} \parallel \text{coin\_id}_b \parallel r_{\text{nf}, b})$$
3. If $\nu_a = \nu_b$, this constitutes an explicit non-trivial collision for SHAKE-256-384.
4. Under the Bras-Høyer-Tapp (BHT) quantum collision algorithm, finding a collision in a 384-bit hash function requires:
   $$T_{\text{BHT}} \ge \Omega(2^{384 / 3}) = 2^{128} \text{ quantum operations}$$
5. **Denial-of-Service Resilience:** An adversary attempting to front-run or deny an honest coin $C_{\text{victim}}$ by generating a fraudulent coin $C_{\text{adv}}$ with $\nu_{\text{adv}} = \nu_{\text{victim}}$ must find a second preimage for $\text{SHAKE256}_{384}(\mathsf{domain} \parallel \text{coin\_id}_{\text{victim}} \parallel r_{\text{nf}, \text{victim}})$, which requires at least $2^{256}$ quantum operations via Grover search. Thus, duplicate-nullifier denial attacks are cryptographically infeasible. $\blacksquare$

---

## 5. Spender Unlinkability in the QROM & Conditional Min-Entropy

We formulate the unlinkability experiment $\text{Game}_{\mathcal{A}}^{\text{UNLINK}}(b)$ where the challenger selects a secret challenge coin index $b \in \{0, 1\}$.

### Lemma 3.1 (Conditional Min-Entropy of Spent Secret)
*Let $\text{View} = (R_C, M, B, \nu, \Pi_L, \Pi_H)$ denote the public transaction transcript. For a freshly spent coin with uniformly generated secret randomness $r_{\text{nf}} \leftarrow \{0, 1\}^h$, the min-entropy of $r_{\text{nf}}$ conditioned on the public view satisfies:*
$$H_\infty(r_{\text{nf}} \mid \text{View}) \ge h - \operatorname{negl}(\lambda)$$

*Proof:*
1. In the coin commitment $C_j \equiv \mathbf{B}_1 \mathbf{pk}_j + \mathbf{B}_2 m_v + \mathbf{B}_3 \mathbf{m}_x + \boldsymbol{\rho} \pmod{q_{\text{LoTRS}}}$, the secret polynomial $\mathbf{m}_x = \operatorname{EncodeNF}(\text{coin\_id}, r_{\text{nf}})$ is masked by CBD error $\boldsymbol{\rho} \leftarrow \chi_\rho^2$. By the hardness of Decision Module-LWE ($\text{MLWE}_{2, 2, q, \chi_\rho}$), $C_j$ is computationally indistinguishable from uniform over $R_q^2$, leaking at most $\operatorname{negl}(\lambda)$ information about $r_{\text{nf}}$.
2. In the bridge commitment $B \equiv \mathbf{A}_1 \mathbf{m}_x + \mathbf{A}_2 \boldsymbol{\tau}_B \pmod{q_{\text{LoTRS}}}$, the opening randomness $\boldsymbol{\tau}_B \leftarrow \chi_\tau^2$ is fresh and independent for each spend. By the Decision Module-LWE hardness of $\mathbf{A}_2 \boldsymbol{\tau}_B$, $B$ is computationally indistinguishable from uniform over $R_q^2$.
3. The proofs $\Pi_L$ and $\Pi_H$ satisfy computational and statistical zero-knowledge (via FACCT rejection sampling with $\Delta < 2^{-149.5}$ for $\Pi_L$ and 4 random blinding rows for $\Pi_H$), leaking no auxiliary information beyond validity of the statement.
4. Hence, prior to evaluating the random oracle for $\nu$, the distribution of $r_{\text{nf}}$ given $\text{View} \setminus \{\nu\}$ has statistical min-entropy at least $h - \operatorname{negl}(\lambda)$. $\blacksquare$

---

### Sequence of Games for Unlinkability:
* **$\text{Game}_0$:** Real spend game where the challenger proves spending coin $C_b$.
* **$\text{Game}_1$:** Challenger replaces STARK proof $\Pi_H^*$ with a zero-knowledge simulator $\mathcal{S}_H$ (guaranteed by 4 random blinding rows and `HidingFriPcs`). Advantage hop: $\mathbf{Adv}^{\text{ZK-STARK}}(\mathcal{A})$.
* **$\text{Game}_2$:** Challenger replaces lattice proof $\Pi_L^*$ with $\Sigma$-protocol simulator $\mathcal{S}_L$ (guaranteed by 15-sigma rejection sampling, statistical distance $\Delta \le 2^{-149.5}$). Advantage hop: $\mathbf{Adv}^{\text{ZK-}\Sigma}(\mathcal{A}) \le 2^{-149.5}$.
* **$\text{Game}_3$:** Challenger replaces bridge commitment $B^*$ with a uniform random vector in $R_{q_{\text{LoTRS}}}^2$. Advantage hop: $2 \mathbf{Adv}^{\text{MLWE}}(\mathcal{A})$.
* **$\text{Game}_4$:** Challenger replaces published nullifier $\nu^*$ with a uniform random 384-bit string $\nu^* \leftarrow \{0, 1\}^{384}$.

### Zhandry Compressed Oracle Reduction:
In $\text{Game}_3$, by Lemma 3.1, the secret $r_{\text{nf}}$ has conditional min-entropy $H_\infty(r_{\text{nf}} \mid \text{View}) \ge h - \operatorname{negl}(\lambda)$.  
By the Compressed Oracle Theorem for quantum query algorithms (Zhandry 2019):
$$|\operatorname{Pr}[S_4] - \operatorname{Pr}[S_3]| \le \frac{2 \pi^2 (q_H + 1)^2}{2^h}$$

* **Profile 1 ($h = 256\text{ bits}$):**
  - For $q_H \le 2^{61.8}$: $\mathbf{Adv}^{\text{QROM}} \le \mathbf{2^{-128.0}}$ (**128.0 bits post-quantum security**).
  - For $q_H = 2^{64.0}$: $\mathbf{Adv}^{\text{QROM}} \le \mathbf{2^{-123.7}}$ (**123.7 bits min-entropy**).
* **Profile 2 ($h = 288\text{ bits}$, $\mathbf{m}_x \in R_q^2$):**
  - For $q_H = 2^{64.0}$: $\mathbf{Adv}^{\text{QROM}} \le \mathbf{2^{-155.7}} \ll \mathbf{2^{-128}}$ (**128+ bit post-quantum security**).

### Theorem 3 (Spender Unlinkability Bound)
*For any quantum polynomial-time adversary making at most $q_H$ quantum queries to the random oracle, the spend unlinkability advantage is bounded by:*
$$\mathbf{Adv}^{\text{UNLINK}}(\mathcal{A}) \le \mathbf{Adv}^{\text{ZK-STARK}} + 2^{-149.5} + 2 \mathbf{Adv}^{\text{MLWE}} + \frac{2 \pi^2 (q_H + 1)^2}{2^h}$$
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
> The $\approx 118.62\text{ KiB}$ (Profile 1) and $\approx 119.75\text{ KiB}$ (Profile 2) sizes represent analytical projections based on LoTRS v2 published parameters ($N=100, T=50$) and conservative Plonky3 FRI parameters ($N_q = 86$). They do not constitute empirically measured benchmark sizes until an end-to-end compiled prototype is executed.
