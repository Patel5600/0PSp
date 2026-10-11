# 0PSP Phase 1: Cryptographic Specification & Falsification Framework

**Codename:** 0PSP (Zero-knowledge Post-quantum Spend Primitive)  
**Phase:** 1 (Mathematical Core Falsification)  
**Date:** October 2026  
**Document Status:** Foundation Research Specification

---

## 1. System Model & Lifecycle

### 1.1 Participants & Environment
The protocol operates in an asynchronous network under standard post-quantum cryptographic assumptions (Module-LWE and Module-SIS over polynomial rings).

* **Owner / Wallet:** A logical entity owning an asset committed on-chain. The private spending capability is split among $n$ distributed nodes.
* **Key Holders ($\mathcal{P}_1, \dots, \mathcal{P}_n$):** A set of $n$ participants, each holding a private share $sh_i$ and a public verification key $vk_i$. Any authorized subset $S \subset [n]$ with $|S| \ge t$ can authorize an asset spend.
* **Verifier / Ledger:** Stateless consensus verifiers and an append-only ledger tracking spent nullifiers $\mathcal{N} \subset \{0,1\}^{256}$.
* **Adversary ($\mathcal{A}$):** A Quantum Polynomial-Time (QPT) algorithm that may adaptively corrupt up to $t-1$ key holders, observe all public ledger data and broadcast transcripts, and query partial signing, rerandomization, and nullifier oracles polynomially many times.

### 1.2 Mathematical Substrate: The Ring & Module
* **Cyclotomic Ring:** $R = \mathbb{Z}[x]/(x^n + 1)$ with $n = 256$ (power of 2).
* **Modulus:** Prime $q = 8,380,417$ ($q \equiv 1 \pmod{2n}$, supporting full NTT). Note that $R_q = R/qR$ is **not a field**; it splits into $n$ degree-1 factors modulo $q$.
* **Secret Distribution:** Centered binomial distribution $S_\eta$ with $\eta = 4$. Secrets $s \in R_q^\ell$ and errors $e \in R_q^k$ are short vectors ($\|s\|_\infty \le \eta$).
* **Public Key:** $(A, t) \in R_q^{k \times \ell} \times R_q^k$ where $t = A s + e$.

### 1.3 Spend Transaction Lifecycle
1. **Minting / Receipt:** A coin $C = \mathsf{Commit}(pk, v, \text{coin\_id}, r_{\text{nf}}; \rho)$ is registered on the ledger (e.g., in a Merkle commitment tree or ring of unspent coins).
2. **Threshold Spend Authorization (Experiment 2A):** When spending, $t$ participants verify policy and threshold-sign transaction details $m^* = (m, C, \nu)$ producing $\sigma_{\text{thresh}}$ under static $pk$.
3. **Nullification:** A deterministic, post-quantum nullifier is evaluated by the spender client:
   $$\nu = H_{\text{PQ}}\left( \mathsf{domain}_{\text{null}} \,\|\, \mathsf{Encode}(C) \,\|\, \mathsf{Encode}(r_{\text{nf}}) \right)$$
   and proven inside the zero-knowledge spend proof $\pi$.
4. **Verification:** The verifier asserts:
   * Spend authorization is valid: $\mathsf{VerifySpend}(R, \nu, m, \pi) = 1$.
   * Nullifier has not been recorded previously: $\nu \notin \mathcal{N}$.
   * The nullifier is then atomically appended: $\mathcal{N} \leftarrow \mathcal{N} \cup \{\nu\}$.

---

## 2. Formal SCRL Definition & Split

The Share-Compatible Rerandomization Lemma (SCRL) is decomposed into four testable sub-claims to isolate mathematical failure modes:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SCRL DECOMPOSED SUB-CLAIMS                      │
├────────────────────────────────────────────────────────────────────────┤
│  [SC-1] Representation & Threshold Correctness                         │
│  [SC-2] Rerandomization Feasibility & Norm Preservation                │
│  [SC-3] Related-Key & Unlinkability Security                           │
│  [SC-4] Privacy Composition & Nullifier Binding                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 [SC-1] Representation & Threshold Correctness
* **Inputs:** Secret $s \in R_q^\ell$ ($\|s\|_\infty \le \eta$), parameters $t, n$.
* **Outputs:** Shares $sh_1, \dots, sh_n \in R_q^\ell$, verification keys $vk_1, \dots, vk_n \in R_q^k$.
* **Correctness Condition:**
  For any subset $S \subseteq [n]$ with $|S| = t$, there exist public reconstruction weights $\{\lambda_i\}_{i \in S}$ such that for honest partial signatures $\sigma_i \leftarrow \mathsf{PartSign}(sh_i, m)$:
  $$\mathsf{Combine}(\{\sigma_i\}_{i \in S}) = \sigma \quad \text{s.t.} \quad \mathsf{Verify}(pk, m, \sigma) = 1 \quad \wedge \quad \|\sigma\|_\infty \le \gamma_1 - \beta$$
* **Falsification Verdict:** **Naive Shamir Response Interpolation FAILS.**
  Lagrange coefficients $\lambda_i \pmod q$ can be $O(q)$. When modular wrapping occurs, the combined response $z = \sum \lambda_i z_i \pmod q$ behaves pseudorandomly over $(-q/2, q/2]^d$, driving the rejection sampling acceptance probability to $P_{\text{accept}} \approx 2^{-3840}$ for ML-DSA-65 (and $2^{-5120}$ for ML-DSA-44).
  *Resolution:* Threshold signing schemes must avoid naive linear response interpolation. They must either adopt **additive secret sharing with zero-sum one-time masks** (Threshold Raccoon paradigm) or **scalar Shamir with distributed non-interactive preprocessing** (Ringtail paradigm).

### 2.2 [SC-2] Rerandomization Feasibility
* **Inputs:** Public key $pk = (A, t)$, rerandomization vector $r \in R_q^k$, individual share $sh_i$.
* **Outputs:** Transformed public key $pk' = \varphi_r(pk)$, transformed share $sh'_i = \psi_r(sh_i)$.
* **Correctness Conditions:**
  1. **Homomorphic Alignment:** $A \cdot \psi_r(sh_i) = \varphi_r(A \cdot sh_i)$.
  2. **Shortness Preservation:** $\|sh'_i\|_\infty \le \beta_{\text{share}}$, allowing continued signing without rejection loops.
* **Falsification Verdict:** **ACTIVE BOTTLENECK.**
  If $t' = t + r$, an honest share update requires adding $\Delta_i$ such that $A \Delta_i \equiv r/n \pmod q$. Finding a short $\Delta_i$ is an instance of the inhomogeneous Module-SIS problem. Solving it in PPT requires either a public trapdoor (destroying security) or increases share norms beyond acceptable bounds.

### 2.3 [SC-3] Related-Key Security
* **Security Game:**
  Challenger samples $(sk, pk) \leftarrow \mathsf{KeyGen}(pp)$. Adversary queries:
  * $\mathcal{O}_{\text{Rerand}}(r)$: returns $pk' = \varphi_r(pk)$ and corrupted share updates $\{sh'_i\}_{i \in \text{Corrupt}}$.
  * $\mathcal{O}_{\text{Sign}}(i, m, r)$: returns partial signatures under rerandomized keys.
  Adversary outputs candidate key $s^*$ or distinguishes derived keys from fresh Module-LWE samples.
* **Requirement:** No QPT adversary can recover $s$ or distinguish $pk'$ with non-negligible advantage over Module-LWE.

### 2.4 [SC-4] Privacy Composition
* **Security Game:** Full left-or-right anonymity game where adversary specifies two public keys $pk_0, pk_1$, receives a signature $\sigma^*$ and nullifier $nul^*$ for $pk_b$ ($b \stackrel{\$}{\leftarrow} \{0,1\}$), and must guess $b$.
* **Requirement:** $\mathbf{Adv}^{\text{ANON}}(\mathcal{A}) \le \mathsf{negl}(\lambda)$ under simultaneous availability of nullifiers and threshold oracles.

---

## 3. Construction Comparison: Design A vs. Design B

| Architectural Dimension | Design A: Rerandomized Keys & Shares | Design B: Static Keys + Anonymous Proof |
|---|---|---|
| **Core Mechanism** | Mutates keys and shares per transaction: $(sk', pk') \leftarrow (\psi_r(sk), \varphi_r(pk))$. | Leaves keys and shares static; proves authorization via 1-out-of-$N$ structured ring proof. |
| **Mathematical Dependency** | Requires resolving SCRL and inhomogeneous Module-SIS preimage generation. | Relies on proven lattice multisignatures (Raccoon/Ringtail) + 1-out-of-$N$ proofs (LoTRS). |
| **Attack Surface** | Exposed to Related-Key Attacks (RKA) and share norm drift over successive spends. | Standard EUF-CMA threshold unforgeability; zero related-key exposure. |
| **Implementation Feasibility** | **High risk / unproven:** Lacks existing post-quantum precedent. | **Demonstrated baseline:** LoTRS demonstrates practical structured TRS at **53.53 KiB** (Sept 2026 artifact). |
| **Spend Privacy Level** | Unlinkable if SCRL holds. | Cryptographically unlinkable via zero-knowledge membership proof and nullifier. |

**Strategic Finding:** Design A imposes severe mathematical risks to solve an issue that Design B resolves natively. In transactional privacy, spenders do not need to alter their root identity; they need to prove membership in an eligible anonymity set and cancel an unspendable tag.

---

## 4. Adversarial Attack Catalogue

1. **[ATK-1] Malformed Share & Rogue Contribution:** Corrupted participants submit out-of-bound partial signatures to corrupt aggregated rejection sampling. *Mitigation:* Strict per-share norm bounds $\beta_{\text{partial}}$ verified against public $vk_i$.
2. **[ATK-2] Related-Key Leakage:** Adversary collects linear equations $A \Delta_j \equiv r_j \pmod q$ from observed rerandomizations. *Mitigation:* Eliminated entirely under Design B.
3. **[ATK-3] Adaptive Participant Corruption ($t-1$):** Adversary uses $t-1$ shares to bias signing challenges. *Mitigation:* 2-round commitment protocols with joint deterministic challenge generation.
4. **[ATK-4] Nullifier Collisions & Linkability:** Non-linear threshold rounding in LWR nullifiers causing evaluation mismatches. *Mitigation:* Evaluating the nullifier over the invariant coin commitment opening within the ZK argument (Experiment 2A).
5. **[ATK-5] Transcript Side-Channels:** Statistical variance in rejection sampling revealing secret key norms. *Mitigation:* Strict Gaussian tail bounds with randomized smoothing.

---

## 5. Go / No-Go Decision Criteria

Phase 1 establishes clear mathematical gating criteria:

1. **NO-GO on Naive Shamir Response Interpolation:**
   *Mathematical Proof:* Modular wrap drives acceptance probability to $P_{\text{accept}} \approx 2^{-3840}$.
   *Action:* Adopt collaborative additive masking (Raccoon) or non-interactive preprocessing (Ringtail).
2. **GATE on Design A (SCRL):**
   *Criterion:* Does an efficient algorithm exist to update lattice secret shares under an additive public key shift $t' = t + r$ without increasing share norms beyond $\gamma_1$ and without solving Module-SIS?
   *Status:* No known construction. Flagged as high-risk open problem.
3. **GO on Design B / Experiment 2A (Static Keys + Selection Proof + Commitment-Bound Nullifier):**
   *Criterion:* LoTRS (ACM CCS 2026) validates post-quantum structured threshold ring signatures (calibrated production baseline: **53.53 KiB** at 50-of-100).
   *Action:* Experiment 2A adopted as the primary architecture for 0PSP. The mathematical focus shifts to proving the unified spend relation $\mathcal{R}_{\text{spend}}$.
