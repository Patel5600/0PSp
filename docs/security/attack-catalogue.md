# Adversarial Attack Catalogue & Vulnerability Analysis

**Status:** Formal Falsification Framework — Phase 1  
**Purpose:** Identify concrete mathematical failure modes and counterexamples across all candidate 0PSP constructions before claiming security.

---

## 1. Overview of Threat Classes

Every candidate post-quantum private spend primitive must be evaluated against five distinct failure categories:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     0PSP ADVERSARIAL ATTACK TAXONOMY                    │
├─────────────────────────────────────────────────────────────────────────┤
│  [ATK-1] Malformed Share & Rogue Contribution Attacks                   │
│  [ATK-2] Related-Key & Rerandomization Leakage Attacks                  │
│  [ATK-3] Adaptive Participant Corruption (t-1 Compromise)               │
│  [ATK-4] Nullifier Collisions & Partition Linkability                   │
│  [ATK-5] Anonymity Failures via Lattice & Transcript Side-Channels      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Detailed Attack Specifications

### [ATK-1] Malformed Share & Rogue Contribution Attacks

* **Target Property:** Threshold Correctness & Robustness (Unforgeability under active corruption).
* **Adversary Goal:** A malicious signer $i \in \text{Corrupt\_Set}$ submits an adversarially crafted partial signature $\tilde{\sigma}_i$ or perturbed share update $\tilde{\Delta}_i$ that:
  1. Causes the aggregate signature to silently fail verification (Denial of Service), or
  2. Cancels out secret terms from honest participants to forge an authorization for an unapproved message $m^*$, or
  3. Induces a large norm in the aggregated response vector, causing honest participants to fail rejection sampling repeatedly.
* **Lattice-Specific Vulnerability:**
  In classical discrete-log schemes (e.g., FROST), rogue-key attacks are mitigated via proofs of possession (PoP) or binding commitments. In lattice schemes, an adversary can submit a contribution $\tilde{z}_i$ that is slightly outside the norm bound $S_{\gamma_1}$; if the combiner does not verify exact Euclidean/infinity norms per partial signature, the aggregate $\sum \tilde{z}_i$ exceeds $\gamma_1 - \beta$ and leaks private key information during rejection loops.
* **Required Countermeasure / Defense:**
  * Exact per-share verification via public verification keys $vk_i = A \cdot sh_i$.
  * Strict individual norm verification: $\mathsf{PartVerify}(vk_i, m, \sigma_i) \stackrel{?}{=} 1 \wedge \|\sigma_i\|_\infty \le \beta_{\text{partial}}$.
  * Non-interactive zero-knowledge proofs of well-formedness for all submitted partial commitments.

---

### [ATK-2] Related-Key & Rerandomization Leakage Attacks

* **Target Property:** Key Unlinkability (Property 03) & Root Secret Secrecy under Design A.
* **Adversary Goal:** Given polynomial access to rerandomized public keys $\{pk^{(j)} = \varphi_{r_j}(pk)\}_{j=1}^M$ and/or corresponding share updates, recover the root secret $s$ or distinguish whether two derived keys share the same parent wallet.
* **Lattice-Specific Vulnerability:**
  1. **Linear System Inversion:** If the transformation is linear $\varphi_r(A, t) = (A, t + r)$, and if the share update $\psi_r(sh_i) = sh_i + \Delta_i(r)$ publishes or leaks information about $\Delta_i$, an adversary collects linear equations:
     $$A \cdot \Delta_i(r) \equiv r \pmod q$$
     If $\Delta_i$ is sampled from a non-uniform distribution correlated with $sh_i$, the covariance matrix of observed updates reveals the basis of the secret lattice.
  2. **Short Preimage Leakage (Module-SIS):** Computing a valid short update $\Delta$ such that $A \Delta = r$ is an inhomogeneous MSIS problem. Any trapdoor or randomized algorithm used to sample short preimages can leak the trapdoor or root secret over repeated queries unless GPV-style discrete Gaussian smoothing is enforced with parameter $\sigma > \eta_{\epsilon}(\Lambda^\perp(A))$.
* **Falsification Test:**
  Can a quantum adversary observing $M = \text{poly}(\lambda)$ rerandomized key-share pairs reconstruct a short non-zero vector in $\Lambda^\perp(A)$ using BKZ reduction faster than the standard MLWE security bound?

---

### [ATK-3] Adaptive Participant Corruption ($t-1$ Compromise)

* **Target Property:** Threshold Unforgeability (Game 1 / Game 5).
* **Adversary Goal:** Control up to $t-1$ key holders, obtain their private shares $\{sh_1, \dots, sh_{t-1}\}$, and forge a valid spend authorization without honest party participation.
* **Lattice-Specific Vulnerability:**
  * **Lagrange Amplification Attack:** In Shamir sharing over $R_q$, Lagrange coefficients $\lambda_i$ evaluated at arbitrary points can be of order $O(q)$. An adversary with $t-1$ shares knows $f(X)$ up to a single unknown degree-0 constraint. If honest signers engage in interactive signing without binding the abort/rejection decisions to a joint commitment, the adversary can query honest signers on adversarially biased challenges $c$ to extract the remaining secret coordinates via partial-information leakage.
* **Required Countermeasure / Defense:**
  * Round-optimal commitments to random masks (e.g., 2-round commitment as in Ringtail or Threshold Raccoon).
  * Centralized or distributed abort mechanisms ensuring zero secret-dependent aborts.

---

### [ATK-4] Nullifier Collisions & Partition Linkability

* **Target Property:** Double-Spend Prevention (Property 04) & Anonymity (Property 02).
* **Adversary Goal:**
  1. **False Spend Rejection:** Force a collision $nul(C_1) = nul(C_2)$ for two distinct coins $C_1 \ne C_2$ owned by honest users, rendering an honest coin unspendable.
  2. **Double-Spend Forgery:** Produce two valid, distinct spend authorizations for the same coin $C$ that yield distinct nullifiers $nul \ne nul'$, successfully double-spending.
  3. **Partition Linkability:** Exploit the threshold nullifier computation to determine *which* wallet or key share contributed to the nullifier.
* **Lattice-Specific Vulnerability:**
  * If the nullifier uses Learning With Rounding (LWR):
    $$nul = \lfloor A_{\text{null}} \cdot s \cdot \text{coin\_id} \rceil_p$$
    Rounding introduces non-linearity. Computing this under threshold shares $\sum \lambda_i sh_i = s$ requires distributed rounding. If individual parties round locally:
    $$\sum \lambda_i \lfloor A_{\text{null}} \cdot sh_i \cdot \text{coin\_id} \rceil_p \not\equiv \lfloor A_{\text{null}} \cdot s \cdot \text{coin\_id} \rceil_p$$
    Local rounding errors prevent deterministic matching unless a joint distributed evaluation protocol is executed.
* **Required Countermeasure / Defense:**
  * The nullifier must either:
    1. Be evaluated using a post-quantum key-homomorphic PRF over a module where operations commute without threshold rounding error, or
    2. Be bound to the static coin commitment randomness and proven inside the zero-knowledge membership proof (Design B).

---

### [ATK-5] Anonymity Failures via Lattice & Transcript Side-Channels

* **Target Property:** Spender Anonymity (Property 02).
* **Adversary Goal:** Determine which ring member $pk_j \in R = \{pk_1, \dots, pk_N\}$ authorized a spend transaction.
* **Lattice-Specific Vulnerability:**
  * **Rejection Sampling Distribution Fingerprinting:** In Fiat-Shamir with Aborts (Lyubashevsky), the signature response $z$ is accepted only with probability $1/M \exp(-\frac{\|c s\|^2}{2\sigma^2})$. Even after rejection sampling, if the variance $\sigma$ is chosen too tightly, subtle statistical moments in the distribution of $z$ can correlate with the specific secret norm $\|s_j\|$. In a ring setting, if different ring members have slightly different key norms, an adversary can classify which key produced the signature with advantage non-negligibly greater than $1/N$.
* **Required Countermeasure / Defense:**
  * Strict Gaussian tail-bounds with uniform rejection probability.
  * Zero-knowledge proofs that completely de-correlate the signature from the public key representation (e.g., the 1-out-of-$N$ proof layer in LoTRS).

---

## 3. Go / No-Go Decision Criteria

Phase 1 concludes with an explicit **Go/No-Go** gate based on these mathematical properties:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PHASE 1 GO / NO-GO MATRIX                             │
├────────────────────────────────┬───────────────┬────────────────────────────┤
│ Mathematical Criterion         │ Status        │ Decision Impact            │
├────────────────────────────────┼───────────────┼────────────────────────────┤
│ 1. Share Representability      │ FAIL (Shamir) │ NO-GO on Shamir over R_q.  │
│    Can Shamir shares over R_q  │               │ Must pivot to additive     │
│    avoid Lagrange explosion?   │               │ masks (Raccoon pattern).   │
├────────────────────────────────┼───────────────┼────────────────────────────┤
│ 2. SCRL Rerandomization        │ ACTIVE ATTACK │ If unproven or insecure:   │
│    Can short lattice shares    │               │ NO-GO on Design A.         │
│    be updated under LWE shift? │               │ Must pivot to Design B.    │
├────────────────────────────────┼───────────────┼────────────────────────────┤
│ 3. Design B Viability          │ PROVEN        │ GO: LoTRS proves PQ        │
│    Can static threshold keys   │ (LoTRS baseline) structured TRS is         │
│    achieve spend anonymity?    │               │ achievable at ~35 KB.      │
├────────────────────────────────┼───────────────┼────────────────────────────┤
│ 4. Deterministic PQ Nullifier  │ FEASIBLE      │ GO if bound to coin        │
│    Can nullifier be bound      │               │ commitment; requires       │
│    without secret-key leakage? │               │ formal reduction to LWR.   │
└────────────────────────────────┴───────────────┴────────────────────────────┘
```

### Definitive Phase 1 Decision Rule:

* **Proceed with Design A IF AND ONLY IF:**
  A formal reduction proves that short secret shares can be updated consistently with a public key shift $t' = t + r$ without solving MSIS and without leaking $s$ over $M = \text{poly}(\lambda)$ queries.
* **Pivot to Design B IF:**
  SCRL fails or introduces unmanageable related-key vulnerabilities. In Design B, threshold signing remains static, spend anonymity is handled via structured ring proofs (LoTRS), and double spending is prevented via an asset-bound nullifier.
