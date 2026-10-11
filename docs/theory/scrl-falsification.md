# SCRL Falsification: Four Sub-Claims & Precision Bounds

**Document Version:** 1.0 (Corrected Parameter Alignment & Shamir Scope)  
**Phase:** 1 (Falsification Target)  
**Date:** October 2026

---

## 1. Executive Summary: Scope of the Mathematical Finding

A prior draft stated that "Shamir secret sharing is incompatible with lattice keys." **This conclusion was overly broad and mathematically inaccurate.**

As demonstrated by **Ringtail** (ePrint 2024/1113), standard Shamir secret sharing over the finite field $\mathbb{F}_q$ can be applied directly to LWE secrets by treating $s \in R_q^\ell$ as a collection of $n \ell$ scalar coefficients in $\mathbb{F}_q$, because $R_q$ is an $\mathbb{F}_q$-algebra.

To maintain mathematical rigor, we strictly separate three distinct concepts:

| Proposition | Status | Cryptographic Assessment |
|---|---|---|
| **P1: Ring Structure** | **True** | $R_q = \mathbb{Z}_q[x]/(x^n + 1)$ with $q \equiv 1 \pmod{2n}$ is fully split and contains zero divisors. |
| **P2: Shamir Sharing Feasibility** | **True (Feasible)** | Shamir sharing over $R_q$ is **achievable** coordinate-wise over the scalar field $\mathbb{F}_q$. Zero divisors in $R_q$ do not prevent coordinate-wise sharing over $\mathbb{F}_q$. |
| **P3: Naive Response Interpolation** | **Falsified (Defective)** | Ordinary Lagrange interpolation of individual, bounded ML-DSA signing responses modulo $q$ results in modular wrapping, driving rejection sampling acceptance probability to $\approx 2^{-3840}$. |

The no-go result in Phase 1 is strictly confined to **P3 (naive response interpolation without cancellation masks)**. It is **not** a general impossibility theorem for Shamir sharing in lattice cryptography.

---

## 2. Parameter-Consistent Norm & Rejection Analysis

We examine the exact rejection sampling failure under consistent FIPS 204 parameters for both **ML-DSA-44** and **ML-DSA-65**.

### 2.1 Parameter Baseline (NIST FIPS 204)

| Parameter | ML-DSA-44 (Level 2) | ML-DSA-65 (Level 3) | Description |
|---|---|---|---|
| Modulus $q$ | $8,380,417$ | $8,380,417$ | Prime $2^{23} - 2^7 + 1$ |
| Ring Dimension $n$ | $256$ | $256$ | Degree of cyclotomic polynomial $x^n + 1$ |
| Secret Rank $\ell$ | $4$ | $5$ | Module dimension of secret key $s$ |
| Secret Bound $\eta$ | $2$ | $4$ | Centered binomial bound: $\|s\|_\infty \le \eta$ |
| Challenge Weight $\tau$ | $39$ | $49$ | Non-zero coefficients in challenge $c$ |
| Max Challenge Norm $\beta = \tau \eta$ | $78$ | $196$ | Upper bound on $\|c s\|_\infty$ |
| Mask Bound $\gamma_1$ | $2^{17} = 131,072$ | $2^{19} = 524,288$ | Rejection bound: requires $\|z\|_\infty < \gamma_1 - \beta$ |
| Rejection Target $\gamma_1 - \beta$ | $130,994$ | $524,092$ | Permissible infinity norm for valid signature |

---

### 2.2 Rejection Sampling Analysis: Unmodded Bound vs. Modular Wrap

Consider a $(2, 3)$ threshold configuration with evaluation points $\omega_1 = 1, \omega_2 = 2, \omega_3 = 3 \in \mathbb{F}_q^*$. For signers $\{1, 2\}$, the Lagrange coefficients evaluated at $X = 0$ are:
$$\lambda_1 = \frac{(0-2)}{(1-2)} = 2, \qquad \lambda_2 = \frac{(0-1)}{(2-1)} = -1 \equiv q - 1 \pmod q$$
*(Or for evaluation points $\{1, 2, 3\}$ in general, coefficients satisfy $\max |\lambda_i| \ge 2$).*

If non-adjacent signers participate (e.g., subset $\{2, 3\}$ evaluated with points $1, 2, 3$ where $\lambda_2 = \frac{-3}{2-3} = 3, \lambda_3 = \frac{-2}{3-2} = -2 \equiv q-2$), the centered coefficients are small integers if points are consecutive small integers.

However, if an arbitrary threshold subset $S \subset [n]$ is chosen with evaluation points distributed across $\mathbb{F}_q^*$ (e.g., powers of the primitive root $\zeta$ for NTT compatibility):
$$\max_{i \in S} |\lambda_i| \approx O(q) \approx \frac{q}{2} \approx 4.19 \times 10^6$$

#### Case A: Unmodded Sum Calculation
If $\lambda_i \approx q/2$, the unmodded integer product over $\mathbb{Z}$ yields:
* **Under ML-DSA-65 ($\gamma_1 = 524,288, \tau = 49, \eta_{\text{share}} \approx 12$):**
  $$\| \lambda_i \cdot c \cdot sh_i \|_\infty \approx (4.19 \times 10^6) \times 49 \times 12 \approx 2.46 \times 10^9$$
  Ratio to $\gamma_1$: $\frac{2.46 \times 10^9}{524,288} \approx \mathbf{4,692 \times}$.
* **Under ML-DSA-44 ($\gamma_1 = 131,072, \tau = 39, \eta_{\text{share}} \approx 6$):**
  $$\| \lambda_i \cdot c \cdot sh_i \|_\infty \approx (4.19 \times 10^6) \times 39 \times 6 \approx 9.80 \times 10^8$$
  Ratio to $\gamma_1$: $\frac{9.80 \times 10^8}{131,072} \approx \mathbf{7,477 \times}$.

#### Case B: Rigorous Modular Distribution & Rejection Probability
Because signature operations are performed in the quotient ring $R_q$, the value $\sum \lambda_i z_i \pmod q$ does **not** evaluate to $2.46 \times 10^9$. It wraps modulo $q$ and falls into the centered interval:
$$\left(-\frac{q}{2}, \; \frac{q}{2}\right] = (-4,190,208, \; 4,190,208]$$

When modular wrap occurs, the combined vector $z = \sum \lambda_i z_i \pmod q$ is distributed roughly uniformly across $(-q/2, q/2]^d$ where $d = n \cdot \ell$.

For the signature to pass verification, **all $d$ coordinates** of $z$ must simultaneously fall within the acceptance window:
$$\|z\|_\infty < \gamma_1 - \beta$$

The probability that a single coordinate falls within $(-\gamma_1 + \beta, \; \gamma_1 - \beta)$ under a uniform modular distribution is:
$$p_1 = \frac{2(\gamma_1 - \beta)}{q}$$

* **For ML-DSA-65 ($d = 256 \times 5 = 1,280$ coordinates):**
  $$p_1 = \frac{2(524,092)}{8,380,417} \approx 0.12507 \approx \frac{1}{8}$$
  $$P_{\text{accept}} = p_1^{1280} \approx (0.12507)^{1280} \approx \left(2^{-3}\right)^{1280} = \mathbf{2^{-3840}}$$
* **For ML-DSA-44 ($d = 256 \times 4 = 1,024$ coordinates):**
  $$p_1 = \frac{2(130,994)}{8,380,417} \approx 0.03126 \approx \frac{1}{32}$$
  $$P_{\text{accept}} = p_1^{1024} \approx (0.03126)^{1024} \approx \left(2^{-5}\right)^{1024} = \mathbf{2^{-5120}}$$

**Mathematical Conclusion:**  
An acceptance probability of $2^{-3840}$ is equivalent to an infinite rejection loop. This formally proves why **naive interpolation of signing responses fails**, and why Ringtail and Threshold Raccoon use specialized distributed masking and non-interactive preprocessing to guarantee bounded responses.

---

## 3. Four Decomposed SCRL Research Targets

We maintain the split of SCRL into four independent, sequenced research claims:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SCRL DECOMPOSED TARGETS                         │
├────────────────────────────────────────────────────────────────────────┤
│  [SC-1] Representation & Correctness                                   │
│         Can threshold lattice signing work without naive Lagrange      │
│         wrapping? (Solved via Raccoon/Ringtail masking paradigms).     │
│                                                                        │
│  [SC-2] Rerandomization Feasibility                                    │
│         Can secret shares be updated under an additive LWE shift       │
│         t' = t + r without solving inhomogeneous Module-SIS?           │
│                                                                        │
│  [SC-3] Related-Key & Unlinkability Security                           │
│         Does observing M = poly(λ) rerandomizations leak the secret    │
│         lattice basis under Module-LWE?                                │
│                                                                        │
│  [SC-4] Privacy Composition & Nullifier Soundness                      │
│         Does evaluating the nullifier break anonymity or enable        │
│         partition attacks against uncorrupted threshold shares?        │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Status of Sub-Claims

1. **[SC-1] Share Representation:**
   * *Status:* Resolved by adopting the **additive zero-sum masking** paradigm (Threshold Raccoon) or **scalar Shamir with distributed masking** (Ringtail). Naive Shamir response combination is abandoned.
2. **[SC-2] Rerandomization Feasibility:**
   * *Status:* **ACTIVE OPEN BOTTLENECK.**
   * *Mathematical Obstruction:* For public key $pk = (A, t)$, setting $pk' = (A, t + r)$ requires key holders to update shares $sh_i' = sh_i + \Delta_i$ such that $A \Delta_i \equiv r/n \pmod q$ with $\|\Delta_i\|_\infty \ll \gamma_1$. Finding short preimages $\Delta_i$ without a trapdoor is an instance of **inhomogeneous Module-SIS**.
3. **[SC-3] Related-Key Security:**
   * *Status:* Blocked on SC-2.
4. **[SC-4] Privacy Composition:**
   * *Status:* Transitioned to the **Nullifier-Bound Spend Soundness** experiment (`docs/theory/nullifier-bound-spend-soundness.md`).

---

## 4. Phase 1 Revised Research Decision Gate

1. **GO on Design B as Research Baseline:**
   Static threshold keys avoid the unresolved MSIS preimage problem of SC-2 entirely. Spender privacy is achieved via a 1-out-of-$N$ structured ring proof (LoTRS), while double spending is prevented by an asset-bound nullifier.
2. **HOLD on SCRL General Impossibility Claim:**
   The failure of naive Shamir response interpolation is documented and quantified ($P_{\text{accept}} \approx 2^{-3840}$). We do not claim general impossibility for all Shamir lattice schemes; we acknowledge Ringtail as a working counterexample for threshold authentication.
3. **BLOCK on Novelty Claims:**
   All claims of novelty are suspended pending formal comparison against the 2024 Threshold Linkable Dual-Ring scheme, Obscura-PQ (2026), LoTRS, and Ringtail.
