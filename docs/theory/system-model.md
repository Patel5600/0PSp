# System Model

**Status:** Draft — under active construction  
**Document version:** 0.2

---

## 1. Purpose

This document fixes the exact system model for 0PSP before any construction is attempted. Every security claim, every proof, and every implementation decision must be checkable against this model. If the model is underspecified, no security argument is meaningful.

---

## 2. Participants

| Role | Description |
|---|---|
| **Owner** | Holds (or jointly holds) a secret authorization key for a coin |
| **Key Holder** | One of `n` participants holding a share of the owner's secret key |
| **Verifier** | A stateless party who checks that a spend is authorized and non-duplicate |
| **Ledger** | Append-only set of published nullifiers; checked by verifiers |
| **Adversary** | QPT algorithm; may corrupt up to `t-1` key holders and observe public transcripts |

---

## 3. Assets and Lifecycle

A **coin** is a tuple `C = (cmt, coin_id)` where:
- `cmt` is a cryptographic commitment to `(value, asset_type, pk)` — the owner's public key
- `coin_id` is a unique identifier for this coin (e.g., derived from the commitment randomness)

**Coin lifecycle:**

```
Issue        → Owner generates (sk, pk), publishes cmt = Commit(value, pk; r)
Share        → Owner splits sk into (sh₁,…,shₙ) using (t, n)-Shamir
Spend        → t key holders jointly produce:
                  (1) a spend authorization σ proving pk ∈ authorized ring R
                  (2) a nullifier nul = PRF_sk(coin_id) published to Ledger
Verify       → Verifier checks:
                  (1) σ is a valid authorization for some pk in R (anonymously)
                  (2) nul has not been seen before (no double-spend)
```

---

## 4. Keys and Representations

### 4.1 The Ring

```
n   : power of 2, e.g. 256
q   : prime with q ≡ 1 (mod 2n)
R   : Z[x] / (x^n + 1)   — the cyclotomic ring
R_q : R / qR              — coefficients reduced mod q
```

**Critical note:** `R_q` is a **ring**, not a field. `Z[x]/(x^n+1, q)` factors over `Z_q[x]` as a product of irreducible polynomials, making `R_q ≅ ∏ F_{q^{f_i}}`. This means arithmetic in `R_q` is NOT the same as arithmetic over a field, and Shamir secret sharing does not automatically lift to `R_q`.

### 4.2 Secret Key

```
sk = s ∈ R_q^ℓ    with ‖s‖_∞ ≤ η
```

`s` is a **short** vector — coefficients bounded by `η` (e.g., `η = 4` for Dilithium-III parameters). This shortness is essential for the signature scheme; it is NOT merely a technical convenience.

**Why shortness matters:** The Fiat-Shamir signature (Dilithium-style) requires the signer to produce a response `z = y + cs` where `y` is a fresh mask and `c` is a challenge polynomial. For `z` to be publishable without leaking `s`, we need `‖cs‖_∞ ≤ β` where `β = τη`. If `‖s‖_∞` is not bounded, `z` leaks `s` directly or rejection sampling loops infinitely.

### 4.3 Public Key

```
(A, t)   where  t = As + e,  A ←$ R_q^{k×ℓ},  e ←$ χ^k
```

The public key is a Module-LWE sample. `e` is a short error vector; its role is to prevent key recovery from `(A, t)` under Module-LWE.

### 4.4 Shares

**This is where the first underspecified assumption appears.**

The initial formulation assumed we can Shamir-share `s` over `R_q^ℓ`. But Shamir over `R_q` requires Lagrange interpolation, which requires:

1. Division by `(ω_i - ω_j)` in the ring — only valid if `(ω_i - ω_j)` is a unit in `R_q`.
2. The resulting shares must remain **short** for threshold signing to work.

**Condition 1 analysis:**  
Evaluation points `ω_i ∈ Z_q*` (scalars, not ring elements). Then `ω_i - ω_j ∈ Z_q`, and since `q` is prime, every nonzero element of `Z_q` is a unit. **Condition 1 holds** for scalar evaluation points.

**Condition 2 analysis:**  
A share is `sh_i = f(ω_i)` where `f(X) = s + a_1 X + … + a_{t-1} X^{t-1}` with `a_j ←$ R_q^ℓ` (the randomness polynomial). Each `f(ω_i) = s + Σ_j a_j ω_i^j`. If `a_j` are sampled uniformly over `R_q^ℓ`, then `f(ω_i)` is uniformly distributed over `R_q^ℓ` — it has **large** coefficients (up to `q/2` in centered representation). **Condition 2 fails** with uniform randomness.

**Sub-question:** Can we sample `a_j` from a short distribution and still have a secure sharing scheme?  
- If `a_j ←$ χ^ℓ` (short), the share `sh_i = s + Σ_j a_j ω_i^j` has `‖sh_i‖_∞ ≤ η(1 + Σ |ω_i^j|)`.
- For `ω_i ∈ {1,...,t}` and `t = 5`, the largest `ω_i^{t-1} ≤ 5^4 = 625`. For `η = 4`, `‖sh_i‖_∞ ≤ 4 · (1 + 625) ≈ 2504`. This exceeds `γ_1 = 2^17 = 131072`... actually not immediately — 2504 << 131072. But reconstruction multiplies by Lagrange coefficients which can be much larger.
- **Lagrange norm problem:** Reconstruction `s = Σ λ_i sh_i` where `λ_i ∈ Z_q`. Centered Lagrange coefficients can be as large as `q/2 ≈ 4·10^6`. The reconstructed `s` is correct (sums to the original short `s`), but an individual `λ_i · sh_i` has norm up to `(q/2) · ‖sh_i‖_∞`, which is enormous.

**This is the central structural issue.** Reconstruction works algebraically. But threshold signing requires each party to sign with their *share*, not with the reconstructed secret. If the signing protocol needs the share to be short, and the Lagrange recombination of responses uses large coefficients, the final signature may be invalid or the response vectors may be too large.

### 4.5 Nullifier

```
nul = PRF_s(coin_id)   ∈ {0,1}^256
```

For threshold compatibility, `nul` must be computable from a single share or from a shared-secret derived quantity. This creates a sub-problem:
- If `PRF_s` requires knowing `s` (the full secret), then threshold parties must reconstruct `s` to compute `nul`, which defeats the purpose of threshold signing.
- If `PRF_s` is key-homomorphic, then `nul = ⊕_i PRF_{sh_i}(coin_id)` and no reconstruction is needed — but this requires a key-homomorphic PRF compatible with the lattice structure.

**Open sub-problem:** Does a key-homomorphic PRF exist for our lattice-based secret distribution?  
- BKW (Boneh-Kim-Wu) 2017: Key-homomorphic PRF from Module-LWE. The sum of PRF outputs under related keys can be computed. But "key-homomorphic" here means `PRF_{k_1+k_2}(x) = PRF_{k_1}(x) + PRF_{k_2}(x)`, not XOR.
- For Shamir sharing: `s = Σ λ_i sh_i`, so `PRF_s(x) = PRF_{Σ λ_i sh_i}(x)`. With additive homomorphism: `PRF_s(x) = Σ λ_i PRF_{sh_i}(x)` — this works if the PRF is linear in the key.
- **But:** Lagrange coefficients `λ_i` are large integers in `Z_q`. Computing `λ_i · PRF_{sh_i}(x)` requires scalar multiplication of PRF outputs, which must be defined over the same group. If PRF outputs are in `Z_q^m`, this is fine. If PRF outputs are in `{0,1}^256`, it is not.

This sub-problem needs a concrete resolution before the full design can proceed.

---

## 5. Adversary Model

### 5.1 Adversary Capabilities

| Capability | Bound |
|---|---|
| Corrupted key holders | At most `t-1` |
| Signing oracle queries | Polynomial in `λ` |
| Rerandomization oracle queries | Polynomial in `λ` (if rerandomization is used) |
| Nullifier oracle queries | Polynomial in `λ` |
| Quantum computation | QPT (quantum polynomial time) |

### 5.2 What the Adversary Observes

**Public:** `(A, t = As + e)`, ring `R = {pk_1,...,pk_N}`, all published nullifiers, all published signatures and rerandomized keys, verification keys `vk_i = A·sh_i`.

**Corrupted:** `sh_i` for each `i ∈ Corrupt_set`, with `|Corrupt_set| < t`.

**Not observed:** `sk = s`, uncorrupted shares `sh_i` for `i ∉ Corrupt_set`, commitment randomness.

### 5.3 Security Goals (Informal)

1. **Unforgeability:** No QPT adversary can produce a valid spend for a coin it does not control, even after observing valid spends and corrupting up to `t-1` parties.
2. **Anonymity:** No QPT adversary can identify which ring member authorized a spend.
3. **Double-spend prevention:** No QPT adversary can cause the same nullifier to be accepted twice.
4. **Key unlinkability:** (Only if rerandomization is used) No QPT adversary can link a rerandomized key to its source.

---

## 6. Spend Transaction Structure

A valid spend consists of:

```
Spend = {
    ring:       [pk_1, ..., pk_N]       // Eligible owners (public)
    sigma:      spend authorization      // Proves one ring member authorized
    nullifier:  nul ∈ {0,1}^256         // Published to prevent double-spend
    pk_derived: optional rerandomized pk // Used in sigma if rerandomization applies
}
```

The verifier checks:
1. `Verify(ring, sigma) = 1`
2. `nul ∉ Ledger`
3. If rerandomized: `pk_derived` is validly derived (public check, no secret)

---

## 7. What Is Not Specified Yet (Open Items)

| Item | Status | Dependency |
|---|---|---|
| Threshold signing protocol | Unspecified | Requires share format resolution (§4.4) |
| Rerandomization map φ | Unspecified | Requires SCRL feasibility analysis |
| Share update map ψ | Unspecified | Blocked on φ |
| Membership proof system | Unspecified | Depends on whether Design A or B is pursued |
| Nullifier PRF construction | Partially specified (SHAKE-256 placeholder) | Blocked on key-homomorphic PRF analysis |
| Security reductions | Not attempted | Blocked on construction choice |
