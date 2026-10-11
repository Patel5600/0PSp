# Phase 1: Mathematical Core — Attack the SCRL

**Status:** Active research  
**Goal:** Prove or falsify the Share-Compatible Rerandomization Lemma

---

## The Problem Statement (Precise)

Let:
- `pp = (n, q, k, ℓ, χ, A)` where `A ←$ Rq^{k×ℓ}`
- `s ←$ χ^ℓ`, `e ←$ χ^k`
- `pk = (A, t)` where `t = As + e`
- `(sh₁, …, shₙ)` be an `(τ, n)`-Shamir sharing of `s` over `Rq^ℓ`
  - Concretely: sample polynomial `f(X) = s + a₁X + … + aτ₋₁Xᵀ⁻¹` with `aᵢ ←$ χ^ℓ`
  - `shᵢ = f(ωᵢ)` for distinct evaluation points `ω₁, …, ωₙ ∈ Zq*`

**Rerandomization target:**  
Given randomness `r ←$ Rq^k`, define:
```
pk' := (A, t + r)        // shift the LWE sample
```

**SCRL asks:** Is there a map `Δᵢ : Rq^ℓ × Rq^k → Rq^ℓ` such that:

```
(SC-1)  A · Δᵢ(shᵢ, r) = A·shᵢ + r/n   (each share absorbs 1/n of the shift)
(SC-2)  Σᵢ λᵢ · Δᵢ(shᵢ, r) ≈ s + A⁺r  (Lagrange recombination is consistent)
(SC-3)  ‖Δᵢ(shᵢ, r) - shᵢ‖₂ ≤ β'      (shares remain short after update)
(SC-4)  Δᵢ(·, r) is computationally indistinguishable from fresh χ^ℓ sampling
```

where `A⁺` denotes a right pseudoinverse or a related linear map, and `λᵢ` are Lagrange coefficients.

---

## Known Obstacles

### Obstacle 1: The Algebraic Mismatch

Standard Shamir over `Zq` lifts cleanly: if `f(X)` is a polynomial with coefficients in `Zq`, then `f(ωᵢ) + δᵢ` for random `δᵢ` gives consistent rerandomization only if `Σ λᵢ δᵢ = Δ` for a known target `Δ`.

But our secrets are **short vectors** in `Rq^ℓ`. Adding noise to each share individually destroys the Lagrange recombination structure unless the noise vectors are correlated. Correlated noise may leak information about `s`.

**Concrete tension:**
- For `τ = 2, n = 3` (2-of-3 threshold) with scalars, let `s = s₀ + a₁·1` (affine polynomial)
- `sh₁ = s + a₁`, `sh₂ = s + 2a₁`, `sh₃ = s + 3a₁`
- Add `δ₁, δ₂, δ₃` independently: Lagrange combination gives `s + a₁·α + (δ₁·λ₁ + δ₂·λ₂)` for the `{1,2}` pair
- For this to equal `s + Δ_target`, we need `δ₁·λ₁ + δ₂·λ₂ = Δ_target - a₁·α`
- But `Δ_target - a₁·α` depends on `a₁` (secret randomness), so correlated noise is forced

This is the *algebraic mismatch*: the noise required for consistency reveals information about the secret polynomial's randomness.

### Obstacle 2: Norm Explosion

Shamir over lattice vectors requires modular arithmetic, but Lagrange coefficients `λᵢ = ∏_{j≠i} (ωⱼ)/(ωⱼ - ωᵢ)` can be large in `Zq`. Multiplying shares by large Lagrange coefficients amplifies vector norms. After rerandomization, the updated shares may no longer be short.

**Quantitatively:** For `n = 256`, `q ≈ 2²³`, Lagrange coefficients can be up to `q/2 ≈ 2²²`, amplifying a norm-`η` share to norm `η · q/2 ≈ 2²²·η`. This exceeds any reasonable signing bound.

*Mitigation under study:* Use evaluation points from a special NTT-compatible subgroup where Lagrange coefficients are small (e.g., powers of a primitive `n`-th root of unity modulo `q`). Need to verify this is possible for `(τ, n)` parameters of interest.

### Obstacle 3: Module Structure Mismatch

Shamir's theorem is stated over a field. `Rq = Z[x]/(xⁿ+1, q)` is a ring, not a field (unless `q` is prime and `xⁿ+1` is irreducible mod `q`, which it generally is not for `n=256` — it splits into irreducible factors). 

*Consequence:* Lagrange interpolation may not be well-defined over `Rq`, or the uniqueness of interpolation may fail. This could mean there is no consistent re-sharing at all over this ring.

*Potential fix:* Work component-wise over the NTT representation where each NTT coefficient lives in `Zq` (a field, since `q` is prime). This converts the ring problem into `n` independent scalar secret-sharing instances. Rerandomization in NTT domain may be feasible, with inverse-NTT recovering the time-domain share.

---

## Research Directions

### Direction A: NTT-Domain Shamir (Most Promising)

**Approach:** Apply NTT to convert `s ∈ Rq^ℓ` to `ŝ = NTT(s) ∈ Zq^{nℓ}`. Share each of the `nℓ` coordinates independently using Shamir over `Zq` (which is a field). Rerandomization is applied coordinate-wise. Inverse NTT recovers the share in the ring domain.

**Pros:**
- Lagrange interpolation is well-defined over `Zq`
- Rerandomization per-coordinate is independent
- NTT is efficient

**Cons:**
- Shares in NTT domain are not short (they are elements of `Zq`, not bounded by `η`)
- After inverse NTT, the time-domain share may not be short
- The signing algorithm (e.g., Dilithium-style rejection sampling) requires short secrets

*This is the primary obstruction:* NTT-domain Shamir breaks the norm constraints needed for lattice signing.

**Potential mitigation:** Dilithium-like rejection sampling applied per share. Each party runs a local rejection loop until their partial signature is within bounds. This already happens in schemes like Threshold Raccoon. The question is whether rerandomization *of the key* (not just the signature) is compatible.

### Direction B: Additive Masking Rerandomization

**Approach:** Rather than rerandomizing the secret key, rerandomize the *commitment* to the key. Each party `i` holds a share `shᵢ` of `s`. For a transaction-specific randomness `r`, each party computes a masked share `sh'ᵢ = shᵢ + mᵢ` where `mᵢ` are additive masks with `Σ λᵢ mᵢ = 0`.

**Pros:**
- Lagrange combination of `{sh'ᵢ}` still recovers `s` (masks cancel)
- No new key is derived; rerandomization is at the commitment level
- Related to Threshold Raccoon's one-time masks

**Cons:**
- This is *not* key rerandomization — it's masking during signing
- An adversary who sees the public commitment `A·sh'ᵢ` can observe that `A(sh'ᵢ - shⱼ)` for two observations may reveal `A·(mᵢ - mⱼ)`, potentially leaking mask relations

**Assessment:** Direction B solves a different (weaker) problem. If full key rerandomization (unlinkable across transactions) is required, Direction B is insufficient.

### Direction C: Key Encapsulation Rerandomization

**Approach:** Don't rerandomize the secret key at all. Instead, derive a per-transaction *ephemeral* public key via a key encapsulation mechanism: each signer provides an encryption of their share under the verifier's public key, and the verifier derives a transaction-specific "viewing key" that links the nullifier to the transaction.

**Pros:**
- Avoids the algebraic mismatch entirely
- Compatible with existing threshold schemes

**Cons:**
- Requires an additional KEM (e.g., Kyber/ML-KEM) and changes the architecture
- May not satisfy Property P3 (key unlinkability) as stated, since the original `shᵢ` are used directly

**Assessment:** Direction C may be the basis of a weaker but achievable primitive. If SCRL proves impossible, this becomes the fallback construction with a modified P3 definition.

---

## Candidate SCRL Construction (Provisional)

Based on Direction A + the Threshold Raccoon masking idea:

```
Setup: Work in NTT domain. Evaluation points ωᵢ are NTT-compatible.

ShareKey(sk = s, τ, n):
  ŝ := NTT(s)  ∈ Zq^{nℓ}   // NTT of each coefficient vector
  For each coordinate c in [nℓ]:
    Sample f_c(X) = ŝ[c] + a_{c,1}·X + … + a_{c,τ-1}·X^{τ-1} over Zq
    sh_{i,c} := f_c(ωᵢ)   for each i
  shᵢ := NTT⁻¹({sh_{i,c}}_c)   // invert back to ring domain

RerandomizeKey(pk = (A, t), r):
  t' := t + r     // additive shift
  // Corresponding share update:
  For each coordinate c:
    // Must find Δ_{i,c} such that Σ λᵢ Δ_{i,c} = [A⁺r]_c in NTT domain
    // Proposed: distribute r uniformly: Δ_{i,c} := [A⁺r]_c · (1/n) mod q
    //           Then each sh'_{i,c} = sh_{i,c} + Δ_{i,c}
  sh'ᵢ := NTT⁻¹({sh'_{i,c}}_c)

Verify SCRL conditions:
  (SC-1): A · NTT⁻¹({sh'_{i,c}}) = A·shᵢ + r·(1/n)?
          → Need A⁺ to exist and Lagrange to sum correctly
  (SC-2): Σ λᵢ sh'ᵢ = s + A⁺r?
          → Requires Σ λᵢ · (1/n) = 1/n · Σ λᵢ = 1/n · 1 = 1/n ≠ 1 ✗ FAILS
```

**The construction fails at (SC-2).** The Lagrange sum of the per-share additive corrections gives `r/n`, not `r`. This is the algebraic mismatch instantiated concretely.

**Fix attempt:** Scale each per-share correction by `n`: `Δ_{i,c} = n · [A⁺r]_c`. Then `Σ λᵢ sh'ᵢ = s + n·(1/n)·A⁺r = s + A⁺r`. But then each share's correction is `n · A⁺r`, which has norm `n · ‖A⁺r‖`, potentially large.

**For small `r` (e.g., `‖r‖₂ ≤ ε`), and with `n = 3`:** Norms may remain acceptable. But for the general case with large module shifts, norm explosion is a genuine concern.

**This is the open problem.** The construction sketch exists but the norm analysis and indistinguishability proof are unresolved.

---

## Immediate Next Steps (Phase 1)

- [ ] **P1.1:** Verify whether NTT-domain Shamir with evaluation at NTT points is well-defined for our `(n, q)` parameters. Check: does `q ≡ 1 (mod 2n)` hold? For `q = 8380417, n = 256`: `8380417 - 1 = 8380416 = 2^13 · 1023 = 2^13 · 3 · 341 = 2^13 · 3 · 11 · 31`. We need `512 | 8380416`. `8380416 / 512 = 16368`. ✓ So `q ≡ 1 (mod 512)` — NTT of length 512 is supported. Good.
- [ ] **P1.2:** Compute Lagrange coefficients for `(2,3)` and `(3,5)` threshold at NTT evaluation points. Check their magnitudes relative to `q`.
- [ ] **P1.3:** Run the norm explosion analysis: for a fixed `r` with `‖r‖₂ ≤ γ₁`, what is `‖sh'ᵢ - shᵢ‖₂` after the correction? Is it within the rejection sampling bound?
- [ ] **P1.4:** Attempt a simple Python simulation of the construction. Verify (SC-1) and (SC-2) hold numerically before attempting algebraic proof.
- [ ] **P1.5:** Survey related impossibility results. Is there a theorem showing that any rerandomization of a Shamir-shared lattice key must leak information? Check: Dodis–Yampolskiy PRF, lattice-based verifiable secret sharing impossibilities.

---

## Falsification Criteria

The SCRL is **falsified** if any of the following hold:

1. `(SC-2)` is incompatible with `(SC-4)` — i.e., any consistent rerandomization leaks the secret polynomial's randomness under MLWE.
2. Norm explosion for any rerandomization with `‖r‖₂ > δ` for some threshold `δ` that makes the scheme impractical.
3. An efficient attack recovering `s` from `poly(λ)` pairs `(shᵢ, sh'ᵢ)`.
