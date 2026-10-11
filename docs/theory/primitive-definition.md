# Primitive Definition: 0PSP

**Document version:** 0.1 (draft — not peer reviewed)  
**Status:** Research definition — no security claims yet

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `λ` | Security parameter |
| `q` | Modulus (prime) |
| `n` | Polynomial ring dimension |
| `k, ℓ` | Module rank parameters |
| `R = Z[x]/(xⁿ+1)` | NTT-friendly cyclotomic ring |
| `Rq = R/qR` | Quotient ring |
| `Rq^k` | Module (rank-k free module over Rq) |
| `χ` | Error distribution (bounded discrete Gaussian) |
| `β` | Bound on short vectors |
| `η` | Coefficient bound for secret key |
| `γ₁, γ₂` | Commitment/hint parameters |

---

## 2. Hardness Assumptions

### 2.1 Module-LWE (MLWE)

**Definition.** The `MLWE_{k,ℓ,q,χ}` problem: distinguish  
`(A, A·s + e)` from `(A, u)` where:
- `A ←$ Rq^{k×ℓ}` uniform
- `s ←$ χ^ℓ` secret
- `e ←$ χ^k` error
- `u ←$ Rq^k` uniform

**Assumed hard** for quantum adversaries when `n ≥ 256`, `q ≈ 2²³`, and `χ` is a bounded discrete Gaussian with width ≥ 1.

### 2.2 Module-SIS (MSIS)

**Definition.** The `MSIS_{k,ℓ,q,β}` problem: given `A ←$ Rq^{k×ℓ}`, find `z ∈ Rq^ℓ` such that `A·z = 0` and `0 < ‖z‖₂ ≤ β`.

**Assumed hard** for the same parameter regime.

---

## 3. The 0PSP Primitive

### 3.1 Syntax

A **0PSP scheme** is a tuple of PPT algorithms:

```
Π = (Setup, KeyGen, ShareKey, RerandomizeKey, Sign, Aggregate, Verify, Nullify)
```

#### `Setup(1^λ) → pp`
Generates public parameters: ring dimension `n`, modulus `q`, module rank `(k, ℓ)`, distributions `χ`, commitment parameters.

#### `KeyGen(pp) → (sk, pk)`
- Sample `A ←$ Rq^{k×ℓ}`, `s ←$ χ^ℓ`, `e ←$ χ^k`
- Set `t := A·s + e` (Module-LWE instance)
- Output `sk := s`, `pk := (A, t)`

#### `ShareKey(sk, t, n) → (sh₁, …, shₙ, vk₁, …, vkₙ)`
- Run `(t, n)`-Shamir over the coefficient representation of `s ∈ Rq^ℓ`
- Each share `shᵢ` is a short vector in `Rq^ℓ`
- Verification keys `vkᵢ := A·shᵢ` allow public verification of individual shares
- **Open question (SCRL):** Can this be done without leaking `s` across polynomially many share queries?

#### `RerandomizeKey(pk, r) → pk'`
- For randomness `r ←$ Rq^k`, compute `pk' := pk + (0, r)` (additive shift in the `t`-component)
- **Open question:** Is there a matching `RerandomizeShare(shᵢ, r) → sh'ᵢ` such that threshold signing on `pk'` still works with `{sh'ᵢ}`?

#### `Sign(shᵢ, msg, coin_id) → σᵢ` (partial signature)
Each party `i` produces a partial signature over `(msg, coin_id)` using their share `shᵢ`.

#### `Aggregate(σ₁, …, σₜ, msg, coin_id, pk') → σ`
Combine `t` partial signatures into a single aggregate signature. Requires verification that each `σᵢ` was produced with a rerandomized share consistent with `pk'`.

#### `Verify(pk', msg, σ) → {0, 1}`
Verify the aggregate signature against the rerandomized public key.

#### `Nullify(shᵢ, coin_id) → nul` (deterministic)
Compute a transaction-specific nullifier:
```
nul := PRF_{shᵢ}(coin_id)
```
where `PRF` is a lattice-based pseudorandom function (e.g., based on the Banerjee–Peikert–Rosen PRF under LWR). The nullifier is:
- **Deterministic:** same inputs always yield the same output
- **Unlinkable:** `nul` reveals nothing about `shᵢ` beyond "some authorized holder spent this coin"
- **Binding:** distinct `coin_id` values yield distinct `nul` values with overwhelming probability

---

## 4. Security Properties (Informal)

### P1 — Post-Quantum Security
Authorization soundness holds against a QPT adversary under MLWE and MSIS.

Formally: No QPT adversary `A` can produce a valid `(msg, σ)` under `pk` without knowledge of `t` shares consistent with `sk`, except with negligible probability in `λ`.

### P2 — Spender Anonymity (Ring-Member Privacy)
Given a ring `R = {pk₁, …, pkₙ}` and a valid signature `σ` over `msg`, no PPT adversary can identify which `pkᵢ` the signer controls, except with advantage `negl(λ)` over uniform guessing.

Formally modeled as a left-or-right anonymity game (see `docs/security/anonymity-game.md`).

### P3 — Rerandomization Security (Key Unlinkability)
Given `pk` and `pk' = RerandomizeKey(pk, r)`, no PPT adversary can distinguish whether `pk` and `pk'` share the same underlying `sk`, except with advantage `negl(λ)`.

### P4 — Nullifier Correctness and Binding
1. **Correctness:** An honest spend with `(shᵢ, coin_id)` always produces the same `nul`.
2. **Collision resistance:** A QPT adversary cannot find `(coin_id₁, coin_id₂)` with `coin_id₁ ≠ coin_id₂` such that `Nullify(sh, coin_id₁) = Nullify(sh, coin_id₂)`, except with negligible probability.
3. **Spend-hiding:** `nul` is computationally indistinguishable from a PRF output to a verifier who does not know `sk`.

### P5 — Threshold Security (t-of-n)
Security holds against an adversary who corrupts up to `t-1` shares: no QPT adversary controlling `t-1` shares can produce a valid aggregate signature, except with negligible probability.

---

## 5. The Critical Open Problem: SCRL

**Share-Compatible Rerandomization Lemma (SCRL)**

*Claim (to be proven or falsified):*  
There exists a rerandomization map `φ_r : Rq^{k×ℓ} × Rq^k → Rq^k` and a corresponding share-update map `ψ_r : Rq^ℓ × Rq → Rq^ℓ` such that:

1. **(Consistency)** `A · ψ_r(shᵢ, r) = φ_r(A·shᵢ, r)` for all `i`
2. **(Threshold Preservation)** For any `t`-subset `S ⊆ [n]`, Lagrange interpolation over `{ψ_r(shᵢ, r)}_{i∈S}` recovers a short vector in the same coset as `s + δ(r)` where `δ(r)` is a known public offset
3. **(Indistinguishability)** `φ_r(pk, r)` is computationally indistinguishable from a fresh `KeyGen` output under MLWE
4. **(Non-recoverability)** Given polynomially many pairs `(pk, φ_r(pk, r))`, no QPT adversary can recover `sk`

**Attack surface for Phase 1:**  
The tension is between (1)+(2) — which require algebraic structure — and (3)+(4) — which require hiding that structure. The same algebraic regularity that enables share consistency may enable key recovery. This is the core research question.

---

## 6. Parameter Targets

| Parameter | Target value | Rationale |
|---|---|---|
| Security level | 128-bit post-quantum | NIST Level 1 / Category 1 |
| Ring dimension `n` | 256 | Standard, supported by NTT |
| Modulus `q` | ≈ 2²³ (8,380,417) | Dilithium prime, NTT-friendly |
| Module rank `k` | 4 | Dilithium-III baseline |
| Module rank `ℓ` | 4 | Dilithium-III baseline |
| Secret bound `η` | 2 | Low-norm secrets |
| Signature bound `γ₁` | 2¹⁷ | Rejection sampling target |
| Nullifier size | ≤ 32 bytes | Comparable to Zcash note nullifier |
| Threshold | `(2, 3)` to `(3, 5)` | Practical wallet configurations |

---

## 7. Comparison with Existing Approaches

| Requirement | ML-DSA | Raccoon | Ringtail | LoTRS | **0PSP target** |
|---|---|---|---|---|---|
| PQ secure | ✓ | ✓ | ✓ | ✓ | ✓ |
| Spender anonymity | ✗ | ✗ | ✗ | ✓ (ring) | ✓ |
| Key rerandomization | ✗ | ✗ | ✗ | ✗ | ✓ |
| Nullifier | ✗ | ✗ | ✗ | ✗ | ✓ |
| Threshold (t-of-n) | ✗ | ✓ | ✓ | ✓ | ✓ |
| All five combined | ✗ | ✗ | ✗ | ✗ | **open** |

---

## 8. What Falsifies This

The following would require abandoning or significantly restructuring the target construction:

1. A proof that SCRL is impossible — i.e., that consistency (1)+(2) is incompatible with indistinguishability (3) under MLWE.
2. A polynomial-time quantum algorithm distinguishing rerandomized keys from fresh keys.
3. A key-recovery attack using `O(poly(n))` rerandomization transcripts.
4. A threshold-signature forgery using `t-1` shares and a rerandomization oracle.

Any of these would be **useful research results**, not failures. We update the target, not the standards.
