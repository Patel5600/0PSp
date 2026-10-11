# Security Games and Formal Definitions

**Document version:** 0.1 (draft)  
**Status:** Definitions only — reduction proofs not yet attempted

---

## Overview

This document defines the formal security experiments for each of the five 0PSP properties.
Each game is defined as an interaction between a challenger `C` and a QPT adversary `A`.
Security holds if `A`'s advantage is `negl(λ)` for all QPT `A`.

---

## Game 1: Authorization Soundness (Unforgeability)

**Intuition:** No QPT adversary can produce a valid spend authorization without controlling at least `t` valid shares.

```
Game UNFORG(A, Π, λ):
  pp ← Setup(1^λ)
  (sk, pk) ← KeyGen(pp)
  (sh₁,…,shₙ, vk₁,…,vkₙ) ← ShareKey(sk, t, n)
  
  // Adversary controls up to t-1 shares (adaptive corruption)
  Corrupt_set ← ∅
  
  // A interacts with oracles:
  //   OSign(i, msg, coin_id): returns σᵢ if |Corrupt_set| < t
  //   OCorrupt(i): adds shᵢ to A's view, adds i to Corrupt_set
  //   ONull(coin_id): returns nul for an uncorrupted share (honestly computed)
  
  (msg*, σ*, coin_id*) ← A^{OSign, OCorrupt, ONull}(pp, pk, vk₁,…,vkₙ)
  
  // Win condition:
  return (
    Verify(pk, msg*, σ*) = 1          // valid signature
    AND coin_id* was never queried to OSign  // not a trivial replay
    AND |Corrupt_set| < t              // A did not control t shares
  )
```

**Definition.** Π is `(t, n)`-**threshold-unforgeable** if for all QPT `A`:
```
Pr[UNFORG(A, Π, λ) = 1] ≤ negl(λ)
```

**Reduction target:** Reduce to MSIS_{k,ℓ,q,β}. A forger who produces `σ*` without `t` shares implicitly solves a short-integer solution problem.

---

## Game 2: Spender Anonymity (Ring Member Privacy)

**Intuition:** Given a ring of public keys and a valid spend, the verifier cannot determine which ring member spent.

```
Game ANON(A, Π, λ):
  pp ← Setup(1^λ)
  
  Phase 1 — key generation:
  For i in 1..N:
    (skᵢ, pkᵢ) ← KeyGen(pp)
    (sh^i_1,…,sh^i_n, vk^i_1,…,vk^i_n) ← ShareKey(skᵢ, t, n)
  
  Ring R := {pk₁, …, pkₙ}
  
  // A sees all public keys and may query signatures for any ring member
  // A then challenges on two target identities:
  (i₀, i₁, msg, coin_id, state) ← A^{OSign}(pp, R)
    where OSign(j, msg', coin_id') returns a valid σⱼ for pkⱼ
  
  // Challenger picks a bit and signs with the chosen identity:
  b ←$ {0, 1}
  σ* ← Aggregate({Sign(sh^{ib}_j, msg, coin_id)}_{j∈S}) for some t-subset S
  
  b' ← A^{OSign}(state, R, msg, coin_id, σ*)
  
  return (b' = b)
```

**Definition.** Π is **anonymity-preserving** if for all QPT `A`:
```
Adv_ANON(A) := |Pr[ANON(A,...) = 1] - 1/2| ≤ negl(λ)
```

**Reduction target:** Reduce to MLWE. Distinguishing which key was used requires distinguishing Module-LWE samples.

**Note on rerandomization interaction:** If `pk' = RerandomizeKey(pk, r)` is used, the anonymity game must be run over `pk'`. The reduction must show that distinguishing `pk'` from a fresh key is as hard as MLWE.

---

## Game 3: Key Unlinkability (Rerandomization Security)

**Intuition:** Given an original key and a rerandomized key, no QPT adversary can link them.

```
Game UNLINK(A, Π, λ):
  pp ← Setup(1^λ)
  (sk₀, pk₀) ← KeyGen(pp)
  (sk₁, pk₁) ← KeyGen(pp)   // independent fresh key
  
  r ←$ Rq^k
  pk'₀ ← RerandomizeKey(pk₀, r)
  
  b ←$ {0, 1}
  pk_b := if b=0 then pk'₀ else pk₁
  
  // A may query a rerandomization oracle (bounded: poly(λ) queries)
  // ORerand(pk): returns RerandomizeKey(pk, r') for fresh r'
  // OSign(pk, msg, coin_id): returns σ for that pk (uses corresponding sk)
  
  b' ← A^{ORerand, OSign}(pp, pk₀, pk_b)
  
  return (b' = b)
```

**Definition.** Π has **key unlinkability** if for all QPT `A`:
```
Adv_UNLINK(A) := |Pr[UNLINK(A,...) = 1] - 1/2| ≤ negl(λ)
```

**Reduction target:** Reduce to MLWE. A `pk'₀` that reveals its relation to `pk₀` yields a distinguisher for Module-LWE.

---

## Game 4: Nullifier Correctness and Double-Spend Prevention

**Intuition:** The nullifier reveals nothing about the spender, but reveals reuse of the same coin.

### 4a — Nullifier Pseudorandomness

```
Game NULL-PR(A, Π, λ):
  pp ← Setup(1^λ)
  (sk, pk) ← KeyGen(pp)
  (sh₁,…,shₙ) ← ShareKey(sk, t, n)
  
  b ←$ {0, 1}
  
  For each query (coin_id) from A:
    if b=0: return Nullify(sh₁, coin_id)    // real PRF
    if b=1: return F(coin_id)               // random function
  
  b' ← A(pp, pk)
  return (b' = b)
```

**Definition.** The nullifier is **pseudorandom** if for all QPT `A`:
```
Adv_NULL-PR(A) := |Pr[NULL-PR(A,...) = 1] - 1/2| ≤ negl(λ)
```

**Reduction target:** Reduce to Learning With Rounding (LWR) or MLWE, depending on the PRF construction.

### 4b — Nullifier Binding (No Double-Spend Without Detection)

**Correctness requirement (non-game):**
```
∀ coin_id: Nullify(shᵢ, coin_id) = Nullify(shⱼ, coin_id) for all i,j
  (nullifier is independent of which share computes it, given consistent sk)
```

**Collision resistance requirement:**
```
Pr[ Nullify(sh, cid₁) = Nullify(sh, cid₂) AND cid₁ ≠ cid₂ ] ≤ negl(λ)
```

---

## Game 5: Threshold Security Under Rerandomization

**Intuition:** Corrupting `t-1` shares and seeing polynomially many rerandomizations should not enable forgery.

```
Game THRESH-UNFORG(A, Π, λ):
  pp ← Setup(1^λ)
  (sk, pk) ← KeyGen(pp)
  (sh₁,…,shₙ) ← ShareKey(sk, t, n)
  
  Corrupt_set ← ∅
  Rerand_transcripts ← []
  
  // A may:
  //   OCorrupt(i): receive shᵢ (bounded: at most t-1 corruptions)
  //   ORerand(pk): receive a rerandomized pk' and all updated shares {sh'ᵢ}
  //     for i ∉ Corrupt_set only (honest parties don't reveal their shares)
  //   OSign(i, msg, coin_id): receive a partial sig from honest party i
  //   OAggregate(msg, coin_id, {σᵢ}_{i∈S}): receive aggregate for S ⊆ honest parties
  
  (msg*, σ*, pk*) ← A^{OCorrupt, ORerand, OSign, OAggregate}(pp, pk)
  
  return (
    Verify(pk*, msg*, σ*) = 1
    AND (msg*, pk*) was not a direct output of OAggregate
    AND |Corrupt_set| < t
  )
```

**Definition.** Π is **threshold-unforgeable under rerandomization** if for all QPT `A`:
```
Pr[THRESH-UNFORG(A, Π, λ) = 1] ≤ negl(λ)
```

**This game is the key novelty.** Existing threshold lattice schemes (Raccoon, Ringtail) do not include a rerandomization oracle in their unforgeability game.

---

## Game 6: Full Composition (Combined Security)

The five games above must hold *simultaneously* — not just individually. Composition security requires:

1. The rerandomization oracle in Game 5 does not break the anonymity in Game 2
2. The signing oracle in Game 2 does not break nullifier pseudorandomness in Game 4
3. The corruption oracle in Games 1/5 does not break key unlinkability in Game 3

**Open question:** Does simultaneous security follow from the individual game proofs, or does the composition introduce new attack vectors? This is a primary Phase 2 target.

A tentative argument is that the properties are *modularly composable* under the MLWE assumption, but this needs a formal hybrid argument.

---

## Attack Catalog (Phase 1 Targets)

The following attacks must be either:
- **Ruled out** via a formal reduction, or
- **Instantiated** as a concrete break

| Attack | Target property | Expected reduction |
|---|---|---|
| Transcript attack on rerandomization | P3 (unlinkability) | → MLWE |
| Share recovery from rerandomization pairs | P5 (threshold) | → MLWE (key recovery) |
| Nullifier inversion | P4 (double-spend) | → LWR PRF security |
| Ring member tracing via nullifier | P2 (anonymity) | → PRF unlinkability |
| Adaptive corruption + rerandomization forgery | P1+P5 | → MSIS |
| Lattice reduction on accumulated shares | P5 | → GapSVP / worst-case |

---

## What We Are Not Claiming

1. We do **not** claim these reductions hold yet.
2. We do **not** claim the SCRL lemma is true.
3. We do **not** claim quantum hardness of MLWE beyond the current state of lattice cryptanalysis.
4. We do **not** claim any advantages from the rho/BKZ attack complexity estimates until benchmarked.
