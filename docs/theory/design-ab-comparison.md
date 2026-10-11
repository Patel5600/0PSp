# Architectural Comparison: Design A vs. Design B

**Status:** Foundational Architectural Assessment — Phase 1  
**Target:** Determine whether spend-specific key rerandomization is a strict requirement or an artificial cryptographic bottleneck.

---

## 1. Executive Framing

A central assumption in early discussions was that achieving spend privacy in a post-quantum threshold setting requires **rerandomizing** the public key and all constituent secret shares for every transaction (the Share-Compatible Rerandomization Lemma, SCRL).

However, in private transactional systems, anonymity does not inherently mandate mutating the public key. We must systematically evaluate two distinct architectural paths before committing mathematical resources to solving or falsifying SCRL:

```
┌────────────────────────────────────────────────────────────────────────┐
│ DESIGN A: Key & Share Rerandomization Architecture                     │
│                                                                        │
│   Root Keys (sk, pk) ──► Rerandomize: (sk', pk') ──► Threshold Sign    │
│                                                      on pk'            │
│   - New ephemeral key derived per spend                                │
│   - Shares transformed via ψ_r; PK transformed via φ_r                 │
│   - Verifier checks validity under pk'                                 │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ DESIGN B: Static Threshold Key with Anonymous Membership Proof         │
│                                                                        │
│   Root Keys (sk, pk) [Static] ──► 1-out-of-N ZK / Ring Proof           │
│                               ──► Threshold Multisig on Context        │
│                               ──► Deterministic Asset-Bound Nullifier  │
│   - Original threshold keys remain unmodified                          │
│   - Privacy achieved by hiding the key index among a set/tree          │
│   - Double-spending prevented by asset-bound nullifier                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Formal Mechanics

### 2.1 Design A: Rerandomized Keys & Shares

* **Key Generation:** $(sk, pk) \leftarrow \mathsf{KeyGen}(pp)$, shares $(sh_1, \dots, sh_n) \leftarrow \mathsf{Share}(sk, t, n)$.
* **Per-Transaction Rerandomization:**
  * Sample fresh transaction randomness $r \leftarrow \mathcal{R}$.
  * Transform public key: $pk' \leftarrow \varphi_r(pk)$.
  * Key holders compute updated shares: $sh'_i \leftarrow \psi_r(sh_i)$.
* **Authorization:**
  * Participants produce partial signatures $\sigma'_i \leftarrow \mathsf{PartSign}(sh'_i, m)$.
  * Aggregate signature: $\sigma' \leftarrow \mathsf{Combine}(\{\sigma'_i\})$.
  * Verifier checks: $\mathsf{Verify}(pk', m, \sigma') \stackrel{?}{=} 1$.
* **Nullifier:** $nul \leftarrow \mathsf{Nullify}(sk', \text{coin\_id})$ or $\mathsf{Nullify}(sk, \text{coin\_id})$.
* **Anonymity:** Verifier sees $pk'$ and cannot link it to $pk$ (requires key unlinkability under related keys).

### 2.2 Design B: Static Threshold Keys + Anonymous Proof

* **Key Generation:** $(sk, pk) \leftarrow \mathsf{KeyGen}(pp)$, threshold shares $(sh_1, \dots, sh_n)$ remain static across the coin's lifetime.
* **Spend Membership Context:**
  * Coin is committed on-chain as $C = \mathsf{Commit}(pk, v; \rho) \in \mathbb{T}$ (Merkle tree or ring $R = \{pk_1, \dots, pk_N\}$).
* **Authorization:**
  * The $t$ key holders cooperatively produce an aggregated threshold signature $\sigma_{\text{thresh}}$ proving authorization under their static shared key $pk$.
  * The proof of membership $\pi_{\text{anon}}$ proves in zero-knowledge:
    $$\exists \, j \in [N] \quad \text{s.t.} \quad pk = R[j] \quad \wedge \quad \mathsf{Verify}(pk, m, \sigma_{\text{thresh}}) = 1$$
    *(Or via structured 1-out-of-$N$ proofs as demonstrated in LoTRS).*
* **Nullifier:**
  * Computed deterministically over the static secret and coin identifier:
    $$nul = \mathsf{PRF}_{sk}(\text{coin\_id})$$
    *(Evaluated via distributed threshold PRF evaluation without secret reconstruction).*
* **Anonymity:** Verifier sees only the ring $R$, the proof $\pi_{\text{anon}}$, and the nullifier $nul$. No individual key $pk$ or $pk'$ is revealed.

---

## 3. Comparative Analysis Across Core Dimensions

| Dimension | Design A (Rerandomized Keys & Shares) | Design B (Static Keys + Anonymous Proof) | Advantage |
|---|---|---|---|
| **Underlying Math Complexity** | **Extremely High:** Requires solving SCRL. Must construct linear or homomorphic mappings over lattice distributions preserving shortness and rejection bounds. | **Moderate / Standard:** Relies on well-studied lattice multisignatures (e.g., Raccoon/Ringtail) combined with lattice 1-out-of-$N$ proofs (e.g., LoTRS) or lattice SNARKs. | **Design B** |
| **Related-Key Attack Surface** | **Substantial:** Adversary observes polynomial sequences of derived keys $(pk, \varphi_{r_1}(pk), \dots)$ and partial shares $(sh_i, \psi_{r_1}(sh_i), \dots)$. Demands non-standard Related-Key Derivation (RKA) security proofs. | **Zero:** Root keys and shares are never transformed. Standard EUF-CMA threshold unforgeability under static keys applies. | **Design B** |
| **Norm & Distribution Drift** | **Critical Vulnerability:** Lattice secrets must be short. Repeated or even single additive rerandomization risks norm explosion or statistical leakage of secret lattice basis structure. | **None:** Shares remain strictly in their initial centered binomial / Gaussian distribution. Rejection sampling bounds are standard. | **Design B** |
| **Threshold PRF / Nullifier** | Complex interaction: does $nul$ bind to root $sk$ or derived $sk'$? If $sk'$, proving collision across distinct spends of the same asset requires extra ZK proofs. | Natural alignment: $nul$ is bound directly to the immutable asset commitment opening and root key shares via standard distributed PRF. | **Design B** |
| **On-Chain Footprint** | Potentially smaller proof if $pk'$ can be verified directly without a heavy membership proof; however, hiding $pk'$ among eligible spenders still requires a ring/membership proof. | Signature + proof size is bounded by the ring proof. LoTRS demonstrates ~35 KB for 50-of-100 threshold settings. | **Neutral / Context-dependent** |
| **Unique Capabilities** | Allows one-time address delegation without exposing root identity; useful for blind off-chain routing. | Standard spend model (matches Zcash Orchard and Monero architectural logic). | **Design A (if functional)** |

---

## 4. Does Design A Solve a Real Requirement or an Artificial One?

To justify the significant cryptographic risk and complexity of Design A, we must answer: **What exact privacy or protocol capability does Design A provide that Design B cannot deliver?**

1. **Transaction Unlinkability:** Design B already provides cryptographic unlinkability. Because the verifier only checks a zero-knowledge membership argument over the ring $R$ and checks $nul \notin \mathsf{Ledger}$, the verifier learns nothing about which key authorized the spend. Rerandomizing the key adds zero additional anonymity if a membership proof is already employed.
2. **Stealth Address Receiving vs. Spending:** In privacy protocols (e.g., Monero, Dual-Key Stealth Addresses), key rerandomization is primarily used by the **sender/receiver** so that funds can be paid to a one-time destination address. For **spending authorization**, the spender does not need to rerandomize their key; they need to prove membership and cancel the nullifier.
3. **Threshold Coordination Overhead:** In Design A, all $t$ distributed signers must coordinate not only on the transaction message $m$, but on the rerandomization factor $r$, ensuring each signer's share is transformed by the exact same scalar/polynomial shift. A Byzantine signer providing a desynchronized share update bricks the signature. In Design B, signers use their invariant local keys.

---

## 5. Architectural Recommendation for Phase 1

1. **Do not treat SCRL as a prerequisite for post-quantum spend privacy.** Design B achieves all five desired properties (Post-Quantum Security, Spender Anonymity, Double-Spend Prevention, Threshold Compatibility, and Unlinkability) without requiring algebraic share rerandomization.
2. **Maintain SCRL as a pure mathematical research target.** Investigate whether share-compatible rerandomization is mathematically possible or fundamentally impossible over lattice modules. If impossible, publish the impossibility theorem; if possible, evaluate whether its efficiency beats Design B.
3. **Adopt Design B as the primary protocol baseline.** By integrating the structured threshold ring signature techniques of LoTRS with an explicit post-quantum distributed nullifier, 0PSP establishes a viable, defensible post-quantum private spend primitive.
