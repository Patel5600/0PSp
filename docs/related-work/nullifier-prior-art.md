# Post-Quantum Threshold Nullifiers & Linkable Signatures: Prior Art Comparison

**Document Version:** 1.0  
**Phase:** 1 (Prior Art & Novelty Calibration)  
**Date:** October 2026

---

## 1. Context and Purpose

A central objective of 0PSP is to evaluate whether a post-quantum private-spend primitive with threshold authorization and double-spend detection is materially novel, or whether it can be constructed directly from existing post-quantum linkable primitives.

This document examines the two most relevant recent prior-art schemes alongside established lattice threshold signatures:
1. **ID-Based Threshold Linkable Dual-Ring Signature (2024)** (Lattice-based identity-based linkable dual-ring signature with threshold capabilities).
2. **Obscura-PQ (August 2026)** (Lattice-based linkable ring-signature privacy protocol for Algorand, featuring deterministic serial numbers and a testnet prototype).
3. **LoTRS (ACM CCS 2026)** (Practical structured threshold ring signatures from lattices).
4. **Ringtail (ePrint 2024/1113)** (2-round lattice threshold signature from Shamir-shared LWE).
5. **Threshold Raccoon (ePrint 2024/184)** (Practical lattice threshold signatures using additive one-time masks).

---

## 2. Property-by-Property Comparison Matrix

| Property / Feature | ID-Based Threshold Linkable Dual-Ring (2024) | Obscura-PQ (August 2026) | LoTRS (ACM CCS 2026) | Ringtail (2024) | Threshold Raccoon (2024) | 0PSP Target Relation |
|---|---|---|---|---|---|---|
| **Underlying Problem** | Lattice SIS / LWE | Module-LWE / MSIS | Module-LWE / MSIS | Plain LWE | Module-LWE / MSIS | Module-LWE / MSIS |
| **Spender Anonymity** | Linkable Dual-Ring (signer in 1 of 2 rings) | Linkable Ring Signature (1-of-$N$) | Structured Ring Signature (1-of-$N$ orgs) | None (public group key) | None (public group key) | Anonymous membership in coin set / ring |
| **Double-Spend Prevention** | Linkability tag $L = \text{Tag}(sk, \text{params})$ | Deterministic Serial Number $S = \text{PRF}(sk)$ | None (Signature only, no nullifier) | None | None | Sound, Asset-Bound Nullifier $\nu = H_{\text{PQ}}(C, r_{\text{nf}})$ |
| **Threshold Key Architecture** | Identity-Based Threshold Key Extraction | Single-signer only ($t=1$) | Aggregated multisig layer ($T$-of-$T$ sub-group) | $t$-of-$n$ Shamir secret sharing of LWE key | Additive secret sharing with one-time masks | $t$-of-$n$ threshold spend authorization |
| **Anonymity Set Scalability** | Theoretical ($O(N)$ growth in verification) | Capped at $N \le 10$ members on Algorand testnet | Scalable: $N=100$, $T=50$ grid | Scalable to 1024 threshold parties (no ring) | 2-of-3, 3-of-5 configurations (no ring) | Target: $N \ge 64$ ring or tree; sub-linear in $N$ |
| **Concrete Signature / Proof Size** | Tens of kilobytes (asymptotic bounds) | Experimental transaction payload | **53.53 KiB** (Sept 2026 Zenodo artifact; ~35 KB preview) | ~10–25 KB (depending on party count) | ~11–13 KB (for 2-of-3 threshold) | Competitive with LoTRS (**53.53 KiB** baseline) |
| **Threshold Nullifier Evaluation** | Master Key Authority distributes partial tags | Not supported (single signer) | Not supported | Not supported | Not supported | Experiment 2A (single witness + threshold auth) |

---

## 3. Deep Analysis of Key Prior Art

### 3.1 ID-Based Threshold Linkable Dual-Ring Signature (2024)
* **Mechanics:** Built in an identity-based setting where a Private Key Generator (PKG) extracts keys for users. Uses a "dual-ring" structure (one ring of honest potential signers, one ring of corrupted/revoked signers) and defines a linkability tag derived from the lattice secret.
* **Double-Spending Application:** The linkability tag reveals when the same identity signs two distinct messages. If a tag matches an existing ledger record, the second signature is linked and rejected.
* **Limitations relative to 0PSP:**
  1. **Trusted Setup / Key Escrow:** Being Identity-Based, the PKG holds master secrets capable of deriving any user's key, violating trustless blockchain decentralization.
  2. **Non-Asset-Bound Linkability:** The linkability tag links *all* signatures produced by that identity. In a private spend protocol, a user spending Coin A and Coin B must **not** produce linkable tags; only spending Coin A twice should produce a matching tag (nullifier).
  3. **No UTXO / Asset Binding:** Does not prove that the identity owns a specific unspent output or committed balance.

---

### 3.2 Obscura-PQ (August 2026)
* **Authors & System:** Proposed as a post-quantum privacy protocol for Algorand, utilizing linkable ring signatures and a deterministic serial number.
* **Mechanics:** Extends lattice-based ring signatures with a deterministic nullifier / serial number derived from the spender's secret key. Demonstrates end-to-end integration with a blockchain ledger and smart contract verifier.
* **Critical Limitations:**
  1. **Strict Anonymity Cap:** The ring size is artificially constrained to $N \le 10$ due to smart contract computational limits and transaction byte caps. An anonymity set of 10 provides weak statistical privacy against flow-tracing heuristics.
  2. **Absence of Threshold Wallet Support:** Obscura-PQ is strictly a single-party spend scheme ($t = 1$). It provides no mechanism for $t$-of-$n$ key holders (institutional custody, multi-sig wallets) to jointly construct the serial number and ring signature without sharing the root private key.
  3. **Nullifier Evaluation:** Evaluated by a single signer possessing the complete secret key.

---

### 3.3 Ringtail (ePrint 2024/1113) & Threshold Raccoon (ePrint 2024/184)
* **Ringtail:** Demonstrates that standard Shamir secret sharing over $\mathbb{F}_q$ can be applied to LWE secrets by treating $s \in \mathbb{Z}_q^m$ as a vector over the field $\mathbb{F}_q$. It achieves non-interactive distributed key generation and 2-round threshold signatures up to 1024 parties. However, it provides zero spender privacy and zero nullifier functionality.
* **Threshold Raccoon:** Implements Dilithium-style threshold signatures using additive one-time masks, avoiding polynomial interpolation entirely. Like Ringtail, it is an authentication primitive, not a transactional privacy protocol.

---

## 4. The Refined 0PSP Novelty Question

The initial formulation claimed novelty simply by assembling "five ingredients." Prior art demonstrates that:
* Lattice threshold signatures are solved (Raccoon, Ringtail).
* Lattice structured threshold ring signatures are solved (LoTRS).
* Lattice linkable ring signatures with serial numbers have been prototyped (Obscura-PQ).
* Lattice threshold linkable signatures have been explored (ID-Based Dual-Ring 2024).

Therefore, the **novelty hypothesis** must be formulated around the precise unaddressed capability:

> **Research Hypothesis:**  
> Existing post-quantum spend and linkable ring signature constructions cannot support **threshold custody wallets** ($t$-of-$n$ signers) without either:  
> (a) Escrowing/reconstructing the complete private key to evaluate the nullifier (breaking threshold security), or  
> (b) Producing global identity linkability that links unrelated spends by the same wallet (breaking spend privacy), or  
> (c) Relying on an untrusted external identity provider / PKG.  
>  
> 0PSP investigates whether an asset-bound post-quantum nullifier can be evaluated **collaboratively across $t$-of-$n$ threshold key shares** such that:  
> 1. The spend authorization is anonymously verified in a scalable ring/tree ($N \ge 64$).  
> 2. The nullifier is soundly bound to the specific unspent asset commitment.  
> 3. Zero information about uncorrupted secret shares is leaked.

This hypothesis will be falsified if Obscura-PQ can be trivially generalized to threshold PRFs, or if LoTRS can be extended with an asset-bound tag without introducing algebraic or norm incompatibilities.
