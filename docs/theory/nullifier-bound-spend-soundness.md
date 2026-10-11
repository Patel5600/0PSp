# Nullifier-Bound Spend Soundness: Cryptographic Relation & Security Game

**Document Version:** 1.0  
**Phase:** 1 (Core Mathematical Target)  
**Date:** October 2026

---

## 1. Motivation: The Binding Bottleneck

In an anonymous transaction protocol, authorization alone is insufficient. If a spender merely proves:
1. "I am one of the $N$ eligible spenders in Ring $R$," and publishes
2. A detached nullifier $\nu = \text{PRF}_{sk}(\text{coin\_id})$,

an adversary can trivially execute several critical attacks:
* **Nullifier Substitution Attack:** An authorized spender produces a valid membership proof for Coin $A$, but publishes a dummy nullifier $\nu^*$ (or the nullifier of unrelated Coin $B$), allowing Coin $A$ to be spent repeatedly.
* **Asset Desynchronization Attack:** The spender evaluates $\nu$ using their secret key but binds it to a fabricated $\text{coin\_id}' \ne \text{coin\_id}$, bypassing the on-chain duplicate check.
* **Threshold Extraction Failure:** If computing $\nu$ requires evaluating an unshared PRF over the master secret $sk$, the $t$ threshold participants must reconstruct $sk$ locally, destroying threshold security.

To prevent these failure modes, the spend authorization and nullifier must be **cryptographically bound** inside a single verifiable relation that can be evaluated across $t$-of-$n$ threshold shares.

---

## 2. Formal Cryptographic Relation: $\mathcal{R}_{\text{spend}}$

Let $\mathbb{T}$ be the set of all committed coins on the ledger. A coin commitment is defined as:
$$C = \mathsf{Commit}(pk, v, \text{coin\_id}, r_{\text{nf}}; \rho) \in R_q^k$$
where:
* $pk = (A, t) \in R_q^{k \times \ell} \times R_q^k$ with $t = A s + e$ ($\|s\|_\infty \le \eta$).
* $v \in \mathbb{Z}$ is the asset value.
* $\text{coin\_id} \in \{0,1\}^{256}$ is the immutable asset identifier (e.g., hash of the funding output).
* $r_{\text{nf}} \in \{0,1\}^{256}$ is a high-entropy secret value dedicated **solely** to nullifier derivation.
* $\rho \in S_\eta^k$ is the commitment opening trapdoor.

### 2.1 The Target Relation
The zero-knowledge spend proof $\pi$ proves knowledge of a witness $w$ satisfying:

$$\mathcal{R}_{\text{spend}}\left( (R_C, \nu, M), \; w \right) = 1$$

where the public statement is:
$$\mathsf{Public} = (R_C = \{C_1, \dots, C_N\}, \; \nu \in \{0,1\}^{384}, \; M \in \{0,1\}^{256})$$
where $M = H_{\text{msg}}(m_{\text{tx}} \,\|\, \text{chain\_id} \,\|\, \nu)$ binds transaction details without disclosing the selected commitment $C_j$.

and the hidden witness is:
$$\mathsf{Witness} = \left( j \in [N], \; C_j \in R_q^k, \; pk_j = (A, t_j), \; s \in R_q^\ell, \; e \in R_q^k, \; v \in \mathbb{Z}, \; \text{coin\_id} \in \{0,1\}^{256}, \; r_{\text{nf}} \in \{0,1\}^{256}, \; \rho \in R_q^k, \; \mathsf{auth} \right)$$

### 2.2 Verifier Predicate
The verifier accepts if and only if all four sub-predicates evaluate to true:

1. **Ring Membership Predicate ($\mathcal{P}_{\text{member}}$):**
   $$C_j \in R_C \quad \wedge \quad C_j = \mathsf{Commit}(pk_j, v, \text{coin\_id}, r_{\text{nf}}; \rho)$$
   *(Verified in zero-knowledge: $C_j$ and $j$ remain strictly hidden).*
2. **Lattice Secret Well-Formedness Predicate ($\mathcal{P}_{\text{norm}}$):**
   $$t_j = A s + e \quad \wedge \quad \|s\|_\infty \le \eta \quad \wedge \quad \|e\|_\infty \le \eta \quad \wedge \quad \|\rho\|_\infty \le \eta$$
3. **Exact Nullifier Binding Predicate ($\mathcal{P}_{\text{null}}$):**
   $$\nu = H_{\text{nf}}\left( \mathsf{domain}_{\text{null}} \,\|\, \mathsf{Encode}(C_j) \,\|\, \mathsf{Encode}(r_{\text{nf}}) \right) \in \{0,1\}^{384}$$
   *(The exact secret $r_{\text{nf}}$ committed inside $C_j$ evaluates the 384-bit nullifier over the canonical encoding of $C_j$. Under the QROM, $\nu$ is pseudorandom and computationally unlinkable across distinct coins).*
4. **Transaction Authorization Predicate ($\mathcal{P}_{\text{auth}}$):**
   $$\mathsf{VerifyAuth}(pk_j, M, \mathsf{auth}) = 1$$
   *(The proof binds to the public transaction context $M$ under the exact public key $pk_j$ opening $C_j$, preventing signature malleability or message substitution).*

---

## 3. The Five Soundness Conditions

Any candidate 0PSP construction must formally satisfy all five conditions:

1. **Witness Existence:** The spender possesses a valid witness $(C_j, pk_j, s, r_{\text{nf}}, \rho)$ matching an active coin $C_j \in R_C$.
2. **Sound Derivation:** The published $\nu$ is deterministically and uniquely determined by the pair $(C_j, r_{\text{nf}})$ matching the committed asset.
3. **Double-Spend Determinism vs. Collision Safety:**
   * **Double-Spend Determinism:** Two spends using the same witness $(C_j, r_{\text{nf}})$ must produce identical nullifiers $\nu_1 = \nu_2$ with probability 1, guaranteed by functional determinism. The ledger duplicate check rejects $\nu \in \mathcal{N}$.
   * **Collision Safety:** Distinct legitimate coins $C_a \ne C_b$ with independent $r_{\text{nf}, a} \ne r_{\text{nf}, b}$ must not collide ($\nu_a \ne \nu_b$). With a 384-bit output, BHT quantum collision security guarantees collision probability is $< 2^{-128}$.
   * **Unlinkability:** For two distinct coins $C_a \ne C_b$ owned by the same wallet, $\nu_a$ and $\nu_b$ are computationally indistinguishable from independent uniform random strings in $\{0,1\}^{384}$.
4. **Non-Malleability & Non-Bypassing:** An adversary cannot generate a proof $\pi^*$ that satisfies the verifier with a forged nullifier $\nu^* \ne H_{\text{nf}}(C_j^*, r_{\text{nf}}^*)$.
5. **Threshold Evaluability Without Key Reconstruction:**
   A threshold subset of key holders $S \subset [n]$ ($|S| \ge t$) can collaboratively authorize the spend on $M$, while the spender client generates $\pi$ locally using $(r_{\text{nf}}, \rho)$ (Experiment 2A), ensuring zero reconstruction of the master secret key.

---

## 4. The Formal Security Game: `Game SPEND-SOUND`

The central experiment measuring whether 0PSP survives adversarial attack is formalized below.

```
Game SPEND-SOUND(A, Π, λ):
  pp ← Setup(1^λ)
  LedgerState := { Coins: ∅, Nullifiers: ∅ }
  KeyStore := ∅
  Corrupt_Set := ∅

  // Challenger exposes four interactive oracles to Adversary A:
  // 1. ODeposit(v): Generates honest (sk, pk), shares sk into {sh_i}, 
  //                 creates C = Commit(pk, v, coin_id; ρ),
  //                 Coins ← Coins ∪ {C}, returns (C, pk, coin_id, vk_1..n)
  //
  // 2. OCorrupt(wallet_id, party_idx):
  //                 If |Corrupt_Set[wallet_id]| < t - 1:
  //                   Corrupt_Set[wallet_id] ← Corrupt_Set[wallet_id] ∪ {party_idx}
  //                   return sh_{party_idx}
  //
  // 3. OSpend(wallet_id, C, R, m):
  //                 Executes threshold signing with honest participants,
  //                 computes ν = PRF_s(coin_id), generates π,
  //                 Nullifiers ← Nullifiers ∪ {ν}, Coins ← Coins \ {C},
  //                 returns (ν, π)
  //
  // 4. OAdvDeposit(C_adv): Adversary inserts arbitrary well-formed coin into Coins

  (R*, ν*, m*, π*) ← A^{ODeposit, OCorrupt, OSpend, OAdvDeposit}(pp)

  // Verification checks:
  valid_proof := (VerifySpend(R*, ν*, m*, π*) == 1)
  is_duplicate := (ν* ∈ Nullifiers)

  // Adversary Win Conditions:
  Win_Theft := (valid_proof AND (R* ⊆ Coins) AND (R* contains only uncorrupted honest coins)
                AND (no OSpend was queried on the spent coin))

  Win_DoubleSpend := (valid_proof AND NOT is_duplicate AND 
                      (The underlying coin C* was already spent in a prior OSpend query))

  Win_Bypass := (valid_proof AND NOT is_duplicate AND
                 (ν* ≠ PRF_s(coin_id*) for the true spent coin witness))

  return (Win_Theft OR Win_DoubleSpend OR Win_Bypass)
```

### Security Definition
A 0PSP construction achieves **Nullifier-Bound Spend Soundness** if for all QPT adversaries $\mathcal{A}$:
$$\Pr[\mathsf{SPEND}\text{-}\mathsf{SOUND}(\mathcal{A}, \Pi, \lambda) = 1] \le \mathsf{negl}(\lambda)$$

---

## 5. The Threshold Evaluation Challenge (Condition 5)

Why does Condition 5 constitute the true mathematical bottleneck?

In classical curves (e.g., Zcash / Monero):
$$\nu = \mathcal{H}_{\text{map}}(C)^x$$
If $x$ is shared via Shamir ($x = \sum \lambda_i x_i$), participants simply compute partial nullifiers $\nu_i = \mathcal{H}_{\text{map}}(C)^{x_i}$ and combine them: $\nu = \prod \nu_i^{\lambda_i}$. The group homomorphic property matches the secret sharing.

In lattices:
* **The Rounding Barrier:** Standard post-quantum PRFs (such as Banerjee-Peikert-Rosen or LWR) use modular rounding:
  $$f_s(x) = \lfloor A_x \cdot s \rceil_p \pmod p$$
  Modular rounding is **inherently non-linear**:
  $$\sum \lambda_i \lfloor A_x \cdot sh_i \rceil_p \ne \left\lfloor A_x \cdot \sum \lambda_i sh_i \right\rceil_p$$
  Individual rounded evaluations cannot be linearly combined without threshold rounding error.
* **The Noise Accumulation Barrier:** If evaluating an unrounded MLWE-based PRF with noise, partial noise terms accumulate and must be filtered or rounded collaboratively without revealing the intermediate secret coordinate values.

### Candidate Architectural Solutions for Condition 5

1. **Construction 1: Distributed, Noise-Flooded Threshold PRF**
   Parties evaluate linear terms $A_x \cdot sh_i$, apply distributed Gaussian noise flooding to hide partial shares, and execute collaborative threshold rounding.
   * *Status / Open Requirements:* Requires a concrete PRF family, proof that noise flooding does not alter the deterministic nullifier output across repeated spends, and proof that transcripts leak zero share information under malicious corruptions. Maintained as a comparison baseline.

2. **Construction 2A: Single-Witness Nullifier with Threshold Authorization (Preferred Baseline)**
   The coin commitment embeds a private nullifier secret $r_{\text{nf}}$:
   $$\nu = H_{\text{PQ}}\left( \mathsf{domain}_{\text{null}} \,\|\, \mathsf{Encode}(C_j) \,\|\, \mathsf{Encode}(r_{\text{nf}}) \right)$$
   The spender client computes $\nu$ locally from $r_{\text{nf}}$, while the $t$-of-$n$ key holders independently verify policy and produce an aggregated threshold authorization $\sigma_{\text{thresh}}$ under static $pk$. The proof $\pi$ binds both components together.
   * *Security Balance:* An attacker with $r_{\text{nf}}$ cannot spend without $\sigma_{\text{thresh}}$; threshold signers cannot spend without $r_{\text{nf}}$. Eliminates the non-linear threshold PRF barrier entirely.

3. **Construction 2B: Shared-Witness Multi-Party Nullifier Prover**
   The nullifier secret $r_{\text{nf}}$ is split among the $n$ key holders, requiring multi-party zero-knowledge proof generation to prove knowledge of $r_{\text{nf}}$ without assembling it.
   * *Trade-off:* Eliminates single-witness storage risk, but introduces high network communication overhead and MPC prover latency.

See `docs/theory/spend-relation-and-proof-binding.md` for the complete mathematical relation and reduction proofs.
