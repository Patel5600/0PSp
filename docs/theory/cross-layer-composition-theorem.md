# Cross-Layer Composition — Conditional Lemmas and Open Assumptions

**Status:** Conditional proof outline. Earlier versions called this a completed theorem; that claim is withdrawn because the required commitment, extractors, zero-knowledge backend and parameter security have not been instantiated.

## 1. Public statement and intended relations

The public statement is \((R_C,\nu,B,M,\mathsf{state})\). The hidden witness must contain one index \(j\), selected coin commitment \(C_j\), wallet key \(pk_j\), coin_id, nullifier secret \(r_{\mathrm{nf}}\), coin commitment opening, bridge opening, and valid threshold authorization.

Layer 1 is intended to prove hidden selection, commitment opening, and authorization for one and the same \(j\). Layer 2 is intended to prove:

\[
B=\operatorname{Com}_{\mathrm{bridge}}(\operatorname{Encode}(\mathsf{version},coin\_id,r_{\mathrm{nf}});\tau_B)
\]

and

\[
\nu=\operatorname{SHAKE256}_{384}
(\mathsf{domain}\parallel\mathsf{version}\parallel coin\_id\parallel r_{\mathrm{nf}}).
\]

Neither relation has been implemented as an end-to-end proof in this repository.

## 2. Conditional same-witness lemma

**Lemma (conditional).** Suppose:
1. an accepted Layer 1 proof has an extractor yielding \(x_L=(\mathsf{version},coin\_id_L,r_{\mathrm{nf},L})\) and \(\tau_L\) such that \(B=\operatorname{Com}_{\mathrm{bridge}}(x_L;\tau_L)\);
2. an accepted Layer 2 proof has a compatible extractor yielding \(x_H=(\mathsf{version},coin\_id_H,r_{\mathrm{nf},H})\) and \(\tau_H\) such that \(B=\operatorname{Com}_{\mathrm{bridge}}(x_H;\tau_H)\) and \(\nu\) is the correct hash of \(x_H\);
3. the bridge commitment is binding for the exact allowed message and randomness domains;
4. both proofs' public statement encodings, protocol identifiers and commitment parameters are byte-for-byte identical.

Then, except with the bridge commitment's binding failure probability, the extracted commitment inputs agree: \(x_L=x_H\). Deterministic hashing then fixes the nullifier for that committed input.

**Proof sketch.** Two distinct openings of the same \(B\) would violate the assumed binding property. This argument is conditional; it does not establish that the candidate formula in the other documents is a binding commitment.

## 3. What is not proved by the lemma

The lemma does not itself prove:
- that the selected coin commitment is hiding or binding;
- that Layer 1 hides the selected index;
- that LoTRS supports arbitrary \(t\)-of-\(n\) wallet custody after the proposed extension;
- that either proof has the required quantum knowledge-soundness/extractability property;
- that Layer 2 is zero knowledge;
- that the actual bridge commitment is hiding;
- that the QROM challenge input retains the assumed conditional min-entropy;
- that the Module-SIS/Module-LWE instances meet 128-bit quantum security;
- that the full protocol is unlinkable or practical.

## 4. Double-spend argument target

For one valid coin, commitment binding must fix the coin_id and r_nf used by every accepted proof. Since the nullifier function is deterministic, repeated valid spends then publish the same \(\nu\). The ledger must atomically reject any \(\nu\) already spent.

This requires a valid commitment-opening relation, proof soundness/knowledge soundness for the actual composition, valid minting/asset uniqueness rules, and ledger state correctness. Collision resistance between distinct coins is a separate property that reduces accidental duplicate-nullifier conflicts; it is not the reason repeated spends are rejected.

## 5. QROM unlinkability target

Use a fully stated left-or-right game with adversary oracle access, challenge choice, public transcript, corrupted participants, and allowed auxiliary information. If a compressed-oracle/O2H bound is used, state its exact theorem and hypotheses. In particular, do not infer statistical conditional min-entropy from computational hiding alone. The expression \(2\pi^2(q_H+1)^2/2^h\) is an illustrative conditional bound until the game-specific reduction is completed.

## 6. Parameter and performance caveats

LoTRS has separate main and binary proof moduli \(q=2^{43}-67\) and \(\hat q=2^{35}-451\). The current ML-DSA-like implementation is not a LoTRS implementation. Earlier Core-SVP/BKZ estimates in this repository are not formal hardness proofs; the claimed block sizes and error models need independent estimator validation. The 118.62/119.75 KiB package sizes are projections, not measured proof sizes.

The only valid conclusion at this stage is the conditional same-commitment interface above. Full soundness, unlinkability, security level and practicality remain open.
