# 0PSP Phase 1 Specification — Current Research Model

**Status:** Candidate model, not an implemented or proven primitive. This document supersedes earlier wording that treated SCRL or the five-property composition as the current construction.

## 1. Research objective

Study whether an asset-specific deterministic nullifier can be bound to the same hidden coin and threshold authorization that a spend proof validates, without revealing which member of the public anonymity set was selected.

The target properties are post-quantum authorization under explicit assumptions; hidden coin selection; deterministic asset-bound nullifier and duplicate-nullifier rejection; wallet custody threshold \(t\)-of-\(n\), distinct from anonymity-set size \(N\); and practical proof and verification costs that must be measured.

Novelty and end-to-end security remain unverified research hypotheses.

## 2. Current public statement and witness target

Candidate public statement:

\[
\mathsf{Public}=(R_C,\nu,B,M,\mathsf{state})
\]

where \(R_C=\{C_1,\ldots,C_N\}\) is the eligible commitment set, \(\nu\) is a 48-byte nullifier, \(B\) is a fresh per-spend bridge commitment, \(M\) binds chain context, inputs, outputs and fees, and \(\mathsf{state}\) binds the accepted ledger root and spent-nullifier set.

Candidate witness:

\[
w=(j,pk_j,v,coin\_id,r_{\mathrm{nf}},\rho,\tau_B,\mathsf{auth})
\]

The index \(j\) and selected commitment \(C_j=R_C[j]\) must remain hidden. A complete relation must prove that \(C_j\) opens to the same wallet key and coin data used by the nullifier and authorization relations.

## 3. Nullifier candidate

\[
\nu=\operatorname{SHAKE256}
(\mathsf{domain}_{\mathrm{null}}\parallel
\mathsf{version}\parallel
\mathsf{Encode}(coin\_id)\parallel
r_{\mathrm{nf}},48\text{ bytes})
\]

Here \(r_{\mathrm{nf}}\) is a distinct coin-specific secret. The commitment must bind it to the coin. The formula is deterministic; this alone does not prove unlinkability, PQ security of the complete protocol, or soundness of the witness relation.

Domain, version, input lengths and canonical encoding must be frozen. The public verifier must reject a nullifier already recorded in the ledger's spent set.

## 4. Parameter namespaces

The current Python parameter object models ML-DSA-like arithmetic:
- \(n=256\), \(q=8{,}380{,}417\).
- It is not a LoTRS parameter object.

The LoTRS artifact has separate roles for \(q=2^{43}-67\) and \(\hat q=2^{35}-451\). Do not silently instantiate the LoTRS proof using the ML-DSA ring class. The exact LoTRS arithmetic and auxiliary-prime NTT implementation must be reused or separately implemented and tested.

## 5. Protocol sketch (conditional)

1. Mint a commitment whose opening binds wallet authorization key, coin identity, value and nullifier secret.
2. Publish the coin commitment into the eligible set according to ledger consensus.
3. A qualified \(t\)-of-\(n\) policy authorizes the transaction context. The relation between threshold authorization and the hidden commitment must be constructed explicitly.
4. The prover computes deterministic \(\nu\), commits to nullifier input with fresh \(B\), and produces the paired proofs.
5. Ledger verification checks both proof relations, transaction context, current eligible state, value conservation and duplicate-nullifier status; then atomically records \(\nu\) as spent.

Every item above is a specification target until a concrete implementation and proof exist. The current repository does not implement steps 3–5 as one secure protocol.

## 6. Phase 1 gates

- Select and analyze real coin and bridge commitments.
- Prove the same hidden index connects selection, commitment opening and threshold authorization.
- Define a complete STARK AIR over explicitly specified fields, with all range and integer equality checks constrained.
- Prove the two proofs compose under stated zero knowledge and knowledge-soundness assumptions.
- Calculate security against the weakest component and reproduce parameter estimates.
- Measure proof size, proving time, verification time, communication rounds and peak memory.

No token, chain, production deployment, or novelty claim is in scope until these gates are passed.
