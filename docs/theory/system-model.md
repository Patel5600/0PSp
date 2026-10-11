# 0PSP System Model — Candidate Relation

**Status:** Candidate model. No secure end-to-end construction currently instantiates this system model.

## Participants

| Role | Description |
|---|---|
| Owner | Owns a coin commitment and its authorization right |
| Custody participant | Holds one share/key material in the specified t-of-n wallet policy |
| Prover | Produces hidden-member and nullifier proofs |
| Verifier | Verifies proof statements, transaction context and ledger state |
| Ledger | Maintains eligible coin commitments and an atomic set of spent nullifiers |
| Adversary | Quantum-capable adversary with explicitly defined corruption, oracle and transcript access |

## Public statement and witness

Candidate public statement:

\[
\mathsf{Public}=(R_C,\nu,B,M,\mathsf{state}).
\]

The public set \(R_C\) contains candidate coin commitments. The index of the spent commitment must remain hidden. The public nullifier \(\nu\) is deterministic; \(B\) is a fresh bridge commitment; \(M\) binds chain ID, transaction version, inputs, outputs and fees; \(\mathsf{state}\) binds the relevant ledger state.

The witness contains a selected index \(j\), selected commitment opening, wallet key/witness, coin identity, nullifier secret, bridge opening and threshold authorization. A complete proof must show all elements refer to the same hidden coin.

## Adversary capabilities to specify

The formal game must state:
- whether the adversary adaptively corrupts up to \(t-1\) custody participants;
- whether it may choose malformed commitments or keys;
- how valid coins are minted and how duplicate identifiers are prevented;
- whether it can request honest spends/signatures and observe aborts;
- whether hash access is classical or quantum superposition queries;
- what side-channel, timing, amount and anonymity-set leakage is allowed;
- how concurrent transactions and state updates are serialized.

## Nullifier and ledger rule

Candidate nullifier:

\[
\nu=\operatorname{SHAKE256}_{384}
(\mathsf{domain}\parallel\mathsf{version}\parallel\operatorname{Encode}(coin\_id)\parallel r_{\mathrm{nf}}).
\]

The commitment and proof must bind \(r_{\mathrm{nf}}\) to the coin and force the published nullifier to use that same secret. The ledger must atomically reject a nullifier already spent. The hash formula alone does not establish unlinkability or spend authorization.

## Threshold policy versus anonymity set

Wallet custody t-of-n and anonymity-set size \(N\) are different dimensions. The model must say whether the identity of the contributing custody subset is hidden, public, or partially leaked. LoTRS's structured threshold row/column pattern cannot be assumed to implement an arbitrary wallet policy without an explicit protocol mapping and proof.

## Current limitations

The repository's ring/bridge Python helper uses ML-DSA-like q=8,380,417, not LoTRS's q=2^43-67 and q-hat=2^35-451. The bridge commitment is not yet instantiated with proved binding and hiding. A Layer 2 AIR, its actual zero-knowledge backend, and cross-layer composition have not been implemented or proved. All combined-size figures remain projections.
