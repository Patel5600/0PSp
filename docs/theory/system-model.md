# 0PSP System Model — Active Single-Relation Candidate

**Status: OPEN.** The role model is specified; a complete secure protocol has not been instantiated.

## Participants

| Role | Description |
|---|---|
| Owner | Owns a valid coin commitment and spending right |
| Custody participant | Holds key material in the specified \(t\)-of-\(n\) authorization scheme |
| Prover | Produces the anonymous spend proof using a valid hidden witness |
| Verifier | Verifies the proof and transaction statement |
| Ledger | Maintains eligible commitments and atomically rejects spent nullifiers |
| Adversary | Quantum-capable; corruption, oracle access, registration, and transcript powers must be defined |

## Public statement and witness

\[
\mathsf{Public}=(R_C,\nu,M,\mathsf{state},\mathsf{params\_id})
\]
\[
w=(j,C_j,pk_j,v,\mathsf{coin\_id},r_{\mathrm{nf}},\rho_C,\sigma_{\mathrm{th}})
\]

The public set \(R_C\) is visible; the selected index \(j\) must remain hidden. The proof must connect the selected commitment opening, selected key, threshold signature, nullifier, and transaction/state rules using the same hidden coin.

## Candidate equations

\[
C_j=\operatorname{SHAKE256}_{384}(D_C\parallel
\operatorname{Encode}(\mathsf{version},\mathsf{params\_id},pk_j,v,\mathsf{coin\_id},r_{\mathrm{nf}},\rho_C)).
\]

\[
\nu=\operatorname{SHAKE256}_{384}(D_N\parallel\mathsf{version}\parallel
\operatorname{LenEncode}(\mathsf{coin\_id})\parallel\mathsf{coin\_id}\parallel
\operatorname{LenEncode}(r_{\mathrm{nf}})\parallel r_{\mathrm{nf}}).
\]

These are candidate functional relations. Commitment hiding/binding and full proof of both relations remain open.

## Adversary model requirements

Each experiment must specify adaptive corruption limits, malicious coin/key registration, honest mint/spend/signing oracles, classical and quantum oracle access, timing/amount/ordering leakage, aborts and side channels, replay and concurrent transaction handling, and whether the contributing custody subset is hidden or public.

## Ledger invariants

The verifier checks the full proof, transaction digest, policy/state rules, and eligibility of the selected coin. The ledger atomically rejects a nullifier already spent. Hash collision resistance does not replace authorization or proof soundness.

## Threshold versus anonymity

Wallet custody threshold \((t,n)\) and anonymity-set size \(N\) are separate. Ringtail's threshold semantics and any SoK/LRS anonymity semantics require an explicit mapping.

## Current code boundary

The nullifier module implements deterministic functional hashing and an in-memory replay model. The coin-commitment module recomputes a hash candidate. Neither is a proof system, consensus ledger, Ringtail adapter, or cryptographic security verifier. The ring helper is ML-DSA-like research arithmetic, not LoTRS or Ringtail arithmetic.
