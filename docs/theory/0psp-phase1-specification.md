# 0PSP Phase 1 Specification — Active V0 Research Model

**Status: OPEN.** This is a research target, not a completed primitive or security proof.

> **RFC-02 clarification (2026-10-11):** The phase-one goal still requires transaction authorization under the same hidden coin/key. The exact authorization semantics have not been frozen: committee threshold authorization and self-spend key-knowledge are different policies, not interchangeable implementations. See [the current relation draft](spend-relation-spec.md).

## Objective

Study whether a post-quantum private-spend protocol can prove in one anonymous proof that the spender: (1) selected a valid coin from a public anonymity set without revealing which member; (2) knows its canonical commitment opening; (3) has threshold authorization for the transaction under that same coin key; (4) published the deterministic nullifier bound to that coin; and (5) satisfies ledger and transaction rules.

Novelty, end-to-end security, zero knowledge, and practical proof costs remain unverified.

## Active architecture

CHP3 retires the earlier LoTRS + separate STARK + lattice bridge as the active V0 path. That architecture remains historical research. V0 targets one proof-of-knowledge / signature-of-knowledge relation for the complete spend. The proof backend is not selected or integrated.

Ringtail is a candidate threshold-signature component. Its published prototype uses dealer-based key generation; V0 must state that trust assumption unless DKG is added. The generic PQ SoK/LRS repository is an experimental scaffold, and its documented zero-knowledge enhancement does not convey a security guarantee to 0PSP.

## Public statement and hidden witness

\[
x_{\mathrm{pub}}=(R_C,\nu,M,\mathsf{state},\mathsf{params\_id})
\]

Here \(R_C=\{C_1,\ldots,C_N\}\) is the public eligible-coin set, \(\nu\in\{0,1\}^{384}\) is the nullifier, \(M\) binds protocol version, chain ID, inputs, outputs, fees and \(\nu\), and state identifies the ledger snapshot used for verification.

\[
w=(j,C_j,pk_j,v,\mathsf{coin\_id},r_{\mathrm{nf}},\rho_C,\sigma_{\mathrm{th}})
\]

The index \(j\) and selected commitment \(C_j=R_C[j]\) are hidden witnesses. Privacy means that the complete transcript does not reveal the selected member beyond explicitly permitted leakage.

## Candidate coin commitment

\[
C=\operatorname{SHAKE256}_{384}\left(D_C\parallel
\operatorname{Encode}(\mathsf{version},\mathsf{params\_id},pk,v,\mathsf{coin\_id},r_{\mathrm{nf}},\rho_C)\right).
\]

The functional helper uses a 48-byte output, explicit field lengths, a 36-byte nullifier secret, and independent 36-byte commitment salt. This is a hash-commitment candidate, not a proven commitment. Hiding, binding, canonical public-key serialization, and a QROM proof of the exact opening relation remain open.

## Candidate nullifier

\[
\nu=\operatorname{SHAKE256}_{384}\left(D_N\parallel\mathsf{version}\parallel
\operatorname{LenEncode}(\mathsf{coin\_id})\parallel\mathsf{coin\_id}\parallel
\operatorname{LenEncode}(r_{\mathrm{nf}})\parallel r_{\mathrm{nf}}\right).
\]

Current functional interface: 32-byte coin ID, 36-byte per-coin secret, 48-byte output, fixed domain/version, length-prefixed encoding. Determinism is testable; unlinkability does not follow from SHAKE output length. The 32-byte coin ID must be scoped to one canonical ledger/deployment and asset namespace because the nullifier preimage has no separate chain/asset field. The minting process must enforce uniqueness and bind that scoped ID into the coin commitment. The current helper does not generate or validate coin IDs, so this remains a full-construction gate; reusing a coin ID and nullifier secret across domains would reuse the nullifier and can enable unwanted cross-domain correlation or replay. A QROM theorem must specify the exact game, conditional-entropy premise, query budget, and reduction. The generic \(2^{b/3}\) quantum collision-work estimate is not a protocol theorem.

## Required single-relation predicates

The same hidden \(j\), key, coin ID and \(r_{\mathrm{nf}}\) must satisfy:
1. \(j\in[N]\) and \(C_j=R_C[j]\).
2. The canonical coin commitment opening is correct.
3. The concrete threshold signature verifies under the same key bound into \(C_j\) on \(M\).
4. \(\nu\) is the deterministic nullifier from the same committed coin ID and \(r_{\mathrm{nf}}\).
5. The coin is eligible and unspent; transaction outputs, fees, and value conservation satisfy protocol rules.
6. The index, opening, and threshold signature remain hidden to the degree required by the anonymity game.

The repository has only helper functions for commitment hashing, nullifier hashing, and an in-memory replay model. It does not implement a proof establishing these predicates together.

## Status gates

| Property | Required evidence | Status |
|---|---|---|
| Threshold authorization | Concrete threshold scheme, access structure, corruption model | OPEN |
| Commitment hiding/binding | Defined games and a concrete reduction | OPEN |
| Proof knowledge-soundness / zero-knowledge | Selected backend, exact relation, theorem matching implementation | OPEN |
| Hidden-member anonymity | Left/right game over full transcript and allowed leakage | OPEN |
| Double-spend resistance | Binding, soundness, unique minting, atomic ledger rejection | OPEN |
| 128-bit quantum target | Concrete weakest-component security analysis | OPEN |
| Proof size/runtime | Reproducible compiled measurements | UNMEASURED |
| Novelty | Versioned comparison at matched functionality | UNVERIFIED |

## Parameter namespace discipline

The current Python ring helper uses \(q=8{,}380{,}417\), an ML-DSA-like research parameter family. LoTRS uses \(q=2^{43}-67\) and \(\hat q=2^{35}-451\) in distinct roles. Ringtail has its own parameters. These are not interchangeable, and this repository does not yet integrate LoTRS or Ringtail arithmetic.

## Implementation gates

Pin upstream revisions, licenses, parameter manifests and test vectors; pass conformance tests; implement the complete one-proof relation; test valid spend, replay, wrong key/signature, wrong opening/nullifier, malformed encoding, stale state and invalid threshold subsets; establish the backend's actual ZK and quantum soundness; measure complete proof bytes/time/memory; obtain independent cryptanalysis.

**Decision:** GO for component conformance and small functional prototypes. HOLD end-to-end security and production use. No token, chain, or novelty claim is in scope until the gates pass.

## Primary sources

- Ringtail: https://eprint.iacr.org/2024/1113 and https://github.com/daryakaviani/ringtail
- Experimental PQ SoK/LRS scaffold: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature
- LoTRS comparator/artifact: https://eprint.iacr.org/2026/974 and https://zenodo.org/records/22807126
- Obscura-PQ: https://arxiv.org/abs/2608.22645
- NIST FIPS 202: https://csrc.nist.gov/pubs/fips/202/final
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
