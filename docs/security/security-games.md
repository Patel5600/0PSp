# Security Games and Formal Definitions — Active V0 Research Targets

**Status:** Definitions and reduction targets only. No complete reduction or end-to-end theorem is established.

The V0 candidate is one anonymous proof for hidden coin membership, threshold authorization, and a commitment-bound deterministic nullifier. SCRL/key rerandomization and the paired LoTRS+STARK bridge are historical paths, not active requirements.

## Common adversary model

Specify security parameter, public parameters, ledger state, minting/spend oracles, full public transcripts, corruptible custody participants, and classical/quantum oracle access. State whether an adversary can register malformed coins/keys, adaptively corrupt participants, request honest spends/signatures, replay transactions, race concurrent spends, or observe aborts/side channels. A game is incomplete without interfaces and permitted leakage.

## Required games

### Authorization and spend soundness
The adversary wins by causing an accepted spend without satisfying the wallet's \(t\)-of-\(n\) policy for the selected hidden coin. The reduction must use the concrete threshold-signature scheme and the selected proof system's actual soundness or knowledge-soundness definition.

### Hidden-member anonymity
The challenger chooses one of two eligible commitments in a left/right game. The adversary identifies the spent member from the entire transaction/proof transcript, including nullifier, transaction digest, ledger state, timing, amount and corrupted participants. The public set is allowed leakage; revealing the selected index or a stable link is not.

### Nullifier correctness and double-spend resistance
A valid coin has a deterministic nullifier fixed by committed data. The adversary wins by having a spend accepted with an inconsistent nullifier or by spending the same coin twice with distinct accepted nullifiers. The ledger's atomic duplicate-nullifier rule is part of the experiment.

### Collision safety and sender unlinkability
Distinct valid commitments producing the same nullifier must be analyzed separately from replay rejection. Under frozen V2, two commitments that share (namespace_id, coin_id, r_nf) but use different commitment salts deterministically share a nullifier; this is not a hash collision and can leave one note unspendable. In addition, a sender who knows that output tuple can compute its V2 nullifier and link a future spend. CHp4.7 therefore records a V3 recipient-keyed nullifier candidate plus one-use source anchor and canonical output slot: the sender knows the public key commitment, not the recipient's secret key. The actual proof must bind the key commitment, key opening, output tuple, commitment opening and nullifier in one relation. Ledger one-use rules remain necessary. See [CHp4.7](../audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md).

### Full composition
A completed theorem must account for commitment binding/hiding, threshold unforgeability, hidden-member anonymity, knowledge soundness of the single proof, application-level zero knowledge, QROM/hash assumptions, state validity and public leakage. Security of individual ingredients does not automatically prove composition.

## Proof-status vocabulary

Use: definition, candidate assumption, conditional lemma, proof completed and checked, or measured implementation result. Do not call a reduction proven until every hybrid, extractor premise, adversary restriction, quantitative advantage term and source theorem is explicit and checked.

## Current status

The nullifier and coin commitment are functional hash helpers, not proof verifiers. Ringtail adapter and single anonymous proof are not integrated. All security games remain OPEN; no production or novelty claim is approved.
