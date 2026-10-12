# Adversarial Attack Catalogue — Phase 1 Falsification

**Status:** Attack framework. Mitigations in this document are candidate requirements, not evidence that 0PSP is secure.

## Attack classes

1. **Malformed share / rogue contribution:** a malicious signer supplies invalid shares, biased commitments or malformed transcript contributions.
2. **Related-key / rerandomization leakage:** repeated transformations leak secret information or invalidate signature bounds. This applies to the historical SCRL/Design A line, not the current baseline.
3. **Adaptive custody corruption:** an adversary corrupts up to the allowed participant threshold, biases challenges or uses selective aborts.
4. **Nullifier misuse:** choose a nullifier disconnected from the hidden coin; substitute a coin ID or nullifier secret; make the same asset produce a different accepted nullifier; or exploit duplicate minting.
5. **Anonymity leakage:** public signature keys, coin commitments, bridge commitments, transaction fields, proof transcript, ring composition or timing reveals the selected member.
6. **Field/canonical-encoding attack:** exploit noncanonical representatives, unchecked limbs, signed carry wraparound, inconsistent q versus q-hat domains or noncanonical byte encodings.
7. **Proof-composition attack:** both Layer 1 and Layer 2 proofs verify but bind to different witnesses because a commitment is not actually binding or public-statement encodings differ.
8. **Parameter/estimator error:** rely on a nominal security level, a BKZ block size larger than lattice dimension, or a heuristic estimate omitting a weaker component.
9. **Zero-knowledge failure:** treat blinding rows or a hiding PCS as sufficient while the chosen trace/PCS/transcript still exposes witness information.
10. **Multi-identity nullifier fork:** allow a prover to reuse a registered commitment while substituting `coin_id` or `r_nf` and thereby derive a second nullifier. Prevent by binding these values into the commitment and proving the exact shared opening/nullifier relation; then test alternate-witness rejection in the actual proof backend.
11. **Issuer value-binding gap:** let a mint register `(C, v, deposit_tx)` without checking that hidden commitment opening `C` contains the same `v`. A receipt over those fields is insufficient. Require an issuance proof or another reviewed mechanism that binds opening, authorized deposit value and namespace without revealing the opening.
12. **Transaction-digest detachment/replay:** accept a valid key-knowledge proof while treating the transaction digest as an unused public input, allowing the proof to be reused with changed transaction fields. Constrain canonical transaction fields and digest inside the relation.


## Current gate table

| Question | Status | Required response |
|---|---|---|
| Is SCRL solved? | No; not active baseline | Preserve as separate falsification result only |
| Does current bridge commitment provide hiding and binding? | Not established | Select a concrete commitment, prove properties, validate parameterization |
| Does an extended LoTRS proof implement generic t-of-n custody? | Not established | Specify protocol and prove its hidden relation |
| Is Layer 2 a zero-knowledge STARK? | Not implemented | Build actual AIR/backend and verify complete protocol ZK |
| Does composition guarantee same hidden witness? | Conditional only | Prove binding commitment and compatible extractors |
| Is the full system 128-bit post-quantum secure? | No claim allowed | Reproduce estimator/attack analysis for every component and full composition |

## Additional CHp4.3 adversarial case

12. **Same-nullifier output griefing:** create distinct output commitments that share the hidden tuple `(namespace_id, coin_id, r_nf)` but use different commitment salts. The commitments can differ while their nullifier is identical; first-spend-wins can make another note unspendable. Do not assume only the attacker is harmed. Analyze transaction output construction, recipient control and witness constraints in the actual proof relation. This risk is distinct from a hash collision and is tracked in [CHp4.3](../audit/chp4.3-identity-invariant-decision-review.md).
