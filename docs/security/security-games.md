# Security Games and Formal Definitions — Draft Research Targets

**Status:** Definitions only. Reduction proofs and a complete composition theorem are not established.

Earlier games for spend-specific key rerandomization describe the abandoned Design A/SCRL line. The current baseline is static keys plus hidden coin selection and a commitment-bound nullifier; rerandomization is not a required property unless later analysis shows it is necessary.

## Common adversary model

Specify the security parameter, public parameters, ledger state, honest minting and spend oracles, public transcripts, corruptible key holders, and quantum random-oracle access. State whether the adversary can choose malformed coins, adaptively corrupt participants, replay transactions, or register keys/commitments. A game without these interfaces is not a complete security definition.

## Required games

### Authorization soundness

The adversary wins by obtaining an accepted spend for a valid coin without satisfying the wallet's specified t-of-n authorization policy. The reduction must reference the concrete threshold-signature/MPC protocol, not only Module-LWE or Module-SIS by name.

### Hidden-member anonymity

The challenger chooses one of two eligible commitments under a left-or-right game. The adversary wins by identifying which one was used from the entire transcript. The game must include public transaction fields, bridge commitment, nullifier, proof transcripts, ledger state, corrupted participants, and explicitly permitted leakage.

### Nullifier correctness and double-spend resistance

An honest coin must have a deterministic nullifier fixed by committed coin data. An adversary wins if it produces two accepted spends of the same committed coin with distinct nullifiers, or an accepted spend whose nullifier is not the value specified by the proof relation. Ledger duplicate checking is part of the game.

### Collision safety

Distinct valid coins producing the same nullifier is a separate event. Its argument uses the concrete nullifier function and mint/asset-uniqueness rules; it does not replace the authorization or spend-soundness game.

### Full composition

A complete theorem must account for commitment binding/hiding, threshold unforgeability, hidden-member anonymity, knowledge soundness of both proofs, protocol zero knowledge, QROM/hash assumptions, state validity, and all public leakage. Individual component security does not automatically establish composition security.

## Proof-status discipline

Use one of the labels “definition”, “candidate assumption”, “conditional lemma”, “proof completed and checked”, or “measured implementation result”. Do not label a proposed reduction “proven” until every hybrid, extractor premise, adversary restriction and advantage term is explicit and supported by a cited theorem or a complete proof.
