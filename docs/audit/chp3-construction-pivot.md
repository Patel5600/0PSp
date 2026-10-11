# CHP3 Construction Pivot — Retire the Two-Layer Bridge

**Decision:** retire the dual LoTRS-plus-STARK bridge architecture as the active V0 plan. Use one proof-of-knowledge relation for the complete spend statement.

The old design required a new LoTRS extension, a custom lattice bridge commitment, a separate proof system for SHAKE and cross-field relations, cross-proof witness binding, and end-to-end QROM/parameter analysis. The candidate bridge equation did not establish hiding/binding and proof-size estimates were not measured. This is not a theorem that two-layer proofs are impossible; it is a decision not to make V0 depend on an uninstantiated bridge.

## New V0 path

Use Ringtail for threshold signing and a generic post-quantum linkable-ring/signature-of-knowledge framework to prove one NP relation: selected coin membership/opening, threshold-signature validity under the same hidden key, and deterministic nullifier derivation. The ledger rejects duplicate nullifiers. There is no separate bridge value B.

## Research-source caveats

- LoTRS v2: https://zenodo.org/records/22807126. Its N=100,T=50 artifact reports a measured 53.53 KiB signature and says its estimator does not substantiate 128-bit PQ security. Comparator only, not V0 proof engine.
- Ringtail: https://eprint.iacr.org/2024/1113 and https://github.com/daryakaviani/ringtail. Published two-round LWE threshold signature; available implementation is an academic prototype with dealer-based Shamir sharing.
- Generic post-quantum LRS / SoK: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature. It targets NP statements, but the repository warns it is experimental and its ZK enhancement is informal.
- Obscura-PQ: https://arxiv.org/abs/2608.22645 and https://github.com/n-azimi/Obscura-PQ. Useful integrated linkable-spend comparator; its Algorand implementation is single-signer and capped at ring size 10.
- 2024 identity-based threshold linkable dual-ring signature: https://www.mdpi.com/2410-387X/8/4/48. Relevant prior art, but its KGC introduces escrow and its threshold semantics require careful comparison.

## Acceptance criteria

- [ ] upstream revisions and licenses pinned;
- [ ] component vectors pass unchanged;
- [ ] one proof verifies all spend predicates;
- [ ] repeated spend yields same nullifier and ledger rejects it;
- [ ] wrong signature, opening and nullifier are rejected;
- [ ] selected coin remains hidden in the complete transcript;
- [ ] measured size/runtime/memory recorded at N=2,4,8,16,32,64;
- [ ] security claims remain OPEN until formal review.

The single-relation path removes the bridge-composition obligation. It does not establish ZK, knowledge soundness, threshold correctness or unlinkability.
