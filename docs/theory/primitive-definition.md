# Primitive Definition: 0PSP — Historical API, Current Status

**Status:** Informal draft only. This file is retained as notation/background; it is not an accepted construction or security definition.

The original five-property target and Share-Compatible Rerandomization Lemma (SCRL) were the initial Design A research direction. The active Phase 1 baseline is Design B: static authorization keys, hidden coin selection, and a deterministic nullifier bound to the same committed coin. Key rerandomization is not a required property of the current baseline unless a later security comparison demonstrates that it is necessary.

Do not treat historical formulas as implemented or secure. In particular:
- a named Module-LWE/Module-SIS assumption does not establish a reduction by itself;
- a lattice PRF placeholder does not establish a nullifier construction;
- the secret-sharing interface must match the exact threshold-signature protocol;
- the current source parameter type is ML-DSA-like and not a LoTRS parameter manifest.

Use the current model in the Phase 1 specification, the spend relation document, and the open obligations in the Phase 1 consistency audit.
