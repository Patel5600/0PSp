# Architecture Comparison: Static Keys vs. Key Rerandomization

**Status:** Research comparison. Neither architecture has been demonstrated as a complete secure 0PSP construction.

## Design A — Rerandomize keys and shares

Each spend transforms the public key and its key shares. This may provide a useful property in some models, but it introduces related-key security requirements, share-distribution and signing-correctness obligations, and potential short-preimage problems. The Share-Compatible Rerandomization Lemma (SCRL) remains an independent research problem.

## Design B — Static keys, hidden membership and asset-bound nullifier

Keys remain static. A proof must hide which eligible coin was selected, bind the selected coin commitment to the correct wallet authorization, bind the deterministic nullifier to the same coin, and prove all protocol/state rules. This avoids the need for SCRL but **does not automatically solve spend privacy**. It depends on a concrete commitment and proof system that satisfy all required properties.

## Comparison

| Dimension | Design A | Design B |
|---|---|---|
| Key update | Required | Not required |
| Primary additional proof obligation | Share-compatible rerandomization and related-key security | Hidden-member authorization and asset-bound nullifier |
| Main security risk | Short-share update, distribution leakage, related-key attacks | Witness mismatch, weak commitment, proof composition, transcript leakage |
| Current status | Open research problem; not active baseline | Leading architecture hypothesis; not proven |
| Implementation | Paused | Full protocol not implemented |

## Decision

Do not treat Design B as “proven” or as automatically achieving all five target properties. Use it as the leading architecture to falsify first because it avoids requiring key mutation for every spend. Keep SCRL as a separate research track only if a concrete need for key rerandomization is identified.

Before implementation, specify the exact threshold custody protocol, prove that the same hidden key and coin are used in membership/authorization/nullifier relations, select commitment schemes with explicit hiding and binding reductions, and analyze the full composition. Prior art includes LoTRS, Ringtail, Threshold Raccoon, Obscura-PQ and Zcash Orchard; novelty remains unverified.

Sources:
- LoTRS: https://eprint.iacr.org/2026/974 and https://github.com/lotrs-sig/lotrs
- Ringtail: https://eprint.iacr.org/2024/1113
- Threshold Raccoon: https://eprint.iacr.org/2024/184
- Obscura-PQ: https://arxiv.org/abs/2608.22645
- Orchard nullifiers: https://zcash.github.io/orchard/design/nullifiers.html
