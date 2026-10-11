# SCRL Attack Notes — Historical Research Track

**Status:** Historical Design A analysis. Not the active 0PSP implementation path; not a general impossibility proof.

The original SCRL line asks whether a public-key transformation and a share transformation can be made consistent while keeping the shares short enough for a specified lattice signing protocol and preserving the required distribution.

The historical notes consider a transformation such as \(pk'=(A,t+r)\) and share updates whose public-key contributions sum consistently to the shift. A valid result would need to specify all rings/modules, exact share reconstruction, distribution samplers, norm representatives, signature response protocol, and security game.

Important corrections:
- Shamir sharing over the scalar field can be applied coordinate-wise to LWE secrets. The existence of zero divisors in a polynomial quotient ring does not establish impossibility.
- Large Lagrange coefficients suggest a potential norm/distribution problem, but modular reduction and rejection behavior must be analyzed for the actual protocol. The earlier \(2^{-3840}\) acceptance and infinite-loop claims are not established and must not be cited as theorem results.
- Finding one invalid share-update construction would falsify that construction only, not every possible share-compatible rerandomization map.
- Related-key security, key indistinguishability, threshold correctness and response shortness are separate sub-claims.

The active Phase 1 architecture is Design B (static keys, hidden coin selection, and an asset-bound nullifier) because it does not require solving SCRL in advance. SCRL should resume only if a demonstrated requirement for key rerandomization emerges.

References:
- Ringtail: https://eprint.iacr.org/2024/1113
- Threshold Raccoon: https://eprint.iacr.org/2024/184
- LoTRS: https://eprint.iacr.org/2026/974
