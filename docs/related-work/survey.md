# Related Work Survey — Current, Qualified Comparison

**Status:** Living survey; findings are literature-derived and do not prove 0PSP novelty.

| Work | Contribution | Difference from the 0PSP target |
|---|---|---|
| ML-DSA / FIPS 204 | Standardized post-quantum digital signatures | No built-in hidden coin selection, ledger nullifier or threshold spend relation |
| Ringtail (ePrint 2024/1113) | Two-round threshold signatures from LWE | Not itself a complete anonymous-spend/ledger-nullifier protocol |
| Threshold Raccoon (ePrint 2024/184 and related work) | Threshold signing design using masking to address lattice-signature aggregation challenges | Not by itself a full hidden-coin spend protocol |
| LoTRS (ePrint 2026/974; CCS 2026 artifact) | Structured threshold ring signatures from lattices; hidden-column selection proof and aggregated multisignature | No asset-specific nullifier or complete private-spend ledger protocol in the documented artifact |
| Obscura-PQ (arXiv:2608.22645) | Lattice-based linkable ring-signature privacy protocol with deterministic serial number and Algorand testnet implementation, according to its authors | Does not establish the 0PSP target's full t-of-n custody and hidden-coin composition |
| Zcash Orchard | Complete nullifier/spend design binding nullifiers to note data under its protocol relation | Existing Orchard uses its established non-post-quantum curve/proof construction; not a PQ drop-in |
| 0PSP | Research question: threshold-controlled authorization, hidden asset membership, deterministic asset-bound nullifier and PQ security | Construction, novelty, concrete parameters and end-to-end security remain unverified |

## LoTRS is a baseline, not a plug-in

LoTRS proves a particular structured threshold ring-signature statement. Its row/column organization must not be assumed to implement an arbitrary wallet custody t-of-n policy. A 0PSP extension needs a formal relation and proof that the hidden selected commitment and threshold wallet authorization refer to the same asset/key.

Do not claim a 128-bit security baseline from current LoTRS v2 reference parameters: its estimator output says listed estimates do not substantiate 128-bit post-quantum security. See the companion benchmark calibration document.

## Nullifier design: what must be composed

A deterministic public hash is not automatically a secure nullifier system. The proof must bind the same hidden coin, coin identity, nullifier secret and wallet authorization; the ledger must reject a previously spent nullifier. Unlinkability requires a full game and proof, accounting for public state, amounts, transaction timing, anonymity-set composition and transcripts.

Zcash Orchard ties nullifier derivation to committed note fields and its protocol relation. It is a useful reference, not evidence that a direct SHAKE-based 0PSP relation is already secure.

Sources:
- Orchard nullifier design: https://zcash.github.io/orchard/design/nullifiers.html
- Protocol specification: https://zips.z.cash/protocol/nu6.pdf
- Obscura-PQ: https://arxiv.org/abs/2608.22645
- LoTRS: https://eprint.iacr.org/2026/974
- Ringtail: https://eprint.iacr.org/2024/1113
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final

## Research gap statement

> Under an explicit adversary model, can a post-quantum spend proof combine threshold wallet custody, hidden asset membership, deterministic asset-bound nullifiers, and practical anonymity sets while proving that all relations use the same hidden coin, at a measurable cost that improves on or enables something not offered by existing designs?

This is not a verified novelty claim. A systematic search must compare precise definitions, assumptions, constructions, parameters and implementations before claiming the gap is unfilled.
