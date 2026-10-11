# Nullifier and Post-Quantum Private-Spend Prior Art

**Status:** Prior-art working note. Statements about specific implementation features must be verified against the cited version before being used for novelty claims.

## Why nullifier correctness is more than hashing

For a valid coin, the spend statement must prove that the public nullifier deterministically derives from data bound into that exact coin commitment. The ledger rejects a repeated nullifier. Two separate questions must be analyzed:
- double-spend resistance: the same committed asset cannot produce two accepted fresh nullifiers;
- collision safety: distinct assets should not accidentally produce the same nullifier and create false conflicts.

Collision resistance alone does not prove spend authorization, membership soundness or unlinkability.

## Relevant schemes and references

### LoTRS

LoTRS is a lattice-based structured threshold ring signature scheme, not a complete UTXO private-spend protocol. Its artifact has a selection proof and aggregated threshold signature. The documented scheme does not supply the asset-specific nullifier relation targeted by 0PSP.

Sources: https://eprint.iacr.org/2026/974 and https://github.com/lotrs-sig/lotrs

### Ringtail and Threshold Raccoon

These are important threshold-signature references for lattice/LWE designs. Ringtail gives a two-round threshold signature construction from LWE; it is not itself a full anonymous coin-spend protocol. Threshold Raccoon work addresses challenges of threshold lattice signing with masks. Exact protocol variants and parameters should be cited per paper.

Sources: https://eprint.iacr.org/2024/1113 and https://eprint.iacr.org/2024/184

### Obscura-PQ

The authors describe a lattice-based linkable ring-signature privacy protocol for Algorand, with deterministic serial numbers and a testnet implementation. This is direct prior art for a post-quantum private-spend path. 0PSP must compare the actual threat model and functionality rather than assume novelty from assembling a list of ingredients.

Source: https://arxiv.org/abs/2608.22645

### Zcash Orchard

Orchard derives nullifiers from committed note fields and a nullifier-deriving key through its specified protocol relation. It is a useful example of binding nullifier derivation to note data and spend proof. Its current construction is not a PQ replacement for 0PSP.

Sources: https://zcash.github.io/orchard/design/nullifiers.html and https://zips.z.cash/protocol/nu6.pdf

### Hash output length

SHAKE256-384 is a candidate output format, not an unlinkability proof. A generic quantum collision-finding scale around 2^128 operations for 384-bit output is a heuristic attack model. Do not turn it into an unconditional collision probability statement.

Source: https://csrc.nist.gov/pubs/fips/202/final

## Open comparison questions

1. Does the candidate spend proof hide which coin commitment is selected, including through public signature and transaction fields?
2. Does the same t-of-n authorization policy apply to the hidden coin key without disclosing the selected custodian subset beyond allowed leakage?
3. Can the proof system establish the nullifier relation with explicit quantum soundness and zero knowledge?
4. Is the chosen commitment actually both binding and hiding under stated post-quantum assumptions?
5. Are size, time and memory measured under equivalent security targets and anonymity sets?

Until those comparisons are complete, no claim that existing work lacks the exact combination is approved.
