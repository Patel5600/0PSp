# CHp4.5 — Audit of the hidden-witness output-identity proposal

**Status:** adversarial specification review; not an approved construction.  
**Reviewed:** 2026-10-12  
**Release:** **NO-GO**.  
**Change class:** review/documentation only. No V2 primitive, KAT, API, proof format or ledger behavior is changed.

## Executive verdict

This revision improves on the prior proposal in one important way: it recognizes that deriving an output `coin_id` solely from public inputs defeats the stated hidden-identity requirement, and proposes to derive output fields from secret input-witness material plus transaction entropy inside a future proof relation.

That is a **candidate direction for analysis**, not a formal resolution. The document claims a verified privacy lemma and 192-bit output-identity collision resistance without providing the necessary proof, and its byte-level definitions and sample tests are incompatible with the repository's normative V2 types and encoding. The listed completion statuses are therefore not supported by the submitted evidence.

Do not copy its normative derivation or tests into RFC-02. Preserve the current V2 byte contract and keep production **NO-GO**.

## 1. The threat model is useful

The cross-recipient attack is a valid threat to assess: two commitments can differ because their commitment randomness or recipients differ while the same `(namespace_id, coin_id, r_nf)` yields the same V2 nullifier. An atomic nullifier set stops the second accepted spend but cannot make both notes spendable. Output integrity, nullifier consistency, recipient safety, monetary soundness and atomic ledger enforcement are distinct obligations.

The proposal is right to reject the assertion that the sender necessarily harms only themself.

## 2. Its hidden-witness derivation is not yet a privacy proof

The proposed output derivation uses `coin_id_in`, `r_nf_in`, `sk_in`, `s_tx`, protocol fields and the output index. Because most of these are hidden in the intended proof statement, this avoids the direct public-input flaw in the earlier proposal.

However:

- “At least 768 bits of min-entropy” is asserted, not derived. The key's scheme and encoding are not selected; independence and distributions of the witness fields are not specified; and the adversary chooses the proof witness, including `s_tx`, unless the protocol separately constrains its generation.
- A secret-prefix hash is not automatically a proven PRF for the exact construction merely because SHAKE256 is used. State the random-oracle/PRF model, inputs, adversarial queries, key assumptions and reductions, or mark the claim unproved.
- Preimage resistance alone does not establish indistinguishability of the complete public transcript. The proof transcript, commitment structure, published nullifiers, output note delivery, amounts, timing, transaction shape and collusion model must be accounted for.
- “Zero on-chain leakage” and “100% privacy” are not justified by the text. At most, a future proof might establish a carefully scoped computational statement under a specified leakage function.
- The recipient must receive the opening fields needed to spend their output through a defined authenticated/encrypted note payload. The payload format, binding to the exact output commitment and delivery failure model are not specified here.

The hidden-witness approach may be studied further, but the current document must not label its privacy lemma **Verified**.

## 3. Concrete mismatch with the repository's V2 contract

The normative byte contract is defined in [RFC-02](../theory/spend-relation-spec.md) and implemented by the Python/native reference components. The proposal's Section 1 and sample code use abbreviated formulas that omit required V2 fields and encodings.

Current V2 component field sizes/encoding include:

- `namespace_id`: 48 bytes;
- `coin_id`: 32 bytes;
- `r_nf`: 36 bytes (288 bits);
- `rho_C`: 36 bytes;
- commitment and nullifier outputs: 48 bytes;
- explicit domain/version bytes and length prefixes in the normative SHAKE256 inputs, with the specified little-endian integer encodings.

The proposal instead declares a 32-byte namespace and 32-byte `r_nf`, assumes a fixed 32-byte `params_id`, and uses shorthand commitment/nullifier formulas. Its test helper removes the V2 version and length prefixes, omits the commitment's namespace binding, and computes nullifiers over a different byte string. These are not byte-for-byte V2 regression tests.

Specific derivation encoding defects:
- `B_rnf` declares a 24-byte domain tag, but `b"0PSp-TransferRNF-v2\x00\x00\x00"` is only 22 bytes. The claimed payload size is therefore inconsistent.
- The derivation truncates `r_nf_out` to 32 bytes even though the V2 `NullifierSecret` is exactly 36 bytes. Such an output cannot be passed to the current V2 API.
- The proposal's `sk_in_0[32]` requires a selected, frozen authorization key scheme and canonical secret-key representation. Neither is currently defined.
- `deposit_id`, `r_seed` and the final mint index lack a fully specified canonical encoding/length treatment in the mint rule.

These are release-blocking specification defects, not cosmetic differences.

## 4. The collision bound is wrong for the proposed 32-byte coin ID

The proposal computes:

```text
coin_id_out = Truncate_32(SHAKE256-384(encoded_witness))
```

That is a 256-bit output. A generic collision search against this truncated output has a birthday security level of about **128 bits**, not 192 bits. The claimed `2^-192` collision-resistance bound for finding any pair of distinct inputs with the same `coin_id_out` does not follow from using a 48-byte SHAKE output before truncation.

The distinction matters:
- the output's 32-byte truncation sets the generic collision bound for `coin_id_out`;
- a fixed-pair collision probability is not the same quantity as an adversary's probability of finding any collision;
- the nullifier's 48-byte output has a generic 192-bit birthday collision target under the usual ideal-hash model;
- a paired `(coin_id, r_nf)` construction requires its own analysis of the two domain-separated derivations and the nullifier function. One may not silently transfer the 192-bit nullifier bound to the shorter output ID.

The text also says domain separation means a mint ID can **never** equal a transfer ID. Domain separation distinguishes inputs; it does not make a finite hash injective. State a computational bound and assumptions instead of claiming impossibility.

## 5. “Distinct indices” is not a uniqueness proof by itself

Different output indices give different encoded inputs if the entire encoding is canonical. They do not logically guarantee distinct hash outputs. A malicious prover chooses `s_tx`; the security argument must cover chosen-witness/grinding behavior and prove that the circuit enforces the exact derivation for every output.

Cross-transaction uniqueness also cannot be inferred simply from the fact that the two transactions spend different primary inputs. Different encoded inputs can collide under a finite hash. State the intended property precisely: is it global `coin_id` uniqueness, global uniqueness of `(coin_id, r_nf)`, or merely unique nullifiers among valid notes? Those are different requirements with different implications.

The relevant safety property is that two distinct accepted output notes cannot share a nullifier except with a stated negligible probability. Global hidden `coin_id` uniqueness remains a separate policy question and is not automatically necessary or proven by this derivation.

## 6. The submitted tests do not verify the stated claims

The sample suite is a toy model, not a test suite over the repository's V2 functions or an instantiated circuit:

- `commit_v2` and `nullifier_v2` use simplified concatenations that differ from the current normative V2 encodings.
- Test 3 comments that a proof fails but never invokes a proof generator/verifier or an implemented predicate checker. Comparing two commitment byte strings does not test circuit rejection.
- `MockLedgerState` is a list/set model without a concurrent transaction, rollback, persistence or consensus implementation. Sequential calls do not establish atomic enforcement under concurrency.
- Test 7's assertion `cm.hex().startswith("07" or " " or cm.hex()[:4])` effectively tests only whether the digest starts with `"07"`; it is not a meaningful deterministic KAT or byte-invariance check.
- Assertions that different indices return different selected sample outputs are finite sample observations, not proof of all-input uniqueness or a 192-bit bound.

Use the repository's actual reference functions and their existing KATs for primitive regression. Label reference tests honestly. Circuit-negative tests must wait until there is an actual circuit and verifier to exercise.

## 7. Unsupported release-gate statuses

The proposal's table labels the privacy lemma **Verified**, the adversarial suite **Code Ready**, and the formal relation **Design Ready**. Those labels are stronger than the evidence supplied.

At most, the text proposes a design and illustrative pseudocode. It contains no privacy simulator/reduction, selected proof backend, runnable implementation of the relation, executed negative circuit proofs, durable ledger integration, or independent audit. The existing repository's release gate remains authoritative. Update status labels only when reviewable artifacts and results exist.

## 8. Required revisions before reconsideration

1. Correct every field width and encoding against the actual V2 types. Do not change those V2 types; output derivation must produce exactly a 32-byte `coin_id` and a 36-byte `r_nf` compatible with the frozen primitives.
2. Replace the blanket 192-bit coin-ID collision claim with a correct claim scoped to each output and derivation. Explicitly discuss the 128-bit generic collision resistance of a 32-byte output and separately analyze tuple/nullifier collisions.
3. Define the secret-key scheme, input key canonicalization, entropy assumptions, transaction-entropy generation, canonical field encodings and output-note delivery/binding.
4. Provide a formal relation that binds each output derivation, output commitment, output value, recipient key and transaction statement to one witness. Define the complete transaction schema before claiming a circuit constraint is implementation-ready.
5. Replace “zero leakage/verified” wording with a concrete leakage function and a privacy proof obligation. Until proved, mark it open.
6. Replace toy helper code with tests against actual repository primitives; remove the fake KAT assertion. Add real circuit-negative tests only after a backend is instantiated.
7. Keep independent review and the complete evidence-first release gate as blockers.

## Decision

**Not accepted as a formal resolution.** The hidden-witness derivation is a plausible research direction to investigate, and the threat model is useful. However, the privacy lemma, uniqueness proof, collision bounds, byte encodings, sample tests and release-gate labels are not validly established as written.

Record this as a proposal under review only. Keep V2 formulas and KATs frozen, do not merge the derivation into RFC-02, and retain **NO-GO** until the missing specification, implementation and independent evidence exists.
