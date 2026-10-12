# CHp4.3 — Identity-invariant decision review (research only)

**Status:** proposal for review; not approved protocol semantics.  
**Branch:** `research/chp4.3-invariant-review`  
**Base:** `main` (unchanged).  
**Release:** **NO-GO**.  
**Change class:** documentation and adversarial reference tests only. No V2 bytes, production API, ledger behavior, authorization mode or default CI gate changes.

## Decision under review

The current protocol names a coin identity as `(namespace_id, coin_id)`, but the issuer-private flow hides `coin_id`. The issuer therefore cannot enforce raw equality of hidden IDs using the existing visible-ID registry.

This proposal evaluates two mutually exclusive policy choices; it does **not** silently decide between them:

1. Keep global identity uniqueness and specify a reviewed privacy-preserving mechanism that enforces it, including leakage, state cost, concurrency behavior and security proof.
2. Revise the invariant so global `coin_id` uniqueness is not required for monetary soundness, and specify the precise semantics and consequences of hidden identity reuse.

A claim that global uniqueness is unnecessary is not accepted solely because deposit replay and spent-nullifier sets exist. The protocol must separately analyze monetary soundness, note spendability/anti-griefing, recipient safety and any assumptions about wallet-generated witnesses.

## Core invariants to prove

### I1 — Single accepted issuance per canonical deposit

The chain adapter returns a canonical deposit identity and authenticated facts. The ledger verifies finality according to a chain-specific policy, then atomically consumes `(namespace_id, deposit_id)` and records the issuance. A second accepted issuance for the same deposit must fail under concurrency.

This is a state-machine requirement, not a consequence of a source transaction existing on-chain. The exact deposit identifier encoding, reorg policy, recovery semantics and durable storage transaction are unimplemented and remain blockers.

### I2 — Issuance/value binding

A single issuance relation must tie the authenticated deposit value and namespace to the same hidden V2 commitment opening:

```text
C = CommitV2(params_id, pk, v_deposit, namespace_id,
             coin_id, r_nf, rho_C)
```

The production proof must bind the canonical deposit evidence and protocol/policy version to the public statement. A test-double verifier does not discharge this obligation. No production issuance verifier currently exists.

### I3 — One nullifier for each valid note opening

The single spend relation must open the exact registered commitment and compute the public nullifier from the **same** `(namespace_id, coin_id, r_nf)` used by that opening. The durable ledger atomically rejects a repeated public nullifier. This is a relation plus state-machine obligation, not something proved by primitive unit tests alone.

### I4 — Distinct valid notes should not unintentionally share a nullifier

If two distinct note commitments use the same `(namespace_id, coin_id, r_nf)`, the frozen V2 nullifier formula yields the same nullifier even if `rho_C` differs. A nullifier set can prevent double acceptance, but it cannot make both notes spendable: the first accepted spend makes a later spend using that nullifier fail.

The protocol must therefore decide whether this tuple reuse is:
- ruled out by wallet construction and transaction/output relations (with precisely stated threat assumptions and evidence),
- an explicitly accepted denial-of-service / unspendability risk, or
- prevented by another reviewed construction that does not silently alter frozen V2 formats.

The ledger cannot infer hidden tuple equality from commitments alone. Do not claim “the attacker only harms itself”; one party may construct outputs for another recipient. Add an adversarial output-creation model before making a recipient-safety claim.

## Conditional argument about global coin-ID uniqueness

If I1 and I2 hold, an attacker cannot create additional accepted monetary value without an authorized deposit or another valid value-preserving spend. If I3 holds, the same note opening always maps to the same public nullifier and cannot be accepted twice by a correct ledger.

Those facts may be sufficient to remove **global hidden `coin_id` uniqueness as a monetary-soundness invariant**, but they do not automatically prove I4, privacy, recipient spendability, or the security of an instantiated ZK relation. In particular, I4 is not resolved merely by requiring new deposits for mints: ordinary transfers may create multiple output commitments without a new external deposit for every output.

Therefore this branch records a candidate invariant reduction, not a proof that the cryptographic deadlock is closed. The change requires review of transaction/output creation, wallet witness generation, value conservation and the exact adversary model.

## Canonical deposit identifier requirements

A canonical deposit identifier should be derived from an authenticated, chain-specific event locator, with fields as needed to disambiguate:

- canonical source-chain/network identifier and namespace/bridge/deployment scope;
- transaction identifier;
- event/log index or output index (one transaction may contain multiple deposit events);
- canonical asset/contract scope where not already uniquely fixed by namespace.

The authenticated event value must be fetched from verified source evidence, not accepted as caller-supplied `v_claimed`. Do not make value part of the uniqueness key unless canonicalization and aliasing behavior have been formally specified. The identifier/hash suite, field encoding, domain separation, finality anchor and protocol/parameter version are all unresolved.

## Required adversarial fixtures (reference model only)

Tests may use the current real Python V2 primitive functions and existing in-memory ledger as a reference model. Name and comments must state that these are finite regression tests, not a ZK theorem, not a production-ledger test and not an unlinkability proof.

1. **Same hidden tuple, distinct commitments:** same `coin_id` and `r_nf`, different `rho_C` produces distinct commitment candidates but the same nullifier. Assert this exact relation and document that the nullifier set cannot allow both spends.
2. **Same coin ID, different nullifier secret:** yields different candidate commitments/nullifiers for selected vectors; does not by itself prove global uniqueness is unnecessary.
3. **Duplicate canonical deposit:** the current state model accepts only one issue for a canonical deposit identity, even if a second request supplies a different commitment. This remains test-double/in-memory evidence only.
4. **Distinct output recipients sharing tuple:** blocked until an actual output relation/schema exists. Do not fabricate a protocol transaction encoding or claim the reference ledger can verify recipient ownership today.
5. **Concurrent duplicate nullifier/deposit:** existing in-memory lock tests are regression checks only; durable consensus/reorg behavior remains blocked until actual adapter/ledger semantics are defined.

## Leakage and privacy decision required

Do not derive `coin_id` from a public deposit ID under the current issuer-private requirement. The issuer should receive only the explicitly listed public statement and deposit evidence; `coin_id`, `r_nf`, and `rho_C` remain hidden in the target flow. The threat model must define leakage from value, deposit amount, timestamps, transaction shape, network metadata, anonymity set, public outputs and issuer/trustee/observer collusion. Hiding these witness fields does not establish transcript unlinkability by itself.

## Change-control

- Keep V2 commitment/nullifier equations and KATs unchanged.
- Do not change production API, ledger behavior, authorization mode, proof format or default CI gate in this branch.
- Any eventual identity-policy change must be a separately reviewed and versioned decision with explicit privacy and security consequences.
- Passing CI establishes only that the executed regression tests pass.
- Main remains **NO-GO** until every mandatory release gate in the evidence-first RFC register has affirmative, reviewable evidence.
