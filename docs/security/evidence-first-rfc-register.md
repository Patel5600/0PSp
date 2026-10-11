# 0PSP Evidence-First RFC Register and NO-GO Dashboard

**Last reviewed:** 2026-10-11  
**Baseline main commit:** `4b55bcea63a9041ba0a23563ec4f6548032612e1`  
**Baseline CI:** [Functional checks run 102](https://github.com/Patel5600/PSp/actions/runs/38138830784) passed on the baseline commit. This validates only the commands in that workflow.  
**Current release decision: `NO-GO`**  
**Scope of this document:** engineering RFCs and evidence plan; it is not a cryptographic proof or approval to deploy.

## Executive decision

The V2 primitive layer has useful, testable components: namespace derivation, random coin-ID and secret/salt generation, a 48-byte SHAKE256 nullifier, a 48-byte SHAKE256 commitment, Python/native known-answer agreement, and native sanitizer/disassembly build checks. It does not yet provide the protocol that consumes these components safely.

The revised plan deliberately avoids (a) adding a second spend commitment without a demonstrated need, (b) claiming a generic proof-of-secret-key automatically replaces committee authorization, (c) replacing SHAKE based on invented constraint numbers, or (d) rewriting the C boundary merely because Rust is available.

No percentage-complete claim is used. A test pass, an RFC, or a benchmark is not a security theorem.

## Current implementation facts

| Area | Evidence present in repository | What that evidence does **not** establish |
|---|---|---|
| Namespace V2 | Canonical fixed-width encoding, 48-byte output, reference/native tests | Correct real-chain ID mapping or live ledger integration |
| Coin commitment V2 | SHAKE256-384 includes `params_id`, key bytes, value, namespace, coin ID, `r_nf`, and independent salt; reference/native KAT | A hiding theorem, a complete binding proof over the eventual accepted key codec, issuer privacy, or proof-system soundness |
| Nullifier V2 | Deterministic 48-byte result over namespace, 32-byte coin ID and 36-byte secret; a 149-byte preimage | That the spend proof enforces the exact same committed opening or that a ledger rejects repeats atomically |
| Native memory handling | OpenSSL APIs and `OPENSSL_cleanse` calls in source; sanitizer and disassembly build targets | Whole-process zeroization, all-copy erasure, constant-time behavior, or leakage absence |
| Authorization | Ringtail adapter contract and research notes | A production adapter, final authorization mode, or signature-verification constraints in an actual ZK backend |
| ZK proof | Relation targets documented | An instantiated backend, knowledge soundness, zero knowledge, or a complete proof of the composed relation |
| Mint and ledger | Documentation/test models only | Durable issuance, proof of value binding, duplicate-deposit protection, atomic spent-nullifier uniqueness, fork/reorg recovery |

## Four RFCs

| RFC | State | Allowed work now | Release blocker |
|---|---|---|---|
| [RFC-01: User-committed issuance](rfc-01-user-committed-issuance.md) | **Design candidate; BLOCKED** | Primitive-level invariant tests and protocol review | Issuance proof/verified mechanism tying ledger value and deposit to the hidden opening; full hiding/linkability analysis; durable atomic ledger |
| [RFC-02: Spend relation](../theory/spend-relation-spec.md) | **Formal specification draft; NOT PROVEN** | Freeze public statement, witness, common predicates, and authorization alternatives | Select one policy-compatible authorization mode and instantiate a proof backend that proves every predicate over one consistent witness |
| [RFC-03: Hash circuit comparison](../plan/rfc-03-hash-circuit-benchmark.md) | **Protocol only; NOT RUN** | Prepare reproducible data format and backend adapter boundary | Chosen, pinned backend; validated parameters and equivalent security targets; measured results on a declared machine |
| [RFC-04: Side-channel diagnostics](rfc-04-side-channel-diagnostics.md) | **Diagnostic plan; NOT CERTIFIED** | Manual non-blocking disassembly and timing diagnostics | Controlled target measurements, whole sensitive-path review, dependency/compiler/target evidence |

## P0: issuance privacy and state correctness

A wallet-side commitment can keep `coin_id`, `r_nf` and salt out of the mint's view. That is necessary but not sufficient:

1. The mint observes `C`, a claimed/public `v`, and deposit evidence.
2. Because it does not know the opening, it cannot independently recompute `C` to check that the opening's hidden value equals `v`.
3. A receipt signed over `(C, v, deposit_tx)` authenticates the mint's recorded fields. It does not, by itself, prove that the hidden commitment opening contains that same value.
4. The protocol therefore needs a verified issuance relation/proof (or a different reviewed construction) that binds `C` to the authorized value and deposit without disclosing the private opening. No such backend is implemented here.
5. The mint state transition must atomically check deposit replay, any coin-ID/commitment uniqueness policy, accepted value, and receipt/state-root update. A future spend transition must atomically reject a previously spent public nullifier.

Until these conditions are specified and implemented, no live issuance or production mint claims are allowed.

## RFC-01 invariant model

The current candidate commitment already includes namespace, public key bytes, value, coin ID, nullifier secret, parameter ID and independent commitment salt. The first regression tests verify primitive-level alternate-opening rejection and nullifier determinism. They are not end-to-end tests of a ZK relation or ledger state machine.

Required eventual protocol tests:

- For one valid coin opening, every accepted spend derives the same nullifier.
- A witness with substituted `coin_id` or `r_nf` cannot satisfy the same registered commitment in the spend relation.
- Ledger value and the value in the opening must be identical; the issuance transition must establish this without revealing the opening.
- Replaying a deposit cannot mint a second accepted record.
- Concurrent submissions of one nullifier admit at most one state transition, including documented fork/reorg and recovery rules.
- Any signed receipt is bound to the canonical namespace, commitment, value, deposit identifier, protocol version and state transition.

## RFC-02 acceptance boundary

The formal relation must include the same selected commitment, public key, value, namespace, coin ID, nullifier secret and transaction semantics. Merely presenting a valid proof of knowledge of an unrelated secret is not authorization.

The two authorization candidates have different policies:

- **Committee-signature mode:** the exact selected threshold-signature scheme is verified for the transaction under the same key bound into the coin commitment. Putting verification inside a circuit has an unknown cost until implemented and measured.
- **Self-spend key-knowledge mode:** the proof establishes the scheme-specific public/secret key relation and binds all transaction fields to the public statement. A generic `PoK(sk)` with no transaction-relation binding is insufficient. This mode does not replace a committee policy when committee approval is a required rule.

No C function-pointer API is being introduced before the relation and authorization semantics are stable.

## RFC-03 rules

- Do not change the production hash because of a guessed constraint count.
- Record exact source revision, proof backend and version, field/circuit model, hash parameters, compiler/runtime, CPU, memory and repetitions.
- Compare valid constructions with stated security targets. The candidate Poseidon2 tuple `t=16, R_F=8, R_P=22, x^7` is **unvalidated proposal data**, not a demonstrated 384-bit capacity or 384-bit security claim.
- Save machine-readable raw runs as CSV/JSON; report median, spread, peak RSS, trace/constraint measure, proof size and verifier time. Do not invent results when the backend adapter is absent.
- Performance budgets are decision aids only, never security acceptance criteria.

## RFC-04 rules

- The current native code uses `OPENSSL_cleanse`; this is not a claim that every process copy is erased.
- Prefer a verified platform API such as `memset_explicit` or `explicit_bzero` only after checking actual target availability and semantics. Do not silently treat a volatile-pointer loop as equivalent certification.
- A disassembly script may report expected wipe call sites in the built wrapper. It cannot prove that every secret copy is cleared or inspect OpenSSL provider internals.
- Welch's t-test / dudect-style timing output is a diagnostic for its test distribution, binary and host. `|t| < 4.5` is not proof of constant-time behavior. Shared-runner timing is non-blocking and must not be interpreted as a release certificate.

## Release gate (all mandatory)

Production remains **NO-GO** until all of these have affirmative, reviewable evidence:

- [ ] Threat model, leakage function and issuer/trustee collusion model frozen.
- [ ] Canonical real-chain namespace mapping and protocol/parameter versioning specified.
- [ ] Issuance protocol proves hidden commitment/value/deposit consistency; no issuer learns `coin_id` or `r_nf` in the stated privacy model.
- [ ] Commitment hiding and binding claims have formal definitions, concrete bounds and independent review.
- [ ] A single instantiated proof proves membership, opening, authorization, nullifier and transaction policy over one witness.
- [ ] Scheme-specific key/authorization relation selected; committee policy is not accidentally dropped.
- [ ] Durable ledger prevents duplicate issuance and atomically rejects repeated nullifiers under concurrency, reorg and recovery.
- [ ] Proof-system soundness, zero knowledge, Fiat–Shamir/QROM assumptions and composed quantum-security loss are analyzed.
- [ ] Reproducible end-to-end performance profile and negative tests pass.
- [ ] Controlled side-channel work and complete implementation/dependency/binary review are complete.
- [ ] Independent cryptographic review has no unresolved critical/high findings.

## Change-control rule

Tests and documentation may be added in an isolated branch. No production API, hash, ledger behavior, authorization mode, or default CI gate changes under these RFCs until its specification is approved and the corresponding test harness exists. Passing CI only confirms executed tests. The base `main` status is unchanged and remains **NO-GO**.
