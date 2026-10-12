# V2 Namespace and Security Argument

**Status:** Namespace-bound V2 component code and known-answer tests exist. The full 0PSP construction remains **NO-GO**.

## 1. Namespace format

A namespace is the tuple (ledger_id, deployment_id, asset_id). Each component is exactly 32 canonical bytes. Chain-specific adapters must define an injective mapping from real identifiers into these byte strings. Do not use display names, token tickers, ambiguous strings, or a chain identifier that fails to distinguish separate ledger instances.

The V2 namespace identifier is 48 bytes:

    namespace_id = SHAKE256-384(
      "0PSP-NAMESPACE-v2-SHAKE256" || 0x02 ||
      uint16_le(32) || ledger_id[32] ||
      uint16_le(32) || deployment_id[32] ||
      uint16_le(32) || asset_id[32])

The fixed-width input contracts and domain/version prefix make the byte encoding unambiguous. The 48-byte output is intentionally not truncated to 32 bytes. A 384-bit output has generic quantum collision-search cost on the order of 2^128 oracle queries under the usual BHT-style model, not 192-bit quantum collision security. This estimate is conditional on an idealized oracle model, not a proof of SHAKE's concrete security in this protocol.

**Still open:** the core primitive has no chain-specific adapter or live minting contract. Real ledger/network, deployment and asset identifiers must be canonically mapped to the three inputs above before any production use.

## 2. CHp4.7 identity decision and additive V3 candidate

The frozen V2 coin ID remains a 32-byte value. Global uniqueness of `coin_id` alone is **not** required by the adopted CHp4.7 policy and must not be treated as an injective serial. The full V3 note identity includes namespace, canonical note public-key bundle, `coin_id` and `r_nf`. Issuer privacy rules out solving the policy by exposing hidden IDs in plaintext to the issuer.

CHp4.6's sender-known tuple derivation is not safe to pair with V2 nullifiers when sender-unlinkability matters: the output creator knows the tuple and can compute the unkeyed future `NullifierV2`. V3 therefore adds a recipient-held 48-byte per-note nullifier key. Its domain-separated SHAKE256 commitment is encoded in the canonical public-key bundle that is bound into `CommitV3`; `NullifierV3` is an HMAC-SHA3-384 PRF output keyed by that recipient secret and binds `params_id` into the message, preventing accidental cross-parameter nullifier reuse. V1/V2 formulas and vectors remain unchanged.

Uniqueness also requires a one-use anchor plus a canonical global output slot: authenticated deposit/event identifier for issuance, consumed input V3 nullifier for transfer. The recipient must authenticate the exact namespace/params/bundle tuple, and the eventual proof must verify that authentication and constrain the anchor, slot, recipient bundle, derived `coin_id/r_nf`, commitment opening and public nullifier in a single relation. Otherwise, bundle substitution can target an unknown key and create an unspendable output. The address-auth signature suite/codec remains unselected. The durable ledger must consume the anchor/nullifier atomically with the output append.

Changing `rho_C` alone can still produce different commitments with the same V3 nullifier if the complete V3 note identity is reused. The proof/ledger must prevent accepted identity reuse. Distinct finite hash inputs can collide with nonzero probability; no mathematical injectivity is claimed. Full identity collision bounds, HMAC security in the chosen quantum threat model and V3 circuit cost remain unproved/unmeasured. See [CHp4.7](../audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md).

The Python candidates are not a ZK backend or durable ledger. Key generation/backup, note recovery and encrypted delivery, canonical chain adapters, transaction schema, state recovery, native implementation and independent audit remain blockers. Production remains **NO-GO**.

## 3. Nullifier V2 contract

For namespace ID N (48 bytes), coin ID c (32 bytes), and per-coin nullifier secret r_nf (36 bytes):

    nu = SHAKE256-384(
      "0PSP-NULLIFIER-v2-SHAKE256" || 0x02 ||
      uint16_le(48) || N ||
      uint16_le(32) || c ||
      uint16_le(36) || r_nf)

The encoded input is exactly 149 bytes and the public output is 48 bytes. The input crosses SHAKE256's 136-byte rate boundary, so multi-block and boundary behavior must be tested. V1 remains only for historical compatibility. New spends must not silently accept V1 nullifiers.

## 4. Coin commitment V2 contract

    C = SHAKE256-384(
      "0PSP-COIN-COMMIT-v2-SHAKE256" || 0x02 ||
      uint16_le(len(params_id)) || params_id ||
      uint32_le(len(pk)) || canonical_pk ||
      uint64_le(value) ||
      uint16_le(48) || namespace_id ||
      uint16_le(32) || coin_id ||
      uint16_le(36) || r_nf ||
      uint16_le(36) || rho_C)

The 48-byte output commits to the canonical parameter ID, canonical public key, unsigned 64-bit value, explicit namespace, coin ID, nullifier secret and independent 36-byte salt. Until Ringtail's exact key codec and parameters are pinned, canonical public-key encoding remains an integration gate.

The Python helper recomputes openings for reference tests; `native/coin_commitment_v2.c` implements the same byte contract through OpenSSL EVP, and its C known-answer vector matches the Python vector. Native parity is a functional result, not a commitment theorem or a constant-time proof.

## 5. What can be said about commitment binding

Let E(w) be the exact canonical preimage for an opening w. If the encoding is injective over valid openings, then any adversary that returns two distinct valid openings w and w' that produce the same commitment also provides two distinct SHAKE256-384 preimages with equal 384-bit outputs. A reduction can return those preimages as a hash collision. Its success probability on such an output is at least the binding adversary's success probability; the overhead is encoding and validation.

This argument is conditional. We still need to freeze canonical public-key serialization, prove encoding injectivity for the accepted domain, select the exact quantum collision model, and state concrete query/security parameters. It is not an independent audit or a full project theorem.

## 6. Commitment hiding is still open

Define a challenge game where an adversary chooses two candidate openings with the same public parameters. The challenger commits to one of them using a fresh uniform independent 288-bit rho_C. The adversary must guess which opening was selected.

Salt size alone is not a hiding proof. The final theorem must specify classical random-oracle versus quantum-accessible random-oracle access, account for the visible nullifier and other public outputs, and bound distinguishing advantage as a function of the adversary's query budget.

**Important composition warning:** a naive whole-transcript hiding game that gives the adversary two candidate openings it knows and then publishes the matching nullifier is trivially distinguishable. Given each candidate's (namespace_id, coin_id, r_nf), the adversary computes both candidate nullifiers and compares them to public nu. This is intentional owner-level linkability, but it means standalone commitment hiding cannot be silently promoted to transaction anonymity.

The system-level anonymity game must define which openings and minting transcripts the adversary knows or controls. If a mint authority learns coin_id and r_nf for every issued coin, it can match a later public nullifier to its issuance record. Therefore coin-secret generation/issuance privacy is a protocol prerequisite: either the threat model explicitly trusts the issuer not to observe these openings, or issuance must be designed so the issuer cannot learn the coin_id/r_nf pair. No blind-issuance protocol exists in this repository. This is a **blocking threat-model and construction decision**, not something fixed by SHAKE or a zero-knowledge proof alone.

**RFC-01 clarification (2026-10-11):** [The user-committed issuance candidate](rfc-01-user-committed-issuance.md) reuses the existing single V2 commitment; it does not add a second `C_spend` hash. Keeping `coin_id` and `r_nf` from the mint avoids direct nullifier precomputation, but does not complete issuance. Given only `(C, v, deposit_tx)`, a mint cannot recompute the hidden opening to verify that `C` contains the same `v`. A signed receipt only attests to the mint's record; it is not proof of hidden value/opening consistency. The issuance transition needs a sound proof or another independently reviewed mechanism that ties the commitment opening to the deposit-authorized value without revealing the opening. No such issuance proof or durable ledger exists yet; issuance remains **BLOCKED**.

The desired privacy statement is cryptographic unlinkability under a formal leakage/corruption model, not “100% unlinked”. Timing, amounts, network metadata and anonymity-set size may reveal links even if the issuer does not learn `coin_id` or `r_nf`. See [RFC-01](rfc-01-user-committed-issuance.md) and the [central NO-GO register](evidence-first-rfc-register.md). A classical q/2^288 salt-guessing estimate is not a valid substitute for a quantum-query argument. This repo does not yet contain the required QROM theorem or a complete hiding reduction. A 288-bit salt suggests a generic quantum search scale around 2^144 queries only under a suitable idealized oracle model; that estimate does not prove hiding for this transcript or account for every public output. Do not label V2 cryptographically hiding until that gate is closed.

## 7. Active single-proof relation

Public statement:

    x = (namespace_id, R_C, nu, M, state, params_id)

Witness:

    w = (j, C_j, pk_j, value, coin_id, r_nf, rho_C, sigma_th)

The one proof must establish all predicates for the same hidden selected coin:

1. j is in range and C_j = R_C[j].
2. C_j is the exact V2 commitment opening with the same public namespace.
3. Ringtail's threshold signature sigma_th verifies under the same canonical pk_j on M.
4. nu is the V2 nullifier for the same namespace, coin_id and r_nf.
5. The coin is eligible at the committed state, has not already been spent, and satisfies transaction policy and value conservation.
6. The proof hides j, opening and signature except for explicitly allowed leakage.

The transaction digest M must bind the protocol version, namespace, nullifier, inputs, outputs, fees and required ledger context. The ledger must atomically reject duplicate nullifiers and stale state. Omitting the namespace from any of the public statement, commitment relation or nullifier relation invalidates V2.

## 8. Required games and open reductions

| Property | Required argument | Status |
|---|---|---|
| Namespace separation | Collision analysis plus injective mapping of real ledger/deployment/asset identifiers | Primitive and KAT implemented; adapter open |
| Mint and identity policy | Canonical-deposit single issuance and commitment registration; hidden coin-ID uniqueness under CHp4.3 review | In-memory model only; real ledger and approved identity policy open |
| Commitment binding | Reduction to SHAKE256-384 collision resistance plus encoding injectivity | Conditional implication specified; parameters and canonical key codec open |
| Commitment hiding | QROM/classical-RO game, query budget and bound including all public outputs | Open |
| Threshold authorization | Ringtail unforgeability, exact parameters/key generation, canonical codec and verifier | Not integrated |
| Knowledge/spend soundness | Extractor/reduction from an accepted proof to a witness satisfying every predicate | Open; no proof backend |
| Double-spend resistance | Valid coin fixes the nullifier and durable ledger atomically rejects repeats | Component tests only |
| Anonymity/unlinkability | Left/right game defining allowed leaks and intentional linkability of repeated nullifiers | Open |
| Quantum composition | Concrete reductions and security loss for all primitives and Fiat-Shamir/QROM use | Open |
| Side-channel resistance | Source/data-flow review, per-target release-binary review, statistical leakage tests and operational review | V2 local screen added; full path open |

Listing assumptions is not a composed proof. A top-level theorem bounding the full protocol's advantage does not exist yet.

## 9. Ringtail and proof-backend decision

Ringtail's paper describes a two-round lattice threshold signature based on LWE, but its current upstream Go code explicitly calls itself an unaudited academic proof-of-concept and not production-ready. Pin its revision, license and concrete parameter set; keep its demo networking out of the ledger. Ordinary signature verification must be proven inside the same ZK relation under the hidden public key; a standalone adapter does not solve that requirement. Sources: https://eprint.iacr.org/2024/1113 and https://github.com/daryakaviani/ringtail.

Evaluate SmallWood first as an experimental proof candidate. Its hash-based ZK argument targets small-to-medium statements and its paper discusses hash-preimage and lattice-based relations, but the authors' implementation is a prototype and unaudited. It is a candidate, not a drop-in solution. The feasibility prototype must encode this exact V2 relation and measure prover time/memory, proof bytes and verifier time. Sources: https://eprint.iacr.org/2025/1085 and https://github.com/CryptoExperts/smallwood.

## 10. Side-channel boundary

The V2 nullifier and commitment diagnostics compare fixed and random secret classes, randomize class order, repeat the experiment, include same-input controls and return inconclusive rather than reporting a pass when controls are noisy. The commitment screen tests `r_nf` and `rho_C` separately. They are local screens, not the official dudect implementation, a constant-time proof or side-channel certification. They are deliberately not run in shared CI.

Run on an idle machine using release flags:

    make -C native clean test sanitize-test audit timing-v2-probe-build timing-commitment-v2-probe-build
    make -C native timing-v2
    make -C native timing-commitment-v2

A suspected leak blocks release. An inconclusive test requires a controlled rerun. A clean result only means this experiment did not detect a first-order timing difference for these classes on that machine. OpenSSL EVP/provider code, allocations, compiler output, hardware and callers still need review. Since the full prover and threshold-signature path are not implemented, the full-path side-channel gate cannot yet close.

## References

- NIST FIPS 202: https://csrc.nist.gov/pubs/fips/202/final
- SmallWood paper: https://eprint.iacr.org/2025/1085
- Ringtail paper: https://eprint.iacr.org/2024/1113
- Side-channel specification: ../security/chp4-constant-time-and-side-channel-spec.md
- Implementation: src/primitives/namespace.py, src/primitives/nullifier.py, src/primitives/coin_commitment.py and native/nullifier_v2.c

**Release: NO-GO.** V2 scope binding, functional vectors and tests are implemented; the live mint ledger, full hiding theorem, Ringtail integration, single proof, composed security argument and full-path side-channel review remain open.
