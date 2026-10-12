# 0PSP — Post-Quantum Private Spend Primitive

> Research prototype. No production assets. Complete protocol security: **NO-GO**.

0PSP targets private coin spends with namespace-scoped coin identities, deterministic replay protection, threshold authorization and one post-quantum zero-knowledge proof over the complete spend relation. This repository currently implements hash/encoding components and test models. It does **not** yet implement a live minting ledger, a Ringtail adapter, or the end-to-end proof.

## Current security gate (reviewed 2026-10-12)

**Complete protocol: NO-GO.** The current branch documents a research plan; it does not activate minting, select an authorization mode, integrate a ZK backend, or certify side-channel resistance.

Canonical review tracker: [Evidence-first RFC register and NO-GO dashboard](docs/security/evidence-first-rfc-register.md).
- [RFC-01: user-committed issuance](docs/security/rfc-01-user-committed-issuance.md) is blocked on a proof/verified mechanism binding the hidden commitment opening to the deposited public value and on a durable ledger.
- [RFC-02: formal spend relation](docs/theory/spend-relation-spec.md) is a design draft, not an instantiated or proven proof relation.
- [RFC-03: hash/circuit benchmark](docs/plan/rfc-03-hash-circuit-benchmark.md) has no measured results because the backend is not instantiated.
- [RFC-04: side-channel diagnostics](docs/security/rfc-04-side-channel-diagnostics.md) is non-blocking evidence collection, not constant-time certification.
- [CHp4.1: issuance/spend reference state transitions](docs/audit/chp4.1-reference-state-transitions.md) adds a test-only in-memory state model; injected verifier stubs do not implement or prove the cryptographic relations.
- [CHp4.2: formal relations and adversarial tests](docs/audit/chp4.2-formal-relations-adversarial-tests.md) records exact V2 component equations and finite primitive regressions; the ZK backend, canonical Merkle/transaction encodings, real-ledger/reorg behavior and independent review remain open.
- [CHp4.3: hidden identity-invariant review](docs/audit/chp4.3-identity-invariant-decision-review.md) evaluates whether global hidden coin-ID uniqueness is needed for monetary soundness and records the separate same-nullifier/unspendability risk. This is a review proposal, not an approved protocol change.
- [CHp4.4: deterministic output-ID proposal review](docs/audit/chp4.4-deterministic-output-id-proposal-review.md) audits the suggested circuit-derived ID rule. The finding is useful, but the proposed fix is not accepted as-is because it publicly derives hidden IDs and the sample formulas do not match frozen V2.
- [CHp4.5: hidden-witness output-identity proposal review](docs/audit/chp4.5-hidden-witness-output-identity-proposal-review.md) reviews the friend's revised design. It is a research direction, not a verified fix: V2 field widths, collision claims, privacy proof and sample tests are still inconsistent or unsupported.
- [CHp4.6: output-identity candidate and regression evidence](docs/audit/chp4.6-output-identity-candidate-and-tests.md) adds a transfer reference candidate and hardcoded V2 regressions. [CHp4.7: identity uniqueness and nullifier safety](docs/audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md) records the adopted complete spend-identity policy and issuance-anchor candidate; the proof relation and production enforcement are still missing.
- [Documentation map and maintenance policy](docs/README.md) is the entry point for active specifications, research history, invariant fixtures and repository checks.

## Active construction target: frozen V2 plus additive V3 candidate

- **Namespace identity:** 48-byte SHAKE256-384 digest over canonical 32-byte ledger, deployment and asset identifiers. Chain-specific identifier mapping still needs to be specified and implemented.
- **CHp4.7 spend identity decision:** `coin_id` alone is not the uniqueness key. Outputs are derived inside the eventual proof from a one-use creation anchor plus a canonical global output slot, and the full note identity includes its canonical note-public-key bundle, `coin_id` and `r_nf`. A V3 recipient-keyed nullifier candidate keeps the nullifier key secret from the creator; CHp4.6's sender-known tuple must not be paired with V2 nullifiers where sender-unlinkability is required. This is a versioned candidate, not yet circuit-enforced.
- **Issuance privacy:** the wallet can keep `coin_id`, `r_nf` and commitment salt private, but the complete issuance flow is not implemented. The mint cannot verify that hidden `C` opens to the recorded public value `v` merely by receiving `(C, v, deposit_tx)`; RFC-01 requires a sound issuance proof or another reviewed mechanism. The mint must never learn `coin_id`/`r_nf` in the intended issuer-unlinkability model.
- **Frozen V2 components:** V2 commitment and nullifier functions, byte formats and known-answer vectors are unchanged.
- **V3 research candidate:** a distinct-domain 48-byte `CommitV3` commits to a canonical recipient key bundle, and `NullifierV3` uses HMAC-SHA3-384 keyed by a recipient-held 48-byte per-note secret. Recipient-key commitment, canonical bundle, V3 commitment, output-identity derivation and selected vectors now have Python reference code. No V3 native implementation or proof relation exists yet.
- **Threshold authorization:** Ringtail is the target signature scheme, with its exact parameter set, key encoding and key-generation model still to be pinned. Upstream code is marked academic and unaudited.
- **One proof:** the eventual selected relation must enforce the chosen version's commitment opening, key-bundle binding, same-witness nullifier correctness, output derivation, membership, authorization, transaction semantics and value conservation over one witness. V2 relation targets remain documented; the V3 key commitment and HMAC candidate add substantial proof/circuit work. No proof backend is integrated.
- **Atomic ledger rule:** deposit/event anchors and input nullifiers must be consumed at most once; output commitments and nullifier consumption must commit atomically and survive reorg/recovery. The reference ledger is single-process only, and the identity derivation is not constrained by a real ZK proof yet.

The V1 nullifier and commitment helpers remain for historical vectors. They are not the active scoped-spend target and must not be silently mixed with V2.

## Repository integrity and maintenance

The [Repository integrity watch](.github/workflows/repo-integrity-watch.yml) checks local Markdown targets and deterministic hidden-tuple fixtures on PRs, main pushes and a daily schedule. Dependency updates are reviewed deliberately in consolidated maintenance changes rather than spawned automatically as separate PRs. These checks are maintenance safeguards, not cryptographic certification.

Run locally:

    python scripts/check_repo_integrity.py
    python -m pytest tests/adversarial/test_hidden_tuple_reuse.py -q

## Status

| Component | Evidence | Remaining gate |
|---|---|---|
| Namespace V2 | Python/native known-answer vector and component binding tests | Real-chain canonical ID adapter; namespace integration into mint ledger |
| Coin ID generation | Native OS-backed RNG API and tests | One-use anchor/output-slot proof constraints and joint identity collision analysis remain open |
| Nullifier V2 | Python reference, OpenSSL native implementation, fixed KAT, native parity | Frozen legacy suite; provider/binary review and platform leakage testing |
| V3 nullifier/commitment candidates | Python KATs for recipient-keyed HMAC-SHA3-384 nullifier, key commitment, key bundle and V3 commitment | Circuit feasibility, key generation/backup, native implementation, proof binding, PRF/privacy analysis and independent review |
| Ringtail threshold signature | Target selected | Pinned reviewed adapter, test vectors and proof-relation integration |
| Single post-quantum ZK proof | Candidate relation documented; authorization mode remains open | Backend not instantiated; no knowledge-soundness/ZK reduction or composed proof |
| End-to-end security | Threat model and game checklist | Composed proof, independent cryptanalysis and benchmarks |
| Full-path side channels | Separate V2 nullifier and commitment timing screens compile in CI; native disassembly artifact covers V1/V2 | Screens have not been run on a controlled target; whole secret-flow/binary audit and full-prover leakage tests remain open |
| Production | **NO-GO** | All mandatory gates closed |

## Build and verification

Requirements: Python 3.11+, C compiler, OpenSSL development headers and binutils.

    python -m pip install -e ".[dev]"
    make -C native clean test
    make -C native sanitize-test
    make -C native audit
    export PSP_NULLIFIER_LIBRARY="$PWD/native/build/libpsp_nullifier.so"
    python -m pytest tests/ -q

To run the V2 timing screen locally, use a quiet machine and the release compiler flags:

    make -C native timing-v2-probe-build
    make -C native timing-v2
    make -C native timing-commitment-v2-probe-build
    make -C native timing-commitment-v2

The two timing screens are diagnostics inspired by fixed-vs-random timing tests, not official dudect, not run as shared-CI timing gates, and not proof of constant-time behavior. The commitment screen tests the nullifier secret and commitment salt separately. A suspicious or inconclusive result must be investigated. A clean result does not establish absence of other side channels.

The old scripts `security_budget_evaluator.py`, `audit_phase1_claims.py` and `verify_nullifier_relation.py` include V1 or historical CHP3 checks. Their success does not validate V2 minting, commitment hiding, threshold signatures, zero knowledge, or protocol security.

## Security decisions and open proofs

- [V2 namespace, commitment and security argument](docs/security/v2-protocol-security-argument.md)
- [Constructionable V0 target](docs/theory/constructionable-v0.md)
- [Spend relation and proof binding](docs/theory/spend-relation-and-proof-binding.md)
- [Nullifier-bound spend soundness](docs/theory/nullifier-bound-spend-soundness.md)
- [Proof-system feasibility study](docs/theory/proof-system-feasibility-study.md)
- [Ringtail adapter contract](docs/theory/ringtail-adapter-contract.md)
- [Side-channel and constant-time release gates](docs/security/chp4-constant-time-and-side-channel-spec.md)
- [Evidence-first RFC register and NO-GO dashboard](docs/security/evidence-first-rfc-register.md)
- [RFC-01 user-committed issuance](docs/security/rfc-01-user-committed-issuance.md)
- [RFC-02 spend relation specification](docs/theory/spend-relation-spec.md)
- [RFC-03 hash/circuit benchmark protocol](docs/plan/rfc-03-hash-circuit-benchmark.md)
- [RFC-04 native memory/side-channel diagnostics](docs/security/rfc-04-side-channel-diagnostics.md)
- [CHP4 construction-readiness record](docs/security/chp4-construction-readiness.md)
- [Dependency-minimization and construction roadmap](docs/plan/dependency-minimization-and-construction-roadmap.md)

The formal commitment argument currently has a conditional binding implication: a pair of distinct canonical openings that hashes to one commitment yields a SHAKE output collision. The hiding proof in the quantum random-oracle model is still open. V2 functional tests do not solve that proof obligation.

For post-quantum zero knowledge, evaluate [SmallWood](https://eprint.iacr.org/2025/1085) as a research candidate, not an assumed solution. Its reference implementation is unaudited. Ringtail's paper is available at https://eprint.iacr.org/2024/1113; its current Go prototype explicitly warns that it is not production-ready.

The complete proof system, composed security theorem, real mint ledger, independent cryptanalysis, end-to-end benchmark, and full-path side-channel assurance remain open. No novelty or production security claim is made.
