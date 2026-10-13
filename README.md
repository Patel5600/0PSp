# 0PSP — Post-Quantum Private Spend Primitive

> Research prototype. No production assets. Complete protocol security: **NO-GO**.

0PSP targets private coin spends with namespace-scoped coin identities, deterministic replay protection, threshold authorization and one post-quantum zero-knowledge proof over the complete spend relation. This repository currently implements hash/encoding components and test models. It does **not** yet implement a live minting ledger, a Ringtail adapter, or the end-to-end proof.

## Current security gate (reviewed 2026-10-13; CHp4.11 deposit evidence remains under review)

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
- [CHp4.6: output-identity candidate and regression evidence](docs/audit/chp4.6-output-identity-candidate-and-tests.md) adds a reference candidate and hardcoded V2 regression vectors; no ZK circuit or production fix is claimed.
- [CHp4.8: Namespace V2 EVM adapter and mint-scope binding](docs/audit/chp4.8-namespace-v2-evm-adapter.md) adds a pinned EVM JSON-RPC manifest mapping and fixed-namespace reference-ledger checks; it is not a production chain/light client.
- [CHp4.9: Namespace V3 direct-hash remediation](docs/audit/chp4.9-namespace-v3-direct-hash-remediation.md) supersedes CHp4.8's intermediate-hash EVM mapping. It directly hashes canonical descriptors into one SHAKE256-384 output, adds native/Python known-answer parity, and types NamespaceIdV3 through the reference ledger.
- [CHp4.10: namespace RPC quorum and durable finality journal](docs/audit/chp4.10-namespace-rpc-finality-hardening.md) adds a strict-majority read-only RPC policy, namespace-scoped SQLite finalized-header ancestry journal and fail-closed startup wiring. It still is not a consensus light client or chain-specific deposit/proof verifier.
- [CHp4.11: EVM deposit evidence contract](docs/audit/chp4.11-evm-deposit-evidence-contract.md) defines a canonical receipt/event observation, local log identity, beneficiary binding, and the missing transaction/receipt trie and consensus proofs. The implementation is an observation normalizer, not mint authorization.
- [CHp4.12: EVM transaction and receipt trie inclusion verifier](docs/audit/chp4.12-evm-trie-inclusion-verifier.md) adds strict Ethereum Keccak/RLP/MPT primitives and verifies raw transaction plus receipt inclusion against roots extracted from a journaled raw header. It still does not authenticate consensus, establish asset custody, or produce trusted mint authorization.
- [Documentation map and maintenance policy](docs/README.md) is the entry point for active specifications, research history, invariant fixtures and repository checks.

## Active V2 construction target

- **Namespace identity:** Namespace V2 remains frozen. The EVM adapter uses typed Namespace V3 and hashes the full canonical chain/deployment/asset descriptors directly into one 48-byte SHAKE256-384 digest, without 256-bit intermediate identity hashes. Under an idealized generic quantum collision model, the 384-bit output has BHT-style query scale about 2^128, not collision-freedom. CHp4.10 adds majority-quorum RPC reads and durable checkpoint-to-finalized ancestry checks; those are corroboration and reorg-detection layers, not a light client or consensus proof. CHp4.11 adds a pinned deposit-event observation policy and beneficiary binding to the reference issuance statement. CHp4.12 verifies raw transaction and receipt trie inclusion against roots extracted from the exact raw header RLP, using the same transaction index and strict Ethereum Keccak/RLP/MPT primitives. However, the header's consensus authenticity, asset-custody semantics, trusted DepositAuthorization adapter, durable mint ledger, and issuance proof remain missing. See [CHp4.9](docs/audit/chp4.9-namespace-v3-direct-hash-remediation.md), [CHp4.10](docs/audit/chp4.10-namespace-rpc-finality-hardening.md), [CHp4.11](docs/audit/chp4.11-evm-deposit-evidence-contract.md), and [CHp4.12](docs/audit/chp4.12-evm-trie-inclusion-verifier.md).
- **Coin identity:** global uniqueness of hidden `(namespace_id, coin_id)` is under explicit review in CHp4.3 and is not silently removed or approved. The issuer cannot directly deduplicate an ID it never receives. Do not derive `coin_id` from public deposit data under the current issuer-privacy target. Deposit replay, issuance/value binding, same-witness spend binding, and recipient spendability are separate obligations.
- **Issuance privacy:** the wallet can keep `coin_id`, `r_nf` and commitment salt private, but the complete issuance flow is not implemented. The mint cannot verify that hidden `C` opens to the recorded public value `v` merely by receiving `(C, v, deposit_tx)`; RFC-01 requires a sound issuance proof or another reviewed mechanism. The mint must never learn `coin_id`/`r_nf` in the intended issuer-unlinkability model.
- **Coin commitment candidate:** 48-byte SHAKE256 output over a canonical, domain-separated encoding of the parameter ID, public key, value, namespace, coin ID, nullifier secret and independent 36-byte salt. Both Python reference and native OpenSSL implementations now have the same fixed known-answer vector.
- **Nullifier V2:** 48-byte SHAKE256 output over a separate domain, V2 version, 48-byte namespace ID, 32-byte coin ID and 36-byte per-coin secret. The preimage is 149 bytes and crosses a SHAKE256 rate boundary.
- **Threshold authorization:** Ringtail is the target signature scheme, with its exact parameter set, key encoding and key-generation model still to be pinned. Upstream code is marked academic and unaudited.
- **One proof:** must prove hidden membership, exact commitment opening, V2 nullifier correctness, transaction semantics, state eligibility and the selected authorization policy over the same witness. Whether that policy requires an in-circuit threshold signature or permits self-spend key-knowledge remains unresolved. No proof backend is integrated.
- **Atomic ledger rule:** deposit replay and spent-nullifier rejection must be durable and atomic. Hidden `(namespace_id, coin_id)` uniqueness is not yet compatible with the stated issuer-private message flow without an additional privacy-preserving mechanism. The current Python models are not consensus code.

The V1 nullifier and commitment helpers remain for historical vectors. They are not the active scoped-spend target and must not be silently mixed with V2.

## Repository integrity and maintenance

The [Repository integrity watch](.github/workflows/repo-integrity-watch.yml) checks local Markdown targets and deterministic hidden-tuple fixtures on PRs, main pushes and a daily schedule. Dependency updates are reviewed deliberately in consolidated maintenance changes rather than spawned automatically as separate PRs. These checks are maintenance safeguards, not cryptographic certification.

Run locally:

    python scripts/check_repo_integrity.py
    python -m pytest tests/adversarial/test_hidden_tuple_reuse.py -q

## Status

| Component | Evidence | Remaining gate |
|---|---|---|
| Namespace V2 core / Namespace V3 EVM mapping | V2 KAT unchanged; V3 direct-hash Python/native KATs; typed ledger-boundary tests; strict-majority RPC policy and durable finalized ancestry (CHp4.10) | Intended-chain smoke test; authenticated consensus/light-client strategy; cryptographic proof binding and independent security review |
| Deposit evidence / EVM event reader | CHp4.11 canonical observation, receipt-local log ID, pinned emitter/asset/event/code checks, beneficiary binding and adversarial tests | Authenticated execution-header consensus; transaction+receipt MPT inclusion proofs; reviewed deposit-contract/asset custody semantics; trusted DepositAuthorization and durable atomic mint ledger |
| Coin ID generation | Native OS-backed RNG API and tests | Identity policy under review; random generation alone does not reject deliberate reuse or prevent same-nullifier output collisions |
| Nullifier V2 | Python reference, OpenSSL native implementation, fixed KAT, native parity | Provider/binary review and platform leakage testing |
| Commitment V2 | Python/native fixed vector, native error-path checks, separate OS-backed salt generation and opening substitution tests | Canonical Ringtail key codec; formal hiding and binding theorem |
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
