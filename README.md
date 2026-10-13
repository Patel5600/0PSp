# 0PSP — Post-Quantum Private Spend Primitive

> Research prototype. No production assets. Complete protocol security: **NO-GO**.

0PSP targets private coin spends with namespace-scoped coin identities, deterministic replay protection, threshold authorization and one post-quantum zero-knowledge proof over the complete spend relation. This repository currently implements hash/encoding components and test models. It does **not** yet implement a live minting ledger, a Ringtail adapter, or the end-to-end proof.

## Current security gate (2026-10-13; CHp4.25 namespace smoke harness and CHp4.7 identity candidate reviewed)

**Complete protocol: NO-GO.** CHp4.25 adds a fail-closed exact-height Mainnet smoke harness, but no intended-deployment smoke has run because the independently approved deployment manifest/trust pins are missing. CHp4.7 adds V3 identity/nullifier reference candidates, but no complete proof relation or production enforcement is integrated. The repository does not activate production minting or establish external audit status.

Canonical review tracker: [Evidence-first RFC register and NO-GO dashboard](docs/security/evidence-first-rfc-register.md), plus the [binary Production Gate Matrix](docs/security/production-gate-matrix.md). Every mandatory gate is explicitly GO or NO-GO; the complete protocol remains NO-GO until each mandatory gate is evidenced closed.
- [RFC-01: user-committed issuance](docs/security/rfc-01-user-committed-issuance.md) is blocked on a proof/verified mechanism binding the hidden commitment opening to the deposited public value and on a durable ledger.
- [RFC-02: V2-only spend relation](docs/theory/spend-relation-spec.md) preserves the frozen V2 formulas and states the uninstantiated relation predicates.
- [CHp4.7 V3 candidate relation](docs/theory/spend-relation-v3-candidate.md) is separate, non-normative research material; HMAC-SHA3-384 is provisional and the V3 proof/authorization path is not production-approved.
- [RFC-03: hash/circuit benchmark](docs/plan/rfc-03-hash-circuit-benchmark.md) has no measured results because the backend is not instantiated.
- [RFC-04: side-channel diagnostics](docs/security/rfc-04-side-channel-diagnostics.md) is non-blocking evidence collection, not constant-time certification.
- [CHp4.1: issuance/spend reference state transitions](docs/audit/chp4.1-reference-state-transitions.md) adds a test-only in-memory state model; injected verifier stubs do not implement or prove the cryptographic relations.
- [CHp4.2: formal relations and adversarial tests](docs/audit/chp4.2-formal-relations-adversarial-tests.md) records exact V2 component equations and finite primitive regressions; the ZK backend, canonical Merkle/transaction encodings, real-ledger/reorg behavior and independent review remain open.
- [CHp4.3: hidden identity-invariant review](docs/audit/chp4.3-identity-invariant-decision-review.md) evaluates whether global hidden coin-ID uniqueness is needed for monetary soundness and records the separate same-nullifier/unspendability risk. This is a review proposal, not an approved protocol change.
- [CHp4.4: deterministic output-ID proposal review](docs/audit/chp4.4-deterministic-output-id-proposal-review.md) audits the suggested circuit-derived ID rule. The finding is useful, but the proposed fix is not accepted as-is because it publicly derives hidden IDs and the sample formulas do not match frozen V2.
- [CHp4.5: hidden-witness output-identity proposal review](docs/audit/chp4.5-hidden-witness-output-identity-proposal-review.md) reviews the friend's revised design. It is a research direction, not a verified fix: V2 field widths, collision claims, privacy proof and sample tests are still inconsistent or unsupported.
- [CHp4.6: output-identity candidate and regression evidence](docs/audit/chp4.6-output-identity-candidate-and-tests.md) adds a transfer reference candidate and hardcoded V2 regressions. [CHp4.7: identity uniqueness and nullifier safety](docs/audit/chp4.7-output-identity-uniqueness-and-nullifier-safety.md) records the adopted complete spend-identity policy and issuance-anchor candidate; the proof relation and production enforcement are still missing.
- [CHp4.8: Namespace V2 EVM adapter and mint-scope binding](docs/audit/chp4.8-namespace-v2-evm-adapter.md) adds a pinned EVM JSON-RPC manifest mapping and fixed-namespace reference-ledger checks; it is not a production chain/light client.
- [CHp4.9: Namespace V3 direct-hash remediation](docs/audit/chp4.9-namespace-v3-direct-hash-remediation.md) supersedes CHp4.8's intermediate-hash EVM mapping. It directly hashes canonical descriptors into one SHAKE256-384 output, adds native/Python known-answer parity, and types NamespaceIdV3 through the reference ledger.
- [CHp4.10: namespace RPC quorum and durable finality journal](docs/audit/chp4.10-namespace-rpc-finality-hardening.md) adds a strict-majority read-only RPC policy, namespace-scoped SQLite finalized-header ancestry journal and fail-closed startup wiring. It still is not a consensus light client or chain-specific deposit/proof verifier.
- [CHp4.11: EVM deposit evidence contract](docs/audit/chp4.11-evm-deposit-evidence-contract.md) defines a canonical receipt/event observation, local log identity, beneficiary binding, and the missing transaction/receipt trie and consensus proofs. The implementation is an observation normalizer, not mint authorization.
- [CHp4.12: EVM transaction and receipt trie inclusion verifier](docs/audit/chp4.12-evm-trie-inclusion-verifier.md) adds strict Ethereum Keccak/RLP/MPT primitives and verifies raw transaction plus receipt inclusion against roots extracted from a journaled raw header. It still does not authenticate consensus, establish asset custody, or produce trusted mint authorization.
- [CHp4.13: Ethereum Mainnet light-client finality integration](docs/audit/chp4.13-helios-authenticated-finality.md) adds a supervised, SHA-256-pinned Helios 0.12.0 process, a fresh out-of-band beacon checkpoint, and a durable checkpoint-to-finalized execution-header journal feeding CHp4.12. The integration is a candidate; no real-network smoke test or independent review is claimed, and it still does not issue mint authorization.
- [CHp4.14: deposit asset-movement evidence](docs/audit/chp4.14-asset-movement-evidence.md) binds native deposits to the proven transaction value and token deposits to one matching ERC-20 Transfer log, while pinning protocol/token runtime code at the deposit block. It is a movement signal, not custody authorization; contract/proxy semantics, real smoke testing, durable minting and issuance proof remain blockers.
- [CHp4.15: authenticated EVM state proofs](docs/audit/chp4.15-authenticated-evm-state-proofs.md) verifies EIP-1186 account/storage values against the state root in an authenticated finalized header. Block-boundary state does not prove transaction-specific causation or custody; the production mint path remains NO-GO.
- [CHp4.16: Ethereum proof differential tests](docs/audit/chp4.16-ethereum-proof-differential-tests.md) compares local Keccak/RLP/MPT behavior against test-only independent implementations. This is stronger regression evidence, not a full audit or a custody proof.
- [CHp4.17: durable ledger and commitment Merkle tree](docs/audit/chp4.17-durable-merkle-ledger.md) adds a depth-63 namespace-bound tree, SQLite atomic issuance/spend state transitions, restart replay protection, and startup auditing that reconciles all persisted Merkle nodes, records, and event-chain entries. It remains a single-node state machine; trusted deposit authorization and the real proof backend are not supplied.
- [CHp4.18: canonical V2 transaction and digest](docs/audit/chp4.18-canonical-spend-transaction-v2.md) freezes TxFieldsV2 and TxDigestV2 at the host/API boundary and rejects public-field/digest substitutions before the ledger invokes a verifier callback. Exact-main Functional checks and Repository integrity watch passed; the actual ZK relation must still constrain the exact same encoding; production remains NO-GO.
- [CHp4.20: proof-backend feasibility](docs/audit/chp4.20-zk-backend-feasibility.md) rejects the assumption that a transparent/hash-based STARK automatically provides zero knowledge. No backend is approved until the exact private-spend relation, witness hiding, post-quantum assumptions and target-hardware cost are demonstrated.
- [CHp4.21: static SHAKE arithmetization cost model](docs/audit/chp4.21-keccak-zk-cost-model.md) adds a tested, parameterized estimator for the frozen SHAKE256-384 predicates. Its example reports 23,543,088 modeled multiplication-equivalents for one input and one output under a 1,024-byte illustrative public-key encoding; this is not an actual backend benchmark or a proof. All proof/authorization/custody production gates remain NO-GO.
- [CHp4.22: SmallWood Python R1CS adapter scaling audit](docs/audit/chp4.22-smallwood-r1cs-adapter-scaling.md) finds the pinned generic adapter's dense constraint-table expansion is infeasible for even one SHAKE-sized relation; it does not reject all SmallWood implementations, but this adapter is NO-GO as-is.
- [CHp4.23: binary-field Keccak feasibility](docs/audit/chp4.23-binary-field-keccak-feasibility.md) models the frozen hash relation over a characteristic-two field at 5,991,472 SHAKE-subrelation rows in the illustrative scenario. This is a deterministic estimate, not an instantiated circuit or proof. Aurora/libiop is only the next feasibility candidate; complete production remains NO-GO.
- [Documentation map and maintenance policy](docs/README.md) is the entry point for active specifications, research history, invariant fixtures and repository checks.

## Active construction target: frozen V2 plus additive V3 candidate

- **Namespace identity:** Namespace V2 remains frozen. The EVM adapter uses typed Namespace V3 and hashes the full canonical chain/deployment/asset descriptors directly into one 48-byte SHAKE256-384 digest, without 256-bit intermediate identity hashes. Under an idealized generic quantum collision model, the 384-bit output has BHT-style query scale about 2^128, not collision-freedom. CHp4.10 adds majority-quorum RPC reads and durable checkpoint-to-finalized ancestry checks; those are corroboration and reorg-detection layers, not a light client or consensus proof. CHp4.11 adds a pinned deposit-event observation policy and beneficiary binding to the reference issuance statement. CHp4.12 verifies raw transaction and receipt trie inclusion against roots extracted from the exact raw header RLP, using the same transaction index and strict Ethereum Keccak/RLP/MPT primitives. CHp4.13 now supplies a candidate Ethereum Mainnet route that runs a pinned Helios light client, links the out-of-band execution checkpoint to its finalized header, invokes CHp4.12, and checks the protocol runtime-code fingerprint through Helios at the deposit block. CHp4.14 also requires native transaction value to equal the Deposit amount or a matching token Transfer log from depositor to protocol, plus token code fingerprint verification. CHp4.18 additionally closes the previously unspecified host transaction encoding only if exact-head CI passes. Actual binary/checkpoint/RPC smoke verification, independent differential review, proxy implementation/upgrade and asset-custody semantics, trusted DepositAuthorization conversion, and the actual issuance/spend proof remain open. CHp4.17 adds durable single-node state transitions but does not implement the trusted adapter or proof backend. CHp4.15 adds EIP-1186 state proofs but does not close transaction-specific causation or custody. CHp4.16 adds test-only differential conformance checks for Keccak, RLP and MPT. See [CHp4.9](docs/audit/chp4.9-namespace-v3-direct-hash-remediation.md), [CHp4.10](docs/audit/chp4.10-namespace-rpc-finality-hardening.md), [CHp4.11](docs/audit/chp4.11-evm-deposit-evidence-contract.md), [CHp4.12](docs/audit/chp4.12-evm-trie-inclusion-verifier.md), [CHp4.13](docs/audit/chp4.13-helios-authenticated-finality.md), [CHp4.14](docs/audit/chp4.14-asset-movement-evidence.md), and [CHp4.15](docs/audit/chp4.15-authenticated-evm-state-proofs.md), and [CHp4.16](docs/audit/chp4.16-ethereum-proof-differential-tests.md), and [CHp4.17](docs/audit/chp4.17-durable-merkle-ledger.md), and [CHp4.18](docs/audit/chp4.18-canonical-spend-transaction-v2.md), and [CHp4.20](docs/audit/chp4.20-zk-backend-feasibility.md).
- **CHp4.7 spend identity decision:** `coin_id` alone is not the uniqueness key. Outputs are derived inside the eventual proof from a one-use creation anchor plus a canonical global output slot, and the V3 nullifier binds the canonical note-public-key bundle, exact registered commitment, `coin_id` and `r_nf`. A V3 recipient-keyed nullifier candidate keeps the nullifier key secret from the creator; CHp4.6's sender-known tuple must not be paired with V2 nullifiers where sender-unlinkability is required. This is a versioned candidate, not yet circuit-enforced.
- **Issuance privacy:** the wallet can keep `coin_id`, `r_nf` and commitment salt private, but the complete issuance flow is not implemented. The mint cannot verify that hidden `C` opens to the recorded public value `v` merely by receiving `(C, v, deposit_tx)`; RFC-01 requires a sound issuance proof or another reviewed mechanism. The mint must never learn `coin_id`/`r_nf` in the intended issuer-unlinkability model.
- **Frozen V2 components:** V2 commitment and nullifier functions, byte formats and known-answer vectors are unchanged.
- **V3 research candidate:** a distinct-domain 48-byte `CommitV3` commits to a canonical recipient key bundle, and `NullifierV3` uses HMAC-SHA3-384 keyed by a recipient-held 48-byte per-note secret over the exact note commitment, bundle, parameter ID and hidden tuple. The recipient must authenticate the exact bundle; the eventual proof must verify that authentication and bind the bundle and commitment to the output. This also avoids V2's deterministic same-nullifier result when different commitment salts reuse the same tuple. V3 key commitment, canonical bundle, V3 commitment, anchored issuance/transfer derivation and selected vectors have Python reference code with version-distinct result types. No V3 native implementation or proof relation exists yet.
- **Threshold authorization:** Ringtail remains a research candidate, not a selected production suite. Its exact parameter set, key/signature codec, key-generation/dealer model and verifier semantics are not pinned, and no adapter is integrated. The upstream implementation explicitly describes itself as an academic proof-of-concept that is not ready for production.
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
| Namespace V2 core / Namespace V3 EVM mapping | V2 KAT unchanged; V3 direct-hash Python/native KATs; typed ledger-boundary tests; strict-majority RPC policy and durable finalized ancestry (CHp4.10) | Intended-chain smoke test; authenticated consensus/light-client strategy; cryptographic proof binding and independent security review |
| Deposit evidence / EVM event reader | CHp4.11 canonical event observation; CHp4.12 transaction/receipt MPT inclusion; CHp4.13 digest-pinned Helios finality; CHp4.14 native-value or ERC-20 movement-signal checks; CHp4.15 authenticated account/storage proof primitive | No real Mainnet smoke test, independent differential review, approved contract/proxy/token custody semantics, or trusted DepositAuthorization conversion |
| Durable mint ledger / commitment membership | CHp4.17 depth-63 namespace-scoped append-only Merkle tree, SQLite atomic issue/spend transactions, unique deposit/commitment/nullifier constraints, and record/tree/event-chain audit at startup | Single-node only; real authorization/proof backend not integrated; external state-head anchoring, backup/recovery/power-loss testing, and full issuance/spend relation binding remain open |
| Coin ID generation | Native OS-backed RNG API and tests | One-use anchor/output-slot proof constraints and joint identity collision analysis remain open |
| Nullifier V2 | Python reference, OpenSSL native implementation, fixed KAT, native parity | Frozen legacy suite; provider/binary review and platform leakage testing |
| V3 nullifier/commitment candidates | Python KATs for recipient-keyed HMAC-SHA3-384 nullifier, key commitment, key bundle and V3 commitment | Circuit feasibility, key generation/backup, native implementation, proof binding, PRF/privacy analysis and independent review |
| Ringtail threshold signature | Target selected | Pinned reviewed adapter, test vectors and proof-relation integration |
| Single post-quantum ZK proof | Candidate relation documented; authorization mode remains open | Backend not instantiated; no knowledge-soundness/ZK reduction or composed proof |
| End-to-end security | Threat model and game checklist | Composed proof, independent cryptanalysis and benchmarks |
| Full-path side channels | Separate V2 nullifier and commitment timing screens compile in CI; native disassembly artifact covers V1/V2 | Screens have not been run on a controlled target; whole secret-flow/binary audit and full-prover leakage tests remain open |
| Production | **NO-GO** | Mandatory production gates remain open; see the evidence-first register and gate matrix |

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
