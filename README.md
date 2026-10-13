# 0PSP — Post-Quantum Private Spend Primitive

> Research prototype. No production assets. Complete protocol security: **NO-GO**.

0PSP targets private coin spends with namespace-scoped coin identities, replay protection, threshold authorization and one post-quantum zero-knowledge proof over the complete spend relation. The repository now contains hash/encoding primitives, native implementations, EVM header/trie/state-proof components, and a durable single-node SQLite reference ledger. It still does **not** provide an accepted production minting path, a production Ringtail adapter, or the instantiated end-to-end issuance/spend proof. The reference ledger and test callbacks are not production authorization.

## Current security gate (CHp4.25 candidate; PR #30 is open and unmerged)

**Complete protocol: NO-GO.** This branch adds a reproducible Mainnet smoke runner and exact-height account-code checks, but the intended-deployment smoke has **not been run** and the production proof/authorization path remains unimplemented. Namespace V2 is frozen; Namespace V3 is the current EVM mapping. The code, consensus dependency, and full composition have **not received an independent security review** in this increment. **External cryptographic audit: NOT PERFORMED.**

Canonical source of truth: the [Evidence-first RFC register and NO-GO dashboard](docs/security/evidence-first-rfc-register.md) and the [Production Gate Matrix](docs/security/production-gate-matrix.md). Detailed audit history is maintained in the [documentation map](docs/README.md).

### Current implementation and release blockers

- **Namespace identity:** Namespace V2 and its KATs remain frozen. Namespace V3 directly hashes canonical chain/deployment/asset descriptors. The primitive codec is tested; it does not prove chain consensus or force a proof circuit to use the namespace.
- **EVM deposit path:** CHp4.10 adds strict-majority RPC corroboration and a durable local ancestry journal; CHp4.12 adds transaction/receipt trie inclusion; CHp4.13 adds a candidate Helios Mainnet light-client route; CHp4.14 adds asset-movement checks; CHp4.15 adds authenticated account/storage proof primitives. These layers do not establish custody or authorize minting.
- **CHp4.25 Namespace V2/V3 gate:** [Audit record](docs/audit/chp4.25-namespace-v2-v3-end-to-end-gate.md) and [Mainnet smoke runner](scripts/smoke_namespace_mainnet.py) now check runtime code at an exact finalized block against an EIP-1186 account proof tied to that header's authenticated state root. The runner has **not** been run against the intended deployment because its real trust pins and deployment manifest are not supplied.
- **Durable ledger and transaction encoding:** CHp4.17 supplies a single-node SQLite reference ledger and depth-63 commitment tree; CHp4.18 freezes the host-side TxFieldsV2/TxDigestV2 codec. Trusted production authorization and the actual proof constraints remain absent.
- **Proof feasibility:** CHp4.21 is a deterministic cost model, CHp4.22 finds the pinned dense SmallWood adapter infeasible at the evaluated scale, and CHp4.23 estimates a characteristic-two circuit shape without instantiating a proof. [CHp4.24 PR #28](https://github.com/Patel5600/0PSp/pull/28) remains open and unmerged; it does not approve Aurora/libiop as a backend.
- **Authorization and zero knowledge:** No production Ringtail adapter or accepted ZK backend is integrated. The complete shared-witness issuance/spend proof, value conservation, output openings, and proof-bound namespace/transaction digest remain NO-GO.
- **Security review:** Independent security review of the CHp4.25 composition is **NOT PERFORMED**. **External cryptographic audit: NOT PERFORMED.** No external audit or production approval is claimed.

## Active V2 construction target

- **Namespace identity:** Namespace V2 remains frozen and its existing KATs are unchanged. The EVM adapter uses typed Namespace V3, directly hashing the full canonical chain/deployment/asset descriptors into one 48-byte SHAKE256-384 digest without 256-bit intermediate identity hashes. Under an idealized generic quantum collision model, the 384-bit output has BHT-style collision-query scale about 2^128; this is not collision-freedom.

  CHp4.10 adds strict-majority RPC corroboration and a durable checkpoint-to-finalized ancestry journal, neither of which by itself authenticates consensus. CHp4.13 adds a candidate Ethereum Mainnet Helios light-client route. CHp4.12 verifies transaction/receipt trie inclusion, CHp4.14 checks asset-movement signals, CHp4.15 verifies account/storage proofs against an authenticated header state root, and CHp4.16 adds test-only differential tests.

  CHp4.25 adds a smoke runner that resolves Namespace V3 at one exact finalized block height and compares the protocol (and configured token) code against both the independent fingerprint and EIP-1186 account proof for that authenticated state root. Its code tests passed CI, but **no intended-deployment Mainnet smoke has been run**. Proxy upgrade/custody semantics, trusted DepositAuthorization, the accepted issuance/spend proof, production recovery, and independent review remain open. The full EVM-to-proof production path remains NO-GO. See [CHp4.9](docs/audit/chp4.9-namespace-v3-direct-hash-remediation.md), [CHp4.10](docs/audit/chp4.10-namespace-rpc-finality-hardening.md), [CHp4.13](docs/audit/chp4.13-helios-authenticated-finality.md), and [CHp4.25](docs/audit/chp4.25-namespace-v2-v3-end-to-end-gate.md).
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
| Namespace V2 core / Namespace V3 EVM mapping | V2 KAT unchanged; V3 direct-hash Python/native KATs; typed ledger boundary; CHp4.10 RPC quorum/journal; CHp4.13 Helios Mainnet candidate; CHp4.25 exact-height smoke harness with account-code/state-root consistency tests | Intended-deployment Mainnet smoke NOT RUN; Helios/checkpoint/deployment trust review; exact V3 proof binding; internal independent security review NOT PERFORMED; external cryptographic audit NOT PERFORMED |
| Deposit evidence / EVM event reader | CHp4.11 event policy; CHp4.12 transaction/receipt MPT inclusion; CHp4.13 Helios finality candidate; CHp4.14 movement signals; CHp4.15 EIP-1186 state-proof primitive; CHp4.25 code/state-root smoke harness | No intended-deployment Mainnet evidence; proxy/token custody policy and trusted DepositAuthorization conversion still absent; proof-bound issuance is missing |
| Durable mint ledger / commitment membership | CHp4.17 depth-63 namespace-scoped append-only Merkle tree, SQLite atomic issue/spend transactions, unique deposit/commitment/nullifier constraints, and record/tree/event-chain audit at startup | Single-node only; real authorization/proof backend not integrated; external state-head anchoring, backup/recovery/power-loss testing, and full issuance/spend relation binding remain open |
| Coin ID generation | Native OS-backed RNG API and tests | Identity policy under review; random generation alone does not reject deliberate reuse or prevent same-nullifier output collisions |
| Nullifier V2 | Python reference, OpenSSL native implementation, fixed KAT, native parity | Provider/binary review and platform leakage testing |
| Commitment V2 | Python/native fixed vector, native error-path checks, separate OS-backed salt generation and opening substitution tests | Canonical Ringtail key codec; formal hiding and binding theorem |
| Ringtail threshold signature | Target selected | Pinned reviewed adapter, test vectors and proof-relation integration |
| Single post-quantum ZK proof | Candidate relation documented; authorization mode remains open | Backend not instantiated; no knowledge-soundness/ZK reduction or composed proof |
| End-to-end security | Threat model and game checklist | Composed proof, independent cryptanalysis and benchmarks |
| Full-path side channels | Separate V2 nullifier and commitment timing screens compile in CI; native disassembly artifact covers V1/V2 | Screens have not been run on a controlled target; whole secret-flow/binary audit and full-prover leakage tests remain open |
| Production | **NO-GO** | Mandatory production gates remain open; no end-to-end production approval is claimed. |

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
