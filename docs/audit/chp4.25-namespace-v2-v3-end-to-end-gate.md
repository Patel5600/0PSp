# CHp4.25 — Namespace V2/V3 composite production gate

**Scope:** frozen Namespace V2 core, direct-hash Namespace V3 EVM mapping, strict-majority RPC policy, authenticated Ethereum Mainnet finality, and binding of the observed deployment code to authenticated execution state.

**Composite production status: NO-GO.**

**External cryptographic audit:** NOT PERFORMED.  
**Independent security review of this composite path:** NOT PERFORMED.  
**Intended-deployment Mainnet smoke run:** NOT PERFORMED by this change.

This record distinguishes an implemented/verifiable primitive from an accepted end-to-end production path. It does not change the Namespace V2 formula or any existing V2 KAT.

## Gate decisions

| Sub-gate | Status | Evidence and limit |
|---|---|---|
| Namespace V2 core and existing Python/native KATs | **GO for the frozen primitive only** | Existing V2 vectors and formula remain unchanged. This does not authenticate an EVM chain or establish production proof binding. |
| Namespace V3 direct-hash Python/native KATs | **GO for deterministic codec behavior only** | Existing vectors exercise direct hashing of the full canonical descriptor tuple without 256-bit intermediate component hashes. Finite KATs do not prove collision freedom. |
| Typed Namespace V3 ledger boundary | **GO for reference/API type checks only** | The reference ledger rejects V2/V3 type confusion and mismatched namespace IDs before callback use. The type is not a cryptographic constraint inside a proof. |
| Strict-majority JSON-RPC policy | **GO for the tested read-only policy only** | The policy requires a strict majority of at least three distinct transport objects and fails closed on disagreement/malformed responses. Distinct objects and provider labels do not prove administrative or infrastructure independence. |
| Durable finalized ancestry journal | **GO for its specified local persistence contract only** | SQLite records the trusted execution checkpoint and parent-linked observed ancestry, freezes on conflict, and uses full synchronous mode. The CHp4.10 journal alone is not a light client. |
| Ethereum Mainnet consensus strategy | **Implementation candidate; operational acceptance NO-GO** | CHp4.13 integrates digest-pinned Helios 0.12.0 plus an out-of-band weak-subjectivity checkpoint and authenticated execution-header ancestry. The upstream dependency is not independently reviewed for this project and has not been accepted as a reviewed production dependency. |
| Deployment code at an authenticated state root | **GO only when the live smoke actually proves it** | The smoke runner selects one exact finalized header, derives Namespace V3 using code observed at that exact height, and verifies protocol/token runtime code against EIP-1186 account proofs anchored to the authenticated header state root. A fake/unit run is not Mainnet evidence. |
| Intended-deployment Ethereum Mainnet smoke | **NO-GO — not run** | This change provides an executable runner and fail-closed configuration checks. No trusted deployment manifest and real run output have been supplied or captured. |
| Namespace V3 bytes bound by the accepted issuance/spend proof | **NO-GO** | The repository has not selected and integrated an accepted production ZK backend that constrains the exact 48-byte namespace value in the complete issuance/spend relation. |
| Independent security review | **NOT PERFORMED** | The author and implementation agent cannot self-certify this as an independent review. Review must cover consensus assumptions, checkpoint provenance, fixed-height code/state binding, proxy semantics, durable storage/rollback, and the exact production composition. |
| External cryptographic audit | **NOT PERFORMED** | Tracked separately; the absence of an external audit does not waive any missing implementation or internal-review gate. |
| **Composite Namespace V2/V3 EVM-to-proof production path** | **NO-GO** | The end-to-end condition is not met until the intended deployment smoke succeeds, proof binding is implemented and adversarially tested, the chosen consensus dependency/pins are reviewed, and the internal independent review closes all findings. |

## Live smoke runner

Run on a controlled Linux host after installing the official pinned Helios 0.12.0 Mainnet binary. The script does not download a binary, discover a deployment, generate trust pins, or treat an RPC response as its own trust anchor.

The operator must supply these environment variables:

| Variable | Required value |
|---|---|
| **PSP_HELIOS_BINARY** | Absolute path to the installed Linux x86_64 Helios executable |
| **PSP_HELIOS_BINARY_SHA256** | Independently verified 32-byte executable SHA-256 digest, hex |
| **PSP_HELIOS_EXECUTION_RPC_URL** | HTTPS execution JSON-RPC endpoint supporting the pinned Helios configuration |
| **PSP_HELIOS_CONSENSUS_RPC_URL** | HTTPS consensus/beacon API endpoint |
| **PSP_HELIOS_WEAK_SUBJECTIVITY_CHECKPOINT** | Current, independently sourced 32-byte Mainnet beacon checkpoint root, hex |
| **PSP_MAINNET_EXECUTION_CHECKPOINT_NUMBER** | Trusted execution checkpoint number in canonical decimal |
| **PSP_MAINNET_EXECUTION_CHECKPOINT_HASH** | Independently sourced 32-byte execution header hash at that number, hex |
| **PSP_PROTOCOL_ADDRESS** | Actual intended deployed protocol address, 20 bytes, hex |
| **PSP_PROTOCOL_RUNTIME_FINGERPRINT** | Independently reviewed 48-byte v2 runtime-code fingerprint for that deployment, hex |
| **PSP_EXPECTED_NAMESPACE_ID** | Independently recomputed and approved 48-byte Namespace V3 ID for the exact chain/deployment/asset/epoch manifest, hex |
| **PSP_FINALITY_JOURNAL_PATH** | Absolute path to a persistent SQLite file; not the in-memory database sentinel |

For a token asset, set both **PSP_ASSET_ADDRESS** (20 bytes) and **PSP_ASSET_RUNTIME_FINGERPRINT** (48 bytes). For native asset mode, leave both unset. Optional values are **PSP_DEPLOYMENT_EPOCH** and **PSP_ASSET_EPOCH** (canonical decimal, default 0), **PSP_HELIOS_RPC_PORT** (default 18545), and **PSP_MAX_HEADERS_PER_SYNC** (default 4096, allowed 1..100000).

All trust pins must come from independent provenance, not from the same endpoint this test checks. The expected Namespace V3 ID must be independently recomputed and approved from the canonical descriptor manifest; do not copy the runner's output back into the expected-value field without an independent comparison. The expected-ID check catches local manifest/epoch/asset mapping mistakes but does not bind the value inside a zero-knowledge proof. Keep the execution checkpoint recent enough to synchronize within the configured header bound; the process intentionally fails instead of persisting a partial catch-up. Do not delete a journal or change a checkpoint merely to clear an error.

Run:

    python scripts/smoke_namespace_mainnet.py

A successful live run reports:
- exact Mainnet chain/genesis identity and computed Namespace V3 ID, matching the independently pinned expected ID;
- the exact finalized block height/hash at which code was queried;
- protocol runtime-code fingerprint match and account code-hash agreement with an EIP-1186 proof tied to that authenticated header’s state root;
- authenticated finalized ancestry, including durable persistence through the observed finalized head.

For token mode, the same exact-height state proof is required for the token account. The script emits a zero exit status only if these smoke checks pass. Its JSON report intentionally continues to set composite_production_gate to NO-GO, proof_binding to NO-GO_NOT_INSTANTIATED_BY_THIS_SMOKE, independent_security_review to NOT_PERFORMED, and external_cryptographic_audit to NOT_PERFORMED. It does not verify a deposit transaction, receipt, custody behavior, mint authorization, or issuance/spend proof.

## CI evidence for the code commit

The implementation and test suite at exact commit `465bdead0dfea01238d9b9459739322ae1715538` completed both repository workflows successfully on 2026-10-13:

- [Functional checks](https://github.com/Patel5600/0PSp/actions/runs/38369177561): **success**. The job completed native build/tests, ASan/UBSan checks, probe builds, diagnostics, and the repository's unit/property test command, including the namespace smoke harness's negative-path regressions.
- [Repository integrity watch](https://github.com/Patel5600/0PSp/actions/runs/38369177527): **success**.

These checks are regression evidence for that exact implementation/test commit. They are not evidence that a live Mainnet deployment smoke passed, that RPC operators are operationally independent, that Helios is independently security-reviewed, that the complete proof relation exists, or that any external audit occurred. The next documentation commit also requires CI verification.

## Why the gate cannot honestly be marked GO yet

1. **Real deployment evidence is missing.** The smoke runner is a new reproducible procedure, not an executed Mainnet test. No actual protocol address, independently sourced runtime fingerprint, execution checkpoint, Helios binary hash, or current beacon checkpoint has been accepted in this change.
2. **Consensus trust still requires review.** Helios provides a concrete Mainnet light-client integration, but digest pinning is supply-chain identity, not an audit of correctness. Checkpoint provenance, upstream release suitability, RPC failure behavior, binary installation and restart/recovery need review.
3. **The accepted proof relation is absent.** A NamespaceIdV3 Python type or a successful state proof cannot force a future spend proof to use those exact 48 public bytes. The selected proof backend must constrain them alongside the complete shared-witness opening, membership, nullifier, amount conservation, output openings and authorization predicates.
4. **Independent review has not occurred.** The same work that wrote the code cannot certify its own implementation as independently reviewed.

## Next acceptance sequence

1. Obtain and review the real deployment/build artifacts, contract/asset addresses, proxy implementation/admin configuration, epochs, code fingerprints, execution checkpoint, beacon checkpoint and Helios executable digest.
2. Run the smoke runner against the intended Mainnet deployment and archive its exact commit SHA, sanitized JSON output, binary digest, checkpoint provenance and CI result. Resolve any catch-up/reorg/code-proof mismatch rather than bypassing it.
3. Select and integrate an accepted production ZK backend. Bind the exact V3 namespace bytes into the complete issuance/spend relation and prove adversarial namespace, digest, amount, opening, membership, nullifier and authorization substitutions are rejected.
4. Have a second reviewer independently inspect this whole path and its negative tests; address every blocking finding and record reviewer/evidence references.
5. Keep external audit explicitly NOT PERFORMED unless one actually occurs. Re-evaluate this composite gate only from evidence on one exact release commit.

**Current decision: NO-GO.** This increment adds the missing live smoke procedure and exact-height authenticated code-binding checks; it does not claim to have executed the real-chain test, implemented the absent proof relation, or performed an independent review.
