# CHP4 / V2 Construction Readiness Record

**Checkpoint:** namespace-bound component functions and fixed vectors are implemented. Full 0PSP protocol remains **NO-GO**.

**RFC review update (2026-10-13):** The active work packages and blocking gates are tracked in [the evidence-first RFC register](evidence-first-rfc-register.md). The existing V2 commitment already includes `value`, namespace, `coin_id`, `r_nf`, key bytes, parameter ID and independent salt in its preimage. The identified multi-identity risk is not fixed by adding a second `C_spend`: the eventual spend proof must enforce that the commitment opening and nullifier use the exact same witness. More importantly, no live issuance flow yet proves that the mint's recorded public value equals the hidden value in `C`.

**Do not infer readiness from component tests:** Python/native equality proves byte-contract agreement only. It does not prove issuer unlinkability, commitment hiding, ZK relation soundness, ledger atomicity or constant-time execution. Authorization mode remains unresolved; see [RFC-02 spend relation](../theory/spend-relation-spec.md).


CHp4.17 adds a reference depth-63 commitment tree and file-backed SQLite ledger with atomic issue/spend state transitions, unique deposit/commitment/nullifier constraints, and startup reconciliation of Merkle nodes, transition records, and the event-chain head. This closes an engineering persistence gap in the reference state machine only. The injected deposit-authorizer and proof-verifier callbacks are still dependencies, not production implementations; the canonical transaction digest, authorization mode, actual issuance/spend proof, live-chain smoke test, and custody policy remain blockers. External audit is explicitly not claimed.

## Active V2 component contract

### Namespace

The public namespace is a 48-byte SHAKE256-384 digest of the domain/version and three canonical 32-byte IDs:

    "0PSP-NAMESPACE-v2-SHAKE256" || 0x02 ||
    uint16_le(32) || ledger_id[32] ||
    uint16_le(32) || deployment_id[32] ||
    uint16_le(32) || asset_id[32]

CHp4.9 supersedes CHp4.8's EVM identity derivation. The frozen Namespace V2 core is unchanged, but the current EVM adapter uses typed Namespace V3 and hashes the full canonical ledger/deployment/asset descriptors directly into one SHAKE256-384 output. Python and native implementations have matching known-answer vectors, and the reference ledger requires NamespaceIdV3 at its context boundary. CHp4.10 adds a strict-majority RPC transport and a durable SQLite checkpoint-to-finalized ancestry journal. CHp4.11 defines the quorum-observed deposit profile and beneficiary binding. CHp4.12 adds Ethereum Keccak/RLP/MPT primitives and checks raw transaction and receipt inclusion at the same transaction index against the roots reconstructed from the exact raw execution-header RLP. CHp4.13 adds a candidate supervised Helios 0.12.0 Ethereum Mainnet light-client process, a binary SHA-256 pin, fresh out-of-band beacon checkpoint, and durable execution checkpoint-to-finalized header journal; it wires authenticated-header membership into the CHp4.12 proof verifier. The returned type is still inclusion evidence, not trusted DepositAuthorization. No real network smoke test or independent differential review has been completed. The verifier additionally queries the protocol runtime code through Helios at the exact deposit block and compares its fingerprint to the pinned Namespace V3 manifest. The beneficiary is carried in the issuance statement model, but the actual proof must bind it under a reviewed policy. Proxy implementation/upgrade semantics and actual asset custody, trusted authorization conversion, durable atomic issuance/spend ledger and reorg recovery remain unimplemented. CHp4.14 further requires native transaction value to equal the proven Deposit event amount, or token deposits to have exactly one matching standard ERC-20 Transfer log from the event depositor to the protocol, and queries token runtime code through Helios at the deposit block. These are movement signals, not custody proofs; malicious token logic, proxy upgrades, forwarding/refunds and balance-accounting semantics still need a reviewed trust policy.

### Deposit evidence v1

The target event is `Deposit(address indexed depositor, address indexed asset, address indexed beneficiary, uint256 amount)`; its `topic0` must be pinned from reviewed ABI artifacts using Ethereum Keccak-256. The observation records the canonical namespace, chain ID, protocol emitter, asset, event topic, transaction hash/index, receipt-local log ordinal, global log index (diagnostic only), block number/hash, `transactionsRoot`, `receiptsRoot`, depositor, beneficiary, amount, and block-specific code fingerprint. The deposit ID is `transaction_hash[32] || BE32(receipt_log_ordinal)`; the finality anchor is `BE64(block_number) || block_hash[32]`.

**Do not treat this evidence as authorization.** CHp4.12 verifies raw transaction and receipt inclusion at the same `RLP(transaction_index)` against roots extracted from raw execution-header RLP. CHp4.13 candidate-wires the verifier to a supervised, binary-pinned Helios Ethereum Mainnet light client and durable checkpoint-to-finalized header ancestry, with protocol code checked at the deposit block. CHp4.14 checks that native event amount equals proven transaction value, or that an ERC-20 Transfer log from the pinned token matches depositor, protocol recipient and amount; it also checks token code at the block. CI uses mocked headers and test vectors, not a real Helios binary, checkpoint, RPC provider, token, or deployed contract. Transfer logs and code hashes do not establish custody by themselves, particularly with proxies or unusual tokens. Before production, smoke-test against a real finalized deposit, differential-test Keccak/RLP/MPT, review contract/proxy/token behavior and custody semantics, then create trusted `DepositAuthorization` only from verified inclusion plus an explicitly approved custody policy. The relevant trie/receipt rules are described in [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) and the [Ethereum trie specification](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/).

### Coin identity and minting

The native API generates a fresh opaque 32-byte coin ID using OpenSSL RAND_bytes; randomness is not a uniqueness proof. CHp4.7 records an additive V3 candidate that does not treat `coin_id` alone as a global identity key. It binds an accepted output to a canonical one-use creation anchor and canonical global output slot. Issuance anchors must come from the authenticated deposit/event adapter, and transfer anchors must be the consumed input V3 nullifier. This is a candidate protocol policy, not a production-enforced invariant.

#### Recipient-keyed, commitment-bound V3 nullifier candidate

- `src/primitives/coin_commitment_v3.py` defines a separate V3 commitment over value, namespace, tuple, independent salt and canonical V3 recipient bundle.
- `src/primitives/nullifier_v3.py` defines a 48-byte recipient-keyed HMAC-SHA3-384 nullifier candidate over the parameters, namespace, encoded public-key bundle, exact registered V3 commitment, `coin_id` and `r_nf`. The bundle contains a domain-separated commitment to a 48-byte recipient-held nullifier key.
- `src/protocol/note_public_key_bundle_v3.py` defines the bounded canonical bundle codec. `src/protocol/output_identity.py` contains versioned issuance/transfer identity derivations using an anchor and canonical global output slot.
- V1/V2 encodings and vectors remain unchanged. Distinct commitment salts produce distinct keyed inputs for this candidate, avoiding V2's deterministic same-nullifier reuse for two commitments with the same hidden tuple; a finite-output collision remains possible, so no injectivity claim is made.
- These functions are reference code, **not a ZK relation**. The proof must bind the same witness across the registered commitment opening, value, namespace, tuple, bundle/key-commitment opening, authorization key, anchor, output slot, value-conservation relation, and public nullifier. The recipient must authenticate the exact bundle. An unbound/substitutable key bundle could produce an unspendable output.
- The Python MintRegistryModel is only an in-memory test model. A durable ledger must atomically consume an issuance anchor or parent nullifier and register outputs; it must not accept an identity candidate independently of an accepted complete proof.

Open gates include canonical chain/deposit identity, selected authorization-signature codec and recipient address authentication, note key recovery/delivery, the shared-witness proof and its feasibility, uniqueness policy under malicious witnesses, and independent security review. The global hidden-ID rule in [CHp4.3](../audit/chp4.3-identity-invariant-decision-review.md) is superseded as a design question by this V3 candidate, but its required proof/ledger enforcement is **not implemented**. Production remains **NO-GO**.

### Nullifier V2

    "0PSP-NULLIFIER-v2-SHAKE256" || 0x02 ||
    uint16_le(48) || namespace_id[48] ||
    uint16_le(32) || coin_id[32] ||
    uint16_le(36) || r_nf[36]

The preimage length is 149 bytes; SHAKE256 outputs 48 bytes. This crosses the 136-byte SHAKE256 rate boundary. The older V1 helper is legacy test compatibility only.

### Coin commitment V2

The V2 48-byte commitment has Python-reference and native OpenSSL implementations over the same canonical length-prefixed encoding: parameter ID, public key bytes, unsigned 64-bit value, namespace ID, coin ID, 36-byte nullifier secret and independent 36-byte salt. The native function is `psp_coin_commitment_v2` in `native/coin_commitment_v2.c`; its known-answer vector matches the Python reference. The native salt generator is a separate API. The exact formula and conditional binding implication are in [the V2 security argument](v2-protocol-security-argument.md). Commitment hiding in the QROM remains open.

## Reproducible checks

CI now performs:
1. Native build with warnings treated as errors.
2. V1 and V2 known-answer, length-validation, failure-output-clearing, and independent coin-ID/nullifier-secret/commitment-salt RNG smoke checks.
3. Python namespace/nullifier/commitment V2 vectors and native/reference agreement tests.
4. Optimized disassembly capture for the combined native V1/V2/nullifier/commitment library.
5. ASan/UBSan runs for native V1/V2 test executables; compile-only validation of separate V2 nullifier and commitment timing screens.
6. Full Python unit/property tests, including namespace RPC quorum, durable finality-journal and deposit-evidence adversarial regression tests.

Local commands:

    python -m pip install -e ".[dev]"
    make -C native clean test
    make -C native sanitize-test
    make -C native audit
    export PSP_NULLIFIER_LIBRARY="$PWD/native/build/libpsp_nullifier.so"
    python -m pytest tests/ -q

On an idle test machine, the V2 diagnostic can be built/run manually:

    make -C native timing-v2-probe-build
    make -C native timing-v2
    make -C native timing-commitment-v2-probe-build
    make -C native timing-commitment-v2

The two local diagnostics compare fixed versus random values in randomized order, repeat trials, and use same-input controls. The commitment screen tests `r_nf` and `rho_C` separately. Neither is the official dudect implementation. It has not established a timing result for a controlled target. A clean result would still not prove constant-time behavior or absence of other side channels, and timing diagnostics are not run in shared CI because its scheduler/virtualization noise makes timing conclusions unreliable.

The old security-budget, phase-1 and nullifier-relation scripts contain historical CHP3/V1 diagnostics. Their success does not validate V2 minting, commitment hiding, Ringtail, zero knowledge or overall protocol security.

## Evidence versus claims

| Claim | Evidence | Decision |
|---|---|---|
| Namespace byte encoding | Python and native known-answer vector; field-substitution tests | Component functional checks pass; chain adapter open |
| Coin-ID generation | Native OpenSSL RNG function and repeated-sample smoke test | Functional only; no entropy proof; generated IDs are not a uniqueness proof |
| V3 output identity | CHp4.7 issuance/transfer reference vectors bind anchor, recipient bundle, parameters, entropy and global output slot | Candidate only; authenticated anchor canonicality and proof-constrained one-use slot remain open |
| Recipient-keyed V3 nullifier | HMAC-SHA3-384 candidate binds canonical bundle and exact V3 commitment; adversarial vectors cover salt changes and tuple/bundle substitutions | Key secrecy, recipient address authentication, PRF/privacy analysis, same-witness proof binding and independent review remain open |
| V3 mint/spend identity uniqueness | In-memory reference tests and deterministic identity derivation vectors | Not durable/consensus enforcement; no circuit constraint or production ledger rule |
| Issuer/sender unlinkability | Candidate keeps nullifier-deriving key outside sender knowledge and binds the exact commitment into HMAC input | No end-to-end issuance/privacy proof, recovery format, address-auth verification, or transcript leakage analysis |
| Deposit evidence | CHp4.11 canonical event normalizer; CHp4.12 raw transaction/receipt MPT inclusion; CHp4.13 pinned Helios Mainnet finality and block-specific protocol code; CHp4.14 native transaction-value equality or ERC-20 Transfer-log matching plus pinned token code | Functional test evidence only; no real Mainnet smoke test, independent differential review, approved proxy/custody semantics, trusted DepositAuthorization conversion, durable atomic mint ledger or issuance proof |
| Scoped mint uniqueness | Concurrent in-memory model tests | Not a durable ledger or consensus proof |
| Mint-authority privacy | No blind-issuance construction implemented | OPEN: authority that knows coin ID and nullifier secret can match a later public nullifier to its record |
| Nullifier V2 byte agreement | Fixed KAT plus Python/native comparison | Functional checks pass; not a security theorem |
| Commitment V2 byte agreement | Matching native/Python KAT, native namespace-binding and failure-path tests, opening recomputation and field-substitution tests | Functional checks pass; formal hiding and final binding parameters open |
| Native source control-flow observations | Fixed widths and public metadata checks | Partial source inspection only |
| Optimized native binaries | CI disassembly artifact includes V1/V2 nullifier and commitment objects | Review and provider internals OPEN |
| Constant-time behavior | Separate V2 nullifier and commitment screens compile in CI but have not been run on a controlled target | **NOT ESTABLISHED** |
| Absence of exploitable side channels | No complete platform or full-protocol leakage assessment | **NOT ESTABLISHED** |
| Threshold signature inside proof | No pinned Ringtail adapter | OPEN |
| Complete single-relation ZK proof | No backend instantiated | OPEN |
| Quantum soundness/anonymity/composition | No composed reduction or independent cryptanalysis | OPEN |
| Production readiness | Several mathematical, ledger and implementation gates remain | **NO-GO** |

## Full-construction blockers

1. Implement actual canonical ledger/deployment/asset adapters and a durable atomic mint registry.
2. Freeze canonical public-key and parameter encodings and complete the commitment hiding theorem, including the quantum random-oracle model and all public outputs.
3. Pin and review Ringtail source, parameters, license and key-generation assumptions; integrate its signature verification into the same hidden-witness relation.
4. Instantiate a single post-quantum ZK argument for membership, commitment opening, threshold authorization, V2 nullifier and state/policy predicates.
5. Complete knowledge-soundness, zero-knowledge, spend-soundness, replay/double-spend, unlinkability and composition arguments with concrete parameters.
6. Review release binaries, OpenSSL provider internals, secret lifetime and errors; run controlled per-target timing/leakage tests for every sensitive routine.
7. Measure full end-to-end proof size, runtime, memory and verifier cost, then obtain independent cryptographic review.

The Python reference and ctypes FFI are not a secret-safe production boundary. The native V2 nullifier and commitment use OpenSSL EVP and allocate an EVP context per call; both use OpenSSL RAND_bytes for new secrets/salts, and each output is cleared on supported failure paths. Fixed-size checks, sanitizers and wrapper disassembly do not prove constant-time execution. The selected provider, compiler output, memory allocation, hardware, FFI/callers and complete prover remain under review.

**Release decision: NO-GO.** The V2 component checkpoint is stronger and testable, but the live ledger, commitment theorem, Ringtail integration, complete proof, composed security argument and full-path side-channel assurance are still open.
