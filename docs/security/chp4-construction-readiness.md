# CHP4 / V2 Construction Readiness Record

**Checkpoint:** namespace-bound component functions and fixed vectors are implemented. Full 0PSP protocol remains **NO-GO**.

**RFC review update (2026-10-12):** The active work packages and blocking gates are tracked in [the evidence-first RFC register](evidence-first-rfc-register.md). The existing V2 commitment already includes `value`, namespace, `coin_id`, `r_nf`, key bytes, parameter ID and independent salt in its preimage. The identified multi-identity risk is not fixed by adding a second `C_spend`: the eventual spend proof must enforce that the commitment opening and nullifier use the exact same witness. More importantly, no live issuance flow yet proves that the mint's recorded public value equals the hidden value in `C`.

**Do not infer readiness from component tests:** Python/native equality proves byte-contract agreement only. It does not prove issuer unlinkability, commitment hiding, ZK relation soundness, ledger atomicity or constant-time execution. Authorization mode remains unresolved; see [RFC-02 spend relation](../theory/spend-relation-spec.md).


## Active V2 component contract

### Namespace

The public namespace is a 48-byte SHAKE256-384 digest of the domain/version and three canonical 32-byte IDs:

    "0PSP-NAMESPACE-v2-SHAKE256" || 0x02 ||
    uint16_le(32) || ledger_id[32] ||
    uint16_le(32) || deployment_id[32] ||
    uint16_le(32) || asset_id[32]

CHp4.9 supersedes CHp4.8's EVM identity derivation. The frozen Namespace V2 core is unchanged, but the current EVM adapter uses typed Namespace V3 and hashes the full canonical ledger/deployment/asset descriptors directly into one SHAKE256-384 output. Python and native implementations have matching known-answer vectors, and the reference ledger requires NamespaceIdV3 at its context boundary. This is code-level identity mapping, not a trustless light client or production minting contract. The actual deposit/event verifier, proof verifier, durable ledger and chain finality/reorg handling remain unimplemented.

### Coin identity and minting

The native API generates a fresh opaque 32-byte coin ID using OpenSSL RAND_bytes. The candidate identity is (namespace_id, coin_id), but global hidden-ID uniqueness is under review in [CHp4.3](../audit/chp4.3-identity-invariant-decision-review.md), not an approved production rule. One-use canonical deposit consumption and duplicate-nullifier rejection are separate obligations. The Python MintRegistryModel is only an in-memory test model.

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
6. Full Python unit/property tests.

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
| Coin-ID generation | Native OpenSSL RNG function and repeated-sample smoke test | Functional only; no entropy proof; ledger uniqueness open |
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
