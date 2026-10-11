# CHP4 Construction Readiness Record

**Checkpoint:** first secret-processing component implemented; full protocol remains **NO-GO**.  
**Scope:** fixed-width SHAKE256 nullifier candidate, native OpenSSL wrapper, per-coin secret generation, reproducible functional tests, and implementation-security release gates.

## Concrete component contract

The active research candidate currently defines:

- Coin identifier: 32 bytes.
- Per-coin nullifier secret: 36 bytes (288 bits), independent from wallet keys and commitment salt.
- Preimage: `"0PSP-NULLIFIER-v1-SHAKE256" || 0x01 || uint16_le(32) || coin_id || uint16_le(36) || r_nf`.
- Preimage length: 99 bytes.
- Output: SHAKE256-384, exactly 48 bytes.
- Secret generation: OpenSSL `RAND_bytes` through the native C interface; fail closed without a Python RNG fallback.
- Error handling: fixed-size output is cleared on supported failure paths; native wrapper validates public pointer/length metadata and does not branch on secret bytes in its own source.
- Replay demonstration: in-memory atomic duplicate-nullifier rejection, explicitly not a consensus ledger.

The 99-byte input fits within one SHAKE256 rate block (136 bytes). That is a byte-layout fact, not a cryptographic security argument.

## Reproducible checks

The repository CI performs:
1. Native compilation with `-O2 -Wall -Wextra -Werror -pedantic`.
2. Native known-answer, encoding, failure-path, and RNG smoke checks.
3. Optimized wrapper disassembly capture as a review artifact.
4. Compilation of the preliminary timing probe, without treating timing output as a release gate.
5. Python/native known-answer agreement, nullifier functional smoke tests, arithmetic diagnostics, and unit/property tests.

Local commands:

```sh
python -m pip install -e ".[dev]"
make -C native clean test
make -C native audit
make -C native timing-probe-build
export PSP_NULLIFIER_LIBRARY="$PWD/native/build/libpsp_nullifier.so"
python scripts/verify_nullifier_relation.py
python -m pytest tests/ -q
```

The timing probe is deliberately not run in shared CI because scheduler and virtualization noise make such a run unsuitable as release evidence. It is a preliminary diagnostic, not dudect and not a constant-time proof.

## Evidence versus claims

| Claim | Current evidence | Decision |
|---|---|---|
| Python/native byte-level agreement | Fixed known-answer vectors and CI tests | Functional check passes |
| Fresh per-coin secret generation | OpenSSL RNG integration and smoke checks | Functional check only; not an entropy proof |
| Wrapper does not branch on secret bytes in source | Source inspection; optimized wrapper disassembly captured | Preliminary, compiler/build-specific evidence |
| Constant-time SHAKE implementation | OpenSSL internals/provider and supported target binaries not independently assessed | **OPEN** |
| No exploitable side channels | No complete platform-level leakage assessment; timing probe is non-gating | **NOT ESTABLISHED** |
| Asset/deployment-scoped coin IDs | Required invariant documented, but minting derivation and enforcement are not implemented | **OPEN** |
| Coin-commitment hiding and binding | SHAKE commitment candidate only; reduction not completed | **OPEN** |
| Threshold authorization in the anonymous proof | Ringtail adapter not integrated | **OPEN** |
| Complete single-relation zero-knowledge proof | Backend and full relation not instantiated | **OPEN** |
| Quantum soundness, unlinkability, composition | No complete reduction or independent cryptanalysis | **OPEN** |
| Production readiness | Several mathematical and implementation gates remain open | **NO-GO** |

## Explicit implementation boundary

The Python reference is not a constant-time secret-handling boundary. The C wrapper's source-level control flow is not sufficient to prove constant-time behavior: compiler output, OpenSSL's selected implementation, hardware, FFI, memory lifecycle, and callers all matter. A successful test suite does not establish zero knowledge, anonymity, collision resistance, post-quantum security, or absence of side channels.

The nullifier does not accept a separate asset or deployment identifier. Until a canonical minting function and ledger validation enforce a unique `coin_id` namespace per deployment and asset, the full protocol must not claim asset-bound nullifiers.

## Next mandatory gates

1. Specify and implement canonical minting and asset/deployment namespace validation.
2. Select and pin the threshold-signature implementation and concrete single-proof backend.
3. Instantiate the complete relation, including hidden membership, commitment opening, threshold signature, nullifier, state and policy predicates.
4. Complete the commitment hiding/binding and full-protocol soundness/unlinkability arguments, including the quantum-oracle model and concrete bounds.
5. Review the selected OpenSSL provider, optimized native binaries and every supported target; run a reviewed statistical timing harness and adversarial leakage tests.
6. Obtain independent cryptographic review and reproducible end-to-end proof-size/runtime/memory measurements.

Until all gates are closed with evidence, this checkpoint is a research component integration, not a production-ready 0PSP protocol.
