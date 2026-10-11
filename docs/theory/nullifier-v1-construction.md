# Nullifier v1 — Fixed Byte Contract and Native Component (Legacy)

> **Legacy-only component.** V1 does not include a namespace input and must not be used for new scoped spends. The active V2 format explicitly binds the ledger/deployment/asset namespace into both the commitment and nullifier. See [V2 security argument](../security/v2-protocol-security-argument.md) and [V2 spend relation](spend-relation-and-proof-binding.md). V1 remains only for historical known-answer tests and compatibility; no implicit V1-to-V2 migration is allowed.

**Status:** functional reference plus native implementation candidate. This is the first secret-processing component for constructionable V0, not a complete spend protocol or a proven PRF/commitment scheme.

## 1. Frozen candidate relation

```text
nu = SHAKE256-384(
    "0PSP-NULLIFIER-v1-SHAKE256" ||
    version ||
    uint16_le(len(coin_id)) || coin_id ||
    uint16_le(len(r_nf)) || r_nf
)
```

All values in this encoding are fixed:
- Domain: ASCII `0PSP-NULLIFIER-v1-SHAKE256`, exactly 26 bytes.
- Version: one byte, `0x01`.
- Coin ID length: 2-byte little-endian integer, value 32.
- Coin ID: exactly 32 bytes.
- Nullifier-secret length: 2-byte little-endian integer, value 36.
- Nullifier secret `r_nf`: exactly 36 bytes (288 bits).
- Output: 48 bytes (384 bits).

The exact absorbed message is 99 bytes. SHAKE256 has a 136-byte rate, so the fixed input fits within one rate block. This is an encoding fact, not a security theorem.

The output is deterministic. The per-coin secret is independent from wallet keys, threshold shares and coin-commitment salt `rho_C`. It must be bound by the selected coin commitment opening and proved as part of the same hidden spend witness. It must not be reused for another coin. Because the v1 nullifier input has no separate chain/asset field, `coin_id` must be generated/validated in a canonical ledger/deployment-and-asset namespace and bound into the coin commitment. That minting invariant is not enforced by this component; see [Constructionable V0](constructionable-v0.md).

## 2. Implementation split

### Python reference

`src/primitives/nullifier.py` defines canonical `CoinId`, `NullifierSecret` and `Nullifier` types, the fixed 99-byte encoding, deterministic SHAKE256 output, functional consistency checks, and a thread-safe in-memory replay model. The Python code and its `hashlib` call are reference/test code only. Python object copies, memory management and interpreter execution are not a constant-time secret-handling boundary.

Debug representations for `CoinId` and `NullifierSecret` redact their bytes.

### Native C candidate

`native/nullifier_v1.c` uses OpenSSL EVP SHAKE256 to process the fixed-width message and return 48 bytes. It also creates 36-byte per-coin secrets through OpenSSL `RAND_bytes`. The native wrapper:
- validates only public pointer/length metadata;
- uses fixed public lengths and fixed byte framing;
- does not branch on secret byte values or use a secret as a memory/table index in its own source;
- clears its output buffer on supported error paths;
- borrows the caller's nullifier-secret buffer without modifying it;
- fails closed if the native library cannot load or the cryptographic call fails.

The caller still owns secret lifetime and copies. The wrapper and RNG call do not zeroize a caller's input. Output clearing on failure, OpenSSL use, or branch-free wrapper code is not a whole-program constant-time guarantee.

The Python `ctypes` adapter is provided for parity tests and initial integration only. A production caller should keep secret handling in a reviewed native/Rust layer and avoid accidental copies, formatting, logs, crash dumps and secret-dependent error behavior.

## 3. Reproducible checks

With a C compiler, OpenSSL development headers and binutils installed:

```sh
make -C native test
make -C native audit
export PSP_NULLIFIER_LIBRARY="$PWD/native/build/libpsp_nullifier.so"
python scripts/verify_nullifier_relation.py
python -m pytest tests/ -q
```

The native tests check two known-answer vectors, fixed lengths, deterministic output, sample coin/secret substitution, failure output clearing, and an RNG integration smoke check. Unit tests compare the native output against the Python reference. The secret-randomness distinction test is probabilistic sanity checking; it is not a proof of entropy.

`make -C native audit` emits optimized wrapper disassembly to `native/build/nullifier_v1.disasm.txt`. CI retains that file as an artifact for review. It does not disassemble or certify OpenSSL internals, and it is not a proof of constant-time behavior.

`make -C native timing` runs a small, non-gating timing-class probe. It is not dudect and must not be used to claim that leakage is absent. The probe should be replaced or supplemented by a reviewed statistical harness on each supported release target.

## 4. Known-answer vectors

Vector A:
- `coin_id = bytes([0, 1, ..., 31])`
- `r_nf = bytes([0, 1, ..., 35])`
- `nu = e672f7462704e6b2140be549ff12b9db66f6f53f0ae6826e612a3b1cf1b0d8a6bdef7c74ad25ba4227a620d4d1d19b42`

Vector B uses a 32-byte all-zero coin ID and a 36-byte all-zero secret:
- `nu = a68519942737e0ea666ce446643a77f2033093069ce1e18f202dfcd8c13839b6e0565abaad751114382ca2d6a2e65663`

Both vectors are checked by C tests and the Python unit suite.

## 5. Security boundary and remaining work

These checks do **not** establish:
- commitment hiding/binding in the Quantum Random Oracle Model;
- hidden-member anonymity, unlinkability, or a concrete QROM advantage bound;
- that the active single-relation proof enforces nullifier derivation, commitment opening and threshold signature under one shared witness;
- threshold-signature security, key-generation trust assumptions, proof knowledge soundness, or complete zero knowledge;
- resistance to timing/cache/power/EM/fault channels for every build and target;
- production readiness.

The native wrapper's source-level behavior has been scoped and its generated wrapper disassembly is collected, but the disassembly has not been independently reviewed. A custom one-off timing probe is not a release test. A reviewed dudect-style evaluation, target/compiler matrix, dependency/backend review, memory/failure review, and independent cryptographic implementation audit remain required.

Constructionable V0 still requires one concrete proof backend implementing the complete relation, formal or well-supported security reductions, reproducible parameter analysis, end-to-end benchmarks, and independent cryptanalysis. **Production status remains NO-GO.**

## References

- NIST FIPS 202 (SHA-3 / SHAKE): https://csrc.nist.gov/pubs/fips/202/final
- RustCrypto `subtle` constant-time-oriented primitives and limitations: https://docs.rs/subtle/latest/subtle/
- dudect timing-leakage test harness: https://github.com/oreparaz/dudect
- [Constructionable V0](constructionable-v0.md)
- [CHP4 constant-time and side-channel release gates](../security/chp4-constant-time-and-side-channel-spec.md)
