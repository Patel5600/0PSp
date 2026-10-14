# 0PSP Native Cryptographic Engine (C11)

This directory contains the zero-dependency, constant-time C11 implementation of 0PSP cryptographic primitives and data structures.

## Design Principles

1. **Zero External Runtime Dependencies:**
   - Pure C11 standard library + direct OS kernel CSPRNG APIs.
   - Eliminates OpenSSL, LibGCrypt, and external cryptographic library drift/dependencies.
2. **Microarchitectural Timing Invariance:**
   - Branchless, lookup-table-free 24-round Keccak-f[1600] state permutation.
   - Bitwise rotations via compiler intrinsics (`_rotl64` on MSVC/MinGW, `(x << n) | (x >> (64 - n))` on Clang/GCC).
   - No data-dependent branches or secret-indexed memory lookups.
   - Hardware cycle-counter timing probes (`RDTSC`) verify microarchitectural timing invariance ($|t| < 4.5$ Welch's t-test).
3. **Defense-in-Depth Secret Protection:**
   - Compiler memory barrier and volatile scrubbing (`psp_secure_zero`) prevents dead-store elimination.
   - Physical RAM locking (`VirtualLock` on Windows, `mlock` on Linux) prevents plaintext secrets from swapping to disk.
4. **OS Kernel CSPRNG:**
   - Windows: `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
   - Linux / POSIX: `getrandom(2)` with `GRND_NONBLOCK` fallback to `/dev/urandom`.

## Implemented Primitives

| Primitive | Function | Standard / Specification |
|---|---|---|
| **Keccak-f[1600]** | `psp_keccak_f1600` | NIST FIPS 202 24-round permutation |
| **SHAKE256** | `psp_shake256`, `psp_shake256_parts` | NIST FIPS 202 Extendable Output Function (XOF) |
| **SHA3-384** | `psp_sha3_384`, `psp_sha3_384_parts` | NIST FIPS 202 Cryptographic Hash |
| **Keccak-256** | `psp_keccak256`, `psp_keccak256_parts` | Ethereum / EVM standard Keccak-256 |
| **HMAC-SHA3-384** | `psp_hmac_sha3_384`, `psp_hmac_sha3_384_parts` | RFC 2104 Keyed-Hashing for Message Authentication |
| **Namespace V3** | `psp_namespace_v3_derive` | 0PSP direct-hash descriptor binding |
| **Nullifier V1** | `psp_nullifier_v1` | Legacy V1 SHAKE256-384 nullifier |
| **Nullifier V2** | `psp_nullifier_v2` | Scoped V2 SHAKE256-384 nullifier |
| **Nullifier V3** | `psp_nullifier_v3` | Recipient-keyed HMAC-SHA3-384 nullifier |
| **Nullifier Key Commitment** | `psp_nullifier_v3_key_commitment` | Domain-separated SHA3-384 key commitment |
| **Coin Commitment V2** | `psp_coin_commitment_v2` | V2 SHAKE256-384 commitment |
| **Coin Commitment V3** | `psp_coin_commitment_v3` | V3 SHAKE256-384 commitment binding key bundle |
| **Merkle Tree V3** | `psp_merkle_leaf_hash`, `psp_merkle_node_hash`, `psp_merkle_verify_path` | Depth-63 domain-separated Merkle accumulator |

## Building

### Windows (GCC / MinGW)
```bash
gcc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -shared -Iinclude \
    keccak_f1600.c random.c nullifier_v1.c namespace_v3.c nullifier_v2.c nullifier_v3.c \
    coin_commitment_v2.c coin_commitment_v3.c merkle_tree_v3.c \
    -lbcrypt -o build/libpsp_native.dll
```

### Linux (GCC / Clang)
```bash
make test
```

## Testing & Verification

1. **NIST FIPS 202 Known Answer Tests (KAT):**
   ```bash
   ./build/test_keccak_kat.exe
   ```
2. **0PSP V3 Cryptographic KATs (byte-for-byte agreement with Python reference):**
   ```bash
   ./build/test_v3_primitives.exe
   ```
3. **Hardware RDTSC Timing Screen (Microarchitectural leakage probe):**
   ```bash
   ./build/timing_probe_v3_native.exe
   ```
