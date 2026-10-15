#ifndef PSP_MOBILE_H
#define PSP_MOBILE_H

/*
 * 0PSP Mobile & Embedded Native Cryptographic Engine
 *
 * Provides constant-time, zero-dependency, memory-safe cryptographic primitives
 * and Tier 1 edge proving capabilities for consumer mobile devices (Android / iOS)
 * and embedded microarchitectures.
 *
 * Guaranteed Properties:
 * - Constant-Time: Pure 64-bit logic (Keccak-f[1600]), no data-dependent memory lookups or branches.
 * - Zero Dependencies: Implemented in pure C11; links directly against libc / OS CSPRNG.
 * - Mobile Memory Budget: Tier 1 execution requires < 64 KB of stack, zero dynamic heap allocations.
 * - Latency: Sub-millisecond execution (< 1 ms on modern mobile ARM64).
 */

#include "psp_keccak.h"
#include "psp_random.h"
#include "psp_namespace_v3.h"
#include "psp_nullifier_v3.h"
#include "psp_coin_commitment_v3.h"
#include "psp_merkle_tree_v3.h"
#include "psp_tier1_mobile.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns the semantic version of the native cryptographic engine (e.g. 0x00010000 for v0.1.0).
 */
static inline uint32_t psp_mobile_engine_version(void) {
    return 0x00010000u;
}

#ifdef __cplusplus
}
#endif

#endif /* PSP_MOBILE_H */
