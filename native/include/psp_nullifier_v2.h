#ifndef PSP_NULLIFIER_V2_H
#define PSP_NULLIFIER_V2_H

#include "psp_nullifier_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_NAMESPACE_COMPONENT_V2_BYTES 32u
#define PSP_NAMESPACE_V2_BYTES 48u
#define PSP_SCOPED_COIN_ID_V2_BYTES 32u
#define PSP_NULLIFIER_V2_SECRET_BYTES 36u
#define PSP_NULLIFIER_V2_OUTPUT_BYTES 48u
#define PSP_NULLIFIER_V2_VERSION 2u

/*
 * Derive namespace_id = SHAKE256-384(
 *   "0PSP-NAMESPACE-v2-SHAKE256" || 0x02 ||
 *   uint16_le(32) || ledger_id[32] ||
 *   uint16_le(32) || deployment_id[32] ||
 *   uint16_le(32) || asset_id[32]).
 *
 * Inputs must already be canonical, chain-specific 32-byte identifiers.
 * A ticker or human-readable chain name is not a canonical asset/ledger ID.
 * Output is cleared on supported failure paths.
 */
int psp_namespace_v2_derive(
    const uint8_t *ledger_id, size_t ledger_id_len,
    const uint8_t *deployment_id, size_t deployment_id_len,
    const uint8_t *asset_id, size_t asset_id_len,
    uint8_t *out, size_t out_len);

/*
 * Generate a fresh opaque 32-byte coin ID using OpenSSL RAND_bytes.
 * The ID is unique only probabilistically; the ledger MUST atomically reject
 * a duplicate (namespace_id, coin_id) pair. This helper is not a mint ledger.
 */
int psp_coin_id_v2_generate(uint8_t *out, size_t out_len);

/*
 * Compute SHAKE256-384 over the exact namespace-bound preimage:
 *   "0PSP-NULLIFIER-v2-SHAKE256" || 0x02 ||
 *   uint16_le(48) || namespace_id[48] ||
 *   uint16_le(32) || coin_id[32] ||
 *   uint16_le(36) || r_nf[36]
 * Total absorbed message length: 149 bytes. Output is exactly 48 bytes.
 *
 * This directly domain-binds the nullifier to the ledger/deployment/asset
 * namespace. It requires the V2 witness relation and commitment to use the
 * same namespace_id and coin_id. Inputs and output must not overlap.
 *
 * Fixed lengths and source-level branch structure are not a constant-time
 * proof. OpenSSL provider code, compiled machine code, hardware, FFI, callers
 * and the complete prover remain in the side-channel review scope.
 */
int psp_nullifier_v2(
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
