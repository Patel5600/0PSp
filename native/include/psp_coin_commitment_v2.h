#ifndef PSP_COIN_COMMITMENT_V2_H
#define PSP_COIN_COMMITMENT_V2_H

#include "psp_nullifier_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_COIN_COMMITMENT_V2_SALT_BYTES 36u
#define PSP_COIN_COMMITMENT_V2_OUTPUT_BYTES 48u
#define PSP_COIN_COMMITMENT_V2_VERSION 2u

/*
 * Generate a fresh 36-byte V2 commitment salt using OpenSSL RAND_bytes.
 * Never reuse the result as r_nf or for another coin.
 */
int psp_coin_commitment_v2_generate_salt(uint8_t *out, size_t out_len);

/*
 * Compute SHAKE256-384 over the canonical V2 commitment preimage:
 *   "0PSP-COIN-COMMIT-v2-SHAKE256" || 0x02 ||
 *   u16le(params_id_len) || params_id ||
 *   u32le(public_key_len) || canonical_public_key ||
 *   u64le(value) ||
 *   u16le(48) || namespace_id[48] ||
 *   u16le(32) || coin_id[32] ||
 *   u16le(36) || r_nf[36] ||
 *   u16le(36) || rho_C[36]
 *
 * Public-key canonicality is the caller's responsibility until the exact
 * threshold signature scheme and codec are pinned. All lengths and pointers
 * are public metadata. Inputs/output must not overlap. This API and the
 * source-level control flow do not imply a constant-time guarantee.
 */
int psp_coin_commitment_v2(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *public_key, size_t public_key_len,
    uint64_t value,
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    const uint8_t *rho_c, size_t rho_c_len,
    uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
