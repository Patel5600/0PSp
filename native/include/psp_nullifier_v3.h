#ifndef PSP_NULLIFIER_V3_H
#define PSP_NULLIFIER_V3_H

#include "psp_keccak.h"
#include "psp_random.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_NULLIFIER_V3_KEY_BYTES 48u
#define PSP_NULLIFIER_V3_KEY_COMMITMENT_BYTES 48u
#define PSP_NULLIFIER_V3_NAMESPACE_BYTES 48u
#define PSP_NULLIFIER_V3_COMMITMENT_BYTES 48u
#define PSP_NULLIFIER_V3_COIN_ID_BYTES 32u
#define PSP_NULLIFIER_V3_RNF_BYTES 36u
#define PSP_NULLIFIER_V3_OUTPUT_BYTES 48u
#define PSP_NULLIFIER_V3_VERSION 3u

/*
 * Generate a fresh 48-byte nullifier secret key (nk) from OS CSPRNG.
 * Clears buffer on any entropy failure.
 */
int psp_nullifier_v3_generate_key(uint8_t *out, size_t out_len);

/*
 * Compute NullifierKeyCommitmentV3 = SHAKE256-384(
 *   "0PSP-NULLIFIER-KEY-COMMIT-v3-SHAKE256" || 0x03 || nk[48]
 * )
 * Output is exactly 48 bytes.
 */
int psp_nullifier_v3_key_commitment(
    const uint8_t *nk, size_t nk_len,
    uint8_t *out, size_t out_len);

/*
 * Compute NullifierV3 = HMAC-SHA3-384_{nk}(
 *   "0PSP-NULLIFIER-v3-HMAC-SHA3-384" || 0x03 ||
 *   u16le(params_id_len) || params_id ||
 *   u16le(48) || namespace_id[48] ||
 *   u32le(bundle_len) || public_key_bundle ||
 *   u16le(48) || commitment[48] ||
 *   u16le(32) || coin_id[32] ||
 *   u16le(36) || r_nf[36]
 * )
 * Output is exactly 48 bytes.
 *
 * Constant-time: uses psp_hmac_sha3_384 and memory zeroization.
 */
int psp_nullifier_v3(
    const uint8_t *nk, size_t nk_len,
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *public_key_bundle, size_t public_key_bundle_len,
    const uint8_t *commitment, size_t commitment_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* PSP_NULLIFIER_V3_H */
