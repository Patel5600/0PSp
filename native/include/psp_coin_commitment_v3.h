#ifndef PSP_COIN_COMMITMENT_V3_H
#define PSP_COIN_COMMITMENT_V3_H

#include "psp_keccak.h"
#include "psp_random.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_COIN_COMMITMENT_V3_SALT_BYTES 36u
#define PSP_COIN_COMMITMENT_V3_NAMESPACE_BYTES 48u
#define PSP_COIN_COMMITMENT_V3_COIN_ID_BYTES 32u
#define PSP_COIN_COMMITMENT_V3_RNF_BYTES 36u
#define PSP_COIN_COMMITMENT_V3_OUTPUT_BYTES 48u
#define PSP_COIN_COMMITMENT_V3_VERSION 3u

/*
 * Generate a fresh 36-byte commitment salt (rho_coin) from OS CSPRNG.
 */
int psp_coin_commitment_v3_generate_salt(uint8_t *out, size_t out_len);

/*
 * Compute CoinCommitmentV3 = SHAKE256-384(
 *   "0PSP-COIN-COMMIT-v3-SHAKE256" || 0x03 ||
 *   u16le(params_id_len) || params_id ||
 *   u32le(pk_bundle_len) || pk_bundle ||
 *   u64le(value) ||
 *   u16le(48) || namespace_id[48] ||
 *   u16le(32) || coin_id[32] ||
 *   u16le(36) || r_nf[36] ||
 *   u16le(36) || rho_coin[36]
 * )
 * Output is exactly 48 bytes.
 */
int psp_coin_commitment_v3(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *pk_bundle, size_t pk_bundle_len,
    uint64_t value,
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    const uint8_t *rho_coin, size_t rho_coin_len,
    uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* PSP_COIN_COMMITMENT_V3_H */
