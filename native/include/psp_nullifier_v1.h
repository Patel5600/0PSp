#ifndef PSP_NULLIFIER_V1_H
#define PSP_NULLIFIER_V1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_NULLIFIER_V1_COIN_ID_BYTES 32u
#define PSP_NULLIFIER_V1_SECRET_BYTES 36u
#define PSP_NULLIFIER_V1_OUTPUT_BYTES 48u
#define PSP_NULLIFIER_V1_VERSION 1u

enum psp_nullifier_status {
    PSP_NULLIFIER_OK = 0,
    PSP_NULLIFIER_ERR_ARGUMENT = -1,
    PSP_NULLIFIER_ERR_CRYPTO = -2
};

/*
 * Generate 36 fresh bytes for one coin-specific nullifier secret using the
 * linked OpenSSL CSPRNG. The caller must keep the result secret, bind it into
 * that coin's commitment opening, never reuse it for another coin, and manage
 * its remaining copies/lifetime. A correctly-sized output is cleared on error.
 */
int psp_nullifier_v1_generate_secret(uint8_t *out, size_t out_len);

/*
 * Compute SHAKE256-384 over the exact V0 candidate encoding:
 *   DOMAIN_NULLIFIER[26] || version[1] || uint16_le(coin_id_len) || coin_id[32]
 *      || uint16_le(r_nf_len) || r_nf[36]
 * Total absorbed message length: 99 bytes. Output is exactly 48 bytes.
 *
 * Lengths/pointers are public metadata. The wrapper has no source-level
 * branch or index controlled by secret bytes. This is NOT a constant-time
 * guarantee: compiler output, OpenSSL internals, hardware, FFI and callers
 * require separate review. Inputs and output must not overlap.
 */
int psp_nullifier_v1(const uint8_t *coin_id, size_t coin_id_len,
                     const uint8_t *r_nf, size_t r_nf_len,
                     uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
