#include "psp_nullifier_v1.h"
#include "psp_keccak.h"
#include "psp_random.h"

static const uint8_t DOMAIN_NULLIFIER[] = "0PSP-NULLIFIER-v1-SHAKE256";
static const uint8_t PROTOCOL_VERSION = PSP_NULLIFIER_V1_VERSION;
static const uint8_t COIN_ID_LENGTH_LE[2] = {PSP_NULLIFIER_V1_COIN_ID_BYTES, 0u};
static const uint8_t SECRET_LENGTH_LE[2] = {PSP_NULLIFIER_V1_SECRET_BYTES, 0u};

int psp_nullifier_v1_generate_secret(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_NULLIFIER_V1_SECRET_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    psp_secure_zero(out, PSP_NULLIFIER_V1_SECRET_BYTES);
    if (psp_random_bytes(out, PSP_NULLIFIER_V1_SECRET_BYTES) != PSP_CRYPTO_OK) {
        psp_secure_zero(out, PSP_NULLIFIER_V1_SECRET_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}

int psp_nullifier_v1(const uint8_t *coin_id, size_t coin_id_len,
                     const uint8_t *r_nf, size_t r_nf_len,
                     uint8_t *out, size_t out_len) {
    const uint8_t *parts[6];
    const size_t lengths[6] = {
        sizeof(DOMAIN_NULLIFIER) - 1u,
        sizeof(PROTOCOL_VERSION),
        sizeof(COIN_ID_LENGTH_LE),
        PSP_NULLIFIER_V1_COIN_ID_BYTES,
        sizeof(SECRET_LENGTH_LE),
        PSP_NULLIFIER_V1_SECRET_BYTES
    };
    int st;

    if (out == NULL || out_len != PSP_NULLIFIER_V1_OUTPUT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    psp_secure_zero(out, PSP_NULLIFIER_V1_OUTPUT_BYTES);

    if (coin_id == NULL || coin_id_len != PSP_NULLIFIER_V1_COIN_ID_BYTES ||
        r_nf == NULL || r_nf_len != PSP_NULLIFIER_V1_SECRET_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }

    parts[0] = DOMAIN_NULLIFIER;
    parts[1] = &PROTOCOL_VERSION;
    parts[2] = COIN_ID_LENGTH_LE;
    parts[3] = coin_id;
    parts[4] = SECRET_LENGTH_LE;
    parts[5] = r_nf;

    st = psp_shake256_parts(parts, lengths, 6u, out, PSP_NULLIFIER_V1_OUTPUT_BYTES);
    if (st != PSP_CRYPTO_OK) {
        psp_secure_zero(out, PSP_NULLIFIER_V1_OUTPUT_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}
