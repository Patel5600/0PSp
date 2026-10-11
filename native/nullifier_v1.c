#include "psp_nullifier_v1.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static const uint8_t DOMAIN_NULLIFIER[] = "0PSP-NULLIFIER-v1-SHAKE256";
static const uint8_t PROTOCOL_VERSION = PSP_NULLIFIER_V1_VERSION;
static const uint8_t COIN_ID_LENGTH_LE[2] = {PSP_NULLIFIER_V1_COIN_ID_BYTES, 0u};
static const uint8_t SECRET_LENGTH_LE[2] = {PSP_NULLIFIER_V1_SECRET_BYTES, 0u};

int psp_nullifier_v1_generate_secret(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_NULLIFIER_V1_SECRET_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_NULLIFIER_V1_SECRET_BYTES);
    if (RAND_bytes(out, (int)PSP_NULLIFIER_V1_SECRET_BYTES) != 1) {
        OPENSSL_cleanse(out, PSP_NULLIFIER_V1_SECRET_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}

int psp_nullifier_v1(const uint8_t *coin_id, size_t coin_id_len,
                     const uint8_t *r_nf, size_t r_nf_len,
                     uint8_t *out, size_t out_len) {
    EVP_MD_CTX *ctx = NULL;
    int status = PSP_NULLIFIER_ERR_CRYPTO;

    if (out == NULL || out_len != PSP_NULLIFIER_V1_OUTPUT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_NULLIFIER_V1_OUTPUT_BYTES);

    /* Validation depends only on public pointer/length metadata. */
    if (coin_id == NULL || coin_id_len != PSP_NULLIFIER_V1_COIN_ID_BYTES ||
        r_nf == NULL || r_nf_len != PSP_NULLIFIER_V1_SECRET_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, DOMAIN_NULLIFIER, sizeof(DOMAIN_NULLIFIER) - 1u) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, &PROTOCOL_VERSION, sizeof(PROTOCOL_VERSION)) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, COIN_ID_LENGTH_LE, sizeof(COIN_ID_LENGTH_LE)) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, coin_id, PSP_NULLIFIER_V1_COIN_ID_BYTES) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, SECRET_LENGTH_LE, sizeof(SECRET_LENGTH_LE)) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, r_nf, PSP_NULLIFIER_V1_SECRET_BYTES) != 1) {
        goto cleanup;
    }
    if (EVP_DigestFinalXOF(ctx, out, PSP_NULLIFIER_V1_OUTPUT_BYTES) != 1) {
        goto cleanup;
    }
    status = PSP_NULLIFIER_OK;

cleanup:
    EVP_MD_CTX_free(ctx);
    if (status != PSP_NULLIFIER_OK) {
        OPENSSL_cleanse(out, PSP_NULLIFIER_V1_OUTPUT_BYTES);
    }
    return status;
}
