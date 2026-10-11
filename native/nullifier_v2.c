#include "psp_nullifier_v2.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static const uint8_t DOMAIN_NAMESPACE_V2[] = "0PSP-NAMESPACE-v2-SHAKE256";
static const uint8_t DOMAIN_NULLIFIER_V2[] = "0PSP-NULLIFIER-v2-SHAKE256";
static const uint8_t VERSION_V2 = PSP_NULLIFIER_V2_VERSION;
static const uint8_t COMPONENT_LENGTH_LE[2] = {
    PSP_NAMESPACE_COMPONENT_V2_BYTES, 0u
};
static const uint8_t NAMESPACE_LENGTH_LE[2] = {
    PSP_NAMESPACE_V2_BYTES & 0xffu, (PSP_NAMESPACE_V2_BYTES >> 8) & 0xffu
};
static const uint8_t COIN_ID_LENGTH_LE[2] = {
    PSP_SCOPED_COIN_ID_V2_BYTES, 0u
};
static const uint8_t SECRET_LENGTH_LE[2] = {
    PSP_NULLIFIER_V2_SECRET_BYTES, 0u
};

static int shake256_parts(const uint8_t *const *parts, const size_t *lengths,
                          size_t count, uint8_t *out, size_t out_len) {
    EVP_MD_CTX *ctx = NULL;
    size_t i;
    int status = PSP_NULLIFIER_ERR_CRYPTO;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
        goto cleanup;
    }
    for (i = 0u; i < count; ++i) {
        if (EVP_DigestUpdate(ctx, parts[i], lengths[i]) != 1) {
            goto cleanup;
        }
    }
    if (EVP_DigestFinalXOF(ctx, out, out_len) != 1) {
        goto cleanup;
    }
    status = PSP_NULLIFIER_OK;

cleanup:
    EVP_MD_CTX_free(ctx);
    if (status != PSP_NULLIFIER_OK && out != NULL && out_len != 0u) {
        OPENSSL_cleanse(out, out_len);
    }
    return status;
}

int psp_namespace_v2_derive(
    const uint8_t *ledger_id, size_t ledger_id_len,
    const uint8_t *deployment_id, size_t deployment_id_len,
    const uint8_t *asset_id, size_t asset_id_len,
    uint8_t *out, size_t out_len) {
    const uint8_t *parts[8];
    const size_t lengths[8] = {
        sizeof(DOMAIN_NAMESPACE_V2) - 1u, sizeof(VERSION_V2),
        sizeof(COMPONENT_LENGTH_LE), PSP_NAMESPACE_COMPONENT_V2_BYTES,
        sizeof(COMPONENT_LENGTH_LE), PSP_NAMESPACE_COMPONENT_V2_BYTES,
        sizeof(COMPONENT_LENGTH_LE), PSP_NAMESPACE_COMPONENT_V2_BYTES
    };
    size_t i;

    if (out == NULL || out_len != PSP_NAMESPACE_V2_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_NAMESPACE_V2_BYTES);
    if (ledger_id == NULL || ledger_id_len != PSP_NAMESPACE_COMPONENT_V2_BYTES ||
        deployment_id == NULL || deployment_id_len != PSP_NAMESPACE_COMPONENT_V2_BYTES ||
        asset_id == NULL || asset_id_len != PSP_NAMESPACE_COMPONENT_V2_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }

    parts[0] = DOMAIN_NAMESPACE_V2;
    parts[1] = &VERSION_V2;
    parts[2] = COMPONENT_LENGTH_LE;
    parts[3] = ledger_id;
    parts[4] = COMPONENT_LENGTH_LE;
    parts[5] = deployment_id;
    parts[6] = COMPONENT_LENGTH_LE;
    parts[7] = asset_id;
    for (i = 0u; i < 8u; ++i) {
        /* Every part pointer and size is fixed or public metadata. */
        if (parts[i] == NULL || lengths[i] == 0u) {
            return PSP_NULLIFIER_ERR_ARGUMENT;
        }
    }
    return shake256_parts(parts, lengths, 8u, out, PSP_NAMESPACE_V2_BYTES);
}

int psp_coin_id_v2_generate(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_SCOPED_COIN_ID_V2_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_SCOPED_COIN_ID_V2_BYTES);
    if (RAND_bytes(out, (int)PSP_SCOPED_COIN_ID_V2_BYTES) != 1) {
        OPENSSL_cleanse(out, PSP_SCOPED_COIN_ID_V2_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}

int psp_nullifier_v2_generate_secret(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_NULLIFIER_V2_SECRET_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_NULLIFIER_V2_SECRET_BYTES);
    if (RAND_bytes(out, (int)PSP_NULLIFIER_V2_SECRET_BYTES) != 1) {
        OPENSSL_cleanse(out, PSP_NULLIFIER_V2_SECRET_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}

int psp_coin_commitment_v2_generate_salt(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_NULLIFIER_V2_SALT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_NULLIFIER_V2_SALT_BYTES);
    if (RAND_bytes(out, (int)PSP_NULLIFIER_V2_SALT_BYTES) != 1) {
        OPENSSL_cleanse(out, PSP_NULLIFIER_V2_SALT_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}

int psp_nullifier_v2(
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    uint8_t *out, size_t out_len) {
    const uint8_t *parts[8];
    const size_t lengths[8] = {
        sizeof(DOMAIN_NULLIFIER_V2) - 1u, sizeof(VERSION_V2),
        sizeof(NAMESPACE_LENGTH_LE), PSP_NAMESPACE_V2_BYTES,
        sizeof(COIN_ID_LENGTH_LE), PSP_SCOPED_COIN_ID_V2_BYTES,
        sizeof(SECRET_LENGTH_LE), PSP_NULLIFIER_V2_SECRET_BYTES
    };

    if (out == NULL || out_len != PSP_NULLIFIER_V2_OUTPUT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_NULLIFIER_V2_OUTPUT_BYTES);
    if (namespace_id == NULL || namespace_id_len != PSP_NAMESPACE_V2_BYTES ||
        coin_id == NULL || coin_id_len != PSP_SCOPED_COIN_ID_V2_BYTES ||
        r_nf == NULL || r_nf_len != PSP_NULLIFIER_V2_SECRET_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }

    parts[0] = DOMAIN_NULLIFIER_V2;
    parts[1] = &VERSION_V2;
    parts[2] = NAMESPACE_LENGTH_LE;
    parts[3] = namespace_id;
    parts[4] = COIN_ID_LENGTH_LE;
    parts[5] = coin_id;
    parts[6] = SECRET_LENGTH_LE;
    parts[7] = r_nf;
    return shake256_parts(parts, lengths, 8u, out, PSP_NULLIFIER_V2_OUTPUT_BYTES);
}
