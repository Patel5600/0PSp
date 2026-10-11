#include "psp_coin_commitment_v2.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>

static const uint8_t DOMAIN_COIN_COMMITMENT_V2[] = "0PSP-COIN-COMMIT-v2-SHAKE256";
static const uint8_t VERSION_V2 = PSP_COIN_COMMITMENT_V2_VERSION;
static const uint8_t NAMESPACE_LENGTH_LE[2] = {
    PSP_NAMESPACE_V2_BYTES & 0xffu, (PSP_NAMESPACE_V2_BYTES >> 8) & 0xffu
};
static const uint8_t COIN_ID_LENGTH_LE[2] = {
    PSP_SCOPED_COIN_ID_V2_BYTES, 0u
};
static const uint8_t SECRET_LENGTH_LE[2] = {
    PSP_NULLIFIER_V2_SECRET_BYTES, 0u
};
static const uint8_t SALT_LENGTH_LE[2] = {
    PSP_COIN_COMMITMENT_V2_SALT_BYTES, 0u
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

int psp_coin_commitment_v2_generate_salt(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_COIN_COMMITMENT_V2_SALT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_COIN_COMMITMENT_V2_SALT_BYTES);
    if (RAND_bytes(out, (int)PSP_COIN_COMMITMENT_V2_SALT_BYTES) != 1) {
        OPENSSL_cleanse(out, PSP_COIN_COMMITMENT_V2_SALT_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}

int psp_coin_commitment_v2(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *public_key, size_t public_key_len,
    uint64_t value,
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    const uint8_t *rho_c, size_t rho_c_len,
    uint8_t *out, size_t out_len) {
    uint8_t params_len_le[2];
    uint8_t public_key_len_le[4];
    uint8_t value_le[8];
    const uint8_t *parts[15];
    size_t lengths[15];
    size_t i;
    uint32_t public_key_len_u32;

    if (out == NULL || out_len != PSP_COIN_COMMITMENT_V2_OUTPUT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_COIN_COMMITMENT_V2_OUTPUT_BYTES);

    if (params_id == NULL || params_id_len == 0u || params_id_len > UINT16_MAX ||
        public_key == NULL || public_key_len == 0u || public_key_len > UINT32_MAX ||
        namespace_id == NULL || namespace_id_len != PSP_NAMESPACE_V2_BYTES ||
        coin_id == NULL || coin_id_len != PSP_SCOPED_COIN_ID_V2_BYTES ||
        r_nf == NULL || r_nf_len != PSP_NULLIFIER_V2_SECRET_BYTES ||
        rho_c == NULL || rho_c_len != PSP_COIN_COMMITMENT_V2_SALT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }

    params_len_le[0] = (uint8_t)(params_id_len & 0xffu);
    params_len_le[1] = (uint8_t)((params_id_len >> 8) & 0xffu);
    public_key_len_u32 = (uint32_t)public_key_len;
    public_key_len_le[0] = (uint8_t)(public_key_len_u32 & UINT32_C(0xff));
    public_key_len_le[1] = (uint8_t)((public_key_len_u32 >> 8) & UINT32_C(0xff));
    public_key_len_le[2] = (uint8_t)((public_key_len_u32 >> 16) & UINT32_C(0xff));
    public_key_len_le[3] = (uint8_t)((public_key_len_u32 >> 24) & UINT32_C(0xff));
    for (i = 0u; i < sizeof(value_le); ++i) {
        value_le[i] = (uint8_t)((value >> (8u * i)) & UINT64_C(0xff));
    }

    parts[0] = DOMAIN_COIN_COMMITMENT_V2;
    lengths[0] = sizeof(DOMAIN_COIN_COMMITMENT_V2) - 1u;
    parts[1] = &VERSION_V2;
    lengths[1] = sizeof(VERSION_V2);
    parts[2] = params_len_le;
    lengths[2] = sizeof(params_len_le);
    parts[3] = params_id;
    lengths[3] = params_id_len;
    parts[4] = public_key_len_le;
    lengths[4] = sizeof(public_key_len_le);
    parts[5] = public_key;
    lengths[5] = public_key_len;
    parts[6] = value_le;
    lengths[6] = sizeof(value_le);
    parts[7] = NAMESPACE_LENGTH_LE;
    lengths[7] = sizeof(NAMESPACE_LENGTH_LE);
    parts[8] = namespace_id;
    lengths[8] = namespace_id_len;
    parts[9] = COIN_ID_LENGTH_LE;
    lengths[9] = sizeof(COIN_ID_LENGTH_LE);
    parts[10] = coin_id;
    lengths[10] = coin_id_len;
    parts[11] = SECRET_LENGTH_LE;
    lengths[11] = sizeof(SECRET_LENGTH_LE);
    parts[12] = r_nf;
    lengths[12] = r_nf_len;
    parts[13] = SALT_LENGTH_LE;
    lengths[13] = sizeof(SALT_LENGTH_LE);
    parts[14] = rho_c;
    lengths[14] = rho_c_len;

    return shake256_parts(parts, lengths, 15u, out,
                          PSP_COIN_COMMITMENT_V2_OUTPUT_BYTES);
}
