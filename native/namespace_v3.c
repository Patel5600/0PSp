#include "psp_namespace_v3.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

static const uint8_t DOMAIN_NAMESPACE_V3[] = "0PSP-NAMESPACE-v3-SHAKE256";
static const uint8_t VERSION_V3 = PSP_NAMESPACE_V3_VERSION;

static void encode_u32_le(size_t value, uint8_t out[4]) {
    uint32_t v = (uint32_t)value;
    out[0] = (uint8_t)(v & UINT32_C(0xff));
    out[1] = (uint8_t)((v >> 8) & UINT32_C(0xff));
    out[2] = (uint8_t)((v >> 16) & UINT32_C(0xff));
    out[3] = (uint8_t)((v >> 24) & UINT32_C(0xff));
}

static int valid_component(const uint8_t *value, size_t length) {
    return value != NULL &&
           length >= 1u &&
           length <= PSP_NAMESPACE_V3_COMPONENT_MAX_BYTES;
}

int psp_namespace_v3_derive(
    const uint8_t *ledger_identity, size_t ledger_identity_len,
    const uint8_t *deployment_identity, size_t deployment_identity_len,
    const uint8_t *asset_identity, size_t asset_identity_len,
    uint8_t *out, size_t out_len) {
    EVP_MD_CTX *ctx = NULL;
    uint8_t ledger_len_le[4];
    uint8_t deployment_len_le[4];
    uint8_t asset_len_le[4];
    int status = PSP_NULLIFIER_ERR_CRYPTO;

    if (out == NULL || out_len != PSP_NAMESPACE_V3_ID_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    OPENSSL_cleanse(out, PSP_NAMESPACE_V3_ID_BYTES);

    if (!valid_component(ledger_identity, ledger_identity_len) ||
        !valid_component(deployment_identity, deployment_identity_len) ||
        !valid_component(asset_identity, asset_identity_len)) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }

    encode_u32_le(ledger_identity_len, ledger_len_le);
    encode_u32_le(deployment_identity_len, deployment_len_le);
    encode_u32_le(asset_identity_len, asset_len_le);

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, DOMAIN_NAMESPACE_V3,
                         sizeof(DOMAIN_NAMESPACE_V3) - 1u) != 1 ||
        EVP_DigestUpdate(ctx, &VERSION_V3, sizeof(VERSION_V3)) != 1 ||
        EVP_DigestUpdate(ctx, ledger_len_le, sizeof(ledger_len_le)) != 1 ||
        EVP_DigestUpdate(ctx, ledger_identity, ledger_identity_len) != 1 ||
        EVP_DigestUpdate(ctx, deployment_len_le, sizeof(deployment_len_le)) != 1 ||
        EVP_DigestUpdate(ctx, deployment_identity, deployment_identity_len) != 1 ||
        EVP_DigestUpdate(ctx, asset_len_le, sizeof(asset_len_le)) != 1 ||
        EVP_DigestUpdate(ctx, asset_identity, asset_identity_len) != 1 ||
        EVP_DigestFinalXOF(ctx, out, PSP_NAMESPACE_V3_ID_BYTES) != 1) {
        goto cleanup;
    }
    status = PSP_NULLIFIER_OK;

cleanup:
    EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(ledger_len_le, sizeof(ledger_len_le));
    OPENSSL_cleanse(deployment_len_le, sizeof(deployment_len_le));
    OPENSSL_cleanse(asset_len_le, sizeof(asset_len_le));
    if (status != PSP_NULLIFIER_OK) {
        OPENSSL_cleanse(out, PSP_NAMESPACE_V3_ID_BYTES);
    }
    return status;
}
