#include "psp_namespace_v3.h"
#include "psp_keccak.h"

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
    const uint8_t *parts[8];
    size_t lengths[8];
    uint8_t ledger_len_le[4];
    uint8_t deployment_len_le[4];
    uint8_t asset_len_le[4];
    int status;

    if (out == NULL || out_len != PSP_NAMESPACE_V3_ID_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    psp_secure_zero(out, PSP_NAMESPACE_V3_ID_BYTES);

    if (!valid_component(ledger_identity, ledger_identity_len) ||
        !valid_component(deployment_identity, deployment_identity_len) ||
        !valid_component(asset_identity, asset_identity_len)) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }

    encode_u32_le(ledger_identity_len, ledger_len_le);
    encode_u32_le(deployment_identity_len, deployment_len_le);
    encode_u32_le(asset_identity_len, asset_len_le);

    parts[0] = DOMAIN_NAMESPACE_V3; lengths[0] = sizeof(DOMAIN_NAMESPACE_V3) - 1u;
    parts[1] = &VERSION_V3; lengths[1] = sizeof(VERSION_V3);
    parts[2] = ledger_len_le; lengths[2] = sizeof(ledger_len_le);
    parts[3] = ledger_identity; lengths[3] = ledger_identity_len;
    parts[4] = deployment_len_le; lengths[4] = sizeof(deployment_len_le);
    parts[5] = deployment_identity; lengths[5] = deployment_identity_len;
    parts[6] = asset_len_le; lengths[6] = sizeof(asset_len_le);
    parts[7] = asset_identity; lengths[7] = asset_identity_len;

    status = psp_shake256_parts(parts, lengths, 8u, out, PSP_NAMESPACE_V3_ID_BYTES);

    psp_secure_zero(ledger_len_le, sizeof(ledger_len_le));
    psp_secure_zero(deployment_len_le, sizeof(deployment_len_le));
    psp_secure_zero(asset_len_le, sizeof(asset_len_le));

    if (status != PSP_CRYPTO_OK) {
        psp_secure_zero(out, PSP_NAMESPACE_V3_ID_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}
