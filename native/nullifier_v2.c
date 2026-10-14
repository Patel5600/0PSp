#include "psp_nullifier_v2.h"
#include "psp_keccak.h"
#include "psp_random.h"

static const uint8_t DOMAIN_NAMESPACE_V2[] = "0PSP-NAMESPACE-v2-SHAKE256";
static const uint8_t DOMAIN_NULLIFIER_V2[] = "0PSP-NULLIFIER-v2-SHAKE256";
static const uint8_t VERSION_V2 = PSP_NULLIFIER_V2_VERSION;
static const uint8_t COMPONENT_LENGTH_LE[2] = {
    PSP_NAMESPACE_COMPONENT_V2_BYTES, 0u
};
static const uint8_t NAMESPACE_LENGTH_LE[2] = {
    (uint8_t)(PSP_NAMESPACE_V2_BYTES & 0xffu), (uint8_t)((PSP_NAMESPACE_V2_BYTES >> 8u) & 0xffu)
};
static const uint8_t COIN_ID_LENGTH_LE[2] = {
    PSP_SCOPED_COIN_ID_V2_BYTES, 0u
};
static const uint8_t SECRET_LENGTH_LE[2] = {
    PSP_NULLIFIER_V2_SECRET_BYTES, 0u
};

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
    int st;

    if (out == NULL || out_len != PSP_NAMESPACE_V2_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    psp_secure_zero(out, PSP_NAMESPACE_V2_BYTES);
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
        if (parts[i] == NULL || lengths[i] == 0u) {
            return PSP_NULLIFIER_ERR_ARGUMENT;
        }
    }
    st = psp_shake256_parts(parts, lengths, 8u, out, PSP_NAMESPACE_V2_BYTES);
    return (st == PSP_CRYPTO_OK) ? PSP_NULLIFIER_OK : PSP_NULLIFIER_ERR_CRYPTO;
}

int psp_coin_id_v2_generate(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_SCOPED_COIN_ID_V2_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    psp_secure_zero(out, PSP_SCOPED_COIN_ID_V2_BYTES);
    if (psp_random_bytes(out, PSP_SCOPED_COIN_ID_V2_BYTES) != PSP_CRYPTO_OK) {
        psp_secure_zero(out, PSP_SCOPED_COIN_ID_V2_BYTES);
        return PSP_NULLIFIER_ERR_CRYPTO;
    }
    return PSP_NULLIFIER_OK;
}

int psp_nullifier_v2_generate_secret(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_NULLIFIER_V2_SECRET_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    psp_secure_zero(out, PSP_NULLIFIER_V2_SECRET_BYTES);
    if (psp_random_bytes(out, PSP_NULLIFIER_V2_SECRET_BYTES) != PSP_CRYPTO_OK) {
        psp_secure_zero(out, PSP_NULLIFIER_V2_SECRET_BYTES);
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
    int st;

    if (out == NULL || out_len != PSP_NULLIFIER_V2_OUTPUT_BYTES) {
        return PSP_NULLIFIER_ERR_ARGUMENT;
    }
    psp_secure_zero(out, PSP_NULLIFIER_V2_OUTPUT_BYTES);
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
    st = psp_shake256_parts(parts, lengths, 8u, out, PSP_NULLIFIER_V2_OUTPUT_BYTES);
    return (st == PSP_CRYPTO_OK) ? PSP_NULLIFIER_OK : PSP_NULLIFIER_ERR_CRYPTO;
}
