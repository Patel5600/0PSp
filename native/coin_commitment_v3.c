#include "psp_coin_commitment_v3.h"
#include <string.h>

static const uint8_t DOMAIN_COMMIT_V3[] = "0PSP-COIN-COMMIT-v3-SHAKE256";
static const uint8_t VERSION_V3 = PSP_COIN_COMMITMENT_V3_VERSION;

static const uint8_t LEN_48_LE[2] = { 48u, 0u };
static const uint8_t LEN_32_LE[2] = { 32u, 0u };
static const uint8_t LEN_36_LE[2] = { 36u, 0u };

int psp_coin_commitment_v3_generate_salt(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_COIN_COMMITMENT_V3_SALT_BYTES) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    return psp_random_bytes(out, out_len);
}

int psp_coin_commitment_v3(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *pk_bundle, size_t pk_bundle_len,
    uint64_t value,
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    const uint8_t *rho_coin, size_t rho_coin_len,
    uint8_t *out, size_t out_len) {
    const uint8_t *parts[16];
    size_t lengths[16];
    uint8_t params_len_le[2];
    uint8_t bundle_len_le[4];
    uint8_t value_le[8];
    size_t i;

    if (params_id == NULL || params_id_len > 65535u ||
        pk_bundle == NULL || pk_bundle_len > 4294967295ULL ||
        namespace_id == NULL || namespace_id_len != PSP_COIN_COMMITMENT_V3_NAMESPACE_BYTES ||
        coin_id == NULL || coin_id_len != PSP_COIN_COMMITMENT_V3_COIN_ID_BYTES ||
        r_nf == NULL || r_nf_len != PSP_COIN_COMMITMENT_V3_RNF_BYTES ||
        rho_coin == NULL || rho_coin_len != PSP_COIN_COMMITMENT_V3_SALT_BYTES ||
        out == NULL || out_len != PSP_COIN_COMMITMENT_V3_OUTPUT_BYTES) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    params_len_le[0] = (uint8_t)(params_id_len & 0xffu);
    params_len_le[1] = (uint8_t)((params_id_len >> 8u) & 0xffu);

    bundle_len_le[0] = (uint8_t)(pk_bundle_len & 0xffu);
    bundle_len_le[1] = (uint8_t)((pk_bundle_len >> 8u) & 0xffu);
    bundle_len_le[2] = (uint8_t)((pk_bundle_len >> 16u) & 0xffu);
    bundle_len_le[3] = (uint8_t)((pk_bundle_len >> 24u) & 0xffu);

    for (i = 0; i < 8; ++i) {
        value_le[i] = (uint8_t)((value >> (i * 8u)) & 0xffu);
    }

    parts[0] = DOMAIN_COMMIT_V3; lengths[0] = sizeof(DOMAIN_COMMIT_V3) - 1u;
    parts[1] = &VERSION_V3; lengths[1] = sizeof(VERSION_V3);
    parts[2] = params_len_le; lengths[2] = sizeof(params_len_le);
    parts[3] = params_id; lengths[3] = params_id_len;
    parts[4] = bundle_len_le; lengths[4] = sizeof(bundle_len_le);
    parts[5] = pk_bundle; lengths[5] = pk_bundle_len;
    parts[6] = value_le; lengths[6] = sizeof(value_le);
    parts[7] = LEN_48_LE; lengths[7] = sizeof(LEN_48_LE);
    parts[8] = namespace_id; lengths[8] = namespace_id_len;
    parts[9] = LEN_32_LE; lengths[9] = sizeof(LEN_32_LE);
    parts[10] = coin_id; lengths[10] = coin_id_len;
    parts[11] = LEN_36_LE; lengths[11] = sizeof(LEN_36_LE);
    parts[12] = r_nf; lengths[12] = r_nf_len;
    parts[13] = LEN_36_LE; lengths[13] = sizeof(LEN_36_LE);
    parts[14] = rho_coin; lengths[14] = rho_coin_len;

    return psp_shake256_parts(parts, lengths, 15u, out, out_len);
}
