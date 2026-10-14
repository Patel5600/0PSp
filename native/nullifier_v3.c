#include "psp_nullifier_v3.h"
#include <string.h>

static const uint8_t DOMAIN_KEY_COMMIT_V3[] = "0PSP-NULLIFIER-KEY-COMMIT-v3-SHAKE256";
static const uint8_t DOMAIN_NULLIFIER_V3[] = "0PSP-NULLIFIER-v3-HMAC-SHA3-384";
static const uint8_t VERSION_V3 = PSP_NULLIFIER_V3_VERSION;

static const uint8_t LEN_48_LE[2] = { 48u, 0u };
static const uint8_t LEN_32_LE[2] = { 32u, 0u };
static const uint8_t LEN_36_LE[2] = { 36u, 0u };

int psp_nullifier_v3_generate_key(uint8_t *out, size_t out_len) {
    if (out == NULL || out_len != PSP_NULLIFIER_V3_KEY_BYTES) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    return psp_random_bytes(out, out_len);
}

int psp_nullifier_v3_key_commitment(
    const uint8_t *nk, size_t nk_len,
    uint8_t *out, size_t out_len) {
    const uint8_t *parts[4];
    const size_t lengths[4] = {
        sizeof(DOMAIN_KEY_COMMIT_V3) - 1u,
        sizeof(VERSION_V3),
        sizeof(LEN_48_LE),
        PSP_NULLIFIER_V3_KEY_BYTES
    };

    if (nk == NULL || nk_len != PSP_NULLIFIER_V3_KEY_BYTES ||
        out == NULL || out_len != PSP_NULLIFIER_V3_KEY_COMMITMENT_BYTES) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    parts[0] = DOMAIN_KEY_COMMIT_V3;
    parts[1] = &VERSION_V3;
    parts[2] = LEN_48_LE;
    parts[3] = nk;

    return psp_shake256_parts(parts, lengths, 4u, out, out_len);
}

int psp_nullifier_v3(
    const uint8_t *nk, size_t nk_len,
    const uint8_t *namespace_id, size_t namespace_id_len,
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *public_key_bundle, size_t public_key_bundle_len,
    const uint8_t *commitment, size_t commitment_len,
    const uint8_t *coin_id, size_t coin_id_len,
    const uint8_t *r_nf, size_t r_nf_len,
    uint8_t *out, size_t out_len) {
    const uint8_t *parts[14];
    size_t lengths[14];
    uint8_t params_len_le[2];
    uint8_t bundle_len_le[4];

    if (nk == NULL || nk_len != PSP_NULLIFIER_V3_KEY_BYTES ||
        namespace_id == NULL || namespace_id_len != PSP_NULLIFIER_V3_NAMESPACE_BYTES ||
        params_id == NULL || params_id_len > 65535u ||
        public_key_bundle == NULL || public_key_bundle_len > 4294967295ULL ||
        commitment == NULL || commitment_len != PSP_NULLIFIER_V3_COMMITMENT_BYTES ||
        coin_id == NULL || coin_id_len != PSP_NULLIFIER_V3_COIN_ID_BYTES ||
        r_nf == NULL || r_nf_len != PSP_NULLIFIER_V3_RNF_BYTES ||
        out == NULL || out_len != PSP_NULLIFIER_V3_OUTPUT_BYTES) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    params_len_le[0] = (uint8_t)(params_id_len & 0xffu);
    params_len_le[1] = (uint8_t)((params_id_len >> 8u) & 0xffu);

    bundle_len_le[0] = (uint8_t)(public_key_bundle_len & 0xffu);
    bundle_len_le[1] = (uint8_t)((public_key_bundle_len >> 8u) & 0xffu);
    bundle_len_le[2] = (uint8_t)((public_key_bundle_len >> 16u) & 0xffu);
    bundle_len_le[3] = (uint8_t)((public_key_bundle_len >> 24u) & 0xffu);

    parts[0] = DOMAIN_NULLIFIER_V3; lengths[0] = sizeof(DOMAIN_NULLIFIER_V3) - 1u;
    parts[1] = &VERSION_V3; lengths[1] = sizeof(VERSION_V3);
    parts[2] = params_len_le; lengths[2] = sizeof(params_len_le);
    parts[3] = params_id; lengths[3] = params_id_len;
    parts[4] = LEN_48_LE; lengths[4] = sizeof(LEN_48_LE);
    parts[5] = namespace_id; lengths[5] = namespace_id_len;
    parts[6] = bundle_len_le; lengths[6] = sizeof(bundle_len_le);
    parts[7] = public_key_bundle; lengths[7] = public_key_bundle_len;
    parts[8] = LEN_48_LE; lengths[8] = sizeof(LEN_48_LE);
    parts[9] = commitment; lengths[9] = commitment_len;
    parts[10] = LEN_32_LE; lengths[10] = sizeof(LEN_32_LE);
    parts[11] = coin_id; lengths[11] = coin_id_len;
    parts[12] = LEN_36_LE; lengths[12] = sizeof(LEN_36_LE);
    parts[13] = r_nf; lengths[13] = r_nf_len;

    return psp_hmac_sha3_384_parts(nk, nk_len, parts, lengths, 14u, out);
}
