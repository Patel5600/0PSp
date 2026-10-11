#include "psp_nullifier_v2.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

static int from_hex(const char *hex, uint8_t *out, size_t out_len) {
    size_t i;
    if (strlen(hex) != out_len * 2u) return 0;
    for (i = 0; i < out_len; ++i) {
        unsigned int value;
        if (sscanf(hex + 2u * i, "%2x", &value) != 1) return 0;
        out[i] = (uint8_t)value;
    }
    return 1;
}

static int equals_hex(const uint8_t *buf, size_t n, const char *expected) {
    uint8_t parsed[PSP_NULLIFIER_V2_OUTPUT_BYTES];
    return n == sizeof(parsed) && from_hex(expected, parsed, sizeof(parsed)) &&
           memcmp(buf, parsed, sizeof(parsed)) == 0;
}

static int all_zero(const uint8_t *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) if (buf[i] != 0u) return 0;
    return 1;
}

int main(void) {
    uint8_t ledger[PSP_NAMESPACE_COMPONENT_V2_BYTES];
    uint8_t deployment[PSP_NAMESPACE_COMPONENT_V2_BYTES];
    uint8_t asset[PSP_NAMESPACE_COMPONENT_V2_BYTES];
    uint8_t namespace_id[PSP_NAMESPACE_V2_BYTES];
    uint8_t namespace_id_2[PSP_NAMESPACE_V2_BYTES];
    uint8_t coin_id[PSP_SCOPED_COIN_ID_V2_BYTES];
    uint8_t generated_id_a[PSP_SCOPED_COIN_ID_V2_BYTES];
    uint8_t generated_id_b[PSP_SCOPED_COIN_ID_V2_BYTES];
    uint8_t secret[PSP_NULLIFIER_V2_SECRET_BYTES];
    uint8_t out[PSP_NULLIFIER_V2_OUTPUT_BYTES];
    uint8_t out_2[PSP_NULLIFIER_V2_OUTPUT_BYTES];
    size_t i;
    static const char namespace_vector[] =
        "04c0037350b1b2551c5b7f8b19642abd"
        "e118113083130340a0986aacfaad3d7"
        "d38c96dac07c80e9c3d45e0a1111279d2";
    static const char nullifier_vector[] =
        "059698470b8228712d86c630144b9aae"
        "0d0815ba1f2038b53c9d22d484af5d46"
        "60100eb47c8fea686ebb4855cd35159d";

    for (i = 0u; i < sizeof(ledger); ++i) {
        ledger[i] = (uint8_t)i;
        deployment[i] = (uint8_t)(i + 32u);
        asset[i] = (uint8_t)(i + 64u);
        coin_id[i] = (uint8_t)i;
    }
    for (i = 0u; i < sizeof(secret); ++i) secret[i] = (uint8_t)i;

    if (psp_namespace_v2_derive(
            ledger, sizeof(ledger), deployment, sizeof(deployment),
            asset, sizeof(asset), namespace_id, sizeof(namespace_id)) != PSP_NULLIFIER_OK ||
        !equals_hex(namespace_id, sizeof(namespace_id), namespace_vector)) {
        fputs("FAIL: namespace-v2 known-answer vector\n", stderr);
        return 1;
    }

    if (psp_nullifier_v2(
            namespace_id, sizeof(namespace_id), coin_id, sizeof(coin_id),
            secret, sizeof(secret), out, sizeof(out)) != PSP_NULLIFIER_OK ||
        !equals_hex(out, sizeof(out), nullifier_vector)) {
        fputs("FAIL: nullifier-v2 known-answer vector\n", stderr);
        return 1;
    }

    asset[0] ^= 1u;
    if (psp_namespace_v2_derive(
            ledger, sizeof(ledger), deployment, sizeof(deployment),
            asset, sizeof(asset), namespace_id_2, sizeof(namespace_id_2)) != PSP_NULLIFIER_OK ||
        memcmp(namespace_id, namespace_id_2, sizeof(namespace_id)) == 0) {
        fputs("FAIL: asset namespace separation\n", stderr);
        return 1;
    }
    if (psp_nullifier_v2(
            namespace_id_2, sizeof(namespace_id_2), coin_id, sizeof(coin_id),
            secret, sizeof(secret), out_2, sizeof(out_2)) != PSP_NULLIFIER_OK ||
        memcmp(out, out_2, sizeof(out)) == 0) {
        fputs("FAIL: nullifier changes across namespaces\n", stderr);
        return 1;
    }

    if (psp_coin_id_v2_generate(generated_id_a, sizeof(generated_id_a)) != PSP_NULLIFIER_OK ||
        psp_coin_id_v2_generate(generated_id_b, sizeof(generated_id_b)) != PSP_NULLIFIER_OK ||
        memcmp(generated_id_a, generated_id_b, sizeof(generated_id_a)) == 0) {
        fputs("FAIL: coin-ID RNG smoke check\n", stderr);
        OPENSSL_cleanse(generated_id_a, sizeof(generated_id_a));
        OPENSSL_cleanse(generated_id_b, sizeof(generated_id_b));
        return 1;
    }

    memset(out, 0xA5, sizeof(out));
    if (psp_nullifier_v2(
            namespace_id, PSP_NAMESPACE_V2_BYTES - 1u, coin_id, sizeof(coin_id),
            secret, sizeof(secret), out, sizeof(out)) != PSP_NULLIFIER_ERR_ARGUMENT ||
        !all_zero(out, sizeof(out))) {
        fputs("FAIL: invalid namespace length / output clearing\n", stderr);
        return 1;
    }

    memset(namespace_id_2, 0xA5, sizeof(namespace_id_2));
    if (psp_namespace_v2_derive(
            ledger, sizeof(ledger) - 1u, deployment, sizeof(deployment),
            asset, sizeof(asset), namespace_id_2, sizeof(namespace_id_2)) !=
            PSP_NULLIFIER_ERR_ARGUMENT ||
        !all_zero(namespace_id_2, sizeof(namespace_id_2))) {
        fputs("FAIL: invalid namespace source length / output clearing\n", stderr);
        return 1;
    }

    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(generated_id_a, sizeof(generated_id_a));
    OPENSSL_cleanse(generated_id_b, sizeof(generated_id_b));
    puts("PASS: namespace-v2/nullifier-v2 vectors, domain separation, and RNG smoke checks");
    puts("LIMIT: duplicate mint prevention must be atomic in ledger state; tests do not prove security");
    return 0;
}
