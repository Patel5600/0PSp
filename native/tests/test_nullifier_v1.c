#include "psp_nullifier_v1.h"

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
    uint8_t parsed[PSP_NULLIFIER_V1_OUTPUT_BYTES];
    return n == sizeof(parsed) && from_hex(expected, parsed, sizeof(parsed)) &&
           memcmp(buf, parsed, sizeof(parsed)) == 0;
}

static int compute(const uint8_t *coin, const uint8_t *secret, uint8_t *out) {
    return psp_nullifier_v1(coin, PSP_NULLIFIER_V1_COIN_ID_BYTES,
                            secret, PSP_NULLIFIER_V1_SECRET_BYTES,
                            out, PSP_NULLIFIER_V1_OUTPUT_BYTES) == PSP_NULLIFIER_OK;
}

int main(void) {
    uint8_t coin[PSP_NULLIFIER_V1_COIN_ID_BYTES];
    uint8_t secret[PSP_NULLIFIER_V1_SECRET_BYTES];
    uint8_t out[PSP_NULLIFIER_V1_OUTPUT_BYTES];
    uint8_t out2[PSP_NULLIFIER_V1_OUTPUT_BYTES];
    uint8_t secret_a[PSP_NULLIFIER_V1_SECRET_BYTES];
    uint8_t secret_b[PSP_NULLIFIER_V1_SECRET_BYTES];
    size_t i;
    static const char vector_a[] =
        "e672f7462704e6b2140be549ff12b9db66f6f53f0ae6826e"
        "612a3b1cf1b0d8a6bdef7c74ad25ba4227a620d4d1d19b42";
    static const char vector_zero[] =
        "a68519942737e0ea666ce446643a77f2033093069ce1e18f"
        "202dfcd8c13839b6e0565abaad751114382ca2d6a2e65663";

    for (i = 0; i < sizeof(coin); ++i) coin[i] = (uint8_t)i;
    for (i = 0; i < sizeof(secret); ++i) secret[i] = (uint8_t)i;
    if (!compute(coin, secret, out) || !equals_hex(out, sizeof(out), vector_a)) {
        fputs("FAIL: deterministic known-answer vector\n", stderr);
        return 1;
    }

    memset(coin, 0, sizeof(coin));
    memset(secret, 0, sizeof(secret));
    if (!compute(coin, secret, out) || !equals_hex(out, sizeof(out), vector_zero)) {
        fputs("FAIL: all-zero known-answer vector\n", stderr);
        return 1;
    }

    coin[0] = 1u;
    if (!compute(coin, secret, out2) || memcmp(out, out2, sizeof(out)) == 0) {
        fputs("FAIL: coin-ID binding vector\n", stderr);
        return 1;
    }
    coin[0] = 0u;
    secret[0] = 1u;
    if (!compute(coin, secret, out2) || memcmp(out, out2, sizeof(out)) == 0) {
        fputs("FAIL: secret binding vector\n", stderr);
        return 1;
    }

    memset(out, 0xA5, sizeof(out));
    if (psp_nullifier_v1(coin, 31u, secret, sizeof(secret), out, sizeof(out)) !=
        PSP_NULLIFIER_ERR_ARGUMENT) {
        fputs("FAIL: invalid coin-ID length accepted\n", stderr);
        return 1;
    }
    for (i = 0; i < sizeof(out); ++i) {
        if (out[i] != 0u) {
            fputs("FAIL: output not cleared on invalid input\n", stderr);
            return 1;
        }
    }
    if (psp_nullifier_v1(coin, sizeof(coin), secret, 35u, out, sizeof(out)) !=
        PSP_NULLIFIER_ERR_ARGUMENT) {
        fputs("FAIL: invalid secret length accepted\n", stderr);
        return 1;
    }
    if (psp_nullifier_v1(coin, sizeof(coin), secret, sizeof(secret), out, 47u) !=
        PSP_NULLIFIER_ERR_ARGUMENT) {
        fputs("FAIL: invalid output length accepted\n", stderr);
        return 1;
    }

    if (psp_nullifier_v1_generate_secret(secret_a, sizeof(secret_a)) != PSP_NULLIFIER_OK ||
        psp_nullifier_v1_generate_secret(secret_b, sizeof(secret_b)) != PSP_NULLIFIER_OK) {
        fputs("FAIL: secret generation failed\n", stderr);
        return 1;
    }
    if (memcmp(secret_a, secret_b, sizeof(secret_a)) == 0) {
        fputs("FAIL: identical consecutive random secret samples\n", stderr);
        OPENSSL_cleanse(secret_a, sizeof(secret_a));
        OPENSSL_cleanse(secret_b, sizeof(secret_b));
        return 1;
    }
    OPENSSL_cleanse(secret_a, sizeof(secret_a));
    OPENSSL_cleanse(secret_b, sizeof(secret_b));

    puts("PASS: native nullifier-v1 vectors, canonical lengths and RNG smoke check");
    puts("SECURITY LIMIT: functional tests are not a constant-time proof or crypto audit");
    return 0;
}
