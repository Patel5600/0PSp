#include "../include/psp_keccak.h"
#include <stdio.h>
#include <string.h>

static int hex_compare(const uint8_t *data, size_t len, const char *expected_hex) {
    char buf[3];
    for (size_t i = 0; i < len; ++i) {
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        if (buf[0] != expected_hex[i * 2] || buf[1] != expected_hex[i * 2 + 1]) {
            return -1;
        }
    }
    return 0;
}

int main(void) {
    uint8_t out[64];
    int failures = 0;

    printf("Running Keccak/SHAKE256/SHA3-384 Known Answer Tests...\n");

    /* Test 1: SHA3-384 of empty string */
    psp_sha3_384((const uint8_t *)"", 0, out);
    if (hex_compare(out, 48, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004") != 0) {
        printf("FAILED: SHA3-384 empty string\n");
        failures++;
    } else {
        printf("PASS: SHA3-384 empty string\n");
    }

    /* Test 2: SHAKE256 of empty string (48 bytes) */
    psp_shake256((const uint8_t *)"", 0, out, 48);
    if (hex_compare(out, 48, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6") != 0) {
        printf("FAILED: SHAKE256-384 empty string\n");
        failures++;
    } else {
        printf("PASS: SHAKE256-384 empty string\n");
    }

    /* Test 3: SHAKE256 of 'abc' (48 bytes) */
    psp_shake256((const uint8_t *)"abc", 3, out, 48);
    if (hex_compare(out, 48, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa") != 0) {
        printf("FAILED: SHAKE256-384 'abc'\n");
        failures++;
    } else {
        printf("PASS: SHAKE256-384 'abc'\n");
    }

    /* Test 4: Keccak-256 of empty string */
    psp_keccak256((const uint8_t *)"", 0, out);
    if (hex_compare(out, 32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") != 0) {
        printf("FAILED: Keccak-256 empty string\n");
        failures++;
    } else {
        printf("PASS: Keccak-256 empty string\n");
    }

    /* Test 5: HMAC-SHA3-384 of message with key */
    uint8_t hmac_out[48];
    const uint8_t key[4] = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t msg[5] = "hello";
    psp_hmac_sha3_384(key, 4, msg, 5, hmac_out);
    printf("HMAC-SHA3-384 ('hello', key=01020304): %02x%02x%02x%02x...\n",
           hmac_out[0], hmac_out[1], hmac_out[2], hmac_out[3]);

    if (failures == 0) {
        printf("ALL KECCAK/SHAKE/SHA3 TESTS PASSED PERFECTLY!\n");
        return 0;
    }
    return 1;
}
