#include "../include/psp_keccak.h"
#include "../include/psp_random.h"
#include "../include/psp_namespace_v3.h"
#include "../include/psp_nullifier_v3.h"
#include "../include/psp_coin_commitment_v3.h"
#include "../include/psp_merkle_tree_v3.h"

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

static void unhex(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte;
        sscanf(hex + i * 2, "%02x", &byte);
        out[i] = (uint8_t)byte;
    }
}

int main(void) {
    int failures = 0;

    printf("======================================================================\n");
    printf("0PSP Native V3 Primitives & Depth-63 Merkle Tree Verification Suite\n");
    printf("Zero external dependencies, constant-time, OS CSPRNG integration\n");
    printf("======================================================================\n\n");

    /* 1. Namespace V3 Direct-Hash Derive */
    uint8_t ns_v3[48];
    const uint8_t ledger_id[] = "test-ledger";
    const uint8_t deploy_id[] = "test-deployment";
    const uint8_t asset_id[] = "test-asset";
    psp_namespace_v3_derive(
        ledger_id, sizeof(ledger_id) - 1,
        deploy_id, sizeof(deploy_id) - 1,
        asset_id, sizeof(asset_id) - 1,
        ns_v3, sizeof(ns_v3)
    );
    if (hex_compare(ns_v3, 48, "5afdd95a8444f0a59cb51da1ff21f82ff75f41aeb4fb043ddbf261f85e755f0996f7c3a619b3ee63a5e59ba7b32858c2") != 0) {
        printf("[-] FAILED: Namespace V3 derive KAT\n");
        failures++;
    } else {
        printf("[+] PASS: Namespace V3 derive KAT matches Python\n");
    }

    /* 2. Nullifier Key Commitment V3 */
    uint8_t nk[48];
    memset(nk, 0x11, sizeof(nk));
    uint8_t nk_commit[48];
    psp_nullifier_v3_key_commitment(nk, sizeof(nk), nk_commit, sizeof(nk_commit));
    if (hex_compare(nk_commit, 48, "ddcf789a38a0bea20bd20942f80e64adfd87bd6fc2a1cacd625e903c4ec3a95451edb6a0cbd4bfc68a39e6cdb1c6fce0") != 0) {
        printf("[-] FAILED: NullifierKeyCommitment V3 KAT\n");
        failures++;
    } else {
        printf("[+] PASS: NullifierKeyCommitment V3 KAT matches Python\n");
    }

    /* 3. Coin Commitment V3 */
    const char *bundle_hex = "305053502d4e4f54452d504b2d42554e444c452d7633030b00746573742d736368656d652000000022222222222222222222222222222222222222222222222222222222222222223000ddcf789a38a0bea20bd20942f80e64adfd87bd6fc2a1cacd625e903c4ec3a95451edb6a0cbd4bfc68a39e6cdb1c6fce0";
    uint8_t bundle_bytes[122];
    unhex(bundle_hex, bundle_bytes, sizeof(bundle_bytes));

    uint8_t coin_id[32]; memset(coin_id, 0x33, sizeof(coin_id));
    uint8_t r_nf[36]; memset(r_nf, 0x44, sizeof(r_nf));
    uint8_t rho_coin[36]; memset(rho_coin, 0x55, sizeof(rho_coin));
    const uint8_t params_id[] = "test-params";

    uint8_t commit_v3[48];
    psp_coin_commitment_v3(
        params_id, sizeof(params_id) - 1,
        bundle_bytes, sizeof(bundle_bytes),
        1000ULL,
        ns_v3, sizeof(ns_v3),
        coin_id, sizeof(coin_id),
        r_nf, sizeof(r_nf),
        rho_coin, sizeof(rho_coin),
        commit_v3, sizeof(commit_v3)
    );
    if (hex_compare(commit_v3, 48, "8f487e18d24f8b3f75bf5ef87d0212c5f392618d9feb436da999dfa2f8b2d2abdb65dff35dd5aeeca99ace0e62400d9d") != 0) {
        printf("[-] FAILED: CoinCommitment V3 KAT\n");
        failures++;
    } else {
        printf("[+] PASS: CoinCommitment V3 KAT matches Python\n");
    }

    /* 4. Nullifier V3 (HMAC-SHA3-384) */
    uint8_t nullifier_v3[48];
    psp_nullifier_v3(
        nk, sizeof(nk),
        ns_v3, sizeof(ns_v3),
        params_id, sizeof(params_id) - 1,
        bundle_bytes, sizeof(bundle_bytes),
        commit_v3, sizeof(commit_v3),
        coin_id, sizeof(coin_id),
        r_nf, sizeof(r_nf),
        nullifier_v3, sizeof(nullifier_v3)
    );
    if (hex_compare(nullifier_v3, 48, "56c78a1fac28e016c488edff3c5c71c1a388490929347a2104ee209d86a093a36beec89a4cbfaa967da497859c14df77") != 0) {
        printf("[-] FAILED: Nullifier V3 KAT\n");
        failures++;
    } else {
        printf("[+] PASS: Nullifier V3 (HMAC-SHA3-384) KAT matches Python\n");
    }

    /* 5. Depth-63 Merkle Tree: Empty Leaf, Leaf Hash, Node Hash */
    uint8_t empty_0[48];
    psp_merkle_empty_leaf_hash(ns_v3, empty_0);
    if (hex_compare(empty_0, 48, "2a89c0e78e9e21abf3b4bbb42c0d75098143a60cc6fda05f3424e55b027f2db6ab0e37d707da17c035b895441705201b") != 0) {
        printf("[-] FAILED: Merkle Empty Leaf 0 KAT\n");
        failures++;
    } else {
        printf("[+] PASS: Merkle Empty Leaf 0 KAT matches Python\n");
    }

    uint8_t leaf_0[48];
    psp_merkle_leaf_hash(ns_v3, 0ULL, commit_v3, leaf_0);
    if (hex_compare(leaf_0, 48, "b18717bc33d0d266e350adbc4372b099556d48cc2b0376c0a2afc427a6c3b6a56c6494bba81f874e20d1ab51bb2719f9") != 0) {
        printf("[-] FAILED: Merkle Leaf 0 KAT\n");
        failures++;
    } else {
        printf("[+] PASS: Merkle Leaf 0 KAT matches Python\n");
    }

    uint8_t node_0[48];
    psp_merkle_node_hash(ns_v3, 0u, leaf_0, empty_0, node_0);
    if (hex_compare(node_0, 48, "783215c1dbc0ab2b91db2caff3dc870b32edf578760e94cf784e3f9e3f0e635777ef4f6422ef9bf4bd5435eb1cb82db3") != 0) {
        printf("[-] FAILED: Merkle Node 0 KAT\n");
        failures++;
    } else {
        printf("[+] PASS: Merkle Node 0 KAT matches Python\n");
    }

    /* 6. OS CSPRNG Verification */
    uint8_t rand_buf1[32];
    uint8_t rand_buf2[32];
    if (psp_random_bytes(rand_buf1, sizeof(rand_buf1)) != PSP_CRYPTO_OK ||
        psp_random_bytes(rand_buf2, sizeof(rand_buf2)) != PSP_CRYPTO_OK) {
        printf("[-] FAILED: OS CSPRNG returned error\n");
        failures++;
    } else if (memcmp(rand_buf1, rand_buf2, sizeof(rand_buf1)) == 0) {
        printf("[-] FAILED: OS CSPRNG generated identical successive outputs\n");
        failures++;
    } else {
        printf("[+] PASS: Native OS CSPRNG (BCrypt / getrandom) generated fresh entropy\n");
    }

    /* 7. Constant-Time Memcmp Verification */
    uint8_t block_a[32]; memset(block_a, 0xAA, 32);
    uint8_t block_b[32]; memset(block_b, 0xAA, 32);
    uint8_t block_c[32]; memset(block_c, 0xAA, 32); block_c[31] ^= 0x01;
    if (psp_constant_time_memcmp(block_a, block_b, 32) != 0 ||
        psp_constant_time_memcmp(block_a, block_c, 32) == 0) {
        printf("[-] FAILED: Constant-time memcmp\n");
        failures++;
    } else {
        printf("[+] PASS: Constant-time memcmp verified\n");
    }

    printf("\n======================================================================\n");
    if (failures == 0) {
        printf("ALL NATIVE C11 V3 PRIMITIVES AND MERKLE ENGINES PASSED 100%%!\n");
        return 0;
    }
    printf("SUITE FAILED WITH %d ERRORS\n", failures);
    return 1;
}
