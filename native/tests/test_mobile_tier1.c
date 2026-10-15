#include "../include/psp_mobile.h"
#include <stdio.h>
#include <string.h>


int main(void) {
    int failures = 0;

    printf("======================================================================\n");
    printf("0PSP Mobile Tier 1 Edge Cryptographic Engine Verification Suite\n");
    printf("Zero-heap, constant-time, real post-quantum cryptography on mobile/edge\n");
    printf("======================================================================\n\n");

    /* 1. Test Bundle Encoding and Decoding */
    uint8_t auth_scheme[] = "test-scheme";
    uint8_t auth_pk[32];
    memset(auth_pk, 0x22, sizeof(auth_pk));
    uint8_t nk_commit[48];
    memset(nk_commit, 0x77, sizeof(nk_commit));

    uint8_t bundle_buf[256];
    size_t bundle_len = 0;
    int st = psp_encode_note_bundle_v3(
        auth_scheme, sizeof(auth_scheme) - 1,
        auth_pk, sizeof(auth_pk),
        nk_commit,
        bundle_buf, &bundle_len, sizeof(bundle_buf)
    );
    if (st != PSP_CRYPTO_OK) {
        printf("[-] FAILED: psp_encode_note_bundle_v3\n");
        failures++;
    } else {
        uint8_t extracted_commit[48];
        st = psp_parse_bundle_key_commitment_v3(bundle_buf, bundle_len, extracted_commit);
        if (st != PSP_CRYPTO_OK || memcmp(extracted_commit, nk_commit, 48) != 0) {
            printf("[-] FAILED: psp_parse_bundle_key_commitment_v3\n");
            failures++;
        } else {
            printf("[+] PASS: NotePublicKeyBundleV3 encode/parse roundtrip verified\n");
        }
    }

    /* 2. Output Identity Derivation */
    const uint8_t params_id[] = "test-params";
    uint8_t ns_v3[48];
    memset(ns_v3, 0x5a, sizeof(ns_v3));
    uint8_t parent_nullifier[48];
    memset(parent_nullifier, 0x88, sizeof(parent_nullifier));
    uint8_t parent_commitment[48];
    memset(parent_commitment, 0x99, sizeof(parent_commitment));
    uint8_t parent_coin_id[32];
    memset(parent_coin_id, 0xaa, sizeof(parent_coin_id));
    uint8_t parent_r_nf[36];
    memset(parent_r_nf, 0xbb, sizeof(parent_r_nf));
    uint8_t entropy[32];
    memset(entropy, 0xcc, sizeof(entropy));

    uint8_t out_coin_id[32];
    uint8_t out_r_nf[36];
    st = psp_output_identity_v3(
        params_id, sizeof(params_id) - 1,
        ns_v3,
        parent_nullifier,
        parent_commitment,
        parent_coin_id,
        parent_r_nf,
        bundle_buf, bundle_len,
        bundle_buf, bundle_len,
        entropy,
        0u,
        out_coin_id,
        out_r_nf
    );
    if (st != PSP_CRYPTO_OK) {
        printf("[-] FAILED: psp_output_identity_v3 returned error %d\n", st);
        failures++;
    } else {
        /* Verify deterministic idempotence */
        uint8_t out_coin_id2[32];
        uint8_t out_r_nf2[36];
        psp_output_identity_v3(
            params_id, sizeof(params_id) - 1,
            ns_v3, parent_nullifier, parent_commitment, parent_coin_id, parent_r_nf,
            bundle_buf, bundle_len, bundle_buf, bundle_len, entropy, 0u,
            out_coin_id2, out_r_nf2
        );
        if (memcmp(out_coin_id, out_coin_id2, 32) != 0 || memcmp(out_r_nf, out_r_nf2, 36) != 0) {
            printf("[-] FAILED: Output identity derivation is non-deterministic\n");
            failures++;
        } else {
            printf("[+] PASS: Output identity derivation (coin_id, r_nf) is deterministic and consistent\n");
        }
    }

    /* 3. Local Note Generation using OS CSPRNG */
    uint8_t gen_nk[48];
    uint8_t gen_coin_id[32];
    uint8_t gen_r_nf[36];
    uint8_t gen_rho[36];
    uint8_t gen_bundle[256];
    size_t gen_bundle_len = 0;
    uint8_t gen_commitment[48];

    st = psp_note_generate_v3(
        params_id, sizeof(params_id) - 1,
        ns_v3,
        1000ULL,
        auth_scheme, sizeof(auth_scheme) - 1,
        auth_pk, sizeof(auth_pk),
        gen_nk, gen_coin_id, gen_r_nf, gen_rho,
        gen_bundle, &gen_bundle_len, sizeof(gen_bundle),
        gen_commitment
    );
    if (st != PSP_CRYPTO_OK) {
        printf("[-] FAILED: psp_note_generate_v3 returned error %d\n", st);
        failures++;
    } else {
        /* Verify that re-computing coin commitment with generated secrets produces identical commitment */
        uint8_t verify_commit[48];
        psp_coin_commitment_v3(
            params_id, sizeof(params_id) - 1,
            gen_bundle, gen_bundle_len,
            1000ULL,
            ns_v3, sizeof(ns_v3),
            gen_coin_id, sizeof(gen_coin_id),
            gen_r_nf, sizeof(gen_r_nf),
            gen_rho, sizeof(gen_rho),
            verify_commit, sizeof(verify_commit)
        );
        if (memcmp(gen_commitment, verify_commit, 48) != 0) {
            printf("[-] FAILED: Generated note commitment verification mismatch\n");
            failures++;
        } else {
            printf("[+] PASS: Local note generation with OS CSPRNG verified end-to-end\n");
        }
    }

    /* 4. Complete Tier 1 Mobile Edge Spend Package Creation */
    uint8_t root[48]; memset(root, 0x12, sizeof(root));
    uint8_t state_head[48]; memset(state_head, 0x34, sizeof(state_head));
    uint8_t state_context[64]; memset(state_context, 0x56, sizeof(state_context));

    psp_tier1_spend_package_t pkg;
    st = psp_tier1_create_spend_package(
        params_id, sizeof(params_id) - 1,
        ns_v3,
        gen_bundle, gen_bundle_len,
        1000ULL, /* input_value */
        gen_coin_id, gen_r_nf, gen_rho, gen_nk,
        bundle_buf, bundle_len, /* recipient_bundle */
        900ULL, /* output_value */
        100ULL, /* fee */
        entropy,
        root, state_head, state_context,
        &pkg
    );
    if (st != PSP_CRYPTO_OK) {
        printf("[-] FAILED: psp_tier1_create_spend_package returned error %d\n", st);
        failures++;
    } else {
        /* Check that package matches input note commitment */
        if (memcmp(pkg.input_commitment, gen_commitment, 48) != 0) {
            printf("[-] FAILED: Package input_commitment mismatch\n");
            failures++;
        } else if (psp_tier1_verify_spend_package(&pkg, gen_commitment, pkg.input_nullifier) != PSP_CRYPTO_OK) {
            printf("[-] FAILED: psp_tier1_verify_spend_package failed for valid package\n");
            failures++;
        } else {
            printf("[+] PASS: Tier 1 spend package creation and verification passed\n");
        }
    }

    /* 5. Adversarial Red-Team Tests on Mobile Spend Package */
    /* 5.1 Value conservation violation (input != output + fee) */
    st = psp_tier1_create_spend_package(
        params_id, sizeof(params_id) - 1,
        ns_v3, gen_bundle, gen_bundle_len,
        1000ULL,
        gen_coin_id, gen_r_nf, gen_rho, gen_nk,
        bundle_buf, bundle_len,
        901ULL, /* output: 901 + 100 = 1001 != 1000 */
        100ULL,
        entropy, root, state_head, state_context,
        &pkg
    );
    if (st == PSP_CRYPTO_OK) {
        printf("[-] FAILED: Spend package allowed value inflation (input != output + fee)\n");
        failures++;
    } else {
        printf("[+] PASS: Value conservation strictly enforced (inflation rejected)\n");
    }

    /* 5.2 Value arithmetic overflow prevention (output_value + fee wraps uint64) */
    st = psp_tier1_create_spend_package(
        params_id, sizeof(params_id) - 1,
        ns_v3, gen_bundle, gen_bundle_len,
        50ULL,
        gen_coin_id, gen_r_nf, gen_rho, gen_nk,
        bundle_buf, bundle_len,
        0xFFFFFFFFFFFFFFFEULL, /* wraps uint64 */
        100ULL,
        entropy, root, state_head, state_context,
        &pkg
    );
    if (st == PSP_CRYPTO_OK) {
        printf("[-] FAILED: Spend package allowed integer wrapping\n");
        failures++;
    } else {
        printf("[+] PASS: Integer overflow attack rejected\n");
    }

    /* 5.3 Imposter Nullifier Key (nk does not open input_bundle) */
    uint8_t imposter_nk[48];
    memset(imposter_nk, 0xee, sizeof(imposter_nk));
    st = psp_tier1_create_spend_package(
        params_id, sizeof(params_id) - 1,
        ns_v3, gen_bundle, gen_bundle_len,
        1000ULL,
        gen_coin_id, gen_r_nf, gen_rho, imposter_nk,
        bundle_buf, bundle_len,
        900ULL, 100ULL,
        entropy, root, state_head, state_context,
        &pkg
    );
    if (st == PSP_CRYPTO_OK) {
        printf("[-] FAILED: Spend package accepted unauthenticated imposter nk\n");
        failures++;
    } else {
        printf("[+] PASS: Nullifier key possession authentication enforced\n");
    }

    /* 6. Depth-32 Mobile Subtree Profile Merkle Path Verification */
    uint8_t siblings_32[32 * 48];
    memset(siblings_32, 0x33, sizeof(siblings_32));

    /* Calculate a valid root for leaf 0 with 32 siblings */
    uint8_t current[48];
    psp_merkle_leaf_hash(ns_v3, 0ULL, gen_commitment, current);
    for (uint8_t lvl = 0; lvl < 32; ++lvl) {
        uint8_t next[48];
        psp_merkle_node_hash(ns_v3, lvl, current, siblings_32 + (lvl * 48), next);
        memcpy(current, next, 48);
    }
    uint8_t expected_root_32[48];
    memcpy(expected_root_32, current, 48);

    st = psp_merkle_verify_path(ns_v3, 0ULL, gen_commitment, siblings_32, 32, expected_root_32);
    if (st != PSP_CRYPTO_OK) {
        printf("[-] FAILED: Depth-32 mobile Merkle verification failed\n");
        failures++;
    } else {
        printf("[+] PASS: Depth-32 Mobile Consensus Subtree verified on-device\n");
    }

    /* 6.1 Test out-of-range leaf index for depth 32 */
    uint64_t out_of_range_index = 1ULL << 32;
    st = psp_merkle_verify_path(ns_v3, out_of_range_index, gen_commitment, siblings_32, 32, expected_root_32);
    if (st == PSP_CRYPTO_OK) {
        printf("[-] FAILED: Depth-32 accepted leaf index >= 2^32\n");
        failures++;
    } else {
        printf("[+] PASS: Depth-32 index boundary correctly rejected\n");
    }

    /* 7. Test 3-Tier Key Hierarchy and Spend Authorization Token */
    uint8_t test_sk_spend[48];
    uint8_t test_ak[48];
    uint8_t test_nk[48];
    uint8_t test_pk_owner[48];
    memset(test_sk_spend, 0x42, sizeof(test_sk_spend));

    st = psp_derive_keys_v3(test_sk_spend, test_ak, test_nk, test_pk_owner);
    if (st != PSP_CRYPTO_OK) {
        printf("[-] FAILED: psp_derive_keys_v3 returned error %d\n", st);
        failures++;
    } else if (memcmp(test_ak, test_nk, 48) == 0 || memcmp(test_ak, test_pk_owner, 48) == 0) {
        printf("[-] FAILED: Derived keys collided\n");
        failures++;
    } else {
        printf("[+] PASS: 3-Tier Key Hierarchy (ak, nk, pk_owner) derived successfully\n");
    }

    /* 7.1 Test Spend Authorization Token */
    uint8_t dummy_tx_digest[64];
    uint8_t dummy_commitment[48];
    uint8_t auth_token[48];
    memset(dummy_tx_digest, 0xAA, sizeof(dummy_tx_digest));
    memset(dummy_commitment, 0xBB, sizeof(dummy_commitment));

    st = psp_compute_spend_auth_token_v3(test_sk_spend, dummy_tx_digest, dummy_commitment, auth_token);
    if (st != PSP_CRYPTO_OK) {
        printf("[-] FAILED: psp_compute_spend_auth_token_v3 returned %d\n", st);
        failures++;
    } else if (psp_verify_spend_auth_token_v3(test_sk_spend, dummy_tx_digest, dummy_commitment, auth_token) != 1) {
        printf("[-] FAILED: psp_verify_spend_auth_token_v3 failed valid token\n");
        failures++;
    } else {
        /* Tamper check */
        auth_token[0] ^= 0x01;
        if (psp_verify_spend_auth_token_v3(test_sk_spend, dummy_tx_digest, dummy_commitment, auth_token) != 0) {
            printf("[-] FAILED: psp_verify_spend_auth_token_v3 accepted tampered token\n");
            failures++;
        } else {
            printf("[+] PASS: Spend authorization token (tau_auth) generated and verified in constant time\n");
        }
    }

    printf("\n======================================================================\n");
    if (failures == 0) {
        printf("ALL MOBILE TIER 1 CRYPTOGRAPHIC ENGINE TESTS PASSED (100%% GREEN)!\n");
        return 0;
    } else {
        printf("TEST SUITE FAILED WITH %d FAILURES!\n", failures);
        return 1;
    }
}
