#define _POSIX_C_SOURCE 200809L
#include "psp_coin_commitment_v2.h"

#include <math.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLE_COUNT 30000u
#define REPEAT_COUNT 3u
#define WARMUP_COUNT 1000u

typedef struct {
    uint64_t n;
    double mean;
    double m2;
} welford;

static uint32_t rng_next(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void push(welford *w, double x) {
    double delta;
    ++w->n;
    delta = x - w->mean;
    w->mean += delta / (double)w->n;
    w->m2 += delta * (x - w->mean);
}

static double welch_t(const uint64_t *a, size_t na, const uint64_t *b, size_t nb) {
    welford sa = {0u, 0.0, 0.0};
    welford sb = {0u, 0.0, 0.0};
    size_t i;
    double va, vb, denom;
    for (i = 0u; i < na; ++i) push(&sa, (double)a[i]);
    for (i = 0u; i < nb; ++i) push(&sb, (double)b[i]);
    va = sa.m2 / (double)(sa.n - 1u);
    vb = sb.m2 / (double)(sb.n - 1u);
    denom = sqrt(va / (double)sa.n + vb / (double)sb.n);
    return denom == 0.0 ? 0.0 : (sa.mean - sb.mean) / denom;
}

/*
 * Local fixed-vs-random timing screen, inspired by dudect but not the official
 * implementation. variant 0 tests r_nf while rho_C is fixed; variant 1 tests
 * rho_C while r_nf is fixed. The control uses identical all-zero secret inputs
 * in both randomized classes. A clean result is not a CT proof.
 */
static int run_experiment(int control, int variant, unsigned repeat, double *t_out) {
    static const uint8_t params_id[] = "ringtail-test-params-v1";
    static const uint8_t public_key[] = "canonical-threshold-public-key-v1";
    uint8_t namespace_id[PSP_NAMESPACE_V2_BYTES];
    uint8_t coin_id[PSP_SCOPED_COIN_ID_V2_BYTES];
    uint8_t secret[PSP_NULLIFIER_V2_SECRET_BYTES];
    uint8_t salt[PSP_COIN_COMMITMENT_V2_SALT_BYTES];
    uint8_t output[PSP_COIN_COMMITMENT_V2_OUTPUT_BYTES];
    uint8_t (*random_values)[PSP_NULLIFIER_V2_SECRET_BYTES] = NULL;
    unsigned char *classes = NULL;
    uint64_t *times_a = NULL, *times_b = NULL;
    size_t na = 0u, nb = 0u, i, j;
    uint32_t class_state = UINT32_C(0x7a3c91d5) ^
                           (uint32_t)(repeat * UINT32_C(0x9e3779b9)) ^
                           (uint32_t)(variant * UINT32_C(0x85ebca6b));
    uint32_t secret_state = UINT32_C(0x243f6a88) ^
                            (uint32_t)(repeat * UINT32_C(0x85ebca6b)) ^
                            (uint32_t)(variant * UINT32_C(0xc2b2ae35));
    volatile uint8_t sink = 0u;
    int status = EXIT_FAILURE;

    memset(namespace_id, 0x71, sizeof(namespace_id));
    memset(coin_id, 0x29, sizeof(coin_id));
    memset(secret, 0, sizeof(secret));
    memset(salt, 0, sizeof(salt));
    memset(output, 0, sizeof(output));

    random_values = calloc(SAMPLE_COUNT, sizeof(*random_values));
    classes = calloc(SAMPLE_COUNT, sizeof(*classes));
    times_a = calloc(SAMPLE_COUNT, sizeof(*times_a));
    times_b = calloc(SAMPLE_COUNT, sizeof(*times_b));
    if (random_values == NULL || classes == NULL || times_a == NULL || times_b == NULL) {
        fputs("commitment timing probe allocation failed\n", stderr);
        goto cleanup;
    }

    for (i = 0u; i < SAMPLE_COUNT; ++i) {
        classes[i] = (unsigned char)(rng_next(&class_state) >> 31);
    }
    if (!control) {
        for (i = 0u; i < SAMPLE_COUNT; ++i) {
            if (classes[i] != 0u) {
                for (j = 0u; j < PSP_NULLIFIER_V2_SECRET_BYTES; ++j) {
                    random_values[i][j] = (uint8_t)(rng_next(&secret_state) >> 24);
                }
            }
        }
    }

    for (i = 0u; i < WARMUP_COUNT; ++i) {
        memset(secret, (int)(i & 0xffu), sizeof(secret));
        memset(salt, (int)((i * 3u) & 0xffu), sizeof(salt));
        if (psp_coin_commitment_v2(
                params_id, sizeof(params_id) - 1u,
                public_key, sizeof(public_key) - 1u,
                UINT64_C(2500),
                namespace_id, sizeof(namespace_id),
                coin_id, sizeof(coin_id),
                secret, sizeof(secret), salt, sizeof(salt),
                output, sizeof(output)) != PSP_NULLIFIER_OK) {
            fputs("commitment timing warmup failed\n", stderr);
            goto cleanup;
        }
    }

    for (i = 0u; i < SAMPLE_COUNT; ++i) {
        uint64_t start, elapsed;
        memset(secret, 0, sizeof(secret));
        memset(salt, 0, sizeof(salt));
        if (!control && classes[i] != 0u) {
            if (variant == 0) {
                memcpy(secret, random_values[i], sizeof(secret));
            } else {
                memcpy(salt, random_values[i], sizeof(salt));
            }
        }

        start = now_ns();
        {
            int rc = psp_coin_commitment_v2(
                params_id, sizeof(params_id) - 1u,
                public_key, sizeof(public_key) - 1u,
                UINT64_C(2500),
                namespace_id, sizeof(namespace_id),
                coin_id, sizeof(coin_id),
                secret, sizeof(secret), salt, sizeof(salt),
                output, sizeof(output));
            elapsed = now_ns() - start;
            if (rc != PSP_NULLIFIER_OK) {
                fputs("commitment timing measured call failed\n", stderr);
                goto cleanup;
            }
        }

        sink ^= output[(i + repeat + (unsigned)variant) % sizeof(output)];
        if (classes[i] == 0u) times_a[na++] = elapsed;
        else times_b[nb++] = elapsed;
    }

    if (na < SAMPLE_COUNT / 3u || nb < SAMPLE_COUNT / 3u) {
        fputs("commitment timing class balance low; run is inconclusive\n", stderr);
        *t_out = INFINITY;
        status = EXIT_SUCCESS;
        goto cleanup;
    }
    *t_out = welch_t(times_a, na, times_b, nb);
    printf("commitment-%s %s repeat %u: nA=%zu nB=%zu Welch-t=%.4f\n",
           variant == 0 ? "r_nf" : "rho_C",
           control ? "control" : "fixed-vs-random",
           repeat + 1u, na, nb, *t_out);
    (void)sink;
    status = EXIT_SUCCESS;

cleanup:
    if (random_values != NULL) {
        OPENSSL_cleanse(random_values, SAMPLE_COUNT * sizeof(*random_values));
    }
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(output, sizeof(output));
    free(random_values);
    free(classes);
    free(times_a);
    free(times_b);
    return status;
}

int main(void) {
    unsigned repeat;
    int inconclusive = 0;
    int leakage_suspected = 0;
    int variant;

    puts("Namespace-bound V2 commitment timing screen");
    puts("NOT dudect; a passing result is not proof of constant-time execution.");
    puts("Tests r_nf and rho_C separately with same-input controls.");

    for (variant = 0; variant < 2; ++variant) {
        for (repeat = 0u; repeat < REPEAT_COUNT; ++repeat) {
            double control_t, target_t;
            if (run_experiment(1, variant, repeat, &control_t) != EXIT_SUCCESS ||
                run_experiment(0, variant, repeat, &target_t) != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }
            if (!isfinite(control_t) || fabs(control_t) >= 5.0) {
                inconclusive = 1;
            } else if (fabs(target_t) >= 10.0) {
                leakage_suspected = 1;
            } else if (fabs(target_t) >= 5.0) {
                inconclusive = 1;
            }
        }
    }

    if (leakage_suspected) {
        puts("FAIL: timing difference detected with a clean control; investigate before any release.");
        return EXIT_FAILURE;
    }
    if (inconclusive) {
        puts("INCONCLUSIVE: control noise or intermediate t-scores; rerun on an idle target.");
        return 2;
    }
    puts("No first-order timing difference detected for these classes on this run only.");
    puts("This does NOT establish constant-time behavior or rule out other channels.");
    return EXIT_SUCCESS;
}
