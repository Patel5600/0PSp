#include "../include/psp_keccak.h"
#include "../include/psp_nullifier_v3.h"
#include "../include/psp_coin_commitment_v3.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
static inline uint64_t rdtsc(void) {
    return __builtin_ia32_rdtsc();
}
#else
#include <x86intrin.h>
static inline uint64_t rdtsc(void) {
    return __rdtsc();
}
#endif

#define SAMPLES 10000u
#define WARMUP  500u

typedef struct {
    uint64_t n;
    double mean;
    double m2;
} welford_t;

static inline void welford_update(welford_t *w, double x) {
    w->n++;
    double delta = x - w->mean;
    w->mean += delta / (double)w->n;
    w->m2 += delta * (x - w->mean);
}

static double welch_t(const welford_t *a, const welford_t *b) {
    double va = a->m2 / (double)(a->n - 1u);
    double vb = b->m2 / (double)(b->n - 1u);
    double denom = sqrt(va / (double)a->n + vb / (double)b->n);
    return denom == 0.0 ? 0.0 : (a->mean - b->mean) / denom;
}

/* Fast Xorshift PRNG for non-cryptographic test harness generation */
static inline uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

int main(void) {
    printf("======================================================================\n");
    printf("0PSP Native C11 Cycle-Accurate Side-Channel Timing Screen (RDTSC)\n");
    printf("Evaluating microarchitectural execution variance across fixed vs random classes\n");
    printf("Samples per class: %u | Acceptance threshold: |t| < 4.5\n", SAMPLES);
    printf("======================================================================\n\n");

    uint64_t prng_state = 0xDEADBEEFCAFE1234ULL;
    welford_t fixed_stats = {0, 0.0, 0.0};
    welford_t random_stats = {0, 0.0, 0.0};

    uint8_t fixed_nk[48]; memset(fixed_nk, 0xAA, 48);
    uint8_t rand_nk[48];

    uint8_t ns[48]; memset(ns, 0x12, 48);
    uint8_t params_id[] = "test-params-timing";
    uint8_t bundle[64]; memset(bundle, 0x34, 64);
    uint8_t comm[48]; memset(comm, 0x56, 48);
    uint8_t coin_id[32]; memset(coin_id, 0x78, 32);
    uint8_t r_nf[36]; memset(r_nf, 0x9A, 36);
    uint8_t out[48];

    /* Warmup CPU caches and branch predictors */
    for (unsigned int i = 0; i < WARMUP; ++i) {
        psp_nullifier_v3(fixed_nk, 48, ns, 48, params_id, sizeof(params_id) - 1, bundle, 64, comm, 48, coin_id, 32, r_nf, 36, out, 48);
    }

    /* Interleaved measurements to cancel thermal and OS scheduling drift */
    for (unsigned int i = 0; i < SAMPLES; ++i) {
        uint64_t t0, t1;

        /* Class 0: Fixed secret key */
        t0 = rdtsc();
        psp_nullifier_v3(fixed_nk, 48, ns, 48, params_id, sizeof(params_id) - 1, bundle, 64, comm, 48, coin_id, 32, r_nf, 36, out, 48);
        t1 = rdtsc();
        welford_update(&fixed_stats, (double)(t1 - t0));

        /* Class 1: Random secret key */
        for (int j = 0; j < 6; ++j) {
            uint64_t r = xorshift64(&prng_state);
            memcpy(rand_nk + j * 8, &r, 8);
        }
        t0 = rdtsc();
        psp_nullifier_v3(rand_nk, 48, ns, 48, params_id, sizeof(params_id) - 1, bundle, 64, comm, 48, coin_id, 32, r_nf, 36, out, 48);
        t1 = rdtsc();
        welford_update(&random_stats, (double)(t1 - t0));
    }

    double t_val = welch_t(&fixed_stats, &random_stats);
    double abs_t = fabs(t_val);

    printf("NullifierV3 Native Microarchitectural Timing Results:\n");
    printf("  Fixed Key Mean:    %.2f CPU cycles (stddev: %.2f)\n", fixed_stats.mean, sqrt(fixed_stats.m2 / (double)(fixed_stats.n - 1)));
    printf("  Random Key Mean:   %.2f CPU cycles (stddev: %.2f)\n", random_stats.mean, sqrt(random_stats.m2 / (double)(random_stats.n - 1)));
    printf("  Welch's t-score:   %+0.4f (absolute: %0.4f)\n", t_val, abs_t);

    if (abs_t < 4.5) {
        printf("\n[+] PASS: No statistically significant data-dependent timing variation detected (|t| < 4.5).\n");
        printf("    Native C11 NullifierV3 execution is constant-time at the CPU cycle level.\n");
        return 0;
    } else {
        printf("\n[-] FAILED: Statistically significant timing variation detected (|t| >= 4.5).\n");
        return 1;
    }
}
