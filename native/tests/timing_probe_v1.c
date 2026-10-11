#define _POSIX_C_SOURCE 200809L
#include "psp_nullifier_v1.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SAMPLE_COUNT 40000u

static uint32_t next_u32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
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

static void stats(const uint64_t *x, size_t n, double *mean, double *variance) {
    size_t i; double sum = 0.0, ss = 0.0;
    for (i = 0; i < n; ++i) sum += (double)x[i];
    *mean = sum / (double)n;
    for (i = 0; i < n; ++i) { double d = (double)x[i] - *mean; ss += d*d; }
    *variance = ss / (double)(n - 1u);
}

int main(void) {
    uint8_t coin[PSP_NULLIFIER_V1_COIN_ID_BYTES];
    uint8_t secret_a[PSP_NULLIFIER_V1_SECRET_BYTES] = {0};
    uint8_t secret_b[PSP_NULLIFIER_V1_SECRET_BYTES];
    uint8_t out[PSP_NULLIFIER_V1_OUTPUT_BYTES];
    uint64_t *a = calloc(SAMPLE_COUNT, sizeof(*a));
    uint64_t *b = calloc(SAMPLE_COUNT, sizeof(*b));
    size_t na = 0, nb = 0, i;
    uint32_t state = UINT32_C(0x7a3c91d5);
    double ma, mb, va, vb, t;
    int result = EXIT_FAILURE;
    if (!a || !b) { fputs("allocation failed\n", stderr); goto done; }
    for (i = 0; i < sizeof(coin); ++i) coin[i] = (uint8_t)(i * 7u + 3u);
    for (i = 0; i < sizeof(secret_b); ++i) secret_b[i] = (uint8_t)(i * 31u + 11u);
    for (i = 0; i < SAMPLE_COUNT; ++i) {
        unsigned cls = next_u32(&state) & 1u;
        const uint8_t *secret = cls ? secret_b : secret_a;
        uint64_t start = now_ns();
        int rc = psp_nullifier_v1(coin, sizeof(coin), secret, sizeof(secret_a), out, sizeof(out));
        uint64_t elapsed = now_ns() - start;
        if (rc != PSP_NULLIFIER_OK) { fputs("native call failed\n", stderr); goto done; }
        if (cls) b[nb++] = elapsed; else a[na++] = elapsed;
    }
    stats(a, na, &ma, &va); stats(b, nb, &mb, &vb);
    t = (ma - mb) / sqrt(va/(double)na + vb/(double)nb);
    puts("Preliminary timing probe only; not dudect and not a CT proof.");
    printf("sample counts: A=%zu B=%zu\nmean ns: A=%.2f B=%.2f\nWelch t=%.4f\n", na, nb, ma, mb, t);
    if (fabs(t) >= 4.5) puts("REVIEW REQUIRED: difference detected or environmental noise is high.");
    else puts("No difference detected in this run; do not treat as evidence of constant-time execution.");
    result = EXIT_SUCCESS;
done:
    free(a); free(b); return result;
}
