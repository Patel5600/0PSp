#include "psp_keccak.h"
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif

/*
 * Standard 64-bit circular left shift.
 * Under modern compilers (GCC, Clang, MSVC), this optimizes directly
 * to a single constant-time RORX or ROL instruction.
 */
static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    return (x << (n & 63u)) | (x >> ((64u - (n & 63u)) & 63u));
}

/*
 * Keccak-f[1600] 24 round constants.
 */
static const uint64_t KECCAK_RC[PSP_KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/*
 * Guaranteed memory zeroization.
 * Prevents dead-store elimination across all compiler optimization levels.
 */
void psp_secure_zero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
#if defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0u;
    }
    __asm__ __volatile__("" ::: "memory");
#endif
}

/*
 * Constant-time byte array comparison.
 */
int psp_constant_time_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *ua = (const uint8_t *)a;
    const uint8_t *ub = (const uint8_t *)b;
    uint8_t diff = 0u;
    size_t i;
    for (i = 0u; i < len; ++i) {
        diff |= (ua[i] ^ ub[i]);
    }
    return (int)diff;
}

/*
 * Constant-time 24-round Keccak-f[1600] permutation.
 */
void psp_keccak_f1600(uint64_t state[PSP_KECCAK_STATE_WORDS]) {
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t Bba, Bbe, Bbi, Bbo, Bbu;
    uint64_t Bga, Bge, Bgi, Bgo, Bgu;
    uint64_t Bka, Bke, Bki, Bko, Bku;
    uint64_t Bma, Bme, Bmi, Bmo, Bmu;
    uint64_t Bsa, Bse, Bsi, Bso, Bsu;
    uint64_t Ca, Ce, Ci, Co, Cu;
    uint64_t Da, De, Di, Do, Du;
    int round;

    Aba = state[0];  Abe = state[1];  Abi = state[2];  Abo = state[3];  Abu = state[4];
    Aga = state[5];  Age = state[6];  Agi = state[7];  Ago = state[8];  Agu = state[9];
    Aka = state[10]; Ake = state[11]; Aki = state[12]; Ako = state[13]; Aku = state[14];
    Ama = state[15]; Ame = state[16]; Ami = state[17]; Amo = state[18]; Amu = state[19];
    Asa = state[20]; Ase = state[21]; Asi = state[22]; Aso = state[23]; Asu = state[24];

    for (round = 0; round < PSP_KECCAK_ROUNDS; ++round) {
        /* 1. Theta step */
        Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        Da = Cu ^ rotl64(Ce, 1);
        De = Ca ^ rotl64(Ci, 1);
        Di = Ce ^ rotl64(Co, 1);
        Do = Ci ^ rotl64(Cu, 1);
        Du = Co ^ rotl64(Ca, 1);

        Aba ^= Da; Abe ^= De; Abi ^= Di; Abo ^= Do; Abu ^= Du;
        Aga ^= Da; Age ^= De; Agi ^= Di; Ago ^= Do; Agu ^= Du;
        Aka ^= Da; Ake ^= De; Aki ^= Di; Ako ^= Do; Aku ^= Du;
        Ama ^= Da; Ame ^= De; Ami ^= Di; Amo ^= Do; Amu ^= Du;
        Asa ^= Da; Ase ^= De; Asi ^= Di; Aso ^= Do; Asu ^= Du;

        /* 2. Rho and Pi steps */
        Bba = Aba;
        Bbe = rotl64(Age, 44);
        Bbi = rotl64(Aki, 43);
        Bbo = rotl64(Amo, 21);
        Bbu = rotl64(Asu, 14);

        Bga = rotl64(Abo, 28);
        Bge = rotl64(Agu, 20);
        Bgi = rotl64(Aka, 3);
        Bgo = rotl64(Ame, 45);
        Bgu = rotl64(Asi, 61);

        Bka = rotl64(Abe, 1);
        Bke = rotl64(Agi, 6);
        Bki = rotl64(Ako, 25);
        Bko = rotl64(Amu, 8);
        Bku = rotl64(Asa, 18);

        Bma = rotl64(Abu, 27);
        Bme = rotl64(Aga, 36);
        Bmi = rotl64(Ake, 10);
        Bmo = rotl64(Ami, 15);
        Bmu = rotl64(Aso, 56);

        Bsa = rotl64(Abi, 62);
        Bse = rotl64(Ago, 55);
        Bsi = rotl64(Aku, 39);
        Bso = rotl64(Ama, 41);
        Bsu = rotl64(Ase, 2);

        /* 3. Chi step */
        Aba = Bba ^ ((~Bbe) & Bbi);
        Abe = Bbe ^ ((~Bbi) & Bbo);
        Abi = Bbi ^ ((~Bbo) & Bbu);
        Abo = Bbo ^ ((~Bbu) & Bba);
        Abu = Bbu ^ ((~Bba) & Bbe);

        Aga = Bga ^ ((~Bge) & Bgi);
        Age = Bge ^ ((~Bgi) & Bgo);
        Agi = Bgi ^ ((~Bgo) & Bgu);
        Ago = Bgo ^ ((~Bgu) & Bga);
        Agu = Bgu ^ ((~Bga) & Bge);

        Aka = Bka ^ ((~Bke) & Bki);
        Ake = Bke ^ ((~Bki) & Bko);
        Aki = Bki ^ ((~Bko) & Bku);
        Ako = Bko ^ ((~Bku) & Bka);
        Aku = Bku ^ ((~Bka) & Bke);

        Ama = Bma ^ ((~Bme) & Bmi);
        Ame = Bme ^ ((~Bmi) & Bmo);
        Ami = Bmi ^ ((~Bmo) & Bmu);
        Amo = Bmo ^ ((~Bmu) & Bma);
        Amu = Bmu ^ ((~Bma) & Bme);

        Asa = Bsa ^ ((~Bse) & Bsi);
        Ase = Bse ^ ((~Bsi) & Bso);
        Asi = Bsi ^ ((~Bso) & Bsu);
        Aso = Bso ^ ((~Bsu) & Bsa);
        Asu = Bsu ^ ((~Bsa) & Bse);

        /* 4. Iota step */
        Aba ^= KECCAK_RC[round];
    }

    state[0]  = Aba; state[1]  = Abe; state[2]  = Abi; state[3]  = Abo; state[4]  = Abu;
    state[5]  = Aga; state[6]  = Age; state[7]  = Agi; state[8]  = Ago; state[9]  = Agu;
    state[10] = Aka; state[11] = Ake; state[12] = Aki; state[13] = Ako; state[14] = Aku;
    state[15] = Ama; state[16] = Ame; state[17] = Ami; state[18] = Amo; state[19] = Amu;
    state[20] = Asa; state[21] = Ase; state[22] = Asi; state[23] = Aso; state[24] = Asu;
}

int psp_sponge_init(psp_sponge_ctx_t *ctx, size_t rate_bytes, uint8_t domain_byte) {
    if (ctx == NULL || rate_bytes == 0 || rate_bytes > PSP_KECCAK_STATE_BYTES) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    psp_secure_zero(ctx, sizeof(*ctx));
    ctx->rate = rate_bytes;
    ctx->domain_byte = domain_byte;
    ctx->byte_index = 0u;
    ctx->squeezed = 0u;
    return PSP_CRYPTO_OK;
}

void psp_sponge_cleanse(psp_sponge_ctx_t *ctx) {
    if (ctx != NULL) {
        psp_secure_zero(ctx, sizeof(*ctx));
    }
}

int psp_sponge_absorb(psp_sponge_ctx_t *ctx, const uint8_t *in, size_t in_len) {
    uint8_t *state_bytes;
    size_t take;

    if (ctx == NULL || (in == NULL && in_len > 0)) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    if (ctx->squeezed) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    state_bytes = (uint8_t *)ctx->state;
    while (in_len > 0) {
        take = ctx->rate - ctx->byte_index;
        if (take > in_len) {
            take = in_len;
        }

        for (size_t i = 0; i < take; ++i) {
            state_bytes[ctx->byte_index + i] ^= in[i];
        }

        ctx->byte_index += take;
        in += take;
        in_len -= take;

        if (ctx->byte_index == ctx->rate) {
            psp_keccak_f1600(ctx->state);
            ctx->byte_index = 0u;
        }
    }
    return PSP_CRYPTO_OK;
}

static void psp_sponge_finalize_pad(psp_sponge_ctx_t *ctx) {
    uint8_t *state_bytes = (uint8_t *)ctx->state;
    state_bytes[ctx->byte_index] ^= ctx->domain_byte;
    state_bytes[ctx->rate - 1] ^= 0x80u;
    psp_keccak_f1600(ctx->state);
    ctx->byte_index = 0u;
    ctx->squeezed = 1u;
}

int psp_sponge_squeeze(psp_sponge_ctx_t *ctx, uint8_t *out, size_t out_len) {
    uint8_t *state_bytes;
    size_t take;

    if (ctx == NULL || (out == NULL && out_len > 0)) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    if (!ctx->squeezed) {
        psp_sponge_finalize_pad(ctx);
    }

    state_bytes = (uint8_t *)ctx->state;
    while (out_len > 0) {
        take = ctx->rate - ctx->byte_index;
        if (take > out_len) {
            take = out_len;
        }

        memcpy(out, &state_bytes[ctx->byte_index], take);
        ctx->byte_index += take;
        out += take;
        out_len -= take;

        if (ctx->byte_index == ctx->rate && out_len > 0) {
            psp_keccak_f1600(ctx->state);
            ctx->byte_index = 0u;
        }
    }
    return PSP_CRYPTO_OK;
}

/*
 * SHAKE256 implementations
 */
int psp_shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    psp_sponge_ctx_t ctx;
    int st;

    st = psp_sponge_init(&ctx, PSP_SHAKE256_RATE_BYTES, PSP_SHAKE256_DOMAIN_BYTE);
    if (st != PSP_CRYPTO_OK) return st;

    st = psp_sponge_absorb(&ctx, in, in_len);
    if (st != PSP_CRYPTO_OK) {
        psp_sponge_cleanse(&ctx);
        return st;
    }

    st = psp_sponge_squeeze(&ctx, out, out_len);
    psp_sponge_cleanse(&ctx);
    return st;
}

int psp_shake256_parts(const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t *out, size_t out_len) {
    psp_sponge_ctx_t ctx;
    size_t i;
    int st;

    st = psp_sponge_init(&ctx, PSP_SHAKE256_RATE_BYTES, PSP_SHAKE256_DOMAIN_BYTE);
    if (st != PSP_CRYPTO_OK) return st;

    for (i = 0u; i < count; ++i) {
        st = psp_sponge_absorb(&ctx, parts[i], lengths[i]);
        if (st != PSP_CRYPTO_OK) {
            psp_sponge_cleanse(&ctx);
            return st;
        }
    }

    st = psp_sponge_squeeze(&ctx, out, out_len);
    psp_sponge_cleanse(&ctx);
    return st;
}

/*
 * SHA3-384 implementations
 */
int psp_sha3_384(const uint8_t *in, size_t in_len, uint8_t out[48]) {
    psp_sponge_ctx_t ctx;
    int st;

    st = psp_sponge_init(&ctx, PSP_SHA3_384_RATE_BYTES, PSP_SHA3_DOMAIN_BYTE);
    if (st != PSP_CRYPTO_OK) return st;

    st = psp_sponge_absorb(&ctx, in, in_len);
    if (st != PSP_CRYPTO_OK) {
        psp_sponge_cleanse(&ctx);
        return st;
    }

    st = psp_sponge_squeeze(&ctx, out, 48u);
    psp_sponge_cleanse(&ctx);
    return st;
}

int psp_sha3_384_parts(const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t out[48]) {
    psp_sponge_ctx_t ctx;
    size_t i;
    int st;

    st = psp_sponge_init(&ctx, PSP_SHA3_384_RATE_BYTES, PSP_SHA3_DOMAIN_BYTE);
    if (st != PSP_CRYPTO_OK) return st;

    for (i = 0u; i < count; ++i) {
        st = psp_sponge_absorb(&ctx, parts[i], lengths[i]);
        if (st != PSP_CRYPTO_OK) {
            psp_sponge_cleanse(&ctx);
            return st;
        }
    }

    st = psp_sponge_squeeze(&ctx, out, 48u);
    psp_sponge_cleanse(&ctx);
    return st;
}

/*
 * Constant-time HMAC-SHA3-384 (RFC 2104)
 * Block size B = 104 bytes (SHA3-384 rate). Output = 48 bytes.
 */
int psp_hmac_sha3_384_parts(const uint8_t *key, size_t key_len, const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t out[48]) {
    uint8_t k_padded[PSP_SHA3_384_RATE_BYTES];
    uint8_t k_ipad[PSP_SHA3_384_RATE_BYTES];
    uint8_t k_opad[PSP_SHA3_384_RATE_BYTES];
    uint8_t inner_digest[48];
    psp_sponge_ctx_t ctx;
    size_t i;
    int st;

    if (key == NULL || out == NULL || (parts == NULL && count > 0)) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    psp_secure_zero(k_padded, sizeof(k_padded));
    if (key_len > PSP_SHA3_384_RATE_BYTES) {
        st = psp_sha3_384(key, key_len, k_padded);
        if (st != PSP_CRYPTO_OK) return st;
    } else {
        memcpy(k_padded, key, key_len);
    }

    for (i = 0u; i < PSP_SHA3_384_RATE_BYTES; ++i) {
        k_ipad[i] = k_padded[i] ^ 0x36u;
        k_opad[i] = k_padded[i] ^ 0x5cu;
    }

    /* 1. Inner hash = SHA3-384(k_ipad || parts...) */
    st = psp_sponge_init(&ctx, PSP_SHA3_384_RATE_BYTES, PSP_SHA3_DOMAIN_BYTE);
    if (st != PSP_CRYPTO_OK) goto cleanup;

    st = psp_sponge_absorb(&ctx, k_ipad, sizeof(k_ipad));
    if (st != PSP_CRYPTO_OK) goto cleanup;

    for (i = 0u; i < count; ++i) {
        st = psp_sponge_absorb(&ctx, parts[i], lengths[i]);
        if (st != PSP_CRYPTO_OK) goto cleanup;
    }

    st = psp_sponge_squeeze(&ctx, inner_digest, sizeof(inner_digest));
    if (st != PSP_CRYPTO_OK) goto cleanup;
    psp_sponge_cleanse(&ctx);

    /* 2. Outer hash = SHA3-384(k_opad || inner_digest) */
    st = psp_sponge_init(&ctx, PSP_SHA3_384_RATE_BYTES, PSP_SHA3_DOMAIN_BYTE);
    if (st != PSP_CRYPTO_OK) goto cleanup;

    st = psp_sponge_absorb(&ctx, k_opad, sizeof(k_opad));
    if (st != PSP_CRYPTO_OK) goto cleanup;

    st = psp_sponge_absorb(&ctx, inner_digest, sizeof(inner_digest));
    if (st != PSP_CRYPTO_OK) goto cleanup;

    st = psp_sponge_squeeze(&ctx, out, 48u);

cleanup:
    psp_sponge_cleanse(&ctx);
    psp_secure_zero(k_padded, sizeof(k_padded));
    psp_secure_zero(k_ipad, sizeof(k_ipad));
    psp_secure_zero(k_opad, sizeof(k_opad));
    psp_secure_zero(inner_digest, sizeof(inner_digest));
    return st;
}

int psp_hmac_sha3_384(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[48]) {
    const uint8_t *parts[1] = { msg };
    const size_t lengths[1] = { msg_len };
    return psp_hmac_sha3_384_parts(key, key_len, parts, lengths, 1u, out);
}

/*
 * Ethereum Keccak-256 (rate 136, domain byte 0x01)
 */
int psp_keccak256_parts(const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t out[32]) {
    psp_sponge_ctx_t ctx;
    size_t i;
    int st;

    st = psp_sponge_init(&ctx, PSP_KECCAK256_RATE_BYTES, PSP_KECCAK_DOMAIN_BYTE);
    if (st != PSP_CRYPTO_OK) return st;

    for (i = 0u; i < count; ++i) {
        st = psp_sponge_absorb(&ctx, parts[i], lengths[i]);
        if (st != PSP_CRYPTO_OK) {
            psp_sponge_cleanse(&ctx);
            return st;
        }
    }

    st = psp_sponge_squeeze(&ctx, out, 32u);
    psp_sponge_cleanse(&ctx);
    return st;
}

int psp_keccak256(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    const uint8_t *parts[1] = { in };
    const size_t lengths[1] = { in_len };
    return psp_keccak256_parts(parts, lengths, 1u, out);
}
