#ifndef PSP_KECCAK_H
#define PSP_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_KECCAK_ROUNDS 24
#define PSP_KECCAK_STATE_WORDS 25
#define PSP_KECCAK_STATE_BYTES 200

#define PSP_SHAKE256_RATE_BYTES 136
#define PSP_SHA3_384_RATE_BYTES 104
#define PSP_SHA3_256_RATE_BYTES 136
#define PSP_KECCAK256_RATE_BYTES 136

#define PSP_SHAKE256_DOMAIN_BYTE 0x1F
#define PSP_SHA3_DOMAIN_BYTE     0x06
#define PSP_KECCAK_DOMAIN_BYTE   0x01

enum psp_crypto_status {
    PSP_CRYPTO_OK = 0,
    PSP_CRYPTO_ERR_ARGUMENT = -1,
    PSP_CRYPTO_ERR_OVERFLOW = -2,
    PSP_CRYPTO_ERR_SYSTEM = -3
};

/*
 * Opaque streaming sponge state.
 */
typedef struct {
    uint64_t state[PSP_KECCAK_STATE_WORDS];
    size_t rate;
    size_t byte_index;
    uint8_t domain_byte;
    uint8_t squeezed;
} psp_sponge_ctx_t;

/*
 * Constant-time 24-round Keccak-f[1600] permutation.
 * Operates purely on 64-bit bitwise logic (AND, NOT, XOR, ROTL64).
 * Strictly branchless and lookup-free with respect to state contents.
 */
void psp_keccak_f1600(uint64_t state[PSP_KECCAK_STATE_WORDS]);

/*
 * Guaranteed memory zeroization.
 * Prevents compiler dead-store elimination through volatile pointer access
 * and an explicit microarchitectural compiler memory barrier.
 */
void psp_secure_zero(void *ptr, size_t len);

/*
 * Constant-time byte array comparison.
 * Returns 0 if equal, non-zero if unequal.
 * Does not branch early on mismatch; accumulates bitwise differences.
 */
int psp_constant_time_memcmp(const void *a, const void *b, size_t len);

/*
 * Sponge streaming API
 */
int psp_sponge_init(psp_sponge_ctx_t *ctx, size_t rate_bytes, uint8_t domain_byte);
int psp_sponge_absorb(psp_sponge_ctx_t *ctx, const uint8_t *in, size_t in_len);
int psp_sponge_squeeze(psp_sponge_ctx_t *ctx, uint8_t *out, size_t out_len);
void psp_sponge_cleanse(psp_sponge_ctx_t *ctx);

/*
 * One-shot and multi-part SHAKE256
 */
int psp_shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
int psp_shake256_parts(const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t *out, size_t out_len);

/*
 * One-shot and multi-part SHA3-384
 */
int psp_sha3_384(const uint8_t *in, size_t in_len, uint8_t out[48]);
int psp_sha3_384_parts(const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t out[48]);

/*
 * One-shot and multi-part HMAC-SHA3-384 (RFC 2104 constant-time HMAC)
 */
int psp_hmac_sha3_384(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[48]);
int psp_hmac_sha3_384_parts(const uint8_t *key, size_t key_len, const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t out[48]);

/*
 * One-shot Ethereum Keccak-256 (rate 136, domain byte 0x01)
 */
int psp_keccak256(const uint8_t *in, size_t in_len, uint8_t out[32]);
int psp_keccak256_parts(const uint8_t *const *parts, const size_t *lengths, size_t count, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* PSP_KECCAK_H */
