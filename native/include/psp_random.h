#ifndef PSP_RANDOM_H
#define PSP_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Obtain high-entropy cryptographically secure random bytes directly from the OS kernel.
 * On Windows: BCryptGenRandom (BCRYPT_USE_SYSTEM_PREFERRED_RNG).
 * On Linux: getrandom() syscall.
 *
 * Fails closed on any entropy error or truncation. Clears out buffer on failure.
 */
int psp_random_bytes(uint8_t *out, size_t len);

/*
 * Pin sensitive memory in physical RAM to prevent swapping/paging to disk.
 * On Windows: VirtualLock.
 * On Linux: mlock.
 */
int psp_secure_lock(void *ptr, size_t len);

/*
 * Unpin memory after use.
 * On Windows: VirtualUnlock.
 * On Linux: munlock.
 */
int psp_secure_unlock(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PSP_RANDOM_H */
