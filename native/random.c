#include "psp_random.h"
#include "psp_keccak.h"

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#endif

int psp_random_bytes(uint8_t *out, size_t len) {
    if (out == NULL || len == 0) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

#if defined(_WIN32) || defined(_WIN64)
    NTSTATUS status = BCryptGenRandom(
        NULL,
        (PUCHAR)out,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status)) {
        psp_secure_zero(out, len);
        return PSP_CRYPTO_ERR_SYSTEM;
    }
    return PSP_CRYPTO_OK;
#else
    size_t acquired = 0;
    while (acquired < len) {
        ssize_t ret = getrandom(out + acquired, len - acquired, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            psp_secure_zero(out, len);
            return PSP_CRYPTO_ERR_SYSTEM;
        }
        acquired += (size_t)ret;
    }
    return PSP_CRYPTO_OK;
#endif
}

int psp_secure_lock(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
#if defined(_WIN32) || defined(_WIN64)
    if (!VirtualLock(ptr, len)) {
        return PSP_CRYPTO_ERR_SYSTEM;
    }
    return PSP_CRYPTO_OK;
#else
    if (mlock(ptr, len) != 0) {
        return PSP_CRYPTO_ERR_SYSTEM;
    }
    return PSP_CRYPTO_OK;
#endif
}

int psp_secure_unlock(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
#if defined(_WIN32) || defined(_WIN64)
    if (!VirtualUnlock(ptr, len)) {
        return PSP_CRYPTO_ERR_SYSTEM;
    }
    return PSP_CRYPTO_OK;
#else
    if (munlock(ptr, len) != 0) {
        return PSP_CRYPTO_ERR_SYSTEM;
    }
    return PSP_CRYPTO_OK;
#endif
}
