#ifndef PSP_NAMESPACE_V3_H
#define PSP_NAMESPACE_V3_H

#include "psp_nullifier_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_NAMESPACE_V3_ID_BYTES 48u
#define PSP_NAMESPACE_V3_COMPONENT_MAX_BYTES 4096u
#define PSP_NAMESPACE_V3_VERSION 3u

/*
 * Compute Namespace V3 directly over three canonical identity descriptors:
 *
 *   "0PSP-NAMESPACE-v3-SHAKE256" || 0x03 ||
 *   uint32_le(ledger_len) || ledger_identity[ledger_len] ||
 *   uint32_le(deployment_len) || deployment_identity[deployment_len] ||
 *   uint32_le(asset_len) || asset_identity[asset_len]
 *
 * Each descriptor must be 1..4096 bytes. Output is SHAKE256-384 (48 bytes).
 * No 32-byte intermediate component digest is used in the namespace identity.
 *
 * The caller must canonicalize and domain-separate each descriptor. Inputs and
 * output must not overlap. Output is cleared on supported failure paths.
 * This API does not prove constant-time execution.
 */
int psp_namespace_v3_derive(
    const uint8_t *ledger_identity, size_t ledger_identity_len,
    const uint8_t *deployment_identity, size_t deployment_identity_len,
    const uint8_t *asset_identity, size_t asset_identity_len,
    uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
