#ifndef PSP_MERKLE_TREE_V3_H
#define PSP_MERKLE_TREE_V3_H

#include "psp_keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_MERKLE_TREE_DEPTH 63u
#define PSP_MERKLE_NODE_BYTES 48u
#define PSP_MERKLE_NAMESPACE_BYTES 48u
#define PSP_MERKLE_COMMITMENT_BYTES 48u

/*
 * Compute depth-63 empty leaf hash:
 *   SHAKE256-384("0PSP-COMMITMENT-EMPTY-LEAF-v1-SHAKE256" || 0x01 || u16le(48) || namespace_id[48])
 */
int psp_merkle_empty_leaf_hash(const uint8_t *namespace_id, uint8_t *out);

/*
 * Compute depth-63 active leaf hash:
 *   SHAKE256-384("0PSP-COMMITMENT-LEAF-v1-SHAKE256" || 0x01 || u16le(48) || namespace_id[48] ||
 *                u64le(index) || u16le(48) || commitment[48])
 */
int psp_merkle_leaf_hash(
    const uint8_t *namespace_id,
    uint64_t index,
    const uint8_t *commitment,
    uint8_t *out);

/*
 * Compute depth-63 internal node hash:
 *   SHAKE256-384("0PSP-COMMITMENT-NODE-v1-SHAKE256" || 0x01 || u16le(48) || namespace_id[48] ||
 *                u8(level) || u16le(48) || left[48] || u16le(48) || right[48])
 */
int psp_merkle_node_hash(
    const uint8_t *namespace_id,
    uint8_t level,
    const uint8_t *left,
    const uint8_t *right,
    uint8_t *out);

/*
 * Verify depth-63 Merkle inclusion path in constant time:
 * Traverses siblings from level 0 to depth-1, checking that reconstructed root == expected_root.
 * Returns 0 on valid inclusion, non-zero on mismatch or invalid argument.
 */
int psp_merkle_verify_path(
    const uint8_t *namespace_id,
    uint64_t leaf_index,
    const uint8_t *commitment,
    const uint8_t *siblings_flat, /* depth * 48 bytes */
    size_t depth,
    const uint8_t *expected_root);

#ifdef __cplusplus
}
#endif

#endif /* PSP_MERKLE_TREE_V3_H */
