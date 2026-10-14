#include "psp_merkle_tree_v3.h"
#include <string.h>

static const uint8_t DOMAIN_EMPTY_LEAF[] = "0PSP-COMMITMENT-EMPTY-LEAF-v1-SHAKE256";
static const uint8_t DOMAIN_LEAF[] = "0PSP-COMMITMENT-LEAF-v1-SHAKE256";
static const uint8_t DOMAIN_NODE[] = "0PSP-COMMITMENT-NODE-v1-SHAKE256";
static const uint8_t TREE_VERSION = 1u;

int psp_merkle_empty_leaf_hash(const uint8_t *namespace_id, uint8_t *out) {
    const uint8_t *parts[3];
    const size_t lengths[3] = {
        sizeof(DOMAIN_EMPTY_LEAF) - 1u,
        sizeof(TREE_VERSION),
        PSP_MERKLE_NAMESPACE_BYTES
    };

    if (namespace_id == NULL || out == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    parts[0] = DOMAIN_EMPTY_LEAF;
    parts[1] = &TREE_VERSION;
    parts[2] = namespace_id;

    return psp_shake256_parts(parts, lengths, 3u, out, PSP_MERKLE_NODE_BYTES);
}

int psp_merkle_leaf_hash(
    const uint8_t *namespace_id,
    uint64_t index,
    const uint8_t *commitment,
    uint8_t *out) {
    const uint8_t *parts[5];
    size_t lengths[5];
    uint8_t index_be[8];
    size_t i;

    if (namespace_id == NULL || commitment == NULL || out == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    /* index serialized as 8 bytes big-endian */
    for (i = 0; i < 8; ++i) {
        index_be[i] = (uint8_t)((index >> ((7u - i) * 8u)) & 0xffu);
    }

    parts[0] = DOMAIN_LEAF; lengths[0] = sizeof(DOMAIN_LEAF) - 1u;
    parts[1] = &TREE_VERSION; lengths[1] = sizeof(TREE_VERSION);
    parts[2] = namespace_id; lengths[2] = PSP_MERKLE_NAMESPACE_BYTES;
    parts[3] = index_be; lengths[3] = sizeof(index_be);
    parts[4] = commitment; lengths[4] = PSP_MERKLE_COMMITMENT_BYTES;

    return psp_shake256_parts(parts, lengths, 5u, out, PSP_MERKLE_NODE_BYTES);
}

int psp_merkle_node_hash(
    const uint8_t *namespace_id,
    uint8_t level,
    const uint8_t *left,
    const uint8_t *right,
    uint8_t *out) {
    const uint8_t *parts[6];
    size_t lengths[6];
    uint8_t level_be[4];

    if (namespace_id == NULL || left == NULL || right == NULL || out == NULL || level >= PSP_MERKLE_TREE_DEPTH) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    /* level serialized as 4 bytes big-endian */
    level_be[0] = 0u;
    level_be[1] = 0u;
    level_be[2] = 0u;
    level_be[3] = level;

    parts[0] = DOMAIN_NODE; lengths[0] = sizeof(DOMAIN_NODE) - 1u;
    parts[1] = &TREE_VERSION; lengths[1] = sizeof(TREE_VERSION);
    parts[2] = level_be; lengths[2] = sizeof(level_be);
    parts[3] = namespace_id; lengths[3] = PSP_MERKLE_NAMESPACE_BYTES;
    parts[4] = left; lengths[4] = PSP_MERKLE_NODE_BYTES;
    parts[5] = right; lengths[5] = PSP_MERKLE_NODE_BYTES;

    return psp_shake256_parts(parts, lengths, 6u, out, PSP_MERKLE_NODE_BYTES);
}

int psp_merkle_verify_path(
    const uint8_t *namespace_id,
    uint64_t leaf_index,
    const uint8_t *commitment,
    const uint8_t *siblings_flat,
    size_t depth,
    const uint8_t *expected_root) {
    uint8_t current[PSP_MERKLE_NODE_BYTES];
    uint64_t cursor;
    size_t level;
    int st;

    if (namespace_id == NULL || commitment == NULL || siblings_flat == NULL || expected_root == NULL || depth != PSP_MERKLE_TREE_DEPTH) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    st = psp_merkle_leaf_hash(namespace_id, leaf_index, commitment, current);
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    cursor = leaf_index;
    for (level = 0; level < depth; ++level) {
        const uint8_t *sibling = siblings_flat + (level * PSP_MERKLE_NODE_BYTES);
        uint8_t next[PSP_MERKLE_NODE_BYTES];

        if (cursor & 1u) {
            st = psp_merkle_node_hash(namespace_id, (uint8_t)level, sibling, current, next);
        } else {
            st = psp_merkle_node_hash(namespace_id, (uint8_t)level, current, sibling, next);
        }
        if (st != PSP_CRYPTO_OK) {
            psp_secure_zero(current, sizeof(current));
            return st;
        }
        memcpy(current, next, PSP_MERKLE_NODE_BYTES);
        cursor >>= 1u;
    }

    int match = psp_constant_time_memcmp(current, expected_root, PSP_MERKLE_NODE_BYTES);
    psp_secure_zero(current, sizeof(current));
    return (match == 0) ? PSP_CRYPTO_OK : PSP_CRYPTO_ERR_ARGUMENT;
}
