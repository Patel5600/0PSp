#include "psp_tier1_mobile.h"
#include <string.h>

const uint8_t PSP_DOMAIN_OUTPUT_COIN_ID_V3[] = "0PSP-OUTPUT-COIN-ID-v3-anchor-index-candidate";
const uint8_t PSP_DOMAIN_OUTPUT_RNF_V3[] = "0PSP-OUTPUT-RNF-v3-anchor-index-candidate";
const uint8_t PSP_DOMAIN_NOTE_BUNDLE_V3[] = "0PSP-NOTE-PK-BUNDLE-v3";
const uint8_t PSP_DOMAIN_TX_FIELDS_V3[] = "0PSP-TX-FIELDS-v3-CANDIDATE-v2-SHAKE256";
const uint8_t PSP_DOMAIN_TX_PAYOUT_CONTEXT_V3[] = "0PSP-TX-PAYOUT-CONTEXT-v3-CANDIDATE-v1-SHAKE256";
const uint8_t PSP_DOMAIN_TX_DIGEST_V3[] = "0PSP-TX-DIGEST-v3-CANDIDATE-v2-SHAKE256";
const uint8_t PSP_POLICY_NK_POSSESSION_V3[] = "0PSP-V3-NK-POSSESSION-CANDIDATE-v1";
const uint8_t PSP_DOMAIN_AK_V3[] = "0PSP_AK_DERIVE_V3";
const uint8_t PSP_DOMAIN_NK_V3[] = "0PSP_NK_DERIVE_V3";
const uint8_t PSP_DOMAIN_OWNER_V3[] = "0PSP_OWNER_V3";
const uint8_t PSP_DOMAIN_SPEND_AUTH_V3[] = "0PSP_SPEND_AUTH_V3";

static const uint8_t VERSION_V3 = 0x03;

static void write_u16_le(uint8_t out[2], uint16_t v) {
    out[0] = (uint8_t)(v & 0xffu);
    out[1] = (uint8_t)((v >> 8u) & 0xffu);
}

static void write_u16_be(uint8_t out[2], uint16_t v) {
    out[0] = (uint8_t)((v >> 8u) & 0xffu);
    out[1] = (uint8_t)(v & 0xffu);
}

static void write_u32_le(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v & 0xffu);
    out[1] = (uint8_t)((v >> 8u) & 0xffu);
    out[2] = (uint8_t)((v >> 16u) & 0xffu);
    out[3] = (uint8_t)((v >> 24u) & 0xffu);
}

static void write_u64_le(uint8_t out[8], uint64_t v) {
    for (size_t i = 0; i < 8; ++i) {
        out[i] = (uint8_t)((v >> (i * 8u)) & 0xffu);
    }
}

int psp_parse_bundle_key_commitment_v3(
    const uint8_t *bundle, size_t bundle_len,
    uint8_t *out_nk_commitment) {
    size_t prefix_len = sizeof(PSP_DOMAIN_NOTE_BUNDLE_V3) - 1u + 1u;
    size_t offset;
    uint16_t scheme_id_len;
    uint32_t auth_pk_len;
    uint16_t commit_len;

    if (bundle == NULL || out_nk_commitment == NULL || bundle_len < prefix_len + 8u + PSP_TIER1_KEY_BYTES) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    if (memcmp(bundle, PSP_DOMAIN_NOTE_BUNDLE_V3, sizeof(PSP_DOMAIN_NOTE_BUNDLE_V3) - 1u) != 0 ||
        bundle[sizeof(PSP_DOMAIN_NOTE_BUNDLE_V3) - 1u] != VERSION_V3) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    offset = prefix_len;
    scheme_id_len = (uint16_t)bundle[offset] | ((uint16_t)bundle[offset + 1] << 8u);
    offset += 2u;
    if (scheme_id_len == 0u || offset + scheme_id_len + 4u > bundle_len) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    offset += scheme_id_len;

    auth_pk_len = (uint32_t)bundle[offset] |
                  ((uint32_t)bundle[offset + 1] << 8u) |
                  ((uint32_t)bundle[offset + 2] << 16u) |
                  ((uint32_t)bundle[offset + 3] << 24u);
    offset += 4u;
    if (auth_pk_len == 0u || offset + auth_pk_len + 2u > bundle_len) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    offset += auth_pk_len;

    commit_len = (uint16_t)bundle[offset] | ((uint16_t)bundle[offset + 1] << 8u);
    offset += 2u;
    if (commit_len != PSP_TIER1_KEY_BYTES || offset + PSP_TIER1_KEY_BYTES != bundle_len) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    memcpy(out_nk_commitment, bundle + offset, PSP_TIER1_KEY_BYTES);
    return PSP_CRYPTO_OK;
}

int psp_encode_note_bundle_v3(
    const uint8_t *auth_scheme_id, size_t auth_scheme_id_len,
    const uint8_t *auth_public_key, size_t auth_public_key_len,
    const uint8_t *nullifier_key_commitment,
    uint8_t *out_bundle, size_t *out_bundle_len, size_t max_bundle_len) {
    size_t total_len;
    size_t offset;
    uint8_t len16[2];
    uint8_t len32[4];

    if (auth_scheme_id == NULL || auth_scheme_id_len == 0 || auth_scheme_id_len > 0xffff ||
        auth_public_key == NULL || auth_public_key_len == 0 ||
        nullifier_key_commitment == NULL ||
        out_bundle == NULL || out_bundle_len == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    total_len = sizeof(PSP_DOMAIN_NOTE_BUNDLE_V3) - 1u + 1u +
                2u + auth_scheme_id_len +
                4u + auth_public_key_len +
                2u + PSP_TIER1_KEY_BYTES;

    if (total_len > max_bundle_len || total_len > PSP_TIER1_MAX_BUNDLE_BYTES) {
        return PSP_CRYPTO_ERR_OVERFLOW;
    }

    offset = 0;
    memcpy(out_bundle + offset, PSP_DOMAIN_NOTE_BUNDLE_V3, sizeof(PSP_DOMAIN_NOTE_BUNDLE_V3) - 1u);
    offset += sizeof(PSP_DOMAIN_NOTE_BUNDLE_V3) - 1u;
    out_bundle[offset++] = VERSION_V3;

    write_u16_le(len16, (uint16_t)auth_scheme_id_len);
    memcpy(out_bundle + offset, len16, 2u);
    offset += 2u;
    memcpy(out_bundle + offset, auth_scheme_id, auth_scheme_id_len);
    offset += auth_scheme_id_len;

    write_u32_le(len32, (uint32_t)auth_public_key_len);
    memcpy(out_bundle + offset, len32, 4u);
    offset += 4u;
    memcpy(out_bundle + offset, auth_public_key, auth_public_key_len);
    offset += auth_public_key_len;

    write_u16_le(len16, (uint16_t)PSP_TIER1_KEY_BYTES);
    memcpy(out_bundle + offset, len16, 2u);
    offset += 2u;
    memcpy(out_bundle + offset, nullifier_key_commitment, PSP_TIER1_KEY_BYTES);
    offset += PSP_TIER1_KEY_BYTES;

    *out_bundle_len = offset;
    return PSP_CRYPTO_OK;
}

int psp_output_identity_v3(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *namespace_id,
    const uint8_t *parent_nullifier,
    const uint8_t *parent_commitment,
    const uint8_t *parent_coin_id,
    const uint8_t *parent_r_nf,
    const uint8_t *parent_bundle, size_t parent_bundle_len,
    const uint8_t *recipient_bundle, size_t recipient_bundle_len,
    const uint8_t *transaction_entropy,
    uint16_t output_index,
    uint8_t *out_coin_id,
    uint8_t *out_r_nf) {
    uint8_t dummy_commit[PSP_TIER1_KEY_BYTES];
    const uint8_t *parts[16];
    size_t lengths[16];
    uint8_t params_len_le[2];
    uint8_t commit_len_le[2];
    uint8_t parent_bundle_len_le[4];
    uint8_t recipient_bundle_len_le[4];
    uint8_t slot_be[2];
    int st;

    if (params_id == NULL || params_id_len == 0 || params_id_len > 0xffff ||
        namespace_id == NULL || parent_nullifier == NULL || parent_commitment == NULL ||
        parent_coin_id == NULL || parent_r_nf == NULL ||
        parent_bundle == NULL || parent_bundle_len == 0 ||
        recipient_bundle == NULL || recipient_bundle_len == 0 ||
        transaction_entropy == NULL ||
        out_coin_id == NULL || out_r_nf == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    /* Validate canonical bundle format for both parent and recipient */
    if (psp_parse_bundle_key_commitment_v3(parent_bundle, parent_bundle_len, dummy_commit) != PSP_CRYPTO_OK ||
        psp_parse_bundle_key_commitment_v3(recipient_bundle, recipient_bundle_len, dummy_commit) != PSP_CRYPTO_OK) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    psp_secure_zero(dummy_commit, sizeof(dummy_commit));

    write_u16_le(params_len_le, (uint16_t)params_id_len);
    write_u16_le(commit_len_le, (uint16_t)PSP_TIER1_COMMITMENT_BYTES);
    write_u32_le(parent_bundle_len_le, (uint32_t)parent_bundle_len);
    write_u32_le(recipient_bundle_len_le, (uint32_t)recipient_bundle_len);
    write_u16_be(slot_be, output_index);

    /* Construct common preimage slices */
    lengths[0] = 0; /* filled per domain below */
    parts[1] = &VERSION_V3; lengths[1] = 1u;
    parts[2] = params_len_le; lengths[2] = 2u;
    parts[3] = params_id; lengths[3] = params_id_len;
    parts[4] = namespace_id; lengths[4] = PSP_TIER1_NAMESPACE_BYTES;
    parts[5] = parent_nullifier; lengths[5] = PSP_TIER1_NULLIFIER_BYTES;
    parts[6] = commit_len_le; lengths[6] = 2u;
    parts[7] = parent_commitment; lengths[7] = PSP_TIER1_COMMITMENT_BYTES;
    parts[8] = parent_coin_id; lengths[8] = PSP_TIER1_COIN_ID_BYTES;
    parts[9] = parent_r_nf; lengths[9] = PSP_TIER1_RNF_BYTES;
    parts[10] = parent_bundle_len_le; lengths[10] = 4u;
    parts[11] = parent_bundle; lengths[11] = parent_bundle_len;
    parts[12] = recipient_bundle_len_le; lengths[12] = 4u;
    parts[13] = recipient_bundle; lengths[13] = recipient_bundle_len;
    parts[14] = transaction_entropy; lengths[14] = PSP_TIER1_ENTROPY_BYTES;
    parts[15] = slot_be; lengths[15] = 2u;

    /* 1. Derive output coin_id (32 bytes) */
    parts[0] = PSP_DOMAIN_OUTPUT_COIN_ID_V3;
    lengths[0] = sizeof(PSP_DOMAIN_OUTPUT_COIN_ID_V3) - 1u;
    st = psp_shake256_parts(parts, lengths, 16u, out_coin_id, PSP_TIER1_COIN_ID_BYTES);
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* 2. Derive output r_nf (36 bytes) */
    parts[0] = PSP_DOMAIN_OUTPUT_RNF_V3;
    lengths[0] = sizeof(PSP_DOMAIN_OUTPUT_RNF_V3) - 1u;
    st = psp_shake256_parts(parts, lengths, 16u, out_r_nf, PSP_TIER1_RNF_BYTES);
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    return PSP_CRYPTO_OK;
}

int psp_note_generate_v3(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *namespace_id,
    uint64_t value,
    const uint8_t *auth_scheme_id, size_t auth_scheme_id_len,
    const uint8_t *auth_public_key, size_t auth_public_key_len,
    uint8_t *out_nk,
    uint8_t *out_coin_id,
    uint8_t *out_r_nf,
    uint8_t *out_rho_coin,
    uint8_t *out_bundle, size_t *out_bundle_len, size_t max_bundle_len,
    uint8_t *out_commitment) {
    uint8_t nk_commit[PSP_TIER1_KEY_BYTES];
    int st;

    if (params_id == NULL || params_id_len == 0 || namespace_id == NULL ||
        auth_scheme_id == NULL || auth_scheme_id_len == 0 ||
        auth_public_key == NULL || auth_public_key_len == 0 ||
        out_nk == NULL || out_coin_id == NULL || out_r_nf == NULL ||
        out_rho_coin == NULL || out_bundle == NULL || out_bundle_len == NULL ||
        out_commitment == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    /* Generate cryptographic randomness from OS CSPRNG */
    if (psp_random_bytes(out_nk, PSP_TIER1_KEY_BYTES) != PSP_CRYPTO_OK ||
        psp_random_bytes(out_coin_id, PSP_TIER1_COIN_ID_BYTES) != PSP_CRYPTO_OK ||
        psp_random_bytes(out_r_nf, PSP_TIER1_RNF_BYTES) != PSP_CRYPTO_OK ||
        psp_random_bytes(out_rho_coin, PSP_TIER1_SALT_BYTES) != PSP_CRYPTO_OK) {
        return PSP_CRYPTO_ERR_SYSTEM;
    }

    /* Compute nullifier key commitment */
    st = psp_nullifier_v3_key_commitment(out_nk, PSP_TIER1_KEY_BYTES, nk_commit, sizeof(nk_commit));
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* Encode NotePublicKeyBundleV3 */
    st = psp_encode_note_bundle_v3(
        auth_scheme_id, auth_scheme_id_len,
        auth_public_key, auth_public_key_len,
        nk_commit,
        out_bundle, out_bundle_len, max_bundle_len
    );
    psp_secure_zero(nk_commit, sizeof(nk_commit));
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* Compute Note Commitment C */
    st = psp_coin_commitment_v3(
        params_id, params_id_len,
        out_bundle, *out_bundle_len,
        value,
        namespace_id, PSP_TIER1_NAMESPACE_BYTES,
        out_coin_id, PSP_TIER1_COIN_ID_BYTES,
        out_r_nf, PSP_TIER1_RNF_BYTES,
        out_rho_coin, PSP_TIER1_SALT_BYTES,
        out_commitment, PSP_TIER1_COMMITMENT_BYTES
    );
    return st;
}

int psp_tx_fields_v3_encode_single(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *namespace_id,
    const uint8_t *root,
    const uint8_t *nullifier,
    const uint8_t *state_head,
    const uint8_t *state_context_digest,
    const uint8_t *chain_id,
    const uint8_t *recipient_address,
    uint64_t withdraw_value,
    const uint8_t *relayer_address,
    const uint8_t *policy_id, size_t policy_id_len,
    uint64_t fee,
    const uint8_t *output_entropy,
    const uint8_t *output_commitment,
    uint8_t *out_tx_fields, size_t *out_tx_fields_len, size_t max_tx_fields_len) {
    size_t total_len, offset;
    uint8_t len16[2], len32[4], fee_bytes[8], withdraw_bytes[8];
    uint8_t payout_digest[PSP_TIER1_COMMITMENT_BYTES];
    const uint8_t *parts[11];
    size_t lengths[11];
    int st;

    if (params_id == NULL || params_id_len == 0 || params_id_len > 0xffff ||
        namespace_id == NULL || root == NULL || nullifier == NULL ||
        state_head == NULL || state_context_digest == NULL || chain_id == NULL ||
        recipient_address == NULL || relayer_address == NULL ||
        policy_id == NULL || policy_id_len == 0 || policy_id_len > 0xffff ||
        output_entropy == NULL || output_commitment == NULL ||
        out_tx_fields == NULL || out_tx_fields_len == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    write_u16_le(len16, (uint16_t)params_id_len);
    write_u64_le(fee_bytes, fee);
    write_u64_le(withdraw_bytes, withdraw_value);
    parts[0] = PSP_DOMAIN_TX_PAYOUT_CONTEXT_V3;
    lengths[0] = sizeof(PSP_DOMAIN_TX_PAYOUT_CONTEXT_V3) - 1u;
    parts[1] = &VERSION_V3; lengths[1] = 1u;
    parts[2] = chain_id; lengths[2] = PSP_TIER1_CHAIN_ID_BYTES;
    parts[3] = namespace_id; lengths[3] = PSP_TIER1_NAMESPACE_BYTES;
    parts[4] = len16; lengths[4] = sizeof(len16);
    parts[5] = params_id; lengths[5] = params_id_len;
    parts[6] = recipient_address; lengths[6] = PSP_TIER1_ADDRESS_BYTES;
    parts[7] = withdraw_bytes; lengths[7] = sizeof(withdraw_bytes);
    parts[8] = relayer_address; lengths[8] = PSP_TIER1_ADDRESS_BYTES;
    parts[9] = fee_bytes; lengths[9] = sizeof(fee_bytes);
    parts[10] = output_commitment; lengths[10] = PSP_TIER1_COMMITMENT_BYTES;
    st = psp_shake256_parts(parts, lengths, 11u, payout_digest, sizeof(payout_digest));
    if (st != PSP_CRYPTO_OK) {
        psp_secure_zero(payout_digest, sizeof(payout_digest));
        return st;
    }

    total_len = sizeof(PSP_DOMAIN_TX_FIELDS_V3) - 1u + 1u +
                2u + params_id_len + PSP_TIER1_NAMESPACE_BYTES +
                PSP_TIER1_COMMITMENT_BYTES + PSP_TIER1_NULLIFIER_BYTES +
                PSP_TIER1_STATE_HEAD_BYTES + PSP_TIER1_STATE_CONTEXT_BYTES +
                PSP_TIER1_CHAIN_ID_BYTES + PSP_TIER1_ADDRESS_BYTES + 8u +
                PSP_TIER1_ADDRESS_BYTES + 2u + policy_id_len + 8u +
                PSP_TIER1_ENTROPY_BYTES + 4u +
                PSP_TIER1_COMMITMENT_BYTES + PSP_TIER1_COMMITMENT_BYTES;
    if (total_len > max_tx_fields_len || total_len > PSP_TIER1_MAX_TX_FIELDS_BYTES) {
        psp_secure_zero(payout_digest, sizeof(payout_digest));
        return PSP_CRYPTO_ERR_OVERFLOW;
    }

    offset = 0;
    memcpy(out_tx_fields + offset, PSP_DOMAIN_TX_FIELDS_V3, sizeof(PSP_DOMAIN_TX_FIELDS_V3) - 1u);
    offset += sizeof(PSP_DOMAIN_TX_FIELDS_V3) - 1u;
    out_tx_fields[offset++] = VERSION_V3;
    memcpy(out_tx_fields + offset, len16, sizeof(len16)); offset += sizeof(len16);
    memcpy(out_tx_fields + offset, params_id, params_id_len); offset += params_id_len;
    memcpy(out_tx_fields + offset, namespace_id, PSP_TIER1_NAMESPACE_BYTES); offset += PSP_TIER1_NAMESPACE_BYTES;
    memcpy(out_tx_fields + offset, root, PSP_TIER1_COMMITMENT_BYTES); offset += PSP_TIER1_COMMITMENT_BYTES;
    memcpy(out_tx_fields + offset, nullifier, PSP_TIER1_NULLIFIER_BYTES); offset += PSP_TIER1_NULLIFIER_BYTES;
    memcpy(out_tx_fields + offset, state_head, PSP_TIER1_STATE_HEAD_BYTES); offset += PSP_TIER1_STATE_HEAD_BYTES;
    memcpy(out_tx_fields + offset, state_context_digest, PSP_TIER1_STATE_CONTEXT_BYTES); offset += PSP_TIER1_STATE_CONTEXT_BYTES;
    memcpy(out_tx_fields + offset, chain_id, PSP_TIER1_CHAIN_ID_BYTES); offset += PSP_TIER1_CHAIN_ID_BYTES;
    memcpy(out_tx_fields + offset, recipient_address, PSP_TIER1_ADDRESS_BYTES); offset += PSP_TIER1_ADDRESS_BYTES;
    memcpy(out_tx_fields + offset, withdraw_bytes, sizeof(withdraw_bytes)); offset += sizeof(withdraw_bytes);
    memcpy(out_tx_fields + offset, relayer_address, PSP_TIER1_ADDRESS_BYTES); offset += PSP_TIER1_ADDRESS_BYTES;
    write_u16_le(len16, (uint16_t)policy_id_len);
    memcpy(out_tx_fields + offset, len16, sizeof(len16)); offset += sizeof(len16);
    memcpy(out_tx_fields + offset, policy_id, policy_id_len); offset += policy_id_len;
    memcpy(out_tx_fields + offset, fee_bytes, sizeof(fee_bytes)); offset += sizeof(fee_bytes);
    memcpy(out_tx_fields + offset, output_entropy, PSP_TIER1_ENTROPY_BYTES); offset += PSP_TIER1_ENTROPY_BYTES;
    write_u32_le(len32, 1u);
    memcpy(out_tx_fields + offset, len32, sizeof(len32)); offset += sizeof(len32);
    memcpy(out_tx_fields + offset, output_commitment, PSP_TIER1_COMMITMENT_BYTES); offset += PSP_TIER1_COMMITMENT_BYTES;
    memcpy(out_tx_fields + offset, payout_digest, sizeof(payout_digest)); offset += sizeof(payout_digest);
    psp_secure_zero(payout_digest, sizeof(payout_digest));
    *out_tx_fields_len = offset;
    return PSP_CRYPTO_OK;
}


int psp_tx_digest_v3_candidate(
    const uint8_t *tx_fields, size_t tx_fields_len,
    uint8_t *out_tx_digest) {
    const uint8_t *parts[4];
    size_t lengths[4];
    uint8_t len32[4];

    if (tx_fields == NULL || tx_fields_len == 0 || out_tx_digest == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    write_u32_le(len32, (uint32_t)tx_fields_len);

    parts[0] = PSP_DOMAIN_TX_DIGEST_V3; lengths[0] = sizeof(PSP_DOMAIN_TX_DIGEST_V3) - 1u;
    parts[1] = &VERSION_V3; lengths[1] = 1u;
    parts[2] = len32; lengths[2] = 4u;
    parts[3] = tx_fields; lengths[3] = tx_fields_len;

    return psp_shake256_parts(parts, lengths, 4u, out_tx_digest, PSP_TIER1_DIGEST_BYTES);
}

int psp_tier1_create_spend_package(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *namespace_id,
    const uint8_t *input_bundle, size_t input_bundle_len,
    uint64_t input_value,
    const uint8_t *input_coin_id,
    const uint8_t *input_r_nf,
    const uint8_t *input_rho_coin,
    const uint8_t *input_nk,
    const uint8_t *recipient_bundle, size_t recipient_bundle_len,
    uint64_t output_value,
    uint64_t fee,
    const uint8_t *output_entropy,
    const uint8_t *commitment_root,
    const uint8_t *state_head,
    const uint8_t *state_context_digest,
    const uint8_t *chain_id,
    const uint8_t *recipient_address,
    uint64_t withdraw_value,
    const uint8_t *relayer_address,
    psp_tier1_spend_package_t *out_pkg) {
    uint8_t encoded_nk_commit[PSP_TIER1_KEY_BYTES];
    uint8_t derived_nk_commit[PSP_TIER1_KEY_BYTES];
    uint64_t total_out;
    int st;

    if (params_id == NULL || params_id_len == 0 || namespace_id == NULL ||
        input_bundle == NULL || input_bundle_len == 0 ||
        input_coin_id == NULL || input_r_nf == NULL || input_rho_coin == NULL ||
        input_nk == NULL || recipient_bundle == NULL || recipient_bundle_len == 0 ||
        output_entropy == NULL || commitment_root == NULL ||
        state_head == NULL || state_context_digest == NULL || chain_id == NULL ||
        recipient_address == NULL || relayer_address == NULL || out_pkg == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    /* Check conservation over integers, without uint64 wraparound. */
    if (output_value > UINT64_MAX - withdraw_value) return PSP_CRYPTO_ERR_ARGUMENT;
    total_out = output_value + withdraw_value;
    if (total_out > UINT64_MAX - fee) return PSP_CRYPTO_ERR_ARGUMENT;
    total_out += fee;
    if (total_out != input_value || withdraw_value != 0u) {
        /* This native helper does not execute external withdrawals; fail closed. */
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    /* 2. NK-possession authorization check: input_nk opens input_bundle's key commitment */
    st = psp_parse_bundle_key_commitment_v3(input_bundle, input_bundle_len, encoded_nk_commit);
    if (st != PSP_CRYPTO_OK) {
        return st;
    }
    st = psp_nullifier_v3_key_commitment(input_nk, PSP_TIER1_KEY_BYTES, derived_nk_commit, sizeof(derived_nk_commit));
    if (st != PSP_CRYPTO_OK) {
        psp_secure_zero(encoded_nk_commit, sizeof(encoded_nk_commit));
        return st;
    }
    if (psp_constant_time_memcmp(encoded_nk_commit, derived_nk_commit, PSP_TIER1_KEY_BYTES) != 0) {
        psp_secure_zero(encoded_nk_commit, sizeof(encoded_nk_commit));
        psp_secure_zero(derived_nk_commit, sizeof(derived_nk_commit));
        return PSP_CRYPTO_ERR_ARGUMENT;
    }
    psp_secure_zero(encoded_nk_commit, sizeof(encoded_nk_commit));
    psp_secure_zero(derived_nk_commit, sizeof(derived_nk_commit));

    /* 3. Compute Input Commitment C_in */
    st = psp_coin_commitment_v3(
        params_id, params_id_len,
        input_bundle, input_bundle_len,
        input_value,
        namespace_id, PSP_TIER1_NAMESPACE_BYTES,
        input_coin_id, PSP_TIER1_COIN_ID_BYTES,
        input_r_nf, PSP_TIER1_RNF_BYTES,
        input_rho_coin, PSP_TIER1_SALT_BYTES,
        out_pkg->input_commitment, PSP_TIER1_COMMITMENT_BYTES
    );
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* 4. Compute Input Nullifier N_V3 */
    st = psp_nullifier_v3(
        input_nk, PSP_TIER1_KEY_BYTES,
        namespace_id, PSP_TIER1_NAMESPACE_BYTES,
        params_id, params_id_len,
        input_bundle, input_bundle_len,
        out_pkg->input_commitment, PSP_TIER1_COMMITMENT_BYTES,
        input_coin_id, PSP_TIER1_COIN_ID_BYTES,
        input_r_nf, PSP_TIER1_RNF_BYTES,
        out_pkg->input_nullifier, PSP_TIER1_NULLIFIER_BYTES
    );
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* 5. Derive Output Identity (coin_id, r_nf) */
    st = psp_output_identity_v3(
        params_id, params_id_len,
        namespace_id,
        out_pkg->input_nullifier,
        out_pkg->input_commitment,
        input_coin_id,
        input_r_nf,
        input_bundle, input_bundle_len,
        recipient_bundle, recipient_bundle_len,
        output_entropy,
        0u, /* slot 0 */
        out_pkg->output_coin_id,
        out_pkg->output_r_nf
    );
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* 6. Sample fresh output rho_coin from OS CSPRNG */
    if (psp_random_bytes(out_pkg->output_rho_coin, PSP_TIER1_SALT_BYTES) != PSP_CRYPTO_OK) {
        return PSP_CRYPTO_ERR_SYSTEM;
    }

    /* 7. Compute Output Commitment C_out */
    st = psp_coin_commitment_v3(
        params_id, params_id_len,
        recipient_bundle, recipient_bundle_len,
        output_value,
        namespace_id, PSP_TIER1_NAMESPACE_BYTES,
        out_pkg->output_coin_id, PSP_TIER1_COIN_ID_BYTES,
        out_pkg->output_r_nf, PSP_TIER1_RNF_BYTES,
        out_pkg->output_rho_coin, PSP_TIER1_SALT_BYTES,
        out_pkg->output_commitment, PSP_TIER1_COMMITMENT_BYTES
    );
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* 8. Encode canonical TxFieldsV3Candidate */
    st = psp_tx_fields_v3_encode_single(
        params_id, params_id_len,
        namespace_id,
        commitment_root,
        out_pkg->input_nullifier,
        state_head,
        state_context_digest,
        chain_id,
        recipient_address,
        withdraw_value,
        relayer_address,
        PSP_POLICY_NK_POSSESSION_V3, sizeof(PSP_POLICY_NK_POSSESSION_V3) - 1u,
        fee,
        output_entropy,
        out_pkg->output_commitment,
        out_pkg->encoded_tx,
        &out_pkg->encoded_tx_len,
        sizeof(out_pkg->encoded_tx)
    );
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    /* 9. Compute transaction digest */
    st = psp_tx_digest_v3_candidate(
        out_pkg->encoded_tx,
        out_pkg->encoded_tx_len,
        out_pkg->tx_digest
    );
    return st;
}

int psp_tier1_verify_spend_package(
    const psp_tier1_spend_package_t *pkg,
    const uint8_t *expected_input_commitment,
    const uint8_t *expected_input_nullifier) {
    uint8_t recomputed_digest[PSP_TIER1_DIGEST_BYTES];
    int st;

    if (pkg == NULL || expected_input_commitment == NULL || expected_input_nullifier == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    if (psp_constant_time_memcmp(pkg->input_commitment, expected_input_commitment, PSP_TIER1_COMMITMENT_BYTES) != 0 ||
        psp_constant_time_memcmp(pkg->input_nullifier, expected_input_nullifier, PSP_TIER1_NULLIFIER_BYTES) != 0) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    st = psp_tx_digest_v3_candidate(pkg->encoded_tx, pkg->encoded_tx_len, recomputed_digest);
    if (st != PSP_CRYPTO_OK) {
        return st;
    }

    if (psp_constant_time_memcmp(pkg->tx_digest, recomputed_digest, PSP_TIER1_DIGEST_BYTES) != 0) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    return PSP_CRYPTO_OK;
}

int psp_derive_keys_v3(
    const uint8_t sk_spend[48],
    uint8_t ak_out[48],
    uint8_t nk_out[48],
    uint8_t pk_owner_out[48]) {
    const uint8_t *parts[3];
    size_t lengths[3];

    if (sk_spend == NULL || ak_out == NULL || nk_out == NULL || pk_owner_out == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    /* 1. ak = SHAKE256-384("0PSP_AK_DERIVE_V3" || sk_spend) */
    parts[0] = PSP_DOMAIN_AK_V3;
    lengths[0] = sizeof(PSP_DOMAIN_AK_V3) - 1u;
    parts[1] = sk_spend;
    lengths[1] = 48u;
    psp_shake256_parts(parts, lengths, 2, ak_out, 48u);

    /* 2. nk = SHAKE256-384("0PSP_NK_DERIVE_V3" || sk_spend) */
    parts[0] = PSP_DOMAIN_NK_V3;
    lengths[0] = sizeof(PSP_DOMAIN_NK_V3) - 1u;
    parts[1] = sk_spend;
    lengths[1] = 48u;
    psp_shake256_parts(parts, lengths, 2, nk_out, 48u);

    /* 3. pk_owner = SHAKE256-384("0PSP_OWNER_V3" || ak || nk) */
    parts[0] = PSP_DOMAIN_OWNER_V3;
    lengths[0] = sizeof(PSP_DOMAIN_OWNER_V3) - 1u;
    parts[1] = ak_out;
    lengths[1] = 48u;
    parts[2] = nk_out;
    lengths[2] = 48u;
    psp_shake256_parts(parts, lengths, 3, pk_owner_out, 48u);

    return PSP_CRYPTO_OK;
}

int psp_compute_spend_auth_token_v3(
    const uint8_t sk_spend[48],
    const uint8_t tx_digest[64],
    const uint8_t commitment[48],
    uint8_t auth_token_out[48]) {
    const uint8_t *parts[3];
    size_t lengths[3];

    if (sk_spend == NULL || tx_digest == NULL || commitment == NULL || auth_token_out == NULL) {
        return PSP_CRYPTO_ERR_ARGUMENT;
    }

    parts[0] = PSP_DOMAIN_SPEND_AUTH_V3;
    lengths[0] = sizeof(PSP_DOMAIN_SPEND_AUTH_V3) - 1u;
    parts[1] = tx_digest;
    lengths[1] = 64u;
    parts[2] = commitment;
    lengths[2] = 48u;

    return psp_hmac_sha3_384_parts(sk_spend, 48u, parts, lengths, 3, auth_token_out);
}

int psp_verify_spend_auth_token_v3(
    const uint8_t sk_spend[48],
    const uint8_t tx_digest[64],
    const uint8_t commitment[48],
    const uint8_t auth_token[48]) {
    uint8_t expected[48];
    uint8_t diff = 0;
    int st;

    if (sk_spend == NULL || tx_digest == NULL || commitment == NULL || auth_token == NULL) {
        return 0;
    }

    st = psp_compute_spend_auth_token_v3(sk_spend, tx_digest, commitment, expected);
    if (st != PSP_CRYPTO_OK) {
        return 0;
    }

    for (size_t i = 0; i < 48; ++i) {
        diff |= (uint8_t)(expected[i] ^ auth_token[i]);
    }
    psp_secure_zero(expected, sizeof(expected));

    return (diff == 0) ? 1 : 0;
}
