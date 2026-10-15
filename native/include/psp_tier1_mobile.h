#ifndef PSP_TIER1_MOBILE_H
#define PSP_TIER1_MOBILE_H

#include "psp_keccak.h"
#include "psp_random.h"
#include "psp_nullifier_v3.h"
#include "psp_coin_commitment_v3.h"
#include "psp_merkle_tree_v3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSP_TIER1_COIN_ID_BYTES 32u
#define PSP_TIER1_RNF_BYTES 36u
#define PSP_TIER1_SALT_BYTES 36u
#define PSP_TIER1_KEY_BYTES 48u
#define PSP_TIER1_COMMITMENT_BYTES 48u
#define PSP_TIER1_NULLIFIER_BYTES 48u
#define PSP_TIER1_NAMESPACE_BYTES 48u
#define PSP_TIER1_ENTROPY_BYTES 32u
#define PSP_TIER1_DIGEST_BYTES 64u
#define PSP_TIER1_STATE_HEAD_BYTES 48u
#define PSP_TIER1_STATE_CONTEXT_BYTES 64u
#define PSP_TIER1_MAX_BUNDLE_BYTES 65535u
#define PSP_TIER1_MAX_TX_FIELDS_BYTES 4096u

/*
 * Canonical domain separators for V3 mobile tier 1 operations
 */
extern const uint8_t PSP_DOMAIN_OUTPUT_COIN_ID_V3[];
extern const uint8_t PSP_DOMAIN_OUTPUT_RNF_V3[];
extern const uint8_t PSP_DOMAIN_NOTE_BUNDLE_V3[];
extern const uint8_t PSP_DOMAIN_TX_FIELDS_V3[];
extern const uint8_t PSP_DOMAIN_TX_DIGEST_V3[];
extern const uint8_t PSP_POLICY_NK_POSSESSION_V3[];

/*
 * Tier 1 Mobile Edge Spend Package.
 * Contains the public handoff tuple Req_Tier1 and the recipient's output secrets
 * for secure local wallet tracking.
 */
typedef struct {
    uint8_t input_commitment[PSP_TIER1_COMMITMENT_BYTES];
    uint8_t input_nullifier[PSP_TIER1_NULLIFIER_BYTES];
    uint8_t output_commitment[PSP_TIER1_COMMITMENT_BYTES];
    uint8_t output_coin_id[PSP_TIER1_COIN_ID_BYTES];
    uint8_t output_r_nf[PSP_TIER1_RNF_BYTES];
    uint8_t output_rho_coin[PSP_TIER1_SALT_BYTES];
    uint8_t tx_digest[PSP_TIER1_DIGEST_BYTES];
    size_t encoded_tx_len;
    uint8_t encoded_tx[PSP_TIER1_MAX_TX_FIELDS_BYTES];
} psp_tier1_spend_package_t;

/*
 * Deterministic transfer output identity derivation candidate.
 * Derives output coin_id (32 bytes) and output r_nf (36 bytes)
 * from parent nullifier, parent commitment, recipient bundle, and entropy.
 *
 * Matching Python derive_output_identity_v3_candidate and Rust spend_v3.rs.
 */
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
    uint8_t *out_r_nf);

/*
 * Canonical NotePublicKeyBundleV3 encoder.
 * Encodes:
 *   "0PSP-NOTE-PK-BUNDLE-v3" || 0x03 ||
 *   u16le(auth_scheme_id_len) || auth_scheme_id ||
 *   u32le(auth_pk_len) || auth_pk ||
 *   u16le(48) || nullifier_key_commitment[48]
 */
int psp_encode_note_bundle_v3(
    const uint8_t *auth_scheme_id, size_t auth_scheme_id_len,
    const uint8_t *auth_public_key, size_t auth_public_key_len,
    const uint8_t *nullifier_key_commitment,
    uint8_t *out_bundle, size_t *out_bundle_len, size_t max_bundle_len);

/*
 * Extract the 48-byte nullifier_key_commitment from a canonical NotePublicKeyBundleV3.
 */
int psp_parse_bundle_key_commitment_v3(
    const uint8_t *bundle, size_t bundle_len,
    uint8_t *out_nk_commitment);

/*
 * Generate a fresh random note for local mobile wallet storage using OS CSPRNG.
 * Produces: nk, coin_id, r_nf, rho_coin, canonical bundle, and note commitment C.
 */
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
    uint8_t *out_commitment);

/*
 * Encode canonical TxFieldsV3Candidate for single-output transactions.
 */
int psp_tx_fields_v3_encode_single(
    const uint8_t *params_id, size_t params_id_len,
    const uint8_t *namespace_id,
    const uint8_t *root,
    const uint8_t *nullifier,
    const uint8_t *state_head,
    const uint8_t *state_context_digest,
    const uint8_t *policy_id, size_t policy_id_len,
    uint64_t fee,
    const uint8_t *output_entropy,
    const uint8_t *output_commitment,
    uint8_t *out_tx_fields, size_t *out_tx_fields_len, size_t max_tx_fields_len);

/*
 * Compute the 64-byte canonical transaction digest from encoded TxFieldsV3:
 *   SHAKE256-512("0PSP-TX-DIGEST-v3-CANDIDATE-v2-SHAKE256" || 0x03 || u32le(len) || fields)
 */
int psp_tx_digest_v3_candidate(
    const uint8_t *tx_fields, size_t tx_fields_len,
    uint8_t *out_tx_digest);

/*
 * Complete Mobile Tier 1 Spend Package Creator.
 *
 * Runs entirely on the mobile device in constant-time with zero heap allocation:
 * 1. Checks value conservation: input_value == output_value + fee (128-bit overflow-safe).
 * 2. Checks nullifier key authorization: input_nk opens input_bundle's key commitment.
 * 3. Computes input commitment C_in and nullifier N_V3.
 * 4. Derives output identity (coin_id_out, r_nf_out) and output commitment C_out.
 * 5. Generates canonical TxFieldsV3Candidate and computes tx_digest.
 * 6. Returns the complete psp_tier1_spend_package_t.
 */
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
    psp_tier1_spend_package_t *out_pkg);

/*
 * Verify that a generated Tier 1 spend package matches expected commitments and nullifiers.
 */
int psp_tier1_verify_spend_package(
    const psp_tier1_spend_package_t *pkg,
    const uint8_t *expected_input_commitment,
    const uint8_t *expected_input_nullifier);

#ifdef __cplusplus
}
#endif

#endif /* PSP_TIER1_MOBILE_H */
