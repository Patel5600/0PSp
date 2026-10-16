//! Experimental one-input/one-output V3 spend candidate relation.
//!
//! Enforces, over one witness:
//! - canonical TxFieldsV3Candidate and the fixed NK-possession policy ID;
//! - BundleV3 key-commitment opening, CommitV3 opening, and same-key NullifierV3;
//! - depth-63 namespace-bound commitment membership against the transaction root;
//! - anchor/index-derived output identity and the output's CommitV3 opening;
//! - exact one-output transaction binding and u64 value conservation.
//!
//! It does NOT authenticate the root/state head, prove finalized consensus, enforce
//! an atomic nullifier/commitment transition, authenticate intended-payee identity,
//! or establish that OpenVM v2.0.2 meets the project 128-bit PQ/witness-hiding target.
//! Those are separate host trust, ledger, proof-system, and review gates.

use super::{
    coin_commitment_v3, constant_time_eq, hmac_sha3_384, nullifier_key_commitment_v3,
    nullifier_message_v3, parse_bundle_key_commitment, shake256_384, shake256_512, Reader, COIN_ID_BYTES,
    HASH_BYTES, KEY_BYTES, RHO_BYTES, R_NF_BYTES,
};

pub const SPEND_WITNESS_MAGIC: &[u8] =
    b"0PSP-OPENVM-V3-SPEND-CANDIDATE-WITNESS-v1";
pub const TX_FIELDS_DOMAIN: &[u8] = b"0PSP-TX-FIELDS-v3-CANDIDATE-v2-SHAKE256";
pub const TX_DIGEST_DOMAIN: &[u8] = b"0PSP-TX-DIGEST-v3-CANDIDATE-v2-SHAKE256";
pub const TX_VERSION: u8 = 0x03;
pub const SPEND_POLICY_NK: &[u8] = b"0PSP-V3-NK-POSSESSION-CANDIDATE-v1";
pub const PUBLIC_STATEMENT_DOMAIN: &[u8] =
    b"0PSP-OPENVM-V3-SPEND-PUBLIC-STATEMENT-CANDIDATE-v2";
pub const TREE_DEPTH: usize = 63;
pub const MAX_TX_BYTES: usize = 1_000_000;
pub const MAX_BUNDLE_BYTES: usize = 65_535;
pub const MAX_WITNESS_BYTES: usize = 2_000_000;

const EMPTY_LEAF_DOMAIN: &[u8] = b"0PSP-COMMITMENT-EMPTY-LEAF-v1-SHAKE256";
const LEAF_DOMAIN: &[u8] = b"0PSP-COMMITMENT-LEAF-v1-SHAKE256";
const DOM_MERKLE_NODE: &[u8] = b"0PSP-COMMITMENT-NODE-v1-SHAKE256";
const OUTPUT_COIN_ID_DOMAIN: &[u8] = b"0PSP-OUTPUT-COIN-ID-v3-anchor-index-candidate";
const OUTPUT_RNF_DOMAIN: &[u8] = b"0PSP-OUTPUT-RNF-v3-anchor-index-candidate";
const OUTPUT_ID_VERSION: u8 = 0x03;
const OUTPUT_ENTROPY_BYTES: usize = 32;
const STATE_CONTEXT_BYTES: usize = 64;

#[derive(Clone)]
struct TxFields {
    params_id: Vec<u8>,
    namespace: [u8; HASH_BYTES],
    root: [u8; HASH_BYTES],
    nullifier: [u8; HASH_BYTES],
    state_head: [u8; HASH_BYTES],
    state_context_digest: [u8; STATE_CONTEXT_BYTES],
    policy_id: Vec<u8>,
    fee: u64,
    output_entropy: [u8; OUTPUT_ENTROPY_BYTES],
    output_commitment: [u8; HASH_BYTES],
    encoded: Vec<u8>,
}

fn encode_tx(tx: &TxFields) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        TX_FIELDS_DOMAIN.len() + 1 + 2 + tx.params_id.len() + 4 * HASH_BYTES
            + STATE_CONTEXT_BYTES + 2 + tx.policy_id.len() + 8 + OUTPUT_ENTROPY_BYTES + 4 + HASH_BYTES,
    );
    out.extend_from_slice(TX_FIELDS_DOMAIN);
    out.push(TX_VERSION);
    out.extend_from_slice(&(tx.params_id.len() as u16).to_le_bytes());
    out.extend_from_slice(&tx.params_id);
    out.extend_from_slice(&tx.namespace);
    out.extend_from_slice(&tx.root);
    out.extend_from_slice(&tx.nullifier);
    out.extend_from_slice(&tx.state_head);
    out.extend_from_slice(&tx.state_context_digest);
    out.extend_from_slice(&(tx.policy_id.len() as u16).to_le_bytes());
    out.extend_from_slice(&tx.policy_id);
    out.extend_from_slice(&tx.fee.to_le_bytes());
    out.extend_from_slice(&tx.output_entropy);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&tx.output_commitment);
    out
}

fn parse_tx(encoded: &[u8]) -> Result<TxFields, String> {
    if encoded.is_empty() || encoded.len() > MAX_TX_BYTES {
        return Err("TxFieldsV3 length outside configured bounds".into());
    }
    let mut r = Reader::new(encoded);
    if r.take(TX_FIELDS_DOMAIN.len(), "TxFieldsV3 domain")? != TX_FIELDS_DOMAIN {
        return Err("TxFieldsV3 domain mismatch".into());
    }
    if r.take(1, "TxFieldsV3 version")? != [TX_VERSION] {
        return Err("TxFieldsV3 version mismatch".into());
    }
    let params_id = r.vec_u16("params_id")?;
    let namespace = r.fixed::<HASH_BYTES>("namespace_id")?;
    let root = r.fixed::<HASH_BYTES>("commitment_root")?;
    let nullifier = r.fixed::<HASH_BYTES>("input_nullifier")?;
    let state_head = r.fixed::<HASH_BYTES>("ledger_state_head")?;
    let state_context_digest = r.fixed::<STATE_CONTEXT_BYTES>("state_context_digest")?;
    let policy_id = r.vec_u16("authorization_policy_id")?;
    let fee = r.u64_le("fee")?;
    let output_entropy = r.fixed::<OUTPUT_ENTROPY_BYTES>("output_entropy")?;
    let output_count = r.u32_le("output_count")?;
    if output_count != 1 {
        return Err("this proof profile requires exactly one output".into());
    }
    let output_commitment = r.fixed::<HASH_BYTES>("output commitment")?;
    r.finish("TxFieldsV3")?;
    let tx = TxFields {
        params_id, namespace, root, nullifier, state_head, state_context_digest, policy_id, fee,
        output_entropy, output_commitment, encoded: encoded.to_vec(),
    };
    if tx.encode() != encoded {
        return Err("TxFieldsV3 is not canonical".into());
    }
    if tx.policy_id != SPEND_POLICY_NK {
        return Err("TxFieldsV3 does not select the exact NK-possession policy".into());
    }
    Ok(tx)
}

impl TxFields {
    fn encode(&self) -> Vec<u8> {
        encode_tx(self)
    }

    fn digest(&self) -> [u8; 64] {
        let mut preimage = Vec::with_capacity(TX_DIGEST_DOMAIN.len() + 1 + 4 + self.encoded.len());
        preimage.extend_from_slice(TX_DIGEST_DOMAIN);
        preimage.push(TX_VERSION);
        preimage.extend_from_slice(&(self.encoded.len() as u32).to_le_bytes());
        preimage.extend_from_slice(&self.encoded);
        shake256_512(&preimage)
    }
}

fn leaf_hash(namespace: &[u8; HASH_BYTES], index: u64, commitment: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut preimage = Vec::with_capacity(LEAF_DOMAIN.len() + 1 + HASH_BYTES + 8 + HASH_BYTES);
    preimage.extend_from_slice(LEAF_DOMAIN);
    preimage.push(0x01);
    preimage.extend_from_slice(namespace);
    preimage.extend_from_slice(&index.to_be_bytes());
    preimage.extend_from_slice(commitment);
    shake256_384(&preimage)
}

fn node_hash(
    namespace: &[u8; HASH_BYTES],
    level: usize,
    left: &[u8; HASH_BYTES],
    right: &[u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    let mut preimage = Vec::with_capacity(DOM_MERKLE_NODE.len() + 1 + 4 + 3 * HASH_BYTES);
    preimage.extend_from_slice(DOM_MERKLE_NODE);
    preimage.push(MERKLE_NODE_FORMAT_VERSION);
    preimage.extend_from_slice(&(level as u32).to_be_bytes());
    preimage.extend_from_slice(namespace);
    preimage.extend_from_slice(left);
    preimage.extend_from_slice(right);
    shake256_384(&preimage)
}

fn verify_membership(
    namespace: &[u8; HASH_BYTES],
    root: &[u8; HASH_BYTES],
    index: u64,
    commitment: &[u8; HASH_BYTES],
    siblings: &[[u8; HASH_BYTES]],
) -> bool {
    if index >= (1u64 << TREE_DEPTH) || siblings.len() != TREE_DEPTH {
        return false;
    }
    let mut current = leaf_hash(namespace, index, commitment);
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((index >> level) & 1) == 1 {
            node_hash(namespace, level, sibling, &current)
        } else {
            node_hash(namespace, level, &current, sibling)
        };
    }
    constant_time_eq(&current, root)
}

fn derive_output_identity(
    params_id: &[u8],
    namespace: &[u8; HASH_BYTES],
    parent_nullifier: &[u8; HASH_BYTES],
    parent_commitment: &[u8; HASH_BYTES],
    parent_coin_id: &[u8; COIN_ID_BYTES],
    parent_r_nf: &[u8; R_NF_BYTES],
    parent_bundle: &[u8],
    recipient_bundle: &[u8],
    entropy: &[u8; OUTPUT_ENTROPY_BYTES],
) -> Result<([u8; COIN_ID_BYTES], [u8; R_NF_BYTES]), String> {
    if params_id.is_empty() || params_id.len() > u16::MAX as usize {
        return Err("params_id length invalid for output identity".into());
    }
    if parent_bundle.is_empty() || parent_bundle.len() > MAX_BUNDLE_BYTES
        || recipient_bundle.is_empty() || recipient_bundle.len() > MAX_BUNDLE_BYTES
    {
        return Err("parent or recipient BundleV3 length outside configured bounds".into());
    }
    parse_bundle_key_commitment(parent_bundle)?;
    parse_bundle_key_commitment(recipient_bundle)?;

    let encode = |domain: &[u8]| {
        let mut preimage = Vec::with_capacity(
            domain.len() + 1 + 2 + params_id.len() + HASH_BYTES + 2 + HASH_BYTES
                + COIN_ID_BYTES + R_NF_BYTES + 4 + parent_bundle.len()
                + 4 + recipient_bundle.len() + OUTPUT_ENTROPY_BYTES + 2,
        );
        preimage.extend_from_slice(domain);
        preimage.push(OUTPUT_ID_VERSION);
        preimage.extend_from_slice(&(params_id.len() as u16).to_le_bytes());
        preimage.extend_from_slice(params_id);
        preimage.extend_from_slice(namespace);
        preimage.extend_from_slice(parent_nullifier);
        preimage.extend_from_slice(&(HASH_BYTES as u16).to_le_bytes());
        preimage.extend_from_slice(parent_commitment);
        preimage.extend_from_slice(parent_coin_id);
        preimage.extend_from_slice(parent_r_nf);
        preimage.extend_from_slice(&(parent_bundle.len() as u32).to_le_bytes());
        preimage.extend_from_slice(parent_bundle);
        preimage.extend_from_slice(&(recipient_bundle.len() as u32).to_le_bytes());
        preimage.extend_from_slice(recipient_bundle);
        preimage.extend_from_slice(entropy);
        // This profile supports one output, whose canonical transaction slot is zero.
        preimage.extend_from_slice(&0u16.to_be_bytes());
        preimage
    };

    let coin_hash = shake256_384(&encode(OUTPUT_COIN_ID_DOMAIN));
    let r_nf_hash = shake256_384(&encode(OUTPUT_RNF_DOMAIN));
    let mut coin_id = [0u8; COIN_ID_BYTES];
    coin_id.copy_from_slice(&coin_hash[..COIN_ID_BYTES]);
    let mut r_nf = [0u8; R_NF_BYTES];
    r_nf.copy_from_slice(&r_nf_hash[..R_NF_BYTES]);
    Ok((coin_id, r_nf))
}

/// Verify the complete one-input/one-output candidate predicate and reveal only
/// a transaction digest derived from canonical public TxFieldsV3Candidate bytes.
pub fn verify_v3_spend_witness(witness: &[u8]) -> Result<[u8; 64], String> {
    if witness.is_empty() || witness.len() > MAX_WITNESS_BYTES {
        return Err("V3 spend witness length outside configured bounds".into());
    }
    let mut r = Reader::new(witness);
    if r.take(SPEND_WITNESS_MAGIC.len(), "V3 spend witness magic")? != SPEND_WITNESS_MAGIC {
        return Err("V3 spend witness magic mismatch".into());
    }
    let tx_bytes = r.vec_u32("TxFieldsV3", MAX_TX_BYTES)?;
    let tx = parse_tx(&tx_bytes)?;
    let input_bundle = r.vec_u32("input BundleV3", MAX_BUNDLE_BYTES)?;
    let input_value = r.u64_le("input value")?;
    let input_coin_id = r.fixed::<COIN_ID_BYTES>("input coin_id")?;
    let input_r_nf = r.fixed::<R_NF_BYTES>("input r_nf")?;
    let input_rho = r.fixed::<RHO_BYTES>("input rho_C")?;
    let input_nk = r.fixed::<KEY_BYTES>("input nullifier key")?;
    let leaf_index = r.u64_le("input leaf index")?;
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        siblings.push(r.fixed::<HASH_BYTES>("Merkle sibling")?);
    }
    let output_bundle = r.vec_u32("output BundleV3", MAX_BUNDLE_BYTES)?;
    let output_value = r.u64_le("output value")?;
    let output_rho = r.fixed::<RHO_BYTES>("output rho_C")?;
    r.finish("V3 spend witness")?;

    if input_value < tx.fee {
        return Err("input value is below the transaction fee".into());
    }
    if input_bundle.is_empty() || input_bundle.len() > MAX_BUNDLE_BYTES {
        return Err("input BundleV3 length outside configured bounds".into());
    }

    let encoded_nk_commitment = parse_bundle_key_commitment(&input_bundle)?;
    let derived_nk_commitment = nullifier_key_commitment_v3(&input_nk);
    if !constant_time_eq(&encoded_nk_commitment, &derived_nk_commitment) {
        return Err("input nk does not open the exact input BundleV3 key commitment".into());
    }

    let input_commitment = coin_commitment_v3(
        &tx.params_id, &input_bundle, input_value, &tx.namespace,
        &input_coin_id, &input_r_nf, &input_rho,
    )?;
    if !verify_membership(&tx.namespace, &tx.root, leaf_index, &input_commitment, &siblings) {
        return Err("input CommitV3 is not a member of TxFieldsV3 commitment_root".into());
    }

    let input_nullifier_message = nullifier_message_v3(
        &tx.params_id, &tx.namespace, &input_bundle, &input_commitment,
        &input_coin_id, &input_r_nf,
    )?;
    let input_nullifier = hmac_sha3_384(&input_nk, &input_nullifier_message);
    if !constant_time_eq(&input_nullifier, &tx.nullifier) {
        return Err("calculated input NullifierV3 does not match TxFieldsV3 input nullifier".into());
    }

    let (output_coin_id, output_r_nf) = derive_output_identity(
        &tx.params_id, &tx.namespace, &input_nullifier, &input_commitment,
        &input_coin_id, &input_r_nf, &input_bundle, &output_bundle, &tx.output_entropy,
    )?;
    let output_commitment = coin_commitment_v3(
        &tx.params_id, &output_bundle, output_value, &tx.namespace,
        &output_coin_id, &output_r_nf, &output_rho,
    )?;
    if !constant_time_eq(&output_commitment, &tx.output_commitment) {
        return Err("derived output identity/CommitV3 does not match the exact TxFieldsV3 output".into());
    }

    // Use u128 arithmetic so an otherwise valid u64 addition cannot wrap.
    let total_out = u128::from(output_value) + u128::from(tx.fee);
    if u128::from(input_value) != total_out {
        return Err("V3 spend violates input = output + fee value conservation".into());
    }

    let tx_digest = tx.digest();
    let mut public_statement = Vec::with_capacity(PUBLIC_STATEMENT_DOMAIN.len() + 1 + HASH_BYTES);
    public_statement.extend_from_slice(PUBLIC_STATEMENT_DOMAIN);
    public_statement.push(TX_VERSION);
    public_statement.extend_from_slice(&tx_digest);
    let public_digest = shake256_512(&public_statement);
    Ok(public_digest)
}

// ============================================================================
// 0PSP 2-Tier Post-Quantum Key Hierarchy & Spend Relation (Audit Milestone 1)
// ============================================================================

pub const DOM_AK_V3: &[u8] = b"0PSP_AK_DERIVE_V3";
pub const DOM_NK_V3: &[u8] = b"0PSP_NK_DERIVE_V3";
pub const DOM_OWNER_V3: &[u8] = b"0PSP_OWNER_V3";
pub const DOM_COMMIT_V3: &[u8] = b"0PSP_COMMIT_V3";
pub const DOM_NULLIFIER_V3: &[u8] = b"0PSP_NULLIFIER_V3";
// Shared by both candidate paths so leaf/node preimages match the Python/C tree codec.
const MERKLE_NODE_FORMAT_VERSION: u8 = 0x01;
pub const DOM_TX_BIND_V3: &[u8] = b"0PSP_TX_STATEMENT_V3";
pub const DOM_SPEND_AUTH_V3: &[u8] = b"0PSP_SPEND_AUTH_V3";

pub const MERKLE_DEPTH_32: usize = 32;

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicStatementV3 {
    pub param_id: [u8; 32],
    pub namespace_id: [u8; HASH_BYTES],
    pub anchor_root: [u8; HASH_BYTES],
    pub nullifier: [u8; HASH_BYTES],
    pub out_commitment: [u8; HASH_BYTES],
    pub tx_context_digest: [u8; HASH_BYTES], // Binds recipient, relayer, fee, chain_id
    pub fee: u64,
    pub withdraw_value: u64,
}

#[repr(C)]
pub struct PrivateWitnessV3 {
    pub sk_spend: [u8; HASH_BYTES], // Master spend secret (Custody Authorization)
    pub value_in: u64,
    pub coin_id_in: [u8; 32],
    pub salt_in: [u8; 32],
    pub merkle_path: [[u8; HASH_BYTES]; MERKLE_DEPTH_32],
    pub leaf_index: u32,
    pub pk_owner_out: [u8; HASH_BYTES],
    pub value_out: u64,
    pub coin_id_out: [u8; 32],
    pub salt_out: [u8; 32],
}

/// Verify the full 2-tier key-separated spend relation with Depth-32 Merkle verification,
/// same-witness nullifier binding, and value conservation.
pub fn verify_spend_relation_v3(
    pub_stmt: &PublicStatementV3,
    wit: &PrivateWitnessV3,
) -> Result<[u8; HASH_BYTES], String> {
    // 1. Key Hierarchy Derivation (Eliminates NOAUTH & V2 Sender-Linkability)
    let mut ak_preimage = Vec::with_capacity(DOM_AK_V3.len() + HASH_BYTES);
    ak_preimage.extend_from_slice(DOM_AK_V3);
    ak_preimage.extend_from_slice(&wit.sk_spend);
    let ak = shake256_384(&ak_preimage);

    let mut nk_preimage = Vec::with_capacity(DOM_NK_V3.len() + HASH_BYTES);
    nk_preimage.extend_from_slice(DOM_NK_V3);
    nk_preimage.extend_from_slice(&wit.sk_spend);
    let nk = shake256_384(&nk_preimage);

    let mut owner_preimage = Vec::with_capacity(DOM_OWNER_V3.len() + 2 * HASH_BYTES);
    owner_preimage.extend_from_slice(DOM_OWNER_V3);
    owner_preimage.extend_from_slice(&ak);
    owner_preimage.extend_from_slice(&nk);
    let pk_owner_in = shake256_384(&owner_preimage);

    // 2. Input Note Commitment Opening
    let val_in_bytes = wit.value_in.to_le_bytes();
    let mut c_in_preimage = Vec::with_capacity(
        DOM_COMMIT_V3.len() + 32 + HASH_BYTES + HASH_BYTES + 8 + 32 + 32,
    );
    c_in_preimage.extend_from_slice(DOM_COMMIT_V3);
    c_in_preimage.extend_from_slice(&pub_stmt.param_id);
    c_in_preimage.extend_from_slice(&pub_stmt.namespace_id);
    c_in_preimage.extend_from_slice(&pk_owner_in);
    c_in_preimage.extend_from_slice(&val_in_bytes);
    c_in_preimage.extend_from_slice(&wit.coin_id_in);
    c_in_preimage.extend_from_slice(&wit.salt_in);
    let c_in = shake256_384(&c_in_preimage);

    // 3. Same-Witness Recipient-Keyed V3 Nullifier Binding
    // Bind the protocol version and parameter set explicitly, in addition to the
    // namespace and commitment. The fixed-width param_id is exactly 32 bytes.
    let mut nf_data =
        Vec::with_capacity(DOM_NULLIFIER_V3.len() + 1 + 32 + HASH_BYTES + HASH_BYTES);
    nf_data.extend_from_slice(DOM_NULLIFIER_V3);
    nf_data.push(TX_VERSION);
    nf_data.extend_from_slice(&pub_stmt.param_id);
    nf_data.extend_from_slice(&pub_stmt.namespace_id);
    nf_data.extend_from_slice(&c_in);
    let expected_nf = hmac_sha3_384(&nk, &nf_data);
    if !constant_time_eq(&expected_nf, &pub_stmt.nullifier) {
        return Err("ERR_NULLIFIER_MISMATCH".into());
    }

    // 4. Authenticated Merkle Path Verification up to anchor_root (Depth 32)
    // Use the exact active Merkle leaf/node encoding. This helper is still a separate
    // depth-32 experimental profile; the active OpenVM entrypoint remains depth 63.
    let mut curr = leaf_hash(&pub_stmt.namespace_id, u64::from(wit.leaf_index), &c_in);
    for (level, sibling) in wit.merkle_path.iter().enumerate() {
        curr = if ((wit.leaf_index >> level) & 1) == 1 {
            node_hash(&pub_stmt.namespace_id, level, sibling, &curr)
        } else {
            node_hash(&pub_stmt.namespace_id, level, &curr, sibling)
        };
    }
    if !constant_time_eq(&curr, &pub_stmt.anchor_root) {
        return Err("ERR_ANCHOR_ROOT_MISMATCH".into());
    }

    // 5. Strict 64-Bit Value Conservation (No Wraparound)
    let total_out = wit
        .value_out
        .checked_add(pub_stmt.withdraw_value)
        .and_then(|v| v.checked_add(pub_stmt.fee))
        .ok_or_else(|| "ERR_VALUE_OVERFLOW".to_string())?;
    if wit.value_in != total_out {
        return Err("ERR_VALUE_CONSERVATION_FAILED".into());
    }

    // 6. Output Change Note Commitment Binding
    let val_out_bytes = wit.value_out.to_le_bytes();
    let mut c_out_preimage = Vec::with_capacity(
        DOM_COMMIT_V3.len() + 32 + HASH_BYTES + HASH_BYTES + 8 + 32 + 32,
    );
    c_out_preimage.extend_from_slice(DOM_COMMIT_V3);
    c_out_preimage.extend_from_slice(&pub_stmt.param_id);
    c_out_preimage.extend_from_slice(&pub_stmt.namespace_id);
    c_out_preimage.extend_from_slice(&wit.pk_owner_out);
    c_out_preimage.extend_from_slice(&val_out_bytes);
    c_out_preimage.extend_from_slice(&wit.coin_id_out);
    c_out_preimage.extend_from_slice(&wit.salt_out);
    let c_out = shake256_384(&c_out_preimage);
    if !constant_time_eq(&c_out, &pub_stmt.out_commitment) {
        return Err("ERR_OUTPUT_COMMITMENT_MISMATCH".into());
    }

    // 7. Cryptographic Spend Authorization & Statement Digest Binding
    let fee_bytes = pub_stmt.fee.to_le_bytes();
    let withdraw_bytes = pub_stmt.withdraw_value.to_le_bytes();
    let mut stmt_preimage = Vec::with_capacity(
        DOM_TX_BIND_V3.len() + 32 + 5 * HASH_BYTES + 16,
    );
    stmt_preimage.extend_from_slice(DOM_TX_BIND_V3);
    stmt_preimage.extend_from_slice(&pub_stmt.param_id);
    stmt_preimage.extend_from_slice(&pub_stmt.namespace_id);
    stmt_preimage.extend_from_slice(&pub_stmt.anchor_root);
    stmt_preimage.extend_from_slice(&pub_stmt.nullifier);
    stmt_preimage.extend_from_slice(&pub_stmt.out_commitment);
    stmt_preimage.extend_from_slice(&pub_stmt.tx_context_digest);
    stmt_preimage.extend_from_slice(&fee_bytes);
    stmt_preimage.extend_from_slice(&withdraw_bytes);

    Ok(shake256_384(&stmt_preimage))
}


#[cfg(test)]
mod depth32_relation_tests {
    use super::*;

    fn fixture() -> (PublicStatementV3, PrivateWitnessV3) {
        let param_id = [0x11u8; 32];
        let namespace_id = [0x22u8; HASH_BYTES];
        let sk_spend = [0x33u8; HASH_BYTES];
        let value_in = 100u64;
        let coin_id_in = [0x44u8; 32];
        let salt_in = [0x55u8; 32];
        let leaf_index = 5u32;
        let pk_owner_out = [0x77u8; HASH_BYTES];
        let value_out = 85u64;
        let coin_id_out = [0x88u8; 32];
        let salt_out = [0x99u8; 32];
        let fee = 5u64;
        let withdraw_value = 10u64;

        let mut ak_preimage = Vec::new();
        ak_preimage.extend_from_slice(DOM_AK_V3);
        ak_preimage.extend_from_slice(&sk_spend);
        let ak = shake256_384(&ak_preimage);
        let mut nk_preimage = Vec::new();
        nk_preimage.extend_from_slice(DOM_NK_V3);
        nk_preimage.extend_from_slice(&sk_spend);
        let nk = shake256_384(&nk_preimage);
        let mut owner_preimage = Vec::new();
        owner_preimage.extend_from_slice(DOM_OWNER_V3);
        owner_preimage.extend_from_slice(&ak);
        owner_preimage.extend_from_slice(&nk);
        let pk_owner_in = shake256_384(&owner_preimage);

        let mut c_in_preimage = Vec::new();
        c_in_preimage.extend_from_slice(DOM_COMMIT_V3);
        c_in_preimage.extend_from_slice(&param_id);
        c_in_preimage.extend_from_slice(&namespace_id);
        c_in_preimage.extend_from_slice(&pk_owner_in);
        c_in_preimage.extend_from_slice(&value_in.to_le_bytes());
        c_in_preimage.extend_from_slice(&coin_id_in);
        c_in_preimage.extend_from_slice(&salt_in);
        let c_in = shake256_384(&c_in_preimage);

        let mut nf_data = Vec::new();
        nf_data.extend_from_slice(DOM_NULLIFIER_V3);
        nf_data.push(TX_VERSION);
        nf_data.extend_from_slice(&param_id);
        nf_data.extend_from_slice(&namespace_id);
        nf_data.extend_from_slice(&c_in);
        let nullifier = hmac_sha3_384(&nk, &nf_data);

        let merkle_path = [[0x66u8; HASH_BYTES]; MERKLE_DEPTH_32];
        let mut root = leaf_hash(&namespace_id, u64::from(leaf_index), &c_in);
        for (level, sibling) in merkle_path.iter().enumerate() {
            root = if ((leaf_index >> level) & 1) == 1 {
                node_hash(&namespace_id, level, sibling, &root)
            } else {
                node_hash(&namespace_id, level, &root, sibling)
            };
        }

        let mut c_out_preimage = Vec::new();
        c_out_preimage.extend_from_slice(DOM_COMMIT_V3);
        c_out_preimage.extend_from_slice(&param_id);
        c_out_preimage.extend_from_slice(&namespace_id);
        c_out_preimage.extend_from_slice(&pk_owner_out);
        c_out_preimage.extend_from_slice(&value_out.to_le_bytes());
        c_out_preimage.extend_from_slice(&coin_id_out);
        c_out_preimage.extend_from_slice(&salt_out);
        let out_commitment = shake256_384(&c_out_preimage);

        let statement = PublicStatementV3 {
            param_id,
            namespace_id,
            anchor_root: root,
            nullifier,
            out_commitment,
            tx_context_digest: [0xaau8; HASH_BYTES],
            fee,
            withdraw_value,
        };
        let witness = PrivateWitnessV3 {
            sk_spend,
            value_in,
            coin_id_in,
            salt_in,
            merkle_path,
            leaf_index,
            pk_owner_out,
            value_out,
            coin_id_out,
            salt_out,
        };
        (statement, witness)
    }

    #[test]
    fn depth32_reference_relation_accepts_consistent_witness() {
        let (statement, witness) = fixture();
        assert!(verify_spend_relation_v3(&statement, &witness).is_ok());
    }

    #[test]
    fn depth32_relation_rejects_parameter_id_mutation() {
        let (mut statement, witness) = fixture();
        statement.param_id[0] ^= 1;
        assert!(verify_spend_relation_v3(&statement, &witness).is_err());
    }

    #[test]
    fn depth32_relation_rejects_merkle_index_bit_mutation() {
        let (statement, mut witness) = fixture();
        witness.leaf_index ^= 1;
        assert_eq!(
            verify_spend_relation_v3(&statement, &witness).unwrap_err(),
            "ERR_ANCHOR_ROOT_MISMATCH"
        );
    }

    #[test]
    fn depth32_relation_rejects_value_overflow() {
        let (statement, mut witness) = fixture();
        witness.value_out = u64::MAX;
        assert_eq!(
            verify_spend_relation_v3(&statement, &witness).unwrap_err(),
            "ERR_VALUE_OVERFLOW"
        );
    }
}
