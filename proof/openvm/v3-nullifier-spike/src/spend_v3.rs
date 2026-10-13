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
    nullifier_message_v3, parse_bundle_key_commitment, shake256_384, Reader, COIN_ID_BYTES,
    HASH_BYTES, KEY_BYTES, RHO_BYTES, R_NF_BYTES,
};

pub const SPEND_WITNESS_MAGIC: &[u8] =
    b"0PSP-OPENVM-V3-SPEND-CANDIDATE-WITNESS-v1";
pub const TX_FIELDS_DOMAIN: &[u8] = b"0PSP-TX-FIELDS-v3-CANDIDATE-SHAKE256";
pub const TX_DIGEST_DOMAIN: &[u8] = b"0PSP-TX-DIGEST-v3-CANDIDATE-SHAKE256";
pub const TX_VERSION: u8 = 0x03;
pub const SPEND_POLICY_NK: &[u8] = b"0PSP-V3-NK-POSSESSION-CANDIDATE-v1";
pub const PUBLIC_STATEMENT_DOMAIN: &[u8] =
    b"0PSP-OPENVM-V3-SPEND-PUBLIC-STATEMENT-CANDIDATE-v1";
pub const TREE_DEPTH: usize = 63;
pub const MAX_TX_BYTES: usize = 1_000_000;
pub const MAX_BUNDLE_BYTES: usize = 65_535;
pub const MAX_WITNESS_BYTES: usize = 2_000_000;

const EMPTY_LEAF_DOMAIN: &[u8] = b"0PSP-COMMITMENT-EMPTY-LEAF-v1-SHAKE256";
const LEAF_DOMAIN: &[u8] = b"0PSP-COMMITMENT-LEAF-v1-SHAKE256";
const NODE_DOMAIN: &[u8] = b"0PSP-COMMITMENT-NODE-v1-SHAKE256";
const OUTPUT_COIN_ID_DOMAIN: &[u8] = b"0PSP-OUTPUT-COIN-ID-v3-anchor-index-candidate";
const OUTPUT_RNF_DOMAIN: &[u8] = b"0PSP-OUTPUT-RNF-v3-anchor-index-candidate";
const OUTPUT_ID_VERSION: u8 = 0x03;
const OUTPUT_ENTROPY_BYTES: usize = 32;

#[derive(Clone)]
struct TxFields {
    params_id: Vec<u8>,
    namespace: [u8; HASH_BYTES],
    root: [u8; HASH_BYTES],
    nullifier: [u8; HASH_BYTES],
    state_head: [u8; HASH_BYTES],
    policy_id: Vec<u8>,
    fee: u64,
    output_entropy: [u8; OUTPUT_ENTROPY_BYTES],
    output_commitment: [u8; HASH_BYTES],
    encoded: Vec<u8>,
}

fn encode_tx(tx: &TxFields) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        TX_FIELDS_DOMAIN.len() + 1 + 2 + tx.params_id.len() + 4 * HASH_BYTES
            + 2 + tx.policy_id.len() + 8 + OUTPUT_ENTROPY_BYTES + 4 + HASH_BYTES,
    );
    out.extend_from_slice(TX_FIELDS_DOMAIN);
    out.push(TX_VERSION);
    out.extend_from_slice(&(tx.params_id.len() as u16).to_le_bytes());
    out.extend_from_slice(&tx.params_id);
    out.extend_from_slice(&tx.namespace);
    out.extend_from_slice(&tx.root);
    out.extend_from_slice(&tx.nullifier);
    out.extend_from_slice(&tx.state_head);
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
        params_id, namespace, root, nullifier, state_head, policy_id, fee,
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

    fn digest(&self) -> [u8; HASH_BYTES] {
        let mut preimage = Vec::with_capacity(TX_DIGEST_DOMAIN.len() + 1 + 4 + self.encoded.len());
        preimage.extend_from_slice(TX_DIGEST_DOMAIN);
        preimage.push(TX_VERSION);
        preimage.extend_from_slice(&(self.encoded.len() as u32).to_le_bytes());
        preimage.extend_from_slice(&self.encoded);
        shake256_384(&preimage)
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
    let mut preimage = Vec::with_capacity(NODE_DOMAIN.len() + 1 + 4 + 3 * HASH_BYTES);
    preimage.extend_from_slice(NODE_DOMAIN);
    preimage.push(0x01);
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
pub fn verify_v3_spend_witness(witness: &[u8]) -> Result<[u8; 32], String> {
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
    let public_digest = shake256_384(&public_statement);
    let mut output = [0u8; 32];
    output.copy_from_slice(&public_digest[..32]);
    Ok(output)
}
