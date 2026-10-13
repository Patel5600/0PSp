//! OpenVM guest for the explicitly non-authorizing R_spend subset.
//!
//! This proves commitment opening, same-witness NullifierV2, depth-63 Merkle
//! membership, canonical TxFieldsV2/TxDigestV2, output commitment openings and
//! u64 value conservation. It intentionally accepts only a test-only NOAUTH
//! params/policy ID. It does not verify a signature and MUST NOT authorize spend.

use core::cmp::min;

pub const TEST_PARAMS_ID: &[u8] = b"0PSP-OPENVM-PARTIAL-NOAUTH-TEST-v1";
pub const TEST_POLICY_ID: &[u8] = b"0PSP-OPENVM-PARTIAL-NOAUTH-TEST-v1";
pub const WITNESS_MAGIC: &[u8] = b"0PSP-OPENVM-RSPEND-NOAUTH-WITNESS-v1";
pub const PUBLIC_OUTPUT_DOMAIN: &[u8] = b"0PSP-OPENVM-PARTIAL-NOAUTH-PUBLIC-v1";
pub const TX_FIELDS_DOMAIN: &[u8] = b"0PSP-TX-FIELDS-v2-SHAKE256";
pub const TX_DIGEST_DOMAIN: &[u8] = b"0PSP-TX-DIGEST-v2-SHAKE256";
pub const COMMITMENT_DOMAIN: &[u8] = b"0PSP-COIN-COMMIT-v2-SHAKE256";
pub const NULLIFIER_DOMAIN: &[u8] = b"0PSP-NULLIFIER-v2-SHAKE256";
pub const EMPTY_LEAF_DOMAIN: &[u8] = b"0PSP-COMMITMENT-EMPTY-LEAF-v1-SHAKE256";
pub const LEAF_DOMAIN: &[u8] = b"0PSP-COMMITMENT-LEAF-v1-SHAKE256";
pub const NODE_DOMAIN: &[u8] = b"0PSP-COMMITMENT-NODE-v1-SHAKE256";
pub const TREE_DEPTH: usize = 63;
pub const HASH_BYTES: usize = 48;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_PUBLIC_KEY_BYTES: usize = 4096;
pub const MAX_FIELDS_BYTES: usize = 1_000_000;
pub const MAX_WITNESS_BYTES: usize = 2_000_000;

#[cfg(not(target_os = "zkvm"))]
use sha3::digest::{ExtendableOutput, Update, XofReader};
#[cfg(not(target_os = "zkvm"))]
use sha3::Shake256;

#[cfg(target_os = "zkvm")]
#[repr(align(4))]
struct AlignedState([u8; 200]);

/// SHAKE256 with exactly 48 output bytes and the FIPS 202 SHAKE domain byte 0x1f.
/// On OpenVM this uses the pinned Keccak-f extension; the host fallback is only
/// for test-vector conformance and is not part of the proved guest execution.
pub fn shake256_384(input: &[u8]) -> [u8; 48] {
    #[cfg(target_os = "zkvm")]
    {
        use openvm_keccak256_guest::{native_keccakf, native_xorin, KECCAK_RATE};
        let mut state = AlignedState([0u8; 200]);
        let mut input_offset = 0usize;
        let mut rate_offset = 0usize;
        while input_offset < input.len() {
            let take = min(KECCAK_RATE - rate_offset, input.len() - input_offset);
            // SAFETY: the aligned state has 200 bytes; the selected region has
            // KECCAK_RATE-rate_offset bytes; take is bounded by that region.
            unsafe {
                native_xorin(
                    state.0[rate_offset..].as_mut_ptr(),
                    input[input_offset..].as_ptr(),
                    take,
                );
            }
            rate_offset += take;
            input_offset += take;
            if rate_offset == KECCAK_RATE {
                // SAFETY: state has the required 200-byte size and 4-byte alignment.
                unsafe { native_keccakf(state.0.as_mut_ptr()) };
                rate_offset = 0;
            }
        }
        state.0[rate_offset] ^= 0x1f;
        state.0[KECCAK_RATE - 1] ^= 0x80;
        // SAFETY: state has the required 200-byte size and 4-byte alignment.
        unsafe { native_keccakf(state.0.as_mut_ptr()) };
        let mut output = [0u8; HASH_BYTES];
        output.copy_from_slice(&state.0[..HASH_BYTES]);
        output
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        let mut hasher = Shake256::default();
        Update::update(&mut hasher, input);
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; HASH_BYTES];
        reader.read(&mut output);
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Transaction {
    params_id: Vec<u8>,
    namespace: [u8; 48],
    root: [u8; 48],
    nullifier: [u8; 48],
    state_head: [u8; 48],
    policy_id: Vec<u8>,
    fee: u64,
    outputs: Vec<[u8; 48]>,
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, count: usize, field: &str) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(count)
            .ok_or_else(|| format!("offset overflow while reading {field}"))?;
        if end > self.data.len() {
            return Err(format!("truncated {field}"));
        }
        let result = &self.data[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u16_le(&mut self, field: &str) -> Result<u16, String> {
        let raw: [u8; 2] = self.take(2, field)?.try_into().unwrap();
        Ok(u16::from_le_bytes(raw))
    }

    fn u32_le(&mut self, field: &str) -> Result<u32, String> {
        let raw: [u8; 4] = self.take(4, field)?.try_into().unwrap();
        Ok(u32::from_le_bytes(raw))
    }

    fn u64_le(&mut self, field: &str) -> Result<u64, String> {
        let raw: [u8; 8] = self.take(8, field)?.try_into().unwrap();
        Ok(u64::from_le_bytes(raw))
    }

    fn vec_u16(&mut self, field: &str) -> Result<Vec<u8>, String> {
        let length = self.u16_le(&format!("{field} length"))? as usize;
        if length == 0 {
            return Err(format!("{field} must not be empty"));
        }
        Ok(self.take(length, field)?.to_vec())
    }

    fn vec_u32(&mut self, field: &str, max: usize) -> Result<Vec<u8>, String> {
        let length = self.u32_le(&format!("{field} length"))? as usize;
        if length == 0 || length > max {
            return Err(format!("{field} length is outside 1..={max}"));
        }
        Ok(self.take(length, field)?.to_vec())
    }

    fn fixed<const N: usize>(&mut self, field: &str) -> Result<[u8; N], String> {
        Ok(self.take(N, field)?.try_into().unwrap())
    }

    fn finish(&self, field: &str) -> Result<(), String> {
        if self.offset != self.data.len() {
            return Err(format!("{field} contains trailing bytes"));
        }
        Ok(())
    }
}

fn parse_transaction(encoded: &[u8]) -> Result<Transaction, String> {
    if encoded.len() > MAX_FIELDS_BYTES {
        return Err("TxFieldsV2 exceeds the byte safety limit".into());
    }
    let mut r = Reader::new(encoded);
    if r.take(TX_FIELDS_DOMAIN.len(), "TxFieldsV2 domain")? != TX_FIELDS_DOMAIN {
        return Err("TxFieldsV2 domain mismatch".into());
    }
    if r.take(1, "TxFieldsV2 version")? != [0x02] {
        return Err("TxFieldsV2 version mismatch".into());
    }
    let params_id = r.vec_u16("params_id")?;
    if params_id != TEST_PARAMS_ID {
        return Err("guest only accepts its explicit partial NOAUTH test params ID".into());
    }
    let namespace = r.fixed::<48>("namespace_id")?;
    let root = r.fixed::<48>("commitment_root")?;
    let nullifier = r.fixed::<48>("nullifier")?;
    let state_head = r.fixed::<48>("ledger_state_head")?;
    let policy_id = r.vec_u16("authorization_policy_id")?;
    if policy_id != TEST_POLICY_ID {
        return Err("guest only accepts its explicit partial NOAUTH test policy".into());
    }
    let fee = r.u64_le("fee")?;
    let count = r.u32_le("output_count")? as usize;
    if count == 0 || count > MAX_OUTPUTS {
        return Err(format!("this proof profile supports 1..={MAX_OUTPUTS} outputs"));
    }
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        outputs.push(r.fixed::<48>("output commitment")?);
    }
    r.finish("TxFieldsV2")?;
    for i in 0..outputs.len() {
        for j in 0..i {
            if outputs[i] == outputs[j] {
                return Err("TxFieldsV2 repeats an output commitment".into());
            }
        }
    }
    let tx = Transaction {
        params_id,
        namespace,
        root,
        nullifier,
        state_head,
        policy_id,
        fee,
        outputs,
    };
    if encode_transaction(&tx) != encoded {
        return Err("TxFieldsV2 failed canonical byte-for-byte round trip".into());
    }
    Ok(tx)
}

fn encode_transaction(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        TX_FIELDS_DOMAIN.len() + 1 + 2 + tx.params_id.len() + 48 * 4 +
        2 + tx.policy_id.len() + 8 + 4 + 48 * tx.outputs.len()
    );
    out.extend_from_slice(TX_FIELDS_DOMAIN);
    out.push(0x02);
    out.extend_from_slice(&(tx.params_id.len() as u16).to_le_bytes());
    out.extend_from_slice(&tx.params_id);
    out.extend_from_slice(&tx.namespace);
    out.extend_from_slice(&tx.root);
    out.extend_from_slice(&tx.nullifier);
    out.extend_from_slice(&tx.state_head);
    out.extend_from_slice(&(tx.policy_id.len() as u16).to_le_bytes());
    out.extend_from_slice(&tx.policy_id);
    out.extend_from_slice(&tx.fee.to_le_bytes());
    out.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
    for c in &tx.outputs {
        out.extend_from_slice(c);
    }
    out
}

fn commitment_v2(
    params_id: &[u8],
    namespace: &[u8; 48],
    public_key: &[u8],
    value: u64,
    coin_id: &[u8; 32],
    r_nf: &[u8; 36],
    rho: &[u8; 36],
) -> Result<[u8; 48], String> {
    if params_id.is_empty() || params_id.len() > u16::MAX as usize {
        return Err("params_id length is invalid".into());
    }
    if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY_BYTES {
        return Err("public key length is invalid for the partial proof profile".into());
    }
    let mut preimage = Vec::with_capacity(
        COMMITMENT_DOMAIN.len() + 1 + 2 + params_id.len() + 4 +
        public_key.len() + 8 + 2 + 48 + 2 + 32 + 2 + 36 + 2 + 36
    );
    preimage.extend_from_slice(COMMITMENT_DOMAIN);
    preimage.push(0x02);
    preimage.extend_from_slice(&(params_id.len() as u16).to_le_bytes());
    preimage.extend_from_slice(params_id);
    preimage.extend_from_slice(&(public_key.len() as u32).to_le_bytes());
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(&value.to_le_bytes());
    preimage.extend_from_slice(&(48u16).to_le_bytes());
    preimage.extend_from_slice(namespace);
    preimage.extend_from_slice(&(32u16).to_le_bytes());
    preimage.extend_from_slice(coin_id);
    preimage.extend_from_slice(&(36u16).to_le_bytes());
    preimage.extend_from_slice(r_nf);
    preimage.extend_from_slice(&(36u16).to_le_bytes());
    preimage.extend_from_slice(rho);
    Ok(shake256_384(&preimage))
}

fn nullifier_v2(
    namespace: &[u8; 48],
    coin_id: &[u8; 32],
    r_nf: &[u8; 36],
) -> [u8; 48] {
    let mut preimage = Vec::with_capacity(NULLIFIER_DOMAIN.len() + 1 + 2 + 48 + 2 + 32 + 2 + 36);
    preimage.extend_from_slice(NULLIFIER_DOMAIN);
    preimage.push(0x02);
    preimage.extend_from_slice(&(48u16).to_le_bytes());
    preimage.extend_from_slice(namespace);
    preimage.extend_from_slice(&(32u16).to_le_bytes());
    preimage.extend_from_slice(coin_id);
    preimage.extend_from_slice(&(36u16).to_le_bytes());
    preimage.extend_from_slice(r_nf);
    shake256_384(&preimage)
}

fn leaf_hash(namespace: &[u8; 48], index: u64, commitment: &[u8; 48]) -> [u8; 48] {
    let mut preimage = Vec::with_capacity(LEAF_DOMAIN.len() + 1 + 48 + 8 + 48);
    preimage.extend_from_slice(LEAF_DOMAIN);
    preimage.push(0x01);
    preimage.extend_from_slice(namespace);
    preimage.extend_from_slice(&index.to_be_bytes());
    preimage.extend_from_slice(commitment);
    shake256_384(&preimage)
}

fn node_hash(namespace: &[u8; 48], level: usize, left: &[u8; 48], right: &[u8; 48]) -> [u8; 48] {
    let mut preimage = Vec::with_capacity(NODE_DOMAIN.len() + 1 + 4 + 48 + 48 + 48);
    preimage.extend_from_slice(NODE_DOMAIN);
    preimage.push(0x01);
    preimage.extend_from_slice(&(level as u32).to_be_bytes());
    preimage.extend_from_slice(namespace);
    preimage.extend_from_slice(left);
    preimage.extend_from_slice(right);
    shake256_384(&preimage)
}

fn verify_membership(
    namespace: &[u8; 48],
    root: &[u8; 48],
    index: u64,
    commitment: &[u8; 48],
    siblings: &[[u8; 48]],
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
    current == *root
}

fn transaction_digest(fields: &[u8]) -> Result<[u8; 48], String> {
    if fields.len() > u32::MAX as usize {
        return Err("TxFieldsV2 length exceeds uint32".into());
    }
    let mut preimage = Vec::with_capacity(TX_DIGEST_DOMAIN.len() + 1 + 4 + fields.len());
    preimage.extend_from_slice(TX_DIGEST_DOMAIN);
    preimage.push(0x02);
    preimage.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    preimage.extend_from_slice(fields);
    Ok(shake256_384(&preimage))
}

/// Validate the fixed test-only witness and return a 32-byte public output
/// commitment. The public output binds all canonical public transaction fields.
pub fn verify_noauth_witness(witness: &[u8]) -> Result<[u8; 32], String> {
    if witness.len() > MAX_WITNESS_BYTES {
        return Err("witness exceeds the configured byte safety limit".into());
    }
    let mut r = Reader::new(witness);
    if r.take(WITNESS_MAGIC.len(), "witness domain")? != WITNESS_MAGIC {
        return Err("partial NOAUTH witness domain mismatch".into());
    }
    let fields_len = r.u32_le("TxFieldsV2 length")? as usize;
    if fields_len == 0 || fields_len > MAX_FIELDS_BYTES {
        return Err("TxFieldsV2 length outside configured bound".into());
    }
    let fields = r.take(fields_len, "TxFieldsV2")?;
    let tx = parse_transaction(fields)?;

    let input_commitment = r.fixed::<48>("input commitment")?;
    let index = r.u64_le("leaf index")?;
    if index >= (1u64 << TREE_DEPTH) {
        return Err("leaf index must be in [0, 2^63-1]".into());
    }
    let input_pk = r.vec_u32("input public key", MAX_PUBLIC_KEY_BYTES)?;
    let input_value = r.u64_le("input value")?;
    let input_coin_id = r.fixed::<32>("input coin ID")?;
    let input_r_nf = r.fixed::<36>("input r_nf")?;
    let input_rho = r.fixed::<36>("input rho_C")?;
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        siblings.push(r.fixed::<48>("membership sibling")?);
    }
    let opening_count = r.u32_le("output opening count")? as usize;
    if opening_count != tx.outputs.len() {
        return Err("output opening count differs from TxFieldsV2".into());
    }

    let expected_input_commitment = commitment_v2(
        &tx.params_id, &tx.namespace, &input_pk, input_value,
        &input_coin_id, &input_r_nf, &input_rho
    )?;
    if expected_input_commitment != input_commitment {
        return Err("CommitV2 input opening mismatch".into());
    }
    if nullifier_v2(&tx.namespace, &input_coin_id, &input_r_nf) != tx.nullifier {
        return Err("NullifierV2 does not use the same coin ID/r_nf opening".into());
    }
    if !verify_membership(&tx.namespace, &tx.root, index, &input_commitment, &siblings) {
        return Err("input commitment is not a member of the public commitment root".into());
    }

    let mut output_sum = 0u64;
    for commitment in &tx.outputs {
        let pk = r.vec_u32("output public key", MAX_PUBLIC_KEY_BYTES)?;
        let value = r.u64_le("output value")?;
        let coin_id = r.fixed::<32>("output coin ID")?;
        let r_nf = r.fixed::<36>("output r_nf")?;
        let rho = r.fixed::<36>("output rho_C")?;
        if commitment_v2(&tx.params_id, &tx.namespace, &pk, value, &coin_id, &r_nf, &rho)? != *commitment {
            return Err("CommitV2 output opening mismatch".into());
        }
        output_sum = output_sum.checked_add(value)
            .ok_or_else(|| "output value sum overflows uint64".to_string())?;
    }
    r.finish("partial NOAUTH witness")?;
    let total = output_sum.checked_add(tx.fee)
        .ok_or_else(|| "output sum plus fee overflows uint64".to_string())?;
    if total != input_value {
        return Err("input value does not equal output values plus fee".into());
    }

    let tx_digest = transaction_digest(fields)?;
    let mut public_preimage = Vec::with_capacity(PUBLIC_OUTPUT_DOMAIN.len() + 1 + 48);
    public_preimage.extend_from_slice(PUBLIC_OUTPUT_DOMAIN);
    public_preimage.push(0x01);
    public_preimage.extend_from_slice(&tx_digest);
    let full_public_digest = shake256_384(&public_preimage);
    Ok(full_public_digest[..32].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake256_384_matches_fips_202_vectors() {
        assert_eq!(
            shake256_384(b"").to_vec(),
            bytes_from_hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6")
        );
        assert_eq!(
            shake256_384(b"abc").to_vec(),
            bytes_from_hex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa")
        );
    }

    fn bytes_from_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn guest_profile_is_explicitly_non_authorizing() {
        assert_ne!(TEST_POLICY_ID, b"0PSP-THRESHOLD-MLDSA65-v1");
        assert!(TEST_POLICY_ID.starts_with(b"0PSP-OPENVM-PARTIAL-NOAUTH"));
    }

    #[test]
    fn malformed_witnesses_fail_closed() {
        assert!(verify_noauth_witness(b"").is_err());
        assert!(verify_noauth_witness(b"wrong-domain-witness").is_err());
    }
}
