//! Isolated OpenVM feasibility guest for the non-normative V3 nullifier candidate.
//!
//! Checks canonical BundleV3 parsing, the nullifier-key commitment opening, the
//! CommitV3 opening, and the HMAC-SHA3-384 NullifierV3 relation. It is NOT a complete
//! spend relation: no Merkle membership, authenticated state root, output identity,
//! value accounting, spend authorization, ledger transition, or production ZK claim.

#[cfg(target_os = "zkvm")]
use core::cmp::min;

pub const WITNESS_MAGIC: &[u8] = b"0PSP-OPENVM-V3-NULLIFIER-SPIKE-WITNESS-v1";
pub const BUNDLE_DOMAIN: &[u8] = b"0PSP-NOTE-PK-BUNDLE-v3";
pub const BUNDLE_VERSION: u8 = 0x03;
pub const COMMITMENT_DOMAIN_V3: &[u8] = b"0PSP-COIN-COMMIT-v3-SHAKE256";
pub const NULLIFIER_DOMAIN_V3: &[u8] = b"0PSP-NULLIFIER-v3-HMAC-SHA3-384";
pub const NULLIFIER_KEY_COMMITMENT_DOMAIN_V3: &[u8] =
    b"0PSP-NULLIFIER-KEY-COMMIT-v3-SHAKE256";
pub const PUBLIC_STATEMENT_DOMAIN: &[u8] =
    b"0PSP-OPENVM-V3-NULLIFIER-PUBLIC-STATEMENT";
pub const HASH_BYTES: usize = 48;
pub const KEY_BYTES: usize = 48;
pub const COIN_ID_BYTES: usize = 32;
pub const R_NF_BYTES: usize = 36;
pub const RHO_BYTES: usize = 36;
pub const SHAKE256_RATE: usize = 136;
pub const SHA3_384_RATE: usize = 104;
pub const MAX_BUNDLE_BYTES: usize = 65_535;
pub const MAX_WITNESS_BYTES: usize = 2_000_000;

#[cfg(not(target_os = "zkvm"))]
use sha3::digest::{ExtendableOutput, Update, XofReader};
#[cfg(not(target_os = "zkvm"))]
use sha3::{Digest, Sha3_384, Shake256};

#[cfg(target_os = "zkvm")]
#[repr(align(4))]
struct AlignedState([u8; 200]);

/// SHAKE256-384 using FIPS 202 domain byte 0x1f.
///
/// The zkVM branch uses the pinned OpenVM Keccak-f extension. The host branch
/// exists only for known-answer and adversarial conformance tests.
pub fn shake256_384(input: &[u8]) -> [u8; HASH_BYTES] {
    #[cfg(target_os = "zkvm")]
    {
        use openvm_keccak256_guest::{native_keccakf, native_xorin};

        let mut state = AlignedState([0u8; 200]);
        let mut input_offset = 0usize;
        let mut rate_offset = 0usize;
        while input_offset < input.len() {
            let take = min(SHAKE256_RATE - rate_offset, input.len() - input_offset);
            // SAFETY: state is 200 bytes and 4-byte aligned; the selected rate region
            // is at least take bytes long.
            unsafe {
                native_xorin(
                    state.0[rate_offset..].as_mut_ptr(),
                    input[input_offset..].as_ptr(),
                    take,
                );
            }
            rate_offset += take;
            input_offset += take;
            if rate_offset == SHAKE256_RATE {
                // SAFETY: state has the size and alignment required by the extension.
                unsafe { native_keccakf(state.0.as_mut_ptr()) };
                rate_offset = 0;
            }
        }
        state.0[rate_offset] ^= 0x1f;
        state.0[SHAKE256_RATE - 1] ^= 0x80;
        // SAFETY: state has the size and alignment required by the extension.
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

/// SHA3-384 using FIPS 202 domain byte 0x06 and rate 104 bytes.
///
/// HMAC-SHA3-384 uses this function for inner and outer digests. It is implemented
/// from the OpenVM Keccak-f extension on zkVM, and RustCrypto on the host test path.
fn sha3_384(input: &[u8]) -> [u8; HASH_BYTES] {
    #[cfg(target_os = "zkvm")]
    {
        use openvm_keccak256_guest::{native_keccakf, native_xorin};

        let mut state = AlignedState([0u8; 200]);
        let mut input_offset = 0usize;
        let mut rate_offset = 0usize;
        while input_offset < input.len() {
            let take = min(SHA3_384_RATE - rate_offset, input.len() - input_offset);
            // SAFETY: state is 200 bytes and 4-byte aligned; the selected rate region
            // is at least take bytes long.
            unsafe {
                native_xorin(
                    state.0[rate_offset..].as_mut_ptr(),
                    input[input_offset..].as_ptr(),
                    take,
                );
            }
            rate_offset += take;
            input_offset += take;
            if rate_offset == SHA3_384_RATE {
                // SAFETY: state has the size and alignment required by the extension.
                unsafe { native_keccakf(state.0.as_mut_ptr()) };
                rate_offset = 0;
            }
        }
        state.0[rate_offset] ^= 0x06;
        state.0[SHA3_384_RATE - 1] ^= 0x80;
        // SAFETY: state has the size and alignment required by the extension.
        unsafe { native_keccakf(state.0.as_mut_ptr()) };
        let mut output = [0u8; HASH_BYTES];
        output.copy_from_slice(&state.0[..HASH_BYTES]);
        output
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        let digest = Sha3_384::digest(input);
        let mut output = [0u8; HASH_BYTES];
        output.copy_from_slice(&digest);
        output
    }
}

/// HMAC-SHA3-384. SHA3-384's HMAC block size is its 104-byte sponge rate.
fn hmac_sha3_384(key: &[u8; KEY_BYTES], message: &[u8]) -> [u8; HASH_BYTES] {
    const BLOCK_BYTES: usize = SHA3_384_RATE;
    let mut key_block = [0u8; BLOCK_BYTES];
    key_block[..KEY_BYTES].copy_from_slice(key);

    let mut inner = Vec::with_capacity(BLOCK_BYTES + message.len());
    for byte in key_block.iter() {
        inner.push(*byte ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_digest = sha3_384(&inner);

    let mut outer = Vec::with_capacity(BLOCK_BYTES + HASH_BYTES);
    for byte in key_block.iter() {
        outer.push(*byte ^ 0x5c);
    }
    outer.extend_from_slice(&inner_digest);
    sha3_384(&outer)
}

fn constant_time_eq<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let mut difference = 0u8;
    for index in 0..N {
        difference |= left[index] ^ right[index];
    }
    difference == 0
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

/// Parse the canonical BundleV3 byte layout and return its 48-byte nk commitment.
fn parse_bundle_key_commitment(encoded: &[u8]) -> Result<[u8; HASH_BYTES], String> {
    let mut prefix = Vec::with_capacity(BUNDLE_DOMAIN.len() + 1);
    prefix.extend_from_slice(BUNDLE_DOMAIN);
    prefix.push(BUNDLE_VERSION);
    if !encoded.starts_with(&prefix) {
        return Err("BundleV3 domain/version mismatch".into());
    }
    if encoded.len() > MAX_BUNDLE_BYTES {
        return Err("BundleV3 exceeds spike size limit".into());
    }

    let mut reader = Reader::new(&encoded[prefix.len()..]);
    let _scheme_id = reader.vec_u16("auth_scheme_id")?;
    let _auth_public_key = reader.vec_u32("auth_public_key", MAX_BUNDLE_BYTES)?;
    let commitment_length = reader.u16_le("nullifier key commitment length")? as usize;
    if commitment_length != HASH_BYTES {
        return Err("BundleV3 nullifier key commitment length must be 48".into());
    }
    let commitment = reader.fixed::<HASH_BYTES>("nullifier key commitment")?;
    reader.finish("BundleV3")?;
    Ok(commitment)
}

fn nullifier_key_commitment_v3(key: &[u8; KEY_BYTES]) -> [u8; HASH_BYTES] {
    let mut preimage = Vec::with_capacity(
        NULLIFIER_KEY_COMMITMENT_DOMAIN_V3.len() + 1 + 2 + KEY_BYTES
    );
    preimage.extend_from_slice(NULLIFIER_KEY_COMMITMENT_DOMAIN_V3);
    preimage.push(0x03);
    preimage.extend_from_slice(&(KEY_BYTES as u16).to_le_bytes());
    preimage.extend_from_slice(key);
    shake256_384(&preimage)
}

fn coin_commitment_v3(
    params_id: &[u8],
    bundle: &[u8],
    value: u64,
    namespace: &[u8; HASH_BYTES],
    coin_id: &[u8; COIN_ID_BYTES],
    r_nf: &[u8; R_NF_BYTES],
    rho_coin: &[u8; RHO_BYTES],
) -> Result<[u8; HASH_BYTES], String> {
    if params_id.is_empty() || params_id.len() > u16::MAX as usize {
        return Err("params_id length must be in 1..=65535".into());
    }
    if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
        return Err("BundleV3 length outside spike bounds".into());
    }
    parse_bundle_key_commitment(bundle)?;

    let mut preimage = Vec::with_capacity(
        COMMITMENT_DOMAIN_V3.len() + 1 + 2 + params_id.len() + 4 + bundle.len()
            + 8 + 2 + HASH_BYTES + 2 + COIN_ID_BYTES + 2 + R_NF_BYTES + 2 + RHO_BYTES
    );
    preimage.extend_from_slice(COMMITMENT_DOMAIN_V3);
    preimage.push(0x03);
    preimage.extend_from_slice(&(params_id.len() as u16).to_le_bytes());
    preimage.extend_from_slice(params_id);
    preimage.extend_from_slice(&(bundle.len() as u32).to_le_bytes());
    preimage.extend_from_slice(bundle);
    preimage.extend_from_slice(&value.to_le_bytes());
    preimage.extend_from_slice(&(HASH_BYTES as u16).to_le_bytes());
    preimage.extend_from_slice(namespace);
    preimage.extend_from_slice(&(COIN_ID_BYTES as u16).to_le_bytes());
    preimage.extend_from_slice(coin_id);
    preimage.extend_from_slice(&(R_NF_BYTES as u16).to_le_bytes());
    preimage.extend_from_slice(r_nf);
    preimage.extend_from_slice(&(RHO_BYTES as u16).to_le_bytes());
    preimage.extend_from_slice(rho_coin);
    Ok(shake256_384(&preimage))
}

fn nullifier_message_v3(
    params_id: &[u8],
    namespace: &[u8; HASH_BYTES],
    bundle: &[u8],
    commitment: &[u8; HASH_BYTES],
    coin_id: &[u8; COIN_ID_BYTES],
    r_nf: &[u8; R_NF_BYTES],
) -> Result<Vec<u8>, String> {
    if params_id.is_empty() || params_id.len() > u16::MAX as usize {
        return Err("params_id length must be in 1..=65535".into());
    }
    if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
        return Err("BundleV3 length outside spike bounds".into());
    }
    parse_bundle_key_commitment(bundle)?;

    let mut message = Vec::with_capacity(
        NULLIFIER_DOMAIN_V3.len() + 1 + 2 + params_id.len() + 2 + HASH_BYTES
            + 4 + bundle.len() + 2 + HASH_BYTES + 2 + COIN_ID_BYTES + 2 + R_NF_BYTES
    );
    message.extend_from_slice(NULLIFIER_DOMAIN_V3);
    message.push(0x03);
    message.extend_from_slice(&(params_id.len() as u16).to_le_bytes());
    message.extend_from_slice(params_id);
    message.extend_from_slice(&(HASH_BYTES as u16).to_le_bytes());
    message.extend_from_slice(namespace);
    message.extend_from_slice(&(bundle.len() as u32).to_le_bytes());
    message.extend_from_slice(bundle);
    message.extend_from_slice(&(HASH_BYTES as u16).to_le_bytes());
    message.extend_from_slice(commitment);
    message.extend_from_slice(&(COIN_ID_BYTES as u16).to_le_bytes());
    message.extend_from_slice(coin_id);
    message.extend_from_slice(&(R_NF_BYTES as u16).to_le_bytes());
    message.extend_from_slice(r_nf);
    Ok(message)
}

/// Verify one V3 note opening and its recipient-keyed nullifier candidate.
///
/// The returned 32-byte digest is a small guest output. This spike does not
/// authenticate the source of the statement or prove a full spend.
pub fn verify_v3_nullifier_witness(witness: &[u8]) -> Result<[u8; 32], String> {
    if witness.is_empty() || witness.len() > MAX_WITNESS_BYTES {
        return Err("witness length outside configured bounds".into());
    }
    let mut reader = Reader::new(witness);
    if reader.take(WITNESS_MAGIC.len(), "witness magic")? != WITNESS_MAGIC {
        return Err("V3 nullifier spike witness magic mismatch".into());
    }

    let params_id = reader.vec_u16("params_id")?;
    let namespace = reader.fixed::<HASH_BYTES>("namespace_id")?;
    let bundle = reader.vec_u32("BundleV3", MAX_BUNDLE_BYTES)?;
    let value = reader.u64_le("value")?;
    let coin_id = reader.fixed::<COIN_ID_BYTES>("coin_id")?;
    let r_nf = reader.fixed::<R_NF_BYTES>("r_nf")?;
    let rho_coin = reader.fixed::<RHO_BYTES>("rho_coin")?;
    let nullifier_key = reader.fixed::<KEY_BYTES>("nullifier deriving key")?;
    let expected_commitment = reader.fixed::<HASH_BYTES>("expected CommitV3")?;
    let expected_nullifier = reader.fixed::<HASH_BYTES>("expected NullifierV3")?;
    reader.finish("V3 nullifier spike witness")?;

    let encoded_key_commitment = parse_bundle_key_commitment(&bundle)?;
    let derived_key_commitment = nullifier_key_commitment_v3(&nullifier_key);
    if !constant_time_eq(&encoded_key_commitment, &derived_key_commitment) {
        return Err("nullifier key does not open BundleV3 key commitment".into());
    }

    let derived_commitment = coin_commitment_v3(
        &params_id, &bundle, value, &namespace, &coin_id, &r_nf, &rho_coin,
    )?;
    if !constant_time_eq(&derived_commitment, &expected_commitment) {
        return Err("CommitV3 opening does not match expected public commitment".into());
    }

    let message = nullifier_message_v3(
        &params_id, &namespace, &bundle, &derived_commitment, &coin_id, &r_nf,
    )?;
    let derived_nullifier = hmac_sha3_384(&nullifier_key, &message);
    if !constant_time_eq(&derived_nullifier, &expected_nullifier) {
        return Err("NullifierV3 does not match expected public nullifier".into());
    }

    let mut public_statement = Vec::with_capacity(
        PUBLIC_STATEMENT_DOMAIN.len() + 1 + 2 + params_id.len() + 3 * HASH_BYTES
    );
    public_statement.extend_from_slice(PUBLIC_STATEMENT_DOMAIN);
    public_statement.push(0x03);
    public_statement.extend_from_slice(&(params_id.len() as u16).to_le_bytes());
    public_statement.extend_from_slice(&params_id);
    public_statement.extend_from_slice(&namespace);
    public_statement.extend_from_slice(&expected_commitment);
    public_statement.extend_from_slice(&expected_nullifier);
    let full_digest = shake256_384(&public_statement);
    let mut public_digest = [0u8; 32];
    public_digest.copy_from_slice(&full_digest[..32]);
    Ok(public_digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(encoded: &str) -> Vec<u8> {
        assert_eq!(encoded.len() % 2, 0, "odd-length hex fixture: {} characters", encoded.len());
        encoded.as_bytes().chunks_exact(2).map(|pair| {
            let digit = |value: u8| -> u8 {
                match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    b'A'..=b'F' => value - b'A' + 10,
                    _ => panic!("invalid hex fixture"),
                }
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        }).collect()
    }

    fn fixed<const N: usize>(hex: &str) -> [u8; N] {
        decode_hex(hex).try_into().unwrap()
    }

    const BUNDLE_HEX: &str = concat!(
        "305053502d4e4f54452d504b2d42554e444c452d763303",
        "1300746573742d617574682d736368656d652d7631",
        "19000000746573742d726563697069656e742d7075626c69632d6b6579",
        "300075e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95",
        "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8",
    );
    const KEY_COMMITMENT_HEX: &str = concat!(
        "75e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95",
        "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8",
    );
    const COMMITMENT_HEX: &str = concat!(
        "7c29d710d6a81bed4f3df766421d66fa497072be7513022487eb55c8d4839f82",
        "a9cf6dd11105ce21602715f0644f99d0",
    );
    const NULLIFIER_HEX: &str = concat!(
        "5309bdb17ad1527c06763ae96dfd806520132899bbdbc6519070883abb568a1",
        "af3bc2a43c3a965325df2ba084bcf6f93",
    );

    fn fixture_witness(
        bundle: &[u8],
        value: u64,
        rho_coin: [u8; RHO_BYTES],
        nullifier_key: [u8; KEY_BYTES],
        expected_commitment: [u8; HASH_BYTES],
        expected_nullifier: [u8; HASH_BYTES],
    ) -> Vec<u8> {
        let params_id = b"v3-candidate-params";
        let namespace = [0x11u8; HASH_BYTES];
        let coin_id = [0x22u8; COIN_ID_BYTES];
        let r_nf = [0x33u8; R_NF_BYTES];
        let mut witness = Vec::new();
        witness.extend_from_slice(WITNESS_MAGIC);
        witness.extend_from_slice(&(params_id.len() as u16).to_le_bytes());
        witness.extend_from_slice(params_id);
        witness.extend_from_slice(&namespace);
        witness.extend_from_slice(&(bundle.len() as u32).to_le_bytes());
        witness.extend_from_slice(bundle);
        witness.extend_from_slice(&value.to_le_bytes());
        witness.extend_from_slice(&coin_id);
        witness.extend_from_slice(&r_nf);
        witness.extend_from_slice(&rho_coin);
        witness.extend_from_slice(&nullifier_key);
        witness.extend_from_slice(&expected_commitment);
        witness.extend_from_slice(&expected_nullifier);
        witness
    }

    fn valid_witness() -> Vec<u8> {
        fixture_witness(
            &decode_hex(BUNDLE_HEX),
            500,
            [0xA1; RHO_BYTES],
            [0x44; KEY_BYTES],
            fixed(COMMITMENT_HEX),
            fixed(NULLIFIER_HEX),
        )
    }

    #[test]
    fn python_reference_known_answers_are_enforced() {
        let bundle = decode_hex(BUNDLE_HEX);
        let key = [0x44u8; KEY_BYTES];
        assert_eq!(
            nullifier_key_commitment_v3(&key),
            fixed::<HASH_BYTES>(KEY_COMMITMENT_HEX),
        );
        assert_eq!(
            coin_commitment_v3(
                b"v3-candidate-params",
                &bundle,
                500,
                &[0x11u8; HASH_BYTES],
                &[0x22u8; COIN_ID_BYTES],
                &[0x33u8; R_NF_BYTES],
                &[0xA1u8; RHO_BYTES],
            ).unwrap(),
            fixed(COMMITMENT_HEX),
        );
        let message = nullifier_message_v3(
            b"v3-candidate-params",
            &[0x11u8; HASH_BYTES],
            &bundle,
            &fixed(COMMITMENT_HEX),
            &[0x22u8; COIN_ID_BYTES],
            &[0x33u8; R_NF_BYTES],
        ).unwrap();
        assert_eq!(
            hmac_sha3_384(&key, &message),
            fixed(NULLIFIER_HEX),
        );
        assert_ne!(verify_v3_nullifier_witness(&valid_witness()).unwrap(), [0u8; 32]);
    }

    #[test]
    fn wrong_nullifier_key_fails_bundle_commitment() {
        let bundle = decode_hex(BUNDLE_HEX);
        let witness = fixture_witness(
            &bundle,
            500,
            [0xA1; RHO_BYTES],
            [0x45; KEY_BYTES],
            fixed(COMMITMENT_HEX),
            fixed(NULLIFIER_HEX),
        );
        assert!(verify_v3_nullifier_witness(&witness)
            .unwrap_err().contains("does not open"));
    }

    #[test]
    fn changed_value_or_commitment_salt_fails_opening() {
        let bundle = decode_hex(BUNDLE_HEX);
        for (value, rho) in [(501u64, [0xA1; RHO_BYTES]), (500u64, [0xA2; RHO_BYTES])] {
            let witness = fixture_witness(
                &bundle, value, rho, [0x44; KEY_BYTES],
                fixed(COMMITMENT_HEX), fixed(NULLIFIER_HEX),
            );
            assert!(verify_v3_nullifier_witness(&witness)
                .unwrap_err().contains("CommitV3 opening"));
        }
    }

    #[test]
    fn changed_expected_nullifier_is_rejected() {
        let bundle = decode_hex(BUNDLE_HEX);
        let mut wrong_nullifier = fixed::<HASH_BYTES>(NULLIFIER_HEX);
        wrong_nullifier[0] ^= 1;
        let witness = fixture_witness(
            &bundle, 500, [0xA1; RHO_BYTES], [0x44; KEY_BYTES],
            fixed(COMMITMENT_HEX), wrong_nullifier,
        );
        assert!(verify_v3_nullifier_witness(&witness)
            .unwrap_err().contains("NullifierV3"));
    }

    #[test]
    fn malformed_bundle_and_trailing_witness_bytes_are_rejected() {
        let mut bundle = decode_hex(BUNDLE_HEX);
        bundle[0] ^= 1;
        let bad_bundle_witness = fixture_witness(
            &bundle, 500, [0xA1; RHO_BYTES], [0x44; KEY_BYTES],
            fixed(COMMITMENT_HEX), fixed(NULLIFIER_HEX),
        );
        assert!(verify_v3_nullifier_witness(&bad_bundle_witness)
            .unwrap_err().contains("BundleV3 domain/version"));

        let mut trailing = valid_witness();
        trailing.push(0);
        assert!(verify_v3_nullifier_witness(&trailing)
            .unwrap_err().contains("trailing bytes"));
    }
}
