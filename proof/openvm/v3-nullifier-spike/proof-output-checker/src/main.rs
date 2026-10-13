use eyre::{bail, Context, Result};
use openvm_sdk::{
    fs::read_object_from_file,
    keygen::AppVerifyingKey,
    prover::verify_app_proof_with_expected_exe_commit,
    types::AppExecutionCommit,
    DefaultStarkEngine,
};
use openvm_stark_backend::p3_field::PrimeField32;
use std::{env, fs, path::Path};

fn parse_hex_file(path: &Path, expected_bytes: usize, label: &str) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("unable to read {label} from {}", path.display()))?;
    let encoded = raw.trim();
    if encoded.len() != expected_bytes * 2 {
        bail!(
            "{label} must contain exactly {} lowercase hex characters",
            expected_bytes * 2
        );
    }
    if !encoded.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        bail!("{label} must be lowercase hexadecimal");
    }
    let decoded = hex::decode(encoded).with_context(|| format!("invalid {label} hex"))?;
    if decoded.len() != expected_bytes {
        bail!("{label} decoded to the wrong width");
    }
    Ok(decoded)
}

fn exact_public_output(actual: &[u8], expected: &[u8]) -> Result<()> {
    if expected.len() != 32 {
        bail!("expected public statement digest must be exactly 32 bytes");
    }
    if actual.len() != expected.len() {
        bail!(
            "proof exposes {} public bytes, expected exactly {}",
            actual.len(),
            expected.len()
        );
    }
    if actual != expected {
        bail!(
            "proof public output mismatch: expected {}, got {}",
            hex::encode(expected),
            hex::encode(actual)
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        bail!(
            "usage: proof-output-checker APP_VK APP_PROOF EXPECTED_EXE_COMMIT_HEX_FILE EXPECTED_DIGEST_HEX_FILE"
        );
    }
    let vk_path = Path::new(&args[1]);
    let proof_path = Path::new(&args[2]);
    let expected_exe_path = Path::new(&args[3]);
    let expected_digest_path = Path::new(&args[4]);

    let expected_exe_bytes: [u8; 32] =
        parse_hex_file(expected_exe_path, 32, "expected app executable commitment")?
            .try_into()
            .expect("width checked");
    let expected_digest = parse_hex_file(expected_digest_path, 32, "expected public digest")?;

    let app_vk: AppVerifyingKey =
        read_object_from_file(vk_path).with_context(|| format!("reading {}", vk_path.display()))?;
    let proof = read_object_from_file(proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;

    // App-proof verification consumes only the expected executable commit here.
    // CommitBytes deserialization performs OpenVM's canonicality check; the unused
    // VM-commit field is syntactically valid zero bytes rather than an asserted value.
    let zero_vm_commit = "0".repeat(64);
    let app_commit_json = format!(
        "{{\"app_exe_commit\":\"0x{}\",\"app_vm_commit\":\"0x{}\"}}",
        hex::encode(expected_exe_bytes),
        zero_vm_commit,
    );
    let app_commit: AppExecutionCommit = serde_json::from_str(&app_commit_json)
        .context("parsing canonical expected OpenVM executable commitment")?;
    verify_app_proof_with_expected_exe_commit::<DefaultStarkEngine>(
        &app_vk,
        &proof,
        Some(app_commit.app_exe_commit.into()),
    )
    .context("OpenVM application proof verification failed or executable commitment mismatched")?;

    // OpenVM's UserPublicValuesProof contains one field element per output byte.
    // Refuse non-byte elements rather than truncating or reducing modulo 256.
    let mut actual = Vec::with_capacity(proof.user_public_values.public_values.len());
    for (index, field_value) in proof.user_public_values.public_values.iter().enumerate() {
        let value = field_value.as_canonical_u32();
        if value > u8::MAX as u32 {
            bail!("public output element {index} is not a byte: {value}");
        }
        actual.push(value as u8);
    }
    exact_public_output(&actual, &expected_digest)?;
    println!(
        "PASS: OpenVM app proof verifies for executable {} and exposes exactly the expected 32-byte public digest {}",
        hex::encode(expected_exe_bytes),
        hex::encode(expected_digest),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::exact_public_output;

    #[test]
    fn exact_32_byte_public_output_is_accepted() {
        let expected: Vec<u8> = (0..32).collect();
        assert!(exact_public_output(&expected, &expected).is_ok());
    }

    #[test]
    fn appended_or_truncated_public_output_is_rejected() {
        let expected: Vec<u8> = (0..32).collect();
        assert!(exact_public_output(&[expected.clone(), vec![0]].concat(), &expected).is_err());
        assert!(exact_public_output(&expected[..31], &expected).is_err());
    }

    #[test]
    fn mutated_public_output_is_rejected() {
        let expected: Vec<u8> = (0..32).collect();
        let mut actual = expected.clone();
        actual[0] ^= 1;
        assert!(exact_public_output(&actual, &expected).is_err());
    }

    #[test]
    fn wrong_expected_digest_width_is_rejected() {
        assert!(exact_public_output(&[0u8; 32], &[0u8; 31]).is_err());
    }
}
