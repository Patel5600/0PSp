use eyre::{bail, Context, Result};
use openvm_continuations::CommitBytes;
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    fs::write_object_to_file,
    keygen::AppVerifyingKey,
    prover::verify_app_proof_with_expected_exe_commit,
    DefaultStarkEngine, Sdk, StdIn,
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_backend::{p3_field::PrimeField32, soundness::SoundnessCalculator};
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security, base_field_order, challenge_field_bits,
    MAX_APP_LOG_STACKED_HEIGHT,
};
use std::{
    env, fs,
    path::Path,
    time::Instant,
};

const PUBLIC_VALUE_BYTES: usize = 64;
const PINNED_OPENVM_REV: &str = "59a69b8b0cbee7011ac978e4cc07707ee3681944";
const DECLARED_UPSTREAM_SOUNDNESS_BITS: u32 = 100;
const REQUIRED_COMPOSITE_SOUNDNESS_BITS: u32 = 128;
const REQUIRED_APP_RBR_SOUNDNESS_BITS: f64 = 100.0;
const APP_MAX_CONSTRAINTS: usize = 5_000;
const APP_NUM_AIRS: usize = 100;
const APP_MAX_LOG_HEIGHT: usize = 24;
const APP_NUM_COLUMNS: usize = 30_000;
const APP_MAX_INTERACTIONS_PER_AIR: usize = 1_000;
const APP_SOUNDNESS_SOURCE: &str =
    "openvm-org/stark-backend@v2.0.1/crates/stark-backend/tests/soundness.rs";

fn sdk_from_config(path: &Path) -> Result<Sdk> {
    let toml = fs::read_to_string(path)
        .with_context(|| format!("reading OpenVM config {}", path.display()))?;
    let mut vm_config = SdkVmConfig::from_toml(&toml)
        .with_context(|| format!("parsing OpenVM config {}", path.display()))?;
    // OpenVM 2.0.2 defaults this memory region to 32 bytes. Keep the
    // logical public-value count and the public-value address space in sync.
    vm_config.system.config = vm_config
        .system
        .config
        .clone()
        .with_public_values(PUBLIC_VALUE_BYTES);
    let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    Sdk::new(
        AppConfig::new(vm_config, app_params),
        AggregationSystemParams::default(),
    )
    .map_err(Into::into)
}

fn read_elf(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("reading guest ELF {}", path.display()))?;
    if bytes.len() < 4 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        bail!("guest executable is not an ELF file: {}", path.display());
    }
    Ok(bytes)
}

fn input_from_witness(path: &Path) -> Result<StdIn> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading witness fixture {}", path.display()))?;
    if bytes.is_empty() {
        bail!("witness fixture is empty: {}", path.display());
    }
    // read_vec() reads a u32 byte length followed by the raw bytes from one
    // hint stream. StdIn::write_bytes creates that byte-oriented stream; write()
    // would serde-encode Vec<u8> into a different format and corrupt the magic.
    Ok(StdIn::from_bytes(&bytes))
}

fn as_public_bytes(values: &[openvm_sdk::F]) -> Result<Vec<u8>> {
    if values.len() != PUBLIC_VALUE_BYTES {
        bail!(
            "SDK exposed {} public bytes; expected exactly {}",
            values.len(),
            PUBLIC_VALUE_BYTES
        );
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let word = value.as_canonical_u32();
            if word > u8::MAX as u32 {
                bail!("public output element {index} is not a byte: {word}");
            }
            Ok(word as u8)
        })
        .collect()
}

fn read_hex_file(path: &Path, expected_bytes: usize, label: &str) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    let encoded = raw.trim();
    if encoded.len() != expected_bytes * 2
        || !encoded
            .bytes()
            .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
    {
        bail!("{label} must contain exactly {expected_bytes} bytes of lowercase hexadecimal");
    }
    hex::decode(encoded).with_context(|| format!("decoding {label}"))
}


fn calculate_pinned_app_rbr_soundness() -> (SoundnessCalculator, usize) {
    // Match the conservative application bounds used by the exact pinned upstream
    // backend test suite. This is the app-level RBR calculator only, not the
    // composed 0PSP post-quantum bound and not a witness-hiding proof.
    let params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    let field_bound =
        (params.logup.max_interaction_count as f64).log2().ceil() as usize - params.l_skip;
    let param_bound = (APP_NUM_AIRS as f64).log2().ceil() as usize
        + (APP_MAX_INTERACTIONS_PER_AIR as f64).log2().ceil() as usize
        + APP_MAX_LOG_HEIGHT
        - params.l_skip;
    let n_logup = field_bound.min(param_bound);
    let soundness = SoundnessCalculator::calculate(
        &params,
        base_field_order(),
        challenge_field_bits(),
        APP_MAX_CONSTRAINTS,
        APP_NUM_AIRS,
        params.max_constraint_degree,
        APP_MAX_LOG_HEIGHT,
        APP_NUM_COLUMNS,
        params.w_stack,
        n_logup,
    );
    (soundness, n_logup)
}

fn write_security_profile_manifest(
    evidence_dir: &Path,
    app_commit_hex: &str,
) -> Result<()> {
    // This is reproducibility metadata plus the pinned backend's app-only RBR
    // calculation, not a composed post-quantum security proof.
    let (soundness, n_logup) = calculate_pinned_app_rbr_soundness();
    if !soundness.total_bits.is_finite()
        || soundness.total_bits < REQUIRED_APP_RBR_SOUNDNESS_BITS
    {
        bail!(
            "pinned OpenVM app RBR soundness calculator returned {:.3} bits; upstream 100-bit baseline is not met",
            soundness.total_bits
        );
    }
    let manifest = serde_json::json!({
        "schema": "0psp.openvm.candidate-security-profile.v1",
        "backend": "OpenVM",
        "openvm_git_revision": PINNED_OPENVM_REV,
        "security_parameter_constructor": "app_params_with_100_bits_security",
        "upstream_declared_soundness_bits": DECLARED_UPSTREAM_SOUNDNESS_BITS,
        "calculated_app_rbr_soundness_bits": soundness.total_bits,
        "app_rbr_soundness_target_met": soundness.total_bits >= REQUIRED_APP_RBR_SOUNDNESS_BITS,
        "app_rbr_soundness_components_bits": {
            "logup": soundness.logup_bits,
            "gkr_sumcheck": soundness.gkr_sumcheck_bits,
            "gkr_batching": soundness.gkr_batching_bits,
            "zerocheck_sumcheck": soundness.zerocheck_sumcheck_bits,
            "constraint_batching": soundness.constraint_batching_bits,
            "stacked_reduction": soundness.stacked_reduction_bits,
            "whir": soundness.whir_bits
        },
        "upstream_app_soundness_bounds": {
            "max_constraints_per_air": APP_MAX_CONSTRAINTS,
            "num_airs": APP_NUM_AIRS,
            "max_log_trace_height": APP_MAX_LOG_HEIGHT,
            "num_trace_columns": APP_NUM_COLUMNS,
            "max_interactions_per_air": APP_MAX_INTERACTIONS_PER_AIR,
            "n_logup_bound": n_logup,
            "source": APP_SOUNDNESS_SOURCE
        },
        "composite_post_quantum_soundness_bits": null,
        "composite_post_quantum_target_met": false,
        "required_composite_soundness_bits": REQUIRED_COMPOSITE_SOUNDNESS_BITS,
        "security_target_met": false,
        "profile_status": "NO-GO",
        "relation_scope": "experimental one-input/one-output V3 candidate",
        "complete_production_spend_relation_established": false,
        "end_to_end_witness_hiding_established": false,
        "trusted_finalized_state_established": false,
        "atomic_issue_spend_reorg_recovery_established": false,
        "production_acceptance_enabled": false,
        "application_executable_commitment": app_commit_hex,
        "interpretation": "Calculated pinned upstream app-only round-by-round soundness plus provenance; not a composed post-quantum bound or zero-knowledge proof."
    });
    let path = evidence_dir.join("security-profile.json");
    fs::write(&path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing security profile manifest {}", path.display()))?;
    println!("V3_SPIKE_SECURITY_PROFILE_MANIFEST={}", path.display());
    println!("V3_SPIKE_APP_RBR_SOUNDNESS_BITS={:.3}", soundness.total_bits);
    println!("V3_SPIKE_APP_RBR_N_LOGUP_BOUND={n_logup}");
    println!("V3_SPIKE_SECURITY_PROFILE_STATUS=NO-GO (app-only RBR calculated; composed 128-bit PQ target and witness hiding unmet)");
    Ok(())
}

fn execute(config: &Path, elf_path: &Path, witness_path: &Path) -> Result<()> {
    let sdk = sdk_from_config(config)?;
    let elf = read_elf(elf_path)?;
    let stdin = input_from_witness(witness_path)?;
    let output = sdk
        .execute(elf, stdin)
        .with_context(|| format!("OpenVM rejected witness {}", witness_path.display()))?;
    if output.len() != PUBLIC_VALUE_BYTES {
        bail!(
            "OpenVM exposed {} public bytes; expected exactly {}",
            output.len(),
            PUBLIC_VALUE_BYTES
        );
    }
    println!("Execution output: {:?}", output);
    Ok(())
}

fn peak_rss_kib() -> Result<u64> {
    // GitHub Actions uses Linux; VmHWM is the measured process-wide high-water mark.
    let status = fs::read_to_string("/proc/self/status")
        .context("reading /proc/self/status for SDK runner RSS high-water mark")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or_else(|| eyre::eyre!("Linux status file omitted VmHWM"))?;
    let kib = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| eyre::eyre!("malformed VmHWM line"))?
        .parse::<u64>()
        .context("invalid VmHWM value")?;
    if kib == 0 {
        bail!("process RSS high-water mark was zero");
    }
    Ok(kib)
}

fn write_metric(path: &Path, key: &str, seconds: f64, rss_kib: u64) -> Result<()> {
    if !seconds.is_finite() || seconds < 0.0 {
        bail!("invalid timer value for {key}");
    }
    fs::write(path, format!("{key}={seconds:.6} MAX_RSS_KIB={rss_kib}\n"))
        .with_context(|| format!("writing metrics {}", path.display()))?;
    Ok(())
}

fn prove_one(
    sdk: &Sdk,
    elf: &[u8],
    fixture_dir: &Path,
    app_vk: &AppVerifyingKey,
    app_commit: CommitBytes,
    witness_name: &str,
    digest_name: &str,
    proof_name: &str,
) -> Result<(f64, f64)> {
    let witness_path = fixture_dir.join(witness_name);
    let stdin = input_from_witness(&witness_path)?;
    let mut prover = sdk
        .app_prover(elf.to_vec())
        .with_context(|| format!("constructing app prover for {witness_name}"))?;

    let prove_started = Instant::now();
    let proof = prover
        .prove(stdin)
        .with_context(|| format!("generating app proof for {witness_name}"))?;
    let prove_seconds = prove_started.elapsed().as_secs_f64();

    let verify_started = Instant::now();
    verify_app_proof_with_expected_exe_commit::<DefaultStarkEngine>(
        app_vk,
        &proof,
        Some(prover.app_exe_commit()),
    )
    .with_context(|| format!("verifying app proof for {witness_name}"))?;
    let verify_seconds = verify_started.elapsed().as_secs_f64();

    if CommitBytes::from(prover.app_exe_commit()) != app_commit {
        bail!("application executable commitment changed while proving {witness_name}");
    }
    let actual = as_public_bytes(&proof.user_public_values.public_values)?;
    let expected = read_hex_file(&fixture_dir.join(digest_name), 64, "expected public digest")?;
    if actual != expected {
        bail!(
            "verified proof for {witness_name} exposes digest {}, expected {}",
            hex::encode(actual),
            hex::encode(expected)
        );
    }

    let proof_path = fixture_dir.join(proof_name);
    write_object_to_file(&proof_path, &proof)
        .with_context(|| format!("writing proof {}", proof_path.display()))?;
    println!(
        "PASS: app proof generated and verified for {witness_name}; proof_bytes={} public_digest={}",
        fs::metadata(&proof_path)?.len(),
        hex::encode(expected),
    );
    Ok((prove_seconds, verify_seconds))
}

fn prove(
    config: &Path,
    elf_path: &Path,
    fixture_dir: &Path,
    app_vk_path: &Path,
    expected_commit_path: &Path,
    evidence_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(evidence_dir)?;
    let sdk = sdk_from_config(config)?;
    let elf = read_elf(elf_path)?;

    let keygen_started = Instant::now();
    let (_app_pk, app_vk) = sdk.app_keygen();
    let keygen_seconds = keygen_started.elapsed().as_secs_f64();
    if app_vk.num_user_pvs != PUBLIC_VALUE_BYTES {
        bail!(
            "SDK verifying key expects {} public values; expected {}",
            app_vk.num_user_pvs,
            PUBLIC_VALUE_BYTES
        );
    }
    write_object_to_file(app_vk_path, &app_vk)
        .with_context(|| format!("writing app verifying key {}", app_vk_path.display()))?;

    let probe = sdk
        .app_prover(elf.clone())
        .context("constructing SDK app prover for executable commitment")?;
    let app_commit = CommitBytes::from(probe.app_exe_commit());
    let commit_hex = hex::encode(app_commit.as_slice());
    fs::write(evidence_dir.join("generated-app-exe-commit.txt"), format!("{commit_hex}\n"))?;
    write_security_profile_manifest(evidence_dir, &commit_hex)?;
    println!("V3_SPIKE_GENERATED_APP_EXE_COMMIT={commit_hex}");
    let expected_commit = read_hex_file(expected_commit_path, 32, "pinned app executable commitment")?;
    if expected_commit.as_slice() != app_commit.as_slice() {
        bail!(
            "custom 64-byte OpenVM profile changed the app executable commitment; review and pin {} before accepting proofs",
            commit_hex
        );
    }

    let (app_prove_seconds, app_verify_seconds) = prove_one(
        &sdk,
        &elf,
        fixture_dir,
        &app_vk,
        app_commit,
        "valid.witness",
        "expected-public-digest.txt",
        "valid.app.proof",
    )?;
    let (spend_prove_seconds, spend_verify_seconds) = prove_one(
        &sdk,
        &elf,
        fixture_dir,
        &app_vk,
        app_commit,
        "spend-valid.witness",
        "expected-spend-public-digest.txt",
        "spend-valid.app.proof",
    )?;

    let rss_kib = peak_rss_kib()?;
    // Each stage time is measured separately. RSS is the combined SDK runner's
    // process high-water mark, not a separate per-stage memory measurement.
    write_metric(
        &evidence_dir.join("keygen.metrics"),
        "V3_SPIKE_KEYGEN_SECONDS",
        keygen_seconds,
        rss_kib,
    )?;
    write_metric(
        &evidence_dir.join("app-prove.metrics"),
        "V3_SPIKE_APP_PROVE_SECONDS",
        app_prove_seconds,
        rss_kib,
    )?;
    write_metric(
        &evidence_dir.join("app-verify.metrics"),
        "V3_SPIKE_APP_VERIFY_SECONDS",
        app_verify_seconds,
        rss_kib,
    )?;
    write_metric(
        &evidence_dir.join("spend-prove.metrics"),
        "V3_SPIKE_SPEND_PROVE_SECONDS",
        spend_prove_seconds,
        rss_kib,
    )?;
    write_metric(
        &evidence_dir.join("spend-verify.metrics"),
        "V3_SPIKE_SPEND_VERIFY_SECONDS",
        spend_verify_seconds,
        rss_kib,
    )?;
    println!(
        "V3_SPIKE_SDK_RUNNER_PEAK_RSS_KIB={rss_kib} (combined keygen, proving and verification process)"
    );
    Ok(())
}


fn prove_single_dynamic(
    config: &Path,
    elf_path: &Path,
    witness_path: &Path,
    expected_digest_path: &Path,
    proof_output_path: &Path,
    app_vk_path: &Path,
    expected_commit_path: &Path,
    evidence_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(evidence_dir)?;
    if let Some(parent) = proof_output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = app_vk_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let sdk = sdk_from_config(config)?;
    let elf = read_elf(elf_path)?;

    let keygen_started = Instant::now();
    let (_app_pk, app_vk) = sdk.app_keygen();
    let keygen_seconds = keygen_started.elapsed().as_secs_f64();
    if app_vk.num_user_pvs != PUBLIC_VALUE_BYTES {
        bail!(
            "SDK verifying key expects {} public values; expected {}",
            app_vk.num_user_pvs,
            PUBLIC_VALUE_BYTES
        );
    }
    write_object_to_file(app_vk_path, &app_vk)
        .with_context(|| format!("writing app verifying key {}", app_vk_path.display()))?;

    let probe = sdk
        .app_prover(elf.clone())
        .context("constructing SDK app prover for dynamic ledger executable commitment")?;
    let app_commit = CommitBytes::from(probe.app_exe_commit());
    let commit_hex = hex::encode(app_commit.as_slice());
    fs::write(
        evidence_dir.join("generated-app-exe-commit.txt"),
        format!("{commit_hex}\n"),
    )?;
    write_security_profile_manifest(evidence_dir, &commit_hex)?;
    let expected_commit =
        read_hex_file(expected_commit_path, 32, "pinned app executable commitment")?;
    if expected_commit.as_slice() != app_commit.as_slice() {
        bail!(
            "dynamic ledger proof executable commitment differs from the reviewed pin: generated {}",
            commit_hex
        );
    }

    let fixture_dir = evidence_dir.join("single-proof-fixture");
    fs::create_dir_all(&fixture_dir)?;
    fs::copy(witness_path, fixture_dir.join("spend-valid.witness"))
        .with_context(|| format!("staging dynamic witness {}", witness_path.display()))?;
    fs::copy(
        expected_digest_path,
        fixture_dir.join("expected-spend-public-digest.txt"),
    )
    .with_context(|| format!("staging expected public digest {}", expected_digest_path.display()))?;

    let (prove_seconds, verify_seconds) = prove_one(
        &sdk,
        &elf,
        &fixture_dir,
        &app_vk,
        app_commit,
        "spend-valid.witness",
        "expected-spend-public-digest.txt",
        "ledger-spend.app.proof",
    )?;
    let generated_proof = fixture_dir.join("ledger-spend.app.proof");
    fs::copy(&generated_proof, proof_output_path).with_context(|| {
        format!(
            "copying generated proof to {}",
            proof_output_path.display()
        )
    })?;

    let rss_kib = peak_rss_kib()?;
    write_metric(
        &evidence_dir.join("ledger-keygen.metrics"),
        "V3_SPIKE_LEDGER_KEYGEN_SECONDS",
        keygen_seconds,
        rss_kib,
    )?;
    write_metric(
        &evidence_dir.join("ledger-spend-prove.metrics"),
        "V3_SPIKE_LEDGER_SPEND_PROVE_SECONDS",
        prove_seconds,
        rss_kib,
    )?;
    write_metric(
        &evidence_dir.join("ledger-spend-verify.metrics"),
        "V3_SPIKE_LEDGER_SPEND_VERIFY_SECONDS",
        verify_seconds,
        rss_kib,
    )?;
    println!("V3_SPIKE_LEDGER_PROOF_BYTES={}", fs::metadata(proof_output_path)?.len());
    println!("V3_SPIKE_LEDGER_APP_EXE_COMMIT={commit_hex}");
    println!("V3_SPIKE_LEDGER_PROOF_PATH={}", proof_output_path.display());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") if args.len() == 5 => execute(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        ),
        Some("prove") if args.len() == 8 => prove(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            Path::new(&args[5]),
            Path::new(&args[6]),
            Path::new(&args[7]),
        ),
        Some("prove-one") if args.len() == 10 => prove_single_dynamic(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            Path::new(&args[5]),
            Path::new(&args[6]),
            Path::new(&args[7]),
            Path::new(&args[8]),
            Path::new(&args[9]),
        ),
        _ => {
            bail!(
                "usage:\n  openvm-v3-sdk-runner run CONFIG ELF WITNESS\n  openvm-v3-sdk-runner prove CONFIG ELF FIXTURE_DIR APP_VK EXPECTED_COMMIT EVIDENCE_DIR\n  openvm-v3-sdk-runner prove-one CONFIG ELF WITNESS EXPECTED_DIGEST_HEX PROOF_OUT APP_VK EXPECTED_COMMIT EVIDENCE_DIR"
            )
        }
    }
}

#[cfg(test)]
mod security_profile_manifest_tests {
    use super::*;
    use std::fs;

    #[test]
    fn manifest_never_claims_the_128_bit_target_is_met() {
        let root = std::env::temp_dir().join(format!(
            "0psp-openvm-profile-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create test evidence directory");
        write_security_profile_manifest(&root, &"ab".repeat(32))
            .expect("manifest write must succeed");
        let bytes = fs::read(root.join("security-profile.json")).expect("read manifest");
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("manifest must be valid JSON");
        assert_eq!(value["openvm_git_revision"], PINNED_OPENVM_REV);
        assert_eq!(value["security_parameter_constructor"], "app_params_with_100_bits_security");
        assert_eq!(value["upstream_declared_soundness_bits"], 100);
        assert!(value["calculated_app_rbr_soundness_bits"].as_f64().unwrap() >= 100.0);
        assert_eq!(value["app_rbr_soundness_target_met"], true);
        assert_eq!(value["upstream_app_soundness_bounds"]["max_constraints_per_air"], 5000);
        assert_eq!(value["upstream_app_soundness_bounds"]["num_airs"], 100);
        assert_eq!(value["upstream_app_soundness_bounds"]["n_logup_bound"].as_u64(), Some(calculate_pinned_app_rbr_soundness().1 as u64));
        assert_eq!(value["composite_post_quantum_soundness_bits"], serde_json::Value::Null);
        assert_eq!(value["composite_post_quantum_target_met"], false);
        assert_eq!(value["required_composite_soundness_bits"], 128);
        assert_eq!(value["security_target_met"], false);
        assert_eq!(value["profile_status"], "NO-GO");
        assert_eq!(value["end_to_end_witness_hiding_established"], false);
        assert_eq!(value["production_acceptance_enabled"], false);
        fs::remove_dir_all(root).expect("remove test evidence directory");
    }
}

