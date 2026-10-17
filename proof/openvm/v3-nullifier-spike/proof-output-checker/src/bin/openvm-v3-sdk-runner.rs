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
use openvm_stark_backend::p3_field::PrimeField32;
#[cfg(test)]
use openvm_stark_backend::{
    interaction::LogUpSecurityParameters, soundness::SoundnessCalculator, SystemParams,
    WhirProximityStrategy,
};
use openvm_stark_sdk::config::{app_params_with_100_bits_security, MAX_APP_LOG_STACKED_HEIGHT};
#[cfg(test)]
use openvm_stark_sdk::config::{
    base_field_order, challenge_field_bits, DEFAULT_APP_LOG_BLOWUP, DEFAULT_APP_L_SKIP,
    DEFAULT_INTERNAL_LOG_BLOWUP, DEFAULT_K_WHIR, DEFAULT_LEAF_LOG_BLOWUP,
    DEFAULT_WHIR_QUERY_PHASE_POW_BITS, RECURSION_MAX_CONSTRAINT_DEGREE,
    WHIR_MAX_LOG_FINAL_POLY_LEN,
};
use std::{
    env, fs,
    io::{Read, Write},
    path::Path,
    time::Instant,
};
use zeroize::Zeroize;

const PUBLIC_VALUE_BYTES: usize = 64;
const MAX_STDIN_WITNESS_BYTES: usize = 2_000_000;
const PROOF_RESPONSE_MAGIC: &[u8] = b"0PSP-OPENVM-APP-PROOF-v1";
#[cfg(test)]
const TARGET_SECURITY_BITS: usize = 128;

#[cfg(test)]
fn params_with_target_security(
    log_blowup: usize,
    l_skip: usize,
    n_stack: usize,
    w_stack: usize,
    folding_pow_bits: usize,
    mu_pow_bits: usize,
    proximity: WhirProximityStrategy,
    max_constraint_degree: usize,
    query_phase_pow_bits: usize,
) -> SystemParams {
    let max_interaction_count = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT)
        .logup
        .max_interaction_count;
    let log2_pcs_list_size = SoundnessCalculator::whir_proximity_gap_security(
        proximity.initial_round(),
        challenge_field_bits(),
        l_skip + n_stack,
        log_blowup,
        w_stack,
    )
    .log2_list_size;
    let logup_without_pow = SoundnessCalculator::logup_soundness(
        max_interaction_count,
        7,
        challenge_field_bits(),
        log2_pcs_list_size,
    );
    // The backend's BabyBear grinding costs slightly less than one bit per nominal
    // bit. Add a two-bit margin, then assert the full RBR bound below in tests.
    let logup_pow_bits = ((TARGET_SECURITY_BITS as f64 - logup_without_pow)
        .ceil()
        .max(0.0) as usize)
        .max(18)
        + 2;

    SystemParams::new(
        log_blowup,
        l_skip,
        n_stack,
        w_stack,
        WHIR_MAX_LOG_FINAL_POLY_LEN,
        folding_pow_bits,
        mu_pow_bits,
        proximity,
        TARGET_SECURITY_BITS,
        LogUpSecurityParameters {
            max_interaction_count,
            log_max_message_length: 7,
            pow_bits: logup_pow_bits,
        },
        max_constraint_degree,
        query_phase_pow_bits,
        DEFAULT_K_WHIR,
    )
}

#[cfg(test)]
fn app_params_with_128_bits_security() -> SystemParams {
    params_with_target_security(
        DEFAULT_APP_LOG_BLOWUP,
        DEFAULT_APP_L_SKIP,
        MAX_APP_LOG_STACKED_HEIGHT - DEFAULT_APP_L_SKIP,
        2048,
        5,
        15,
        WhirProximityStrategy::UniqueDecoding,
        3,
        DEFAULT_WHIR_QUERY_PHASE_POW_BITS,
    )
}

#[cfg(test)]
fn leaf_params_with_128_bits_security() -> SystemParams {
    params_with_target_security(
        DEFAULT_LEAF_LOG_BLOWUP,
        4,
        17,
        2048,
        4,
        13,
        WhirProximityStrategy::UniqueDecoding,
        RECURSION_MAX_CONSTRAINT_DEGREE,
        DEFAULT_WHIR_QUERY_PHASE_POW_BITS,
    )
}

#[cfg(test)]
fn internal_params_with_128_bits_security() -> SystemParams {
    params_with_target_security(
        DEFAULT_INTERNAL_LOG_BLOWUP,
        2,
        17,
        512,
        18,
        20,
        WhirProximityStrategy::ListDecoding { m: 2 },
        RECURSION_MAX_CONSTRAINT_DEGREE,
        DEFAULT_WHIR_QUERY_PHASE_POW_BITS,
    )
}

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
    Sdk::new(
        AppConfig::new(
            vm_config,
            app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT),
        ),
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
    let bytes =
        fs::read(path).with_context(|| format!("reading witness fixture {}", path.display()))?;
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
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading {label} {}", path.display()))?;
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

fn prove_stdin(config: &Path, elf_path: &Path) -> Result<()> {
    let sdk = sdk_from_config(config)?;
    let elf = read_elf(elf_path)?;
    let mut witness = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((MAX_STDIN_WITNESS_BYTES + 1) as u64)
        .read_to_end(&mut witness)
        .context("reading in-memory witness from stdin")?;
    if witness.is_empty() || witness.len() > MAX_STDIN_WITNESS_BYTES {
        bail!("stdin witness length is outside configured bounds");
    }

    // StdIn owns its own byte stream. Wipe the transport buffer immediately; the
    // prover's internal execution data is process-local and is released on exit.
    let input = StdIn::from_bytes(&witness);
    witness.zeroize();
    let (_app_pk, app_vk) = sdk.app_keygen();
    let mut prover = sdk
        .app_prover(elf)
        .context("constructing one-shot OpenVM app prover")?;
    let proof = prover
        .prove(input)
        .context("generating one-shot OpenVM app proof")?;
    verify_app_proof_with_expected_exe_commit::<DefaultStarkEngine>(
        &app_vk,
        &proof,
        Some(prover.app_exe_commit()),
    )
    .context("locally verifying one-shot OpenVM app proof")?;
    let public_inputs = as_public_bytes(&proof.user_public_values.public_values)?;
    let proof_bytes = bitcode::serialize(&proof).context("encoding OpenVM app proof")?;
    let proof_len =
        u32::try_from(proof_bytes.len()).context("proof response exceeds u32 length")?;

    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    output.write_all(PROOF_RESPONSE_MAGIC)?;
    output.write_all(&public_inputs)?;
    output.write_all(&proof_len.to_be_bytes())?;
    output.write_all(&proof_bytes)?;
    output.flush()?;
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
    fs::write(
        evidence_dir.join("generated-app-exe-commit.txt"),
        format!("{commit_hex}\n"),
    )?;
    println!("V3_SPIKE_GENERATED_APP_EXE_COMMIT={commit_hex}");
    let expected_commit =
        read_hex_file(expected_commit_path, 32, "pinned app executable commitment")?;
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

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove-stdin") if args.len() == 4 => {
            prove_stdin(Path::new(&args[2]), Path::new(&args[3]))
        }
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
        _ => {
            bail!(
                "usage:\n  openvm-v3-sdk-runner run CONFIG ELF WITNESS\n  openvm-v3-sdk-runner prove CONFIG ELF FIXTURE_DIR APP_VK EXPECTED_COMMIT EVIDENCE_DIR\n  openvm-v3-sdk-runner prove-stdin CONFIG ELF"
            )
        }
    }
}

#[cfg(test)]
mod security_profile_tests {
    use super::*;

    #[test]
    fn active_backend_parameters_match_release_manifest() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../openvm.toml");
        let toml = fs::read_to_string(config_path).expect("read pinned OpenVM config");
        let mut vm_config = SdkVmConfig::from_toml(&toml).expect("parse pinned OpenVM config");
        vm_config.system.config = vm_config
            .system
            .config
            .clone()
            .with_public_values(PUBLIC_VALUE_BYTES);
        let app = AppConfig::new(
            vm_config,
            app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT),
        );
        let aggregation = AggregationSystemParams::default();
        let parameters = serde_json::json!({
            "app_config": app,
            "aggregation": aggregation,
            "transcript": {
                "engine": "BabyBearPoseidon2CpuEngine<CpuTranscript>",
                "field": "BabyBear",
                "extension_degree": 4,
                "permutation": "Poseidon2BabyBear<16>",
                "challenger": "Plonky3 DuplexChallenger",
                "width": 16,
                "rate": 8,
                "digest_elements": 8,
            }
        });
        let pin_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../production1-pins.json");
        let pins: serde_json::Value = serde_json::from_slice(
            &fs::read(pin_path).expect("read Production-1 pin manifest"),
        )
        .expect("parse Production-1 pin manifest");
        assert_eq!(
            pins["backend_parameters"], parameters,
            "active OpenVM FRI/STARK, VM, aggregation, or transcript parameters drifted"
        );
        let engine_type = std::any::type_name::<DefaultStarkEngine>();
        assert!(
            engine_type.contains("BabyBearPoseidon2CpuEngine"),
            "the pinned release must use the BabyBear/Poseidon2 CPU engine"
        );
        let rbr_assumptions = serde_json::json!({
            "max_trace_log_height": 24,
            "max_constraints_per_air": 5000,
            "num_airs": 100,
            "max_interactions_per_air": 1000,
            "num_trace_columns": 30000,
            "w_stack": 2048,
            "bound_scope": "OpenVM application RBR calculator under declared ceilings; not Fiat-Shamir/QROM composition"
        });
        assert_eq!(
            pins["security_profile"]["app_rbr_assumptions"],
            rbr_assumptions,
            "active RBR assumption set drifted from the release manifest"
        );
        let active_app_rbr_bits = profile_bits(
            "active-app",
            &app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT),
            rbr_assumptions["max_constraints_per_air"].as_u64().unwrap() as usize,
            rbr_assumptions["num_airs"].as_u64().unwrap() as usize,
            rbr_assumptions["max_trace_log_height"].as_u64().unwrap() as usize,
            rbr_assumptions["num_trace_columns"].as_u64().unwrap() as usize,
            rbr_assumptions["max_interactions_per_air"].as_u64().unwrap() as usize,
        );
        eprintln!("active preset app-RBR under pinned upstream bounds: {active_app_rbr_bits:.5} bits");
        let expected_app_rbr_bits = pins["security_profile"]["calculated_active_app_rbr_bits"]
            .as_f64()
            .expect("manifest app-RBR value is numeric");
        assert!(
            (active_app_rbr_bits - expected_app_rbr_bits).abs() < 1e-9,
            "active app-RBR calculation drifted from release manifest"
        );
        assert!(active_app_rbr_bits < TARGET_SECURITY_BITS as f64);
    }

    fn n_logup_bound(
        params: &SystemParams,
        num_airs: usize,
        max_interactions_per_air: usize,
        max_log_height: usize,
    ) -> usize {
        let field_bound =
            (params.logup.max_interaction_count as f64).log2().ceil() as usize - params.l_skip;
        let profile_bound = (num_airs as f64).log2().ceil() as usize
            + (max_interactions_per_air as f64).log2().ceil() as usize
            + max_log_height
            - params.l_skip;
        field_bound.min(profile_bound)
    }

    fn profile_bits(
        label: &str,
        params: &SystemParams,
        max_constraints: usize,
        num_airs: usize,
        max_log_height: usize,
        num_columns: usize,
        max_interactions_per_air: usize,
    ) -> f64 {
        let soundness = SoundnessCalculator::calculate(
            params,
            base_field_order(),
            challenge_field_bits(),
            max_constraints,
            num_airs,
            params.max_constraint_degree,
            max_log_height,
            num_columns,
            params.w_stack,
            n_logup_bound(params, num_airs, max_interactions_per_air, max_log_height),
        );
        eprintln!("{label} full soundness components: {soundness:#?}");
        eprintln!(
            "{label} proposed 128-bit profile actually yields {:.2} bits",
            soundness.total_bits
        );
        soundness.total_bits
    }

    #[test]
    fn proposed_profiles_do_not_clear_128_bits_under_documented_bounds() {
        assert!(challenge_field_bits() < TARGET_SECURITY_BITS as f64);
        assert!(
            profile_bits(
                "app",
                &app_params_with_128_bits_security(),
                5000,
                100,
                24,
                30000,
                1000
            ) < TARGET_SECURITY_BITS as f64
        );
        assert!(
            profile_bits(
                "leaf",
                &leaf_params_with_128_bits_security(),
                1000,
                50,
                20,
                2000,
                100
            ) < TARGET_SECURITY_BITS as f64
        );
        assert!(
            profile_bits(
                "internal",
                &internal_params_with_128_bits_security(),
                1000,
                50,
                19,
                2000,
                100,
            ) < TARGET_SECURITY_BITS as f64
        );
    }
}
