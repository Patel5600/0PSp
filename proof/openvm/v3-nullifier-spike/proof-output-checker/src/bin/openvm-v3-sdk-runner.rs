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
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security, MAX_APP_LOG_STACKED_HEIGHT,
};
use std::{
    env, fs,
    path::Path,
    time::Instant,
};

const PUBLIC_VALUE_BYTES: usize = 64;

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
    let mut stdin = StdIn::default();
    // read_vec() in the guest expects a serde-encoded Vec<u8>, including its length.
    stdin.write(&bytes);
    Ok(stdin)
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
        .context("Linux status file omitted VmHWM")?;
    let kib = line
        .split_whitespace()
        .nth(1)
        .context("malformed VmHWM line")?
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
        _ => {
            bail!(
                "usage:\n  openvm-v3-sdk-runner run CONFIG ELF WITNESS\n  openvm-v3-sdk-runner prove CONFIG ELF FIXTURE_DIR APP_VK EXPECTED_COMMIT EVIDENCE_DIR"
            )
        }
    }
}
