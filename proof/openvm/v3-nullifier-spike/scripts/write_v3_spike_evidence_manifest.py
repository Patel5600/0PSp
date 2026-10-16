#!/usr/bin/env python3
"""Emit a non-secret provenance manifest for the V3 OpenVM CI proof slice.

The manifest intentionally excludes proof bytes, witness fixtures, private inputs,
and raw logs. It records hashes, byte lengths, measured runtime/RSS, tool pins,
and the exact CI/source provenance. This is evidence metadata, not a security
certification or a claim that the candidate relation is production-complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HEX_256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_512_RE = re.compile(r"^[0-9a-f]{128}$")
HEX_160_RE = re.compile(r"^[0-9a-f]{40}$")
METRIC_RE = re.compile(
    r"(?P<key>[A-Z0-9_]+)=([0-9]+(?:\.[0-9]+)?)\s+MAX_RSS_KIB=(\d+)"
)
ARTIFACT_ACTION_SHA = "cf430e030ddbb5b0abf93d22962f4752f3646cd9"
RUST_TOOLCHAIN = "1.91.1"
CARGO_OPENVM_RELEASE = "2.0.2"

APP_REJECTED = [
    "wrong-key",
    "changed-value",
    "changed-salt",
    "wrong-nullifier",
    "bad-bundle",
    "trailing-data",
]
SPEND_REJECTED = [
    "spend-wrong-key",
    "spend-changed-value",
    "spend-changed-salt",
    "spend-wrong-nullifier",
    "spend-bad-bundle",
    "spend-trailing-data",
    "spend-bad-root",
    "spend-bad-path",
    "spend-changed-output-entropy",
    "spend-unknown-policy",
    "spend-value-conservation",
]


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        fail(f"cannot hash {path}: {exc}")
    return digest.hexdigest()


def require_file(path: Path) -> Path:
    if not path.is_file():
        fail(f"required evidence input is missing: {path}")
    return path


def read_text(path: Path) -> str:
    try:
        return require_file(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def read_digest(path: Path, label: str, expected_bytes: int = 32) -> str:
    value = read_text(path)
    if len(value) != expected_bytes * 2 or not re.fullmatch(r"[0-9a-f]+", value):
        fail(f"{label} must contain exactly {expected_bytes} bytes of lowercase hexadecimal")
    return value


def timed_metrics(path: Path, expected_key: str) -> dict[str, Any]:
    text = read_text(path)
    match = METRIC_RE.fullmatch(text)
    if not match:
        fail(f"malformed timing/RSS record in {path}: {text!r}")
    if match.group("key") != expected_key:
        fail(f"unexpected timing key in {path}: {match.group('key')!r}")
    seconds = float(match.group(2))
    rss_kib = int(match.group(3))
    if not math.isfinite(seconds) or seconds < 0 or rss_kib < 1:
        fail(f"invalid measured timing/RSS values in {path}")
    return {
        "seconds": seconds,
        "max_rss_kib": rss_kib,
        "rss_scope": "combined SDK runner high-water mark shared across stage timings; not a per-stage measurement",
    }


def command_record(argv: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "exit_code": None, "output": str(exc)[:1000]}
    lines = result.stdout.strip().splitlines()
    return {
        "argv": argv,
        "exit_code": result.returncode,
        "output_first_lines": lines[:5],
    }


def build_proof_record(
    proof_path: Path,
    prove_metrics: Path,
    verify_metrics: Path,
    prove_key: str,
    verify_key: str,
) -> dict[str, Any]:
    require_file(proof_path)
    size_bytes = proof_path.stat().st_size
    if size_bytes <= 0:
        fail(f"proof output is empty: {proof_path}")
    return {
        "size_bytes": size_bytes,
        "sha256": sha256_file(proof_path),
        "prove": timed_metrics(prove_metrics, prove_key),
        "verify": timed_metrics(verify_metrics, verify_key),
    }


def security_profile_record(evidence_dir: Path, executable_commit: str) -> dict[str, Any]:
    path = require_file(evidence_dir / "security-profile.json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid security profile evidence: {exc}")
    required = {
        "schema": "0psp.openvm.candidate-security-profile.v1",
        "backend": "OpenVM",
        "openvm_git_revision": "59a69b8b0cbee7011ac978e4cc07707ee3681944",
        "security_parameter_constructor": "app_params_with_100_bits_security",
        "upstream_declared_soundness_bits": 100,
        "required_composite_soundness_bits": 128,
        "security_target_met": False,
        "profile_status": "NO-GO",
        "complete_production_spend_relation_established": False,
        "end_to_end_witness_hiding_established": False,
        "trusted_finalized_state_established": False,
        "atomic_issue_spend_reorg_recovery_established": False,
        "production_acceptance_enabled": False,
        "application_executable_commitment": executable_commit,
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            fail(f"security profile evidence field {key!r} is not the required fail-closed value")
    return {
        "sha256": sha256_file(path),
        "schema": value["schema"],
        "backend": value["backend"],
        "openvm_git_revision": value["openvm_git_revision"],
        "security_parameter_constructor": value["security_parameter_constructor"],
        "upstream_declared_soundness_bits": value["upstream_declared_soundness_bits"],
        "required_composite_soundness_bits": value["required_composite_soundness_bits"],
        "security_target_met": value["security_target_met"],
        "profile_status": value["profile_status"],
        "complete_production_spend_relation_established": value["complete_production_spend_relation_established"],
        "end_to_end_witness_hiding_established": value["end_to_end_witness_hiding_established"],
        "trusted_finalized_state_established": value["trusted_finalized_state_established"],
        "atomic_issue_spend_reorg_recovery_established": value["atomic_issue_spend_reorg_recovery_established"],
        "production_acceptance_enabled": value["production_acceptance_enabled"],
    }


def ledger_integration_record(evidence_dir: Path, executable_commit: str) -> dict[str, Any]:
    path = require_file(evidence_dir / "ledger-integration.json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid real-proof ledger integration evidence: {exc}")
    required_true = (
        "dynamic_statement_proof_generated_and_verified",
        "mutated_proof_rejected_without_state_change",
        "valid_proof_accepted_as_atomic_state_transition",
        "duplicate_nullifier_replay_rejected_without_state_change",
        "restart_and_integrity_audit_passed",
    )
    if value.get("schema_version") != 1 or value.get("status") != "PASS":
        fail("real-proof ledger integration evidence is not a PASS record")
    for key in required_true:
        if value.get(key) is not True:
            fail(f"real-proof ledger integration is missing successful gate: {key}")
    if value.get("release_status") != "NO-GO":
        fail("ledger integration evidence must keep production release at NO-GO")
    if value.get("production_acceptance_enabled") is not False:
        fail("ledger integration evidence must keep production acceptance disabled")
    if value.get("bootstrap_state_evidence_is_synthetic") is not True:
        fail("ledger integration must label synthetic bootstrap state evidence")
    if value.get("external_finality_established") is not False:
        fail("ledger integration cannot claim external finality")
    if value.get("end_to_end_witness_hiding_established") is not False:
        fail("ledger integration cannot claim end-to-end witness hiding")
    if value.get("composite_post_quantum_security_bits") is not None:
        fail("unknown composite post-quantum security must remain unknown")
    if value.get("required_composite_post_quantum_security_bits") != 128:
        fail("ledger integration must record the required 128-bit composite target")
    proof_size = value.get("proof_size_bytes")
    if isinstance(proof_size, bool) or not isinstance(proof_size, int) or proof_size <= 0:
        fail("ledger integration proof size must be a positive integer")
    proof_sha = value.get("proof_sha256")
    if not isinstance(proof_sha, str) or not HEX_256_RE.fullmatch(proof_sha):
        fail("ledger integration proof digest must be SHA-256 hex")
    if value.get("app_executable_commitment") != executable_commit:
        fail("ledger proof executable commitment differs from the reviewed pin")
    if not HEX_256_RE.fullmatch(str(value.get("checker_sha256", ""))):
        fail("ledger integration checker SHA-256 missing or malformed")
    if not HEX_256_RE.fullmatch(str(value.get("app_verifying_key_sha256", ""))):
        fail("ledger integration app verifying-key SHA-256 missing or malformed")
    if not HEX_512_RE.fullmatch(str(value.get("public_statement_digest", ""))):
        fail("ledger integration public statement digest must be exactly 64 bytes of lowercase hex")
    return {
        "evidence_sha256": sha256_file(path),
        "status": value["status"],
        "scope": value["scope"],
        "dynamic_statement_proof_generated_and_verified": True,
        "mutated_proof_rejected_without_state_change": True,
        "valid_proof_accepted_as_atomic_state_transition": True,
        "duplicate_nullifier_replay_rejected_without_state_change": True,
        "restart_and_integrity_audit_passed": True,
        "proof_size_bytes": proof_size,
        "proof_sha256": proof_sha,
        "checker_sha256": value["checker_sha256"],
        "app_verifying_key_sha256": value["app_verifying_key_sha256"],
        "app_executable_commitment": value["app_executable_commitment"],
        "public_statement_digest": value["public_statement_digest"],
        "state_version_after_accept": value.get("state_version_after_accept"),
        "bootstrap_state_evidence_is_synthetic": True,
        "external_finality_established": False,
        "end_to_end_witness_hiding_established": False,
        "composite_post_quantum_security_bits": None,
        "required_composite_post_quantum_security_bits": 128,
        "production_acceptance_enabled": False,
        "release_status": "NO-GO",
    }


def build_manifest(fixture_dir: Path, checker_path: Path) -> dict[str, Any]:
    evidence_dir = fixture_dir / "evidence"
    if not evidence_dir.is_dir():
        fail(f"evidence directory is missing: {evidence_dir}")

    candidate_sha = os.environ.get("CANDIDATE_HEAD_SHA", "")
    workflow_sha = os.environ.get("GITHUB_SHA", "")
    base_sha = os.environ.get("CANDIDATE_BASE_SHA", "")
    if not HEX_160_RE.fullmatch(candidate_sha):
        fail("CANDIDATE_HEAD_SHA must be a full 40-character commit SHA")
    if not HEX_160_RE.fullmatch(workflow_sha):
        fail("GITHUB_SHA must be a full 40-character workflow commit SHA")
    if base_sha and not HEX_160_RE.fullmatch(base_sha):
        fail("CANDIDATE_BASE_SHA must be empty or a full 40-character commit SHA")

    cargo_openvm_sha = os.environ.get("CARGO_OPENVM_SHA256", "")
    if not HEX_256_RE.fullmatch(cargo_openvm_sha):
        fail("CARGO_OPENVM_SHA256 must be a full SHA-256 hex digest")

    executable_commit = read_digest(
        Path("expected-app-exe-commit.txt"), "OpenVM executable commitment"
    )
    security_profile = security_profile_record(evidence_dir, executable_commit)
    ledger_integration = ledger_integration_record(evidence_dir, executable_commit)
    app_public_digest = read_digest(
        fixture_dir / "expected-public-digest.txt", "expected app public digest", expected_bytes=64
    )
    spend_public_digest = read_digest(
        fixture_dir / "expected-spend-public-digest.txt", "expected spend public digest", expected_bytes=64
    )
    app_vk = require_file(Path("openvm/app.vk"))
    checker = require_file(checker_path.resolve())
    cargo_lock = require_file(Path("Cargo.lock"))
    checker_lock = require_file(Path("proof-output-checker/Cargo.lock"))
    toolchain_file = require_file(evidence_dir / "toolchain.txt")

    app_proof = build_proof_record(
        fixture_dir / "valid.app.proof",
        evidence_dir / "app-prove.metrics",
        evidence_dir / "app-verify.metrics",
        "V3_SPIKE_APP_PROVE_SECONDS",
        "V3_SPIKE_APP_VERIFY_SECONDS",
    )
    spend_proof = build_proof_record(
        fixture_dir / "spend-valid.app.proof",
        evidence_dir / "spend-prove.metrics",
        evidence_dir / "spend-verify.metrics",
        "V3_SPIKE_SPEND_PROVE_SECONDS",
        "V3_SPIKE_SPEND_VERIFY_SECONDS",
    )
    keygen_metrics = timed_metrics(
        evidence_dir / "keygen.metrics", "V3_SPIKE_KEYGEN_SECONDS"
    )
    toolchain_lines = read_text(toolchain_file).splitlines()
    if not toolchain_lines:
        fail("toolchain version capture is empty")

    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not run_id.isdigit() or not run_attempt.isdigit():
        fail("GitHub workflow run ID/attempt context is missing")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    ref = os.environ.get("GITHUB_REF", "")
    if not repository or not ref:
        fail("GitHub repository/ref context is missing")

    return {
        "schema_version": 1,
        "classification": "NON_PRODUCTION_INTERNAL_CI_EVIDENCE",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "repository": repository,
            "candidate_head_sha": candidate_sha,
            "workflow_sha": workflow_sha,
            "base_sha": base_sha or None,
            "ref": ref,
            "event": os.environ.get("GITHUB_EVENT_NAME", ""),
            "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
            "run_id": int(run_id),
            "run_attempt": int(run_attempt),
            "run_url": f"https://github.com/{repository}/actions/runs/{run_id}",
        },
        "runner": {
            "os": os.environ.get("RUNNER_OS", ""),
            "arch": os.environ.get("RUNNER_ARCH", ""),
            "image": "ubuntu-24.04",
        },
        "pinned_inputs": {
            "rust_toolchain": RUST_TOOLCHAIN,
            "cargo_openvm_release": CARGO_OPENVM_RELEASE,
            "cargo_openvm_archive_sha256": cargo_openvm_sha,
            "guest_cargo_lock_sha256": sha256_file(cargo_lock),
            "checker_cargo_lock_sha256": sha256_file(checker_lock),
            "upload_artifact_action_commit": ARTIFACT_ACTION_SHA,
        },
        "toolchain": {
            "recorded_output": toolchain_lines,
            "rustc": command_record(["rustc", f"+{RUST_TOOLCHAIN}", "--version"]),
            "cargo": command_record(["cargo", f"+{RUST_TOOLCHAIN}", "--version"]),
            "cargo_openvm": command_record(["cargo", f"+{RUST_TOOLCHAIN}", "openvm", "--version"]),
            "riscv_gcc": command_record(["riscv64-unknown-elf-gcc", "--version"]),
        },
        "security_profile": security_profile,
        "ledger_integration": ledger_integration,
        "proof_slice": {
            "guest_executable_commitment": executable_commit,
            "app_verification_key_sha256": sha256_file(app_vk),
            "proof_output_checker_sha256": sha256_file(checker),
            "keygen": keygen_metrics,
            "app": {
                **app_proof,
                "expected_public_digest": app_public_digest,
            },
            "spend_candidate": {
                **spend_proof,
                "expected_public_digest": spend_public_digest,
            },
        },
        "adversarial_fixtures_rejected_by_guest": {
            "nullifier_slice": APP_REJECTED,
            "spend_candidate_slice": SPEND_REJECTED,
        },
        "validation_scope": {
            "proof_generation_and_verification_steps_passed": True,
            "ledger_facing_proof_output_checker_passed": True,
            "real_openvm_proof_to_sqlite_atomic_transition_passed": True,
            "cargo_lock_unchanged_check_passed": True,
            "complete_production_relation_established": False,
            "production_authorization_established": False,
            "trusted_finality_or_custody_established": False,
            "zero_knowledge_guarantee_independently_established": False,
            "post_quantum_security_budget_established": False,
            "raw_proof_bytes_uploaded": False,
            "witness_fixtures_uploaded": False,
            "manifest_contains_witness_values": False,
            "limitations": (
                "Metadata-only provenance for a non-production V3 candidate predicate slice. "
                "The artifact intentionally excludes proof bytes, witness JSON files and raw logs. "
                "This manifest does not prove a complete production relation, production authorization, "
                "zero knowledge, post-quantum soundness or launch readiness."
            ),
        },
        "retention": {
            "artifact_retention_days": 90,
            "artifact_scope": "manifest.json only; no raw proof or witness files",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--checker", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = build_manifest(args.fixture_dir.resolve(), args.checker)
        out_path = args.fixture_dir.resolve() / "evidence" / "manifest.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = out_path.with_suffix(".json.tmp")
        serialized = json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
        temporary_path.write_text(serialized, encoding="utf-8")
        temporary_path.replace(out_path)
        print(f"non-secret evidence manifest written: {out_path}")
        print(f"manifest_sha256={sha256_file(out_path)}")
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"evidence manifest generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
