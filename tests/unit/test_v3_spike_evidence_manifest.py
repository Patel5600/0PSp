from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = (
    REPO_ROOT
    / "proof"
    / "openvm"
    / "v3-nullifier-spike"
    / "scripts"
    / "write_v3_spike_evidence_manifest.py"
)
SPEC = importlib.util.spec_from_file_location("v3_evidence_manifest", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MANIFEST_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST_MODULE)


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _fixture_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    fixture_dir = tmp_path / "runner-temp" / "v3-nullifier-witnesses"
    evidence = fixture_dir / "evidence"
    checker = workspace / "proof-output-checker" / "target" / "release" / "psp-openvm-v3-proof-output-checker"

    _write(workspace / "Cargo.lock", "version = 3\n")
    _write(workspace / "proof-output-checker" / "Cargo.lock", "version = 3\n")
    _write(workspace / "openvm" / "app.vk", b"public verification key placeholder")
    _write(workspace / "expected-app-exe-commit.txt", "a" * 64 + "\n")
    _write(checker, b"checker executable placeholder")
    _write(fixture_dir / "expected-public-digest.txt", "b" * 128 + "\n")
    _write(fixture_dir / "expected-spend-public-digest.txt", "c" * 128 + "\n")
    _write(fixture_dir / "valid.app.proof", b"app-proof-placeholder")
    _write(fixture_dir / "spend-valid.app.proof", b"spend-proof-placeholder")
    _write(evidence / "toolchain.txt", "rustc 1.91.1\ncargo 1.91.1\n")
    _write(evidence / "keygen.metrics", "V3_SPIKE_KEYGEN_SECONDS=1.25 MAX_RSS_KIB=2048\n")
    _write(evidence / "app-prove.metrics", "V3_SPIKE_APP_PROVE_SECONDS=2.50 MAX_RSS_KIB=4096\n")
    _write(evidence / "app-verify.metrics", "V3_SPIKE_APP_VERIFY_SECONDS=0.15 MAX_RSS_KIB=1024\n")
    _write(evidence / "spend-prove.metrics", "V3_SPIKE_SPEND_PROVE_SECONDS=3.50 MAX_RSS_KIB=8192\n")
    _write(evidence / "spend-verify.metrics", "V3_SPIKE_SPEND_VERIFY_SECONDS=0.20 MAX_RSS_KIB=1024\n")
    _write(
        evidence / "security-profile.json",
        json.dumps({
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
            "application_executable_commitment": "a" * 64,
            "interpretation": "metadata only",
        }),
    )
    _write(
        evidence / "ledger-integration.json",
        json.dumps({
            "schema_version": 1,
            "status": "PASS",
            "scope": "non-production OpenVM candidate proof to local SQLite transition",
            "dynamic_statement_proof_generated_and_verified": True,
            "mutated_proof_rejected_without_state_change": True,
            "valid_proof_accepted_as_atomic_state_transition": True,
            "duplicate_nullifier_replay_rejected_without_state_change": True,
            "restart_and_integrity_audit_passed": True,
            "proof_size_bytes": 123456,
            "proof_sha256": "d" * 64,
            "checker_sha256": "e" * 64,
            "app_verifying_key_sha256": "f" * 64,
            "app_executable_commitment": "a" * 64,
            "public_statement_digest": "c" * 128,
            "state_version_after_accept": 1,
            "bootstrap_state_evidence_is_synthetic": True,
            "external_finality_established": False,
            "end_to_end_witness_hiding_established": False,
            "composite_post_quantum_security_bits": None,
            "required_composite_post_quantum_security_bits": 128,
            "production_acceptance_enabled": False,
            "release_status": "NO-GO",
        }),
    )

    monkeypatch.chdir(workspace)
    monkeypatch.setenv("CANDIDATE_HEAD_SHA", "1" * 40)
    monkeypatch.setenv("GITHUB_SHA", "2" * 40)
    monkeypatch.setenv("CANDIDATE_BASE_SHA", "3" * 40)
    monkeypatch.setenv("CARGO_OPENVM_SHA256", "4" * 64)
    monkeypatch.setenv("GITHUB_RUN_ID", "123456")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setenv("GITHUB_REPOSITORY", "Patel5600/0PSp")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/10/merge")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_WORKFLOW", "OpenVM V3 nullifier feasibility spike")
    monkeypatch.setenv("RUNNER_OS", "Linux")
    monkeypatch.setenv("RUNNER_ARCH", "X64")
    monkeypatch.setattr(
        MANIFEST_MODULE,
        "command_record",
        lambda argv: {"argv": argv, "exit_code": 0, "output_first_lines": ["test-tool 1.0"]},
    )
    return fixture_dir, checker


def test_manifest_records_hashes_metrics_provenance_and_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_dir, checker = _fixture_tree(tmp_path, monkeypatch)
    manifest = MANIFEST_MODULE.build_manifest(fixture_dir, checker)

    assert manifest["source"]["candidate_head_sha"] == "1" * 40
    assert manifest["source"]["workflow_sha"] == "2" * 40
    assert manifest["source"]["run_id"] == 123456
    assert manifest["proof_slice"]["app"]["size_bytes"] == len(b"app-proof-placeholder")
    assert manifest["proof_slice"]["app"]["prove"] == {
        "seconds": 2.5,
        "max_rss_kib": 4096,
        "rss_scope": "combined SDK runner high-water mark shared across stage timings; not a per-stage measurement",
    }
    assert manifest["proof_slice"]["spend_candidate"]["verify"] == {
        "seconds": 0.2,
        "max_rss_kib": 1024,
        "rss_scope": "combined SDK runner high-water mark shared across stage timings; not a per-stage measurement",
    }
    assert manifest["security_profile"]["profile_status"] == "NO-GO"
    assert manifest["security_profile"]["upstream_declared_soundness_bits"] == 100
    assert manifest["security_profile"]["required_composite_soundness_bits"] == 128
    assert manifest["security_profile"]["security_target_met"] is False
    assert manifest["ledger_integration"]["status"] == "PASS"
    assert manifest["ledger_integration"]["proof_size_bytes"] == 123456
    assert manifest["ledger_integration"]["valid_proof_accepted_as_atomic_state_transition"] is True
    assert manifest["ledger_integration"]["duplicate_nullifier_replay_rejected_without_state_change"] is True
    assert manifest["ledger_integration"]["external_finality_established"] is False
    assert manifest["ledger_integration"]["production_acceptance_enabled"] is False
    assert manifest["validation_scope"]["complete_production_relation_established"] is False
    assert manifest["validation_scope"]["zero_knowledge_guarantee_independently_established"] is False
    assert manifest["validation_scope"]["raw_proof_bytes_uploaded"] is False
    assert manifest["validation_scope"]["witness_fixtures_uploaded"] is False

    serialized = json.dumps(manifest, sort_keys=True)
    assert "app-proof-placeholder" not in serialized
    assert "spend-proof-placeholder" not in serialized
    assert "valid.json" not in serialized
    assert "spend-valid.json" not in serialized


def test_manifest_rejects_malformed_timing_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_dir, checker = _fixture_tree(tmp_path, monkeypatch)
    (fixture_dir / "evidence" / "app-prove.metrics").write_text(
        "V3_SPIKE_APP_PROVE_SECONDS=NaN MAX_RSS_KIB=4096\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="malformed timing/RSS record"):
        MANIFEST_MODULE.build_manifest(fixture_dir, checker)
