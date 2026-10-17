from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from src.protocol import production1_artifacts
from src.protocol.production1_artifacts import Production1ArtifactPinError


PINS = Path(__file__).resolve().parents[2] / "proof/openvm/v3-nullifier-spike/production1-pins.json"


def test_release_manifest_pin_is_stable_across_crlf_checkout(tmp_path, monkeypatch) -> None:
    manifest = PINS.read_bytes().replace(b"\r\n", b"\n")
    crlf_path = tmp_path / "pins.json"
    crlf_path.write_bytes(manifest.replace(b"\n", b"\r\n"))
    captured = {}
    monkeypatch.setattr(
        production1_artifacts,
        "Production1OpenVMProofVerifier",
        lambda **kwargs: captured.update(kwargs) or object(),
    )

    result = production1_artifacts.load_production1_verifier(
        checker_executable=tmp_path / "checker",
        app_verifying_key=tmp_path / "app.vk",
        pins_file=crlf_path,
    )

    assert result is not None
    assert len(captured["expected_app_verifying_key_sha256"]) == 32
    assert len(captured["app_executable_commitment"]) == 32


def test_release_manifest_pins_crypto_profile_and_build_inputs() -> None:
    manifest = json.loads(PINS.read_text(encoding="utf-8"))
    profile = manifest["security_profile"]
    assert profile["constructor"] == "app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT)"
    assert profile["declared_app_rbr_bits"] == 100
    assert profile["composed_post_quantum_bits"] is None
    assert profile["composed_128_bit_target_met"] is False
    assert profile["witness_zero_knowledge_established"] is False
    assert profile["prover_trace_masking_established"] is False

    repo = PINS.parents[3]
    for name, digest in manifest["build_inputs_sha256"].items():
        relative = production1_artifacts._PINNED_BUILD_INPUTS[name]
        content = (repo / relative).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(content).hexdigest() == digest


def test_release_manifest_content_mutation_fails_pin_check(tmp_path) -> None:
    manifest = json.loads(PINS.read_text(encoding="utf-8"))
    manifest["circuit_id"] = "unreviewed-circuit"
    changed_path = tmp_path / "pins.json"
    changed_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(Production1ArtifactPinError, match="release pins are invalid"):
        production1_artifacts.load_production1_verifier(
            checker_executable=tmp_path / "checker",
            app_verifying_key=tmp_path / "app.vk",
            pins_file=changed_path,
        )
