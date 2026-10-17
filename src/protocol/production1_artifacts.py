"""Load a source-controlled platform release pin for the Production-1 verifier."""
from __future__ import annotations

import json
import hashlib
import platform
import sys
from pathlib import Path

from src.protocol.openvm_v3_candidate_verifier import OpenVMV3CandidateProofVerifier
from src.protocol.v3_proof_worker import PRODUCTION1_CIRCUIT_ID


class Production1ArtifactPinError(ValueError):
    pass


_VERIFIED_PINS_TOKEN = object()
# SHA-256 of the committed UTF-8 manifest after canonicalizing CRLF to LF. Git's
# Windows checkout can otherwise change the file bytes without changing its blob.
PRODUCTION1_PINS_SHA256 = "bb970c863bd2a32d15ecf9920bc6e65138f5352a33263800643f4e7eb613ea73"

_PINNED_BUILD_INPUTS = {
    "openvm_toml": Path("proof/openvm/v3-nullifier-spike/openvm.toml"),
    "runner_source": Path(
        "proof/openvm/v3-nullifier-spike/proof-output-checker/src/bin/openvm-v3-sdk-runner.rs"
    ),
    "checker_source": Path(
        "proof/openvm/v3-nullifier-spike/proof-output-checker/src/main.rs"
    ),
    "cargo_lock": Path("proof/openvm/v3-nullifier-spike/proof-output-checker/Cargo.lock"),
    "cargo_manifest": Path("proof/openvm/v3-nullifier-spike/proof-output-checker/Cargo.toml"),
    "rust_toolchain": Path("proof/openvm/v3-nullifier-spike/rust-toolchain.toml"),
    "guest_entry_source": Path("proof/openvm/v3-nullifier-spike/src/main.rs"),
    "guest_library_source": Path("proof/openvm/v3-nullifier-spike/src/lib.rs"),
    "guest_relation_source": Path("proof/openvm/v3-nullifier-spike/src/spend_v3.rs"),
    "guest_cargo_lock": Path("proof/openvm/v3-nullifier-spike/Cargo.lock"),
    "guest_cargo_manifest": Path("proof/openvm/v3-nullifier-spike/Cargo.toml"),
    "host_verifier_adapter": Path("src/protocol/openvm_v3_candidate_verifier.py"),
    "proof_envelope_verifier": Path("src/protocol/proof_backend_v3.py"),
    "proof_client": Path("src/protocol/v3_proof_client.py"),
    "proof_worker": Path("src/protocol/v3_proof_worker.py"),
    "public_statement_codec": Path("src/protocol/transaction_v3_candidate.py"),
    "stateful_testnet_composition": Path("src/protocol/production1_ledger.py"),
}

_SECURITY_PROFILE = {
    "constructor": "app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT)",
    "declared_app_rbr_bits": 100,
    "calculated_active_app_rbr_bits": 100.08983133159032,
    "app_rbr_assumptions": {
        "max_trace_log_height": 24,
        "max_constraints_per_air": 5000,
        "num_airs": 100,
        "max_interactions_per_air": 1000,
        "num_trace_columns": 30000,
        "w_stack": 2048,
        "bound_scope": "OpenVM application RBR calculator under declared ceilings; not Fiat-Shamir/QROM composition",
    },
    "composed_post_quantum_bits": None,
    "composed_128_bit_target_met": False,
    "witness_zero_knowledge_established": False,
    "prover_trace_masking_established": False,
    "transcript_claim": (
        "Pinned OpenVM verifier implementation only; no independent "
        "Fiat-Shamir/QROM composition bound claimed"
    ),
}


def _canonical_sha256(path: Path) -> str:
    content = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


class Production1OpenVMProofVerifier(OpenVMV3CandidateProofVerifier):
    """Verifier constructed only after the committed release manifest is checked."""

    def __init__(self, *, _token: object, **kwargs) -> None:
        if _token is not _VERIFIED_PINS_TOKEN:
            raise TypeError("use load_production1_verifier with the committed release pins")
        super().__init__(**kwargs)


def load_production1_verifier(
    *, checker_executable: str | Path, app_verifying_key: str | Path, pins_file: str | Path
) -> OpenVMV3CandidateProofVerifier:
    try:
        raw = Path(pins_file).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(raw).hexdigest() != PRODUCTION1_PINS_SHA256:
            raise ValueError("pin manifest does not match the source-controlled release digest")
        pins = json.loads(raw)
        if pins["profile"] != "production1_testnet" or pins["circuit_id"] != PRODUCTION1_CIRCUIT_ID:
            raise ValueError("profile/circuit id mismatch")
        if pins["backend"] != "OpenVM" or pins["openvm"] != "2.0.2":
            raise ValueError("unsupported backend release")
        if pins["openvm_git_revision"] != "59a69b8b0cbee7011ac978e4cc07707ee3681944":
            raise ValueError("unsupported OpenVM source revision")
        if pins["stark_backend"] != "2.0.1":
            raise ValueError("unsupported STARK backend release")
        if pins["security_profile"] != _SECURITY_PROFILE:
            raise ValueError("security claim/profile drift")
        recorded_inputs = pins["build_inputs_sha256"]
        if set(recorded_inputs) != set(_PINNED_BUILD_INPUTS):
            raise ValueError("pinned build input set is incomplete or unexpected")
        repo_root = Path(__file__).resolve().parents[2]
        for name, relative_path in _PINNED_BUILD_INPUTS.items():
            if _canonical_sha256(repo_root / relative_path) != recorded_inputs[name]:
                raise ValueError(f"pinned build input changed: {name}")
        machine = platform.machine().lower()
        machine = "x86_64" if machine in {"amd64", "x64"} else machine
        target = f"{'windows' if sys.platform == 'win32' else sys.platform}-{machine}"
        checker_hash = pins["checker_sha256_by_platform"][target]
        return Production1OpenVMProofVerifier(
            _token=_VERIFIED_PINS_TOKEN,
            checker_executable=checker_executable,
            app_verifying_key=app_verifying_key,
            expected_checker_sha256=bytes.fromhex(checker_hash),
            expected_app_verifying_key_sha256=bytes.fromhex(pins["app_verifying_key_sha256"]),
            app_executable_commitment=bytes.fromhex(pins["app_executable_commitment"]),
        )
    except Exception as exc:
        raise Production1ArtifactPinError("Production-1 OpenVM release pins are invalid") from exc


__all__ = [
    "Production1ArtifactPinError",
    "Production1OpenVMProofVerifier",
    "load_production1_verifier",
]
