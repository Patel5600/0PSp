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
PRODUCTION1_PINS_SHA256 = "d3c26b3b73822034b00d88b802b25473e9e7903b48c678d126a91b39bc1f828d"


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
        raw = Path(pins_file).read_bytes()
        if hashlib.sha256(raw).hexdigest() != PRODUCTION1_PINS_SHA256:
            raise ValueError("pin manifest does not match the source-controlled release digest")
        pins = json.loads(raw)
        if pins["profile"] != "production1_testnet" or pins["circuit_id"] != PRODUCTION1_CIRCUIT_ID:
            raise ValueError("profile/circuit id mismatch")
        if pins["backend"] != "OpenVM" or pins["openvm"] != "2.0.2":
            raise ValueError("unsupported backend release")
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
