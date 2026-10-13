#!/usr/bin/env python3
"""Exercise the Python ledger adapter against a real OpenVM app-proof artifact.

This is a CI integration check for the non-production predicate slice. Hash pins
are computed from the exact artifacts built/checked out in the same locked CI job;
they are not a substitute for published deployment release pins.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from make_witnesses import expected_spend_digest, make_spend_context
from src.protocol.openvm_v3_candidate_verifier import (
    OpenVMV3CandidateProofVerifier,
    OpenVMV3CandidateVerifierError,
    v3_spend_public_digest_candidate,
)


def read_lower_hex(path: Path, expected_bytes: int, field: str) -> bytes:
    raw = path.read_text(encoding="ascii").strip()
    if len(raw) != expected_bytes * 2:
        raise ValueError(f"{field} must contain exactly {expected_bytes * 2} hex characters")
    if any(ch not in "0123456789abcdef" for ch in raw):
        raise ValueError(f"{field} must contain lowercase hexadecimal only")
    return bytes.fromhex(raw)


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: verify_candidate_proof_adapter.py CHECKER APP_VK APP_PROOF "
            "EXPECTED_EXE_COMMIT_HEX EXPECTED_SPEND_DIGEST_HEX",
            file=sys.stderr,
        )
        return 2

    checker, app_vk, app_proof, exe_commit_path, digest_path = (
        Path(value).absolute() for value in sys.argv[1:]
    )
    context = make_spend_context()
    statement = context["tx"]
    expected_digest = v3_spend_public_digest_candidate(statement)
    expected_kat = read_lower_hex(digest_path, 32, "expected spend public digest")
    if expected_digest != expected_kat or expected_digest != expected_spend_digest(statement):
        raise OpenVMV3CandidateVerifierError(
            "Python adapter digest does not match the deterministic spend fixture KAT"
        )

    verifier = OpenVMV3CandidateProofVerifier(
        checker_executable=checker,
        app_verifying_key=app_vk,
        expected_checker_sha256=hashlib.sha256(checker.read_bytes()).digest(),
        expected_app_verifying_key_sha256=hashlib.sha256(app_vk.read_bytes()).digest(),
        app_executable_commitment=read_lower_hex(
            exe_commit_path, 32, "expected app executable commitment"
        ),
        timeout_seconds=300,
        max_proof_bytes=2_000_000,
    )
    if not verifier(statement, app_proof.read_bytes()):
        raise OpenVMV3CandidateVerifierError(
            "candidate adapter rejected the generated OpenVM spend proof"
        )
    print(
        "PASS: ledger-facing OpenVM adapter verified the exact generated V3 spend proof; "
        f"checker_sha256={hashlib.sha256(checker.read_bytes()).hexdigest()} "
        f"app_vk_sha256={hashlib.sha256(app_vk.read_bytes()).hexdigest()} "
        f"public_digest={expected_digest.hex()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
