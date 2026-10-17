#!/usr/bin/env python3
"""Exercise the Python state-binding and ledger-facing adapter with a real OpenVM app proof.

This CI integration check covers only the non-production one-input/one-output
predicate slice. Hash pins are computed from the exact artifacts built/checked
out in the same locked CI job; they are not published deployment release pins.
The fixture state verifier below is test evidence, not an external trust source.
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from make_witnesses import (
    SPEND_FINALITY_POLICY,
    SPEND_FINALIZED_ANCHOR,
    SPEND_STATE_SOURCE,
    expected_spend_digest,
    make_spend_context,
)
from src.protocol.openvm_v3_candidate_verifier import (
    OpenVMV3CandidateProofVerifier,
    OpenVMV3CandidateVerifierError,
    v3_spend_public_digest_candidate,
)
from src.protocol.trusted_state_v3 import (
    StateAnchorEvidenceV3,
    TrustedStateRejected,
    VerifiedStateSnapshotV3,
    verify_v3_candidate_spend_preflight,
)


def read_lower_hex(path: Path, expected_bytes: int, field: str) -> bytes:
    raw = path.read_text(encoding="ascii").strip()
    if len(raw) != expected_bytes * 2:
        raise ValueError(f"{field} must contain exactly {expected_bytes * 2} hex characters")
    if any(ch not in "0123456789abcdef" for ch in raw):
        raise ValueError(f"{field} must contain lowercase hexadecimal only")
    return bytes.fromhex(raw)


def expect_preflight_rejection(
    label: str,
    *,
    statement,
    proof: bytes,
    evidence: StateAnchorEvidenceV3,
    verify_state_anchor,
    verifier: OpenVMV3CandidateProofVerifier,
) -> None:
    try:
        verify_v3_candidate_spend_preflight(
            statement,
            proof=proof,
            state_evidence=evidence,
            verify_state_anchor=verify_state_anchor,
            verify_spend_proof=verifier,
        )
    except (TrustedStateRejected, OpenVMV3CandidateVerifierError, ValueError):
        print(f"PASS: real-proof integration rejected adversarial case: {label}")
        return
    raise OpenVMV3CandidateVerifierError(
        f"real-proof integration unexpectedly accepted adversarial case: {label}"
    )


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
    expected_kat = read_lower_hex(digest_path, 64, "expected spend public digest")
    if expected_digest != expected_kat or expected_digest != expected_spend_digest(statement):
        raise OpenVMV3CandidateVerifierError(
            "Python adapter digest does not match the deterministic spend fixture KAT"
        )

    verifier_kwargs = {
        "checker_executable": checker,
        "app_verifying_key": app_vk,
        "expected_checker_sha256": hashlib.sha256(checker.read_bytes()).digest(),
        "expected_app_verifying_key_sha256": hashlib.sha256(app_vk.read_bytes()).digest(),
        "app_executable_commitment": read_lower_hex(
            exe_commit_path, 32, "expected app executable commitment"
        ),
        "timeout_seconds": 300,
        "max_proof_bytes": 2_000_000,
    }
    verifier = OpenVMV3CandidateProofVerifier(**verifier_kwargs)
    proof_bytes = app_proof.read_bytes()

    # First exercise the backend directly, then pass the same real proof through
    # the transaction-to-state preflight and ledger-facing verifier callback.
    if not verifier(statement, proof_bytes):
        raise OpenVMV3CandidateVerifierError(
            "candidate adapter rejected the generated OpenVM spend proof"
        )

    evidence = StateAnchorEvidenceV3(
        source_id=SPEND_STATE_SOURCE,
        finalized_anchor=SPEND_FINALIZED_ANCHOR,
        evidence=b"NONPRODUCTION deterministic fixture evidence only",
    )
    snapshot = VerifiedStateSnapshotV3(
        source_id=SPEND_STATE_SOURCE,
        finalized_anchor=SPEND_FINALIZED_ANCHOR,
        finality_policy_id=SPEND_FINALITY_POLICY,
        namespace_id=statement.namespace_id,
        params_id=statement.params_id,
        commitment_root=statement.commitment_root,
        ledger_state_head=statement.ledger_state_head,
    )

    def verify_fixture_state(received: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        if received != evidence:
            raise ValueError("received unexpected fixture state evidence")
        return snapshot

    binding = verify_v3_candidate_spend_preflight(
        statement,
        proof=proof_bytes,
        state_evidence=evidence,
        verify_state_anchor=verify_fixture_state,
        verify_spend_proof=verifier,
    )
    if binding.statement != statement or binding.transaction_digest == b"":
        raise OpenVMV3CandidateVerifierError(
            "state/proof integration returned an inconsistent transaction binding"
        )

    # A valid proof must not verify against a different transaction statement.
    altered_statement = replace(statement, fee=(statement.fee + 1) % (1 << 64))
    if v3_spend_public_digest_candidate(altered_statement) == expected_digest:
        raise OpenVMV3CandidateVerifierError(
            "mutated statement unexpectedly retained the original public digest"
        )
    expect_preflight_rejection(
        "same proof with changed transaction fee",
        statement=altered_statement,
        proof=proof_bytes,
        evidence=evidence,
        verify_state_anchor=verify_fixture_state,
        verifier=verifier,
    )

    # Corrupt the serialized proof bytes and require the real checker to reject it.
    mutated_proof = bytearray(proof_bytes)
    mutated_proof[len(mutated_proof) // 2] ^= 0x01
    expect_preflight_rejection(
        "mutated serialized proof",
        statement=statement,
        proof=bytes(mutated_proof),
        evidence=evidence,
        verify_state_anchor=verify_fixture_state,
        verifier=verifier,
    )

    # A wrong executable pin must fail closed even when the proof itself is valid.
    wrong_commitment = bytearray(verifier_kwargs["app_executable_commitment"])
    wrong_commitment[0] ^= 0x01
    wrong_commitment_verifier = OpenVMV3CandidateProofVerifier(
        **{**verifier_kwargs, "app_executable_commitment": bytes(wrong_commitment)}
    )
    expect_preflight_rejection(
        "valid proof with wrong executable commitment",
        statement=statement,
        proof=proof_bytes,
        evidence=evidence,
        verify_state_anchor=verify_fixture_state,
        verifier=wrong_commitment_verifier,
    )

    print(
        "PASS: exact OpenVM spend proof passed candidate state-binding preflight; "
        f"checker_sha256={hashlib.sha256(checker.read_bytes()).hexdigest()} "
        f"app_vk_sha256={hashlib.sha256(app_vk.read_bytes()).hexdigest()} "
        f"public_digest={expected_digest.hex()}"
    )
    print(
        "LIMIT: fixture state verifier is synthetic; this integration check does not "
        "establish external finality, production soundness, witness hiding, or Mainnet readiness."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
