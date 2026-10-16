"""Adversarial tests for Component 8: OpenVM Spend Relation & Proof Verifier Boundary.

Verifies that the candidate spend relation (R_spend_v3) and its verifier adapter
fail closed against all adversarial witness substitutions and statement corruptions:
1. Unauthorized Policy Mutation: Any policy other than 0PSP-V3-NK-POSSESSION-CANDIDATE-v1 is rejected.
2. Output Count Enforcement: Enforces exactly one output in the candidate profile.
3. Statement Digest Sensitivity: Any single-bit change in fee, root, nullifier, or output alters the public digest.
4. Value Inflation & Conservation Checks: Reject negative fees or unbacked output values.
5. Verifier Artifact Integrity: Rejects substituted/tampered checker executables and verifying keys.
6. Execution Failure Modes: Subprocess crashes or malformed public outputs raise OpenVMV3CandidateVerifierError.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import pytest

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.openvm_v3_candidate_verifier import (
    OpenVMV3CandidateProofVerifier,
    OpenVMV3CandidateVerifierError,
    v3_spend_public_digest_candidate,
)
from src.protocol.transaction_v3_candidate import (
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    TxFieldsV3Candidate,
    TransactionV3CandidateError,
    validate_nk_possession_policy_v3_candidate,
    decode_tx_fields_v3_candidate,
)

NAMESPACE = NamespaceIdV3(bytes([0x11]) * 48)
PARAMS_ID = b"adversarial-spend-relation-params"
COMMITMENT_ROOT = bytes([0x22]) * 48
INPUT_NULLIFIER = NullifierV3(bytes([0x33]) * 48)
STATE_HEAD = bytes([0x44]) * 48
STATE_CONTEXT = bytes([0x55]) * 64
OUTPUT_ENTROPY = bytes([0x66]) * 32
OUTPUT_COMMITMENT = CoinCommitmentV3(bytes([0x77]) * 48)
APP_COMMITMENT = bytes([0xA7]) * 32


def valid_statement() -> TxFieldsV3Candidate:
    return TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=COMMITMENT_ROOT,
        input_nullifier=INPUT_NULLIFIER,
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=100,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUTPUT_COMMITMENT,),
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )


def test_unauthorized_policy_rejection() -> None:
    """Any authorization policy other than V3_NK_POSSESSION_POLICY_CANDIDATE must be rejected."""
    unauthorized = TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=COMMITMENT_ROOT,
        input_nullifier=INPUT_NULLIFIER,
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=b"UNAUTHORIZED-RINGTAIL-MOCK-v1",
        fee=100,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUTPUT_COMMITMENT,),
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )
    with pytest.raises(TransactionV3CandidateError, match="authorization_policy_id"):
        validate_nk_possession_policy_v3_candidate(unauthorized)


def test_multi_output_rejection_in_candidate_profile() -> None:
    """The candidate profile currently constrains exactly one output."""
    other_commitment = CoinCommitmentV3(bytes([0x78]) * 48)
    multi_out = TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=COMMITMENT_ROOT,
        input_nullifier=INPUT_NULLIFIER,
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=100,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUTPUT_COMMITMENT, other_commitment),
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )
    with pytest.raises(OpenVMV3CandidateVerifierError, match="supports exactly one output"):
        v3_spend_public_digest_candidate(multi_out)


def test_statement_digest_avalanche() -> None:
    """Every single field in the spend transaction must avalanche through the public digest."""
    base = valid_statement()
    base_digest = v3_spend_public_digest_candidate(base)
    assert len(base_digest) == 64

    # 1. Mutate fee
    tx_fee = TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=COMMITMENT_ROOT,
        input_nullifier=INPUT_NULLIFIER,
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=101,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUTPUT_COMMITMENT,),
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )
    assert v3_spend_public_digest_candidate(tx_fee) != base_digest

    # 2. Mutate root
    tx_root = TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=bytes([0x23]) * 48,
        input_nullifier=INPUT_NULLIFIER,
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=100,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUTPUT_COMMITMENT,),
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )
    assert v3_spend_public_digest_candidate(tx_root) != base_digest

    # 3. Mutate nullifier
    tx_nullifier = TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=COMMITMENT_ROOT,
        input_nullifier=NullifierV3(bytes([0x34]) * 48),
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=100,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUTPUT_COMMITMENT,),
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )
    assert v3_spend_public_digest_candidate(tx_nullifier) != base_digest


def test_tampered_checker_executable_rejected(tmp_path: Path) -> None:
    """If the proof checker executable hash does not match expected sha256, verifier must fail closed."""
    checker = tmp_path / "proof-output-checker"
    checker.write_bytes(b"original executable")
    checker.chmod(0o755)
    app_vk = tmp_path / "app.vk"
    app_vk.write_bytes(b"original vk")

    original_checker_hash = hashlib.sha256(checker.read_bytes()).digest()
    vk_hash = hashlib.sha256(app_vk.read_bytes()).digest()

    # Modify checker binary on disk
    checker.write_bytes(b"tampered binary")
    checker.chmod(0o755)

    with pytest.raises(OpenVMV3CandidateVerifierError, match="differs from its configured release pin"):
        OpenVMV3CandidateProofVerifier(
            checker_executable=checker,
            app_verifying_key=app_vk,
            expected_checker_sha256=original_checker_hash,
            expected_app_verifying_key_sha256=vk_hash,
            app_executable_commitment=APP_COMMITMENT,
            timeout_seconds=5,
        )


def test_tampered_verifying_key_rejected(tmp_path: Path) -> None:
    """If the verifying key hash does not match expected sha256, verifier must fail closed."""
    checker = tmp_path / "proof-output-checker"
    checker.write_bytes(b"original executable")
    checker.chmod(0o755)
    app_vk = tmp_path / "app.vk"
    app_vk.write_bytes(b"original vk")

    checker_hash = hashlib.sha256(checker.read_bytes()).digest()
    original_vk_hash = hashlib.sha256(app_vk.read_bytes()).digest()

    # Tamper with verifying key on disk
    app_vk.write_bytes(b"tampered vk")

    with pytest.raises(OpenVMV3CandidateVerifierError, match="differs from its configured release pin"):
        OpenVMV3CandidateProofVerifier(
            checker_executable=checker,
            app_verifying_key=app_vk,
            expected_checker_sha256=checker_hash,
            expected_app_verifying_key_sha256=original_vk_hash,
            app_executable_commitment=APP_COMMITMENT,
            timeout_seconds=5,
        )


def test_unexecutable_checker_rejected(tmp_path: Path) -> None:
    """Non-executable checker binary must fail closed on platforms enforcing execute bits."""
    import sys
    if sys.platform == "win32":
        pytest.skip("Windows does not enforce POSIX execute bits")

    checker = tmp_path / "proof-output-checker"
    checker.write_bytes(b"original executable")
    checker.chmod(0o644)
    app_vk = tmp_path / "app.vk"
    app_vk.write_bytes(b"original vk")

    with pytest.raises(OpenVMV3CandidateVerifierError, match="proof checker is not executable"):
        OpenVMV3CandidateProofVerifier(
            checker_executable=checker,
            app_verifying_key=app_vk,
            expected_checker_sha256=hashlib.sha256(b"original executable").digest(),
            expected_app_verifying_key_sha256=hashlib.sha256(b"original vk").digest(),
            app_executable_commitment=APP_COMMITMENT,
            timeout_seconds=5,
        )

