from __future__ import annotations

import hashlib
import subprocess
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
)

APP_COMMITMENT = bytes([0xA7]) * 32
PROOF_BYTES = b"mock serialized OpenVM application proof"


def statement() -> TxFieldsV3Candidate:
    return TxFieldsV3Candidate(
        params_id=b"verifier-adapter-params",
        namespace_id=NamespaceIdV3(bytes([0x11]) * 48),
        commitment_root=bytes([0x22]) * 48,
        input_nullifier=NullifierV3(bytes([0x33]) * 48),
        ledger_state_head=bytes([0x44]) * 48,
        state_context_digest=bytes([0x77]) * 64,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=7,
        output_entropy=bytes([0x55]) * 32,
        output_commitments=(CoinCommitmentV3(bytes([0x66]) * 48),),
    )


def make_verifier(tmp_path: Path) -> tuple[OpenVMV3CandidateProofVerifier, Path, Path]:
    checker = tmp_path / "proof-output-checker"
    checker.write_bytes(b"pinned test checker executable")
    checker.chmod(0o700)
    app_vk = tmp_path / "app.vk"
    app_vk.write_bytes(b"pinned test application verifying key")
    app_vk.chmod(0o600)
    verifier = OpenVMV3CandidateProofVerifier(
        checker_executable=checker,
        app_verifying_key=app_vk,
        expected_checker_sha256=hashlib.sha256(checker.read_bytes()).digest(),
        expected_app_verifying_key_sha256=hashlib.sha256(app_vk.read_bytes()).digest(),
        app_executable_commitment=APP_COMMITMENT,
        timeout_seconds=9,
    )
    return verifier, checker, app_vk


def test_candidate_public_digest_matches_fixed_guest_vector() -> None:
    # Independently calculated from the frozen candidate TX_FIELDS/TX_DIGEST
    # domains and the guest's public-statement domain.
    assert v3_spend_public_digest_candidate(statement()).hex() == (
        "bc065015515112dd8a826a5009441c5148d87ecc2d53ca954df5e5572937167e624de15f69453d6f6400a01c67d84c81f69ccf6477f7f81d709e3b2dfb9ec488"
    )


def test_verifier_binds_proof_to_exact_executable_and_transaction_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, checker, app_vk = make_verifier(tmp_path)
    captured: dict[str, object] = {}

    original_checker = checker.read_bytes()
    original_vk = app_vk.read_bytes()

    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        staged_checker = Path(command[0])
        staged_vk = Path(command[1])
        # The process must receive private staged artifacts, not the original paths.
        assert staged_checker != checker
        assert staged_vk != app_vk
        assert staged_checker.read_bytes() == original_checker
        assert staged_vk.read_bytes() == original_vk
        assert staged_checker.stat().st_mode & 0o111
        assert Path(command[2]).read_bytes() == PROOF_BYTES
        assert Path(command[3]).read_text(encoding="ascii").strip() == APP_COMMITMENT.hex()
        assert Path(command[4]).read_text(encoding="ascii").strip() == (
            "bc065015515112dd8a826a5009441c5148d87ecc2d53ca954df5e5572937167e624de15f69453d6f6400a01c67d84c81f69ccf6477f7f81d709e3b2dfb9ec488"
        )

        # Simulate the original paths being swapped after staging but immediately
        # before the checker would run. The staged bytes must remain unchanged.
        checker.write_bytes(b"attacker replacement checker")
        app_vk.write_bytes(b"attacker replacement verifying key")
        assert staged_checker.read_bytes() == original_checker
        assert staged_vk.read_bytes() == original_vk
        return subprocess.CompletedProcess(command, 0, stdout="verified\n", stderr="")

    monkeypatch.setattr(
        "src.protocol.openvm_v3_candidate_verifier.subprocess.run",
        fake_run,
    )
    assert verifier(statement(), PROOF_BYTES) is True

    command = captured["command"]
    kwargs = captured["kwargs"]
    assert Path(command[0]).name == "proof-checker"
    assert Path(command[1]).name == "app.vk"
    assert kwargs["shell"] is False
    assert kwargs["capture_output"] is True
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 9


def test_checker_nonzero_exit_is_a_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, *_ = make_verifier(tmp_path)
    monkeypatch.setattr(
        "src.protocol.openvm_v3_candidate_verifier.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, stdout="", stderr="proof rejected"
        ),
    )
    assert verifier(statement(), PROOF_BYTES) is False


def test_changed_checker_or_verifying_key_fails_closed(
    tmp_path: Path,
) -> None:
    verifier, checker, _ = make_verifier(tmp_path)
    checker.write_bytes(b"replacement checker with a different SHA-256 digest")
    with pytest.raises(OpenVMV3CandidateVerifierError, match="checker executable SHA-256"):
        verifier(statement(), PROOF_BYTES)



def test_changed_verifying_key_fails_closed(tmp_path: Path) -> None:
    verifier, _, app_vk = make_verifier(tmp_path)
    app_vk.write_bytes(b"replacement verifying key with a different SHA-256 digest")
    with pytest.raises(OpenVMV3CandidateVerifierError, match="verifying key SHA-256"):
        verifier(statement(), PROOF_BYTES)


def test_invalid_policy_is_rejected_before_running_checker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, *_ = make_verifier(tmp_path)
    monkeypatch.setattr(
        "src.protocol.openvm_v3_candidate_verifier.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("checker must not run for invalid policy"),
    )
    tx = statement()
    invalid = TxFieldsV3Candidate(
        params_id=tx.params_id,
        namespace_id=tx.namespace_id,
        commitment_root=tx.commitment_root,
        input_nullifier=tx.input_nullifier,
        ledger_state_head=tx.ledger_state_head,
        state_context_digest=tx.state_context_digest,
        authorization_policy_id=b"unexpected-policy",
        fee=tx.fee,
        output_entropy=tx.output_entropy,
        output_commitments=tx.output_commitments,
    )
    with pytest.raises(TransactionV3CandidateError, match="does not select"):
        verifier(invalid, PROOF_BYTES)


def test_bad_proof_bytes_rejected_without_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, *_ = make_verifier(tmp_path)
    monkeypatch.setattr(
        "src.protocol.openvm_v3_candidate_verifier.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("checker must not run for invalid proof bytes"),
    )
    assert verifier(statement(), b"") is False
    assert verifier(statement(), bytearray(PROOF_BYTES)) is False


def test_verifier_timeout_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, *_ = make_verifier(tmp_path)

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(
        "src.protocol.openvm_v3_candidate_verifier.subprocess.run",
        timeout,
    )
    with pytest.raises(OpenVMV3CandidateVerifierError, match="failed closed"):
        verifier(statement(), PROOF_BYTES)
