"""Fail-closed adapter for the experimental OpenVM V3 candidate app-proof checker.

This adapter accepts the binary/serialized proof artifact emitted by the pinned
OpenVM CLI, binds verification to a typed canonical TxFieldsV3Candidate, and
checks the exact 32-byte public digest plus an explicitly pinned executable
commitment. It is a candidate integration, not a production authorization or
trusted-state provider. Deployment must pin the checker executable, application
verifying key, executable commitment, and toolchain as reviewed release inputs.
"""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from src.protocol.transaction_v3_candidate import (
    TX_V3_CANDIDATE_VERSION,
    TxFieldsV3Candidate,
    transaction_digest_v3_candidate,
    validate_nk_possession_policy_v3_candidate,
)

PUBLIC_STATEMENT_DOMAIN_V3_SPEND_CANDIDATE = (
    b"0PSP-OPENVM-V3-SPEND-PUBLIC-STATEMENT-CANDIDATE-v2"
)
APP_EXECUTABLE_COMMITMENT_BYTES = 32
PUBLIC_DIGEST_BYTES = 64
MAX_PROOF_BYTES = 2_000_000


class OpenVMV3CandidateVerifierError(ValueError):
    """The verifier is misconfigured or could not verify a candidate proof."""


MAX_PINNED_ARTIFACT_BYTES = 512 * 1024 * 1024


def _regular_file_sha256(path: Path, *, executable: bool = False) -> bytes:
    """Hash a pinned artifact through a no-follow descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OpenVMV3CandidateVerifierError(
            f"cannot safely open pinned verifier artifact: {path}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OpenVMV3CandidateVerifierError(
                f"pinned verifier artifact is not a regular file: {path}"
            )
        if info.st_size <= 0 or info.st_size > MAX_PINNED_ARTIFACT_BYTES:
            raise OpenVMV3CandidateVerifierError(
                f"pinned verifier artifact size is outside the accepted range: {path}"
            )
        if executable and sys.platform != "win32" and not (
            info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            raise OpenVMV3CandidateVerifierError(
                f"proof checker is not executable: {path}"
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_PINNED_ARTIFACT_BYTES:
                raise OpenVMV3CandidateVerifierError(
                    f"pinned verifier artifact exceeds size limit: {path}"
                )
            digest.update(block)
        return digest.digest()
    finally:
        os.close(fd)


def _stage_pinned_artifact(
    source: Path,
    destination: Path,
    *,
    expected_sha256: bytes,
    executable: bool = False,
) -> None:
    """Copy and hash the same open-file bytes, then use only the staged artifact.

    Hashing a source path and later executing/reading that path leaves a
    time-of-check/time-of-use race. This helper opens with O_NOFOLLOW, streams
    from that descriptor into a new file in the verifier's private temp directory,
    hashes exactly those bytes, and refuses to use the copy unless the digest
    matches the configured pin.
    """
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, source_flags)
    except OSError as exc:
        raise OpenVMV3CandidateVerifierError(
            f"cannot safely open pinned verifier artifact: {source}"
        ) from exc

    target_mode = 0o700 if executable else 0o600
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    target_fd: int | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode):
            raise OpenVMV3CandidateVerifierError(
                f"pinned verifier artifact is not a regular file: {source}"
            )
        if info.st_size <= 0 or info.st_size > MAX_PINNED_ARTIFACT_BYTES:
            raise OpenVMV3CandidateVerifierError(
                f"pinned verifier artifact size is outside the accepted range: {source}"
            )
        if executable and sys.platform != "win32" and not (
            info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            raise OpenVMV3CandidateVerifierError(
                f"proof checker is not executable: {source}"
            )
        try:
            target_fd = os.open(destination, target_flags, target_mode)
        except OSError as exc:
            raise OpenVMV3CandidateVerifierError(
                f"cannot create private staged verifier artifact: {destination.name}"
            ) from exc

        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_PINNED_ARTIFACT_BYTES:
                raise OpenVMV3CandidateVerifierError(
                    f"pinned verifier artifact exceeds size limit: {source}"
                )
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise OpenVMV3CandidateVerifierError(
                        f"short write while staging verifier artifact: {destination.name}"
                    )
                view = view[written:]
        os.fsync(target_fd)
        os.fchmod(target_fd, target_mode)
    except Exception:
        if target_fd is not None:
            os.close(target_fd)
            target_fd = None
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)

    if digest.digest() != expected_sha256:
        destination.unlink(missing_ok=True)
        label = "proof-checker executable" if executable else "OpenVM application verifying key"
        raise OpenVMV3CandidateVerifierError(
            f"{label} SHA-256 differs from its configured release pin"
        )


def v3_spend_public_digest_candidate(statement: TxFieldsV3Candidate) -> bytes:
    """Match the guest's full 64-byte, versioned public-statement digest."""
    if not isinstance(statement, TxFieldsV3Candidate):
        raise TypeError("statement must be TxFieldsV3Candidate")
    validate_nk_possession_policy_v3_candidate(statement)
    if len(statement.output_commitments) != 1:
        raise OpenVMV3CandidateVerifierError(
            "the pinned OpenVM guest supports exactly one output"
        )
    tx_digest = transaction_digest_v3_candidate(statement)
    preimage = (
        PUBLIC_STATEMENT_DOMAIN_V3_SPEND_CANDIDATE
        + TX_V3_CANDIDATE_VERSION
        + tx_digest
    )
    return hashlib.shake_256(preimage).digest(PUBLIC_DIGEST_BYTES)


class OpenVMV3CandidateProofVerifier:
    """Callable verifier adapter usable as SQLiteV3CandidateLedger's proof callback.

    The constructor requires expected SHA-256 digests for both the Rust proof
    checker executable and the application verifying key, plus the exact 32-byte
    application executable commitment. The file digests are rechecked for every
    proof to fail closed if a deployed artifact changes after initialization.
    """

    def __init__(
        self,
        *,
        checker_executable: str | Path,
        app_verifying_key: str | Path,
        expected_checker_sha256: bytes,
        expected_app_verifying_key_sha256: bytes,
        app_executable_commitment: bytes,
        timeout_seconds: float = 30.0,
        max_proof_bytes: int = MAX_PROOF_BYTES,
    ) -> None:
        self._checker = Path(checker_executable).absolute()
        self._app_vk = Path(app_verifying_key).absolute()
        self._expected_checker_sha256 = self._validate_hash_pin(
            "expected_checker_sha256", expected_checker_sha256
        )
        self._expected_app_vk_sha256 = self._validate_hash_pin(
            "expected_app_verifying_key_sha256",
            expected_app_verifying_key_sha256,
        )
        if (
            not isinstance(app_executable_commitment, bytes)
            or len(app_executable_commitment) != APP_EXECUTABLE_COMMITMENT_BYTES
        ):
            raise ValueError("app_executable_commitment must be exactly 32 bytes")
        self._app_executable_commitment = app_executable_commitment
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.1 <= timeout_seconds <= 300
        ):
            raise ValueError("timeout_seconds must be in [0.1, 300]")
        if (
            isinstance(max_proof_bytes, bool)
            or not isinstance(max_proof_bytes, int)
            or not 1 <= max_proof_bytes <= MAX_PROOF_BYTES
        ):
            raise ValueError(f"max_proof_bytes must be in [1, {MAX_PROOF_BYTES}]")
        self._timeout_seconds = float(timeout_seconds)
        self._max_proof_bytes = max_proof_bytes
        self._validate_pinned_artifacts()

    @staticmethod
    def _validate_hash_pin(name: str, value: object) -> bytes:
        if not isinstance(value, bytes) or len(value) != 32:
            raise ValueError(f"{name} must be exactly 32 SHA-256 bytes")
        return value

    def _validate_pinned_artifacts(self) -> None:
        checker_sha256 = _regular_file_sha256(self._checker, executable=True)
        if checker_sha256 != self._expected_checker_sha256:
            raise OpenVMV3CandidateVerifierError(
                "proof-checker executable SHA-256 differs from its configured release pin"
            )
        app_vk_sha256 = _regular_file_sha256(self._app_vk)
        if app_vk_sha256 != self._expected_app_vk_sha256:
            raise OpenVMV3CandidateVerifierError(
                "OpenVM application verifying-key SHA-256 differs from its configured release pin"
            )

    def __call__(
        self,
        statement: TxFieldsV3Candidate,
        proof: bytes,
    ) -> bool:
        if not isinstance(statement, TxFieldsV3Candidate):
            raise OpenVMV3CandidateVerifierError(
                "proof callback requires typed canonical TxFieldsV3Candidate"
            )
        validate_nk_possession_policy_v3_candidate(statement)
        if len(statement.output_commitments) != 1:
            raise OpenVMV3CandidateVerifierError(
                "the pinned OpenVM guest supports exactly one output"
            )
        if not isinstance(proof, bytes) or not 1 <= len(proof) <= self._max_proof_bytes:
            return False

        expected_digest = v3_spend_public_digest_candidate(statement)
        with tempfile.TemporaryDirectory(prefix="0psp-openvm-v3-verify-") as temp_dir:
            # Use a private, hash-verified snapshot for both verifier executable and
            # VK. Never hash one pathname and later execute/read that same pathname.
            root = Path(temp_dir)
            checker_suffix = self._checker.suffix if sys.platform == "win32" else ""
            checker_path = root / ("proof-checker" + checker_suffix)
            app_vk_path = root / "app.vk"
            _stage_pinned_artifact(
                self._checker,
                checker_path,
                expected_sha256=self._expected_checker_sha256,
                executable=True,
            )
            _stage_pinned_artifact(
                self._app_vk,
                app_vk_path,
                expected_sha256=self._expected_app_vk_sha256,
            )

            proof_path = root / "submitted.app.proof"
            exe_commit_path = root / "expected-app-exe-commit.txt"
            digest_path = root / "expected-public-digest.txt"
            proof_path.write_bytes(proof)
            exe_commit_path.write_text(
                self._app_executable_commitment.hex() + "\n",
                encoding="ascii",
            )
            digest_path.write_text(expected_digest.hex() + "\n", encoding="ascii")
            os.chmod(proof_path, 0o600)
            os.chmod(exe_commit_path, 0o600)
            os.chmod(digest_path, 0o600)

            try:
                result = subprocess.run(
                    [
                        str(checker_path),
                        str(app_vk_path),
                        str(proof_path),
                        str(exe_commit_path),
                        str(digest_path),
                    ],
                    shell=False,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise OpenVMV3CandidateVerifierError(
                    "OpenVM proof checker failed closed"
                ) from exc

            # Do not accept partial stdout, a matching string, or a host-generated
            # digest as verification. Only the pinned verifier's zero exit status
            # after proof/VK/executable/public-output checking is accepted.
            return result.returncode == 0


__all__ = [
    "OpenVMV3CandidateVerifierError",
    "OpenVMV3CandidateProofVerifier",
    "v3_spend_public_digest_candidate",
]
