from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "proof"
    / "openvm"
    / "v3-nullifier-spike"
    / "scripts"
    / "check_public_output.py"
)
EXPECTED = bytes(range(64))
EXPECTED_HEX = EXPECTED.hex()


def run_check(tmp_path: Path, output_literal: str, expected_hex: str = EXPECTED_HEX):
    log_path = tmp_path / "openvm-run.log"
    expected_path = tmp_path / "expected-digest.txt"
    log_path.write_text(f"Execution output: {output_literal}\n", encoding="utf-8")
    expected_path.write_text(expected_hex + "\n", encoding="ascii")
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(log_path), str(expected_path)],
        capture_output=True,
        text=True,
        check=False,
    )


def bytes_literal(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def test_exact_64_byte_public_digest_is_accepted(tmp_path: Path) -> None:
    result = run_check(tmp_path, bytes_literal(EXPECTED))
    assert result.returncode == 0, result.stderr
    assert "exact 64-byte digest KAT" in result.stdout


def test_appended_public_output_bytes_are_rejected(tmp_path: Path) -> None:
    result = run_check(tmp_path, bytes_literal(EXPECTED + b"\x00"))
    assert result.returncode == 1
    assert "expected exactly 64" in result.stderr


def test_truncated_public_output_is_rejected(tmp_path: Path) -> None:
    result = run_check(tmp_path, bytes_literal(EXPECTED[:-1]))
    assert result.returncode == 1
    assert "expected exactly 64" in result.stderr


def test_mutated_public_digest_is_rejected(tmp_path: Path) -> None:
    mutated = bytes([EXPECTED[0] ^ 1]) + EXPECTED[1:]
    result = run_check(tmp_path, bytes_literal(mutated))
    assert result.returncode == 1
    assert "public-output mismatch" in result.stderr


def test_boolean_values_are_not_accepted_as_public_bytes(tmp_path: Path) -> None:
    malformed = "[" + ", ".join(["True"] + [str(v) for v in EXPECTED[1:]]) + "]"
    result = run_check(tmp_path, malformed)
    assert result.returncode == 1
    assert "list of byte values" in result.stderr


def test_expected_digest_must_be_exactly_64_bytes(tmp_path: Path) -> None:
    result = run_check(tmp_path, bytes_literal(EXPECTED), expected_hex="0011")
    assert result.returncode == 1
    assert "exactly 64 bytes" in result.stderr


def test_missing_execution_output_is_rejected(tmp_path: Path) -> None:
    log_path = tmp_path / "openvm-run.log"
    expected_path = tmp_path / "expected-digest.txt"
    log_path.write_text("guest exited successfully but output was not logged\n", encoding="utf-8")
    expected_path.write_text(EXPECTED_HEX + "\n", encoding="ascii")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(log_path), str(expected_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "does not contain" in result.stderr
