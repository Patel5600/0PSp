#!/usr/bin/env python3
"""Assert that OpenVM's executed guest exposes the expected public statement digest."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_public_output.py OPENVM_RUN_LOG EXPECTED_64_BYTE_DIGEST_HEX", file=sys.stderr)
        return 2

    log_path = Path(sys.argv[1])
    expected_path = Path(sys.argv[2])
    log = log_path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Execution output:\s*(\[[^\]]*\])", log)
    if not match:
        print("OpenVM run log does not contain an execution public-output vector", file=sys.stderr)
        return 1

    try:
        decoded = ast.literal_eval(match.group(1))
        if not isinstance(decoded, list) or not all(
            isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255
            for value in decoded
        ):
            raise ValueError("public output must be a list of byte values")
        actual = bytes(decoded)
    except (ValueError, SyntaxError, TypeError) as exc:
        print(f"invalid OpenVM public-output vector: {exc}", file=sys.stderr)
        return 1

    expected_hex = expected_path.read_text(encoding="ascii").strip().lower()
    if len(expected_hex) != 128 or not re.fullmatch(r"[0-9a-f]{128}", expected_hex):
        print("expected public statement digest must be exactly 64 bytes (128 lowercase hex characters)", file=sys.stderr)
        return 1

    expected = bytes.fromhex(expected_hex)
    if len(actual) != 64:
        print(f"OpenVM exposed {len(actual)} public bytes; expected exactly 64", file=sys.stderr)
        return 1
    if len(actual) != len(expected):
        print(
            f"OpenVM exposed {len(actual)} public bytes; expected exactly {len(expected)}",
            file=sys.stderr,
        )
        return 1
    if actual != expected:
        print(
            f"OpenVM public-output mismatch: expected {expected.hex()}, got {actual.hex()}",
            file=sys.stderr,
        )
        return 1

    print(f"OpenVM public output matches exact 64-byte digest KAT: {expected.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
