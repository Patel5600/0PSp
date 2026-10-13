#!/usr/bin/env python3
"""Create deterministic non-production fixtures for the OpenVM V3 nullifier spike."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

MAGIC = b"0PSP-OPENVM-V3-NULLIFIER-SPIKE-WITNESS-v1"
PUBLIC_STATEMENT_DOMAIN = b"0PSP-OPENVM-V3-NULLIFIER-PUBLIC-STATEMENT"
PARAMS_ID = b"v3-candidate-params"
NAMESPACE = bytes([0x11]) * 48
COIN_ID = bytes([0x22]) * 32
R_NF = bytes([0x33]) * 36
KEY = bytes([0x44]) * 48
RHO_A = bytes([0xA1]) * 36
RHO_B = bytes([0xA2]) * 36
BUNDLE = bytes.fromhex(
    "305053502d4e4f54452d504b2d42554e444c452d763303"
    "1300746573742d617574682d736368656d652d7631"
    "19000000746573742d726563697069656e742d7075626c69632d6b6579"
    "300075e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95"
    "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8"
)
COMMITMENT = bytes.fromhex(
    "7c29d710d6a81bed4f3df766421d66fa497072be7513022487eb55c8d4839f82"
    "a9cf6dd11105ce21602715f0644f99d0"
)
NULLIFIER = bytes.fromhex(
    "5309bdb17ad1527c06763ae96dfd806520132899bbdbc6519070883abb568a1"
    "af3bc2a43c3a965325df2ba084bcf6f93"
)
EXPECTED_KEY_COMMITMENT = bytes.fromhex(
    "75e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95"
    "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8"
)

def witness(
    *,
    bundle: bytes = BUNDLE,
    value: int = 500,
    rho: bytes = RHO_A,
    key: bytes = KEY,
    commitment: bytes = COMMITMENT,
    nullifier: bytes = NULLIFIER,
    trailing: bytes = b"",
) -> bytes:
    encoded = b"".join(
        (
            MAGIC,
            len(PARAMS_ID).to_bytes(2, "little"),
            PARAMS_ID,
            NAMESPACE,
            len(bundle).to_bytes(4, "little"),
            bundle,
            value.to_bytes(8, "little"),
            COIN_ID,
            R_NF,
            rho,
            key,
            commitment,
            nullifier,
            trailing,
        )
    )
    if len(encoded) > 2_000_000:
        raise ValueError("fixture exceeds configured guest bound")
    return encoded

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_witnesses.py OUTPUT_DIRECTORY", file=sys.stderr)
        return 2
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)

    valid = witness()
    cases = {
        "valid.witness": valid,
        "wrong-key.witness": witness(key=bytes([0x45]) * 48),
        "changed-value.witness": witness(value=501),
        "changed-salt.witness": witness(rho=RHO_B),
        "wrong-nullifier.witness": witness(nullifier=bytes([NULLIFIER[0] ^ 1]) + NULLIFIER[1:]),
        "bad-bundle.witness": witness(bundle=bytes([BUNDLE[0] ^ 1]) + BUNDLE[1:]),
        "trailing-data.witness": witness(trailing=b"\x00"),
    }
    for name, payload in cases.items():
        (output / name).write_bytes(payload)

    public_statement = b"".join(
        (
            PUBLIC_STATEMENT_DOMAIN,
            b"\x03",
            len(PARAMS_ID).to_bytes(2, "little"),
            PARAMS_ID,
            NAMESPACE,
            COMMITMENT,
            NULLIFIER,
        )
    )
    public_digest = hashlib.shake_256(public_statement).digest(48)[:32]
    expected_digest_kat = "0e56393a40f9cb5480bce7830aaed68573f828953d1b711f10064893c62fde21"
    if public_digest.hex() != expected_digest_kat:
        raise ValueError("public statement digest KAT mismatch")
    (output / "expected-public-digest.txt").write_text(public_digest.hex() + "\n", encoding="ascii")

    derived_key_commitment = hashlib.shake_256(
        b"0PSP-NULLIFIER-KEY-COMMIT-v3-SHAKE256"
        + b"\x03"
        + len(KEY).to_bytes(2, "little")
        + KEY
    ).digest(48)
    if derived_key_commitment != EXPECTED_KEY_COMMITMENT:
        raise ValueError("fixed nullifier-key commitment KAT no longer matches")
    if BUNDLE[-48:] != derived_key_commitment or len(BUNDLE) != 123:
        raise ValueError("canonical BundleV3 fixture is inconsistent")
    if len(COMMITMENT) != 48 or len(NULLIFIER) != 48:
        raise ValueError("commitment/nullifier KAT length is inconsistent")
    if len(valid) != len(witness()):
        raise ValueError("valid witness is not deterministic")
    print(f"created {len(cases)} witnesses; expected public digest {public_digest.hex()}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
