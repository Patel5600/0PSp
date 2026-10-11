#!/usr/bin/env python3
"""Functional nullifier smoke tests; not a cryptographic security test."""
from __future__ import annotations

import hashlib

from src.primitives.nullifier import (
    COIN_ID_BYTES,
    NULLIFIER_BYTES,
    NULLIFIER_SECRET_BYTES,
    NULLIFIER_INPUT_BYTES,
    DOMAIN_NULLIFIER,
    PROTOCOL_VERSION,
    CoinId,
    NullifierSecret,
    NullifierSet,
    compute_nullifier,
)


def main() -> int:
    coin_id = CoinId(bytes(range(COIN_ID_BYTES)))
    r_nf = NullifierSecret(bytes(range(NULLIFIER_SECRET_BYTES)))
    nu = compute_nullifier(coin_id, r_nf)
    expected = bytes.fromhex(
        "e672f7462704e6b2140be549ff12b9db66f6f53f0ae6826e"
        "612a3b1cf1b0d8a6bdef7c74ad25ba4227a620d4d1d19b42"
    )
    assert len(nu.value) == NULLIFIER_BYTES == 48
    assert nu.value == expected
    assert compute_nullifier(coin_id, r_nf) == nu
    assert NULLIFIER_INPUT_BYTES == 99 <= 136

    other_coin = CoinId(bytes((x + 1) % 256 for x in range(COIN_ID_BYTES)))
    other_secret = NullifierSecret(bytes((x + 7) % 256 for x in range(NULLIFIER_SECRET_BYTES)))
    assert compute_nullifier(other_coin, r_nf) != nu
    assert compute_nullifier(coin_id, other_secret) != nu

    h = hashlib.shake_256()
    h.update(b"0PSP-ALTERNATE-DOMAIN")
    h.update(PROTOCOL_VERSION)
    h.update(len(coin_id.data).to_bytes(2, "little"))
    h.update(coin_id.data)
    h.update(len(r_nf.data).to_bytes(2, "little"))
    h.update(r_nf.data)
    assert h.digest(NULLIFIER_BYTES) != nu.value

    ledger = NullifierSet()
    assert ledger.try_spend(nu)
    assert not ledger.try_spend(nu)

    print("0PSP nullifier-v1 functional smoke tests")
    print("[PASS] fixed known-answer vector and deterministic 384-bit output")
    print("[PASS] sample witness substitutions and domain separation")
    print("[PASS] duplicate-nullifier rejection in the in-memory replay model")
    print("FUNCTIONAL CHECKS PASSED; NO CRYPTOGRAPHIC SECURITY CLAIM.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
