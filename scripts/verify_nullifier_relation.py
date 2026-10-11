#!/usr/bin/env python3
"""Functional nullifier smoke tests; not a cryptographic security test."""
from __future__ import annotations

import hashlib

from src.primitives.nullifier import (
    COIN_ID_BYTES, NULLIFIER_BYTES, NULLIFIER_SECRET_BYTES,
    PROTOCOL_VERSION, CoinId, NullifierSecret, NullifierSet, compute_nullifier,
)


def main() -> int:
    coin_id = CoinId(bytes(range(COIN_ID_BYTES)))
    secret = NullifierSecret(bytes(range(NULLIFIER_SECRET_BYTES)))
    nu = compute_nullifier(coin_id, secret)
    assert len(nu.value) == NULLIFIER_BYTES
    assert compute_nullifier(coin_id, secret) == nu

    other_coin = CoinId(bytes((x + 1) % 256 for x in range(COIN_ID_BYTES)))
    other_secret = NullifierSecret(bytes((x + 7) % 256 for x in range(NULLIFIER_SECRET_BYTES)))
    assert compute_nullifier(other_coin, secret) != nu
    assert compute_nullifier(coin_id, other_secret) != nu

    h = hashlib.shake_256()
    h.update(b"0PSP-ALTERNATE-DOMAIN")
    h.update(PROTOCOL_VERSION)
    h.update(len(coin_id.data).to_bytes(2, "little"))
    h.update(coin_id.data)
    h.update(len(secret.data).to_bytes(2, "little"))
    h.update(secret.data)
    assert h.digest(NULLIFIER_BYTES) != nu.value

    ledger = NullifierSet()
    assert ledger.try_spend(nu)
    assert not ledger.try_spend(nu)

    print("0PSP nullifier functional smoke tests")
    print("[PASS] deterministic 384-bit nullifier")
    print("[PASS] sample witness substitutions alter output")
    print("[PASS] domain separation and protocol version")
    print("[PASS] duplicate-nullifier rejection in in-memory model")
    print("FUNCTIONAL CHECKS PASSED; NO CRYPTOGRAPHIC SECURITY CLAIM.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
