from __future__ import annotations

import pytest

from src.primitives.nullifier import (
    COIN_ID_BYTES, NULLIFIER_BYTES, NULLIFIER_SECRET_BYTES,
    CoinId, Nullifier, NullifierSecret, NullifierSet,
    compute_nullifier, verify_nullifier_consistency,
)


def test_nullifier_is_deterministic_and_384_bits() -> None:
    coin = CoinId(b"\x11" * COIN_ID_BYTES)
    secret = NullifierSecret(b"\x22" * NULLIFIER_SECRET_BYTES)
    n1 = compute_nullifier(coin, secret)
    assert compute_nullifier(coin, secret) == n1
    assert len(n1.value) == NULLIFIER_BYTES
    assert verify_nullifier_consistency(n1, coin, secret)


def test_sample_witness_substitutions_change_output() -> None:
    coin_a = CoinId(b"\x11" * COIN_ID_BYTES)
    coin_b = CoinId(b"\x12" * COIN_ID_BYTES)
    secret = NullifierSecret(b"\x22" * NULLIFIER_SECRET_BYTES)
    other_secret = NullifierSecret(b"\x23" * NULLIFIER_SECRET_BYTES)
    base = compute_nullifier(coin_a, secret)
    assert base != compute_nullifier(coin_b, secret)
    assert base != compute_nullifier(coin_a, other_secret)


def test_rejects_invalid_lengths() -> None:
    with pytest.raises(ValueError, match="coin_id must be exactly 32 bytes"):
        CoinId(b"x" * 31)
    with pytest.raises(ValueError, match="r_nf must be exactly 36 bytes"):
        NullifierSecret(b"x" * 35)
    with pytest.raises(ValueError, match="nullifier must be exactly 48 bytes"):
        Nullifier(b"x" * 32)


def test_nullifier_set_rejects_replay() -> None:
    coin = CoinId(b"\x31" * COIN_ID_BYTES)
    secret = NullifierSecret(b"\x42" * NULLIFIER_SECRET_BYTES)
    nu = compute_nullifier(coin, secret)
    ledger = NullifierSet()
    assert ledger.try_spend(nu)
    assert not ledger.try_spend(nu)
    assert ledger.is_spent(nu)
    assert len(ledger) == 1


def test_wrong_witness_fails_consistency_check() -> None:
    coin = CoinId(b"\x51" * COIN_ID_BYTES)
    secret = NullifierSecret(b"\x62" * NULLIFIER_SECRET_BYTES)
    wrong = NullifierSecret(b"\x63" * NULLIFIER_SECRET_BYTES)
    nu = compute_nullifier(coin, secret)
    assert not verify_nullifier_consistency(nu, coin, wrong)
