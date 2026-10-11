from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.primitives.nullifier import (
    COIN_ID_BYTES,
    NULLIFIER_BYTES,
    NULLIFIER_INPUT_BYTES,
    NULLIFIER_SECRET_BYTES,
    DOMAIN_NULLIFIER,
    PROTOCOL_VERSION,
    CoinId,
    Nullifier,
    NullifierSecret,
    NullifierSet,
    compute_nullifier,
    compute_nullifier_native,
    generate_nullifier_secret_native,
    verify_nullifier_consistency,
)

VECTOR_A = bytes.fromhex(
    "e672f7462704e6b2140be549ff12b9db66f6f53f0ae6826e"
    "612a3b1cf1b0d8a6bdef7c74ad25ba4227a620d4d1d19b42"
)
VECTOR_ZERO = bytes.fromhex(
    "a68519942737e0ea666ce446643a77f2033093069ce1e18f"
    "202dfcd8c13839b6e0565abaad751114382ca2d6a2e65663"
)


def vector_inputs() -> tuple[CoinId, NullifierSecret]:
    return CoinId(bytes(range(32))), NullifierSecret(bytes(range(36)))


def test_fixed_known_answer_vector_and_fixed_preimage_length() -> None:
    coin, secret = vector_inputs()
    actual = compute_nullifier(coin, secret)
    assert actual.value == VECTOR_A
    assert len(actual.value) == NULLIFIER_BYTES == 48
    assert NULLIFIER_INPUT_BYTES == 99
    assert len(
        DOMAIN_NULLIFIER
        + PROTOCOL_VERSION
        + len(coin.data).to_bytes(2, "little")
        + coin.data
        + len(secret.data).to_bytes(2, "little")
        + secret.data
    ) == 99


def test_all_zero_known_answer_vector() -> None:
    actual = compute_nullifier(CoinId(bytes(32)), NullifierSecret(bytes(36)))
    assert actual.value == VECTOR_ZERO


def test_deterministic_and_sample_witness_substitutions_change_output() -> None:
    coin_a = CoinId(b"\x11" * COIN_ID_BYTES)
    coin_b = CoinId(b"\x12" * COIN_ID_BYTES)
    secret_a = NullifierSecret(b"\x22" * NULLIFIER_SECRET_BYTES)
    secret_b = NullifierSecret(b"\x23" * NULLIFIER_SECRET_BYTES)
    base = compute_nullifier(coin_a, secret_a)
    assert compute_nullifier(coin_a, secret_a) == base
    assert compute_nullifier(coin_b, secret_a) != base
    assert compute_nullifier(coin_a, secret_b) != base


def test_coin_and_secret_repr_redact_values() -> None:
    coin_bytes = b"\xab" * COIN_ID_BYTES
    secret_bytes = b"\xcd" * NULLIFIER_SECRET_BYTES
    assert repr(CoinId(coin_bytes)) == "CoinId(<redacted>)"
    assert repr(NullifierSecret(secret_bytes)) == "NullifierSecret(<redacted>)"
    assert coin_bytes.hex()[:16] not in repr(CoinId(coin_bytes))
    assert secret_bytes.hex()[:16] not in repr(NullifierSecret(secret_bytes))


def test_canonical_lengths_and_types_are_enforced() -> None:
    with pytest.raises(ValueError, match="coin_id must be exactly 32 bytes"):
        CoinId(b"x" * 31)
    with pytest.raises(ValueError, match="r_nf must be exactly 36 bytes"):
        NullifierSecret(b"x" * 35)
    with pytest.raises(ValueError, match="nullifier must be exactly 48 bytes"):
        Nullifier(b"x" * 32)
    with pytest.raises(TypeError, match="coin_id must be a CoinId"):
        compute_nullifier(b"x" * 32, NullifierSecret(b"s" * 36))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="r_nf must be a NullifierSecret"):
        compute_nullifier(CoinId(b"x" * 32), b"s" * 36)  # type: ignore[arg-type]


def test_wrong_witness_fails_consistency_check() -> None:
    coin = CoinId(b"\x51" * 32)
    correct = NullifierSecret(b"\x62" * 36)
    wrong = NullifierSecret(b"\x63" * 36)
    nu = compute_nullifier(coin, correct)
    assert verify_nullifier_consistency(nu, coin, correct)
    assert not verify_nullifier_consistency(nu, coin, wrong)


def test_nullifier_set_rejects_replay_atomically_in_process() -> None:
    coin = CoinId(b"\x31" * 32)
    secret = NullifierSecret(b"\x42" * 36)
    nu = compute_nullifier(coin, secret)
    ledger = NullifierSet()
    with ThreadPoolExecutor(max_workers=12) as pool:
        accepted = list(pool.map(lambda _: ledger.try_spend(nu), range(64)))
    assert sum(accepted) == 1
    assert ledger.is_spent(nu)
    assert len(ledger) == 1


def test_native_openssl_matches_reference_vector() -> None:
    library = os.environ.get("PSP_NULLIFIER_LIBRARY")
    if not library:
        pytest.skip("build native library and set PSP_NULLIFIER_LIBRARY to test native implementation")
    coin, secret = vector_inputs()
    native_secret = bytearray(secret.data)
    try:
        native = compute_nullifier_native(coin, native_secret, library_path=library)
        assert native.value == VECTOR_A
        assert native == compute_nullifier(coin, secret)
        assert native_secret == bytearray(secret.data), "native function must borrow, not modify, the caller's buffer"
    finally:
        native_secret[:] = bytes(NULLIFIER_SECRET_BYTES)


def test_native_secret_generator_emits_fixed_length_distinct_samples() -> None:
    library = os.environ.get("PSP_NULLIFIER_LIBRARY")
    if not library:
        pytest.skip("build native library and set PSP_NULLIFIER_LIBRARY to test native implementation")
    first = generate_nullifier_secret_native(library_path=library)
    second = generate_nullifier_secret_native(library_path=library)
    try:
        assert len(first) == len(second) == NULLIFIER_SECRET_BYTES
        assert first != second  # Probabilistic integration smoke test, not an entropy proof.
    finally:
        first[:] = bytes(NULLIFIER_SECRET_BYTES)
        second[:] = bytes(NULLIFIER_SECRET_BYTES)


def test_native_requires_mutable_fixed_size_secret() -> None:
    with pytest.raises(ValueError, match="bytearray of exactly 36 bytes"):
        compute_nullifier_native(
            CoinId(bytes(32)), b"s" * 36, library_path="missing.so"  # type: ignore[arg-type]
        )
