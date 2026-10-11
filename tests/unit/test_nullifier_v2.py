from __future__ import annotations

import os

import pytest

from src.primitives.namespace import (
    NamespaceId,
    ScopedCoinId,
    derive_namespace_id,
    generate_scoped_coin_id_native,
)
from src.primitives.nullifier import (
    NULLIFIER_SECRET_BYTES,
    NULLIFIER_V2_INPUT_BYTES,
    NullifierSecret,
    compute_nullifier_v2,
    compute_nullifier_v2_native,
    generate_nullifier_secret_v2_native,
    verify_nullifier_v2_consistency,
)

NAMESPACE_VECTOR = bytes.fromhex(
    "04c0037350b1b2551c5b7f8b19642abd"
    "e118113083130340a0986aacfaad3d7d"
    "38c96dac07c80e9c3d45e0a1111279d2"
)
NULLIFIER_VECTOR = bytes.fromhex(
    "059698470b8228712d86c630144b9aae"
    "0d0815ba1f2038b53c9d22d484af5d46"
    "60100eb47c8fea686ebb4855cd35159d"
)


def _witness():
    ns = NamespaceId(NAMESPACE_VECTOR)
    coin = ScopedCoinId(bytes(range(32)))
    secret = NullifierSecret(bytes(range(36)))
    return ns, coin, secret


def test_v2_known_answer_and_multiblock_preimage() -> None:
    ns, coin, secret = _witness()
    nullifier = compute_nullifier_v2(ns, coin, secret)
    assert nullifier.value == NULLIFIER_VECTOR
    assert NULLIFIER_V2_INPUT_BYTES == 149
    assert len(nullifier.value) == 48


def test_v2_nullifier_changes_with_namespace_coin_or_secret() -> None:
    ns, coin, secret = _witness()
    baseline = compute_nullifier_v2(ns, coin, secret)
    alternate_ns = derive_namespace_id(bytes([1]) + bytes(31), bytes(32), bytes(32))
    assert compute_nullifier_v2(alternate_ns, coin, secret) != baseline
    assert compute_nullifier_v2(ns, ScopedCoinId(b"c" * 32), secret) != baseline
    assert compute_nullifier_v2(ns, coin, NullifierSecret(b"s" * 36)) != baseline
    assert verify_nullifier_v2_consistency(baseline, ns, coin, secret)
    assert not verify_nullifier_v2_consistency(baseline, alternate_ns, coin, secret)


def test_v2_rejects_wrong_types() -> None:
    ns, coin, secret = _witness()
    with pytest.raises(TypeError, match="namespace_id must be a NamespaceId"):
        compute_nullifier_v2(b"n" * 48, coin, secret)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="coin_id must be a ScopedCoinId"):
        compute_nullifier_v2(ns, b"c" * 32, secret)  # type: ignore[arg-type]


def test_native_v2_matches_reference_vector_and_does_not_mutate_secret() -> None:
    library = os.environ.get("PSP_NULLIFIER_LIBRARY")
    if not library:
        pytest.skip("build native library and set PSP_NULLIFIER_LIBRARY for native comparison")
    ns, coin, secret = _witness()
    secret_buf = bytearray(secret.data)
    try:
        assert compute_nullifier_v2_native(
            ns, coin, secret_buf, library_path=library
        ).value == NULLIFIER_VECTOR
        assert secret_buf == bytearray(secret.data)
        assert compute_nullifier_v2_native(
            ns, coin, secret_buf, library_path=library
        ) == compute_nullifier_v2(ns, coin, secret)
    finally:
        secret_buf[:] = bytes(NULLIFIER_SECRET_BYTES)


def test_native_coin_id_generator_fails_closed_and_returns_fixed_size() -> None:
    library = os.environ.get("PSP_NULLIFIER_LIBRARY")
    if not library:
        pytest.skip("build native library and set PSP_NULLIFIER_LIBRARY for native comparison")
    first = generate_scoped_coin_id_native(library_path=library)
    second = generate_scoped_coin_id_native(library_path=library)
    assert len(first.data) == len(second.data) == 32
    assert first != second  # Probabilistic RNG smoke check, not an entropy proof.
    with pytest.raises(RuntimeError, match="cannot load native 0PSP library"):
        generate_scoped_coin_id_native(library_path="/nonexistent/psp.so")


def test_native_v2_secret_generator_fails_closed_and_returns_mutable_fixed_size() -> None:
    library = os.environ.get("PSP_NULLIFIER_LIBRARY")
    if not library:
        pytest.skip("build native library and set PSP_NULLIFIER_LIBRARY for native comparison")
    first = generate_nullifier_secret_v2_native(library_path=library)
    second = generate_nullifier_secret_v2_native(library_path=library)
    try:
        assert isinstance(first, bytearray) and isinstance(second, bytearray)
        assert len(first) == len(second) == NULLIFIER_SECRET_BYTES
        assert first != second  # Randomness smoke check only, not an entropy proof.
    finally:
        first[:] = bytes(NULLIFIER_SECRET_BYTES)
        second[:] = bytes(NULLIFIER_SECRET_BYTES)

    with pytest.raises(RuntimeError, match="cannot load native nullifier library"):
        generate_nullifier_secret_v2_native(library_path="/nonexistent/psp.so")
