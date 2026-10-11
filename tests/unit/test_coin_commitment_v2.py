from __future__ import annotations

from src.primitives.coin_commitment import (
    COMMITMENT_BYTES,
    COMMITMENT_RANDOMNESS_BYTES,
    CoinCommitment,
    commit_coin_v2,
    verify_coin_opening_v2,
)
from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import NullifierSecret

NAMESPACE_VECTOR = bytes.fromhex(
    "04c0037350b1b2551c5b7f8b19642abd"
    "e118113083130340a0986aacfaad3d7d"
    "38c96dac07c80e9c3d45e0a1111279d2"
)
COMMITMENT_VECTOR = bytes.fromhex(
    "d3c1c39fc5ad52a88015245b550d567a"
    "38bf31138ee1201776ef35b836ad9ce0"
    "6748cdd4a0840566bd1f3cbbf525669d"
)


def _witness():
    return (
        NamespaceId(NAMESPACE_VECTOR),
        b"canonical-threshold-public-key-v1",
        2500,
        ScopedCoinId(bytes(range(32))),
        NullifierSecret(bytes(range(36))),
        b"\x33" * COMMITMENT_RANDOMNESS_BYTES,
        b"ringtail-test-params-v1",
    )


def test_namespace_bound_commitment_v2_known_answer() -> None:
    witness = _witness()
    commitment = commit_coin_v2(*witness)
    assert len(commitment.value) == COMMITMENT_BYTES == 48
    assert commitment.value == COMMITMENT_VECTOR
    assert verify_coin_opening_v2(commitment, *witness)


def test_commitment_v2_binds_namespace_and_all_opening_fields() -> None:
    ns, pk, value, coin, secret, rho, params = _witness()
    commitment = commit_coin_v2(ns, pk, value, coin, secret, rho, params)
    alternate_ns = NamespaceId(bytes([NAMESPACE_VECTOR[0] ^ 1]) + NAMESPACE_VECTOR[1:])
    assert not verify_coin_opening_v2(commitment, alternate_ns, pk, value, coin, secret, rho, params)
    assert not verify_coin_opening_v2(commitment, ns, pk, value + 1, coin, secret, rho, params)
    assert not verify_coin_opening_v2(commitment, ns, pk + b"x", value, coin, secret, rho, params)
    assert not verify_coin_opening_v2(commitment, ns, pk, value, ScopedCoinId(b"c" * 32), secret, rho, params)
    assert not verify_coin_opening_v2(commitment, ns, pk, value, coin, NullifierSecret(b"s" * 36), rho, params)
    assert not verify_coin_opening_v2(commitment, ns, pk, value, coin, secret, b"\x44" * 36, params)
    assert not verify_coin_opening_v2(commitment, ns, pk, value, coin, secret, rho, b"other-params-v1")


def test_commitment_v2_rejects_noncanonical_values() -> None:
    ns, pk, value, coin, secret, rho, params = _witness()
    try:
        commit_coin_v2(ns, pk, True, coin, secret, rho, params)
    except ValueError as exc:
        assert "unsigned 64-bit" in str(exc)
    else:
        raise AssertionError("bool must not be accepted as an integer amount")


def test_commitment_v2_type_rejects_bad_output_length() -> None:
    from src.primitives.coin_commitment import CoinCommitment
    import pytest

    with pytest.raises(ValueError, match="exactly 48 bytes"):
        CoinCommitment(b"short")
