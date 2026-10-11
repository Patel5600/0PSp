from __future__ import annotations

import pytest

from src.primitives.coin_commitment import (
    COMMITMENT_BYTES,
    COMMITMENT_RANDOMNESS_BYTES,
    CoinCommitment,
    commit_coin,
    verify_coin_opening,
)
from src.primitives.nullifier import CoinId, NullifierSecret


def _witness():
    return (
        b"canonical-threshold-public-key-v1",
        2500,
        CoinId(b"\x11" * 32),
        NullifierSecret(b"\x22" * 36),
        b"\x33" * COMMITMENT_RANDOMNESS_BYTES,
        b"ringtail-test-params-v1",
    )


def test_commitment_opening_round_trip() -> None:
    witness = _witness()
    commitment = commit_coin(*witness)
    assert len(commitment.value) == COMMITMENT_BYTES
    assert verify_coin_opening(commitment, *witness)


def test_commitment_binds_each_field() -> None:
    pk, value, coin_id, r_nf, rho, params_id = _witness()
    commitment = commit_coin(pk, value, coin_id, r_nf, rho, params_id)
    assert not verify_coin_opening(commitment, pk, value + 1, coin_id, r_nf, rho, params_id)
    assert not verify_coin_opening(commitment, pk + b"x", value, coin_id, r_nf, rho, params_id)
    assert not verify_coin_opening(
        commitment, pk, value, CoinId(b"\x12" * 32), r_nf, rho, params_id
    )
    assert not verify_coin_opening(
        commitment, pk, value, coin_id, NullifierSecret(b"\x23" * 36), rho, params_id
    )
    assert not verify_coin_opening(
        commitment, pk, value, coin_id, r_nf, b"\x44" * 36, params_id
    )


def test_commitment_parameter_domain_is_bound() -> None:
    pk, value, coin_id, r_nf, rho, params_id = _witness()
    commitment = commit_coin(pk, value, coin_id, r_nf, rho, params_id)
    assert not verify_coin_opening(
        commitment, pk, value, coin_id, r_nf, rho, b"other-params-v1"
    )


def test_commitment_rejects_bad_randomness_length() -> None:
    pk, value, coin_id, r_nf, _, params_id = _witness()
    with pytest.raises(ValueError, match="rho_coin must be exactly 36 bytes"):
        commit_coin(pk, value, coin_id, r_nf, b"short", params_id)


def test_commitment_type_rejects_bad_output_length() -> None:
    with pytest.raises(ValueError, match="coin commitment must be exactly 48 bytes"):
        CoinCommitment(b"short")
