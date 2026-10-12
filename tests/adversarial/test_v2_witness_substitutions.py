"""Adversarial regressions for frozen V2 commitment/nullifier reference primitives.

These tests use the real Python reference primitives, not mock hash functions.
They establish finite-vector binding behavior only; they do not prove collision
resistance, a ZK relation, or a production protocol's soundness.
"""
from __future__ import annotations

import pytest

from src.primitives.coin_commitment import (
    COMMITMENT_RANDOMNESS_BYTES,
    commit_coin_v2,
    verify_coin_opening_v2,
)
from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import (
    NULLIFIER_SECRET_BYTES,
    NullifierSecret,
    compute_nullifier_v2,
    verify_nullifier_v2_consistency,
)

NS_A = NamespaceId(bytes(range(48)))
NS_B = NamespaceId(bytes([bytes(range(48))[0] ^ 1]) + bytes(range(1, 48)))
PK = b"canonical-threshold-public-key-v1"
PARAMS = b"ringtail-test-params-v1"
VALUE = 10
COIN = ScopedCoinId(bytes(range(32)))
R_NF = NullifierSecret(bytes(range(NULLIFIER_SECRET_BYTES)))
RHO = bytes([0x33]) * COMMITMENT_RANDOMNESS_BYTES


def _commitment(namespace=NS_A, value=VALUE, coin=COIN, r_nf=R_NF, rho=RHO):
    return commit_coin_v2(namespace, PK, value, coin, r_nf, rho, PARAMS)


def test_value_inflation_tamper_does_not_open_existing_v2_commitment() -> None:
    commitment = _commitment(value=10)
    assert verify_coin_opening_v2(commitment, NS_A, PK, 10, COIN, R_NF, RHO, PARAMS)
    # Regression vector only: the same commitment must not verify when the
    # witness substitutes 1000 for the deposit-authorized amount 10.
    assert not verify_coin_opening_v2(commitment, NS_A, PK, 1000, COIN, R_NF, RHO, PARAMS)


def test_same_leaf_rejects_changed_coin_id_or_nullifier_secret() -> None:
    commitment = _commitment()
    alternate_coin = ScopedCoinId(bytes([COIN.data[0] ^ 1]) + COIN.data[1:])
    alternate_secret = NullifierSecret(bytes([R_NF.data[0] ^ 1]) + R_NF.data[1:])

    assert not verify_coin_opening_v2(commitment, NS_A, PK, VALUE, alternate_coin, R_NF, RHO, PARAMS)
    assert not verify_coin_opening_v2(commitment, NS_A, PK, VALUE, COIN, alternate_secret, RHO, PARAMS)


def test_namespace_a_commitment_and_nullifier_do_not_replay_in_namespace_b() -> None:
    commitment = _commitment(namespace=NS_A)
    nf_a = compute_nullifier_v2(NS_A, COIN, R_NF)

    assert not verify_coin_opening_v2(commitment, NS_B, PK, VALUE, COIN, R_NF, RHO, PARAMS)
    assert not verify_nullifier_v2_consistency(nf_a, NS_B, COIN, R_NF)
    assert compute_nullifier_v2(NS_B, COIN, R_NF) != nf_a


def test_reused_coin_id_with_new_nullifier_secret_is_a_distinct_candidate_not_same_leaf() -> None:
    # This intentionally records a remaining protocol question: the raw V2
    # hashes do not make the hidden coin_id globally unique. A privacy-preserving
    # ledger cannot enforce uniqueness on coin_id unless it can prove/check it
    # without learning the ID, or the identity invariant is changed by review.
    other_secret = NullifierSecret(bytes([0xA7]) * NULLIFIER_SECRET_BYTES)
    commitment_a = _commitment(coin=COIN, r_nf=R_NF)
    commitment_b = _commitment(coin=COIN, r_nf=other_secret)
    nf_a = compute_nullifier_v2(NS_A, COIN, R_NF)
    nf_b = compute_nullifier_v2(NS_A, COIN, other_secret)

    assert commitment_a != commitment_b
    assert nf_a != nf_b
    assert not verify_coin_opening_v2(commitment_a, NS_A, PK, VALUE, COIN, other_secret, RHO, PARAMS)


@pytest.mark.parametrize(
    ("field", "offset"),
    [("coin_id", i) for i in range(32)] + [("r_nf", i) for i in range(NULLIFIER_SECRET_BYTES)],
)
def test_single_byte_nullifier_witness_substitution_fails_public_nf_match(field: str, offset: int) -> None:
    baseline = compute_nullifier_v2(NS_A, COIN, R_NF)

    if field == "coin_id":
        changed = bytearray(COIN.data)
        changed[offset] ^= 0x01
        changed_coin = ScopedCoinId(bytes(changed))
        assert compute_nullifier_v2(NS_A, changed_coin, R_NF) != baseline
        assert not verify_nullifier_v2_consistency(baseline, NS_A, changed_coin, R_NF)
    else:
        changed = bytearray(R_NF.data)
        changed[offset] ^= 0x01
        changed_secret = NullifierSecret(bytes(changed))
        assert compute_nullifier_v2(NS_A, COIN, changed_secret) != baseline
        assert not verify_nullifier_v2_consistency(baseline, NS_A, COIN, changed_secret)
