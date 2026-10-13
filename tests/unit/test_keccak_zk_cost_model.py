from __future__ import annotations

import pytest

from scripts.estimate_keccak_zk_cost import (
    COMMIT_V2_DOMAIN_BYTES,
    KECCAK_ROUNDS,
    MULTIPLICATION_EQUIVALENTS_PER_PERMUTATION,
    NULLIFIER_V2_PREIMAGE_BYTES,
    SHAKE256_RATE_BYTES,
    TREE_DEPTH,
    HashCost,
    build_hash_costs,
    commitment_v2_preimage_bytes,
    estimate_spend,
    tx_fields_v2_bytes,
)


def test_frozen_preimage_lengths_and_known_transaction_fixture() -> None:
    assert COMMIT_V2_DOMAIN_BYTES == len(b"0PSP-COIN-COMMIT-v2-SHAKE256") == 28
    assert NULLIFIER_V2_PREIMAGE_BYTES == 149
    assert tx_fields_v2_bytes(19, 20, 2) == 370
    # CommitV2 base fixed framing is 203 bytes plus params_id and public-key bytes.
    assert commitment_v2_preimage_bytes(19, 1024) == 1246


@pytest.mark.parametrize(
    ("length", "expected_blocks"),
    [(0, 1), (1, 1), (135, 1), (136, 2), (137, 2), (271, 2), (272, 3)],
)
def test_shake_rate_boundary_is_padded_correctly(length: int, expected_blocks: int) -> None:
    assert HashCost("boundary", length).permutations_per_hash == expected_blocks


def test_static_gate_model_reproduces_one_input_one_output_scenario() -> None:
    result = estimate_spend(
        outputs=1,
        params_id_bytes=19,
        policy_id_bytes=20,
        input_public_key_bytes=1024,
        output_public_key_bytes=1024,
    )
    assert KECCAK_ROUNDS == 24
    assert MULTIPLICATION_EQUIVALENTS_PER_PERMUTATION == 153_600
    assert result["hash_calls"] == 68  # input, leaf, 63 nodes, nullifier, digest, output
    assert result["keccak_f_permutations"] == 153
    assert result["keccak_f_multiplication_equivalents"] == 23_500_800
    assert result["absorb_xor_multiplication_equivalents_upper_bound"] == 42_288
    assert result["modeled_multiplication_equivalents"] == 23_543_088


def test_more_outputs_or_longer_key_encoding_never_reduce_modeled_cost() -> None:
    one = estimate_spend(outputs=1, input_public_key_bytes=128, output_public_key_bytes=128)
    four = estimate_spend(outputs=4, input_public_key_bytes=128, output_public_key_bytes=128)
    long_key = estimate_spend(outputs=1, input_public_key_bytes=2048, output_public_key_bytes=2048)
    assert four["modeled_multiplication_equivalents"] > one["modeled_multiplication_equivalents"]
    assert long_key["modeled_multiplication_equivalents"] > one["modeled_multiplication_equivalents"]
    assert TREE_DEPTH == 63
    assert SHAKE256_RATE_BYTES == 136


@pytest.mark.parametrize(
    "kwargs",
    [
        {"outputs": 0},
        {"outputs": 1025},
        {"params_id_bytes": 0},
        {"policy_id_bytes": 0},
        {"input_public_key_bytes": 0},
    ],
)
def test_invalid_scenario_parameters_reject(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        build_hash_costs(**kwargs)
