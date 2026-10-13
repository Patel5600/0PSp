from __future__ import annotations

import pytest

from scripts.estimate_smallwood_r1cs_adapter import estimate_dense_theta_storage


def test_one_keccak_permutation_scale_already_exceeds_laptop_memory() -> None:
    result = estimate_dense_theta_storage(
        constraints=153_600,
        variables=155_200,
        batch_columns=256,
    )
    assert result["witness_rows"] == 607
    assert result["total_matrix_slots"] == 71_840_563_200
    assert result["pointer_storage_floor_bytes"] == 574_724_505_600
    assert result["pointer_storage_floor_gib"] > 500


def test_two_keccak_permutation_scale_exceeds_two_terabytes_of_pointer_slots() -> None:
    result = estimate_dense_theta_storage(
        constraints=307_200,
        variables=310_000,
        batch_columns=256,
    )
    assert result["witness_rows"] == 1_211
    assert result["total_matrix_slots"] == 286_182_604_800
    assert result["pointer_storage_floor_bytes"] == 2_289_460_838_400
    assert result["pointer_storage_floor_tib"] > 2


def test_primary_input_storage_is_included() -> None:
    no_primary = estimate_dense_theta_storage(
        constraints=10,
        variables=20,
        batch_columns=8,
        primary_inputs=0,
    )
    with_primary = estimate_dense_theta_storage(
        constraints=10,
        variables=20,
        batch_columns=8,
        primary_inputs=3,
    )
    assert with_primary["total_matrix_slots"] - no_primary["total_matrix_slots"] == 2 * 3 * 8


@pytest.mark.parametrize(
    "kwargs",
    [
        {"constraints": 0, "variables": 10, "batch_columns": 4},
        {"constraints": 10, "variables": 0, "batch_columns": 4},
        {"constraints": 10, "variables": 10, "batch_columns": 0},
        {"constraints": 10, "variables": 10, "batch_columns": 4, "primary_inputs": 11},
        {"constraints": 10, "variables": 10, "batch_columns": 4, "primary_inputs": -1},
        {"constraints": 10, "variables": 10, "batch_columns": 4, "pointer_bytes": 0},
    ],
)
def test_invalid_scaling_inputs_reject(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        estimate_dense_theta_storage(**kwargs)
