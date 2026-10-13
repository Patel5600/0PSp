from __future__ import annotations

import pytest

from scripts.estimate_binary_field_keccak import (
    CHI_ROWS_PER_PERMUTATION,
    binary_chi_output,
    binary_chi_relation_holds,
    estimate_binary_field_relation,
)


def test_binary_chi_relation_matches_truth_table() -> None:
    for a in (0, 1):
        for b in (0, 1):
            for c in (0, 1):
                out = binary_chi_output(a, b, c)
                assert binary_chi_relation_holds(a, b, c, out)
                assert not binary_chi_relation_holds(a, b, c, out ^ 1)


def test_chi_cost_per_permutation_is_exact_for_the_fused_relation() -> None:
    assert CHI_ROWS_PER_PERMUTATION == 38_400


def test_one_input_one_output_binary_field_scenario() -> None:
    result = estimate_binary_field_relation(
        outputs=1,
        params_id_bytes=19,
        policy_id_bytes=20,
        input_public_key_bytes=1024,
        output_public_key_bytes=1024,
    )
    assert result["hash_calls"] == 68
    assert result["keccak_f_permutations"] == 153
    assert result["keccak_chi_multiplication_rows"] == 5_875_200
    assert result["hash_preimage_bytes_counted_for_bitness"] == 14_534
    assert result["hash_preimage_bitness_rows_upper_bound"] == 116_272
    assert result["modeled_keccak_relation_rows_upper_bound"] == 5_991_472


def test_more_outputs_never_reduce_the_modeled_binary_field_cost() -> None:
    one = estimate_binary_field_relation(
        outputs=1, input_public_key_bytes=128, output_public_key_bytes=128
    )
    four = estimate_binary_field_relation(
        outputs=4, input_public_key_bytes=128, output_public_key_bytes=128
    )
    assert four["modeled_keccak_relation_rows_upper_bound"] > one["modeled_keccak_relation_rows_upper_bound"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"outputs": 0},
        {"outputs": 1025},
        {"params_id_bytes": 0},
        {"policy_id_bytes": 0},
        {"input_public_key_bytes": 0},
        {"output_public_key_bytes": 0},
    ],
)
def test_invalid_binary_field_scenario_rejects(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        estimate_binary_field_relation(**kwargs)


@pytest.mark.parametrize(
    "values",
    [
        (-1, 0, 0, 0),
        (0, 2, 0, 0),
        (0, 0, 0, 3),
    ],
)
def test_chi_relation_rejects_non_boolean_values(values: tuple[int, int, int, int]) -> None:
    assert not binary_chi_relation_holds(*values)
