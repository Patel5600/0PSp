"""Regression tests for 0PSP Phase 1 arithmetic audit helpers.

These tests cover arithmetic consistency only. They do not instantiate or verify
a cryptographic protocol, STARK AIR, zero-knowledge system, or security theorem.
"""
from __future__ import annotations

import pytest

from scripts.audit_phase1_claims import (
    W,
    carry_residual,
    exhaustive_small_radix_carry_cases,
)


def test_exhaustive_small_radix_carry_recurrence() -> None:
    # Exhaustive bounded test over radix 2..8 and all values covered by the audit.
    assert exhaustive_small_radix_carry_cases() > 0


@pytest.mark.parametrize("base", [2, 3, 4, 5, 8, 16, W])
def test_exact_radix_boundary_has_zero_residual(base: int) -> None:
    # A sum exactly equal to one radix unit must encode as digit 0, carry 1.
    assert carry_residual(
        v_i=0,
        product_sum=base,
        b_i=0,
        carry_in=0,
        carry_out=1,
        base=base,
    ) == 0


def test_last_digit_without_carry_has_zero_residual() -> None:
    assert carry_residual(
        v_i=W - 1,
        product_sum=W - 1,
        b_i=0,
        carry_in=0,
        carry_out=0,
    ) == 0


def test_previous_opposite_sign_candidate_fails_exact_boundary() -> None:
    base = 4
    digit = 0
    product_sum = base
    b_i = 0
    carry_in = 0
    carry_out = 1

    corrected = carry_residual(
        digit, product_sum, b_i, carry_in, carry_out, base=base
    )
    previous_candidate = (
        digit - (product_sum + b_i) + carry_in - base * carry_out
    )

    assert corrected == 0
    assert previous_candidate != 0


def test_invalid_radix_is_rejected() -> None:
    with pytest.raises(ValueError, match="base must be at least 2"):
        carry_residual(0, 0, 0, 0, 0, base=1)
