"""Unit tests for the 0PSP Composite STARK/FRI Soundness Reduction verifier."""
from __future__ import annotations

import pytest

from scripts.verify_composite_soundness import (
    BABYBEAR_P,
    DEFAULT_BLOWUP_FACTOR,
    DEFAULT_EXTENSION_DEGREE,
    DEFAULT_FRI_QUERIES,
    DEFAULT_POW_GRINDING_BITS,
    calculate_composite_soundness,
)


def test_composite_soundness_defaults_exceed_128_bits() -> None:
    report = calculate_composite_soundness()

    # Base field size
    assert report.field_size_bits > 154.0

    # Error term upper bounds
    assert report.eps_quotient_bits <= -131.9
    assert report.eps_lookup_bits <= -132.5
    assert report.eps_deep_bits <= -132.9
    assert report.eps_fri_bits <= -132.0

    # Composite security level must strictly exceed 128 bits post-quantum
    assert report.security_level_bits >= 128.0
    assert report.security_level_bits > 130.0
    assert report.meets_128bit_pq_target is True

    # ZK Blinding rows requirement
    assert report.zk_blinding_rows_required == DEFAULT_FRI_QUERIES + 1  # 39 rows


def test_degree_4_extension_insufficient_soundness() -> None:
    """Verify that degree-4 extension fails to meet 128-bit security, proving degree-5 is strictly necessary."""
    report_d4 = calculate_composite_soundness(extension_degree=4)
    # Degree-4 extension gives ~123.6 bits of field size, yielding quotient error > 2^-105
    assert report_d4.field_size_bits < 125.0
    assert report_d4.eps_quotient_bits > -105.0
    assert report_d4.meets_128bit_pq_target is False
    assert report_d4.security_level_bits < 105.0


def test_fri_query_and_pow_sensitivity() -> None:
    """Verify sensitivity to FRI query count and proof-of-work grinding."""
    # Reducing queries below safe bounds drops soundness
    report_low = calculate_composite_soundness(fri_queries=20, pow_grinding_bits=0)
    assert report_low.meets_128bit_pq_target is False

    # Increasing queries drops FRI error and increases overall composite soundness
    report_default = calculate_composite_soundness()
    report_high = calculate_composite_soundness(fri_queries=45, pow_grinding_bits=24)
    assert report_high.eps_fri_bits < -150.0
    assert report_high.security_level_bits > report_default.security_level_bits
