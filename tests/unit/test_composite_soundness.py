"""Regression tests for fail-closed OpenVM composite-soundness claim handling."""
from __future__ import annotations

import pytest

from scripts.verify_composite_soundness import (
    BABYBEAR_P,
    DEFAULT_EXTENSION_DEGREE,
    PINNED_OPENVM_REV,
    REQUIRED_COMPOSITE_PQ_BITS,
    UPSTREAM_DECLARED_RBR_SOUNDNESS_BITS,
    calculate_composite_soundness,
    main,
)


def test_pinned_openvm_profile_never_claims_128_bit_post_quantum_security() -> None:
    report = calculate_composite_soundness()

    assert report.backend_revision == PINNED_OPENVM_REV
    assert report.base_field_order == BABYBEAR_P
    assert report.extension_degree == 4
    assert report.challenge_field_bits_upper_bound < 125.0
    assert report.upstream_declared_rbr_soundness_bits == 100
    assert report.required_composite_pq_bits == REQUIRED_COMPOSITE_PQ_BITS == 128
    assert report.composite_pq_security_bits is None
    assert report.end_to_end_witness_hiding_established is False
    assert report.meets_128bit_pq_target is False
    assert report.status == "NO-GO"
    assert len(report.blockers) >= 3


def test_legacy_degree_five_assumption_is_not_part_of_the_actual_profile() -> None:
    # The former estimator reported a degree-5 extension that does not match the
    # pinned OpenVM source. The report is bound to source evidence instead.
    report = calculate_composite_soundness()
    assert report.extension_degree == DEFAULT_EXTENSION_DEGREE == 4
    assert "degree-5" in __import__(
        "inspect"
    ).getdoc(__import__("scripts.verify_composite_soundness", fromlist=["calculate_composite_soundness"]).calculate_composite_soundness) or report.extension_degree != 5


def test_cli_is_a_failing_release_gate_until_real_security_evidence_exists(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main() == 1
    output = capsys.readouterr().out
    assert "Composed post-quantum security:  UNKNOWN" in output
    assert "End-to-end witness hiding:       NOT ESTABLISHED" in output
    assert "Release status:                  NO-GO" in output
