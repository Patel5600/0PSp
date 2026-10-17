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
    assert report.extension_degree == DEFAULT_EXTENSION_DEGREE == 4
    assert report.challenge_field_bits_upper_bound < 125.0
    assert report.upstream_declared_rbr_soundness_bits == UPSTREAM_DECLARED_RBR_SOUNDNESS_BITS == 100
    assert report.required_composite_pq_bits == REQUIRED_COMPOSITE_PQ_BITS == 128
    assert report.composite_pq_security_bits is None
    assert report.end_to_end_witness_hiding_established is False
    assert report.meets_128bit_pq_target is False
    assert report.status == "NO-GO"
    assert len(report.blockers) >= 3


def test_hypothetical_degree_five_cannot_be_injected_as_pinned_evidence() -> None:
    report = calculate_composite_soundness()
    assert report.extension_degree == 4
    with pytest.raises(TypeError):
        calculate_composite_soundness(extension_degree=5)  # type: ignore[call-arg]


def test_cli_is_a_failing_release_gate_until_real_security_evidence_exists(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main() == 1
    output = capsys.readouterr().out
    assert "Composed post-quantum security:  UNKNOWN" in output
    assert "End-to-end witness hiding:       NOT ESTABLISHED" in output
    assert "Release status:                  NO-GO" in output
