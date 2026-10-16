"""Unit tests for the automated formal verification suite of V3 cryptographic invariants."""
from __future__ import annotations

import pytest

from scripts.formal_verify_v3_invariants import (
    compute_vandermonde_rank,
    verify_all_v3_invariants,
    verify_invariant_1_value_conservation,
    verify_invariant_2_vandermonde_rank,
    verify_invariant_3_bijective_statement_binding,
)


def test_invariant_1_zero_modular_wraparound() -> None:
    res = verify_invariant_1_value_conservation()
    assert res.verified is True
    assert "Zero Modular Wraparound" in res.invariant_name
    assert "Slack" in res.proof_details or "UNSAT" in res.proof_details


def test_invariant_2_full_row_rank_vandermonde() -> None:
    # Canonical B = 80 blinding rows achieves full row rank 78 / 78
    res = verify_invariant_2_vandermonde_rank(blinding_rows=80)
    assert res.verified is True
    assert "Full Row Rank" in res.invariant_name
    assert "Rank == 78 is True" in res.proof_details
    assert "strictly 0" in res.proof_details


def test_invariant_2_legacy_blinding_fails_full_rank() -> None:
    # Negative control: legacy B = 39 yields row rank 39 < 78 (adversary advantage > 0)
    legacy_rank = compute_vandermonde_rank(78, 39)
    assert legacy_rank == 39, f"Expected legacy rank 39, got {legacy_rank}"

    res_legacy = verify_invariant_2_vandermonde_rank(blinding_rows=39)
    assert res_legacy.verified is False
    assert "Rank == 78 is False" in res_legacy.proof_details
    assert "LEAKAGE" in res_legacy.proof_details


def test_invariant_3_bijective_statement_binding() -> None:
    res = verify_invariant_3_bijective_statement_binding()
    assert res.verified is True
    assert "Strict Bijective Binding" in res.invariant_name
    assert "all 10 orthogonal canonical field mutations" in res.proof_details
    assert "Zero collisions" in res.proof_details


def test_all_invariants_pass_composite_check() -> None:
    results = verify_all_v3_invariants()
    assert len(results) == 3
    assert all(r.verified for r in results)
