"""Unit tests for the mobile prover memory budget model (estimate_mobile_prover_budget.py)."""
from __future__ import annotations

import pytest

from scripts.estimate_mobile_prover_budget import (
    ANDROID_LMK_RAM_LIMIT_MB,
    IOS_JETSAM_RAM_LIMIT_MB,
    MOBILE_TARGET_RAM_BUDGET_MB,
    calculate_monolithic_permutations,
    calculate_tier1_permutations,
    evaluate_mobile_prover_architectures,
)


def test_mobile_budget_constants() -> None:
    assert ANDROID_LMK_RAM_LIMIT_MB == 384
    assert IOS_JETSAM_RAM_LIMIT_MB == 256
    assert MOBILE_TARGET_RAM_BUDGET_MB == 128


def test_evaluate_mobile_prover_architectures_defaults() -> None:
    res = evaluate_mobile_prover_architectures()
    assert res["tree_depth"] == 63
    assert res["outputs"] == 1
    assert res["monolithic_permutations"] == 153
    assert res["tier1_permutations"] == 10
    assert len(res["profiles"]) == 4

    # 1. Monolithic zkVM
    zkvm = res["profiles"][0]
    assert "zkVM" in zkvm.architecture
    assert zkvm.peak_ram_mb > ANDROID_LMK_RAM_LIMIT_MB
    assert zkvm.android_mobile_status == "FATAL_OOM"
    assert zkvm.ios_mobile_status == "FATAL_OOM"

    # 2. SmallWood Dense R1CS
    smallwood = res["profiles"][1]
    assert "SmallWood" in smallwood.architecture
    assert smallwood.peak_ram_mb > 2_000_000  # >= 2.082 TiB
    assert smallwood.android_mobile_status == "FATAL_OOM"

    # 3. Native Keccak AIR
    air = res["profiles"][2]
    assert "Native Keccak AIR" in air.architecture
    assert air.peak_ram_mb < ANDROID_LMK_RAM_LIMIT_MB
    assert air.android_mobile_status == "BORDERLINE"

    # 4. 2-Tier Blinded Split-Prover
    split = res["profiles"][3]
    assert "2-Tier Blinded Split-Prover" in split.architecture
    assert split.peak_ram_mb < MOBILE_TARGET_RAM_BUDGET_MB
    assert split.peak_ram_mb <= 25.0  # Under 25 MB
    assert split.estimated_time_arm64_sec < 1.0  # Sub-second
    assert split.android_mobile_status == "FEASIBLE"
    assert split.ios_mobile_status == "FEASIBLE"
    assert split.witness_privacy_preserved is True


def test_tree_depth_scaling() -> None:
    """Verify that tree_depth affects monolithic provers while Tier 1 remains invariant (O(1))."""
    res_63 = evaluate_mobile_prover_architectures(tree_depth=63, outputs=1)
    res_32 = evaluate_mobile_prover_architectures(tree_depth=32, outputs=1)

    zkvm_63, _, air_63, split_63 = res_63["profiles"]
    zkvm_32, _, air_32, split_32 = res_32["profiles"]

    # Monolithic architectures must scale down with reduced tree depth
    assert res_32["monolithic_permutations"] < res_63["monolithic_permutations"]
    assert zkvm_32.peak_ram_mb < zkvm_63.peak_ram_mb
    assert zkvm_32.estimated_time_arm64_sec < zkvm_63.estimated_time_arm64_sec
    assert air_32.peak_ram_mb < air_63.peak_ram_mb
    assert air_32.android_mobile_status == "FEASIBLE"  # Drops <= 128 MB at depth 32!

    # Tier 1 Split-Prover is O(1) w.r.t tree_depth (0 Merkle node hashes on mobile)
    assert res_32["tier1_permutations"] == res_63["tier1_permutations"]
    assert split_32.peak_ram_mb == split_63.peak_ram_mb
    assert split_32.trace_rows == split_63.trace_rows
    assert split_32.estimated_time_arm64_sec == split_63.estimated_time_arm64_sec


def test_outputs_scaling() -> None:
    """Verify that outputs count scales all architectures, while Tier 1 remains within mobile budget."""
    res_1 = evaluate_mobile_prover_architectures(tree_depth=63, outputs=1)
    res_5 = evaluate_mobile_prover_architectures(tree_depth=63, outputs=5)

    zkvm_1, smallwood_1, air_1, split_1 = res_1["profiles"]
    zkvm_5, smallwood_5, air_5, split_5 = res_5["profiles"]

    # All provers must scale with outputs
    assert res_5["monolithic_permutations"] > res_1["monolithic_permutations"]
    assert res_5["tier1_permutations"] > res_1["tier1_permutations"]
    assert zkvm_5.peak_ram_mb > zkvm_1.peak_ram_mb
    assert air_5.peak_ram_mb > air_1.peak_ram_mb
    assert smallwood_5.peak_ram_mb > smallwood_1.peak_ram_mb

    # Tier 1 scales with outputs but remains safely under 128 MB mobile budget
    assert split_5.peak_ram_mb > split_1.peak_ram_mb
    assert split_5.peak_ram_mb < MOBILE_TARGET_RAM_BUDGET_MB
    assert split_5.android_mobile_status == "FEASIBLE"
    assert split_5.estimated_time_arm64_sec < 1.5  # Fast sub-second / low second latency


def test_evaluate_mobile_prover_boundary_and_invalid_inputs() -> None:
    # Valid boundaries
    res_min = evaluate_mobile_prover_architectures(tree_depth=1, outputs=1)
    assert res_min["tree_depth"] == 1

    res_max = evaluate_mobile_prover_architectures(tree_depth=64, outputs=1024)
    assert res_max["tree_depth"] == 64
    assert res_max["outputs"] == 1024

    # Invalid boundaries
    with pytest.raises(ValueError, match="tree_depth"):
        evaluate_mobile_prover_architectures(tree_depth=0)

    with pytest.raises(ValueError, match="tree_depth"):
        evaluate_mobile_prover_architectures(tree_depth=65)

    with pytest.raises(ValueError, match="outputs"):
        evaluate_mobile_prover_architectures(outputs=0)

    with pytest.raises(ValueError, match="outputs"):
        evaluate_mobile_prover_architectures(outputs=1025)
