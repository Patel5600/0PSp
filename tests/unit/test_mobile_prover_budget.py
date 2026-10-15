"""Unit tests for the mobile prover memory budget model (estimate_mobile_prover_budget.py)."""
from __future__ import annotations

import pytest

from scripts.estimate_mobile_prover_budget import (
    ANDROID_LMK_RAM_LIMIT_MB,
    IOS_JETSAM_RAM_LIMIT_MB,
    MOBILE_TARGET_RAM_BUDGET_MB,
    _next_power_of_two,
    calculate_monolithic_permutations,
    calculate_tier1_permutations,
    evaluate_feasibility,
    evaluate_mobile_prover_architectures,
)


def test_mobile_budget_constants() -> None:
    assert ANDROID_LMK_RAM_LIMIT_MB == 384
    assert IOS_JETSAM_RAM_LIMIT_MB == 256
    assert MOBILE_TARGET_RAM_BUDGET_MB == 128


def test_next_power_of_two() -> None:
    assert _next_power_of_two(0) == 1
    assert _next_power_of_two(1) == 1
    assert _next_power_of_two(2) == 2
    assert _next_power_of_two(3) == 4
    assert _next_power_of_two(1024) == 1024
    assert _next_power_of_two(1025) == 2048


def test_evaluate_feasibility_logic() -> None:
    # Safe mobile profile
    android, ios, support, summary = evaluate_feasibility(peak_ram_mb=22.5, proving_time_sec=0.38)
    assert android == "FEASIBLE"
    assert ios == "FEASIBLE"
    assert support == 100.0
    assert "Fully feasible" in summary

    # Borderline on iOS (>128 MB, <=256 MB)
    android, ios, support, summary = evaluate_feasibility(peak_ram_mb=180.0, proving_time_sec=9.5)
    assert android == "FEASIBLE"
    assert ios == "BORDERLINE"
    assert support == 85.0

    # Infeasible on iOS (>256 MB, <=384 MB)
    android, ios, support, summary = evaluate_feasibility(peak_ram_mb=300.0, proving_time_sec=15.0)
    assert android == "BORDERLINE"
    assert ios == "FATAL_OOM"
    assert support == 45.0

    # Fatal OOM on both (>384 MB)
    android, ios, support, summary = evaluate_feasibility(peak_ram_mb=4626.0, proving_time_sec=133.37)
    assert android == "FATAL_OOM"
    assert ios == "FATAL_OOM"
    assert support == 0.0
    assert "FATAL: Infeasible on mobile" in summary


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
    assert zkvm.device_support_percent == 0.0
    assert zkvm.witness_privacy_proven is False
    assert zkvm.witness_privacy_preserved is False
    assert zkvm.witness_privacy_status == "BLOCKED_BY_ISSUE_36"

    # 2. SmallWood Dense R1CS
    smallwood = res["profiles"][1]
    assert "SmallWood" in smallwood.architecture
    assert smallwood.peak_ram_mb > 2_000_000  # >= 2.082 TiB
    assert smallwood.android_mobile_status == "FATAL_OOM"
    assert smallwood.ios_mobile_status == "FATAL_OOM"
    assert smallwood.device_support_percent == 0.0
    assert smallwood.witness_privacy_proven is False
    assert smallwood.witness_privacy_status == "UNMASKED_WITNESS_LEAKAGE"

    # 3. Native Keccak AIR
    air = res["profiles"][2]
    assert "Native Keccak AIR" in air.architecture
    assert air.peak_ram_mb < ANDROID_LMK_RAM_LIMIT_MB
    assert air.android_mobile_status == "FEASIBLE"
    assert air.ios_mobile_status == "BORDERLINE"
    assert air.device_support_percent == 85.0
    assert air.witness_privacy_proven is False
    assert air.witness_privacy_status == "CONDITIONAL_ON_ZK_BLINDING_ROWS"

    # 4. 2-Tier Blinded Split-Prover
    split = res["profiles"][3]
    assert "2-Tier Blinded Split-Prover" in split.architecture
    assert split.peak_ram_mb < MOBILE_TARGET_RAM_BUDGET_MB
    assert split.peak_ram_mb <= 25.0  # 22.5 MB
    assert split.estimated_time_arm64_sec < 1.0  # 0.38 s
    assert split.android_mobile_status == "FEASIBLE"
    assert split.ios_mobile_status == "FEASIBLE"
    assert split.device_support_percent == 100.0
    assert split.witness_privacy_proven is False  # Honest: conditionally gated on ZK blinding rows
    assert split.witness_privacy_preserved is False  # Backward-compatible property
    assert split.witness_privacy_status == "CONDITIONAL_ON_ZK_BLINDING_ROWS"


def test_tree_depth_scaling_and_stark_power_of_two_domains() -> None:
    """Verify that tree_depth affects monolithic provers while Tier 1 remains invariant (O(1)).

    Also verify that STARK quotient domain sizes round up to 2^k powers of two.
    """
    res_63 = evaluate_mobile_prover_architectures(tree_depth=63, outputs=1)
    res_32 = evaluate_mobile_prover_architectures(tree_depth=32, outputs=1)

    zkvm_63, _, air_63, split_63 = res_63["profiles"]
    zkvm_32, _, air_32, split_32 = res_32["profiles"]

    # Monolithic permutations scale down with reduced tree depth (153 -> 91)
    assert res_32["monolithic_permutations"] == 91
    assert res_63["monolithic_permutations"] == 153

    # STARK Power-of-two domain quantization:
    # At d=63 (16.78M active rows) and d=32 (9.98M active rows), both round to 2^24 = 16,777,216 rows
    assert zkvm_63.trace_rows == 16_777_216
    assert zkvm_32.trace_rows == 16_777_216
    # Active execution buffers scale down, but domain LDE allocation remains invariant
    assert zkvm_32.peak_ram_mb < zkvm_63.peak_ram_mb
    assert zkvm_32.peak_ram_mb > 2_000.0  # Still > 2,000 MB due to 1,950 MB invariant domain allocation!
    assert zkvm_32.estimated_time_arm64_sec < zkvm_63.estimated_time_arm64_sec

    # Native AIR power-of-two domain quantization:
    # At d=63 (131,072 rows) and d=32 (77,958 rows), both round to 2^17 = 131,072 rows
    assert air_63.trace_rows == 131_072
    assert air_32.trace_rows == 131_072
    assert air_32.peak_ram_mb < air_63.peak_ram_mb
    assert air_32.peak_ram_mb <= 160.0

    # Tier 1 Split-Prover is O(1) w.r.t tree_depth (0 Merkle node hashes on mobile)
    assert res_32["tier1_permutations"] == res_63["tier1_permutations"]
    assert split_32.peak_ram_mb == split_63.peak_ram_mb
    assert split_32.trace_rows == split_63.trace_rows
    assert split_32.estimated_time_arm64_sec == split_63.estimated_time_arm64_sec


def test_outputs_scaling_normal_range() -> None:
    """Verify that outputs count scales all architectures, while Tier 1 remains within mobile budget for normal m."""
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

    # Tier 1 scales with outputs: at m=5, 18.0 + 5*4.5 = 40.5 MB, safely under 128 MB target
    assert split_5.peak_ram_mb > split_1.peak_ram_mb
    assert split_5.peak_ram_mb == 40.5
    assert split_5.peak_ram_mb < MOBILE_TARGET_RAM_BUDGET_MB
    assert split_5.android_mobile_status == "FEASIBLE"
    assert split_5.ios_mobile_status == "FEASIBLE"
    assert split_5.device_support_percent == 100.0
    assert split_5.estimated_time_arm64_sec < 1.0


def test_extreme_outputs_feasibility_fatal_oom() -> None:
    """Verify that extreme output counts (m=1024) are strictly classified as FATAL_OOM with 0% device support."""
    res_extreme = evaluate_mobile_prover_architectures(tree_depth=63, outputs=1024)
    split = res_extreme["profiles"][3]

    # At m=1024: RAM = 18.0 + 1024*4.5 = 4,626.0 MB; proving time = 0.25 + 1024*0.13 = 133.37 s
    assert split.peak_ram_mb == 4626.0
    assert split.estimated_time_arm64_sec == 133.37
    # Both Android LMK (384 MB) and iOS Jetsam (256 MB) will SIGKILL this process
    assert split.android_mobile_status == "FATAL_OOM"
    assert split.ios_mobile_status == "FATAL_OOM"
    assert split.device_support_percent == 0.0
    assert "FATAL" in split.rationale
    assert "Terminated by OS SIGKILL" in split.rationale


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
