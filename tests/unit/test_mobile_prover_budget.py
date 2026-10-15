"""Unit tests for the mobile prover memory budget model (estimate_mobile_prover_budget.py)."""
from __future__ import annotations

import pytest

from scripts.estimate_mobile_prover_budget import (
    ANDROID_LMK_RAM_LIMIT_MB,
    IOS_JETSAM_RAM_LIMIT_MB,
    MOBILE_TARGET_RAM_BUDGET_MB,
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


def test_evaluate_mobile_prover_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="tree_depth"):
        evaluate_mobile_prover_architectures(tree_depth=0)

    with pytest.raises(ValueError, match="tree_depth"):
        evaluate_mobile_prover_architectures(tree_depth=65)

    with pytest.raises(ValueError, match="outputs"):
        evaluate_mobile_prover_architectures(outputs=0)
