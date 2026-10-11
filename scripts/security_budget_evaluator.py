#!/usr/bin/env python3
"""Historical numeric consistency diagnostics for the retired CHP3 design.

This script checks older bridge/Layer-2 arithmetic and accounting assumptions
only. It does NOT evaluate constructionable V0, estimate lattice security,
check proofs, prove QROM bounds, verify an AIR, or evaluate cryptographic
security. Exit code 0 does not mean 0PSP is secure or that sizes are measured.
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    n: int
    q: int
    k_b: int
    m_b: int
    ell_b: int
    k_tau: int
    secret_bits: int
    coin_id_bits: int
    chunk_max: int
    eta_tau: int
    beta_bridge: float
    log2_qh: float


PROFILES = (
    Profile(
        name="Profile 1 (illustrative 256-bit secret)",
        n=256,
        q=2**43 - 67,
        k_b=2,
        m_b=3,
        ell_b=1,
        k_tau=2,
        secret_bits=256,
        coin_id_bits=256,
        chunk_max=3,
        eta_tau=2,
        beta_bridge=166.5,
        log2_qh=61.8,
    ),
    Profile(
        name="Profile 2 (illustrative 288-bit secret)",
        n=256,
        q=2**43 - 67,
        k_b=2,
        m_b=4,
        ell_b=2,
        k_tau=2,
        secret_bits=288,
        coin_id_bits=256,
        chunk_max=3,
        eta_tau=2,
        beta_bridge=200.0,
        log2_qh=64.0,
    ),
)

Q_LOTRS = 2**43 - 67
QHAT_LOTRS = 2**35 - 451
Q_ML_DSA = 8_380_417
P_BABYBEAR = 2**31 - 2**27 + 1


def log2_qrom_expression(profile: Profile) -> float:
    """Arithmetic of a conditional expression, not a protocol theorem."""
    return math.log2(2 * math.pi**2) + 2 * profile.log2_qh - profile.secret_bits


def numeric_checks() -> bool:
    ok = True
    print("=" * 76)
    print("0PSP CHP3 — NUMERIC CONSISTENCY DIAGNOSTICS (NOT A SECURITY AUDIT)")
    print("=" * 76)

    print("\n--- Parameter identities ---")
    print(f"LoTRS q      = {Q_LOTRS} (2^43 - 67)")
    print(f"LoTRS q-hat  = {QHAT_LOTRS} (2^35 - 451)")
    print(f"ML-DSA q     = {Q_ML_DSA} (separate parameter family)")
    print(f"BabyBear p   = {P_BABYBEAR}")
    domain_ok = (
        Q_LOTRS == 8_796_093_022_141
        and QHAT_LOTRS == 34_359_737_917
        and Q_ML_DSA == 8_380_417
        and P_BABYBEAR == 2_013_265_921
    )
    print(f"Arithmetic identities: {'OK' if domain_ok else 'ERROR'}")
    ok &= domain_ok

    print("\n--- Capacity and norm arithmetic (assumed profile values) ---")
    for profile in PROFILES:
        dimension_ok = profile.m_b == profile.ell_b + profile.k_tau
        capacity = profile.ell_b * profile.n * 2
        required = profile.coin_id_bits + profile.secret_bits
        capacity_ok = capacity >= required

        # These are arithmetic bounds for the declared coordinate caps only.
        delta_m_inf = 2 * profile.chunk_max
        delta_tau_inf = 2 * profile.eta_tau
        norm_l2 = math.sqrt(
            profile.ell_b * profile.n * delta_m_inf**2
            + profile.k_tau * profile.n * delta_tau_inf**2
        )
        norm_ok = norm_l2 <= profile.beta_bridge

        print(f"\n{profile.name}")
        print(f"  dimension m_B = ell_B + k_tau: {dimension_ok}")
        print(f"  encoded capacity {capacity} bits >= {required} required: {capacity_ok}")
        print(f"  conditional difference-vector norm estimate: {norm_l2:.2f}")
        print(f"  norm <= declared beta {profile.beta_bridge}: {norm_ok}")
        ok &= dimension_ok and capacity_ok and norm_ok

    print("\n--- QROM expression arithmetic only ---")
    print("Premise required: the exact game must justify h bits of hidden-point")
    print("conditional min-entropy and the selected theorem must match the oracle model.")
    for profile in PROFILES:
        log2_adv = log2_qrom_expression(profile)
        print(
            f"{profile.name}: illustrative log2 bound = {log2_adv:.2f}; "
            f"this is not a proven unlinkability advantage"
        )

    print("\n--- Field-extension quotient term (one term only) ---")
    log2_field = 5 * math.log2(P_BABYBEAR)
    log2_eps = math.log2(3 * 260) - log2_field
    print(f"BabyBear log2(p^5) = {log2_field:.4f}")
    print(
        f"If degree=3 and trace height=260 apply, the isolated "
        f"field-size term is approximately 2^{log2_eps:.2f}."
    )
    print("This is not the composite STARK / Fiat-Shamir / quantum soundness bound.")

    print("\n--- FRI scenario arithmetic only ---")
    n_queries = 86
    log2_fri_scenario = -3.0 * n_queries / 2.0
    print(
        f"Under the assumed heuristic formula (1/8)^(N/2), N={n_queries} gives "
        f"2^{log2_fri_scenario:.1f}."
    )
    print("No claim is made that a selected Plonky3 backend attains this bound.")

    print("\n--- Byte accounting for unverified projections ---")
    baseline_bytes = 54_815
    layer1_profile1_bytes = baseline_bytes + 6 * 256 * 36 // 8
    layer1_profile2_bytes = baseline_bytes + 7 * 256 * 36 // 8
    layer2_bytes = 59_744
    profile1_total = layer1_profile1_bytes + layer2_bytes
    profile2_total = layer1_profile2_bytes + layer2_bytes
    expected = (
        layer1_profile1_bytes == 61_727
        and layer1_profile2_bytes == 62_879
        and profile1_total == 121_471
        and profile2_total == 122_623
    )
    print(
        f"Profile 1 arithmetic: {profile1_total} bytes = "
        f"{profile1_total / 1024:.2f} KiB"
    )
    print(
        f"Profile 2 arithmetic: {profile2_total} bytes = "
        f"{profile2_total / 1024:.2f} KiB"
    )
    print("All these component sizes remain assumptions, not measured proofs.")
    ok &= expected

    print("\n" + "=" * 76)
    if ok:
        print("NUMERIC SANITY CHECKS PASSED.")
    else:
        print("NUMERIC SANITY CHECKS FAILED.")
    print("CRYPTOGRAPHIC SECURITY IS NOT EVALUATED BY THIS SCRIPT.")
    print("No Module-SIS/Core-SVP security claim, AIR proof, ZK claim, or QROM theorem")
    print("is validated here. Those require concrete schemes, reductions, and tools.")
    print("=" * 76)
    return ok


def main() -> int:
    return 0 if numeric_checks() else 1


if __name__ == "__main__":
    sys.exit(main())
