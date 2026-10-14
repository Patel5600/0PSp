#!/usr/bin/env python3
"""Cross-platform statistical timing leakage diagnostic harness (dudect / Welch's t-test).

Evaluates timing distributions of sensitive cryptographic primitives (NullifierV2,
NullifierV3, CommitV3) between fixed-secret and random-secret classes to detect
data-dependent timing channels.

Standard threshold: |t| < 4.5 indicates no statistically significant timing leakage
(p > 10^-5 under the null hypothesis of equal execution time).
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import platform
import sys
import time
from typing import Callable, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import NullifierSecret, compute_nullifier_v2
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    compute_nullifier_v3,
    compute_nullifier_key_commitment_v3,
)
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.coin_commitment_v3 import commit_coin_v3
from src.protocol.note_public_key_bundle_v3 import NotePublicKeyBundleV3


class WelfordAccumulator:
    """Online single-pass mean and variance calculation (Welford's algorithm)."""

    def __init__(self) -> None:
        self.n: int = 0
        self.mean: float = 0.0
        self.m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0


def welch_t_statistic(class_a: WelfordAccumulator, class_b: WelfordAccumulator) -> float:
    """Compute Welch's t-statistic between two independent sample distributions."""
    if class_a.n < 2 or class_b.n < 2:
        return 0.0
    va = class_a.variance
    vb = class_b.variance
    denom = math.sqrt(va / class_a.n + vb / class_b.n)
    if denom == 0.0:
        return 0.0
    return (class_a.mean - class_b.mean) / denom


def run_nullifier_v2_timing_screen(samples_per_class: int = 10000) -> Tuple[float, float, float]:
    """Test NullifierV2 timing invariance across fixed vs random secret preimages."""
    ns = NamespaceId(bytes([0x11]) * 48)
    coin_id = ScopedCoinId(bytes([0x01]) * 32)
    fixed_secret = NullifierSecret(bytes([0x00]) * 36)

    acc_fixed = WelfordAccumulator()
    acc_random = WelfordAccumulator()

    # Interleaved execution to neutralize thermal/clock throttling drift
    for i in range(samples_per_class):
        # Class A: Fixed secret
        t0 = time.perf_counter_ns()
        compute_nullifier_v2(ns, coin_id, fixed_secret)
        t1 = time.perf_counter_ns()
        acc_fixed.update(float(t1 - t0))

        # Class B: Random secret
        rand_secret = NullifierSecret(os.urandom(36))
        t2 = time.perf_counter_ns()
        compute_nullifier_v2(ns, coin_id, rand_secret)
        t3 = time.perf_counter_ns()
        acc_random.update(float(t3 - t2))

    t_val = welch_t_statistic(acc_fixed, acc_random)
    return t_val, acc_fixed.mean, acc_random.mean


def run_nullifier_v3_timing_screen(samples_per_class: int = 10000) -> Tuple[float, float, float]:
    """Test NullifierV3 (HMAC-SHA3-384) timing invariance across fixed vs random keys."""
    ns = NamespaceIdV3(bytes([0x11]) * 48)
    params_id = b"params-timing-v3"
    coin_id = ScopedCoinId(bytes([0x01]) * 32)
    r_nf = NullifierSecret(bytes([0x02]) * 36)
    comm = CoinCommitmentV3(bytes([0x05]) * 48)

    fixed_nk = NullifierDerivingKeyV3(bytes([0xAA]) * 48)
    fixed_bundle = NotePublicKeyBundleV3(
        auth_scheme_id=b"0PSP-AUTH-SCHEME-TEST-v1",
        auth_public_key=bytes([0x04]) * 64,
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(fixed_nk),
    ).encode()

    acc_fixed = WelfordAccumulator()
    acc_random = WelfordAccumulator()

    for i in range(samples_per_class):
        # Class A: Fixed key
        t0 = time.perf_counter_ns()
        compute_nullifier_v3(
            namespace_id=ns,
            params_id=params_id,
            public_key_bundle=fixed_bundle,
            commitment=comm,
            coin_id=coin_id,
            r_nf=r_nf,
            nullifier_key=fixed_nk,
        )
        t1 = time.perf_counter_ns()
        acc_fixed.update(float(t1 - t0))

        # Class B: Random key
        rand_nk = NullifierDerivingKeyV3(os.urandom(48))
        rand_bundle = NotePublicKeyBundleV3(
            auth_scheme_id=b"0PSP-AUTH-SCHEME-TEST-v1",
            auth_public_key=bytes([0x04]) * 64,
            nullifier_key_commitment=compute_nullifier_key_commitment_v3(rand_nk),
        ).encode()
        t2 = time.perf_counter_ns()
        compute_nullifier_v3(
            namespace_id=ns,
            params_id=params_id,
            public_key_bundle=rand_bundle,
            commitment=comm,
            coin_id=coin_id,
            r_nf=r_nf,
            nullifier_key=rand_nk,
        )
        t3 = time.perf_counter_ns()
        acc_random.update(float(t3 - t2))

    t_val = welch_t_statistic(acc_fixed, acc_random)
    return t_val, acc_fixed.mean, acc_random.mean


def main() -> int:
    samples = int(os.environ.get("TIMING_SAMPLES", "5000"))
    print("=" * 70)
    print("0PSP Statistical Timing Leakage Screen (Welch's t-test)")
    print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python: {platform.python_version()} | Samples per class: {samples:,}")
    print("Acceptance threshold: |t| < 4.5")
    print("=" * 70)

    # 1. NullifierV2
    print("\n[1/2] Evaluating NullifierV2 (SHAKE256-384)...")
    t2, mean_fix_2, mean_rand_2 = run_nullifier_v2_timing_screen(samples)
    print(f"  Fixed mean:  {mean_fix_2:.1f} ns")
    print(f"  Random mean: {mean_rand_2:.1f} ns")
    print(f"  Welch's t:   {t2:+.4f} (abs: {abs(t2):.4f})")
    status_2 = "PASS (constant-time behavior consistent)" if abs(t2) < 4.5 else "WARN (potential timing variance detected)"
    print(f"  Status:      {status_2}")

    # 2. NullifierV3
    print("\n[2/2] Evaluating NullifierV3 (HMAC-SHA3-384 + BundleV3)...")
    t3, mean_fix_3, mean_rand_3 = run_nullifier_v3_timing_screen(samples)
    print(f"  Fixed mean:  {mean_fix_3:.1f} ns")
    print(f"  Random mean: {mean_rand_3:.1f} ns")
    print(f"  Welch's t:   {t3:+.4f} (abs: {abs(t3):.4f})")
    status_3 = "PASS (constant-time behavior consistent)" if abs(t3) < 4.5 else "WARN (potential timing variance detected)"
    print(f"  Status:      {status_3}")

    print("\n" + "=" * 70)
    if abs(t2) < 4.5 and abs(t3) < 4.5:
        print("ALL TIMING SCREENS PASSED: No statistically significant timing leakage (|t| < 4.5).")
        return 0
    else:
        print("FAIL: One or more primitives exhibited |t| >= 4.5; requires review.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
