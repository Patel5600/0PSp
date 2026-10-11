#!/usr/bin/env python3
"""Arithmetic consistency checks for 0PSP Phase 1 claims.

This script does not validate a cryptographic construction, a commitment,
a lattice reduction, a QROM theorem, a STARK AIR, or zero knowledge.
It only recomputes the numerical identities documented in
docs/audit/chp3-mathematical-review.md.
"""
from __future__ import annotations

import math

Q_LOTRS = 2**43 - 67
QHAT_LOTRS = 2**35 - 451
P_BABYBEAR = 2**31 - 2**27 + 1
W = 2**14


def log2_tail_bound() -> float:
    return math.log2(3584 * 2 * math.exp(-(14**2) / 2))


def log2_conditional_qrom_bound(h: int, log2_queries: int) -> float:
    # log2(2*pi^2*(q_H+1)^2 / 2^h), approximating q_H+1 by q_H.
    return math.log2(2 * math.pi**2) + 2 * log2_queries - h


def main() -> int:
    assert Q_LOTRS == 8_796_093_022_141
    assert QHAT_LOTRS == 34_359_737_917
    assert P_BABYBEAR == 2_013_265_921
    assert Q_LOTRS.bit_length() == 43
    assert QHAT_LOTRS.bit_length() == 35

    six_vectors_36 = 6 * 256 * 36 // 8
    six_vectors_43 = 6 * 256 * 43 // 8
    assert six_vectors_36 == 6_912
    assert six_vectors_43 == 8_256

    residual_bound = W + 3 * W**2 + 2**16 + (2**16) * W
    assert residual_bound == 1_879_130_112
    assert residual_bound < P_BABYBEAR

    tail_log2 = log2_tail_bound()
    assert tail_log2 < -128

    path32 = 74 * 8 * 32
    path48 = 74 * 8 * 48
    assert path32 == 18_944
    assert path48 == 28_416
    assert path48 - path32 == 9_472

    qrom256 = log2_conditional_qrom_bound(256, 64)
    qrom288 = log2_conditional_qrom_bound(288, 64)
    assert -124 < qrom256 < -123
    assert -156 < qrom288 < -155

    print("0PSP CHP3 arithmetic consistency checks")
    print("PASS: LoTRS q/q-hat and BabyBear identities")
    print(f"36-bit six-vector raw packing: {six_vectors_36} bytes = {six_vectors_36/1024:.4f} KiB")
    print(f"43-bit six-vector raw packing: {six_vectors_43} bytes = {six_vectors_43/1024:.4f} KiB")
    print(f"BabyBear residual magnitude bound: {residual_bound} < {P_BABYBEAR}")
    print(f"14-sigma union-tail log2 bound: {tail_log2:.3f}")
    print(f"74x8 Merkle path at 32 bytes/digest: {path32} bytes = {path32/1024:.4f} KiB")
    print(f"74x8 Merkle path at 48 bytes/digest: {path48} bytes = {path48/1024:.4f} KiB")
    print(f"Conditional QROM arithmetic, h=256, q_H=2^64: 2^{qrom256:.3f}")
    print(f"Conditional QROM arithmetic, h=288, q_H=2^64: 2^{qrom288:.3f}")
    print("NOTE: QROM values are conditional arithmetic, not a protocol theorem.")
    print("NOTE: No cryptographic security or end-to-end proof is validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
