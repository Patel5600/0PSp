#!/usr/bin/env python3
"""Estimate a bit-oriented SHAKE relation over a characteristic-two field.

Source for frozen V2 hash preimage sizes: scripts/estimate_keccak_zk_cost.py
This is a circuit-shape estimate, not a proof generator or a backend benchmark.
"""
from __future__ import annotations

import argparse
from typing import Iterable

from scripts.estimate_keccak_zk_cost import build_hash_costs, estimate_spend

KECCAK_ROUNDS = 24
KECCAK_LANES = 25
LANE_WIDTH_BITS = 64
CHI_ANDS_PER_ROUND = KECCAK_LANES * LANE_WIDTH_BITS
CHI_ROWS_PER_PERMUTATION = KECCAK_ROUNDS * CHI_ANDS_PER_ROUND
MAX_OUTPUTS = 1024


def binary_chi_output(a: int, b: int, c: int) -> int:
    """Reference bit function for a XOR ((NOT b) AND c)."""
    for value in (a, b, c):
        if value not in (0, 1):
            raise ValueError("chi inputs must be Boolean bits")
    return a ^ ((1 ^ b) & c)


def binary_chi_relation_holds(a: int, b: int, c: int, out: int) -> bool:
    """Check the GF(2) relation (1+b)*c = out+a."""
    if any(value not in (0, 1) for value in (a, b, c, out)):
        return False
    return (((1 ^ b) & c) == (out ^ a))


def estimate_binary_field_relation(**kwargs: int) -> dict[str, int]:
    """Count chi multiplication rows and a conservative bitness-row upper bound.

    In characteristic two, XOR is field addition and needs no nonlinear
    multiplication. The Keccak chi mapping can fuse one AND and the adjacent
    XOR into one R1CS row: (1+b)*c = out+a. This assumes all values are in
    the GF(2) subfield of the selected binary extension field GF(2^m).

    Every externally supplied source bit must be constrained to the base
    subfield by bit*(bit+1)=0. For an intentionally conservative bound, this
    model counts one bitness row for every bit in every frozen hash preimage,
    including repeated or derived bytes for which a real circuit can reuse
    an existing proof of bitness. It excludes source fields not represented
    in those preimages and all non-hash protocol predicates.
    """
    outputs = kwargs.get("outputs", 1)
    if not 1 <= outputs <= MAX_OUTPUTS:
        raise ValueError(f"outputs must be in 1..{MAX_OUTPUTS}")
    costs = build_hash_costs(**kwargs)
    total_permutations = sum(item.permutations_per_hash * item.count for item in costs)
    total_hash_calls = sum(item.count for item in costs)
    total_preimage_bytes = sum(item.preimage_bytes * item.count for item in costs)
    chi_rows = total_permutations * CHI_ROWS_PER_PERMUTATION
    bitness_upper_bound = total_preimage_bytes * 8
    return {
        "hash_calls": total_hash_calls,
        "keccak_f_permutations": total_permutations,
        "chi_rows_per_permutation": CHI_ROWS_PER_PERMUTATION,
        "keccak_chi_multiplication_rows": chi_rows,
        "hash_preimage_bytes_counted_for_bitness": total_preimage_bytes,
        "hash_preimage_bitness_rows_upper_bound": bitness_upper_bound,
        "modeled_keccak_relation_rows_upper_bound": chi_rows + bitness_upper_bound,
    }


def _positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outputs", type=_positive_int, default=1)
    parser.add_argument("--params-id-bytes", type=_positive_int, default=19)
    parser.add_argument("--policy-id-bytes", type=_positive_int, default=20)
    parser.add_argument("--input-public-key-bytes", type=_positive_int, default=1024)
    parser.add_argument("--output-public-key-bytes", type=_positive_int, default=1024)
    args = parser.parse_args(argv)
    try:
        estimate = estimate_binary_field_relation(
            outputs=args.outputs,
            params_id_bytes=args.params_id_bytes,
            policy_id_bytes=args.policy_id_bytes,
            input_public_key_bytes=args.input_public_key_bytes,
            output_public_key_bytes=args.output_public_key_bytes,
        )
        odd_field = estimate_spend(
            outputs=args.outputs,
            params_id_bytes=args.params_id_bytes,
            policy_id_bytes=args.policy_id_bytes,
            input_public_key_bytes=args.input_public_key_bytes,
            output_public_key_bytes=args.output_public_key_bytes,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print("0PSP binary-extension-field Keccak feasibility model")
    print("Field assumption: characteristic two; every source bit is in the GF(2) subfield")
    print(f"SHAKE calls: {estimate['hash_calls']:,}")
    print(f"Keccak-f permutations: {estimate['keccak_f_permutations']:,}")
    print(f"Chi rows per Keccak-f permutation: {estimate['chi_rows_per_permutation']:,}")
    print(f"Keccak chi multiplication rows: {estimate['keccak_chi_multiplication_rows']:,}")
    print(f"Preimage bytes counted for conservative bitness bound: {estimate['hash_preimage_bytes_counted_for_bitness']:,}")
    print(f"Bitness rows upper bound: {estimate['hash_preimage_bitness_rows_upper_bound']:,}")
    print(f"Modeled Keccak relation rows upper bound: {estimate['modeled_keccak_relation_rows_upper_bound']:,}")
    print(f"Odd-characteristic baseline (CHp4.21 multiplication-equivalents): {odd_field['modeled_multiplication_equivalents']:,}")
    print("EXCLUDED: Ringtail/key authorization, output identity, value/range constraints, public-input and byte-codec binding,")
    print("sparse R1CS matrix overhead, prover memory/time, transcript/ZK masking and all non-hash predicates.")
    print("This is not an implemented circuit, a proof, or a backend measurement.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
