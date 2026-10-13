#!/usr/bin/env python3
"""Model the dense theta_ allocation in SmallWood Python's R1CS-to-PACS adapter.

Pinned source reviewed for this model:
https://github.com/CryptoExperts/smallwood-python/blob/28c269c8a19838030d0cfc48ebb8a61a110302c3/smallwood/pacs/constraints/pacs_r1cs.py

This does not benchmark or reject the SmallWood proof system generally. It models
only the allocation pattern in PACSFromR1CS.get_theta_ at that source revision.
"""
from __future__ import annotations

import argparse
from math import ceil


def estimate_dense_theta_storage(
    *,
    constraints: int,
    variables: int,
    batch_columns: int,
    primary_inputs: int = 0,
    pointer_bytes: int = 8,
) -> dict[str, int | float]:
    """Return dense matrix slots and pointer-storage floor for PACSFromR1CS.

    For every R1CS equation, get_theta_ allocates 3 matrices, each of shape
    (ceil(variables / batch_columns) + 2, batch_columns). For every primary
    input it adds two further rows of batch_columns entries.

    pointer_bytes accounts only for the references in Python lists. It excludes
    list headers, Sage field-element objects, interpreter overhead, equation and
    witness data, and all prover memory. It is a lower bound for a 64-bit
    Python/Sage process under this materialization strategy.
    """
    if constraints <= 0:
        raise ValueError("constraints must be positive")
    if variables <= 0:
        raise ValueError("variables must be positive")
    if batch_columns <= 0:
        raise ValueError("batch_columns must be positive")
    if not 0 <= primary_inputs <= variables:
        raise ValueError("primary_inputs must be in 0..variables")
    if pointer_bytes <= 0:
        raise ValueError("pointer_bytes must be positive")

    witness_rows = ceil(variables / batch_columns)
    equation_slots = (
        3 * constraints * (witness_rows + 2) * batch_columns
    )
    primary_input_slots = 2 * primary_inputs * batch_columns
    total_slots = equation_slots + primary_input_slots
    pointer_floor_bytes = total_slots * pointer_bytes
    gib = pointer_floor_bytes / (1024**3)
    return {
        "witness_rows": witness_rows,
        "equation_matrix_slots": equation_slots,
        "primary_input_matrix_slots": primary_input_slots,
        "total_matrix_slots": total_slots,
        "pointer_storage_floor_bytes": pointer_floor_bytes,
        "pointer_storage_floor_gib": gib,
        "pointer_storage_floor_tib": gib / 1024,
    }


def _positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--constraints", type=_positive_int, default=307200)
    parser.add_argument("--variables", type=_positive_int, default=310000)
    parser.add_argument("--batch-columns", type=_positive_int, default=256)
    parser.add_argument("--primary-inputs", type=int, default=0)
    parser.add_argument("--pointer-bytes", type=_positive_int, default=8)
    args = parser.parse_args()
    try:
        estimate = estimate_dense_theta_storage(
            constraints=args.constraints,
            variables=args.variables,
            batch_columns=args.batch_columns,
            primary_inputs=args.primary_inputs,
            pointer_bytes=args.pointer_bytes,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print("Pinned SmallWood Python PACSFromR1CS dense-allocation model")
    print(f"Constraints: {args.constraints:,}; variables: {args.variables:,}; batch columns: {args.batch_columns:,}")
    print(f"Witness rows: {estimate['witness_rows']:,}")
    print(f"Dense matrix slots: {estimate['total_matrix_slots']:,}")
    print(f"List-pointer storage floor: {estimate['pointer_storage_floor_bytes']:,} bytes")
    print(f"List-pointer storage floor: {estimate['pointer_storage_floor_gib']:.3f} GiB")
    print(f"List-pointer storage floor: {estimate['pointer_storage_floor_tib']:.3f} TiB")
    print("EXCLUDED: list headers, Sage element objects, equations, witnesses, proof structures, and runtime overhead.")
    print("This is a source-derived allocation model, not a process-memory measurement.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
