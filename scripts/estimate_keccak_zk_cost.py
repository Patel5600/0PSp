#!/usr/bin/env python3
"""Conservative static cost model for a bit-sliced SHAKE256-384 spend relation.

This is an estimator, not a proof generator, backend benchmark, or security claim.
It counts the 24 Keccak-f[1600] rounds using a straightforward prime-field mapping:
XOR(a, b) = a + b - 2ab for Boolean bits, AND(a, b) = ab.
It deliberately excludes proof-system overhead and all non-SHAKE predicates.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Iterable

SHAKE256_RATE_BYTES = 136
KECCAK_ROUNDS = 24
THETA_XOR_PER_ROUND = 3_200
CHI_AND_PER_ROUND = 1_600
CHI_XOR_PER_ROUND = 1_600
MULTIPLICATION_EQUIVALENTS_PER_ROUND = (
    THETA_XOR_PER_ROUND + CHI_AND_PER_ROUND + CHI_XOR_PER_ROUND
)
MULTIPLICATION_EQUIVALENTS_PER_PERMUTATION = (
    KECCAK_ROUNDS * MULTIPLICATION_EQUIVALENTS_PER_ROUND
)
NULLIFIER_V2_PREIMAGE_BYTES = 149
TREE_DEPTH = 63
TX_FIELDS_DOMAIN_BYTES = len(b"0PSP-TX-FIELDS-v2-SHAKE256")
TX_DIGEST_DOMAIN_BYTES = len(b"0PSP-TX-DIGEST-v2-SHAKE256")
COMMIT_V2_DOMAIN_BYTES = len(b"0PSP-COIN-COMMIT-v2-SHAKE256")
TREE_LEAF_DOMAIN_BYTES = len(b"0PSP-COMMITMENT-LEAF-v1-SHAKE256")
TREE_NODE_DOMAIN_BYTES = len(b"0PSP-COMMITMENT-NODE-v1-SHAKE256")
MAX_OUTPUTS = 1024


@dataclass(frozen=True)
class HashCost:
    name: str
    preimage_bytes: int
    count: int = 1

    @property
    def permutations_per_hash(self) -> int:
        if self.preimage_bytes < 0:
            raise ValueError("preimage length cannot be negative")
        # SHAKE uses a mandatory padding block when the message ends exactly
        # at the 136-byte rate boundary.
        return self.preimage_bytes // SHAKE256_RATE_BYTES + 1

    @property
    def absorb_xor_equivalents_upper_bound(self) -> int:
        # The first block is XORed into the all-zero initial state and needs no
        # multiplication. Count all later message bits as dynamic; this
        # overestimates where domains/lengths/padding are fixed constants.
        return 8 * max(0, self.preimage_bytes - SHAKE256_RATE_BYTES)


def commitment_v2_preimage_bytes(params_id_bytes: int, public_key_bytes: int) -> int:
    if not 1 <= params_id_bytes < 2**16:
        raise ValueError("params_id_bytes must be in 1..65535")
    if not 1 <= public_key_bytes < 2**32:
        raise ValueError("public_key_bytes must be in 1..2^32-1")
    # Domain, version, params length+bytes, public-key length+bytes, u64 value,
    # and length-prefixed namespace[48], coin_id[32], r_nf[36], rho[36].
    return (
        COMMIT_V2_DOMAIN_BYTES + 1
        + 2 + params_id_bytes
        + 4 + public_key_bytes
        + 8
        + 2 + 48
        + 2 + 32
        + 2 + 36
        + 2 + 36
    )


def tx_fields_v2_bytes(params_id_bytes: int, policy_id_bytes: int, outputs: int) -> int:
    if not 1 <= params_id_bytes < 2**16:
        raise ValueError("params_id_bytes must be in 1..65535")
    if not 1 <= policy_id_bytes < 2**16:
        raise ValueError("policy_id_bytes must be in 1..65535")
    if not 1 <= outputs <= MAX_OUTPUTS:
        raise ValueError(f"outputs must be in 1..{MAX_OUTPUTS}")
    # Four 48-byte fixed fields: namespace, commitment root, nullifier, state head.
    return (
        TX_FIELDS_DOMAIN_BYTES + 1
        + 2 + params_id_bytes
        + 48 * 4
        + 2 + policy_id_bytes
        + 8 + 4 + 48 * outputs
    )


def build_hash_costs(
    *,
    params_id_bytes: int = len(b"params-v2-test-2026"),
    policy_id_bytes: int = len(b"policy-self-spend-v1"),
    input_public_key_bytes: int = 1024,
    output_public_key_bytes: int = 1024,
    outputs: int = 1,
) -> tuple[HashCost, ...]:
    if not 1 <= outputs <= MAX_OUTPUTS:
        raise ValueError(f"outputs must be in 1..{MAX_OUTPUTS}")
    commit_in = commitment_v2_preimage_bytes(params_id_bytes, input_public_key_bytes)
    commit_out = commitment_v2_preimage_bytes(params_id_bytes, output_public_key_bytes)
    fields_bytes = tx_fields_v2_bytes(params_id_bytes, policy_id_bytes, outputs)
    digest_preimage_bytes = (
        TX_DIGEST_DOMAIN_BYTES + 1 + 4 + fields_bytes
    )
    return (
        HashCost("input_commitment", commit_in),
        HashCost("merkle_leaf", TREE_LEAF_DOMAIN_BYTES + 1 + 48 + 8 + 48),
        HashCost("merkle_node", TREE_NODE_DOMAIN_BYTES + 1 + 4 + 48 + 48 + 48, TREE_DEPTH),
        HashCost("nullifier_v2", NULLIFIER_V2_PREIMAGE_BYTES),
        HashCost("transaction_digest_v2", digest_preimage_bytes),
        HashCost("output_commitment_v2", commit_out, outputs),
    )


def estimate_spend(**kwargs: int) -> dict[str, int | tuple[tuple[str, int, int, int], ...]]:
    costs = build_hash_costs(**kwargs)
    detail: list[tuple[str, int, int, int]] = []
    total_calls = 0
    total_permutations = 0
    absorb_equivalents = 0
    for item in costs:
        permutations = item.permutations_per_hash
        total_calls += item.count
        total_permutations += permutations * item.count
        absorb_equivalents += item.absorb_xor_equivalents_upper_bound * item.count
        detail.append((
            item.name,
            item.preimage_bytes,
            item.count,
            permutations,
        ))
    keccak_equivalents = (
        total_permutations * MULTIPLICATION_EQUIVALENTS_PER_PERMUTATION
    )
    return {
        "hash_calls": total_calls,
        "keccak_f_permutations": total_permutations,
        "keccak_f_multiplication_equivalents": keccak_equivalents,
        "absorb_xor_multiplication_equivalents_upper_bound": absorb_equivalents,
        "modeled_multiplication_equivalents": keccak_equivalents + absorb_equivalents,
        "detail": tuple(detail),
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
    parser.add_argument("--params-id-bytes", type=_positive_int, default=len(b"params-v2-test-2026"))
    parser.add_argument("--policy-id-bytes", type=_positive_int, default=len(b"policy-self-spend-v1"))
    parser.add_argument("--input-public-key-bytes", type=_positive_int, default=1024)
    parser.add_argument("--output-public-key-bytes", type=_positive_int, default=1024)
    args = parser.parse_args(argv)
    try:
        estimate = estimate_spend(
            outputs=args.outputs,
            params_id_bytes=args.params_id_bytes,
            policy_id_bytes=args.policy_id_bytes,
            input_public_key_bytes=args.input_public_key_bytes,
            output_public_key_bytes=args.output_public_key_bytes,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print("0PSP SHAKE256-384 spend cost model (NOT a backend benchmark)")
    print(f"Keccak-f multiplication-equivalents per permutation: {MULTIPLICATION_EQUIVALENTS_PER_PERMUTATION:,}")
    print(f"SHAKE calls modeled: {estimate['hash_calls']:,}")
    print(f"Keccak-f permutations modeled: {estimate['keccak_f_permutations']:,}")
    print(f"Keccak-f multiplication-equivalents: {estimate['keccak_f_multiplication_equivalents']:,}")
    print(f"Absorb XOR equivalents (conservative upper bound): {estimate['absorb_xor_multiplication_equivalents_upper_bound']:,}")
    print(f"Total modeled multiplication-equivalents: {estimate['modeled_multiplication_equivalents']:,}")
    print("\nPer-component (name, bytes, count, permutations/hash):")
    for row in estimate["detail"]:
        print(f"  {row[0]}: {row[1]} bytes x {row[2]}; {row[3]} permutation(s)/hash")
    print("\nEXCLUDED: witness byte-range constraints, output-identity derivation, Ringtail verification,")
    print("value-conservation/range gadgets, public-input binding, and all proof-system overhead.")
    print("Output identity and authorization are unresolved. Key sizes are scenario inputs, not frozen parameters.")
    print("Do not treat this estimate as an actual constraint count, proof size, runtime, or security result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
