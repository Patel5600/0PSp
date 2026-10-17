#!/usr/bin/env python3
"""Fail-closed audit of the pinned OpenVM candidate's security claims.

The previous version invented a degree-5 extension, fixed per-query FRI entropy,
and additive error terms that were not derived from the pinned OpenVM backend.
Those outputs must not be used as a post-quantum security proof. This replacement
reports only facts grounded in the exact source revision and refuses the gate
because a composed >=128-bit post-quantum bound and end-to-end witness hiding
have not been established for the candidate.
"""
from __future__ import annotations

import math
import sys
from dataclasses import dataclass

PINNED_OPENVM_REV = "59a69b8b0cbee7011ac978e4cc07707ee3681944"
BABYBEAR_P = 2_013_265_921
DEFAULT_EXTENSION_DEGREE = 4
UPSTREAM_DECLARED_RBR_SOUNDNESS_BITS = 100
REQUIRED_COMPOSITE_PQ_BITS = 128


@dataclass(frozen=True, slots=True)
class SoundnessReport:
    """Observed upstream facts; unknown security is deliberately not guessed."""

    backend_revision: str
    base_field_order: int
    extension_degree: int
    challenge_field_bits_upper_bound: float
    upstream_declared_rbr_soundness_bits: int
    composite_pq_security_bits: None
    end_to_end_witness_hiding_established: bool
    required_composite_pq_bits: int
    meets_128bit_pq_target: bool
    status: str
    blockers: tuple[str, ...]


def calculate_composite_soundness() -> SoundnessReport:
    """Return the evidence status of the pinned profile, not a fabricated estimate.

    OpenVM's pinned upstream `app_params_with_100_bits_security` targets 100-bit
    proven round-by-round (RBR) security under documented classical assumptions.
    That upstream declaration is not an end-to-end >=128-bit post-quantum bound.
    The exact candidate's composed PQ security is therefore recorded as unknown.
    """
    blockers = (
        "The pinned upstream constructor targets 100-bit RBR security, not the required 128-bit post-quantum composite bound.",
        "No independently reviewed quantum soundness reduction has been supplied for this exact backend/profile.",
        "End-to-end witness hiding for the deployed OpenVM guest/proof configuration has not been established.",
        "The candidate relation and local SQLite state policy do not authenticate external consensus finality or reorg recovery.",
    )
    return SoundnessReport(
        backend_revision=PINNED_OPENVM_REV,
        base_field_order=BABYBEAR_P,
        extension_degree=DEFAULT_EXTENSION_DEGREE,
        challenge_field_bits_upper_bound=round(
            DEFAULT_EXTENSION_DEGREE * math.log2(BABYBEAR_P), 3
        ),
        upstream_declared_rbr_soundness_bits=UPSTREAM_DECLARED_RBR_SOUNDNESS_BITS,
        composite_pq_security_bits=None,
        end_to_end_witness_hiding_established=False,
        required_composite_pq_bits=REQUIRED_COMPOSITE_PQ_BITS,
        meets_128bit_pq_target=False,
        status="NO-GO",
        blockers=blockers,
    )


def main() -> int:
    report = calculate_composite_soundness()
    print("0PSP pinned OpenVM security-claim audit")
    print(f"OpenVM revision:                 {report.backend_revision}")
    print(f"Base field order:                {report.base_field_order}")
    print(f"Challenge field:                 BabyBear^{report.extension_degree}")
    print(
        "Ideal challenge-field bit size:  "
        f"{report.challenge_field_bits_upper_bound:.3f} bits (not a proof-system bound)"
    )
    print(
        "Upstream declared security:      "
        f"{report.upstream_declared_rbr_soundness_bits} bits RBR (not a PQ composite claim)"
    )
    print("Composed post-quantum security:  UNKNOWN")
    print("End-to-end witness hiding:       NOT ESTABLISHED")
    print(f"Required composite PQ target:    >= {report.required_composite_pq_bits} bits")
    print(f"Release status:                  {report.status}")
    for blocker in report.blockers:
        print(f"BLOCKER: {blocker}")
    print("FAIL CLOSED: this script does not manufacture a soundness result from assumed parameters.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
