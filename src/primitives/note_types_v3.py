"""Version-distinct V3 note commitment value type.

This module is dependency-free so both commitment and nullifier primitives can
share the type without creating a circular import.
"""
from __future__ import annotations

from dataclasses import dataclass

COMMITMENT_V3_BYTES = 48


@dataclass(frozen=True, slots=True)
class CoinCommitmentV3:
    """Canonical 48-byte V3 note commitment, not interchangeable with V2."""

    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes) or len(self.value) != COMMITMENT_V3_BYTES:
            raise ValueError(
                f"V3 commitment must be exactly {COMMITMENT_V3_BYTES} bytes"
            )

    def __repr__(self) -> str:
        return f"CoinCommitmentV3({self.value.hex()[:16]}…)"
