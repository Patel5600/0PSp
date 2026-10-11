"""0PSP functional nullifier interface.

Deterministic byte-level nullifier generation and replay bookkeeping only.
This module does NOT establish collision resistance, quantum security,
anonymity, commitment binding, or proof soundness.

Candidate: SHAKE256(domain || version || Encode(coin_id) || r_nf), 48 bytes.
The per-coin secret is 36 bytes (288 bits) to leave margin for a stated
quantum-oracle query budget; the exact protocol theorem remains unproved.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass

COIN_ID_BYTES = 32
NULLIFIER_SECRET_BYTES = 36
NULLIFIER_BYTES = 48
DOMAIN_NULLIFIER = b"0PSP-NULLIFIER-v1-SHAKE256"
PROTOCOL_VERSION = b"\x01"


@dataclass(frozen=True)
class CoinId:
    """Canonical 32-byte coin identifier; keep private until proved in ZK."""
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) != COIN_ID_BYTES:
            raise ValueError(f"coin_id must be exactly {COIN_ID_BYTES} bytes")

    def __repr__(self) -> str:
        # A coin ID may be a hidden witness. Do not leak a prefix via debug logs.
        return "CoinId(<redacted>)"


@dataclass(frozen=True)
class NullifierSecret:
    """Per-coin 288-bit secret, distinct from commitment opening randomness."""
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) != NULLIFIER_SECRET_BYTES:
            raise ValueError(f"r_nf must be exactly {NULLIFIER_SECRET_BYTES} bytes")

    def __repr__(self) -> str:
        return "NullifierSecret(<redacted>)"


@dataclass(frozen=True)
class Nullifier:
    """Canonical 48-byte public nullifier."""
    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes) or len(self.value) != NULLIFIER_BYTES:
            raise ValueError(f"nullifier must be exactly {NULLIFIER_BYTES} bytes")

    def __repr__(self) -> str:
        return f"Nullifier({self.value.hex()[:16]}…)"


def compute_nullifier(coin_id: CoinId, r_nf: NullifierSecret) -> Nullifier:
    """Compute deterministic nullifier; this does not validate a coin."""
    if not isinstance(coin_id, CoinId):
        raise TypeError("coin_id must be a CoinId")
    if not isinstance(r_nf, NullifierSecret):
        raise TypeError("r_nf must be a NullifierSecret")
    h = hashlib.shake_256()
    h.update(DOMAIN_NULLIFIER)
    h.update(PROTOCOL_VERSION)
    h.update(len(coin_id.data).to_bytes(2, "little"))
    h.update(coin_id.data)
    h.update(len(r_nf.data).to_bytes(2, "little"))
    h.update(r_nf.data)
    return Nullifier(h.digest(NULLIFIER_BYTES))


def verify_nullifier_consistency(
    nullifier: Nullifier, coin_id: CoinId, r_nf: NullifierSecret
) -> bool:
    """Functional consistency check only; not a ZK proof verifier."""
    return hmac.compare_digest(
        compute_nullifier(coin_id, r_nf).value, nullifier.value
    )


class NullifierSet:
    """Thread-safe in-memory replay model; not a durable consensus ledger."""
    def __init__(self) -> None:
        self._spent: set[bytes] = set()
        self._lock = threading.Lock()

    def add(self, nullifier: Nullifier) -> None:
        with self._lock:
            self._spent.add(nullifier.value)

    def is_spent(self, nullifier: Nullifier) -> bool:
        with self._lock:
            return nullifier.value in self._spent

    def try_spend(self, nullifier: Nullifier) -> bool:
        """Atomically accept first use and reject repeats."""
        with self._lock:
            if nullifier.value in self._spent:
                return False
            self._spent.add(nullifier.value)
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._spent)
