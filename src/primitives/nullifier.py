"""
0PSP — Post-Quantum Private Spend Primitive
src/primitives/nullifier.py

Deterministic nullifier construction for double-spend prevention.

The nullifier nul = PRF_{sk}(coin_id) serves two purposes:
  1. Reveals if the same coin is spent twice (collision = double-spend)
  2. Hides the spender's identity (PRF output is pseudorandom)

CONSTRUCTION:
  We use a simplified PRF based on the BPR (Banerjee-Peikert-Rosen) scheme,
  which is secure under Learning With Rounding (LWR).

  LWR-PRF: f_s(x) = ⌊ A·s·x / p ⌋ mod p
  where A is a public matrix, s is the secret, x is the input.

  For research purposes, we use SHAKE-256(sk_bytes || coin_id) as a
  placeholder PRF. A production implementation must use a provably secure
  lattice-based PRF.

References:
  - Banerjee, Peikert, Rosen (2012): "Pseudorandom Functions and Lattices"
  - Boneh et al. (2013): "Key Homomorphic PRFs and Their Applications"
  - FIPS 202 (SHA-3 / SHAKE-256)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from ..core.params import Params
from ..core.ring import ModuleVec


# ---------------------------------------------------------------------------
# Nullifier types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CoinId:
    """
    Unique identifier for a coin / UTXO.

    In a real spend protocol, this would be derived from the commitment
    opening (note randomness + value + asset type). For research purposes,
    it's a raw bytes identifier.
    """
    data: bytes

    def __repr__(self) -> str:
        return f"CoinId({self.data.hex()[:16]}…)"


@dataclass(frozen=True)
class Nullifier:
    """
    A 32-byte nullifier value.

    Publishing a nullifier on a ledger marks a coin as spent without
    revealing which coin or who spent it.

    Properties:
      - Deterministic: same (sk, coin_id) → same nullifier
      - Collision-resistant: different coin_ids → different nullifiers
      - Spend-hiding: nullifier is computationally indistinguishable
        from a random value without knowledge of sk
    """
    value: bytes  # 32 bytes

    def __post_init__(self) -> None:
        assert len(self.value) == 32, "Nullifier must be 32 bytes"

    def __repr__(self) -> str:
        return f"Nullifier({self.value.hex()[:16]}…)"


# ---------------------------------------------------------------------------
# Nullifier computation
# ---------------------------------------------------------------------------

def _secret_to_bytes(secret: ModuleVec) -> bytes:
    """
    Canonical serialization of a module vector for PRF input.

    Each coefficient is serialized as a 3-byte little-endian integer
    (sufficient for q < 2^24).
    """
    parts = []
    for ring_elem in secret.elems:
        for coeff in ring_elem.coeffs:
            # Store as 3 bytes (sufficient for q ≈ 2^23)
            parts.append(struct.pack("<I", int(coeff) % (1 << 24))[:3])
    return b"".join(parts)


def compute_nullifier(secret: ModuleVec, coin_id: CoinId) -> Nullifier:
    """
    Compute the deterministic nullifier for a coin.

    nul = SHAKE-256(domain || secret_bytes || coin_id.data)[:32]

    This is a PLACEHOLDER PRF. In a production 0PSP implementation, this
    must be replaced with a lattice-based PRF (e.g., BPR-PRF under LWR)
    to enable formal security reductions.

    For the research phase, SHAKE-256 provides:
    - Determinism: same inputs → same output
    - Collision resistance: 128-bit second-preimage resistance
    - Pseudorandomness: assumed under random oracle model

    Parameters
    ----------
    secret : ModuleVec
        The secret share (or reconstructed secret) used for nullification.
        In a threshold setting, all shares must yield the same nullifier.
    coin_id : CoinId
        The unique coin identifier.

    Returns
    -------
    Nullifier
        A 32-byte deterministic nullifier.

    Notes
    -----
    For threshold compatibility: the nullifier must be computable by a
    single share holder (not requiring secret reconstruction). This means
    either:
    (a) The PRF is key-homomorphic: nul = PRF_{s₁}(x) ⊕ PRF_{s₂}(x) ⊕ ...
    (b) The nullifier is derived from a public attribute of the coin
        (like a commitment opening) rather than the secret key directly.

    Option (a) is the BKW key-homomorphic PRF approach (Boneh et al. 2013).
    Option (b) is closer to Zcash's design.
    Both are open research targets for 0PSP's Phase 2.
    """
    domain_sep = b"0PSP-NULLIFIER-v0:"
    sk_bytes = _secret_to_bytes(secret)

    h = hashlib.shake_256()
    h.update(domain_sep)
    h.update(sk_bytes)
    h.update(coin_id.data)
    return Nullifier(value=h.digest(32))


def verify_nullifier_consistency(nullifier: Nullifier, secret: ModuleVec,
                                  coin_id: CoinId) -> bool:
    """
    Check that a nullifier was computed correctly.

    Used during verification: the ledger checks that the published
    nullifier matches a fresh computation (or a ZK proof thereof).

    In the full 0PSP scheme, this would be proven in zero-knowledge:
    "I know a secret sk such that Nullify(sk, coin_id) = nul"
    without revealing sk.
    """
    expected = compute_nullifier(secret, coin_id)
    return expected.value == nullifier.value


def detect_double_spend(nullifier1: Nullifier, nullifier2: Nullifier) -> bool:
    """
    Detect whether two spend transactions share a nullifier (= double spend).

    A ledger maintains a set of seen nullifiers. Before accepting a new
    spend, it checks: is nul already in the spent set?

    Returns True if nullifiers are equal (double-spend detected).
    """
    return nullifier1.value == nullifier2.value


# ---------------------------------------------------------------------------
# Nullifier set (simple research implementation)
# ---------------------------------------------------------------------------

class NullifierSet:
    """
    Maintains a set of published nullifiers.

    In a production blockchain, this would be a Merkle tree or a
    zero-knowledge membership proof structure. For research purposes,
    this is a simple hash set.
    """

    def __init__(self) -> None:
        self._spent: set[bytes] = set()

    def add(self, nul: Nullifier) -> None:
        """Mark a nullifier as spent."""
        self._spent.add(nul.value)

    def is_spent(self, nul: Nullifier) -> bool:
        """Check if a coin has already been spent."""
        return nul.value in self._spent

    def try_spend(self, nul: Nullifier) -> bool:
        """
        Attempt to spend a coin.

        Returns True if this is the first spend (success).
        Returns False if the nullifier was already seen (double-spend).
        """
        if self.is_spent(nul):
            return False
        self.add(nul)
        return True

    def __len__(self) -> int:
        return len(self._spent)

    def __repr__(self) -> str:
        return f"NullifierSet(spent={len(self._spent)})"
