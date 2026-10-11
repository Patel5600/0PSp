"""
0PSP Phase 1 — Non-Cryptographic Validation Script
scripts/verify_nullifier_relation.py

Tests canonical encoding, functional determinism, 384-bit output length,
repeated-spend equality, and witness-substitution failure for the nullifier:
    ν = H_nf(domain_null || Encode(C_j) || Encode(r_nf)) ∈ {0,1}^384

NOTE: This script performs non-cryptographic validation of functional
invariants and data structures. It does NOT prove collision resistance,
zero knowledge, or quantum soundness.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass
from typing import Sequence

# Domain separator as specified in docs/theory/spend-relation-and-proof-binding.md
DOMAIN_NULLIFIER = b"0PSP-NULLIFIER-v1-SHAKE256"
NULLIFIER_BYTES = 48  # 384 bits = 48 bytes (for 128-bit quantum collision resistance)
SECRET_BYTES = 32     # 256 bits = 32 bytes (for 128-bit Grover preimage resistance)


@dataclass(frozen=True)
class SimulatedRingElem:
    """Mock polynomial element in R_q for testing canonical encoding."""
    coeffs: tuple[int, ...]
    q: int = 8_380_417

    def encode(self) -> bytes:
        """Canonical little-endian 32-bit integer encoding per coefficient."""
        return b"".join(struct.pack("<I", c % self.q) for c in self.coeffs)


@dataclass(frozen=True)
class SimulatedCoinCommitment:
    """Simulated coin commitment C ∈ R_q^k."""
    elems: tuple[SimulatedRingElem, ...]

    def encode(self) -> bytes:
        """Canonical encoding: length prefix + packed polynomial elements."""
        header = struct.pack("<I", len(self.elems))
        body = b"".join(e.encode() for e in self.elems)
        return header + body


def compute_nullifier(commitment: SimulatedCoinCommitment, r_nf: bytes) -> bytes:
    """
    Evaluate the deterministic 384-bit post-quantum nullifier:
        ν = SHAKE-256(domain || Encode(C) || Encode(r_nf), 48 bytes)
    """
    assert len(r_nf) == SECRET_BYTES, f"r_nf must be exactly {SECRET_BYTES} bytes"
    hasher = hashlib.shake_256()
    hasher.update(DOMAIN_NULLIFIER)
    hasher.update(commitment.encode())
    hasher.update(r_nf)
    return hasher.digest(NULLIFIER_BYTES)


def test_determinism_and_length():
    """Verify that repeated evaluation yields identical 384-bit nullifiers."""
    coeffs = tuple(range(256))
    poly = SimulatedRingElem(coeffs)
    coin_c = SimulatedCoinCommitment((poly, poly))
    r_nf = secrets.token_bytes(SECRET_BYTES)

    nu_1 = compute_nullifier(coin_c, r_nf)
    nu_2 = compute_nullifier(coin_c, r_nf)

    assert len(nu_1) == NULLIFIER_BYTES, f"Expected {NULLIFIER_BYTES} bytes, got {len(nu_1)}"
    assert nu_1 == nu_2, "Functional determinism failed: identical inputs must produce identical nullifiers"
    print(f"[PASS] Functional determinism & 384-bit length: nu = {nu_1.hex()[:32]}... ({len(nu_1)*8} bits)")


def test_witness_substitution_detection():
    """Verify that substituting a different coin or secret alters the nullifier."""
    coeffs_a = tuple(range(256))
    coeffs_b = tuple((x + 1) % 8_380_417 for x in range(256))

    poly_a = SimulatedRingElem(coeffs_a)
    poly_b = SimulatedRingElem(coeffs_b)

    coin_a = SimulatedCoinCommitment((poly_a, poly_a))
    coin_b = SimulatedCoinCommitment((poly_b, poly_b))

    r_nf_1 = secrets.token_bytes(SECRET_BYTES)
    r_nf_2 = secrets.token_bytes(SECRET_BYTES)

    nu_base = compute_nullifier(coin_a, r_nf_1)
    nu_diff_coin = compute_nullifier(coin_b, r_nf_1)
    nu_diff_secret = compute_nullifier(coin_a, r_nf_2)

    assert nu_base != nu_diff_coin, "Witness substitution failed: different coin produced same nullifier"
    assert nu_base != nu_diff_secret, "Secret modification failed: different r_nf produced same nullifier"
    print("[PASS] Witness substitution detection: modifying C or r_nf alters nu")


def test_domain_separation():
    """Verify that omitting or modifying domain separator alters output."""
    coeffs = tuple(range(256))
    poly = SimulatedRingElem(coeffs)
    coin_c = SimulatedCoinCommitment((poly,))
    r_nf = secrets.token_bytes(SECRET_BYTES)

    nu_standard = compute_nullifier(coin_c, r_nf)

    # Alternate domain
    hasher = hashlib.shake_256()
    hasher.update(b"0PSP-ALTERNATE-DOMAIN")
    hasher.update(coin_c.encode())
    hasher.update(r_nf)
    nu_alt = hasher.digest(NULLIFIER_BYTES)

    assert nu_standard != nu_alt, "Domain separation failed"
    print("[PASS] Domain separation verification")


def main():
    print("=" * 65)
    print("0PSP Phase 1: Nullifier Relation Functional Smoke Tests")
    print("=" * 65)
    test_determinism_and_length()
    test_witness_substitution_detection()
    test_domain_separation()
    print("=" * 65)
    print("FUNCTIONAL SMOKE TESTS PASSED (Non-Cryptographic Validation Only).")
    print("NOTE: Validates data-structure encoding and functional determinism.")
    print("Does NOT establish cryptographic soundness, collision resistance,")
    print("unlinkability, zero knowledge, or post-quantum security.")
    print("=" * 65)


if __name__ == "__main__":
    main()
