"""
0PSP — Post-Quantum Private Spend Primitive
src/primitives/bridge_encoding.py

Canonical 2-bit chunk polynomial encoding and Module-SIS bridge commitment.

Encodes canonical nullifier secret input x = (coin_id || r_nf) (512 bits) into
a short polynomial m_x(X) in R_q = Z_q[X]/(X^256 + 1) with coefficients in {0, 1, 2, 3}.
This bridges Layer 1 (extended lattice Σ-protocol over R_q) and Layer 2 (STARK AIR).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Sequence

from ..core.params import Params, ML_DSA_44
from ..core.ring import RingElem, ModuleVec, ModuleMatrix


# Protocol constants
COIN_ID_BYTES = 32   # 256 bits
SECRET_BYTES = 32    # 256 bits (r_nf)
TOTAL_INPUT_BYTES = COIN_ID_BYTES + SECRET_BYTES  # 64 bytes = 512 bits
CHUNKS_PER_BYTE = 4  # 4 x 2-bit chunks per byte
TOTAL_CHUNKS = TOTAL_INPUT_BYTES * CHUNKS_PER_BYTE  # 256 chunks = 256 coefficients


def encode_nf_to_poly(coin_id: bytes, r_nf: bytes, params: Params = ML_DSA_44) -> RingElem:
    """
    Encode (coin_id || r_nf) into a short polynomial m_x(X) ∈ R_q.

    Each byte is split into 4 two-bit chunks (little-endian within the byte):
        chunk_0 = byte & 0b11
        chunk_1 = (byte >> 2) & 0b11
        chunk_2 = (byte >> 4) & 0b11
        chunk_3 = (byte >> 6) & 0b11

    The 64 bytes yield exactly 256 coefficients c_i ∈ {0, 1, 2, 3}.
    The resulting polynomial has infinity norm ||m_x||_∞ ≤ 3 << q.

    Parameters
    ----------
    coin_id : bytes
        32-byte immutable coin identifier.
    r_nf : bytes
        32-byte secret nullifier randomness.
    params : Params
        Lattice parameters (n=256, q=8380417).

    Returns
    -------
    RingElem
        Polynomial m_x(X) = ∑_{i=0}^{255} c_i X^i ∈ R_q.
    """
    if len(coin_id) != COIN_ID_BYTES:
        raise ValueError(f"coin_id must be exactly {COIN_ID_BYTES} bytes, got {len(coin_id)}")
    if len(r_nf) != SECRET_BYTES:
        raise ValueError(f"r_nf must be exactly {SECRET_BYTES} bytes, got {len(r_nf)}")

    payload = coin_id + r_nf
    coeffs: list[int] = []

    for byte in payload:
        coeffs.append(byte & 0x03)
        coeffs.append((byte >> 2) & 0x03)
        coeffs.append((byte >> 4) & 0x03)
        coeffs.append((byte >> 6) & 0x03)

    if len(coeffs) != params.n:
        raise ValueError(f"Coefficients length {len(coeffs)} != degree n {params.n}")

    return RingElem(coeffs=tuple(coeffs), params=params)


def decode_poly_to_nf(poly: RingElem) -> tuple[bytes, bytes]:
    """
    Decode polynomial m_x(X) ∈ R_q back into (coin_id, r_nf).

    Validates that every coefficient satisfies the strict range constraint:
        c_i ∈ {0, 1, 2, 3}
    Any out-of-range coefficient (or negative / modular representative)
    raises a ValueError, preventing malleability attacks.

    Parameters
    ----------
    poly : RingElem
        Short polynomial with degree n=256.

    Returns
    -------
    tuple[bytes, bytes]
        (coin_id, r_nf) each 32 bytes.
    """
    if len(poly.coeffs) != TOTAL_CHUNKS:
        raise ValueError(f"Polynomial must have {TOTAL_CHUNKS} coefficients, got {len(poly.coeffs)}")

    raw_bytes = bytearray()
    for byte_idx in range(TOTAL_INPUT_BYTES):
        chunk_offset = byte_idx * CHUNKS_PER_BYTE
        c0 = poly.coeffs[chunk_offset]
        c1 = poly.coeffs[chunk_offset + 1]
        c2 = poly.coeffs[chunk_offset + 2]
        c3 = poly.coeffs[chunk_offset + 3]

        for c, name in [(c0, "c0"), (c1, "c1"), (c2, "c2"), (c3, "c3")]:
            if not (0 <= c <= 3):
                raise ValueError(f"Invalid coefficient {name}={c}: must be in range [0, 3]")

        byte_val = c0 | (c1 << 2) | (c2 << 4) | (c3 << 6)
        raw_bytes.append(byte_val)

    coin_id = bytes(raw_bytes[:COIN_ID_BYTES])
    r_nf = bytes(raw_bytes[COIN_ID_BYTES:])
    return coin_id, r_nf


def compute_bridge_commitment(
    A1: ModuleMatrix,
    A2: ModuleMatrix,
    m_x: RingElem,
    tau_B: ModuleVec,
    params: Params = ML_DSA_44,
) -> ModuleVec:
    """
    Evaluate the Module-SIS / Module-LWE bridge commitment:
        B = A_1 · m_x + A_2 · τ_B (mod q)

    Parameters
    ----------
    A1 : ModuleMatrix
        Matrix of dimensions (k_B, 1) over R_q.
    A2 : ModuleMatrix
        Matrix of dimensions (k_B, k_tau) over R_q.
    m_x : RingElem
        Canonical 2-bit encoded polynomial message.
    tau_B : ModuleVec
        Short commitment randomness vector of dimension k_tau.
    params : Params
        Lattice parameter set.

    Returns
    -------
    ModuleVec
        Public commitment vector B ∈ R_q^{k_B}.
    """
    # Wrap m_x as a 1-dimensional module vector
    m_vec = ModuleVec([m_x])
    part1 = A1.mul_vec(m_vec)
    part2 = A2.mul_vec(tau_B)
    return part1 + part2


def verify_bridge_opening(
    B: ModuleVec,
    A1: ModuleMatrix,
    A2: ModuleMatrix,
    m_x: RingElem,
    tau_B: ModuleVec,
    max_tau_norm: int = 2,
    params: Params = ML_DSA_44,
) -> bool:
    """
    Verify opening of bridge commitment B.

    Checks:
    1. Arithmetic equality: B == A_1 · m_x + A_2 · τ_B (mod q)
    2. Message range: ||m_x||_∞ ≤ 3 (all c_i ∈ {0, 1, 2, 3})
    3. Randomness range: ||τ_B||_∞ ≤ max_tau_norm
    """
    # 1. Range check on message
    for c in m_x.coeffs:
        if not (0 <= c <= 3):
            return False

    # 2. Range check on randomness
    if tau_B.norm_inf() > max_tau_norm:
        return False

    # 3. Algebraic equality
    expected = compute_bridge_commitment(A1, A2, m_x, tau_B, params=params)
    return B.elems == expected.elems
