"""
0PSP — Unit Tests: Canonical Bridge Encoding & Module-SIS Commitment
tests/unit/test_bridge_encoding.py
"""

from __future__ import annotations

import os
import secrets
import pytest

from src.core.params import ML_DSA_44, Params
from src.core.ring import RingElem, ModuleVec, ModuleMatrix
from src.core.sampling import make_rng, sample_uniform_ring, sample_cbd
from src.primitives.bridge_encoding import (
    encode_nf_to_poly,
    decode_poly_to_nf,
    compute_bridge_commitment,
    verify_bridge_opening,
    COIN_ID_BYTES,
    SECRET_BYTES,
)

PARAMS = ML_DSA_44


def _sample_matrix(rows: int, cols: int, rng) -> ModuleMatrix:
    return ModuleMatrix([
        ModuleVec([sample_uniform_ring(PARAMS, rng) for _ in range(cols)])
        for _ in range(rows)
    ])


def _sample_noise_vec(dim: int, rng) -> ModuleVec:
    return ModuleVec([sample_cbd(PARAMS, PARAMS.eta, rng) for _ in range(dim)])


class TestBridgeEncoding:
    def test_round_trip(self):
        """Verify that decode(encode(x)) == x for random coin_id and r_nf."""
        coin_id = secrets.token_bytes(COIN_ID_BYTES)
        r_nf = secrets.token_bytes(SECRET_BYTES)

        poly = encode_nf_to_poly(coin_id, r_nf, params=PARAMS)
        assert len(poly.coeffs) == PARAMS.n
        assert poly.norm_inf() <= 3

        decoded_coin_id, decoded_r_nf = decode_poly_to_nf(poly)
        assert decoded_coin_id == coin_id
        assert decoded_r_nf == r_nf

    def test_determinism(self):
        """Identical inputs must yield identical polynomial coefficients."""
        coin_id = b"\xaa" * COIN_ID_BYTES
        r_nf = b"\x55" * SECRET_BYTES

        p1 = encode_nf_to_poly(coin_id, r_nf, params=PARAMS)
        p2 = encode_nf_to_poly(coin_id, r_nf, params=PARAMS)

        assert p1.coeffs == p2.coeffs

    def test_norm_bounds_all_samples(self):
        """Verify that for multiple random inputs, coefficients are strictly in {0, 1, 2, 3}."""
        for _ in range(50):
            coin_id = secrets.token_bytes(COIN_ID_BYTES)
            r_nf = secrets.token_bytes(SECRET_BYTES)
            poly = encode_nf_to_poly(coin_id, r_nf, params=PARAMS)
            for c in poly.coeffs:
                assert 0 <= c <= 3

    def test_malleability_rejection(self):
        """Any coefficient outside {0, 1, 2, 3} must be rejected during decoding."""
        coin_id = secrets.token_bytes(COIN_ID_BYTES)
        r_nf = secrets.token_bytes(SECRET_BYTES)
        poly = encode_nf_to_poly(coin_id, r_nf, params=PARAMS)

        # Corrupt one coefficient to 4
        corrupted_coeffs = list(poly.coeffs)
        corrupted_coeffs[17] = 4
        corrupted_poly = RingElem(coeffs=tuple(corrupted_coeffs), params=PARAMS)

        with pytest.raises(ValueError, match="Invalid coefficient"):
            decode_poly_to_nf(corrupted_poly)

        # Corrupt one coefficient to q - 1
        corrupted_coeffs[17] = PARAMS.q - 1
        corrupted_poly2 = RingElem(coeffs=tuple(corrupted_coeffs), params=PARAMS)
        with pytest.raises(ValueError, match="Invalid coefficient"):
            decode_poly_to_nf(corrupted_poly2)

    def test_invalid_input_lengths(self):
        """Wrong byte lengths must raise ValueError."""
        with pytest.raises(ValueError, match="coin_id must be exactly 32 bytes"):
            encode_nf_to_poly(b"\x00" * 31, b"\x00" * 32, params=PARAMS)

        with pytest.raises(ValueError, match="r_nf must be exactly 32 bytes"):
            encode_nf_to_poly(b"\x00" * 32, b"\x00" * 33, params=PARAMS)


class TestBridgeCommitment:
    def test_commitment_and_verification(self):
        """Verify computation and opening of Module-SIS bridge commitment."""
        rng = make_rng(b"bridge-commitment-test-seed")

        k_B = 2
        k_tau = 2

        # Public matrices A1 ∈ R_q^{2 x 1}, A2 ∈ R_q^{2 x 2}
        A1 = _sample_matrix(k_B, 1, rng)
        A2 = _sample_matrix(k_B, k_tau, rng)

        # Witness: message m_x and randomness tau_B
        coin_id = secrets.token_bytes(COIN_ID_BYTES)
        r_nf = secrets.token_bytes(SECRET_BYTES)
        m_x = encode_nf_to_poly(coin_id, r_nf, params=PARAMS)
        tau_B = _sample_noise_vec(k_tau, rng)

        # Compute commitment B
        B = compute_bridge_commitment(A1, A2, m_x, tau_B, params=PARAMS)
        assert len(B.elems) == k_B

        # Valid opening check
        assert verify_bridge_opening(B, A1, A2, m_x, tau_B, max_tau_norm=PARAMS.eta, params=PARAMS)

    def test_tampered_commitment_rejected(self):
        """Tampering with message or commitment must cause opening check to fail."""
        rng = make_rng(b"bridge-tamper-test-seed")
        k_B = 2
        k_tau = 2
        A1 = _sample_matrix(k_B, 1, rng)
        A2 = _sample_matrix(k_B, k_tau, rng)

        coin_id1 = b"\x11" * COIN_ID_BYTES
        coin_id2 = b"\x22" * COIN_ID_BYTES
        r_nf = secrets.token_bytes(SECRET_BYTES)

        m_x1 = encode_nf_to_poly(coin_id1, r_nf, params=PARAMS)
        m_x2 = encode_nf_to_poly(coin_id2, r_nf, params=PARAMS)
        tau_B = _sample_noise_vec(k_tau, rng)

        B = compute_bridge_commitment(A1, A2, m_x1, tau_B, params=PARAMS)

        # Verifying with substituted message must fail
        assert not verify_bridge_opening(B, A1, A2, m_x2, tau_B, max_tau_norm=PARAMS.eta, params=PARAMS)

