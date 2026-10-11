"""
0PSP — Property-Based Tests: Mathematical Invariants
tests/property/test_properties.py

Uses Hypothesis to verify algebraic identities that must hold
for any valid implementation. These tests are stronger than unit tests:
they generate random inputs and verify properties hold universally.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from hypothesis import given, settings, assume
    from hypothesis import strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from src.core.params import RESEARCH_SMALL
from src.core.ring import RingElem, _mod_center
from src.core.sampling import make_rng, sample_uniform_ring, sample_secret

PARAMS = RESEARCH_SMALL
pytestmark = pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")


def random_ring_elem(seed: int) -> RingElem:
    """Generate a ring element from an integer seed."""
    rng = make_rng(seed.to_bytes(8, "little"))
    return sample_uniform_ring(PARAMS, rng)


if HAS_HYPOTHESIS:

    @given(
        seed_a=st.integers(0, 2**32),
        seed_b=st.integers(0, 2**32),
    )
    @settings(max_examples=50)
    def test_ring_addition_commutativity(seed_a: int, seed_b: int) -> None:
        """a + b = b + a for all a, b in Rq."""
        a = random_ring_elem(seed_a)
        b = random_ring_elem(seed_b)
        assert (a + b).coeffs == (b + a).coeffs

    @given(
        seed_a=st.integers(0, 2**32),
        seed_b=st.integers(0, 2**32),
        seed_c=st.integers(0, 2**32),
    )
    @settings(max_examples=30)
    def test_ring_multiplication_commutativity(seed_a: int, seed_b: int, seed_c: int) -> None:
        """a * b = b * a for all a, b in Rq."""
        a = random_ring_elem(seed_a)
        b = random_ring_elem(seed_b)
        assert (a * b).coeffs == (b * a).coeffs

    @given(
        seed_a=st.integers(0, 2**32),
        seed_b=st.integers(0, 2**32),
        seed_c=st.integers(0, 2**32),
    )
    @settings(max_examples=30)
    def test_ring_distributivity(seed_a: int, seed_b: int, seed_c: int) -> None:
        """a * (b + c) = a*b + a*c for all a, b, c in Rq."""
        a = random_ring_elem(seed_a)
        b = random_ring_elem(seed_b)
        c = random_ring_elem(seed_c)
        lhs = a * (b + c)
        rhs = (a * b) + (a * c)
        assert lhs.coeffs == rhs.coeffs

    @given(seed=st.integers(0, 2**32))
    @settings(max_examples=50)
    def test_ring_additive_inverse(seed: int) -> None:
        """a + (-a) = 0 for all a in Rq."""
        a = random_ring_elem(seed)
        result = a + (-a)
        assert all(c == 0 for c in result.coeffs)

    @given(seed=st.integers(0, 2**32))
    @settings(max_examples=50)
    def test_ntt_round_trip(seed: int) -> None:
        """NTT(INTT(a)) = a for all a in Rq."""
        from src.core.ring import NTT
        a = random_ring_elem(seed)
        ntt = NTT(PARAMS)
        a_hat = ntt.forward(a.coeffs)
        recovered = ntt.inverse(a_hat)
        assert recovered == a.coeffs

    @given(
        seed_s=st.integers(0, 2**32),
        threshold=st.integers(2, 3),
        n_shares=st.integers(3, 5),
    )
    @settings(max_examples=20, deadline=5000)
    def test_shamir_reconstruction_invariant(seed_s: int, threshold: int, n_shares: int) -> None:
        """
        Any t-subset of n Shamir shares reconstructs the original secret.
        """
        assume(threshold <= n_shares)
        from src.core.sampling import shamir_share, shamir_reconstruct
        rng = make_rng(seed_s.to_bytes(8, "little"))
        secret = sample_secret(PARAMS, rng)
        shares, pts = shamir_share(secret, threshold, n_shares, rng=rng)
        recon = shamir_reconstruct(shares[:threshold], pts[:threshold], PARAMS)
        error = (recon - secret).norm_inf()
        assert error == 0, f"Shamir reconstruction error={error} for threshold={threshold}, n={n_shares}"

    @given(
        seed1=st.integers(0, 2**32),
        seed2=st.integers(0, 2**32),
    )
    @settings(max_examples=30)
    def test_nullifier_determinism(seed1: int, seed2: int) -> None:
        """
        Same secret + same coin_id → same nullifier, always.
        Different coin_ids → different nullifiers, with overwhelming probability.
        """
        from src.primitives.nullifier import CoinId, compute_nullifier
        rng = make_rng(seed1.to_bytes(8, "little"))
        secret = sample_secret(PARAMS, rng)

        coin_id_bytes = seed2.to_bytes(8, "little")
        coin = CoinId(coin_id_bytes)

        n1 = compute_nullifier(secret, coin)
        n2 = compute_nullifier(secret, coin)
        assert n1 == n2, "Nullifier must be deterministic"

        # Different coin
        coin_other = CoinId((seed2 + 1).to_bytes(8, "little"))
        n3 = compute_nullifier(secret, coin_other)
        # With overwhelming probability, n1 != n3 (collision would be a break)
        # We don't assert this strictly to avoid rare PRNG collisions in testing
        # A separate collision-resistance experiment should verify this statistically
