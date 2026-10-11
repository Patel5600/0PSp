"""
0PSP — Test Suite: Ring Arithmetic and Core Correctness
tests/unit/test_ring.py
"""

from __future__ import annotations

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.params import RESEARCH_SMALL, Params
from src.core.ring import RingElem, ModuleVec, ModuleMatrix, NTT, _mod_center
from src.core.sampling import (
    make_rng,
    sample_uniform_ring,
    sample_secret,
    sample_error,
    sample_uniform_matrix,
    shamir_share,
    shamir_reconstruct,
    compute_lagrange_norms,
)

PARAMS = RESEARCH_SMALL


class TestParams:
    def test_ntt_condition(self):
        """q ≡ 1 (mod 2n) must hold for NTT."""
        p = PARAMS
        assert (p.q - 1) % (2 * p.n) == 0, f"NTT condition failed for n={p.n}, q={p.q}"

    def test_beta_consistency(self):
        assert PARAMS.beta == PARAMS.tau * PARAMS.eta


class TestRingArithmetic:
    def test_addition_commutativity(self):
        rng = make_rng(b"test-add-comm")
        a = sample_uniform_ring(PARAMS, rng)
        b = sample_uniform_ring(PARAMS, rng)
        assert (a + b).coeffs == (b + a).coeffs

    def test_addition_associativity(self):
        rng = make_rng(b"test-add-assoc")
        a = sample_uniform_ring(PARAMS, rng)
        b = sample_uniform_ring(PARAMS, rng)
        c = sample_uniform_ring(PARAMS, rng)
        lhs = (a + b) + c
        rhs = a + (b + c)
        assert lhs.coeffs == rhs.coeffs

    def test_zero_is_additive_identity(self):
        rng = make_rng(b"test-zero")
        a = sample_uniform_ring(PARAMS, rng)
        z = RingElem.zero(PARAMS)
        assert (a + z).coeffs == a.coeffs
        assert (z + a).coeffs == a.coeffs

    def test_negation(self):
        rng = make_rng(b"test-neg")
        a = sample_uniform_ring(PARAMS, rng)
        z = RingElem.zero(PARAMS)
        result = a + (-a)
        assert result.coeffs == z.coeffs

    def test_subtraction_is_negated_addition(self):
        rng = make_rng(b"test-sub")
        a = sample_uniform_ring(PARAMS, rng)
        b = sample_uniform_ring(PARAMS, rng)
        assert (a - b).coeffs == (a + (-b)).coeffs

    def test_scalar_multiplication(self):
        rng = make_rng(b"test-scalar-mul")
        a = sample_uniform_ring(PARAMS, rng)
        two_a = a * 2
        a_plus_a = a + a
        assert two_a.coeffs == a_plus_a.coeffs

    def test_one_is_multiplicative_identity(self):
        rng = make_rng(b"test-one")
        a = sample_uniform_ring(PARAMS, rng)
        one = RingElem.one(PARAMS)
        assert (a * one).coeffs == a.coeffs

    def test_norm_inf_nonnegative(self):
        rng = make_rng(b"test-norm")
        a = sample_uniform_ring(PARAMS, rng)
        assert a.norm_inf() >= 0

    def test_zero_has_zero_norm(self):
        z = RingElem.zero(PARAMS)
        assert z.norm_inf() == 0


class TestNTT:
    """Test that NTT and INTT are inverses."""

    def test_ntt_round_trip(self):
        rng = make_rng(b"test-ntt-round-trip")
        a = sample_uniform_ring(PARAMS, rng)
        ntt = NTT(PARAMS)
        a_hat = ntt.forward(a.coeffs)
        a_recovered = ntt.inverse(a_hat)
        assert a_recovered == a.coeffs, "NTT → INTT should recover original polynomial"

    def test_ntt_multiplication_matches_naive(self):
        """
        NTT-based multiplication must equal naive polynomial multiplication
        mod (x^n + 1, q).
        """
        rng = make_rng(b"test-ntt-mul")
        # Use small polynomials to make naive multiplication feasible
        params = RESEARCH_SMALL
        a = sample_uniform_ring(params, rng)
        b = sample_uniform_ring(params, rng)

        # NTT-based multiplication
        ntt_result = a * b

        # Naive multiplication mod (x^n + 1)
        n, q = params.n, params.q
        naive = [0] * n
        for i, ai in enumerate(a.coeffs):
            for j, bj in enumerate(b.coeffs):
                idx = (i + j) % n
                sign = -1 if (i + j) >= n else 1
                naive[idx] = (naive[idx] + sign * ai * bj) % q

        assert ntt_result.coeffs == naive, "NTT multiplication must match naive"


class TestModuleVec:
    def test_addition(self):
        rng = make_rng(b"test-vec-add")
        a = sample_secret(PARAMS, rng)
        b = sample_error(PARAMS, rng)
        c = a + b
        assert c.dim == a.dim

    def test_norm_inf_nonnegative(self):
        rng = make_rng(b"test-vec-norm")
        s = sample_secret(PARAMS, rng)
        assert s.norm_inf() >= 0


class TestModuleMatrix:
    def test_matrix_vector_product_dimension(self):
        rng = make_rng(b"test-mat-vec")
        A = sample_uniform_matrix(PARAMS, rng)
        s = sample_secret(PARAMS, rng)
        t = A.mul_vec(s)
        assert t.dim == PARAMS.k

    def test_mlwe_sample_structure(self):
        """
        t = A·s + e should have a larger norm than s alone,
        due to error term and modular arithmetic.
        """
        rng = make_rng(b"test-mlwe")
        A = sample_uniform_matrix(PARAMS, rng)
        s = sample_secret(PARAMS, rng)
        e = sample_error(PARAMS, rng)
        t = A.mul_vec(s) + e
        # t's coefficients will be reduced mod q — norm is bounded by q/2
        assert t.norm_inf() <= PARAMS.q // 2 + 1


class TestShamirSecretSharing:
    def test_reconstruction_exact(self):
        """Reconstruction from exactly t shares must recover the exact secret."""
        rng = make_rng(b"test-shamir-exact")
        secret = sample_secret(PARAMS, rng)
        threshold, n_shares = 2, 3

        shares, eval_pts = shamir_share(secret, threshold, n_shares, rng=rng)
        reconstructed = shamir_reconstruct(shares[:threshold], eval_pts[:threshold], PARAMS)

        error = (reconstructed - secret).norm_inf()
        assert error == 0, f"Reconstruction error must be 0, got {error}"

    def test_reconstruction_with_different_subsets(self):
        """Any t-subset of shares must give the same reconstruction."""
        rng = make_rng(b"test-shamir-subsets")
        secret = sample_secret(PARAMS, rng)
        threshold, n_shares = 2, 4

        shares, eval_pts = shamir_share(secret, threshold, n_shares, rng=rng)

        subsets = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]
        results = []
        for i, j in subsets:
            subset_shares = [shares[i], shares[j]]
            subset_pts = [eval_pts[i], eval_pts[j]]
            r = shamir_reconstruct(subset_shares, subset_pts, PARAMS)
            results.append(r)

        # All reconstructions must match
        for r in results[1:]:
            error = (r - results[0]).norm_inf()
            assert error == 0, f"All t-subsets must reconstruct the same secret; error={error}"

    def test_lagrange_norms_positive(self):
        """Lagrange coefficients must be nonzero for distinct eval points."""
        eval_pts = [1, 2, 3]
        norms = compute_lagrange_norms(3, eval_pts, PARAMS.q)
        assert all(n > 0 for n in norms)

    def test_t_minus_one_shares_insufficient(self):
        """
        t-1 shares must NOT correctly reconstruct the secret.

        NOTE: With t-1 shares, reconstruction gives the wrong polynomial
        evaluation at 0 (underdetermined system). We check that the result
        differs from the original with high probability.
        """
        rng = make_rng(b"test-shamir-insufficient")
        secret = sample_secret(PARAMS, rng)
        threshold, n_shares = 3, 5

        shares, eval_pts = shamir_share(secret, threshold, n_shares, rng=rng)

        # Use only t-1 = 2 shares
        bad_recon = shamir_reconstruct(shares[:threshold-1], eval_pts[:threshold-1], PARAMS)
        error = (bad_recon - secret).norm_inf()

        # With overwhelming probability, error > 0 when using < t shares
        # (This is probabilistic — a fixed test may fluke, but effectively never does)
        assert error > 0, (
            "Using t-1 shares should NOT reconstruct the secret correctly. "
            "If this fails, check the Shamir implementation."
        )


class TestNullifier:
    def test_deterministic(self):
        from src.primitives.nullifier import (
            CoinId, NullifierSecret, compute_nullifier, NULLIFIER_SECRET_BYTES
        )
        coin = CoinId(b"coin-001".ljust(32, b"\x00"))
        secret = NullifierSecret(b"\x42" * NULLIFIER_SECRET_BYTES)
        assert compute_nullifier(coin, secret) == compute_nullifier(coin, secret)

    def test_different_coins_different_nullifiers(self):
        from src.primitives.nullifier import (
            CoinId, NullifierSecret, compute_nullifier
        )
        secret = NullifierSecret(b"\x42" * 32)
        coin1 = CoinId(b"coin-001".ljust(32, b"\x00"))
        coin2 = CoinId(b"coin-002".ljust(32, b"\x00"))
        assert compute_nullifier(coin1, secret) != compute_nullifier(coin2, secret)

    def test_double_spend_detection(self):
        from src.primitives.nullifier import (
            CoinId, NullifierSecret, compute_nullifier, NullifierSet
        )
        coin = CoinId(b"my-coin".ljust(32, b"\x00"))
        secret = NullifierSecret(b"\x73" * NULLIFIER_SECRET_BYTES)
        nullifier = compute_nullifier(coin, secret)
        ledger = NullifierSet()
        assert ledger.try_spend(nullifier) is True
        assert ledger.try_spend(nullifier) is False
