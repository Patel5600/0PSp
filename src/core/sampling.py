"""
0PSP — Post-Quantum Private Spend Primitive
src/core/sampling.py

Sampling routines for Module-LWE keys, errors, and challenge polynomials.

All distributions follow Dilithium / ML-DSA conventions.
Deterministic sampling uses a seed + SHAKE-256 (simulated here with numpy
seeded PRNG for research purposes — production must use a CSPRNG).

References:
  - NIST FIPS 204 §5.1–5.3 (ML-DSA)
  - Ducas et al., CRYSTALS-Dilithium Algorithm Specification v3.1
"""

from __future__ import annotations

import secrets
import numpy as np
from numpy.random import Generator, default_rng

from .params import Params
from .ring import RingElem, ModuleVec, ModuleMatrix


# ---------------------------------------------------------------------------
# Seed-based RNG wrapper
# ---------------------------------------------------------------------------

def make_rng(seed: bytes | None = None) -> Generator:
    """
    Create a numpy Generator from a byte seed.
    If seed is None, uses cryptographically random bytes.

    NOTE: numpy's default_rng is NOT a CSPRNG. For research simulation
    only. A production implementation must use SHAKE-256 as specified in
    FIPS 204.
    """
    if seed is None:
        seed = secrets.token_bytes(32)
    int_seed = int.from_bytes(seed, "little")
    return default_rng(int_seed)


# ---------------------------------------------------------------------------
# Uniform sampling
# ---------------------------------------------------------------------------

def sample_uniform_ring(params: Params, rng: Generator | None = None) -> RingElem:
    """
    Sample a uniformly random polynomial in Rq.
    Coefficients drawn from U([0, q)).
    """
    if rng is None:
        rng = make_rng()
    coeffs = [int(x) for x in rng.integers(0, params.q, size=params.n, dtype=np.int64)]
    return RingElem(coeffs, params)


def sample_uniform_matrix(params: Params, rng: Generator | None = None) -> ModuleMatrix:
    """
    Sample the public matrix A ←$ Rq^{k×ℓ}.
    Each entry is a uniformly random ring element.
    """
    if rng is None:
        rng = make_rng()
    rows = []
    for _ in range(params.k):
        row_elems = [sample_uniform_ring(params, rng) for _ in range(params.ell)]
        rows.append(ModuleVec(row_elems))
    return ModuleMatrix(rows)


# ---------------------------------------------------------------------------
# Bounded secret / error sampling
# ---------------------------------------------------------------------------

def sample_cbd(params: Params, eta: int, rng: Generator | None = None) -> RingElem:
    """
    Sample from centered binomial distribution with parameter η.
    Each coefficient cᵢ = Σ_{j=1}^{η} (bⱼ - b'ⱼ) where b, b' are uniform bits.
    This approximates a discrete Gaussian with σ ≈ √(η/2).

    Parameters
    ----------
    eta : int
        Distribution parameter. Larger η → larger norms, higher security.
    """
    if rng is None:
        rng = make_rng()
    n = params.n
    # Sample 2η bits per coefficient
    bits = rng.integers(0, 2, size=(n, 2 * eta), dtype=np.int64)
    a = bits[:, :eta].sum(axis=1)
    b = bits[:, eta:].sum(axis=1)
    coeffs = [int((int(ai) - int(bi)) % params.q) for ai, bi in zip(a, b)]
    return RingElem(coeffs, params)


def sample_secret(params: Params, rng: Generator | None = None) -> ModuleVec:
    """
    Sample a secret vector s ←$ S_η^ℓ (coefficient-wise bounded by η).
    Uses the CBD distribution as an approximation of the bounded uniform
    distribution used in Dilithium.
    """
    if rng is None:
        rng = make_rng()
    elems = [sample_cbd(params, params.eta, rng) for _ in range(params.ell)]
    return ModuleVec(elems)


def sample_error(params: Params, rng: Generator | None = None) -> ModuleVec:
    """
    Sample an error vector e ←$ S_η^k.
    Same distribution as the secret; used in LWE instance construction.
    """
    if rng is None:
        rng = make_rng()
    elems = [sample_cbd(params, params.eta, rng) for _ in range(params.k)]
    return ModuleVec(elems)


def sample_mask(params: Params, rng: Generator | None = None) -> ModuleVec:
    """
    Sample a masking vector y ←$ S_{γ₁}^ℓ.
    Used in Fiat-Shamir signing as commitment randomness.
    Coefficients uniform in (-γ₁, γ₁].
    """
    if rng is None:
        rng = make_rng()
    elems = []
    for _ in range(params.ell):
        raw = rng.integers(-params.gamma1, params.gamma1 + 1,
                           size=params.n, dtype=np.int64)
        coeffs = [int(x) % params.q for x in raw]
        elems.append(RingElem(coeffs, params))
    return ModuleVec(elems)


# ---------------------------------------------------------------------------
# Challenge polynomial sampling
# ---------------------------------------------------------------------------

def sample_challenge(params: Params, seed: bytes) -> RingElem:
    """
    Sample a challenge polynomial c with exactly τ non-zero coefficients (±1).
    In Dilithium, this is derived via SHAKE-256 from the seed.

    For research purposes, we use a seeded PRNG instead of SHAKE-256.
    The output structure matches: c has exactly params.tau coefficients equal to ±1,
    the rest are 0.
    """
    rng = make_rng(seed)
    n, tau = params.n, params.tau
    positions = [int(x) for x in rng.choice(n, size=tau, replace=False)]
    signs = [int(x) for x in rng.integers(0, 2, size=tau, dtype=np.int64)]
    coeffs = [0] * n
    for pos, s in zip(positions, signs):
        coeffs[pos] = 1 if s == 0 else params.q - 1  # +1 or -1 mod q
    return RingElem(coeffs, params)


# ---------------------------------------------------------------------------
# Shamir secret sharing over Zq (coordinate-wise over ring coefficients)
# ---------------------------------------------------------------------------

def shamir_share(secret: ModuleVec, threshold: int, n_shares: int,
                 eval_points: list[int] | None = None,
                 rng: Generator | None = None) -> tuple[list[ModuleVec], list[int]]:
    """
    Split a module vector `secret ∈ Rq^ℓ` into `n_shares` shares using
    (threshold, n_shares)-Shamir secret sharing.

    Operates **coordinate-wise**: each of the n*ℓ scalar coefficients is
    shared independently over Zq.

    WARNING: This is the NTT-domain-compatible approach described in
    docs/theory/phase1-scrl-attack.md, Direction A. The shares may NOT be
    short after inverse NTT. Norm analysis is required before using these
    shares in a signing protocol.

    Parameters
    ----------
    secret : ModuleVec
        Secret s ∈ Rq^ℓ. Each element is a polynomial in Rq.
    threshold : int
        t — minimum shares needed for reconstruction.
    n_shares : int
        n — total number of shares issued.
    eval_points : list[int], optional
        Evaluation points ω₁, …, ωₙ ∈ Zq*. Defaults to {1, 2, …, n}.
        For NTT compatibility, consider using powers of a 2n-th root of unity.
    rng : Generator, optional
        PRNG for sampling the secret polynomial coefficients.

    Returns
    -------
    shares : list[ModuleVec]
        n shares; shares[i] corresponds to eval_points[i].
    eval_points : list[int]
        The evaluation points used.
    """
    if rng is None:
        rng = make_rng()
    params = secret.params
    q = params.q

    if eval_points is None:
        eval_points = list(range(1, n_shares + 1))
    assert len(eval_points) == n_shares
    assert all(1 <= w < q for w in eval_points), "Eval points must be in Zq*"

    # For each ring element in the secret, for each coefficient, build a
    # degree-(threshold-1) polynomial over Zq and evaluate at each point.
    shares_coeffs: list[list[list[int]]] = [[[] for _ in range(params.ell)]
                                             for _ in range(n_shares)]

    for elem_idx, ring_elem in enumerate(secret.elems):
        for coeff_idx, s_c in enumerate(ring_elem.coeffs):
            # Build polynomial f(X) = s_c + a₁X + … + a_{t-1}X^{t-1}
            # Coefficients sampled uniformly in Zq
            poly_coeffs = [s_c] + [int(x) for x in rng.integers(0, q, size=threshold - 1, dtype=np.int64)]

            for share_idx, omega in enumerate(eval_points):
                # Evaluate f(omega) mod q
                val = 0
                power = 1
                for coeff in poly_coeffs:
                    val = (val + coeff * power) % q
                    power = (power * omega) % q
                shares_coeffs[share_idx][elem_idx].append(int(val))

    # Reconstruct shares as ModuleVec objects
    shares: list[ModuleVec] = []
    for share_idx in range(n_shares):
        ring_elems = []
        for elem_idx in range(params.ell):
            ring_elems.append(RingElem(shares_coeffs[share_idx][elem_idx], params))
        shares.append(ModuleVec(ring_elems))

    return shares, eval_points


def shamir_reconstruct(shares: list[ModuleVec], eval_points: list[int],
                       params: Params) -> ModuleVec:
    """
    Reconstruct a secret from t or more shares using Lagrange interpolation.

    Parameters
    ----------
    shares : list[ModuleVec]
        Exactly threshold (or more) shares.
    eval_points : list[int]
        Corresponding evaluation points. len(shares) == len(eval_points).
    params : Params
        Ring parameters.

    Returns
    -------
    ModuleVec
        Reconstructed secret ≈ original secret (exact if shares are uncorrupted).

    Notes
    -----
    Lagrange coefficients are computed mod q. For lattice secrets, the
    reconstructed vector may NOT be short — this is the norm explosion
    problem documented in phase1-scrl-attack.md.
    """
    q = params.q
    t = len(shares)
    assert t == len(eval_points)

    # Compute Lagrange basis polynomials at X=0
    # λᵢ = ∏_{j≠i} (0 - ωⱼ) / (ωᵢ - ωⱼ) mod q
    lambdas: list[int] = []
    for i, omega_i in enumerate(eval_points):
        num = 1
        den = 1
        for j, omega_j in enumerate(eval_points):
            if i == j:
                continue
            num = (num * (q - omega_j)) % q          # (0 - ωⱼ) mod q
            den = (den * ((omega_i - omega_j) % q)) % q
        den_inv = pow(den, q - 2, q)  # Fermat's little theorem (q prime)
        lambdas.append((num * den_inv) % q)

    # Weighted sum of shares
    result_elems: list[RingElem] = [RingElem.zero(params)] * params.ell
    for share, lam in zip(shares, lambdas):
        for idx, ring_elem in enumerate(share.elems):
            result_elems[idx] = result_elems[idx] + (ring_elem * lam)

    return ModuleVec(result_elems)


def compute_lagrange_norms(threshold: int, eval_points: list[int], q: int) -> list[int]:
    """
    Compute the magnitude of each Lagrange coefficient λᵢ at X=0.
    Used to analyze norm explosion in reconstructed secrets.

    Returns list of |λᵢ| in centered range (-q/2, q/2].
    """
    from .ring import _mod_center
    t = len(eval_points)
    norms = []
    for i, omega_i in enumerate(eval_points):
        num = 1
        den = 1
        for j, omega_j in enumerate(eval_points):
            if i == j:
                continue
            num = (num * (-omega_j % q)) % q
            den = (den * ((omega_i - omega_j) % q)) % q
        den_inv = pow(den, q - 2, q)
        lam = (num * den_inv) % q
        norms.append(abs(_mod_center(lam, q)))
    return norms
