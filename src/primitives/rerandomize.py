"""
0PSP — Post-Quantum Private Spend Primitive
src/primitives/rerandomize.py

Key rerandomization: the SCRL (Share-Compatible Rerandomization Lemma) investigation.

This module implements the candidate construction described in:
  docs/theory/phase1-scrl-attack.md (Direction A + scaled correction)

It also provides tools to:
  1. Test SCRL conditions (SC-1) through (SC-4) numerically
  2. Measure norm explosion after rerandomization
  3. Run the falsification experiment for the SCRL

STATUS: Phase 1 investigation code. The construction is NOT proven secure.
The goal is to understand whether SCRL is achievable or provably impossible.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import NamedTuple

from ..core.params import Params
from ..core.ring import RingElem, ModuleVec, ModuleMatrix, _mod_center
from ..core.sampling import (
    shamir_share,
    shamir_reconstruct,
    compute_lagrange_norms,
    sample_uniform_ring,
    make_rng,
)


# ---------------------------------------------------------------------------
# Key pair and shared key structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicKey:
    """
    ML-DSA style public key: pk = (A, t) where t = A·s + e.

    A is the public matrix, t is the LWE sample.
    """
    A: ModuleMatrix      # Rq^{k×ℓ}
    t: ModuleVec         # Rq^k
    params: Params

    def __repr__(self) -> str:
        return f"PublicKey(t_norm_inf={self.t.norm_inf()}, A={self.A})"


@dataclass(frozen=True)
class SecretKey:
    """
    Short vector secret key: sk = s ∈ Rq^ℓ with ‖s‖∞ ≤ η.
    """
    s: ModuleVec         # Rq^ℓ — short
    params: Params


@dataclass
class ShareBundle:
    """
    A (threshold, n_shares)-Shamir sharing of a secret key.
    Includes verification keys A·shᵢ for each share.
    """
    shares: list[ModuleVec]          # List of n shares in Rq^ℓ
    eval_points: list[int]           # Evaluation points ω₁,…,ωₙ
    vk: list[ModuleVec]              # Verification keys A·shᵢ ∈ Rq^k
    threshold: int
    n_shares: int
    A: ModuleMatrix


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def keygen(params: Params, rng=None) -> tuple[SecretKey, PublicKey]:
    """
    Generate a Module-LWE key pair.

    sk = s ←$ χ^ℓ (short)
    pk = (A, t) where t = A·s + e, e ←$ χ^k

    This is the standard Dilithium-style key generation.
    """
    from ..core.sampling import (
        sample_uniform_matrix,
        sample_secret,
        sample_error,
    )
    if rng is None:
        rng = make_rng()

    A = sample_uniform_matrix(params, rng)
    s = sample_secret(params, rng)
    e = sample_error(params, rng)

    t = A.mul_vec(s) + e

    sk = SecretKey(s=s, params=params)
    pk = PublicKey(A=A, t=t, params=params)
    return sk, pk


def share_key(sk: SecretKey, pk: PublicKey, threshold: int, n_shares: int,
              rng=None) -> ShareBundle:
    """
    Shamir-share the secret key s into n_shares shares.

    Returns a ShareBundle with shares and verification keys.
    Verification keys vkᵢ = A·shᵢ allow checking share consistency
    without revealing the shares themselves.

    NOTE: This is coordinate-wise Shamir over Rq coefficients.
    The shares are NOT necessarily short — see norm analysis below.
    """
    if rng is None:
        rng = make_rng()

    shares, eval_points = shamir_share(sk.s, threshold, n_shares, rng=rng)

    # Compute verification keys
    vk = [pk.A.mul_vec(sh) for sh in shares]

    return ShareBundle(
        shares=shares,
        eval_points=eval_points,
        vk=vk,
        threshold=threshold,
        n_shares=n_shares,
        A=pk.A,
    )


# ---------------------------------------------------------------------------
# Rerandomization (candidate SCRL construction — NOT proven)
# ---------------------------------------------------------------------------

@dataclass
class RerandomizedKey:
    """
    Result of rerandomizing pk = (A, t) with randomness r.
    pk' = (A, t + r).
    """
    pk_prime: PublicKey    # (A, t + r)
    r: ModuleVec           # The rerandomization vector r ∈ Rq^k
    original_pk: PublicKey


def rerandomize_key(pk: PublicKey, r: ModuleVec | None = None,
                    rng=None) -> RerandomizedKey:
    """
    Additively shift the LWE sample: pk' = (A, t + r).

    This is the simplest form of rerandomization. Under MLWE, t + r is
    indistinguishable from a fresh LWE sample if r is uniform in Rq^k.

    Parameters
    ----------
    pk : PublicKey
        Original public key.
    r : ModuleVec, optional
        Rerandomization vector in Rq^k. Sampled uniformly if None.

    Returns
    -------
    RerandomizedKey
        The rerandomized key and the randomness used.
    """
    if rng is None:
        rng = make_rng()
    params = pk.params

    if r is None:
        r_elems = [sample_uniform_ring(params, rng) for _ in range(params.k)]
        r = ModuleVec(r_elems)

    assert r.dim == params.k

    t_prime = pk.t + r
    pk_prime = PublicKey(A=pk.A, t=t_prime, params=params)
    return RerandomizedKey(pk_prime=pk_prime, r=r, original_pk=pk)


def update_share(share: ModuleVec, r: ModuleVec, A: ModuleMatrix,
                 n_shares: int) -> ModuleVec:
    """
    Candidate share update for rerandomization: the SCRL construction attempt.

    Given share shᵢ and rerandomization r, computes:
        sh'ᵢ = shᵢ + Δᵢ

    where Δᵢ is chosen so that (ideally):
        Σ_i λᵢ · sh'ᵢ = s + A⁺·r

    CURRENT APPROACH: Uniform distribution of the correction.
        Δᵢ = n · (A⁺ · r)    (scaled to survive Lagrange summation)

    This is the "scaled correction" discussed in phase1-scrl-attack.md.
    It satisfies (SC-2) exactly IF Σ λᵢ = 1 (standard Shamir normalization).
    The cost is n-fold norm amplification of the correction.

    THIS IS NOT PROVEN SECURE. Use only for norm analysis.

    Parameters
    ----------
    share : ModuleVec
        The original share shᵢ ∈ Rq^ℓ.
    r : ModuleVec
        Rerandomization vector r ∈ Rq^k.
    A : ModuleMatrix
        Public matrix A ∈ Rq^{k×ℓ}.
    n_shares : int
        Total number of shares n (used for scaling).

    Returns
    -------
    ModuleVec
        Updated share sh'ᵢ.

    Notes
    -----
    A⁺ (pseudoinverse) is not directly available for module matrices.
    We approximate via: find z short such that A·z ≈ r.
    For this research code, we use a simplified version: multiply each
    share by a scalar correction derived from r's norm.
    The REAL construction requires solving a short preimage problem, which
    is precisely an SIS instance. This is left as a Phase 1 open problem.
    """
    params = share.params
    q = params.q
    n = n_shares

    # Simplified approximation: scale r by a small integer to create a
    # per-share additive correction in Rq^ℓ dimension.
    # This is NOT the correct construction — it ignores the A structure.
    # Included only to enable norm measurement experiments.
    #
    # Correct approach would require: solve A·z = r for short z, then
    # distribute z across shares. This is an MSIS instance.
    #
    # For now: use r's first ℓ elements as a proxy (dimensionality mismatch
    # handled by truncation/padding). For k ≠ ℓ this is wrong.
    if params.k == params.ell:
        # Simple case: apply r directly as if it's in Rq^ℓ
        correction_elems = [r.elems[i] * n for i in range(params.ell)]
        correction = ModuleVec(correction_elems)
    else:
        # General case: not handled — requires A⁺ computation
        raise NotImplementedError(
            "Share update for k≠ℓ requires pseudoinverse computation. "
            "This is an open problem (MSIS preimage). "
            "See docs/theory/phase1-scrl-attack.md."
        )

    return share + correction


# ---------------------------------------------------------------------------
# SCRL Verification Experiments
# ---------------------------------------------------------------------------

class SCRLCheckResult(NamedTuple):
    """Results of testing SCRL conditions numerically."""
    sc1_holds: bool           # A·sh'ᵢ ≈ A·shᵢ + r (per-share)
    sc2_holds: bool           # Lagrange recombination of sh'ᵢ recovers s + Δ
    sc3_norm_ratio: float     # ‖sh'ᵢ - shᵢ‖∞ / γ₁ (how much norm increased)
    sc3_acceptable: bool      # Whether norm is within signing bounds
    reconstruction_error: int # ‖reconstructed - expected‖∞ (0 = exact)
    original_norm: int        # ‖shᵢ‖∞ before update
    updated_norm: int         # ‖sh'ᵢ‖∞ after update
    lagrange_max_norm: int    # Max |λᵢ| (norm explosion factor)


def check_scrl(sk: SecretKey, pk: PublicKey, bundle: ShareBundle,
               subset_indices: list[int], n_shares: int) -> SCRLCheckResult:
    """
    Numerically verify SCRL conditions for a candidate rerandomization.

    This is the Phase 1 experimental tool — runs the construction and
    checks whether the conditions hold exactly or approximately.

    Parameters
    ----------
    sk : SecretKey
        Original secret key s.
    pk : PublicKey
        Original public key (A, t).
    bundle : ShareBundle
        Shamir share bundle.
    subset_indices : list[int]
        Which t shares to use for reconstruction.
    n_shares : int
        Total number of shares.

    Returns
    -------
    SCRLCheckResult
        Detailed breakdown of which SCRL conditions hold.
    """
    params = sk.params
    q = params.q

    # Rerandomize the key
    rerand = rerandomize_key(pk)
    r = rerand.r

    # Attempt to update shares (may raise NotImplementedError for k≠ℓ)
    try:
        updated_shares = [
            update_share(sh, r, bundle.A, n_shares)
            for sh in bundle.shares
        ]
    except NotImplementedError:
        # Fall back: analyze without actual update
        return SCRLCheckResult(
            sc1_holds=False,
            sc2_holds=False,
            sc3_norm_ratio=float('inf'),
            sc3_acceptable=False,
            reconstruction_error=-1,
            original_norm=bundle.shares[0].norm_inf(),
            updated_norm=-1,
            lagrange_max_norm=max(compute_lagrange_norms(
                bundle.threshold,
                [bundle.eval_points[i] for i in subset_indices],
                q
            )),
        )

    # --- Check SC-1: A·sh'ᵢ ≈ A·shᵢ + r ---
    # For the first share in the subset
    i = subset_indices[0]
    lhs = bundle.A.mul_vec(updated_shares[i])
    rhs = bundle.vk[i] + r
    sc1_diff = (lhs - rhs).norm_inf()
    sc1_holds = sc1_diff == 0

    # --- Check SC-2: Lagrange recombination of updated shares ---
    subset_shares = [updated_shares[i] for i in subset_indices]
    subset_points = [bundle.eval_points[i] for i in subset_indices]
    reconstructed = shamir_reconstruct(subset_shares, subset_points, params)

    # Expected: s (since our simplified update doesn't correctly compute A⁺r)
    # For now: compare to original s as a baseline
    recon_error = (reconstructed - sk.s).norm_inf()
    sc2_holds = recon_error == 0

    # --- Check SC-3: Norm analysis ---
    original_norm = bundle.shares[i].norm_inf()
    updated_norm = updated_shares[i].norm_inf()
    norm_ratio = updated_norm / max(params.gamma1, 1)
    sc3_acceptable = updated_norm <= params.gamma1

    # Lagrange coefficient norms
    lag_norms = compute_lagrange_norms(bundle.threshold, subset_points, q)
    max_lag = max(lag_norms)

    return SCRLCheckResult(
        sc1_holds=sc1_holds,
        sc2_holds=sc2_holds,
        sc3_norm_ratio=norm_ratio,
        sc3_acceptable=sc3_acceptable,
        reconstruction_error=recon_error,
        original_norm=original_norm,
        updated_norm=updated_norm,
        lagrange_max_norm=max_lag,
    )


def norm_explosion_analysis(params: Params, threshold: int, n_shares: int,
                             eval_points: list[int] | None = None) -> dict:
    """
    Analyze Lagrange coefficient norms for the given parameter set.

    This is the key Phase 1 diagnostic: how much do Lagrange coefficients
    amplify share norms? If the amplification factor is > γ₁/η, the
    rerandomized shares cannot be used for signing.

    Returns a dict with:
      'lagrange_norms': list of |λᵢ|
      'max_lagrange': maximum |λᵢ|
      'amplification_factor': max |λᵢ| (relative to 1)
      'norm_bound_secret': η (original share bound)
      'norm_bound_signing': γ₁ (signing/mask bound)
      'explosion_ratio': max_lagrange / (gamma1 / eta) — must be < 1 to be viable
    """
    q = params.q
    if eval_points is None:
        eval_points = list(range(1, threshold + 1))  # Use first t points

    lag_norms = compute_lagrange_norms(threshold, eval_points, q)
    max_lag = max(lag_norms)

    return {
        "lagrange_norms": lag_norms,
        "max_lagrange": max_lag,
        "amplification_factor": max_lag,
        "norm_bound_secret": params.eta,
        "norm_bound_signing": params.gamma1,
        "explosion_ratio": max_lag / (params.gamma1 / max(params.eta, 1)),
        "viable": max_lag <= params.gamma1 // params.eta,
    }
