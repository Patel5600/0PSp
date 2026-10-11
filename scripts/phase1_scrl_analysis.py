"""
0PSP Phase 1 Experiment: SCRL Feasibility and Norm Explosion Analysis
scripts/phase1_scrl_analysis.py

This is the core Phase 1 investigation script.

It runs:
  1. Lagrange coefficient norm analysis for (t,n) threshold configurations
  2. Shamir reconstruction correctness test
  3. Norm explosion measurement for various eval point choices
  4. Preliminary SCRL condition checks

Run with:
  python scripts/phase1_scrl_analysis.py

Interpret the output against the criteria in:
  docs/theory/phase1-scrl-attack.md
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.params import RESEARCH_SMALL, DILITHIUM3, Params
from src.core.sampling import (
    make_rng,
    sample_secret,
    sample_uniform_matrix,
    shamir_share,
    shamir_reconstruct,
    compute_lagrange_norms,
)
from src.core.ring import _mod_center
from src.primitives.rerandomize import (
    keygen,
    share_key,
    rerandomize_key,
    norm_explosion_analysis,
)
from src.primitives.nullifier import (
    CoinId,
    compute_nullifier,
    detect_double_spend,
    NullifierSet,
)


SEP = "─" * 72


def section(title: str) -> None:
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


def result(label: str, value, ok: bool | None = None) -> None:
    status = ""
    if ok is True:
        status = " ✓"
    elif ok is False:
        status = " ✗ PROBLEM"
    print(f"  {label:<45} {value}{status}")


# ---------------------------------------------------------------------------
# Experiment 1: Lagrange Coefficient Norm Analysis
# ---------------------------------------------------------------------------

def experiment_lagrange_norms(params: Params) -> None:
    """
    For each (threshold, n_shares) configuration, compute the Lagrange
    coefficient norms. Report whether norm explosion makes rerandomization
    infeasible for signing.

    The key metric: max|λᵢ| · η ≤ γ₁?
    If yes: rerandomized shares might remain within signing bounds.
    If no: rerandomization causes norm explosion; construction fails here.
    """
    section("Experiment 1: Lagrange Coefficient Norm Analysis")
    print(f"  Parameters: n={params.n}, q={params.q}, η={params.eta}, γ₁={params.gamma1}")
    print()

    configs = [
        (2, 3, "2-of-3"),
        (3, 5, "3-of-5"),
        (5, 9, "5-of-9"),
        (2, 5, "2-of-5"),
    ]

    print(f"  {'Config':<10} {'max|λ|':>15} {'max|λ|·η':>12} {'γ₁':>12} {'Viable?':>10}")
    print(f"  {'-'*10} {'-'*15} {'-'*12} {'-'*12} {'-'*10}")

    for threshold, n_shares, label in configs:
        eval_points = list(range(1, threshold + 1))
        analysis = norm_explosion_analysis(params, threshold, n_shares, eval_points)
        max_lam = analysis["max_lagrange"]
        amplified = max_lam * params.eta
        viable = amplified <= params.gamma1
        print(f"  {label:<10} {max_lam:>15} {amplified:>12} {params.gamma1:>12} {'YES' if viable else 'NO':>10}")

    print()
    print("  Interpretation:")
    print("  If max|λ|·η > γ₁, rerandomized shares are too large for signing.")
    print("  This does NOT rule out SCRL — it means this eval point choice fails.")
    print("  NTT-compatible eval points (powers of 2n-th root of unity) may differ.")


# ---------------------------------------------------------------------------
# Experiment 2: Shamir Reconstruction Correctness
# ---------------------------------------------------------------------------

def experiment_shamir_correctness(params: Params) -> None:
    """
    Verify that Shamir sharing and reconstruction are correct for our
    coordinate-wise implementation over Rq.
    """
    section("Experiment 2: Shamir Sharing / Reconstruction Correctness")
    print(f"  Parameters: n={params.n}, q={params.q}, ℓ={params.ell}")
    print()

    rng = make_rng(b"phase1-correctness-test-0")
    secret = sample_secret(params, rng)
    original_norm = secret.norm_inf()

    for threshold, n_shares, label in [(2, 3, "2-of-3"), (3, 5, "3-of-5")]:
        shares, eval_points = shamir_share(secret, threshold, n_shares, rng=rng)

        # Reconstruct from first t shares
        subset = shares[:threshold]
        subset_pts = eval_points[:threshold]
        reconstructed = shamir_reconstruct(subset, subset_pts, params)

        error = (reconstructed - secret).norm_inf()
        share_norm = max(sh.norm_inf() for sh in shares[:threshold])
        lag_norms = compute_lagrange_norms(threshold, subset_pts, params.q)
        max_lam = max(lag_norms)

        print(f"  {label}:")
        result("  Reconstruction error ‖recon - secret‖∞", error, ok=(error == 0))
        result("  Original secret norm ‖s‖∞", original_norm)
        result("  Share norm ‖shᵢ‖∞ (unrecombined)", share_norm)
        result("  Max Lagrange coefficient |λᵢ|", max_lam)
        result("  Reconstructed vector norm", reconstructed.norm_inf())
        print()

    print("  Note: Reconstruction may be EXACT even when shares are not short.")
    print("  The signing problem arises from large Lagrange coefficients amplifying")
    print("  share norms during the SIGNING step (Fiat-Shamir), not reconstruction.")


# ---------------------------------------------------------------------------
# Experiment 3: NTT Root of Unity Eval Points
# ---------------------------------------------------------------------------

def experiment_ntt_eval_points(params: Params) -> None:
    """
    Test whether using NTT-compatible evaluation points (powers of ζ where
    ζ is a primitive 2n-th root of unity mod q) reduces Lagrange norms
    compared to naive {1, 2, ..., n} eval points.
    """
    section("Experiment 3: NTT-Compatible Evaluation Points")
    print(f"  q = {params.q}, n = {params.n}")
    print(f"  Checking q ≡ 1 (mod {2*params.n})... ", end="")

    ntt_compatible = (params.q - 1) % (2 * params.n) == 0
    print("YES" if ntt_compatible else "NO — NTT not supported for this n")

    if not ntt_compatible:
        print("  Skipping NTT eval point test.")
        return

    import sympy
    print(f"  Finding primitive root of q={params.q}... ", end="", flush=True)
    try:
        g = sympy.primitive_root(params.q)
        print(f"g = {g}")
    except Exception as e:
        print(f"FAILED ({e})")
        return

    # Primitive 2n-th root of unity: ζ = g^((q-1)/(2n)) mod q
    zeta = pow(g, (params.q - 1) // (2 * params.n), params.q)
    print(f"  Primitive {2*params.n}-th root of unity ζ = {zeta}")

    # Generate NTT eval points: ζ¹, ζ², ..., ζᵗ
    threshold = 2
    ntt_points = []
    power = zeta
    for _ in range(threshold):
        ntt_points.append(power)
        power = (power * zeta) % params.q
    naive_points = list(range(1, threshold + 1))

    lag_naive = compute_lagrange_norms(threshold, naive_points, params.q)
    lag_ntt = compute_lagrange_norms(threshold, ntt_points, params.q)

    print()
    print(f"  2-of-t Lagrange norms comparison (threshold={threshold}):")
    result("  Naive eval {1,...,t}: max|λ|", max(lag_naive))
    result("  NTT eval points: max|λ|", max(lag_ntt))
    q_half = params.q // 2
    result("  q/2 (maximum possible centered norm)", q_half)

    if max(lag_ntt) < max(lag_naive):
        print("\n  ✓ NTT eval points REDUCE Lagrange norms. This is promising.")
    else:
        print("\n  ✗ NTT eval points do not reduce norms for this threshold.")
        print("    The norm explosion problem persists regardless of eval point choice.")
        print("    This is evidence that Direction A (NTT-domain Shamir) alone is")
        print("    insufficient to resolve the SCRL obstacle.")


# ---------------------------------------------------------------------------
# Experiment 4: Nullifier Correctness and Double-Spend Detection
# ---------------------------------------------------------------------------

def experiment_nullifier(params: Params) -> None:
    """
    Verify nullifier determinism, consistency, and double-spend detection.
    """
    section("Experiment 4: Nullifier Correctness")

    rng = make_rng(b"phase1-nullifier-test-0")
    secret = sample_secret(params, rng)

    coin1 = CoinId(b"coin-alice-0001")
    coin2 = CoinId(b"coin-alice-0002")
    coin3 = CoinId(b"coin-bob-0001")

    nul1a = compute_nullifier(secret, coin1)
    nul1b = compute_nullifier(secret, coin1)  # same call → same result
    nul2 = compute_nullifier(secret, coin2)
    nul3 = compute_nullifier(secret, coin3)

    print()
    result("  nul(sk, coin1) deterministic (nul1a == nul1b)",
           nul1a == nul1b, ok=(nul1a == nul1b))
    result("  nul(sk, coin1) ≠ nul(sk, coin2)",
           nul1a != nul2, ok=(nul1a != nul2))
    result("  nul(sk, coin2) ≠ nul(sk, coin3)",
           nul2 != nul3, ok=(nul2 != nul3))

    # Double-spend detection
    ledger = NullifierSet()
    r1 = ledger.try_spend(nul1a)
    r2 = ledger.try_spend(nul1b)  # Same nullifier = double-spend
    r3 = ledger.try_spend(nul2)

    print()
    result("  First spend of coin1 accepted", r1, ok=r1)
    result("  Second spend of coin1 rejected (double-spend)", not r2, ok=(not r2))
    result("  First spend of coin2 accepted", r3, ok=r3)
    result("  Nullifiers in ledger", len(ledger))

    print()
    print("  NOTE: This nullifier uses SHAKE-256 as a placeholder PRF.")
    print("  Production requires a lattice-based PRF (BPR/LWR) for formal")
    print("  security reduction. Threshold compatibility (one nullifier per")
    print("  coin without key reconstruction) is an open problem.")


# ---------------------------------------------------------------------------
# Experiment 5: Key Rerandomization
# ---------------------------------------------------------------------------

def experiment_rerandomization(params: Params) -> None:
    """
    Test key rerandomization: pk' = (A, t + r).
    Check that t' ≠ t (different keys) and that the shift is measurable.
    """
    section("Experiment 5: Key Rerandomization")

    rng = make_rng(b"phase1-rerand-test-0")
    sk, pk = keygen(params, rng)

    rerand = rerandomize_key(pk, rng=rng)
    pk_prime = rerand.pk_prime

    # t' = t + r; they should differ
    t_diff = (pk_prime.t - pk.t).norm_inf()
    t_diff_r = (pk_prime.t - pk.t - rerand.r).norm_inf()

    print()
    result("  ‖pk'.t - pk.t‖∞ (shift applied)", t_diff, ok=(t_diff > 0))
    result("  ‖(pk'.t - pk.t) - r‖∞ (additive consistency)", t_diff_r, ok=(t_diff_r == 0))
    result("  pk.t norm_inf", pk.t.norm_inf())
    result("  pk'.t norm_inf", pk_prime.t.norm_inf())
    result("  r norm_inf", rerand.r.norm_inf())

    print()
    print("  OPEN PROBLEM: share update for rerandomized pk.")
    print("  The update_share function raises NotImplementedError for k≠ℓ")
    print("  because computing A⁺r requires solving an MSIS instance.")
    print("  This is the central Phase 1 research challenge.")

    # Attempt share update if params support it (k == ell)
    if params.k == params.ell:
        bundle = share_key(sk, pk, threshold=2, n_shares=3, rng=rng)
        print()
        print("  k == ℓ: Attempting simplified share update...")
        from src.primitives.rerandomize import update_share, check_scrl
        try:
            result_data = check_scrl(sk, pk, bundle, [0, 1], 3)
            result("  SC-1 (A·sh'ᵢ = A·shᵢ + r)", result_data.sc1_holds, ok=result_data.sc1_holds)
            result("  SC-2 (Lagrange recon correct)", result_data.sc2_holds, ok=result_data.sc2_holds)
            result("  SC-3 (norm acceptable)", result_data.sc3_acceptable, ok=result_data.sc3_acceptable)
            result("  Original share norm", result_data.original_norm)
            result("  Updated share norm", result_data.updated_norm)
            result("  Norm ratio (updated/γ₁)", f"{result_data.sc3_norm_ratio:.4f}")
            result("  Max Lagrange coefficient", result_data.lagrange_max_norm)
        except Exception as e:
            print(f"  SCRL check error: {e}")
    else:
        print(f"  k={params.k} ≠ ℓ={params.ell}: simplified share update not attempted.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("=" * 72)
    print("  0PSP Phase 1: SCRL Feasibility Analysis")
    print("  Post-Quantum Private Spend Primitive — Mathematical Core Attack")
    print("=" * 72)

    # Use small params for fast experiments
    print("\n  [Using RESEARCH_SMALL params for fast experiments]")
    print(f"  n={RESEARCH_SMALL.n}, q={RESEARCH_SMALL.q}, k={RESEARCH_SMALL.k}, ℓ={RESEARCH_SMALL.ell}")
    print(f"  η={RESEARCH_SMALL.eta}, γ₁={RESEARCH_SMALL.gamma1}")
    print("\n  WARNING: RESEARCH_SMALL has security_category=0. Research-only parameters, not for security use.")

    params = RESEARCH_SMALL

    experiment_lagrange_norms(params)
    experiment_shamir_correctness(params)
    experiment_ntt_eval_points(params)
    experiment_nullifier(params)
    experiment_rerandomization(params)

    section("Summary of Phase 1 Findings")
    print("""
  The following questions remain open after this analysis:

  Q1 (SCRL feasibility):
     Can Lagrange norm explosion be avoided by NTT-compatible eval points?
     → Measured above. Compare max|λ| vs γ₁/η for your parameter choice.

  Q2 (Share update construction):
     Is there a short-vector solution to A·z = r (MSIS-like)?
     → This would give a correct update_share. Currently NotImplemented.

  Q3 (Simultaneous conditions):
     Can SC-1, SC-2, SC-3, and SC-4 be satisfied simultaneously?
     → SC-4 (indistinguishability) requires a formal MLWE reduction.
        This cannot be tested numerically — requires a proof.

  Q4 (Threshold + Anonymity composition):
     Does the SCRL-based scheme preserve anonymity under Game 2?
     → Requires the full security composition proof (Phase 2).

  Next action:
     Review the Lagrange norm data above. If max|λ|·η ≤ γ₁ for some
     eval point choice, proceed to attempt the SC-1/SC-2 algebraic proof.
     If not, evaluate Direction C (KEM-based rerandomization) as fallback.
""")


if __name__ == "__main__":
    main()
