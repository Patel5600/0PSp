"""
0PSP — Post-Quantum Private Spend Primitive
src/core/params.py

Module-LWE parameter sets mirroring Dilithium-III (FIPS 204 / ML-DSA-65).
All parameters are research defaults — NOT a security-reviewed parameter choice.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class Params:
    """
    Parameter set for a 0PSP scheme instance.

    Attributes
    ----------
    n : int
        Polynomial ring dimension. xⁿ + 1 must be cyclotomic.
        Dilithium uses n=256. NTT requires q ≡ 1 (mod 2n).
    q : int
        Prime modulus. For Dilithium: 8380417 = 2²³ - 2⁷ + 1.
        Satisfies q ≡ 1 (mod 512) so NTT of length 512 is supported.
    k : int
        Module rank (output dimension of A). Dilithium-III: k=6.
    ell : int
        Module rank (input dimension / secret dimension). Dilithium-III: ℓ=5.
    eta : int
        Coefficient bound for secret and error sampling. Dilithium-III: η=4.
    gamma1 : int
        Masking vector bound (commitment randomness). Dilithium-III: γ₁=2¹⁷.
    gamma2 : int
        Low-order rounding bound. Dilithium-III: γ₂=(q-1)/32.
    tau : int
        Challenge polynomial weight (number of ±1 coefficients). Dilithium-III: τ=49.
    beta : int
        Rejection bound for signatures: β = τ·η.
    omega : int
        Maximum number of ones in hint vector. Dilithium-III: ω=55.
    security_bits : int
        Target security level in bits (post-quantum).
    """
    n: int
    q: int
    k: int
    ell: int
    eta: int
    gamma1: int
    gamma2: int
    tau: int
    beta: int
    omega: int
    security_bits: int

    def __post_init__(self) -> None:
        """Verify necessary conditions hold."""
        # NTT requirement: q ≡ 1 (mod 2n)
        assert (self.q - 1) % (2 * self.n) == 0, (
            f"NTT condition failed: q-1={self.q-1} must be divisible by 2n={2*self.n}"
        )
        # β must be consistent
        assert self.beta == self.tau * self.eta, (
            f"Beta mismatch: beta={self.beta} ≠ tau*eta={self.tau*self.eta}"
        )
        # q must be prime (basic check — not Miller-Rabin)
        assert self.q > 1, "q must be > 1"

    @property
    def ring_description(self) -> str:
        return f"Z[x]/(x^{self.n}+1, {self.q})"

    @property
    def module_description(self) -> str:
        return f"R_q^{self.k}×{self.ell} where R_q = {self.ring_description}"


# ---------------------------------------------------------------------------
# Standard parameter sets
# ---------------------------------------------------------------------------

#: ML-DSA-44 (FIPS 204 / NIST Security Level 2)
ML_DSA_44 = Params(
    n=256,
    q=8_380_417,
    k=4,
    ell=4,
    eta=2,
    gamma1=2**17,     # 131,072
    gamma2=(8_380_417 - 1) // 88,  # 95,232
    tau=39,
    beta=39 * 2,       # τ·η = 78
    omega=80,
    security_bits=128,
)

#: ML-DSA-65 (FIPS 204 / Dilithium-III / NIST Security Level 3)
ML_DSA_65 = Params(
    n=256,
    q=8_380_417,
    k=6,
    ell=5,
    eta=4,
    gamma1=2**19,     # 524,288 (Note: FIPS 204 standard value, not 2^17)
    gamma2=(8_380_417 - 1) // 32,  # 261,888
    tau=49,
    beta=49 * 4,       # τ·η = 196
    omega=55,
    security_bits=192,
)

#: Backwards compatibility alias
DILITHIUM3 = ML_DSA_65

#: Smaller research parameter set for rapid testing (NOT secure)
#: n=64 to allow fast experiments; DO NOT use for security evaluations
RESEARCH_SMALL = Params(
    n=64,
    q=8_380_417,      # Same modulus, smaller ring
    k=2,
    ell=2,
    eta=2,
    gamma1=2**10,
    gamma2=(8_380_417 - 1) // 32,
    tau=17,
    beta=17 * 2,       # τ·η = 34
    omega=8,
    security_bits=0,   # Explicitly 0: not intended for security use
)


def default_params() -> Params:
    """Return the default research parameter set (Dilithium-III)."""
    return DILITHIUM3
