"""
0PSP — Post-Quantum Private Spend Primitive
src/core/ring.py

Arithmetic in Rq = Zq[x]/(x^n + 1).

This module provides:
  - RingElem: a polynomial in Rq
  - NTT / INTT: Negacyclic Number Theoretic Transform (Cooley-Tukey / Gentleman-Sande)
  - ModuleVec: a vector of ring elements (element of Rq^d)
  - ModuleMatrix: a matrix of ring elements (element of Rq^{k×ℓ})

All operations are for research and correctness verification.
Efficiency is secondary to clarity in this implementation.

NTT reference:
  Bos et al., "CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM" §1.1
  Ducas et al., "CRYSTALS-Dilithium: Algorithm Specification" v3.1 §1.2
  NIST FIPS 204 §5 (ML-DSA)

The negacyclic NTT evaluates f(x) at the n roots of x^n + 1 = (x - ζ)(x - ζ³)…(x - ζ^{2n-1})
where ζ is a primitive 2n-th root of unity. Pointwise multiplication then
corresponds to multiplication mod x^n + 1.
"""

from __future__ import annotations

import sympy
from typing import Sequence
from dataclasses import dataclass, field

from .params import Params, DILITHIUM3


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _mod_center(a: int, q: int) -> int:
    """Reduce a mod q into the centered range (-q/2, q/2]."""
    r = a % q
    if r > q // 2:
        r -= q
    return r


def _ntt_primitive_root_of_unity(n: int, q: int) -> int:
    """
    Find ζ such that ζ is a primitive 2n-th root of unity mod q.
    Requires q ≡ 1 (mod 2n).

    For Dilithium (n=256, q=8380417): ζ = 1753.
    """
    assert (q - 1) % (2 * n) == 0, f"q-1 must be divisible by 2n={2*n}"
    g = sympy.primitive_root(q)
    # ζ = g^((q-1)/(2n)) mod q
    return pow(int(g), (q - 1) // (2 * n), q)


# ---------------------------------------------------------------------------
# NTT implementation (Cooley-Tukey forward, Gentleman-Sande inverse)
# ---------------------------------------------------------------------------

class NTT:
    """
    Negacyclic Number Theoretic Transform over Zq for Zq[x]/(x^n+1).

    Follows the Dilithium/ML-DSA reference specification algorithm.
    Twiddle factors zetas[k] = ζ^{BitRev(k)} precomputed for k=1..n-1.
    Index 0 is unused (the first active twiddle is at index 1).

    Forward (Cooley-Tukey):
        length starts at n/2 and halves each round.
        For each butterfly block, twiddle = zetas[k], k increments.

    Inverse (Gentleman-Sande):
        length starts at 1 and doubles each round.
        For each butterfly block, twiddle = zetas_inv[k], k increments.
        The n^{-1} scaling is folded into zetas_inv.
    """

    def __init__(self, params: Params) -> None:
        self.n = params.n
        self.q = params.q
        self.zeta = _ntt_primitive_root_of_unity(params.n, params.q)
        self._zetas: list[int] = self._build_zeta_table()
        self._zetas_inv: list[int] = self._build_zeta_inv_table()

    def _bitrev(self, x: int, bits: int) -> int:
        """Reverse the 'bits'-bit binary representation of x."""
        r = 0
        for _ in range(bits):
            r = (r << 1) | (x & 1)
            x >>= 1
        return r

    def _build_zeta_table(self) -> list[int]:
        """
        zetas[k] = ζ^{BitRev_{log2(n)}(k)} mod q, for k = 0..n-1.
        Index 0 = ζ^0 = 1 (unused in the butterfly but kept for indexing).
        Index k (1-based in the algorithm) uses zetas[k].
        """
        n, q = self.n, self.q
        bits = n.bit_length() - 1
        z = self.zeta
        # powers[i] = ζ^i mod q
        powers = [1] * n
        for i in range(1, n):
            powers[i] = (powers[i - 1] * z) % q
        # zetas[k] = ζ^{br(k)}
        return [powers[self._bitrev(k, bits)] for k in range(n)]

    def _build_zeta_inv_table(self) -> list[int]:
        """
        zetas_inv[k] = ζ^{-BitRev(k)} * n^{-1} mod q.
        The n^{-1} factor handles the INTT normalization.
        """
        n, q = self.n, self.q
        bits = n.bit_length() - 1
        zeta_inv = pow(self.zeta, q - 2, q)
        powers_inv = [1] * n
        for i in range(1, n):
            powers_inv[i] = (powers_inv[i - 1] * zeta_inv) % q
        # Inverse butterflies use inverse twiddles; apply n^{-1} exactly once
        # after all stages, in inverse().
        return [powers_inv[self._bitrev(k, bits)] for k in range(n)]

    def forward(self, poly: list[int]) -> list[int]:
        """
        Cooley-Tukey forward NTT.

        Evaluates poly at the n roots ζ, ζ³, ζ⁵, …, ζ^{2n-1}
        (the roots of x^n + 1 mod q).

        Returns the NTT representation (n values in Zq).
        """
        assert len(poly) == self.n
        a = [int(x) % self.q for x in poly]
        n, q = self.n, self.q
        zetas = self._zetas

        length = n >> 1   # Start with n/2 length blocks
        k = 1             # Twiddle index (starts at 1, 0 unused)
        while length >= 1:
            for start in range(0, n, 2 * length):
                w = zetas[k]
                k += 1
                for j in range(start, start + length):
                    t = (w * a[j + length]) % q
                    a[j + length] = (a[j] - t) % q
                    a[j] = (a[j] + t) % q
            length >>= 1
        return a

    def inverse(self, ntt_poly: list[int]) -> list[int]:
        """
        Gentleman-Sande inverse NTT with n^{-1} normalization.

        Recovers poly from its NTT representation.
        """
        assert len(ntt_poly) == self.n
        a = [int(x) for x in ntt_poly]
        n, q = self.n, self.q
        zetas_inv = self._zetas_inv

        length = 1        # Invert the smallest forward-butterfly blocks first
        while length < n:
            # Forward assigns indices [n/(2L), n/L - 1] to this layer.
            # Reverse the layer order, but keep the block order within each layer.
            k = n // (2 * length)
            for start in range(0, n, 2 * length):
                w_inv = zetas_inv[k]
                k += 1
                for j in range(start, start + length):
                    t = a[j]
                    u = a[j + length]
                    a[j] = (t + u) % q
                    # Inverse of (u+w*v, u-w*v) uses (x-y)*w^{-1}.
                    a[j + length] = (w_inv * (t - u)) % q
            length <<= 1

        # Apply the overall n^{-1} scaling factor
        n_inv = pow(n, q - 2, q)
        a = [(x * n_inv) % q for x in a]
        return a


# ---------------------------------------------------------------------------
# Ring element
# ---------------------------------------------------------------------------

@dataclass
class RingElem:
    """
    An element of Rq = Zq[x]/(x^n+1).

    Coefficients are stored as a list of n integers in [0, q).
    NTT representation is cached on first use.

    Attributes
    ----------
    coeffs : list[int]
        Polynomial coefficients [a₀, a₁, …, aₙ₋₁] in standard (time) domain.
    params : Params
        Ring parameters.
    """
    coeffs: list[int]
    params: Params
    _ntt_cache: list[int] | None = field(default=None, repr=False, compare=False)
    _ntt_engine: NTT | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        assert len(self.coeffs) == self.params.n, (
            f"Expected {self.params.n} coefficients, got {len(self.coeffs)}"
        )
        self.coeffs = [int(c) % self.params.q for c in self.coeffs]

    @classmethod
    def zero(cls, params: Params) -> RingElem:
        return cls([0] * params.n, params)

    @classmethod
    def one(cls, params: Params) -> RingElem:
        coeffs = [0] * params.n
        coeffs[0] = 1
        return cls(coeffs, params)

    @classmethod
    def from_int(cls, val: int, params: Params) -> RingElem:
        """Constant polynomial."""
        coeffs = [0] * params.n
        coeffs[0] = int(val) % params.q
        return cls(coeffs, params)

    def _get_ntt(self) -> NTT:
        if self._ntt_engine is None:
            object.__setattr__(self, "_ntt_engine", NTT(self.params))
        return self._ntt_engine

    @property
    def ntt(self) -> list[int]:
        """NTT representation (cached)."""
        if self._ntt_cache is None:
            object.__setattr__(self, "_ntt_cache", self._get_ntt().forward(self.coeffs))
        return self._ntt_cache

    def _invalidate_cache(self) -> None:
        object.__setattr__(self, "_ntt_cache", None)

    def __add__(self, other: RingElem) -> RingElem:
        assert self.params == other.params
        q = self.params.q
        return RingElem([(a + b) % q for a, b in zip(self.coeffs, other.coeffs)], self.params)

    def __sub__(self, other: RingElem) -> RingElem:
        assert self.params == other.params
        q = self.params.q
        return RingElem([(a - b) % q for a, b in zip(self.coeffs, other.coeffs)], self.params)

    def __neg__(self) -> RingElem:
        q = self.params.q
        return RingElem([(-c) % q for c in self.coeffs], self.params)

    def __mul__(self, other: RingElem | int) -> RingElem:
        """Multiply two ring elements (via NTT point-wise, or scalar multiply)."""
        if isinstance(other, int):
            q = self.params.q
            return RingElem([(c * other) % q for c in self.coeffs], self.params)
        assert self.params == other.params
        ntt = self._get_ntt()
        # Point-wise multiplication in NTT domain, then INTT
        product_ntt = [(a * b) % self.params.q for a, b in zip(self.ntt, other.ntt)]
        result_coeffs = ntt.inverse(product_ntt)
        return RingElem(result_coeffs, self.params)

    def __rmul__(self, scalar: int) -> RingElem:
        return self.__mul__(scalar)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RingElem):
            return NotImplemented
        return self.coeffs == other.coeffs and self.params == other.params

    def norm_inf(self) -> int:
        """L∞ norm of centered coefficients."""
        q = self.params.q
        return max(abs(_mod_center(c, q)) for c in self.coeffs)

    def norm_l2_sq(self) -> int:
        """Squared L2 norm of centered coefficients."""
        q = self.params.q
        return sum(_mod_center(c, q) ** 2 for c in self.coeffs)

    def __repr__(self) -> str:
        n_terms = min(4, self.params.n)
        terms = " + ".join(f"{c}·x^{i}" for i, c in enumerate(self.coeffs[:n_terms]) if c)
        return f"RingElem([{terms}…], n={self.params.n}, q={self.params.q})"


# ---------------------------------------------------------------------------
# Module (vector of ring elements)
# ---------------------------------------------------------------------------

class ModuleVec:
    """
    A vector of ring elements: an element of Rq^d.
    """

    def __init__(self, elems: Sequence[RingElem]) -> None:
        assert len(elems) > 0
        params = elems[0].params
        assert all(e.params == params for e in elems), "All elements must share params"
        self.elems: list[RingElem] = list(elems)
        self.params = params
        self.dim = len(elems)

    @classmethod
    def zero(cls, dim: int, params: Params) -> ModuleVec:
        return cls([RingElem.zero(params)] * dim)

    def __add__(self, other: ModuleVec) -> ModuleVec:
        assert self.dim == other.dim
        return ModuleVec([a + b for a, b in zip(self.elems, other.elems)])

    def __sub__(self, other: ModuleVec) -> ModuleVec:
        assert self.dim == other.dim
        return ModuleVec([a - b for a, b in zip(self.elems, other.elems)])

    def __neg__(self) -> ModuleVec:
        return ModuleVec([-e for e in self.elems])

    def __mul__(self, scalar: int) -> ModuleVec:
        return ModuleVec([e * scalar for e in self.elems])

    def __rmul__(self, scalar: int) -> ModuleVec:
        return self.__mul__(scalar)

    def norm_inf(self) -> int:
        return max(e.norm_inf() for e in self.elems)

    def norm_l2_sq(self) -> int:
        return sum(e.norm_l2_sq() for e in self.elems)

    def __repr__(self) -> str:
        return f"ModuleVec(dim={self.dim}, norm_inf={self.norm_inf()})"


class ModuleMatrix:
    """
    A k×ℓ matrix of ring elements: an element of Rq^{k×ℓ}.
    Rows index k (output), columns index ℓ (input).
    """

    def __init__(self, rows: Sequence[ModuleVec]) -> None:
        assert len(rows) > 0
        dim = rows[0].dim
        assert all(r.dim == dim for r in rows), "All rows must have the same dimension"
        self.rows: list[ModuleVec] = list(rows)
        self.k = len(rows)     # output dimension
        self.ell = dim          # input dimension
        self.params = rows[0].params

    def mul_vec(self, v: ModuleVec) -> ModuleVec:
        """Matrix-vector product: A·v ∈ Rq^k."""
        assert v.dim == self.ell, f"Dimension mismatch: A is {self.k}×{self.ell}, v has dim {v.dim}"
        result = []
        for row in self.rows:
            # Dot product of row (dim ℓ) with v (dim ℓ)
            acc = RingElem.zero(self.params)
            for a, b in zip(row.elems, v.elems):
                acc = acc + (a * b)
            result.append(acc)
        return ModuleVec(result)

    def __repr__(self) -> str:
        return f"ModuleMatrix(k={self.k}, ell={self.ell})"
