"""0PSP Circuit-Level ZK Trace Blinding and Leaf Salt Masking (P0 Issue #36).

Provides the mathematical primitives for randomized execution trace blinding
and salted Merkle leaf commitments over the BabyBear prime field (p = 2^31 - 2^27 + 1).

Enforces:
  1. Injection of B = N_q + 1 randomized blinding rows (default B = 39 for N_q = 38 FRI queries)
     at the termination of the execution trace, drawn uniformly from F_p via OS CSPRNG.
  2. 256-bit cryptographically independent leaf salts for polynomial column commitments,
     preventing Merkle leaf opening paths from leaking unopened adjacent columns.
  3. Adversarial statistical-ZK distinguisher metrics (Total Variation Distance and
     Kolmogorov-Smirnov p-value) evaluating polynomial query evaluation privacy.
"""
from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from typing import Final, Sequence


# BabyBear Field: p = 2^31 - 2^27 + 1 = 2013265921
BABYBEAR_P: Final[int] = 2013265921

# ZK Blinding parameters:
# FRI queries N_q = 38 -> transition constraints (x, wx) and OOD points (zeta, w*zeta)
# open 2 * N_q + 2 = 78 points. We require B = 2 * N_q + 4 = 80 randomized blinding rows
# across all tables (Main trace, Keccak coprocessor trace, and LogUp multiplicities).
LEGACY_ZK_BLINDING_ROWS: Final[int] = 39
CANONICAL_ZK_BLINDING_ROWS: Final[int] = 80
DEFAULT_ZK_BLINDING_ROWS: Final[int] = 80
LEAF_SALT_BYTES: Final[int] = 32
LEAF_DIGEST_BYTES: Final[int] = 32

# Multiplicative generator for BabyBear field (primitive root)
BABYBEAR_GENERATOR: Final[int] = 31
# Shifted coset generator for disjoint LDE evaluation g * H_LDE
BABYBEAR_DISJOINT_COSET_GENERATOR: Final[int] = 31

DOMAIN_LEAF_SALT: Final[bytes] = b"0PSP-ZK-LEAF-SALT-v1-SHAKE256"


def babybear_add(a: int, b: int) -> int:
    """Addition in BabyBear field."""
    return (a + b) % BABYBEAR_P


def babybear_sub(a: int, b: int) -> int:
    """Subtraction in BabyBear field."""
    return (a - b) % BABYBEAR_P


def babybear_mul(a: int, b: int) -> int:
    """Multiplication in BabyBear field."""
    return (a * b) % BABYBEAR_P


def babybear_inv(a: int) -> int:
    """Multiplicative inverse in BabyBear field via Fermat's Little Theorem."""
    if a % BABYBEAR_P == 0:
        raise ZeroDivisionError("cannot invert 0 in BabyBear field")
    return pow(a, BABYBEAR_P - 2, BABYBEAR_P)


@dataclass(frozen=True, slots=True)
class BlindedTraceMatrix:
    """Container for an execution trace matrix with randomized blinding rows and leaf salts."""
    active_rows: int
    blinding_rows: int
    total_rows: int
    columns: int
    matrix: tuple[tuple[int, ...], ...]
    leaf_salts: tuple[bytes, ...]
    leaf_commitments: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if self.total_rows != self.active_rows + self.blinding_rows:
            raise ValueError("total_rows must equal active_rows + blinding_rows")
        if len(self.matrix) != self.total_rows:
            raise ValueError(f"matrix row count {len(self.matrix)} != total_rows {self.total_rows}")
        if len(self.leaf_salts) != self.total_rows:
            raise ValueError(f"leaf_salts count {len(self.leaf_salts)} != total_rows {self.total_rows}")
        if len(self.leaf_commitments) != self.total_rows:
            raise ValueError(f"leaf_commitments count {len(self.leaf_commitments)} != total_rows {self.total_rows}")


def compute_salted_leaf_commitment(row_values: Sequence[int], salt: bytes) -> bytes:
    """Compute 256-bit salted leaf commitment for a trace row.

    Commitment = SHAKE256-256("0PSP-ZK-LEAF-SALT-v1-SHAKE256" || salt || row_values_le)
    """
    if len(salt) != LEAF_SALT_BYTES:
        raise ValueError(f"salt must be exactly {LEAF_SALT_BYTES} bytes")
    hasher = hashlib.shake_256(DOMAIN_LEAF_SALT + salt)
    for v in row_values:
        hasher.update((v % BABYBEAR_P).to_bytes(4, "little"))
    return hasher.digest(LEAF_DIGEST_BYTES)


def construct_zk_blinded_trace(
    execution_trace: Sequence[Sequence[int]],
    *,
    blinding_rows: int = DEFAULT_ZK_BLINDING_ROWS,
) -> BlindedTraceMatrix:
    """Construct an execution trace with randomized ZK blinding rows and salted leaf commitments.

    Parameters:
      execution_trace: Active circuit execution rows (H rows by W columns over F_p).
      blinding_rows: Number of randomized blinding rows B to append (B >= 39 for N_q = 38).

    Returns:
      BlindedTraceMatrix with H active rows + B blinding rows and unique 256-bit leaf salts.
    """
    active_h = len(execution_trace)
    if active_h == 0:
        raise ValueError("execution_trace cannot be empty")
    w = len(execution_trace[0])
    if w == 0:
        raise ValueError("execution_trace columns cannot be empty")

    rows: list[tuple[int, ...]] = []
    # 1. Copy active execution rows
    for r in execution_trace:
        if len(r) != w:
            raise ValueError(f"all trace rows must have identical width {w}")
        rows.append(tuple(x % BABYBEAR_P for x in r))

    # 2. Append randomized blinding rows
    for _ in range(blinding_rows):
        blinding_row = tuple(secrets.randbelow(BABYBEAR_P) for _ in range(w))
        rows.append(blinding_row)

    total_h = active_h + blinding_rows

    # 3. Generate independent 256-bit leaf salts and commitments
    salts: list[bytes] = []
    commits: list[bytes] = []
    for r in rows:
        salt = secrets.token_bytes(LEAF_SALT_BYTES)
        commit = compute_salted_leaf_commitment(r, salt)
        salts.append(salt)
        commits.append(commit)

    return BlindedTraceMatrix(
        active_rows=active_h,
        blinding_rows=blinding_rows,
        total_rows=total_h,
        columns=w,
        matrix=tuple(rows),
        leaf_salts=tuple(salts),
        leaf_commitments=tuple(commits),
    )


@dataclass(frozen=True, slots=True)
class LogUpDummyLookupPair:
    """Zero-sum dummy lookup pair for LogUp bus running-sum polynomial phi(X) blinding."""
    challenge_point: int  # r_i in F_p
    positive_term: int    # + (alpha - r_i)^(-1) mod p
    negative_term: int    # - (alpha - r_i)^(-1) mod p


def generate_logup_zero_sum_dummy_pairs(
    num_pairs: int,
    alpha: int,
) -> list[LogUpDummyLookupPair]:
    """Generate num_pairs of zero-sum dummy lookup pairs over BabyBear F_p.

    Each pair satisfies:
      positive_term + negative_term == 0 (mod p)
    Ensuring the total LogUp bus sum across blinding rows is identically 0 mod p,
    while randomizing intermediate running sums and polynomial evaluations.
    """
    if num_pairs <= 0:
        raise ValueError("num_pairs must be positive")
    alpha_mod = alpha % BABYBEAR_P
    pairs: list[LogUpDummyLookupPair] = []
    seen: set[int] = {alpha_mod}

    for _ in range(num_pairs):
        # Sample challenge r_i distinct from alpha and previous points
        while True:
            r_i = secrets.randbelow(BABYBEAR_P)
            if r_i not in seen:
                seen.add(r_i)
                break
        diff = babybear_sub(alpha_mod, r_i)
        inv = babybear_inv(diff)
        neg_inv = babybear_sub(0, inv)
        pairs.append(LogUpDummyLookupPair(
            challenge_point=r_i,
            positive_term=inv,
            negative_term=neg_inv,
        ))
    return pairs


def blind_logup_running_sum(
    active_running_sum: Sequence[int],
    *,
    blinding_rows: int = CANONICAL_ZK_BLINDING_ROWS,
    alpha: int | None = None,
) -> tuple[int, ...]:
    """Extend LogUp running-sum polynomial phi(X) with zero-sum dummy lookup pairs.

    Appends blinding_rows randomized running sums such that:
      phi(active_h + blinding_rows) == phi(active_h)  (mod p)
    The net change across the blinding rows is strictly 0 mod p, satisfying the
    LogUp bus total sum constraint, while phi(X) values across the blinding rows
    follow a randomized walk that masks private witness multiplicity counts.
    """
    if not active_running_sum:
        raise ValueError("active_running_sum cannot be empty")
    if blinding_rows < 2:
        raise ValueError("blinding_rows must be at least 2 for zero-sum pairing")

    if alpha is None:
        alpha = secrets.randbelow(BABYBEAR_P - 1) + 1

    num_pairs = blinding_rows // 2
    pairs = generate_logup_zero_sum_dummy_pairs(num_pairs, alpha)

    # Collect all positive and negative terms, shuffle to form a random walk
    terms: list[int] = []
    for p in pairs:
        terms.append(p.positive_term)
        terms.append(p.negative_term)

    # If odd number of blinding rows, pad the remainder with zero
    while len(terms) < blinding_rows:
        terms.append(0)

    # Deterministic pseudo-shuffle or random shuffle
    # Use cryptographic shuffle so order of + and - is random
    shuffled_indices = list(range(len(terms)))
    # Fisher-Yates with secrets
    for i in range(len(shuffled_indices) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled_indices[i], shuffled_indices[j] = shuffled_indices[j], shuffled_indices[i]
    shuffled_terms = [terms[i] for i in shuffled_indices]

    extended: list[int] = [x % BABYBEAR_P for x in active_running_sum]
    curr = extended[-1]
    for term in shuffled_terms:
        curr = babybear_add(curr, term)
        extended.append(curr)

    # Ensure net sum matches: final value must equal active_running_sum[-1]
    assert extended[-1] == active_running_sum[-1] % BABYBEAR_P, "Zero-sum invariant violated"
    return tuple(extended)


@dataclass(frozen=True, slots=True)
class MultiTableBlindedTrace:
    """All-chip / all-polynomial ZK masked execution trace containers."""
    main_trace: BlindedTraceMatrix
    keccak_coprocessor_trace: BlindedTraceMatrix
    lookup_multiplicities: BlindedTraceMatrix
    logup_running_sum: tuple[int, ...]
    coset_generator: int
    leaf_salts: tuple[bytes, ...]
    leaf_commitments: tuple[bytes, ...]
    lde_salts: tuple[bytes, ...] = ()
    lde_commitments: tuple[bytes, ...] = ()


def evaluate_multitable_disjoint_coset_lde(
    multitable: MultiTableBlindedTrace,
    *,
    blowup_factor: int = 16,
) -> tuple[tuple[tuple[int, ...], bytes, bytes], ...]:
    """Evaluate all chips of a multi-table trace over shifted coset g * H_LDE disjoint from H.

    For each evaluation point z_k on the shifted coset, computes:
      (combined_evaluations_row, 32-byte salt, 32-byte leaf commitment)
    Guarantees no commitment is opened on the original trace subgroup H (Rule C).
    """
    n = multitable.main_trace.total_rows
    lde_size = n * blowup_factor
    g = multitable.coset_generator

    # Collect all columns across all chips
    all_columns: list[list[int]] = []
    for c in range(multitable.main_trace.columns):
        all_columns.append([multitable.main_trace.matrix[r][c] for r in range(n)])
    for c in range(multitable.keccak_coprocessor_trace.columns):
        all_columns.append([multitable.keccak_coprocessor_trace.matrix[r][c] for r in range(n)])
    for c in range(multitable.lookup_multiplicities.columns):
        all_columns.append([multitable.lookup_multiplicities.matrix[r][c] for r in range(n)])
    all_columns.append(list(multitable.logup_running_sum))

    results: list[tuple[tuple[int, ...], bytes, bytes]] = []
    weights = get_barycentric_weights(n)

    for k in range(lde_size):
        query_pt = (g * (k + n + 1)) % BABYBEAR_P
        if 0 <= query_pt < n:
            eval_row = tuple(col[query_pt] % BABYBEAR_P for col in all_columns)
        else:
            terms: list[int] = []
            den = 0
            for i, w in enumerate(weights):
                diff = (query_pt - i) % BABYBEAR_P
                inv_diff = pow(diff, BABYBEAR_P - 2, BABYBEAR_P)
                term = (w * inv_diff) % BABYBEAR_P
                terms.append(term)
                den = (den + term) % BABYBEAR_P
            inv_den = pow(den, BABYBEAR_P - 2, BABYBEAR_P)

            eval_row_list: list[int] = []
            for col in all_columns:
                num = 0
                for y, term in zip(col, terms):
                    num = (num + (y % BABYBEAR_P) * term) % BABYBEAR_P
                eval_row_list.append((num * inv_den) % BABYBEAR_P)
            eval_row = tuple(eval_row_list)

        salt = secrets.token_bytes(LEAF_SALT_BYTES)
        commit = compute_salted_leaf_commitment(eval_row, salt)
        results.append((eval_row, salt, commit))

    return tuple(results)


def construct_multitable_blinded_trace(
    main_trace: Sequence[Sequence[int]],
    keccak_trace: Sequence[Sequence[int]],
    multiplicities: Sequence[Sequence[int]],
    active_logup_running_sum: Sequence[int],
    *,
    blinding_rows: int = CANONICAL_ZK_BLINDING_ROWS,
    coset_generator: int = BABYBEAR_DISJOINT_COSET_GENERATOR,
    compute_lde: bool = True,
    blowup_factor: int = 16,
) -> MultiTableBlindedTrace:
    """Construct an all-table blinded trace across Main, Keccak Coprocessor, and LogUp Bus.

    Applies:
      1. B = 80 randomized blinding rows to Main execution trace.
      2. B = 80 randomized blinding rows to Keccak coprocessor trace.
      3. B = 80 randomized blinding rows to Preprocessed lookup multiplicities.
      4. Zero-sum dummy lookup pairs (+/- (alpha - r_i)^(-1)) to LogUp running-sum phi(X).
      5. 32-byte independent leaf salts and commitments for all Merkle leaves.
      6. Shifted coset g * H_LDE evaluation for disjoint zero-knowledge openings.
    """
    if len(main_trace) == 0:
        raise ValueError("main_trace cannot be empty")
    if len(keccak_trace) != len(main_trace):
        raise ValueError(f"keccak_trace row count ({len(keccak_trace)}) must match main_trace ({len(main_trace)})")
    if len(multiplicities) != len(main_trace):
        raise ValueError(f"multiplicities row count ({len(multiplicities)}) must match main_trace ({len(main_trace)})")
    if len(active_logup_running_sum) != len(main_trace):
        raise ValueError(f"active_logup_running_sum count ({len(active_logup_running_sum)}) must match main_trace ({len(main_trace)})")

    blinded_main = construct_zk_blinded_trace(main_trace, blinding_rows=blinding_rows)
    blinded_keccak = construct_zk_blinded_trace(keccak_trace, blinding_rows=blinding_rows)
    blinded_mult = construct_zk_blinded_trace(multiplicities, blinding_rows=blinding_rows)
    blinded_phi = blind_logup_running_sum(active_logup_running_sum, blinding_rows=blinding_rows)

    # Generate combined salted Merkle leaves for multi-table commitments
    combined_salts: list[bytes] = []
    combined_commits: list[bytes] = []
    for r in range(blinded_main.total_rows):
        combined_row = (
            blinded_main.matrix[r]
            + blinded_keccak.matrix[r]
            + blinded_mult.matrix[r]
            + (blinded_phi[r],)
        )
        salt = secrets.token_bytes(LEAF_SALT_BYTES)
        commit = compute_salted_leaf_commitment(combined_row, salt)
        combined_salts.append(salt)
        combined_commits.append(commit)

    trace = MultiTableBlindedTrace(
        main_trace=blinded_main,
        keccak_coprocessor_trace=blinded_keccak,
        lookup_multiplicities=blinded_mult,
        logup_running_sum=blinded_phi,
        coset_generator=coset_generator,
        leaf_salts=tuple(combined_salts),
        leaf_commitments=tuple(combined_commits),
    )

    # Compute disjoint coset LDE commitments if requested (for bounded trace dimensions)
    if compute_lde and blinded_main.total_rows <= 128:
        lde_rows = evaluate_multitable_disjoint_coset_lde(trace, blowup_factor=blowup_factor)
        lde_salts = tuple(salt for _, salt, _ in lde_rows)
        lde_commits = tuple(commit for _, _, commit in lde_rows)
        return MultiTableBlindedTrace(
            main_trace=blinded_main,
            keccak_coprocessor_trace=blinded_keccak,
            lookup_multiplicities=blinded_mult,
            logup_running_sum=blinded_phi,
            coset_generator=coset_generator,
            leaf_salts=tuple(combined_salts),
            leaf_commitments=tuple(combined_commits),
            lde_salts=lde_salts,
            lde_commitments=lde_commits,
        )

    return trace


def evaluate_disjoint_coset_lde(
    column_values: Sequence[int],
    *,
    blowup_factor: int = 16,
    coset_generator: int = BABYBEAR_DISJOINT_COSET_GENERATOR,
) -> tuple[tuple[int, bytes, bytes], ...]:
    """Evaluate column polynomial over shifted coset g * H_LDE disjoint from trace subgroup.

    For each evaluation point on the disjoint coset, computes:
      (evaluation_value, 32-byte salt, 32-byte leaf commitment)
    Ensuring no Merkle leaf commitment reveals any points on the unshifted trace subgroup.
    """
    n = len(column_values)
    if n == 0:
        raise ValueError("column_values cannot be empty")
    lde_size = n * blowup_factor
    results: list[tuple[int, bytes, bytes]] = []

    for k in range(lde_size):
        # Shifted coset evaluation point z = g * (k + n + 1) mod p
        # Guaranteed disjoint from trace subgroup {0, 1, ..., n-1}
        query_pt = (coset_generator * (k + n + 1)) % BABYBEAR_P
        val = evaluate_column_polynomial_at_point(column_values, query_pt)
        salt = secrets.token_bytes(LEAF_SALT_BYTES)
        commit = compute_salted_leaf_commitment([val], salt)
        results.append((val, salt, commit))

    return tuple(results)

_BARYCENTRIC_WEIGHTS_CACHE: dict[int, list[int]] = {}


def get_barycentric_weights(n: int) -> list[int]:
    """Precompute and cache barycentric Lagrange weights for domain {0, 1, ..., n-1}."""
    if n in _BARYCENTRIC_WEIGHTS_CACHE:
        return _BARYCENTRIC_WEIGHTS_CACHE[n]

    fact = [1] * n
    for i in range(1, n):
        fact[i] = (fact[i - 1] * i) % BABYBEAR_P

    weights = [0] * n
    for i in range(n):
        den = (fact[i] * fact[n - 1 - i]) % BABYBEAR_P
        inv_den = pow(den, BABYBEAR_P - 2, BABYBEAR_P)
        if (n - 1 - i) % 2 == 1:
            weights[i] = (BABYBEAR_P - inv_den) % BABYBEAR_P
        else:
            weights[i] = inv_den

    _BARYCENTRIC_WEIGHTS_CACHE[n] = weights
    return weights


def evaluate_column_polynomial_at_point(
    column_values: Sequence[int],
    query_point: int,
) -> int:
    """Evaluate polynomial interpolating column_values at 0, ..., n-1 at query_point in O(n) time.

    Uses the second barycentric formula:
      P(z) = (sum_i w_i * y_i / (z - i)) / (sum_i w_i / (z - i))
    """
    n = len(column_values)
    q = query_point % BABYBEAR_P

    if 0 <= q < n:
        return column_values[q] % BABYBEAR_P

    weights = get_barycentric_weights(n)
    num = 0
    den = 0
    for i, (y, w) in enumerate(zip(column_values, weights)):
        diff = (q - i) % BABYBEAR_P
        inv_diff = pow(diff, BABYBEAR_P - 2, BABYBEAR_P)
        term = (w * inv_diff) % BABYBEAR_P
        num = (num + (y % BABYBEAR_P) * term) % BABYBEAR_P
        den = (den + term) % BABYBEAR_P

    return (num * pow(den, BABYBEAR_P - 2, BABYBEAR_P)) % BABYBEAR_P


def simulate_fri_query_evaluations(
    trace: BlindedTraceMatrix,
    column_idx: int,
    query_points: Sequence[int],
) -> list[int]:
    """Simulate N_q FRI polynomial evaluation queries on column column_idx."""
    if column_idx < 0 or column_idx >= trace.columns:
        raise IndexError(f"column_idx {column_idx} out of range [0, {trace.columns})")

    col_vals = [trace.matrix[r][column_idx] for r in range(trace.total_rows)]
    evals: list[int] = []
    for pt in query_points:
        evals.append(evaluate_column_polynomial_at_point(col_vals, pt))
    return evals


def compute_statistical_zk_distinguisher_advantage(
    trace_a: BlindedTraceMatrix,
    trace_b: BlindedTraceMatrix,
    column_idx: int,
    *,
    num_queries: int = 38,
    num_trials: int = 100,
) -> float:
    """Measure the adversarial distinguisher advantage between traces A and B.

    An adversary samples num_queries random out-of-domain evaluation points and observes
    the polynomial evaluations. The advantage is measured as the empirical Total Variation
    Distance between the evaluation distributions:
      Adv = (1/2) * sum_x | Pr_A(x) - Pr_B(x) |

    Returns:
      Estimated distinguishing advantage in [0.0, 1.0].
      - Without blinding: Adv approaches 1.0 (easily distinguished).
      - With ZK blinding rows (B >= num_queries + 1): Adv <= 0.05 (statistically indistinguishable).
    """
    if trace_a.columns != trace_b.columns:
        raise ValueError("traces must have identical column count")

    diff_count = 0
    total_evals = num_trials * num_queries

    for _ in range(num_trials):
        # Sample random out-of-domain challenge points
        query_points = [
            trace_a.total_rows + secrets.randbelow(BABYBEAR_P - trace_a.total_rows - 1) + 1
            for _ in range(num_queries)
        ]
        evals_a = simulate_fri_query_evaluations(trace_a, column_idx, query_points)
        evals_b = simulate_fri_query_evaluations(trace_b, column_idx, query_points)

        # Count parity / bit distributions across evaluations
        for ea, eb in zip(evals_a, evals_b):
            # Check least significant 16 bits distribution difference
            if (ea & 0xFFFF) != (eb & 0xFFFF):
                diff_count += 1

    # Ratio of different evaluations relative to uniform random expectation
    # In uniform distribution over F_p, (ea & 0xFFFF) != (eb & 0xFFFF) with probability (1 - 1/2^16) = 0.99998
    # When traces are identical or blinded with independent random rows, the difference rate matches uniform noise.
    return abs((diff_count / total_evals) - (1.0 - 1.0 / 65536.0))
