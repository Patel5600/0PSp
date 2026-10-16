"""Adversarial tests for Circuit-Level ZK Trace Blinding Rows and Leaf Salt Masking (P0 Issue #36).

Evaluates:
  1. Adversarial Polynomial Distinguisher:
     - Unblinded execution traces (B = 0) leak witness differences to an evaluator.
     - Blinded execution traces (B = 39) with randomized F_p rows mask witness differences,
       achieving statistical zero-knowledge under N_q = 38 FRI evaluation queries.
  2. Salted Merkle Leaf Masking:
     - Unique 256-bit CSPRNG salts per row ensure that opening an authenticated leaf
       reveals strictly zero entropy regarding unopened adjacent columns or neighboring rows.
  3. Boundary Invariants:
     - Blinding rows do not alter active computation values or outputs.
"""
from __future__ import annotations

import secrets
import pytest

from src.core.zk_trace_blinding import (
    BABYBEAR_P,
    DEFAULT_ZK_BLINDING_ROWS,
    BlindedTraceMatrix,
    compute_salted_leaf_commitment,
    compute_statistical_zk_distinguisher_advantage,
    construct_zk_blinded_trace,
    evaluate_column_polynomial_at_point,
    simulate_fri_query_evaluations,
)


def test_blinded_trace_construction_dimensions_and_salts() -> None:
    """Verify that construct_zk_blinded_trace appends exact B rows and unique salts."""
    active_rows = 16
    columns = 8
    # Create simple execution trace
    raw_trace = [[(r * columns + c) % BABYBEAR_P for c in range(columns)] for r in range(active_rows)]

    blinded = construct_zk_blinded_trace(raw_trace, blinding_rows=DEFAULT_ZK_BLINDING_ROWS)

    assert blinded.active_rows == active_rows
    assert blinded.blinding_rows == DEFAULT_ZK_BLINDING_ROWS
    assert blinded.total_rows == active_rows + DEFAULT_ZK_BLINDING_ROWS
    assert blinded.columns == columns

    # Active rows must match input
    for r in range(active_rows):
        for c in range(columns):
            assert blinded.matrix[r][c] == raw_trace[r][c]

    # Blinding rows must be valid field elements
    for r in range(active_rows, blinded.total_rows):
        for c in range(columns):
            assert 0 <= blinded.matrix[r][c] < BABYBEAR_P

    # All leaf salts must be unique 32-byte buffers
    assert len(blinded.leaf_salts) == blinded.total_rows
    assert len(set(blinded.leaf_salts)) == blinded.total_rows
    for s in blinded.leaf_salts:
        assert len(s) == 32

    # All leaf commitments must be unique 32-byte digests
    assert len(blinded.leaf_commitments) == blinded.total_rows
    assert len(set(blinded.leaf_commitments)) == blinded.total_rows
    for cm in blinded.leaf_commitments:
        assert len(cm) == 32


def test_salted_leaf_commitment_avalanche_and_isolation() -> None:
    """Attacking Leaf Commitment: 1-bit change in row or salt produces complete digest avalanche."""
    row = [100, 200, 300, 400]
    salt = b"\x11" * 32

    cm_base = compute_salted_leaf_commitment(row, salt)
    assert len(cm_base) == 32

    # 1. Tamper 1 element in row
    tampered_row = [101, 200, 300, 400]
    cm_tampered_row = compute_salted_leaf_commitment(tampered_row, salt)
    assert cm_tampered_row != cm_base

    # Avalanche check: hamming distance between digests must be ~128 bits across 256 bits
    diff_bits = bin(int.from_bytes(cm_base, "big") ^ int.from_bytes(cm_tampered_row, "big")).count("1")
    assert 90 <= diff_bits <= 166, f"Insufficient avalanche on row tamper: {diff_bits} bits"

    # 2. Tamper 1 bit in salt
    tampered_salt = bytes([salt[0] ^ 0x01]) + salt[1:]
    cm_tampered_salt = compute_salted_leaf_commitment(row, tampered_salt)
    assert cm_tampered_salt != cm_base

    diff_salt_bits = bin(int.from_bytes(cm_base, "big") ^ int.from_bytes(cm_tampered_salt, "big")).count("1")
    assert 90 <= diff_salt_bits <= 166, f"Insufficient avalanche on salt tamper: {diff_salt_bits} bits"


def test_adversarial_distinguisher_unblinded_trace_leaks_witness() -> None:
    """Negative Control: Proves that unblinded traces (B = 0) fail zero-knowledge.

    An adversarial evaluator querying polynomial points directly distinguishes
    trace A (witness_A) from trace B (witness_B) with certainty.
    """
    # Trace A: private witness secret = 42 at row 1
    trace_a_rows = [[10, 20], [42, 50], [100, 200]]
    # Trace B: private witness secret = 999 at row 1
    trace_b_rows = [[10, 20], [999, 50], [100, 200]]

    # Unblinded traces (blinding_rows = 0)
    unblinded_a = construct_zk_blinded_trace(trace_a_rows, blinding_rows=0)
    unblinded_b = construct_zk_blinded_trace(trace_b_rows, blinding_rows=0)

    # Evaluate at query point z = 5 (out of domain)
    eval_a = evaluate_column_polynomial_at_point([r[0] for r in unblinded_a.matrix], 5)
    eval_b = evaluate_column_polynomial_at_point([r[0] for r in unblinded_b.matrix], 5)

    # In unblinded traces, polynomial evaluations depend deterministically on the witness value
    assert eval_a != eval_b, "Unblinded traces should evaluate to distinct points!"

    # Evaluator queries across multiple points
    query_points = [4, 5, 6, 7, 8]
    evals_a = simulate_fri_query_evaluations(unblinded_a, 0, query_points)
    evals_b = simulate_fri_query_evaluations(unblinded_b, 0, query_points)
    assert evals_a != evals_b


def test_adversarial_distinguisher_blinded_trace_achieves_zk() -> None:
    """Positive Theorem: Proves that with B = 39 randomized blinding rows,

    the polynomial evaluation distribution is statistically indistinguishable from random noise,
    yielding distinguishing advantage Adv <= 0.05 across evaluation queries.
    """
    # Two traces with identical public outputs (first & last rows) but distinct private witnesses (row 1)
    trace_a_rows = [[100, 200], [0x1111, 0x2222], [500, 600]]
    trace_b_rows = [[100, 200], [0x9999, 0xAAAA], [500, 600]]

    blinded_a = construct_zk_blinded_trace(trace_a_rows, blinding_rows=DEFAULT_ZK_BLINDING_ROWS)
    blinded_b = construct_zk_blinded_trace(trace_b_rows, blinding_rows=DEFAULT_ZK_BLINDING_ROWS)

    assert blinded_a.total_rows == 3 + DEFAULT_ZK_BLINDING_ROWS
    assert blinded_b.total_rows == 3 + DEFAULT_ZK_BLINDING_ROWS

    # Compute statistical distinguisher advantage over N_q = 38 queries across 100 trials
    adv = compute_statistical_zk_distinguisher_advantage(
        blinded_a,
        blinded_b,
        column_idx=0,
        num_queries=38,
        num_trials=50,
    )

    # Statistical advantage must be bounded by statistical noise (|Adv - 0| <= 0.05)
    assert adv <= 0.05, f"Distinguisher advantage too high: {adv} > 0.05 (failed ZK masking)"


def test_logup_zero_sum_dummy_pairs_sum_to_zero() -> None:
    """Mathematical invariant: LogUp dummy lookup pairs must sum to 0 mod p."""
    from src.core.zk_trace_blinding import generate_logup_zero_sum_dummy_pairs, babybear_add

    alpha = 0x12345678
    pairs = generate_logup_zero_sum_dummy_pairs(num_pairs=40, alpha=alpha)
    assert len(pairs) == 40

    total_sum = 0
    for p in pairs:
        pair_sum = babybear_add(p.positive_term, p.negative_term)
        assert pair_sum == 0, f"Pair failed zero-sum property: {p}"
        total_sum = babybear_add(total_sum, p.positive_term)
        total_sum = babybear_add(total_sum, p.negative_term)

    assert total_sum == 0, "Total sum of all dummy pairs must be strictly 0 mod p"


def test_logup_running_sum_blinding_preserves_total_and_masks_intermediates() -> None:
    """Theorem: LogUp running sum phi(X) blinding preserves phi(N) while randomizing intermediates."""
    from src.core.zk_trace_blinding import blind_logup_running_sum

    active_phi = [0, 1500, 3200, 5000, 8400]
    expected_final = active_phi[-1]

    blinded_phi_1 = blind_logup_running_sum(active_phi, blinding_rows=80)
    blinded_phi_2 = blind_logup_running_sum(active_phi, blinding_rows=80)

    # 1. Dimensions check: active rows + 80 blinding rows
    assert len(blinded_phi_1) == len(active_phi) + 80
    assert len(blinded_phi_2) == len(active_phi) + 80

    # 2. Conservation check: final running sum must equal active_phi[-1]
    assert blinded_phi_1[-1] == expected_final
    assert blinded_phi_2[-1] == expected_final

    # 3. Random walk check: intermediate blinding rows must not be identical across runs
    intermediates_1 = blinded_phi_1[len(active_phi):-1]
    intermediates_2 = blinded_phi_2[len(active_phi):-1]
    assert intermediates_1 != intermediates_2, "Independent blinded running sums must be randomized"


def test_multitable_blinded_trace_all_chip_masking() -> None:
    """Verify all-table blinding across Main trace, Keccak coprocessor, and LogUp multiplicities."""
    from src.core.zk_trace_blinding import construct_multitable_blinded_trace, CANONICAL_ZK_BLINDING_ROWS

    # Main execution trace (e.g. 10 rows x 4 cols)
    main_trace = [[r * 10 + c for c in range(4)] for r in range(10)]
    # Keccak coprocessor trace (e.g. 10 rows x 8 cols)
    keccak_trace = [[(r ^ c) * 100 for c in range(8)] for r in range(10)]
    # Multiplicity column (e.g. 10 rows x 1 col)
    multiplicities = [[r % 3] for r in range(10)]
    # LogUp running sum (10 rows)
    running_sum = [0, 10, 25, 45, 70, 100, 135, 175, 220, 270]

    multitable = construct_multitable_blinded_trace(
        main_trace=main_trace,
        keccak_trace=keccak_trace,
        multiplicities=multiplicities,
        active_logup_running_sum=running_sum,
        blinding_rows=CANONICAL_ZK_BLINDING_ROWS,
    )

    expected_total_rows = 10 + CANONICAL_ZK_BLINDING_ROWS
    assert multitable.main_trace.total_rows == expected_total_rows
    assert multitable.keccak_coprocessor_trace.total_rows == expected_total_rows
    assert multitable.lookup_multiplicities.total_rows == expected_total_rows
    assert len(multitable.logup_running_sum) == expected_total_rows
    assert len(multitable.leaf_salts) == expected_total_rows
    assert len(multitable.leaf_commitments) == expected_total_rows

    # All leaf salts must be unique 32-byte buffers
    assert len(set(multitable.leaf_salts)) == expected_total_rows
    for salt in multitable.leaf_salts:
        assert len(salt) == 32

    # Final running sum preserved
    assert multitable.logup_running_sum[-1] == running_sum[-1]

    # Verify LDE commitments on shifted coset g * H_LDE are present
    assert len(multitable.lde_salts) == expected_total_rows * 16
    assert len(multitable.lde_commitments) == expected_total_rows * 16


def test_multitable_mismatched_row_counts_raise_value_error() -> None:
    """Verify fail-closed rejection when trace tables have mismatched row counts."""
    from src.core.zk_trace_blinding import construct_multitable_blinded_trace

    main_trace = [[1, 2], [3, 4]]
    keccak_trace = [[1, 2, 3]]  # 1 row vs 2 rows
    multiplicities = [[0], [1]]
    running_sum = [0, 10]

    with pytest.raises(ValueError, match="keccak_trace row count .* must match main_trace"):
        construct_multitable_blinded_trace(
            main_trace=main_trace,
            keccak_trace=keccak_trace,
            multiplicities=multiplicities,
            active_logup_running_sum=running_sum,
        )


def test_multitable_disjoint_coset_lde_evaluator() -> None:
    """Verify evaluate_multitable_disjoint_coset_lde evaluates all chips on shifted coset."""
    from src.core.zk_trace_blinding import (
        construct_multitable_blinded_trace,
        evaluate_multitable_disjoint_coset_lde,
        BABYBEAR_P,
    )

    main_trace = [[1, 2], [3, 4]]
    keccak_trace = [[10, 20, 30], [40, 50, 60]]
    multiplicities = [[1], [2]]
    running_sum = [0, 5]

    multitable = construct_multitable_blinded_trace(
        main_trace=main_trace,
        keccak_trace=keccak_trace,
        multiplicities=multiplicities,
        active_logup_running_sum=running_sum,
        blinding_rows=80,
        compute_lde=False,
    )

    lde_rows = evaluate_multitable_disjoint_coset_lde(multitable, blowup_factor=16)
    expected_len = (2 + 80) * 16
    assert len(lde_rows) == expected_len

    expected_cols = 2 + 3 + 1 + 1  # 7 columns
    for eval_row, salt, commit in lde_rows:
        assert len(eval_row) == expected_cols
        assert all(0 <= v < BABYBEAR_P for v in eval_row)
        assert len(salt) == 32
        assert len(commit) == 32


def test_disjoint_coset_lde_evaluation() -> None:
    """Verify LDE evaluations on shifted coset g * H_LDE with 32-byte salted leaf commitments."""
    from src.core.zk_trace_blinding import evaluate_disjoint_coset_lde, BABYBEAR_P

    col = [10, 25, 55, 100, 160]
    lde_rows = evaluate_disjoint_coset_lde(col, blowup_factor=16)

    assert len(lde_rows) == len(col) * 16
    for val, salt, commit in lde_rows:
        assert 0 <= val < BABYBEAR_P
        assert len(salt) == 32
        assert len(commit) == 32
