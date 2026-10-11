from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "audit_phase1_claims.py"
SPEC = importlib.util.spec_from_file_location("audit_phase1_claims", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def test_lotrs_modulus_bit_widths_are_distinct():
    assert audit.Q_LOTRS.bit_length() == 43
    assert audit.QHAT_LOTRS.bit_length() == 35


def test_six_vector_packing_arithmetic():
    assert 6 * 256 * 36 // 8 == 6912
    assert 6 * 256 * 43 // 8 == 8256


def test_babybear_residual_bound_is_below_field_modulus():
    bound = audit.W + 3 * audit.W**2 + 2**16 + (2**16) * audit.W
    assert bound == 1_879_130_112
    assert bound < audit.P_BABYBEAR


def test_truncation_tail_arithmetic_is_below_2_minus_128():
    assert audit.log2_tail_bound() < -128


def test_merkle_path_byte_accounting():
    assert 74 * 8 * 32 == 18_944
    assert 74 * 8 * 48 == 28_416


def test_qrom_bound_does_not_claim_128_bits_for_256_bit_entropy_at_2_pow_64_queries():
    assert -124 < audit.log2_conditional_qrom_bound(256, 64) < -123
    assert -156 < audit.log2_conditional_qrom_bound(288, 64) < -155
