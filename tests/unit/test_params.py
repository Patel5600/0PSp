"""Tests for parameter metadata semantics; these are not cryptographic tests."""

from src.core.params import ML_DSA_44, ML_DSA_65, RESEARCH_SMALL


def test_ml_dsa_44_metadata_is_category_not_security_bits():
    assert ML_DSA_44.security_category == 2
    assert ML_DSA_44.n == 256
    assert ML_DSA_44.q == 8_380_417
    assert ML_DSA_44.gamma1 == 2**17


def test_ml_dsa_65_metadata_is_category_not_security_bits():
    assert ML_DSA_65.security_category == 3
    assert ML_DSA_65.n == 256
    assert ML_DSA_65.q == 8_380_417
    assert ML_DSA_65.gamma1 == 2**19


def test_research_small_has_no_security_category():
    assert RESEARCH_SMALL.security_category == 0
    assert RESEARCH_SMALL.n == 64
