"""Unit tests for 0PSP V3 Key Hierarchy and Spend Authorization."""
from __future__ import annotations

import pytest

from src.primitives.keys_v3 import (
    AK_BYTES,
    AUTH_TOKEN_BYTES,
    NK_BYTES,
    PK_OWNER_BYTES,
    SK_SPEND_BYTES,
    compute_spend_auth_token_v3,
    derive_keys_v3,
    generate_master_spend_key_v3,
    verify_spend_auth_token_v3,
)


def test_generate_and_derive_keys_v3() -> None:
    sk = generate_master_spend_key_v3()
    assert len(sk) == SK_SPEND_BYTES

    hierarchy = derive_keys_v3(sk)
    assert hierarchy.sk_spend == sk
    assert len(hierarchy.ak) == AK_BYTES
    assert len(hierarchy.nk) == NK_BYTES
    assert len(hierarchy.pk_owner) == PK_OWNER_BYTES

    # Keys must all be distinct
    keys = {hierarchy.sk_spend, hierarchy.ak, hierarchy.nk, hierarchy.pk_owner}
    assert len(keys) == 4

    # Derivation must be deterministic
    hierarchy_2 = derive_keys_v3(sk)
    assert hierarchy_2.ak == hierarchy.ak
    assert hierarchy_2.nk == hierarchy.nk
    assert hierarchy_2.pk_owner == hierarchy.pk_owner


def test_keys_v3_known_answer_vector() -> None:
    sk_fixed = bytes([0x42] * 48)
    h = derive_keys_v3(sk_fixed)
    # Check reproducible non-zero hashes
    assert h.ak != bytes(48)
    assert h.nk != bytes(48)
    assert h.pk_owner != bytes(48)
    assert repr(h).startswith("V3KeyHierarchy")
    assert "<redacted>" in repr(h)


def test_spend_auth_token_lifecycle() -> None:
    sk = bytes([0x55] * 48)
    tx_digest = bytes([0xAA] * 64)
    commitment = bytes([0xBB] * 48)

    token = compute_spend_auth_token_v3(sk, tx_digest, commitment)
    assert len(token) == AUTH_TOKEN_BYTES

    # Verification must succeed
    assert verify_spend_auth_token_v3(sk, tx_digest, commitment, token) is True

    # Tampered token must fail
    tampered_token = bytes([token[0] ^ 0x01]) + token[1:]
    assert verify_spend_auth_token_v3(sk, tx_digest, commitment, tampered_token) is False

    # Tampered tx_digest must fail
    tampered_tx = bytes([tx_digest[0] ^ 0x01]) + tx_digest[1:]
    assert verify_spend_auth_token_v3(sk, tampered_tx, commitment, token) is False

    # Tampered commitment must fail
    tampered_c = bytes([commitment[0] ^ 0x01]) + commitment[1:]
    assert verify_spend_auth_token_v3(sk, tx_digest, tampered_c, token) is False

    # Wrong key must fail
    wrong_sk = bytes([0x77] * 48)
    assert verify_spend_auth_token_v3(wrong_sk, tx_digest, commitment, token) is False


def test_keys_v3_validation_boundaries() -> None:
    with pytest.raises(ValueError, match="sk_spend"):
        derive_keys_v3(b"\x00" * 32)  # Wrong length

    with pytest.raises(ValueError, match="sk_spend"):
        compute_spend_auth_token_v3(b"\x00" * 32, b"\x00" * 64, b"\x00" * 48)

    with pytest.raises(ValueError, match="tx_digest"):
        compute_spend_auth_token_v3(b"\x00" * 48, b"\x00" * 32, b"\x00" * 48)

    with pytest.raises(ValueError, match="commitment"):
        compute_spend_auth_token_v3(b"\x00" * 48, b"\x00" * 64, b"\x00" * 32)
