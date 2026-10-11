"""RFC-01 regression tests for the existing V2 commitment/nullifier primitives.

These tests deliberately stop at the primitive/reference layer. They do NOT
prove that a mint authority has authenticated the committed value, that a
zero-knowledge spend relation enforces the opening, or that a ledger enforces
atomic nullifier uniqueness. Those protocol gates remain NO-GO.
"""
from __future__ import annotations

from src.primitives.coin_commitment import (
    COMMITMENT_RANDOMNESS_BYTES,
    commit_coin_v2,
    verify_coin_opening_v2,
)
from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import (
    NullifierSecret,
    compute_nullifier_v2,
)

NAMESPACE_VECTOR = bytes.fromhex(
    "04c0037350b1b2551c5b7f8b19642abd"
    "e118113083130340a0986aacfaad3d7d"
    "38c96dac07c80e9c3d45e0a1111279d2"
)


def _opening():
    return (
        NamespaceId(NAMESPACE_VECTOR),
        b"canonical-threshold-public-key-v1",
        2500,
        ScopedCoinId(bytes(range(32))),
        NullifierSecret(bytes(range(36))),
        bytes([0x33]) * COMMITMENT_RANDOMNESS_BYTES,
        b"ringtail-test-params-v1",
    )


def test_same_commitment_rejects_alternate_coin_identity_and_nullifier_secret() -> None:
    namespace, public_key, value, coin_id, r_nf, rho, params_id = _opening()
    commitment = commit_coin_v2(
        namespace, public_key, value, coin_id, r_nf, rho, params_id
    )

    assert verify_coin_opening_v2(
        commitment, namespace, public_key, value, coin_id, r_nf, rho, params_id
    )
    assert not verify_coin_opening_v2(
        commitment,
        namespace,
        public_key,
        value,
        ScopedCoinId(bytes([0xA5]) * 32),
        r_nf,
        rho,
        params_id,
    )
    assert not verify_coin_opening_v2(
        commitment,
        namespace,
        public_key,
        value,
        coin_id,
        NullifierSecret(bytes([0x5A]) * 36),
        rho,
        params_id,
    )


def test_same_commitment_rejects_value_namespace_key_salt_or_parameter_substitution() -> None:
    namespace, public_key, value, coin_id, r_nf, rho, params_id = _opening()
    commitment = commit_coin_v2(
        namespace, public_key, value, coin_id, r_nf, rho, params_id
    )
    other_namespace = NamespaceId(bytes([0x99]) * 48)

    assert not verify_coin_opening_v2(
        commitment, namespace, public_key, value + 1, coin_id, r_nf, rho, params_id
    )
    assert not verify_coin_opening_v2(
        commitment, other_namespace, public_key, value, coin_id, r_nf, rho, params_id
    )
    assert not verify_coin_opening_v2(
        commitment, namespace, public_key + b"-other", value, coin_id, r_nf, rho, params_id
    )
    assert not verify_coin_opening_v2(
        commitment, namespace, public_key, value, coin_id, r_nf, bytes([0x44]) * 36, params_id
    )
    assert not verify_coin_opening_v2(
        commitment, namespace, public_key, value, coin_id, r_nf, rho, b"other-params-v1"
    )


def test_nullifier_is_deterministic_for_the_exact_opening() -> None:
    namespace, _, _, coin_id, r_nf, _, _ = _opening()
    first = compute_nullifier_v2(namespace, coin_id, r_nf)
    second = compute_nullifier_v2(namespace, coin_id, r_nf)

    assert first == second


def test_alternate_opening_is_not_a_valid_same_commitment_opening_even_if_its_nullifier_differs() -> None:
    namespace, public_key, value, coin_id, r_nf, rho, params_id = _opening()
    commitment = commit_coin_v2(
        namespace, public_key, value, coin_id, r_nf, rho, params_id
    )
    alternate_coin = ScopedCoinId(bytes([0xA5]) * 32)
    alternate_secret = NullifierSecret(bytes([0x5A]) * 36)
    alternate_nullifier = compute_nullifier_v2(
        namespace, alternate_coin, alternate_secret
    )

    assert alternate_nullifier != compute_nullifier_v2(namespace, coin_id, r_nf)
    assert not verify_coin_opening_v2(
        commitment,
        namespace,
        public_key,
        value,
        alternate_coin,
        alternate_secret,
        rho,
        params_id,
    )

    # Primitive-level opening rejection only. The end-to-end proof must enforce
    # this exact shared-witness condition; no ZK backend is implemented yet.
