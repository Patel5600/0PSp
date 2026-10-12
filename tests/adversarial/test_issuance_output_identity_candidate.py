"""CHp4.7 regressions for issuance identity derivation.

These tests check the byte-level reference candidate only. They do not prove
that a ZK circuit constrains it or that the deposit adapter is canonical.
"""
from __future__ import annotations

import pytest

from src.primitives.namespace import NamespaceId
from src.protocol.output_identity import (
    DEPOSIT_ID_MAX_BYTES,
    OUTPUT_ID_BYTES,
    OUTPUT_INDEX_MAX,
    NULLIFIER_SECRET_BYTES,
    derive_issuance_output_identity_candidate,
)

NS = NamespaceId(bytes([0x11]) * 48)
PARAMS_ID = b"v2-test-params"
DEPOSIT_ID = b"chain-a:tx123:log0"
ISSUANCE_ENTROPY = bytes([0x55]) * 32


def _derive(
    *,
    deposit_id: bytes = DEPOSIT_ID,
    issuance_entropy: bytes = ISSUANCE_ENTROPY,
    output_index: int = 0,
    namespace_id: NamespaceId = NS,
    params_id: bytes = PARAMS_ID,
):
    return derive_issuance_output_identity_candidate(
        namespace_id=namespace_id,
        deposit_id=deposit_id,
        issuance_entropy=issuance_entropy,
        output_index=output_index,
        params_id=params_id,
    )


def test_issuance_output_identity_candidate_matches_hardcoded_vector() -> None:
    first = _derive()
    repeated = _derive()

    assert len(first.coin_id.data) == OUTPUT_ID_BYTES == 32
    assert len(first.r_nf.data) == NULLIFIER_SECRET_BYTES == 36
    assert first == repeated
    assert first.coin_id.data.hex() == (
        "cf7a25668a6d0b2233058f86ce47535e"
        "2b923cfd9677cea5b2aab65aa647078e"
    )
    assert first.r_nf.data.hex() == (
        "6bf049fe9392c864b1a7cdf14d02333c"
        "1a1c46a256920e05e3c9db106dfa6ba5027834e5"
    )


def test_distinct_anchor_or_output_slot_separates_selected_vectors() -> None:
    baseline = _derive()
    variants = [
        _derive(deposit_id=b"chain-a:tx124:log0"),
        _derive(output_index=1),
        _derive(namespace_id=NamespaceId(bytes([0x12]) * 48)),
        _derive(issuance_entropy=bytes([0x56]) * 32),
        _derive(params_id=b"different-params"),
    ]

    # These are selected deterministic vectors, not a global collision proof.
    assert all(item.coin_id != baseline.coin_id for item in variants)
    assert all(item.r_nf != baseline.r_nf for item in variants)


@pytest.mark.parametrize(
    "bad_index",
    [-1, OUTPUT_INDEX_MAX + 1, True, 1.5],
)
def test_issuance_output_index_must_be_canonical_uint16(bad_index: object) -> None:
    with pytest.raises(ValueError):
        _derive(output_index=bad_index)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_deposit_id",
    [b"", bytes(DEPOSIT_ID_MAX_BYTES + 1), "not-bytes", None],
)
def test_deposit_id_requires_bounded_canonical_bytes(bad_deposit_id: object) -> None:
    with pytest.raises(ValueError):
        _derive(deposit_id=bad_deposit_id)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_entropy",
    [b"", b"short", bytes(ISSUANCE_ENTROPY_BYTES + 1)],
)
def test_issuance_entropy_must_be_exactly_32_bytes(bad_entropy: bytes) -> None:
    with pytest.raises(ValueError):
        _derive(issuance_entropy=bad_entropy)


def test_empty_parameter_id_is_rejected() -> None:
    with pytest.raises(ValueError):
        _derive(params_id=b"")
