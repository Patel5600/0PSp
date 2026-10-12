"""CHp4.7 regressions for V3 issuance identity derivation.

These tests validate selected byte-level reference vectors only. They do not
prove canonical chain adapters, uniqueness of finite hash outputs, or a ZK
circuit's enforcement.
"""
from __future__ import annotations

import pytest

from src.primitives.namespace import NamespaceId
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    compute_nullifier_key_commitment_v3,
)
from src.protocol.note_public_key_bundle_v3 import NotePublicKeyBundleV3
from src.protocol.output_identity import (
    DEPOSIT_ID_MAX_BYTES,
    OUTPUT_ID_BYTES,
    OUTPUT_INDEX_MAX,
    NULLIFIER_SECRET_BYTES,
    ISSUANCE_ENTROPY_BYTES,
    derive_issuance_output_identity_v3_candidate,
)

NS = NamespaceId(bytes([0x11]) * 48)
PARAMS_ID = b"v3-test-params"
DEPOSIT_ID = b"chain-a:tx123:log0"
ISSUANCE_ENTROPY = bytes([0x55]) * 32
KEY = NullifierDerivingKeyV3(bytes([0x44]) * 48)
RECIPIENT_KEY_BUNDLE = NotePublicKeyBundleV3(
    auth_scheme_id=b"test-auth-scheme-v1",
    auth_public_key=b"test-recipient-public-key",
    nullifier_key_commitment=compute_nullifier_key_commitment_v3(KEY),
).encode()


def _derive(
    *,
    deposit_id: bytes = DEPOSIT_ID,
    recipient_key_bundle: bytes = RECIPIENT_KEY_BUNDLE,
    issuance_entropy: bytes = ISSUANCE_ENTROPY,
    output_index: int = 0,
    namespace_id: NamespaceId = NS,
    params_id: bytes = PARAMS_ID,
):
    return derive_issuance_output_identity_v3_candidate(
        namespace_id=namespace_id,
        deposit_id=deposit_id,
        recipient_key_bundle=recipient_key_bundle,
        issuance_entropy=issuance_entropy,
        output_index=output_index,
        params_id=params_id,
    )


def test_v3_issuance_identity_matches_hardcoded_vector() -> None:
    first = _derive()
    assert first == _derive()
    assert len(first.coin_id.data) == OUTPUT_ID_BYTES == 32
    assert len(first.r_nf.data) == NULLIFIER_SECRET_BYTES == 36
    assert first.coin_id.data.hex() == (
        "ea0e208a7bbe7b17e88a6275d99a6395"
        "285e99f95f330764367e3c4f27993a36"
    )
    assert first.r_nf.data.hex() == (
        "906e70e632b2e8ce69825c960ae950a8"
        "33ba65d0b914e76773390ec9d44a8cf7"
        "68a170a6"
    )


def test_distinct_anchor_slot_namespace_recipient_or_params_separates_vectors() -> None:
    baseline = _derive()
    alternate_bundle = NotePublicKeyBundleV3(
        auth_scheme_id=b"test-auth-scheme-v1",
        auth_public_key=b"alternate-recipient-public-key",
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(KEY),
    ).encode()
    variants = [
        _derive(deposit_id=b"chain-a:tx124:log0"),
        _derive(output_index=1),
        _derive(namespace_id=NamespaceId(bytes([0x12]) * 48)),
        _derive(recipient_key_bundle=alternate_bundle),
        _derive(issuance_entropy=bytes([0x56]) * 32),
        _derive(params_id=b"different-params"),
    ]
    # Selected deterministic regressions only, not a global collision theorem.
    assert all(item.coin_id != baseline.coin_id for item in variants)
    assert all(item.r_nf != baseline.r_nf for item in variants)


@pytest.mark.parametrize("bad_index", [-1, OUTPUT_INDEX_MAX + 1, True, 1.5])
def test_output_index_is_canonical_uint16(bad_index: object) -> None:
    with pytest.raises(ValueError):
        _derive(output_index=bad_index)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_deposit_id",
    [b"", bytes(DEPOSIT_ID_MAX_BYTES + 1), "not-bytes", None],
)
def test_deposit_id_requires_bounded_bytes(bad_deposit_id: object) -> None:
    with pytest.raises(ValueError):
        _derive(deposit_id=bad_deposit_id)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_entropy", [b"", b"short", bytes(ISSUANCE_ENTROPY_BYTES + 1)])
def test_entropy_must_have_exact_width(bad_entropy: bytes) -> None:
    with pytest.raises(ValueError):
        _derive(issuance_entropy=bad_entropy)


@pytest.mark.parametrize("bad_bundle", [b"", b"x" * (1 << 16)])
def test_recipient_bundle_is_bounded_nonempty_bytes(bad_bundle: bytes) -> None:
    with pytest.raises(ValueError):
        _derive(recipient_key_bundle=bad_bundle)


def test_empty_parameter_id_is_rejected() -> None:
    with pytest.raises(ValueError):
        _derive(params_id=b"")
