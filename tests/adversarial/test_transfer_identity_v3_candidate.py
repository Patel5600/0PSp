"""Adversarial tests for the superseding V3 anchor/index transfer candidate.

These tests intentionally do not exercise the frozen CHp4.6/V2 function. The
new V3 candidate excludes spend_key_witness because deriving an output from a
threshold signature over the final transaction digest would be circular.
These are host-reference tests only, not circuit or protocol security proofs.
"""
from __future__ import annotations

import inspect

import pytest

from src.primitives.namespace import ScopedCoinId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.nullifier import NullifierSecret
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    compute_nullifier_key_commitment_v3,
)
from src.primitives.coin_commitment_v3 import commit_coin_v3
from src.protocol.note_public_key_bundle_v3 import NotePublicKeyBundleV3
from src.protocol.output_identity import (
    derive_output_identity_v3_candidate,
    verify_output_identity_v3_candidate,
)

NS = NamespaceIdV3(bytes(range(48)))
PARAMS = b"v3-transfer-candidate"
AUTH_ID = b"mldsa87-threshold-candidate"
PARENT_NK = NullifierDerivingKeyV3(bytes(range(48)))
PARENT_COIN_ID = ScopedCoinId(bytes(range(32)))
PARENT_R_NF = NullifierSecret(bytes(range(36)))
PARENT_RHO = bytes([0xA0]) * 36
TX_ENTROPY = bytes(range(64, 96))
RECIPIENT_NK = NullifierDerivingKeyV3(bytes(range(48, 96)))


def _bundle(public_key: bytes, nk: NullifierDerivingKeyV3) -> bytes:
    return NotePublicKeyBundleV3(
        auth_scheme_id=AUTH_ID,
        auth_public_key=public_key,
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(nk),
    ).encode()


PARENT_BUNDLE = _bundle(b"parent-test-pk", PARENT_NK)
RECIPIENT_BUNDLE = _bundle(b"recipient-test-pk", RECIPIENT_NK)
PARENT_COMMITMENT = commit_coin_v3(
    NS,
    PARENT_BUNDLE,
    1000,
    PARENT_COIN_ID,
    PARENT_R_NF,
    PARENT_RHO,
    PARAMS,
)


def _derive(**overrides: object):
    fields: dict[str, object] = {
        "namespace_id": NS,
        "parent_coin_id": PARENT_COIN_ID,
        "parent_r_nf": PARENT_R_NF,
        "parent_public_key_bundle": PARENT_BUNDLE,
        "parent_commitment": PARENT_COMMITMENT,
        "parent_nullifier_key": PARENT_NK,
        "recipient_key_bundle": RECIPIENT_BUNDLE,
        "transaction_entropy": TX_ENTROPY,
        "output_index": 0,
        "params_id": PARAMS,
    }
    fields.update(overrides)
    return derive_output_identity_v3_candidate(**fields)  # type: ignore[arg-type]


def test_v3_transfer_candidate_known_answer_and_verification() -> None:
    output = _derive()
    assert output.coin_id.data.hex() == (
        "b62a03e24daa36ca344e1dbe7ac03559"
        "97057dfc16f4bd23692303b8ee827ddc"
    )
    assert output.r_nf.data.hex() == (
        "15aee3e4489df93ed0e334b131c13848"
        "8964da7c321a21954f8262195d921c6da73d4215"
    )
    assert verify_output_identity_v3_candidate(
        output_coin_id=output.coin_id,
        output_r_nf=output.r_nf,
        namespace_id=NS,
        parent_coin_id=PARENT_COIN_ID,
        parent_r_nf=PARENT_R_NF,
        parent_public_key_bundle=PARENT_BUNDLE,
        parent_commitment=PARENT_COMMITMENT,
        parent_nullifier_key=PARENT_NK,
        recipient_key_bundle=RECIPIENT_BUNDLE,
        transaction_entropy=TX_ENTROPY,
        output_index=0,
        params_id=PARAMS,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"namespace_id": NamespaceIdV3(bytes([0x91]) * 48)},
        {"parent_coin_id": ScopedCoinId(bytes([0x92]) * 32)},
        {"parent_r_nf": NullifierSecret(bytes([0x93]) * 36)},
        {"parent_public_key_bundle": _bundle(b"other-parent-pk", PARENT_NK)},
        {"parent_commitment": CoinCommitmentV3(bytes([0x94]) * 48)},
        {"recipient_key_bundle": _bundle(b"other-recipient-pk", RECIPIENT_NK)},
        {"transaction_entropy": bytes([0x95]) * 32},
        {"output_index": 1},
        {"params_id": b"other-params"},
    ],
)
def test_v3_output_identity_changes_when_any_anchor_or_slot_changes(
    overrides: dict[str, object],
) -> None:
    baseline = _derive()
    changed = _derive(**overrides)
    assert changed.coin_id != baseline.coin_id
    assert changed.r_nf != baseline.r_nf


def test_v3_output_index_substitution_fails_reference_verification() -> None:
    output = _derive()
    with pytest.raises(ValueError, match="output_index"):
        derive_output_identity_v3_candidate(
            namespace_id=NS,
            parent_coin_id=PARENT_COIN_ID,
            parent_r_nf=PARENT_R_NF,
            parent_public_key_bundle=PARENT_BUNDLE,
            parent_commitment=PARENT_COMMITMENT,
            parent_nullifier_key=PARENT_NK,
            recipient_key_bundle=RECIPIENT_BUNDLE,
            transaction_entropy=TX_ENTROPY,
            output_index=65536,
            params_id=PARAMS,
        )
    assert not verify_output_identity_v3_candidate(
        output_coin_id=output.coin_id,
        output_r_nf=output.r_nf,
        namespace_id=NS,
        parent_coin_id=PARENT_COIN_ID,
        parent_r_nf=PARENT_R_NF,
        parent_public_key_bundle=PARENT_BUNDLE,
        parent_commitment=PARENT_COMMITMENT,
        parent_nullifier_key=PARENT_NK,
        recipient_key_bundle=RECIPIENT_BUNDLE,
        transaction_entropy=TX_ENTROPY,
        output_index=1,
        params_id=PARAMS,
    )


def test_v3_candidate_does_not_depend_on_full_spend_key_or_signature() -> None:
    parameters = inspect.signature(derive_output_identity_v3_candidate).parameters
    assert "spend_key_witness" not in parameters
    assert "threshold_signature" not in parameters
    # The final transaction digest binds output commitments. A full signature
    # over that digest must therefore not be an input to output derivation.
    assert "output_index" in parameters
    assert "transaction_entropy" in parameters


def test_wrong_parent_nullifier_key_fails_closed() -> None:
    with pytest.raises(ValueError, match="nullifier key does not open"):
        _derive(parent_nullifier_key=NullifierDerivingKeyV3(bytes([0xA6]) * 48))


@pytest.mark.parametrize("bad_index", [-1, 65536, True, 1.5])
def test_v3_output_index_requires_uint16(bad_index: object) -> None:
    with pytest.raises(ValueError, match="output_index"):
        _derive(output_index=bad_index)
