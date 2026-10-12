"""CHp4.7 regressions for recipient-keyed V3 nullifiers.

These are byte-contract tests for reference functions only. They do not prove
the circuit binds the key commitment or that the nullifier is sender-unlinkable
under every corruption/leakage model.
"""
from __future__ import annotations

import pytest

from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import NullifierSecret, compute_nullifier_v2
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    NullifierKeyCommitmentV3,
    compute_nullifier_key_commitment_v3,
    compute_nullifier_v3,
    verify_nullifier_key_commitment_v3,
)
from src.primitives.coin_commitment_v3 import commit_coin_v3
from src.protocol.note_public_key_bundle_v3 import (
    NotePublicKeyBundleV3,
    decode_note_public_key_bundle_v3,
)

NS = NamespaceId(bytes([0x11]) * 48)
COIN = ScopedCoinId(bytes([0x22]) * 32)
R_NF = NullifierSecret(bytes([0x33]) * 36)
KEY = NullifierDerivingKeyV3(bytes([0x44]) * 48)
PARAMS_ID = b"v3-candidate-params"
AUTH_SCHEME = b"test-auth-scheme-v1"
AUTH_PK = b"test-recipient-public-key"


def _bundle(key: NullifierDerivingKeyV3 = KEY, auth_pk: bytes = AUTH_PK):
    return NotePublicKeyBundleV3(
        auth_scheme_id=AUTH_SCHEME,
        auth_public_key=auth_pk,
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(key),
    )


def test_v3_key_commitment_and_nullifier_match_hardcoded_vectors() -> None:
    bundle = _bundle()
    assert bundle.encode().hex() == (
        "305053502d4e4f54452d504b2d42554e444c452d763303"
        "1300746573742d617574682d736368656d652d7631"
        "19000000746573742d726563697069656e742d7075626c69632d6b6579"
        "300075e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95"
        "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8"
    )
    key_commitment = compute_nullifier_key_commitment_v3(KEY)
    assert key_commitment.value.hex() == (
        "75e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95"
        "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8"
    )
    assert verify_nullifier_key_commitment_v3(key_commitment, KEY)
    assert compute_nullifier_v3(NS, bundle.encode(), COIN, R_NF, KEY).value.hex() == (
        "d034a0df5df2e09108c8d04adeb20d723af581db88f78c215c664451b6bce065"
        "c0d426aa92070ec7b9b80cb4cdc36971"
    )


def test_same_tuple_and_bundle_have_one_nullifier_independent_of_commitment_salt() -> None:
    bundle = _bundle().encode()
    nullifier_a = compute_nullifier_v3(NS, bundle, COIN, R_NF, KEY)
    nullifier_b = compute_nullifier_v3(NS, bundle, COIN, R_NF, KEY)
    assert nullifier_a == nullifier_b

    # Different commitment salts still produce distinct commitments, but do
    # not change the identity-derived nullifier for the same key and tuple.
    cm_a = commit_coin_v3(NS, bundle, 500, COIN, R_NF, bytes([0xA1]) * 36, PARAMS_ID)
    cm_b = commit_coin_v3(NS, bundle, 500, COIN, R_NF, bytes([0xA2]) * 36, PARAMS_ID)
    assert cm_a != cm_b
    assert nullifier_a == nullifier_b


def test_same_tuple_with_another_recipient_key_does_not_reuse_nullifier() -> None:
    key_b = NullifierDerivingKeyV3(bytes([0x45]) * 48)
    bundle_b = _bundle(key_b)
    nullifier_a = compute_nullifier_v3(NS, _bundle().encode(), COIN, R_NF, KEY)
    nullifier_b = compute_nullifier_v3(NS, bundle_b.encode(), COIN, R_NF, key_b)
    assert bundle_b.nullifier_key_commitment != _bundle().nullifier_key_commitment
    assert nullifier_a != nullifier_b


def test_note_public_key_bundle_roundtrips_and_rejects_tampering() -> None:
    encoded = _bundle().encode()
    decoded = decode_note_public_key_bundle_v3(encoded)
    assert decoded == _bundle()
    assert decoded.encode() == encoded

    with pytest.raises(ValueError):
        decode_note_public_key_bundle_v3(encoded[:-1])
    with pytest.raises(ValueError):
        decode_note_public_key_bundle_v3(encoded + b"trailing")
    with pytest.raises(ValueError):
        decode_note_public_key_bundle_v3(b"\x00" + encoded[1:])


def test_nullifier_key_commitment_mismatch_fails_closed() -> None:
    commitment = compute_nullifier_key_commitment_v3(KEY)
    other = NullifierDerivingKeyV3(bytes([0x45]) * 48)
    assert not verify_nullifier_key_commitment_v3(commitment, other)


@pytest.mark.parametrize("bad_key", [b"", b"x" * 47, b"x" * 49, "not-bytes", None])
def test_v3_nullifier_key_has_exact_fixed_width(bad_key: object) -> None:
    with pytest.raises(ValueError):
        NullifierDerivingKeyV3(bad_key)  # type: ignore[arg-type]


def test_v3_is_additive_and_does_not_change_frozen_v2_nullifier() -> None:
    # The old V2 formula retains its existing known-answer vector unchanged.
    ns = NamespaceId(bytes.fromhex(
        "04c0037350b1b2551c5b7f8b19642abd"
        "e118113083130340a0986aacfaad3d7d"
        "38c96dac07c80e9c3d45e0a1111279d2"
    ))
    coin = ScopedCoinId(bytes(range(32)))
    secret = NullifierSecret(bytes(range(36)))
    assert compute_nullifier_v2(ns, coin, secret).value.hex() == (
        "059698470b8228712d86c630144b9aae"
        "0d0815ba1f2038b53c9d22d484af5d46"
        "60100eb47c8fea686ebb4855cd35159d"
    )

    key_b = NullifierDerivingKeyV3(bytes([0x45]) * 48)
    assert compute_nullifier_v3(NS, _bundle().encode(), COIN, R_NF, KEY) != compute_nullifier_v3(
        NS, _bundle(key_b).encode(), COIN, R_NF, key_b
    )
    assert compute_nullifier_v3(NS, _bundle(KEY, b"another-recipient-key").encode(), COIN, R_NF, KEY) != compute_nullifier_v3(
        NS, _bundle(KEY, AUTH_PK).encode(), COIN, R_NF, KEY
    )
