"""CHp4.7 regressions for recipient-keyed, commitment-bound V3 nullifiers.

These are reference byte-contract tests only. They do not prove circuit
soundness, address authentication, sender unlinkability under every leakage
model, or durable ledger safety.
"""
from __future__ import annotations

import pytest

from src.primitives.coin_commitment import CoinCommitment as CoinCommitmentV2
from src.primitives.coin_commitment_v3 import (
    CoinCommitmentV3,
    commit_coin_v3,
    verify_coin_opening_v3,
)
from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.nullifier import (
    Nullifier as NullifierV2,
    NullifierSecret,
    compute_nullifier_v2,
)
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    NullifierV3,
    compute_nullifier_key_commitment_v3,
    compute_nullifier_v3,
    generate_nullifier_deriving_key_v3,
    verify_nullifier_key_commitment_v3,
)
from src.protocol.note_public_key_bundle_v3 import (
    NotePublicKeyBundleV3,
    decode_note_public_key_bundle_v3,
)

NS = NamespaceIdV3(bytes([0x11]) * 48)
COIN = ScopedCoinId(bytes([0x22]) * 32)
R_NF = NullifierSecret(bytes([0x33]) * 36)
KEY = NullifierDerivingKeyV3(bytes([0x44]) * 48)
PARAMS_ID = b"v3-candidate-params"
TRANSFER_PARAMS_ID = b"v3-test-params"
AUTH_SCHEME = b"test-auth-scheme-v1"
AUTH_PK = b"test-recipient-public-key"
SALT_A = bytes([0xA1]) * 36
SALT_B = bytes([0xA2]) * 36


def _bundle(
    key: NullifierDerivingKeyV3 = KEY,
    auth_pk: bytes = AUTH_PK,
) -> NotePublicKeyBundleV3:
    return NotePublicKeyBundleV3(
        auth_scheme_id=AUTH_SCHEME,
        auth_public_key=auth_pk,
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(key),
    )


def _commit(
    bundle: bytes | None = None,
    *,
    value: int = 500,
    salt: bytes = SALT_A,
    params_id: bytes = PARAMS_ID,
    coin_id: ScopedCoinId = COIN,
    r_nf: NullifierSecret = R_NF,
):
    canonical_bundle = _bundle().encode() if bundle is None else bundle
    return commit_coin_v3(
        NS, canonical_bundle, value, coin_id, r_nf, salt, params_id
    )


def _nf(
    key: NullifierDerivingKeyV3 = KEY,
    bundle: bytes | None = None,
    commitment: CoinCommitmentV3 | None = None,
    *,
    params_id: bytes = PARAMS_ID,
    coin_id: ScopedCoinId = COIN,
    r_nf: NullifierSecret = R_NF,
):
    canonical_bundle = _bundle(key).encode() if bundle is None else bundle
    commitment_value = _commit(canonical_bundle, params_id=params_id) if commitment is None else commitment
    return compute_nullifier_v3(
        NS, params_id, canonical_bundle, commitment_value,
        coin_id, r_nf, key,
    )


def test_v3_bundle_key_commitment_note_commitment_and_nullifier_vectors() -> None:
    bundle = _bundle()
    encoded_bundle = bundle.encode()
    assert encoded_bundle.hex() == (
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

    commitment = _commit(encoded_bundle)
    assert commitment.value.hex() == (
        "7c29d710d6a81bed4f3df766421d66fa497072be7513022487eb55c8d4839f82"
        "a9cf6dd11105ce21602715f0644f99d0"
    )
    assert _nf(bundle=encoded_bundle, commitment=commitment).value.hex() == (
        "5309bdb17ad1527c06763ae96dfd806520132899bbdbc6519070883abb568a1"
        "af3bc2a43c3a965325df2ba084bcf6f93"
    )


def test_v2_and_v3_primitive_results_are_type_distinct() -> None:
    ns_v2 = NamespaceId(bytes.fromhex(
        "04c0037350b1b2551c5b7f8b19642abd"
        "e118113083130340a0986aacfaad3d7d"
        "38c96dac07c80e9c3d45e0a1111279d2"
    ))
    nf_v2 = compute_nullifier_v2(
        ns_v2, ScopedCoinId(bytes(range(32))), NullifierSecret(bytes(range(36)))
    )
    nf_v3 = _nf()
    cm_v2 = CoinCommitmentV2(bytes([0x11]) * 48)
    cm_v3 = _commit()

    assert isinstance(nf_v2, NullifierV2)
    assert isinstance(nf_v3, NullifierV3)
    assert type(nf_v2) is not type(nf_v3)
    assert isinstance(cm_v2, CoinCommitmentV2)
    assert isinstance(cm_v3, CoinCommitmentV3)
    assert type(cm_v2) is not type(cm_v3)


def test_v3_primitives_reject_legacy_namespace_type() -> None:
    legacy_namespace = NamespaceId(bytes([0x11]) * 48)
    bundle = _bundle().encode()
    with pytest.raises(TypeError, match="NamespaceIdV3"):
        commit_coin_v3(
            legacy_namespace, bundle, 500, COIN, R_NF, SALT_A, PARAMS_ID
        )
    commitment = _commit(bundle)
    with pytest.raises(TypeError, match="NamespaceIdV3"):
        compute_nullifier_v3(
            legacy_namespace, PARAMS_ID, bundle, commitment, COIN, R_NF, KEY
        )


def test_v3_nullifier_rejects_a_v2_commitment_object() -> None:
    with pytest.raises(TypeError, match="commitment must be a CoinCommitmentV3"):
        compute_nullifier_v3(
            NS, PARAMS_ID, _bundle().encode(),
            CoinCommitmentV2(bytes([0x11]) * 48),  # type: ignore[arg-type]
            COIN, R_NF, KEY,
        )


def test_different_commitment_salts_produce_different_v3_nullifiers() -> None:
    bundle = _bundle().encode()
    cm_a = _commit(bundle, salt=SALT_A)
    cm_b = _commit(bundle, salt=SALT_B)
    nf_a = _nf(bundle=bundle, commitment=cm_a)
    nf_b = _nf(bundle=bundle, commitment=cm_b)

    assert cm_a != cm_b
    assert nf_a != nf_b
    assert _nf(bundle=bundle, commitment=cm_a) == nf_a
    assert verify_coin_opening_v3(
        cm_a, NS, bundle, 500, COIN, R_NF, SALT_A, PARAMS_ID
    )
    assert not verify_coin_opening_v3(
        cm_a, NS, bundle, 501, COIN, R_NF, SALT_A, PARAMS_ID
    )


def test_v3_nullifier_binds_namespace_and_hidden_tuple_fields() -> None:
    """Valid alternate note openings must not reuse a baseline nullifier.

    This exercises the host reference only. It does not establish that a ZK
    circuit binds the same fields to one witness.
    """
    bundle = _bundle().encode()
    baseline_commitment = _commit(bundle)
    baseline_nullifier = compute_nullifier_v3(
        NS, PARAMS_ID, bundle, baseline_commitment, COIN, R_NF, KEY
    )
    assert verify_coin_opening_v3(
        baseline_commitment, NS, bundle, 500, COIN, R_NF, SALT_A, PARAMS_ID
    )

    alternate_namespace = NamespaceIdV3(bytes([0x12]) * 48)
    namespace_commitment = commit_coin_v3(
        alternate_namespace, bundle, 500, COIN, R_NF, SALT_A, PARAMS_ID
    )
    namespace_nullifier = compute_nullifier_v3(
        alternate_namespace, PARAMS_ID, bundle, namespace_commitment, COIN, R_NF, KEY
    )
    assert verify_coin_opening_v3(
        namespace_commitment, alternate_namespace, bundle, 500, COIN, R_NF,
        SALT_A, PARAMS_ID
    )
    assert namespace_nullifier != baseline_nullifier

    alternate_coin = ScopedCoinId(bytes([0x23]) * 32)
    coin_commitment = _commit(bundle, coin_id=alternate_coin)
    coin_nullifier = compute_nullifier_v3(
        NS, PARAMS_ID, bundle, coin_commitment, alternate_coin, R_NF, KEY
    )
    assert verify_coin_opening_v3(
        coin_commitment, NS, bundle, 500, alternate_coin, R_NF, SALT_A, PARAMS_ID
    )
    assert coin_nullifier != baseline_nullifier

    alternate_r_nf = NullifierSecret(bytes([0x34]) * 36)
    r_nf_commitment = _commit(bundle, r_nf=alternate_r_nf)
    r_nf_nullifier = compute_nullifier_v3(
        NS, PARAMS_ID, bundle, r_nf_commitment, COIN, alternate_r_nf, KEY
    )
    assert verify_coin_opening_v3(
        r_nf_commitment, NS, bundle, 500, COIN, alternate_r_nf, SALT_A, PARAMS_ID
    )
    assert r_nf_nullifier != baseline_nullifier


def test_v3_nullifier_binds_bundle_tuple_and_parameter_suite() -> None:
    bundle_a = _bundle().encode()
    cm_a = _commit(bundle_a)
    nf_a = _nf(bundle=bundle_a, commitment=cm_a)

    key_b = NullifierDerivingKeyV3(bytes([0x45]) * 48)
    bundle_b = _bundle(key_b).encode()
    cm_b = _commit(bundle_b)
    nf_b = _nf(key_b, bundle_b, cm_b)
    assert nf_a != nf_b

    alternate_auth_bundle = _bundle(KEY, b"another-recipient-auth-key").encode()
    cm_other_auth = _commit(alternate_auth_bundle)
    assert cm_other_auth != cm_a
    assert _nf(bundle=alternate_auth_bundle, commitment=cm_other_auth) != nf_a

    cm_other_params = _commit(bundle_a, params_id=b"v3-other-suite")
    assert _nf(
        bundle=bundle_a,
        commitment=cm_other_params,
        params_id=b"v3-other-suite",
    ) != nf_a


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

    bundle = _bundle().encode()
    cm = _commit(bundle)
    with pytest.raises(ValueError, match="does not open"):
        compute_nullifier_v3(
            NS, PARAMS_ID, bundle, cm, COIN, R_NF, other
        )


def test_v3_nullifier_rejects_malformed_bundle_or_commitment() -> None:
    valid_bundle = _bundle().encode()
    valid_commitment = _commit(valid_bundle)
    with pytest.raises(ValueError, match="trailing bytes"):
        compute_nullifier_v3(
            NS, PARAMS_ID, valid_bundle + b"x", valid_commitment, COIN, R_NF, KEY
        )
    with pytest.raises(ValueError, match="V3 commitment must be exactly"):
        CoinCommitmentV3(b"short")
    with pytest.raises(TypeError, match="commitment must be a CoinCommitmentV3"):
        compute_nullifier_v3(
            NS, PARAMS_ID, valid_bundle, b"short", COIN, R_NF, KEY  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="params_id"):
        compute_nullifier_v3(
            NS, b"", valid_bundle, valid_commitment, COIN, R_NF, KEY
        )


def test_v3_commitment_rejects_noncanonical_key_bundle() -> None:
    with pytest.raises(ValueError, match="trailing bytes"):
        commit_coin_v3(
            NS, _bundle().encode() + b"x", 500, COIN, R_NF, SALT_A, PARAMS_ID
        )


@pytest.mark.parametrize("bad_key", [b"", b"x" * 47, b"x" * 49, "not-bytes", None])
def test_v3_nullifier_key_has_exact_fixed_width(bad_key: object) -> None:
    with pytest.raises(ValueError):
        NullifierDerivingKeyV3(bad_key)  # type: ignore[arg-type]


def test_v3_is_additive_and_does_not_change_frozen_v2_nullifier() -> None:
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


def test_v3_transfer_identity_rejects_legacy_namespace_type() -> None:
    from src.protocol.output_identity import derive_output_identity_v3_candidate

    bundle = _bundle().encode()
    commitment = _commit(bundle)
    with pytest.raises(TypeError, match="NamespaceIdV3"):
        derive_output_identity_v3_candidate(
            namespace_id=NamespaceId(bytes([0x11]) * 48),
            parent_coin_id=COIN,
            parent_r_nf=R_NF,
            parent_public_key_bundle=bundle,
            parent_commitment=commitment,
            parent_nullifier_key=KEY,
            recipient_key_bundle=bundle,
            transaction_entropy=bytes(32),
            output_index=0,
            params_id=TRANSFER_PARAMS_ID,
        )


def test_v3_output_identity_is_anchored_and_recipient_key_bound() -> None:
    from src.protocol.output_identity import (
        derive_output_identity_v3_candidate,
        verify_output_identity_v3_candidate,
    )

    parent_bundle = _bundle(KEY, b"parent-pk").encode()
    parent_commitment = commit_coin_v3(
        NS, parent_bundle, 700, COIN, R_NF, bytes([0xA0]) * 36, TRANSFER_PARAMS_ID
    )
    recipient_key = NullifierDerivingKeyV3(bytes([0x45]) * 48)
    recipient_bundle = _bundle(recipient_key, b"recipient-pk").encode()
    common = dict(
        namespace_id=NS,
        parent_coin_id=COIN,
        parent_r_nf=R_NF,
        parent_public_key_bundle=parent_bundle,
        parent_commitment=parent_commitment,
        parent_nullifier_key=KEY,
        recipient_key_bundle=recipient_bundle,
        transaction_entropy=bytes([0x66]) * 32,
        params_id=TRANSFER_PARAMS_ID,
    )

    first = derive_output_identity_v3_candidate(output_index=0, **common)
    assert verify_output_identity_v3_candidate(
        output_coin_id=first.coin_id, output_r_nf=first.r_nf, output_index=0, **common
    )
    assert not verify_output_identity_v3_candidate(
        output_coin_id=ScopedCoinId(bytes([0x99]) * 32),
        output_r_nf=first.r_nf, output_index=0, **common
    )
    assert not verify_output_identity_v3_candidate(
        output_coin_id=first.coin_id, output_r_nf=first.r_nf,
        output_index=1, **common
    )

    expected_coin_id = (
        "747c6c1e6cd88c3b377183a046490d38"
        "bcf69fd7fe64cbd14696da797cdf17dd"
    )
    expected_r_nf = (
        "52806b4365e5184f871e96bf52bdda2e"
        "497a97291801e708d46239d9945c4613"
        "87a8da4f"
    )
    assert first.coin_id.data.hex() == expected_coin_id, (
        f"stale V3 output-identity KAT: coin_id={first.coin_id.data.hex()}, "
        f"r_nf={first.r_nf.data.hex()}"
    )
    assert first.r_nf.data.hex() == expected_r_nf

    alternate_bundle = _bundle(recipient_key, b"recipient-pk-alt").encode()
    alternatives = [
        derive_output_identity_v3_candidate(output_index=1, **common),
        derive_output_identity_v3_candidate(
            output_index=0, **{**common, "transaction_entropy": bytes([0x67]) * 32}
        ),
        derive_output_identity_v3_candidate(
            output_index=0, **{**common, "recipient_key_bundle": alternate_bundle}
        ),
        derive_output_identity_v3_candidate(
            output_index=0,
            **{**common, "parent_coin_id": ScopedCoinId(bytes([0x23]) * 32)}
        ),
        derive_output_identity_v3_candidate(
            output_index=0,
            **{**common, "parent_r_nf": NullifierSecret(bytes([0x34]) * 36)}
        ),
        derive_output_identity_v3_candidate(
            output_index=0, **{**common, "namespace_id": NamespaceIdV3(bytes([0x12]) * 48)}
        ),
        derive_output_identity_v3_candidate(
            output_index=0, **{**common, "params_id": b"other-params"}
        ),
        derive_output_identity_v3_candidate(
            output_index=0, **{**common, "parent_commitment": CoinCommitmentV3(bytes([0x98]) * 48)}
        ),
    ]
    assert all(candidate != first for candidate in alternatives)


def test_v3_parent_nullifier_key_is_required_for_transfer_derivation() -> None:
    from src.protocol.output_identity import derive_output_identity_v3_candidate

    bundle = _bundle().encode()
    parent_commitment = _commit(bundle)
    with pytest.raises(TypeError, match="parent_commitment must be a CoinCommitmentV3"):
        derive_output_identity_v3_candidate(
            namespace_id=NS,
            parent_coin_id=COIN,
            parent_r_nf=R_NF,
            parent_public_key_bundle=bundle,
            parent_commitment=CoinCommitmentV2(bytes([0x11]) * 48),  # type: ignore[arg-type]
            parent_nullifier_key=KEY,
            recipient_key_bundle=bundle,
            transaction_entropy=bytes(32),
            output_index=0,
            params_id=PARAMS_ID,
        )

    with pytest.raises(TypeError, match="parent_nullifier_key"):
        derive_output_identity_v3_candidate(
            namespace_id=NS,
            parent_coin_id=COIN,
            parent_r_nf=R_NF,
            parent_public_key_bundle=bundle,
            parent_commitment=parent_commitment,
            parent_nullifier_key=b"not-a-key",  # type: ignore[arg-type]
            recipient_key_bundle=bundle,
            transaction_entropy=bytes(32),
            output_index=0,
            params_id=PARAMS_ID,
        )


def test_v3_nullifier_and_identity_reject_noncanonical_bundles() -> None:
    from src.protocol.output_identity import derive_output_identity_v3_candidate

    bundle = _bundle().encode()
    commitment = _commit(bundle)
    with pytest.raises(ValueError, match="trailing bytes"):
        compute_nullifier_v3(
            NS, PARAMS_ID, bundle + b"x", commitment, COIN, R_NF, KEY
        )

    with pytest.raises(ValueError, match="trailing bytes"):
        derive_output_identity_v3_candidate(
            namespace_id=NS,
            parent_coin_id=COIN,
            parent_r_nf=R_NF,
            parent_public_key_bundle=bundle,
            parent_commitment=commitment,
            parent_nullifier_key=KEY,
            recipient_key_bundle=bundle + b"x",
            transaction_entropy=bytes([0x66]) * 32,
            output_index=0,
            params_id=TRANSFER_PARAMS_ID,
        )

def test_v3_nullifier_key_generation_uses_os_csprng(monkeypatch) -> None:
    import src.primitives.nullifier_v3 as nullifier_v3

    requested_lengths: list[int] = []

    def deterministic_test_source(length: int) -> bytes:
        requested_lengths.append(length)
        return bytes(range(length))

    monkeypatch.setattr(nullifier_v3.secrets, "token_bytes", deterministic_test_source)
    key = generate_nullifier_deriving_key_v3()

    assert requested_lengths == [48]
    assert key.data == bytes(range(48))
    assert len(key.data) == 48
    assert key.data.hex() not in repr(key)
    assert "redacted" in repr(key).lower()
    assert verify_nullifier_key_commitment_v3(
        compute_nullifier_key_commitment_v3(key), key
    )


def test_v3_nullifier_key_generation_rejects_invalid_source_output(monkeypatch) -> None:
    import src.primitives.nullifier_v3 as nullifier_v3

    monkeypatch.setattr(nullifier_v3.secrets, "token_bytes", lambda _length: b"short")
    with pytest.raises(ValueError, match="exactly 48 bytes"):
        generate_nullifier_deriving_key_v3()


def test_v3_nullifier_key_generation_fails_closed_if_os_source_fails(monkeypatch) -> None:
    import src.primitives.nullifier_v3 as nullifier_v3

    def failed_source(_length: int) -> bytes:
        raise OSError("test entropy-source failure")

    monkeypatch.setattr(nullifier_v3.secrets, "token_bytes", failed_source)
    with pytest.raises(OSError, match="test entropy-source failure"):
        generate_nullifier_deriving_key_v3()

