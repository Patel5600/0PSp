"""CHp4.6 selected KATs and adversarial regressions for output identity.

The tests use the repository's real V2 Python reference primitives. They are
finite regressions, not a ZK circuit, uniqueness theorem or privacy proof.
"""
from __future__ import annotations

import pytest

from src.primitives.coin_commitment import commit_coin_v2
from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import NullifierSecret, compute_nullifier_v2
from src.protocol.output_identity import (
    OUTPUT_ID_BYTES,
    TRANSACTION_ENTROPY_BYTES,
    derive_output_identity_candidate,
    verify_output_identity_candidate,
)

NS = NamespaceId(bytes(range(48)))
PARENT_COIN = ScopedCoinId(bytes(range(32)))
PARENT_RNF = NullifierSecret(bytes(range(36)))
SPEND_KEY_WITNESS = bytes(range(32, 64))
TX_ENTROPY = bytes(range(64, 64 + TRANSACTION_ENTROPY_BYTES))
PARAMS_ID = b"candidate-params-v1"


def _derive(index: int):
    return derive_output_identity_candidate(
        namespace_id=NS,
        parent_coin_id=PARENT_COIN,
        parent_r_nf=PARENT_RNF,
        spend_key_witness=SPEND_KEY_WITNESS,
        transaction_entropy=TX_ENTROPY,
        output_index=index,
        params_id=PARAMS_ID,
    )


def test_candidate_and_actual_v2_primitives_hardcoded_kat() -> None:
    parent_nf = compute_nullifier_v2(NS, PARENT_COIN, PARENT_RNF)
    assert parent_nf.value.hex() == (
        "7d2f88a729012317d51ed53caa84b6da"
        "352068057b701026dccf329eebda6ded"
        "3e2bc54f71c5b02e627ef09429d70e10"
    )

    output = _derive(0)
    assert len(output.coin_id.data) == OUTPUT_ID_BYTES == 32
    assert len(output.r_nf.data) == 36
    assert output.coin_id.data.hex() == (
        "dd461494074bfad2fb5ece022e12346f"
        "ae8ff80089c3d8bc3830990712ee987d"
    )
    assert output.r_nf.data.hex() == (
        "ac660bf7d78f987c7c388026e97a7104"
        "ef1a857b74e3971192c0cc7e72715ee0a5e93b15"
    )

    out_nf = compute_nullifier_v2(NS, output.coin_id, output.r_nf)
    assert out_nf.value.hex() == (
        "91fa627aaa307427ecf137b54b312dcd"
        "532cf063cd577b16347a4582c6e59c42"
        "13a477bccc5121ba74cde28dda0866f5"
    )
    commitment = commit_coin_v2(
        NS, b"alice-test-pk", 500, output.coin_id, output.r_nf,
        bytes([0xA0]) * 36, PARAMS_ID,
    )
    assert commitment.value.hex() == (
        "e0fd095c34c9a0acf9ee5d5e06a71a1e"
        "360814037937ef7c9045ac584cb3d058"
        "52c9fb290bfdb15ac85e434f9dde1b36"
    )


def test_distinct_output_indexes_separate_selected_cross_recipient_vector() -> None:
    alice = _derive(0)
    bob = _derive(1)
    assert alice.coin_id != bob.coin_id
    assert alice.r_nf != bob.r_nf

    alice_nf = compute_nullifier_v2(NS, alice.coin_id, alice.r_nf)
    bob_nf = compute_nullifier_v2(NS, bob.coin_id, bob.r_nf)
    assert alice_nf != bob_nf
    assert bob.coin_id.data.hex() == (
        "ccefd7a455f6782e24ba2bb559062ce"
        "31616b30541be66a1ee3de6eaeefc4e70"
    )
    assert bob.r_nf.data.hex() == (
        "1f456c9ee707d0e7690d685ada2bf850"
        "fbd8f0af8c63e54822e75e1328b92feec195db10"
    )
    assert bob_nf.value.hex() == (
        "42f9cd01931c57c204960b0ff2949a10"
        "7b68d4ca7e0a62ed4cca7e6f27975255"
        "b6d808ada88f115e4e982df802d81e74"
    )
    bob_commitment = commit_coin_v2(
        NS, b"bob-test-pk", 500, bob.coin_id, bob.r_nf,
        bytes([0xA1]) * 36, PARAMS_ID,
    )
    assert bob_commitment.value.hex() == (
        "a1d487bacc2bdaa5b90d87bad4968fd4"
        "ad761dd4a8b230c03253b37e8a5661ca"
        "c020b7ab23b69c17902c7d8d54e59c65"
    )


def test_reference_predicate_rejects_tuple_substitution_for_another_index() -> None:
    alice = _derive(0)
    common = dict(
        namespace_id=NS, parent_coin_id=PARENT_COIN, parent_r_nf=PARENT_RNF,
        spend_key_witness=SPEND_KEY_WITNESS, transaction_entropy=TX_ENTROPY,
        params_id=PARAMS_ID,
    )
    assert verify_output_identity_candidate(
        output_coin_id=alice.coin_id, output_r_nf=alice.r_nf,
        output_index=0, **common,
    )
    assert not verify_output_identity_candidate(
        output_coin_id=alice.coin_id, output_r_nf=alice.r_nf,
        output_index=1, **common,
    )


def test_existing_v2_primitives_reproduce_original_same_tuple_failure_mode() -> None:
    """Different recipient commitments can still share one tuple's nullifier."""
    cm_alice = commit_coin_v2(
        NS, b"alice", 500, PARENT_COIN, PARENT_RNF, bytes([0xA2]) * 36, PARAMS_ID
    )
    cm_bob = commit_coin_v2(
        NS, b"bob", 500, PARENT_COIN, PARENT_RNF, bytes([0xB2]) * 36, PARAMS_ID
    )
    assert cm_alice != cm_bob
    nf_alice = compute_nullifier_v2(NS, PARENT_COIN, PARENT_RNF)
    nf_bob = compute_nullifier_v2(NS, PARENT_COIN, PARENT_RNF)
    assert nf_alice == nf_bob


def test_candidate_changes_for_parent_namespace_secret_entropy_and_params() -> None:
    baseline = _derive(0)
    variants = [
        derive_output_identity_candidate(
            namespace_id=NamespaceId(bytes([0xF0]) * 48),
            parent_coin_id=PARENT_COIN, parent_r_nf=PARENT_RNF,
            spend_key_witness=SPEND_KEY_WITNESS, transaction_entropy=TX_ENTROPY,
            output_index=0, params_id=PARAMS_ID,
        ),
        derive_output_identity_candidate(
            namespace_id=NS, parent_coin_id=ScopedCoinId(bytes([0xF1]) * 32),
            parent_r_nf=PARENT_RNF, spend_key_witness=SPEND_KEY_WITNESS,
            transaction_entropy=TX_ENTROPY, output_index=0, params_id=PARAMS_ID,
        ),
        derive_output_identity_candidate(
            namespace_id=NS, parent_coin_id=PARENT_COIN,
            parent_r_nf=NullifierSecret(bytes([0xF2]) * 36),
            spend_key_witness=SPEND_KEY_WITNESS, transaction_entropy=TX_ENTROPY,
            output_index=0, params_id=PARAMS_ID,
        ),
        derive_output_identity_candidate(
            namespace_id=NS, parent_coin_id=PARENT_COIN, parent_r_nf=PARENT_RNF,
            spend_key_witness=bytes([0xF3]) * 32, transaction_entropy=TX_ENTROPY,
            output_index=0, params_id=PARAMS_ID,
        ),
        derive_output_identity_candidate(
            namespace_id=NS, parent_coin_id=PARENT_COIN, parent_r_nf=PARENT_RNF,
            spend_key_witness=SPEND_KEY_WITNESS, transaction_entropy=bytes([0xF4]) * 32,
            output_index=0, params_id=PARAMS_ID,
        ),
        derive_output_identity_candidate(
            namespace_id=NS, parent_coin_id=PARENT_COIN, parent_r_nf=PARENT_RNF,
            spend_key_witness=SPEND_KEY_WITNESS, transaction_entropy=TX_ENTROPY,
            output_index=0, params_id=b"different-params",
        ),
    ]
    assert all(item.coin_id != baseline.coin_id for item in variants)
    assert all(item.r_nf != baseline.r_nf for item in variants)


@pytest.mark.parametrize("bad_index", [-1, 65536, True, 1.5])
def test_output_index_must_be_canonical_uint16(bad_index: object) -> None:
    with pytest.raises(ValueError):
        derive_output_identity_candidate(
            namespace_id=NS, parent_coin_id=PARENT_COIN, parent_r_nf=PARENT_RNF,
            spend_key_witness=SPEND_KEY_WITNESS, transaction_entropy=TX_ENTROPY,
            output_index=bad_index,  # type: ignore[arg-type]
            params_id=PARAMS_ID,
        )


def test_entropy_and_parameter_lengths_are_checked() -> None:
    common = dict(
        namespace_id=NS, parent_coin_id=PARENT_COIN, parent_r_nf=PARENT_RNF,
        spend_key_witness=SPEND_KEY_WITNESS, output_index=0, params_id=PARAMS_ID,
    )
    with pytest.raises(ValueError):
        derive_output_identity_candidate(transaction_entropy=b"short", **common)
    with pytest.raises(ValueError):
        derive_output_identity_candidate(transaction_entropy=TX_ENTROPY, **{**common, "params_id": b""})
