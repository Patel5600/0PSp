"""Differential and unit tests for the C11 Native Mobile Tier 1 Engine."""
import pytest
from pathlib import Path

from src.adapters.native_mobile_adapter import NativeMobileEngine, find_native_library
from src.primitives.namespace import ScopedCoinId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier import NullifierSecret
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    NullifierKeyCommitmentV3,
    compute_nullifier_v3,
    compute_nullifier_key_commitment_v3,
)
from src.primitives.coin_commitment_v3 import commit_coin_v3
from src.protocol.note_public_key_bundle_v3 import NotePublicKeyBundleV3
from src.protocol.output_identity import derive_output_identity_v3_candidate
from src.protocol.transaction_v3_candidate import (
    TxFieldsV3Candidate,
    transaction_digest_v3_candidate,
    V3_NK_POSSESSION_POLICY_CANDIDATE,
)


@pytest.fixture(scope="module")
def native_engine():
    try:
        lib_path = find_native_library()
    except FileNotFoundError:
        pytest.skip("libpsp_native not compiled; run make in native/")
    return NativeMobileEngine(lib_path)


def test_native_bundle_and_output_identity_differential(native_engine):
    """Assert byte-for-byte differential match between C11 and Python output identity."""
    params_id = b"ringtail-differential-test"
    namespace = NamespaceIdV3(b"\x55" * 48)
    parent_coin_id = ScopedCoinId(b"\x11" * 32)
    parent_r_nf = NullifierSecret(b"\x22" * 36)
    parent_nk = NullifierDerivingKeyV3(b"\x33" * 48)
    entropy = b"\x44" * 32

    # Build parent bundle
    parent_nk_commit = compute_nullifier_key_commitment_v3(parent_nk)
    parent_bundle_obj = NotePublicKeyBundleV3(
        auth_scheme_id=b"test-auth",
        auth_public_key=b"\x66" * 32,
        nullifier_key_commitment=parent_nk_commit,
    )
    parent_bundle_bytes = parent_bundle_obj.encode()

    # Build recipient bundle
    recipient_nk = NullifierDerivingKeyV3(b"\x77" * 48)
    recipient_nk_commit = compute_nullifier_key_commitment_v3(recipient_nk)
    recipient_bundle_obj = NotePublicKeyBundleV3(
        auth_scheme_id=b"test-auth",
        auth_public_key=b"\x88" * 32,
        nullifier_key_commitment=recipient_nk_commit,
    )
    recipient_bundle_bytes = recipient_bundle_obj.encode()

    # Compute parent commitment & nullifier in Python
    parent_rho = b"\x99" * 36
    parent_commit = commit_coin_v3(
        namespace, parent_bundle_bytes, 1000,
        parent_coin_id, parent_r_nf, parent_rho, params_id
    )
    parent_nullifier = compute_nullifier_v3(
        namespace, params_id, parent_bundle_bytes, parent_commit,
        parent_coin_id, parent_r_nf, parent_nk
    )

    # 1. Pure Python reference output identity
    py_out = derive_output_identity_v3_candidate(
        namespace_id=namespace,
        parent_coin_id=parent_coin_id,
        parent_r_nf=parent_r_nf,
        parent_public_key_bundle=parent_bundle_bytes,
        parent_commitment=parent_commit,
        parent_nullifier_key=parent_nk,
        recipient_key_bundle=recipient_bundle_bytes,
        transaction_entropy=entropy,
        output_index=0,
        params_id=params_id,
    )

    # 2. Native C11 engine output identity
    native_coin_id, native_r_nf = native_engine.derive_output_identity_v3(
        params_id=params_id,
        namespace_id=namespace.data,
        parent_nullifier=parent_nullifier.value,
        parent_commitment=parent_commit.value,
        parent_coin_id=parent_coin_id.data,
        parent_r_nf=parent_r_nf.data,
        parent_bundle=parent_bundle_bytes,
        recipient_bundle=recipient_bundle_bytes,
        transaction_entropy=entropy,
        output_index=0,
    )

    # Differential assertion: byte-for-byte exact equality
    assert native_coin_id == py_out.coin_id.data
    assert native_r_nf == py_out.r_nf.data


def test_native_tier1_spend_package_differential(native_engine):
    """Assert byte-for-byte differential match between native package and TxFieldsV3Candidate."""
    params_id = b"mobile-tier1-spend-test"
    namespace = NamespaceIdV3(b"\x12" * 48)
    coin_id = ScopedCoinId(b"\x34" * 32)
    r_nf = NullifierSecret(b"\x56" * 36)
    rho_coin = b"\x78" * 36
    nk = NullifierDerivingKeyV3(b"\x9a" * 48)
    entropy = b"\xbc" * 32
    root = b"\xde" * 48
    state_head = b"\xf0" * 48
    state_context = b"\xaa" * 64

    # Build input note bundle
    nk_commit = compute_nullifier_key_commitment_v3(nk)
    bundle_obj = NotePublicKeyBundleV3(
        auth_scheme_id=b"mldsa-test",
        auth_public_key=b"\xcc" * 32,
        nullifier_key_commitment=nk_commit,
    )
    bundle_bytes = bundle_obj.encode()

    input_value = 5000
    output_value = 4900
    fee = 100

    # 1. Generate package in native C11
    native_pkg = native_engine.create_tier1_spend_package(
        params_id=params_id,
        namespace_id=namespace.data,
        input_bundle=bundle_bytes,
        input_value=input_value,
        input_coin_id=coin_id.data,
        input_r_nf=r_nf.data,
        input_rho_coin=rho_coin,
        input_nk=nk.data,
        recipient_bundle=bundle_bytes,
        output_value=output_value,
        fee=fee,
        output_entropy=entropy,
        commitment_root=root,
        state_head=state_head,
        state_context_digest=state_context,
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )

    # 2. Build Python reference TxFieldsV3Candidate statement
    py_tx = TxFieldsV3Candidate(
        params_id=params_id,
        namespace_id=namespace,
        commitment_root=root,
        input_nullifier=parent_nullifier_type(native_pkg.input_nullifier),
        ledger_state_head=state_head,
        state_context_digest=state_context,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=fee,
        output_entropy=entropy,
        output_commitments=(CoinCommitmentV3(native_pkg.output_commitment),),
        chain_id=bytes([0x01]) * 32,
        recipient_address=bytes([0xA1]) * 20,
        withdraw_value=0,
        relayer_address=bytes([0xB2]) * 20,
    )

    py_encoded_tx = py_tx.encode()
    py_tx_digest = transaction_digest_v3_candidate(py_tx)

    # Assert byte-for-byte exact equality of canonical transaction encoding and digest
    assert native_pkg.encoded_tx == py_encoded_tx
    assert native_pkg.tx_digest == py_tx_digest


def parent_nullifier_type(val):
    from src.primitives.nullifier_v3 import NullifierV3
    return NullifierV3(val)


def test_native_spend_package_adversarial_rejection(native_engine):
    """Assert fail-closed rejection on invalid value conservation or unauthorized NK."""
    params_id = b"adversarial-test"
    namespace = b"\x11" * 48
    coin_id = b"\x22" * 32
    r_nf = b"\x33" * 36
    rho = b"\x44" * 36
    nk = b"\x55" * 48
    imposter_nk = b"\x66" * 48

    nk_commit = compute_nullifier_key_commitment_v3(NullifierDerivingKeyV3(nk))
    bundle_bytes = NotePublicKeyBundleV3(
        auth_scheme_id=b"test",
        auth_public_key=b"\x77" * 32,
        nullifier_key_commitment=nk_commit,
    ).encode()

    # 1. Inflation attempt: input (1000) != output (950) + fee (100) -> 1050
    with pytest.raises(ValueError, match="failed with code"):
        native_engine.create_tier1_spend_package(
            params_id=params_id, namespace_id=namespace,
            input_bundle=bundle_bytes, input_value=1000,
            input_coin_id=coin_id, input_r_nf=r_nf, input_rho_coin=rho, input_nk=nk,
            recipient_bundle=bundle_bytes, output_value=950, fee=100,
            output_entropy=b"\x88" * 32, commitment_root=b"\x99" * 48,
            state_head=b"\xaa" * 48, state_context_digest=b"\xbb" * 64,
            chain_id=bytes([0x01]) * 32, recipient_address=bytes([0xA1]) * 20,
            withdraw_value=0, relayer_address=bytes([0xB2]) * 20,
        )

    # 2. Imposter NK attempt
    with pytest.raises(ValueError, match="failed with code"):
        native_engine.create_tier1_spend_package(
            params_id=params_id, namespace_id=namespace,
            input_bundle=bundle_bytes, input_value=1000,
            input_coin_id=coin_id, input_r_nf=r_nf, input_rho_coin=rho, input_nk=imposter_nk,
            recipient_bundle=bundle_bytes, output_value=900, fee=100,
            output_entropy=b"\x88" * 32, commitment_root=b"\x99" * 48,
            state_head=b"\xaa" * 48, state_context_digest=b"\xbb" * 64,
        )


def test_native_note_generation(native_engine):
    """Assert local note generation produces cryptographically valid commitments."""
    note = native_engine.generate_note_v3(
        params_id=b"mobile-wallet-params",
        namespace_id=b"\x12" * 48,
        value=25000,
        auth_scheme_id=b"mldsa-44",
        auth_public_key=b"\xfe" * 32,
    )

    assert len(note.nk) == 48
    assert len(note.coin_id) == 32
    assert len(note.r_nf) == 36
    assert len(note.rho_coin) == 36
    assert len(note.commitment) == 48

    # Verify commitment in Python
    expected_commit = commit_coin_v3(
        NamespaceIdV3(b"\x12" * 48),
        note.bundle,
        25000,
        ScopedCoinId(note.coin_id),
        NullifierSecret(note.r_nf),
        note.rho_coin,
        b"mobile-wallet-params",
    )
    assert note.commitment == expected_commit.value


def test_native_merkle_path_differential(native_engine):
    """Assert native C11 Merkle path verification matches Python commitment tree exactly."""
    from src.primitives.namespace_v3 import derive_namespace_id_v3
    from src.protocol.commitment_tree import CommitmentTree

    ns = derive_namespace_id_v3(b"mobile-ledger", b"deployment", b"asset")
    c1 = b"\x11" * 48
    c2 = b"\x22" * 48
    c3 = b"\x33" * 48

    tree = CommitmentTree(ns, [c1, c2, c3])

    for idx, c in enumerate([c1, c2, c3]):
        path = list(tree.membership_path(idx))
        # Native verification must pass
        assert native_engine.verify_merkle_path(
            namespace_id=ns.data,
            leaf_index=idx,
            commitment=c,
            siblings=path,
            expected_root=tree.root,
        )

    # Tampered commitment must fail
    path = list(tree.membership_path(1))
    assert not native_engine.verify_merkle_path(
        namespace_id=ns.data,
        leaf_index=1,
        commitment=b"\x99" * 48,
        siblings=path,
        expected_root=tree.root,
    )

    # Tampered sibling must fail
    altered_path = list(path)
    altered_path[0] = bytes([altered_path[0][0] ^ 1]) + altered_path[0][1:]
    assert not native_engine.verify_merkle_path(
        namespace_id=ns.data,
        leaf_index=1,
        commitment=c2,
        siblings=altered_path,
        expected_root=tree.root,
    )


def test_native_keys_v3_differential(native_engine):
    """Assert byte-for-byte differential match between C11 and Python V3 key hierarchy."""
    from src.primitives.keys_v3 import (
        derive_keys_v3,
        compute_spend_auth_token_v3,
        verify_spend_auth_token_v3,
    )

    sk_bytes = b"\x77" * 48

    # 1. Derive keys in Python
    keys_py = derive_keys_v3(sk_bytes)

    # 2. Derive keys in Native C11
    ak_c, nk_c, pk_owner_c = native_engine.derive_keys_v3(sk_bytes)

    assert ak_c == keys_py.ak
    assert nk_c == keys_py.nk
    assert pk_owner_c == keys_py.pk_owner

    # 3. Spend auth token differential
    tx_digest = b"\xaa" * 64
    commitment = b"\xbb" * 48

    token_py = compute_spend_auth_token_v3(sk_bytes, tx_digest, commitment)
    token_c = native_engine.compute_spend_auth_token_v3(
        sk_spend=sk_bytes, tx_digest=tx_digest, commitment=commitment
    )

    assert token_c == token_py

    # 4. Verification in native
    assert native_engine.verify_spend_auth_token_v3(
        sk_spend=sk_bytes, tx_digest=tx_digest, commitment=commitment, token=token_c
    )
    # Tampered token must fail
    tampered = bytes([token_c[0] ^ 0xFF]) + token_c[1:]
    assert not native_engine.verify_spend_auth_token_v3(
        sk_spend=sk_bytes, tx_digest=tx_digest, commitment=commitment, token=tampered
    )

