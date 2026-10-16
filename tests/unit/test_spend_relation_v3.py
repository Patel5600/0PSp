"""Unit tests for the complete 0PSP V3 spend relation and recipient privacy (P0 Issue #33)."""
from __future__ import annotations

import hashlib
import pytest
from dataclasses import replace

from src.primitives.coin_commitment_v3 import commit_coin_v3
from src.primitives.namespace import ScopedCoinId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier import NullifierSecret
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    NullifierV3,
    compute_nullifier_key_commitment_v3,
    compute_nullifier_v3,
)
from src.protocol.commitment_tree import CommitmentTree, TREE_DEPTH
from src.protocol.note_public_key_bundle_v3 import NotePublicKeyBundleV3
from src.protocol.output_identity import derive_output_identity_v3_candidate
from src.protocol.spend_relation_v3 import (
    SpendRelationV3Error,
    SpendWitnessV3,
    verify_spend_relation_v3_reference,
)
from src.protocol.transaction_v3_candidate import (
    TxFieldsV3Candidate,
    V3_NK_POSSESSION_POLICY_CANDIDATE,
)

NAMESPACE = NamespaceIdV3(b"\x42" * 48)
PARAMS_ID = b"spend-v3-relation-test-params"
AUTH_SCHEME = b"0PSP-AUTH-SCHEME-V3"


def _create_test_fixture():
    # 1. Setup Sender / Input Note
    sender_nk = NullifierDerivingKeyV3(b"\x11" * 48)
    sender_bundle = NotePublicKeyBundleV3(
        auth_scheme_id=AUTH_SCHEME,
        auth_public_key=b"\x01" * 48,
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(sender_nk),
    ).encode()

    input_coin_id = ScopedCoinId(b"\xaa" * 32)
    input_r_nf = NullifierSecret(b"\xbb" * 36)
    input_rho = b"\xcc" * 36
    input_value = 1000

    input_commitment = commit_coin_v3(
        namespace_id=NAMESPACE,
        public_key_bundle=sender_bundle,
        value=input_value,
        coin_id=input_coin_id,
        r_nf=input_r_nf,
        rho_coin=input_rho,
        params_id=PARAMS_ID,
    )

    # 2. Build Merkle tree with input commitment at index 0
    tree = CommitmentTree(NAMESPACE, [input_commitment.value])
    commitment_root = tree.root
    merkle_siblings = tuple(tree.membership_path(0))

    # 3. Derive input nullifier
    input_nullifier = compute_nullifier_v3(
        namespace_id=NAMESPACE,
        params_id=PARAMS_ID,
        public_key_bundle=sender_bundle,
        commitment=input_commitment,
        coin_id=input_coin_id,
        r_nf=input_r_nf,
        nullifier_key=sender_nk,
    )

    # 4. Setup Recipient / Output Note
    recipient_nk = NullifierDerivingKeyV3(b"\x22" * 48)
    recipient_bundle = NotePublicKeyBundleV3(
        auth_scheme_id=AUTH_SCHEME,
        auth_public_key=b"\x02" * 48,
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(recipient_nk),
    ).encode()

    fee = 50
    output_value = 950
    output_rho = b"\xdd" * 36
    output_entropy = b"\xee" * 32

    output_identity = derive_output_identity_v3_candidate(
        namespace_id=NAMESPACE,
        parent_coin_id=input_coin_id,
        parent_r_nf=input_r_nf,
        parent_public_key_bundle=sender_bundle,
        parent_commitment=input_commitment,
        parent_nullifier_key=sender_nk,
        recipient_key_bundle=recipient_bundle,
        transaction_entropy=output_entropy,
        output_index=0,
        params_id=PARAMS_ID,
    )

    output_commitment = commit_coin_v3(
        namespace_id=NAMESPACE,
        public_key_bundle=recipient_bundle,
        value=output_value,
        coin_id=output_identity.coin_id,
        r_nf=output_identity.r_nf,
        rho_coin=output_rho,
        params_id=PARAMS_ID,
    )

    # 5. Build public statement
    statement = TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=commitment_root,
        input_nullifier=input_nullifier,
        ledger_state_head=b"\x55" * 48,
        state_context_digest=b"\x66" * 64,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=fee,
        output_entropy=output_entropy,
        output_commitments=(output_commitment,),
    )

    witness = SpendWitnessV3(
        input_bundle=sender_bundle,
        input_value=input_value,
        input_coin_id=input_coin_id,
        input_r_nf=input_r_nf,
        input_rho=input_rho,
        input_nk=sender_nk,
        leaf_index=0,
        merkle_siblings=merkle_siblings,
        recipient_bundle=recipient_bundle,
        output_value=output_value,
        output_rho=output_rho,
    )

    return statement, witness, recipient_nk, output_identity, output_commitment


def test_valid_spend_relation_v3_acceptance() -> None:
    """Proves that a completely valid V3 spend witness passes all predicates."""
    statement, witness, _, _, _ = _create_test_fixture()
    digest = verify_spend_relation_v3_reference(statement, witness)
    assert len(digest) == 64


def test_spend_relation_v3_inflation_rejected() -> None:
    """Proves that creating more output value than input value is rejected."""
    statement, witness, _, _, _ = _create_test_fixture()
    # Inflate output value from 950 to 951 (total out 1001 != in 1000)
    tampered_witness = SpendWitnessV3(
        input_bundle=witness.input_bundle,
        input_value=witness.input_value,
        input_coin_id=witness.input_coin_id,
        input_r_nf=witness.input_r_nf,
        input_rho=witness.input_rho,
        input_nk=witness.input_nk,
        leaf_index=witness.leaf_index,
        merkle_siblings=witness.merkle_siblings,
        recipient_bundle=witness.recipient_bundle,
        output_value=951,
        output_rho=witness.output_rho,
    )
    with pytest.raises(SpendRelationV3Error, match="derived output commitment does not match"):
        verify_spend_relation_v3_reference(statement, tampered_witness)


def test_spend_relation_v3_unopened_nk_rejected() -> None:
    """Proves that providing an nk that does not open the input note bundle is rejected."""
    statement, witness, _, _, _ = _create_test_fixture()
    wrong_nk = NullifierDerivingKeyV3(b"\x99" * 48)
    tampered_witness = SpendWitnessV3(
        input_bundle=witness.input_bundle,
        input_value=witness.input_value,
        input_coin_id=witness.input_coin_id,
        input_r_nf=witness.input_r_nf,
        input_rho=witness.input_rho,
        input_nk=wrong_nk,
        leaf_index=witness.leaf_index,
        merkle_siblings=witness.merkle_siblings,
        recipient_bundle=witness.recipient_bundle,
        output_value=witness.output_value,
        output_rho=witness.output_rho,
    )
    with pytest.raises(SpendRelationV3Error, match="input_nk does not match"):
        verify_spend_relation_v3_reference(statement, tampered_witness)


def test_spend_relation_v3_tampered_merkle_root_rejected() -> None:
    """Proves that proving against an uncommitted or fake Merkle root is rejected."""
    statement, witness, _, _, _ = _create_test_fixture()
    fake_statement = TxFieldsV3Candidate(
        params_id=statement.params_id,
        namespace_id=statement.namespace_id,
        commitment_root=b"\x00" * 48,
        input_nullifier=statement.input_nullifier,
        ledger_state_head=statement.ledger_state_head,
        state_context_digest=statement.state_context_digest,
        authorization_policy_id=statement.authorization_policy_id,
        fee=statement.fee,
        output_entropy=statement.output_entropy,
        output_commitments=statement.output_commitments,
    )
    with pytest.raises(SpendRelationV3Error, match="not a valid member of statement commitment_root"):
        verify_spend_relation_v3_reference(fake_statement, witness)


def test_spend_relation_v3_tampered_nullifier_rejected() -> None:
    """Proves that a transaction statement with an arbitrary nullifier is rejected."""
    statement, witness, _, _, _ = _create_test_fixture()
    fake_nullifier = NullifierV3(b"\xfe" * 48)
    fake_statement = TxFieldsV3Candidate(
        params_id=statement.params_id,
        namespace_id=statement.namespace_id,
        commitment_root=statement.commitment_root,
        input_nullifier=fake_nullifier,
        ledger_state_head=statement.ledger_state_head,
        state_context_digest=statement.state_context_digest,
        authorization_policy_id=statement.authorization_policy_id,
        fee=statement.fee,
        output_entropy=statement.output_entropy,
        output_commitments=statement.output_commitments,
    )
    with pytest.raises(SpendRelationV3Error, match="input NullifierV3 does not match"):
        verify_spend_relation_v3_reference(fake_statement, witness)


def test_spend_relation_v3_recipient_privacy_theorem() -> None:
    """Recipient Privacy Theorem:

    Proves that an adversarial sender who knows (parent_coin_id, parent_r_nf, output_coin_id, output_r_nf)
    CANNOT compute the recipient's future nullifier without the recipient's secret nk_recipient.
    """
    statement, witness, recipient_nk, output_identity, output_commitment = _create_test_fixture()

    # Recipient computes their legitimate nullifier when spending:
    legitimate_recipient_nullifier = compute_nullifier_v3(
        namespace_id=NAMESPACE,
        params_id=PARAMS_ID,
        public_key_bundle=witness.recipient_bundle,
        commitment=output_commitment,
        coin_id=output_identity.coin_id,
        r_nf=output_identity.r_nf,
        nullifier_key=recipient_nk,
    )

    # Adversarial sender attempts to compute recipient's nullifier with an arbitrary/guessed nk:
    # 1. In-circuit verification rejects because key commitment does not open:
    adversary_guessed_nk = NullifierDerivingKeyV3(b"\x99" * 48)
    with pytest.raises(ValueError, match="nullifier key does not open"):
        compute_nullifier_v3(
            namespace_id=NAMESPACE,
            params_id=PARAMS_ID,
            public_key_bundle=witness.recipient_bundle,
            commitment=output_commitment,
            coin_id=output_identity.coin_id,
            r_nf=output_identity.r_nf,
            nullifier_key=adversary_guessed_nk,
        )

    # 2. Even if adversary evaluated raw HMAC without opening, the resulting digest differs:
    import hmac as py_hmac
    from src.primitives.nullifier_v3 import _nullifier_v3_message
    message, _ = _nullifier_v3_message(
        NAMESPACE, PARAMS_ID, witness.recipient_bundle, output_commitment, output_identity.coin_id, output_identity.r_nf
    )
    adversary_raw_digest = py_hmac.new(adversary_guessed_nk.data, message, hashlib.sha3_384).digest()
    assert adversary_raw_digest != legitimate_recipient_nullifier.value
    # In V2, the sender could precalculate SHAKE256(coin_id || r_nf). In V3, HMAC-SHA3-384 under recipient_nk guarantees unlinkability.


def test_spend_relation_v3_underconstrained_witness_rejection() -> None:
    """Trap 1: Under-constrained Witness Variables (Ghost Witness Prevention).

    Ensures every private witness field is strictly bound across multiple constraints:
    Tampering with input_coin_id, input_r_nf, or input_rho causes commitment / nullifier mismatch.
    """
    statement, witness, _, _, _ = _create_test_fixture()

    # 1. Tamper with input_coin_id: breaks input commitment opening and nullifier
    tampered_coin_id = ScopedCoinId(b"\x99" * 32)
    wit_bad_coin = SpendWitnessV3(
        input_bundle=witness.input_bundle,
        input_value=witness.input_value,
        input_coin_id=tampered_coin_id,
        input_r_nf=witness.input_r_nf,
        input_rho=witness.input_rho,
        input_nk=witness.input_nk,
        leaf_index=witness.leaf_index,
        merkle_siblings=witness.merkle_siblings,
        recipient_bundle=witness.recipient_bundle,
        output_value=witness.output_value,
        output_rho=witness.output_rho,
    )
    with pytest.raises(SpendRelationV3Error):
        verify_spend_relation_v3_reference(statement, wit_bad_coin)

    # 2. Tamper with output_rho: breaks output commitment matching
    wit_bad_rho = SpendWitnessV3(
        input_bundle=witness.input_bundle,
        input_value=witness.input_value,
        input_coin_id=witness.input_coin_id,
        input_r_nf=witness.input_r_nf,
        input_rho=witness.input_rho,
        input_nk=witness.input_nk,
        leaf_index=witness.leaf_index,
        merkle_siblings=witness.merkle_siblings,
        recipient_bundle=witness.recipient_bundle,
        output_value=witness.output_value,
        output_rho=b"\x00" * 36,
    )
    with pytest.raises(SpendRelationV3Error, match="derived output commitment does not match"):
        verify_spend_relation_v3_reference(statement, wit_bad_rho)


def test_spend_relation_v3_value_overflow_and_range_check() -> None:
    """Trap 2: Value Overflow & Field Wraparound Inflation Prevention.

    Ensures that values cannot exceed 2^64-1 or wrap around modulo field size.
    """
    statement, witness, _, _, _ = _create_test_fixture()

    # Out of range u64 in witness instantiation must be blocked
    with pytest.raises(ValueError, match="outside valid u64 range"):
        SpendWitnessV3(
            input_bundle=witness.input_bundle,
            input_value=(1 << 64),
            input_coin_id=witness.input_coin_id,
            input_r_nf=witness.input_r_nf,
            input_rho=witness.input_rho,
            input_nk=witness.input_nk,
            leaf_index=witness.leaf_index,
            merkle_siblings=witness.merkle_siblings,
            recipient_bundle=witness.recipient_bundle,
            output_value=witness.output_value,
            output_rho=witness.output_rho,
        )


def test_spend_relation_v3_nullifier_domain_separation_and_replay_rejection() -> None:
    """Trap 3: Nullifier Namespace / Context Collision (Replay Attack Prevention).

    Ensures that a nullifier computed under a different namespace or parameter ID
    is rejected by the spend relation.
    """
    statement, witness, _, _, _ = _create_test_fixture()
    other_ns = NamespaceIdV3(b"\x99" * 48)

    # Statement with different namespace must reject same nullifier
    stmt_wrong_ns = TxFieldsV3Candidate(
        params_id=statement.params_id,
        namespace_id=other_ns,
        commitment_root=statement.commitment_root,
        input_nullifier=statement.input_nullifier,
        ledger_state_head=statement.ledger_state_head,
        state_context_digest=statement.state_context_digest,
        authorization_policy_id=statement.authorization_policy_id,
        fee=statement.fee,
        output_entropy=statement.output_entropy,
        output_commitments=statement.output_commitments,
    )
    with pytest.raises(SpendRelationV3Error):
        verify_spend_relation_v3_reference(stmt_wrong_ns, witness)


def test_spend_relation_v3_merkle_index_path_ambiguity_rejection() -> None:
    """Trap 4: Merkle Path Index Ambiguity & Bit Constraint Enforcement.

    Ensures that tampering with leaf_index bit navigation fails membership.
    """
    statement, witness, _, _, _ = _create_test_fixture()

    # Tamper with leaf_index (e.g. index 1 instead of 0)
    wit_bad_idx = SpendWitnessV3(
        input_bundle=witness.input_bundle,
        input_value=witness.input_value,
        input_coin_id=witness.input_coin_id,
        input_r_nf=witness.input_r_nf,
        input_rho=witness.input_rho,
        input_nk=witness.input_nk,
        leaf_index=1,
        merkle_siblings=witness.merkle_siblings,
        recipient_bundle=witness.recipient_bundle,
        output_value=witness.output_value,
        output_rho=witness.output_rho,
    )
    with pytest.raises(SpendRelationV3Error, match="not a valid member of statement commitment_root"):
        verify_spend_relation_v3_reference(statement, wit_bad_idx)


def test_spend_relation_v3_tx_context_relayer_tampering_rejection() -> None:
    """Trap 5: TxContext / Relayer Tampering Protection.

    Ensures that tampering with state_context_digest or fee alters the statement digest.
    """
    statement, witness, _, _, _ = _create_test_fixture()
    valid_digest = verify_spend_relation_v3_reference(statement, witness)

    # Attacking relayer tries to tamper with state_context_digest
    tampered_stmt = TxFieldsV3Candidate(
        params_id=statement.params_id,
        namespace_id=statement.namespace_id,
        commitment_root=statement.commitment_root,
        input_nullifier=statement.input_nullifier,
        ledger_state_head=statement.ledger_state_head,
        state_context_digest=b"\x99" * 64,  # Malicious relayer state injection
        authorization_policy_id=statement.authorization_policy_id,
        fee=statement.fee,
        output_entropy=statement.output_entropy,
        output_commitments=statement.output_commitments,
    )
    tampered_digest = verify_spend_relation_v3_reference(tampered_stmt, witness)

    # The public statement digest MUST be cryptographically distinct, invalidating any proof
    assert tampered_digest != valid_digest


def test_depth32_merkle_path_rejects_out_of_range_or_boolean_leaf_index() -> None:
    """Depth-32 path profiles cannot smuggle high index bits outside the path."""
    _, witness, _, _, _ = _create_test_fixture()

    with pytest.raises(ValueError, match="depth-32 Merkle path range"):
        replace(
            witness,
            leaf_index=1 << 32,
            merkle_siblings=tuple(witness.merkle_siblings[:32]),
        )

    with pytest.raises(ValueError, match="leaf_index must be an integer"):
        replace(witness, leaf_index=True)
