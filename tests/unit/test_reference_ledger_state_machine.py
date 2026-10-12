"""CHp4.1 tests for replay/uniqueness semantics in the reference state model.

Verifier callbacks below are test doubles. These tests do not implement or
prove the V2 issuance relation, a ZK spend relation, or a production ledger.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from src.primitives.namespace_v3 import derive_namespace_id_v3
from src.protocol.reference_ledger import (
    AcceptedSpend,
    DepositAuthorization,
    DepositRejected,
    DuplicateCommitment,
    DuplicateDeposit,
    DuplicateNullifier,
    InvalidInput,
    NamespaceMismatch,
    ProofRejected,
    ReferenceLedger,
    SpendStatement,
)

NS = derive_namespace_id_v3(b"test-ledger", b"test-deployment", b"test-asset")
ANCHOR = bytes([0x22]) * 32
PARAMS = b"v2-test-params"
PROOF = b"test-proof"


def authorization_for(evidence: bytes, *, value: int = 2500, deposit_id: bytes | None = None):
    if evidence != b"valid-deposit":
        return None
    return DepositAuthorization(
        namespace_id=NS,
        deposit_id=deposit_id or bytes([0x33]) * 32,
        authorized_value=value,
        finalized_anchor=ANCHOR,
    )


def make_ledger(*, issue_ok=True, spend_ok=True, authorizer=authorization_for, issue_seen=None):
    def verify_issue(statement, proof):
        if issue_seen is not None:
            issue_seen.append(statement)
        return issue_ok and proof == PROOF

    def verify_spend(statement, proof):
        return spend_ok and proof == PROOF

    return ReferenceLedger(
        expected_namespace_id=NS,
        authorize_deposit=authorizer,
        verify_issuance_proof=verify_issue,
        verify_spend_proof=verify_spend,
    )


def test_issuance_value_is_derived_from_authorized_deposit_not_request() -> None:
    observed = []
    ledger = make_ledger(issue_seen=observed)
    # There is intentionally no value argument to issue().
    record = ledger.issue(
        deposit_evidence=b"valid-deposit",
        commitment=bytes([0x44]) * 48,
        params_id=PARAMS,
        proof=PROOF,
    )
    assert record.value == 2500
    assert observed[0].version == 2
    assert observed[0].authorized_value == 2500
    assert ledger.issued_count == 1
    assert ledger.state_version == 1


def test_unrecognized_deposit_is_rejected_without_state_change() -> None:
    ledger = make_ledger()
    with pytest.raises(DepositRejected):
        ledger.issue(deposit_evidence=b"forged", commitment=b"C" * 48,
                     params_id=PARAMS, proof=PROOF)
    assert ledger.issued_count == 0
    assert ledger.state_version == 0


def test_rejected_issuance_proof_does_not_consume_deposit_or_commitment() -> None:
    ledger = make_ledger(issue_ok=False)
    with pytest.raises(ProofRejected):
        ledger.issue(deposit_evidence=b"valid-deposit", commitment=b"C" * 48,
                     params_id=PARAMS, proof=PROOF)
    assert ledger.issued_count == 0
    assert ledger.state_version == 0
    assert not ledger.contains_commitment(NS, b"C" * 48)


def test_value_opening_mismatch_is_rejected_by_the_relation_verifier_contract() -> None:
    # The test double models a verifier that knows the opening's authorized
    # value. It is not a cryptographic proof verifier. The model must pass the
    # deposit-authorized value, not a caller-supplied amount, to that verifier.
    commitment = b"F" * 48
    opening_value_by_commitment = {commitment: 1_000_000}

    def authorize(_evidence):
        return DepositAuthorization(NS, b"D" * 32, 10, ANCHOR)

    def verify_issue(statement, proof):
        return (proof == PROOF and
                opening_value_by_commitment.get(statement.commitment) == statement.authorized_value)

    ledger = ReferenceLedger(
        expected_namespace_id=NS,
        authorize_deposit=authorize,
        verify_issuance_proof=verify_issue,
        verify_spend_proof=lambda _statement, _proof: True,
    )
    with pytest.raises(ProofRejected):
        ledger.issue(deposit_evidence=b"deposit-10", commitment=commitment,
                     params_id=PARAMS, proof=PROOF)
    assert ledger.issued_count == 0
    assert ledger.state_version == 0


def test_duplicate_deposit_and_duplicate_commitment_are_rejected() -> None:
    ledger = make_ledger()
    c1, c2 = b"A" * 48, b"B" * 48
    ledger.issue(deposit_evidence=b"valid-deposit", commitment=c1,
                 params_id=PARAMS, proof=PROOF)
    with pytest.raises(DuplicateDeposit):
        ledger.issue(deposit_evidence=b"valid-deposit", commitment=c2,
                     params_id=PARAMS, proof=PROOF)
    assert ledger.issued_count == 1
    assert not ledger.contains_commitment(NS, c2)

    # A second authenticated deposit cannot register an already-used commitment.
    def two_deposit_authorizer(evidence):
        if evidence == b"deposit-1":
            return DepositAuthorization(NS, b"D" * 32, 2500, ANCHOR)
        if evidence == b"deposit-2":
            return DepositAuthorization(NS, b"E" * 32, 4000, ANCHOR)
        return None

    other = make_ledger(authorizer=two_deposit_authorizer)
    other.issue(deposit_evidence=b"deposit-1", commitment=c1,
                params_id=PARAMS, proof=PROOF)
    with pytest.raises(DuplicateCommitment):
        other.issue(deposit_evidence=b"deposit-2", commitment=c1,
                    params_id=PARAMS, proof=PROOF)
    assert other.issued_count == 1
    assert other.state_version == 1


def test_concurrent_duplicate_issuance_has_exactly_one_winner() -> None:
    ledger = make_ledger()
    barrier = Barrier(12)

    def submit(_):
        try:
            barrier.wait()
            ledger.issue(deposit_evidence=b"valid-deposit", commitment=b"C" * 48,
                         params_id=PARAMS, proof=PROOF)
            return "accepted"
        except DuplicateDeposit:
            return "duplicate"

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(submit, range(48)))
    assert results.count("accepted") == 1
    assert results.count("duplicate") == 47
    assert ledger.issued_count == 1
    assert ledger.state_version == 1


def statement(nullifier: bytes, outputs: tuple[bytes, ...] = ()) -> SpendStatement:
    return SpendStatement(
        version=2,
        params_id=PARAMS,
        namespace_id=NS,
        commitment_root=b"R" * 48,
        nullifier=nullifier,
        transaction_fields=b"canonical-test-transaction-fields",
        transaction_digest=b"digest-v1",
        ledger_state=ANCHOR,
        authorization_policy=b"test-self-spend-policy-v1",
        new_commitments=outputs,
    )


def test_rejected_spend_proof_has_no_state_effect() -> None:
    ledger = make_ledger(spend_ok=False)
    with pytest.raises(ProofRejected):
        ledger.accept_spend(statement=statement(b"N" * 48, (b"O" * 48,)), proof=PROOF)
    assert ledger.spent_count == 0
    assert ledger.state_version == 0
    assert not ledger.contains_commitment(NS, b"O" * 48)


def test_duplicate_nullifier_is_rejected_and_outputs_append_only_on_success() -> None:
    ledger = make_ledger()
    nullifier, output = b"N" * 48, b"O" * 48
    accepted = ledger.accept_spend(statement=statement(nullifier, (output,)), proof=PROOF)
    assert isinstance(accepted, AcceptedSpend)
    assert ledger.spent_count == 1
    assert ledger.contains_commitment(NS, output)
    assert ledger.state_version == 1

    with pytest.raises(DuplicateNullifier):
        ledger.accept_spend(statement=statement(nullifier, (b"P" * 48,)), proof=PROOF)
    assert ledger.spent_count == 1
    assert not ledger.contains_commitment(NS, b"P" * 48)
    assert ledger.state_version == 1


def test_concurrent_repeated_nullifier_has_exactly_one_winner() -> None:
    ledger = make_ledger()
    nf = b"N" * 48
    barrier = Barrier(12)

    def submit(_):
        try:
            barrier.wait()
            ledger.accept_spend(statement=statement(nf), proof=PROOF)
            return "accepted"
        except DuplicateNullifier:
            return "duplicate"

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(submit, range(48)))
    assert results.count("accepted") == 1
    assert results.count("duplicate") == 47
    assert ledger.spent_count == 1
    assert ledger.state_version == 1


def test_duplicate_output_commitment_is_rejected_without_spending_nullifier() -> None:
    ledger = make_ledger()
    output = b"O" * 48
    ledger.accept_spend(statement=statement(b"N" * 48, (output,)), proof=PROOF)
    with pytest.raises(DuplicateCommitment):
        ledger.accept_spend(statement=statement(b"M" * 48, (output,)), proof=PROOF)
    assert ledger.spent_count == 1
    assert ledger.state_version == 1


def test_shape_errors_fail_before_transition() -> None:
    ledger = make_ledger()
    with pytest.raises(InvalidInput):
        ledger.issue(deposit_evidence=b"valid-deposit", commitment=b"short",
                     params_id=PARAMS, proof=PROOF)
    with pytest.raises(InvalidInput):
        ledger.accept_spend(statement=statement(b"short"), proof=PROOF)
    invalid = statement(b"N" * 48)
    invalid_version = SpendStatement(
        version=1, params_id=invalid.params_id, namespace_id=invalid.namespace_id,
        commitment_root=invalid.commitment_root, nullifier=invalid.nullifier,
        transaction_fields=invalid.transaction_fields, transaction_digest=invalid.transaction_digest,
        ledger_state=invalid.ledger_state, authorization_policy=invalid.authorization_policy,
        new_commitments=invalid.new_commitments,
    )
    with pytest.raises(InvalidInput):
        ledger.accept_spend(statement=invalid_version, proof=PROOF)
    assert ledger.issued_count == 0
    assert ledger.spent_count == 0
    assert ledger.state_version == 0


def test_wrong_namespace_deposit_is_rejected_before_issuance_verifier() -> None:
    seen = []
    wrong_namespace = derive_namespace_id_v3(b"wrong-ledger", b"test-deployment", b"test-asset")

    def wrong_authorizer(_evidence):
        return DepositAuthorization(
            namespace_id=wrong_namespace,
            deposit_id=b"D" * 32,
            authorized_value=100,
            finalized_anchor=ANCHOR,
        )

    ledger = ReferenceLedger(
        expected_namespace_id=NS,
        authorize_deposit=wrong_authorizer,
        verify_issuance_proof=lambda statement, proof: seen.append(statement) or True,
        verify_spend_proof=lambda _statement, _proof: True,
    )
    with pytest.raises(NamespaceMismatch):
        ledger.issue(
            deposit_evidence=b"forged-cross-namespace",
            commitment=b"C" * 48,
            params_id=PARAMS,
            proof=PROOF,
        )
    assert seen == []
    assert ledger.issued_count == 0
    assert ledger.state_version == 0


def test_wrong_namespace_spend_is_rejected_before_spend_verifier() -> None:
    seen = []
    ledger = ReferenceLedger(
        expected_namespace_id=NS,
        authorize_deposit=authorization_for,
        verify_issuance_proof=lambda _statement, _proof: True,
        verify_spend_proof=lambda statement, proof: seen.append(statement) or True,
    )
    wrong_statement = replace(statement(b"N" * 48), namespace_id=bytes([0x99]) * 48)
    with pytest.raises(NamespaceMismatch):
        ledger.accept_spend(statement=wrong_statement, proof=PROOF)
    assert seen == []
    assert ledger.spent_count == 0
    assert ledger.state_version == 0


def test_reference_ledger_requires_a_canonical_fixed_namespace() -> None:
    with pytest.raises(InvalidInput, match="expected_namespace_id"):
        ReferenceLedger(
            expected_namespace_id=b"bad",
            authorize_deposit=authorization_for,
            verify_issuance_proof=lambda _statement, _proof: True,
            verify_spend_proof=lambda _statement, _proof: True,
        )
