from __future__ import annotations

import concurrent.futures
import sqlite3
import threading

import pytest

from src.primitives.namespace_v3 import NamespaceIdV3, derive_namespace_id_v3
from src.protocol.commitment_tree import CommitmentTree, verify_member
from src.protocol.reference_ledger import (
    DepositAuthorization,
    DuplicateCommitment,
    DuplicateDeposit,
    DuplicateNullifier,
    InvalidInput,
    NamespaceMismatch,
    ProofRejected,
    SpendStatement,
)
from src.protocol.transaction_v2 import encode_spend_transaction_v2
from src.protocol.sqlite_ledger import (
    LedgerConfigurationMismatch,
    LedgerIntegrityError,
    SQLiteLedger,
    StaleLedgerState,
)

NS = derive_namespace_id_v3(b"ledger", b"deployment", b"asset")
OTHER_NS = derive_namespace_id_v3(b"ledger", b"other-deployment", b"asset")
PARAMS = b"params-v2-test-2026"
POLICY = b"policy-self-spend-v1"
PROFILE = b"\x99" * 32
DEPOSIT_ID = b"evm-deposit-id-0001"
ANCHOR = b"\x07" * 8 + b"\x08" * 32
BENEFICIARY = b"\x44" * 20
C1, C2, C3 = b"\x11" * 48, b"\x22" * 48, b"\x33" * 48
NF1 = b"\xaa" * 48
def make_ledger(path, *, namespace=NS, params=PARAMS, policy=POLICY, profile=PROFILE,
                authorizer=None, issuance_verifier=None, spend_verifier=None):
    if authorizer is None:
        authorizer = lambda _evidence: DepositAuthorization(
            namespace_id=namespace,
            deposit_id=DEPOSIT_ID,
            authorized_value=(1 << 64) - 1,
            finalized_anchor=ANCHOR,
            beneficiary_address=BENEFICIARY,
        )
    if issuance_verifier is None:
        issuance_verifier = lambda statement, proof: (
            proof == b"valid-issue"
            and statement.authorized_value == (1 << 64) - 1
            and statement.namespace_id == namespace
        )
    if spend_verifier is None:
        spend_verifier = lambda statement, proof: proof == b"valid-spend"
    return SQLiteLedger(
        path,
        expected_namespace_id=namespace,
        expected_params_id=params,
        authorization_policy_id=policy,
        deployment_profile_id=profile,
        authorize_deposit=authorizer,
        verify_issuance_proof=issuance_verifier,
        verify_spend_proof=spend_verifier,
    )


def spend_statement(snapshot, *, nullifier=NF1, outputs=(C2,), root=None, head=None,
                    fields=None, fee=0):
    actual_root = snapshot.commitment_root if root is None else root
    actual_head = snapshot.state_head if head is None else head
    canonical_fields, digest = encode_spend_transaction_v2(
        params_id=PARAMS,
        namespace_id=NS,
        commitment_root=actual_root,
        nullifier=nullifier,
        ledger_state=actual_head,
        authorization_policy_id=POLICY,
        fee=fee,
        new_commitments=tuple(outputs),
    )
    return SpendStatement(
        version=2,
        params_id=PARAMS,
        namespace_id=NS,
        commitment_root=actual_root,
        nullifier=nullifier,
        transaction_fields=canonical_fields if fields is None else fields,
        transaction_digest=digest,
        ledger_state=actual_head,
        authorization_policy=POLICY,
        new_commitments=tuple(outputs),
    )


def test_durable_issuance_pins_value_and_survives_restart(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = make_ledger(path)
    issued = ledger.issue(
        deposit_evidence=b"verified-deposit-bundle",
        commitment=C1,
        params_id=PARAMS,
        proof=b"valid-issue",
    )
    snap = ledger.snapshot()
    assert issued.value == (1 << 64) - 1
    assert issued.commitment_index == 0
    assert issued.state_version == 1
    assert issued.state_head == snap.state_head
    assert issued.commitment_root == snap.commitment_root
    assert ledger.issued_count() == 1
    assert ledger.contains_commitment(C1)
    index, path_nodes = ledger.membership_path(C1)
    assert verify_member(NS, snap.commitment_root, index, C1, path_nodes)
    ledger.audit_integrity()

    reopened = make_ledger(path)
    assert reopened.snapshot() == snap
    saved = reopened.get_issued_record(C1)
    assert saved is not None
    assert saved.deposit_id == DEPOSIT_ID
    assert saved.value == (1 << 64) - 1
    assert saved.state_head == issued.state_head
    assert saved.commitment_root == issued.commitment_root
    reopened.audit_integrity()


def test_issue_rejects_deposit_replay_and_duplicate_commitment_atomically(tmp_path):
    path = tmp_path / "replay.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"evidence", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    snap = ledger.snapshot()
    with pytest.raises(DuplicateDeposit):
        ledger.issue(deposit_evidence=b"evidence", commitment=C2, params_id=PARAMS, proof=b"valid-issue")
    # A different deposit is needed to reach the commitment-uniqueness branch.
    other_auth = lambda _: DepositAuthorization(NS, b"evm-deposit-id-0002", 7, ANCHOR, BENEFICIARY)
    different_deposit = make_ledger(path, authorizer=other_auth,
                                    issuance_verifier=lambda s, p: p == b"valid-issue")
    with pytest.raises(DuplicateCommitment):
        different_deposit.issue(deposit_evidence=b"other evidence", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    assert ledger.snapshot() == snap
    assert ledger.issued_count() == 1
    ledger.audit_integrity()


@pytest.mark.parametrize("bad", ["namespace", "params", "proof", "auth"])
def test_issue_fails_closed_without_mutating_state(tmp_path, bad):
    path = tmp_path / f"reject-{bad}.sqlite3"
    kwargs = {}
    if bad == "namespace":
        kwargs["authorizer"] = lambda _: DepositAuthorization(OTHER_NS, DEPOSIT_ID, 10, ANCHOR, BENEFICIARY)
    if bad == "proof":
        kwargs["issuance_verifier"] = lambda _s, _p: False
    if bad == "auth":
        kwargs["authorizer"] = lambda _: None
    ledger = make_ledger(path, **kwargs)
    before = ledger.snapshot()
    with pytest.raises((NamespaceMismatch, ProofRejected, Exception)):
        if bad == "params":
            ledger.issue(deposit_evidence=b"e", commitment=C1, params_id=b"unapproved", proof=b"valid-issue")
        else:
            ledger.issue(deposit_evidence=b"e", commitment=C1, params_id=PARAMS, proof=b"wrong-proof" if bad == "proof" else b"valid-issue")
    assert ledger.snapshot() == before
    assert ledger.issued_count() == 0
    ledger.audit_integrity()


def test_spend_consumes_nullifier_and_appends_outputs_atomically(tmp_path):
    path = tmp_path / "spend.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"e", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    before = ledger.snapshot()
    stmt = spend_statement(before, outputs=(C2, C3))
    accepted = ledger.accept_spend(statement=stmt, proof=b"valid-spend")
    after = ledger.snapshot()
    assert accepted.state_version == 2
    assert accepted.first_output_index == 1
    assert after.commitment_count == 3
    assert after.state_version == 2
    assert ledger.is_nullifier_spent(NF1)
    assert ledger.contains_commitment(C2) and ledger.contains_commitment(C3)
    assert verify_member(NS, after.commitment_root, 1, C2, ledger.membership_path(C2)[1])
    assert verify_member(NS, after.commitment_root, 2, C3, ledger.membership_path(C3)[1])
    ledger.audit_integrity()

    # Reopen and try the same nullifier against the new current state; it must
    # fail at the uniqueness check even if the test verifier accepts the proof.
    reopened = make_ledger(path)
    current = reopened.snapshot()
    with pytest.raises(DuplicateNullifier):
        reopened.accept_spend(statement=spend_statement(current, nullifier=NF1, outputs=(b"\x55" * 48,)), proof=b"valid-spend")
    assert reopened.snapshot() == current
    reopened.audit_integrity()


@pytest.mark.parametrize("mutation", ["old_head", "wrong_root", "wrong_params", "wrong_policy", "duplicate_output"])
def test_spend_rejects_stale_or_substituted_state_and_rolls_back(tmp_path, mutation):
    path = tmp_path / f"spend-reject-{mutation}.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"e", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    snap = ledger.snapshot()
    if mutation == "old_head":
        second_ledger = make_ledger(
            path,
            authorizer=lambda _: DepositAuthorization(NS, b"evm-deposit-id-0002", 9, ANCHOR, BENEFICIARY),
            issuance_verifier=lambda _statement, _proof: True,
        )
        second_ledger.issue(
            deposit_evidence=b"unused",
            commitment=C3,
            params_id=PARAMS,
            proof=b"valid-issue",
        )
        current = ledger.snapshot()
        statement = spend_statement(current, head=snap.state_head)
        expected = StaleLedgerState
    elif mutation == "wrong_root":
        statement = spend_statement(snap, root=b"\x99" * 48)
        expected = StaleLedgerState
    elif mutation == "wrong_params":
        statement = spend_statement(snap)
        statement = SpendStatement(**{**statement.__dict__, "params_id": b"other"})
        expected = InvalidInput
    elif mutation == "wrong_policy":
        statement = spend_statement(snap)
        statement = SpendStatement(**{**statement.__dict__, "authorization_policy": b"other"})
        expected = InvalidInput
    else:
        valid = spend_statement(snap, outputs=(C2,))
        statement = SpendStatement(**{**valid.__dict__, "new_commitments": (C2, C2)})
        expected = DuplicateCommitment
    before = ledger.snapshot()
    with pytest.raises(expected):
        ledger.accept_spend(statement=statement, proof=b"valid-spend")
    assert ledger.snapshot() == before
    ledger.audit_integrity()


def test_spend_requires_fresh_state_after_verification_race(tmp_path):
    path = tmp_path / "race.sqlite3"
    gate = threading.Barrier(2)
    def verifying(statement, proof):
        gate.wait(timeout=5)
        return proof == b"valid-spend"
    ledger = make_ledger(path, spend_verifier=verifying)
    ledger.issue(deposit_evidence=b"e", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    snapshot = ledger.snapshot()
    statements = [
        spend_statement(snapshot, nullifier=b"\x01" * 48, outputs=(b"\x02" * 48,)),
        spend_statement(snapshot, nullifier=b"\x03" * 48, outputs=(b"\x04" * 48,)),
    ]
    def attempt(statement):
        try:
            return ledger.accept_spend(statement=statement, proof=b"valid-spend")
        except Exception as exc:
            return exc
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, statements))
    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, StaleLedgerState) for result in results) == 1
    assert ledger.snapshot().state_version == 2
    ledger.audit_integrity()


def test_concurrent_issuance_consumes_deposit_once(tmp_path):
    path = tmp_path / "issue-race.sqlite3"
    ledger = make_ledger(path)
    commitments = [bytes([x]) * 48 for x in range(1, 7)]
    def attempt(commitment):
        try:
            return ledger.issue(deposit_evidence=b"same deposit", commitment=commitment,
                                params_id=PARAMS, proof=b"valid-issue")
        except Exception as exc:
            return exc
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(attempt, commitments))
    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, DuplicateDeposit) for result in results) == 5
    assert ledger.issued_count() == 1
    ledger.audit_integrity()


def test_database_configuration_is_pinned_and_memory_or_symlinks_rejected(tmp_path):
    path = tmp_path / "config.sqlite3"
    make_ledger(path)
    with pytest.raises(LedgerConfigurationMismatch):
        make_ledger(path, namespace=OTHER_NS)
    with pytest.raises(LedgerConfigurationMismatch):
        make_ledger(path, params=b"other-parameters")
    with pytest.raises(LedgerConfigurationMismatch):
        make_ledger(path, policy=b"other-policy")
    with pytest.raises(LedgerConfigurationMismatch):
        make_ledger(path, profile=b"\x88" * 32)
    with pytest.raises(ValueError, match="file-backed"):
        make_ledger(":memory:")
    target = tmp_path / "real.sqlite3"
    make_ledger(target)
    link = tmp_path / "symlink.sqlite3"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="regular non-symlink"):
        make_ledger(link)


def test_audit_detects_modified_head_event_digest_or_merkle_root(tmp_path):
    path = tmp_path / "tamper.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"e", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    ledger.audit_integrity()
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE ledger_meta SET state_head=?", (b"\xff" * 48,))
    with pytest.raises(LedgerIntegrityError, match="reconstructed event chain"):
        ledger.audit_integrity()

    # New database: alter root metadata and require the recomputed append tree
    # to detect that modification.
    other_path = tmp_path / "tamper-root.sqlite3"
    other = make_ledger(other_path)
    other.issue(deposit_evidence=b"e", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    with sqlite3.connect(other_path) as conn:
        conn.execute("UPDATE ledger_meta SET commitment_root=?", (b"\xee" * 48,))
    with pytest.raises(LedgerIntegrityError, match="recomputed commitment tree root"):
        other.audit_integrity()


def test_database_file_is_owner_only(tmp_path):
    import stat
    path = tmp_path / "permissions.sqlite3"
    make_ledger(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_integrity_audit_detects_non_root_merkle_node_corruption(tmp_path):
    path = tmp_path / "tamper-sibling.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"e1", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    second_authorizer = lambda _: DepositAuthorization(
        NS, b"evm-deposit-id-0002", 17, ANCHOR, BENEFICIARY
    )
    second = make_ledger(
        path,
        authorizer=second_authorizer,
        issuance_verifier=lambda statement, proof: proof == b"valid-issue" and statement.authorized_value == 17,
    )
    second.issue(deposit_evidence=b"e2", commitment=C2, params_id=PARAMS, proof=b"valid-issue")
    # The persisted root node remains untouched, so a root-only check misses this.
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE merkle_nodes SET node_hash=? WHERE level=0 AND node_index=0",
            (b"\xFA" * 48,),
        )
    with pytest.raises(LedgerIntegrityError, match="persisted Merkle nodes"):
        ledger.audit_integrity()


def test_integrity_audit_reconciles_records_with_canonical_event_payload(tmp_path):
    path = tmp_path / "tamper-record.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"evidence", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE issuance_records SET value_u64_be=? WHERE commitment=?",
            ((17).to_bytes(8, "big"), C1),
        )
    with pytest.raises(LedgerIntegrityError, match="event payload does not match"):
        ledger.audit_integrity()


def test_integrity_audit_rejects_record_head_or_source_link_substitution(tmp_path):
    path = tmp_path / "tamper-links.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"evidence", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE commitments SET source_id=? WHERE commitment=?",
            (b"unrelated-deposit", C1),
        )
    with pytest.raises(LedgerIntegrityError, match="commitment-tree leaf"):
        ledger.audit_integrity()

    clean_path = tmp_path / "tamper-head.sqlite3"
    clean = make_ledger(clean_path)
    clean.issue(deposit_evidence=b"evidence", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    with sqlite3.connect(clean_path) as conn:
        conn.execute(
            "UPDATE issuance_records SET state_head_after=? WHERE commitment=?",
            (b"\xFB" * 48, C1),
        )
    with pytest.raises(LedgerIntegrityError, match="post-state head/root"):
        clean.audit_integrity()


def test_database_reopen_fails_closed_before_accepting_transitions_if_internal_tree_is_corrupt(tmp_path):
    path = tmp_path / "startup-corrupt.sqlite3"
    ledger = make_ledger(path)
    ledger.issue(deposit_evidence=b"evidence", commitment=C1, params_id=PARAMS, proof=b"valid-issue")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE merkle_nodes SET node_hash=? WHERE level=0 AND node_index=0",
            (b"\xFC" * 48,),
        )
    with pytest.raises(LedgerIntegrityError, match="persisted Merkle nodes"):
        make_ledger(path)


def test_fresh_ledger_initializes_empty_state_and_audits_on_startup(tmp_path):
    path = tmp_path / "fresh-empty.sqlite3"
    ledger = make_ledger(path)
    snapshot = ledger.snapshot()
    assert snapshot.namespace_id == NS
    assert snapshot.state_version == 0
    assert snapshot.commitment_count == 0
    assert snapshot.commitment_root == CommitmentTree(NS).root
    assert ledger.issued_count() == 0
    assert ledger.spent_count() == 0
    ledger.audit_integrity()
