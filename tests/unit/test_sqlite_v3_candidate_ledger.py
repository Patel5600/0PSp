"""Adversarial state-machine tests for the non-production V3 SQLite candidate ledger.

The proof verifier is deliberately a test double. These tests establish local
atomicity, anchor handling and persisted-state integrity only; they do not
establish cryptographic spend soundness or trusted external finality.
"""
from __future__ import annotations

import concurrent.futures
import sqlite3
import threading

import pytest

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.commitment_tree import CommitmentTree
from src.protocol.transaction_v3_candidate import (
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    TxFieldsV3Candidate,
)
from src.protocol.trusted_state_v3 import (
    StateAnchorEvidenceV3,
    VerifiedStateSnapshotV3,
)
from src.protocol.sqlite_v3_candidate_ledger import (
    SQLiteV3CandidateLedger,
    SQLiteV3DuplicateCommitment,
    SQLiteV3DuplicateNullifier,
    SQLiteV3LedgerIntegrityError,
    SQLiteV3ProofRejected,
    SQLiteV3StaleLedgerState,
)

NAMESPACE = NamespaceIdV3(b"\x11" * 48)
PARAMS_ID = b"candidate-v3-ledger-params"
PROFILE_ID = b"\x22" * 32
BOOTSTRAP_COMMITMENTS = (b"\x31" * 48, b"\x32" * 48)
BOOTSTRAP_HEAD = b"\x44" * 48
SOURCE_ID = b"fixture-state-source"
FINALIZED_ANCHOR = b"fixture-finalized-checkpoint"
EVIDENCE_BYTES = b"fixture-evidence-not-cryptographic"
VALID_PROOF = b"test-double-accepts-this-proof"
NULLIFIER_A = b"\x51" * 48
NULLIFIER_B = b"\x52" * 48
OUTPUT_A = b"\x61" * 48
OUTPUT_B = b"\x62" * 48
OUTPUT_C = b"\x63" * 48


def make_environment(
    tmp_path,
    *,
    name: str = "candidate.sqlite3",
    commitments: tuple[bytes, ...] = BOOTSTRAP_COMMITMENTS,
    anchor_window: int = 4,
    proof_verifier=None,
):
    tree = CommitmentTree(NAMESPACE, list(commitments))
    evidence = StateAnchorEvidenceV3(
        source_id=SOURCE_ID,
        finalized_anchor=FINALIZED_ANCHOR,
        evidence=EVIDENCE_BYTES,
    )
    snapshot = VerifiedStateSnapshotV3(
        source_id=SOURCE_ID,
        finalized_anchor=FINALIZED_ANCHOR,
        namespace_id=NAMESPACE,
        params_id=PARAMS_ID,
        commitment_root=tree.root,
        ledger_state_head=BOOTSTRAP_HEAD,
    )

    def verify_bootstrap(received: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        if received != evidence:
            raise ValueError("bootstrap evidence differs from fixed test fixture")
        return snapshot

    if proof_verifier is None:
        proof_verifier = lambda _statement, proof: proof == VALID_PROOF

    ledger = SQLiteV3CandidateLedger(
        tmp_path / name,
        expected_namespace_id=NAMESPACE,
        expected_params_id=PARAMS_ID,
        deployment_profile_id=PROFILE_ID,
        bootstrap_evidence=evidence,
        verify_bootstrap_state=verify_bootstrap,
        verify_spend_proof=proof_verifier,
        bootstrap_commitments=commitments,
        anchor_window=anchor_window,
    )
    return ledger, evidence, snapshot, verify_bootstrap


def statement_for(
    ledger: SQLiteV3CandidateLedger,
    *,
    nullifier: bytes = NULLIFIER_A,
    output: bytes = OUTPUT_A,
    root: bytes | None = None,
    state_head: bytes | None = None,
    policy: bytes = V3_NK_POSSESSION_POLICY_CANDIDATE,
) -> TxFieldsV3Candidate:
    current = ledger.snapshot()
    return TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=NAMESPACE,
        commitment_root=current.commitment_root if root is None else root,
        input_nullifier=NullifierV3(nullifier),
        ledger_state_head=current.ledger_state_head if state_head is None else state_head,
        authorization_policy_id=policy,
        fee=0,
        output_entropy=b"\x71" * 32,
        output_commitments=(CoinCommitmentV3(output),),
    )


def test_authenticated_bootstrap_and_single_spend_survive_restart(tmp_path) -> None:
    ledger, evidence, bootstrap, verify_bootstrap = make_environment(tmp_path)
    initial = ledger.snapshot()
    tx = statement_for(ledger, output=OUTPUT_A)

    accepted = ledger.accept_spend(tx, proof=VALID_PROOF)

    assert accepted.nullifier == NULLIFIER_A
    assert accepted.output_commitment == OUTPUT_A
    assert accepted.proof_anchor_version == 0
    assert accepted.state_version == 1
    assert ledger.snapshot().state_version == 1
    assert ledger.contains_commitment(OUTPUT_A)
    assert ledger.is_nullifier_spent(NULLIFIER_A)
    assert ledger.snapshot().commitment_root != initial.commitment_root
    ledger.audit_integrity()

    reopened = SQLiteV3CandidateLedger(
        tmp_path / "candidate.sqlite3",
        expected_namespace_id=NAMESPACE,
        expected_params_id=PARAMS_ID,
        deployment_profile_id=PROFILE_ID,
        bootstrap_evidence=evidence,
        verify_bootstrap_state=verify_bootstrap,
        verify_spend_proof=lambda _statement, proof: proof == VALID_PROOF,
        bootstrap_commitments=None,
        anchor_window=4,
    )
    assert reopened.snapshot() == ledger.snapshot()
    assert reopened.contains_commitment(OUTPUT_A)
    assert reopened.is_nullifier_spent(NULLIFIER_A)
    reopened.audit_integrity()


def test_bad_bootstrap_commitment_list_cannot_claim_authenticated_root(tmp_path) -> None:
    wrong_commitments = (BOOTSTRAP_COMMITMENTS[0],)
    ledger_root = CommitmentTree(NAMESPACE, list(BOOTSTRAP_COMMITMENTS)).root
    evidence = StateAnchorEvidenceV3(
        source_id=SOURCE_ID,
        finalized_anchor=FINALIZED_ANCHOR,
        evidence=EVIDENCE_BYTES,
    )
    authenticated = VerifiedStateSnapshotV3(
        source_id=SOURCE_ID,
        finalized_anchor=FINALIZED_ANCHOR,
        namespace_id=NAMESPACE,
        params_id=PARAMS_ID,
        commitment_root=ledger_root,
        ledger_state_head=BOOTSTRAP_HEAD,
    )

    with pytest.raises(SQLiteV3LedgerIntegrityError, match="does not reconstruct"):
        SQLiteV3CandidateLedger(
            tmp_path / "bad-bootstrap.sqlite3",
            expected_namespace_id=NAMESPACE,
            expected_params_id=PARAMS_ID,
            deployment_profile_id=PROFILE_ID,
            bootstrap_evidence=evidence,
            verify_bootstrap_state=lambda _evidence: authenticated,
            verify_spend_proof=lambda _statement, _proof: True,
            bootstrap_commitments=wrong_commitments,
        )


def test_duplicate_nullifier_is_atomically_rejected(tmp_path) -> None:
    ledger, *_ = make_environment(tmp_path)
    first = statement_for(ledger, nullifier=NULLIFIER_A, output=OUTPUT_A)
    ledger.accept_spend(first, proof=VALID_PROOF)
    before = ledger.snapshot()

    replay = statement_for(ledger, nullifier=NULLIFIER_A, output=OUTPUT_B)
    with pytest.raises(SQLiteV3DuplicateNullifier):
        ledger.accept_spend(replay, proof=VALID_PROOF)

    assert ledger.snapshot() == before
    assert not ledger.contains_commitment(OUTPUT_B)
    assert ledger.is_nullifier_spent(NULLIFIER_A)
    ledger.audit_integrity()


def test_duplicate_output_commitment_is_atomically_rejected(tmp_path) -> None:
    ledger, *_ = make_environment(tmp_path)
    ledger.accept_spend(statement_for(ledger, output=OUTPUT_A), proof=VALID_PROOF)
    before = ledger.snapshot()

    replayed_output = statement_for(
        ledger, nullifier=NULLIFIER_B, output=OUTPUT_A
    )
    with pytest.raises(SQLiteV3DuplicateCommitment):
        ledger.accept_spend(replayed_output, proof=VALID_PROOF)

    assert ledger.snapshot() == before
    assert not ledger.is_nullifier_spent(NULLIFIER_B)
    ledger.audit_integrity()


def test_root_or_head_substitution_fails_before_proof_verifier(tmp_path) -> None:
    proof_calls: list[bytes] = []
    ledger, *_ = make_environment(
        tmp_path,
        proof_verifier=lambda _statement, proof: proof_calls.append(proof) or True,
    )
    before = ledger.snapshot()
    wrong_root = b"\x99" * 48
    tx = statement_for(ledger, root=wrong_root)

    with pytest.raises(SQLiteV3StaleLedgerState):
        ledger.accept_spend(tx, proof=VALID_PROOF)

    assert proof_calls == []
    assert ledger.snapshot() == before
    assert not ledger.is_nullifier_spent(NULLIFIER_A)


def test_proof_rejection_leaves_no_partial_state(tmp_path) -> None:
    ledger, *_ = make_environment(
        tmp_path, proof_verifier=lambda _statement, _proof: False
    )
    before = ledger.snapshot()
    tx = statement_for(ledger, output=OUTPUT_A)

    with pytest.raises(SQLiteV3ProofRejected):
        ledger.accept_spend(tx, proof=b"invalid-proof")

    assert ledger.snapshot() == before
    assert not ledger.contains_commitment(OUTPUT_A)
    assert not ledger.is_nullifier_spent(NULLIFIER_A)
    ledger.audit_integrity()


def test_old_proof_anchor_expires_after_window_advances(tmp_path) -> None:
    ledger, *_ = make_environment(tmp_path, anchor_window=2)
    anchor_zero = ledger.snapshot()
    old_tx = statement_for(
        ledger,
        nullifier=b"\x81" * 48,
        output=b"\x91" * 48,
        root=anchor_zero.commitment_root,
        state_head=anchor_zero.ledger_state_head,
    )
    ledger.accept_spend(
        statement_for(ledger, nullifier=NULLIFIER_A, output=OUTPUT_A),
        proof=VALID_PROOF,
    )
    ledger.accept_spend(
        statement_for(ledger, nullifier=NULLIFIER_B, output=OUTPUT_B),
        proof=VALID_PROOF,
    )
    before = ledger.snapshot()

    with pytest.raises(SQLiteV3StaleLedgerState):
        ledger.accept_spend(old_tx, proof=VALID_PROOF)

    assert ledger.snapshot() == before
    assert not ledger.is_nullifier_spent(b"\x81" * 48)
    ledger.audit_integrity()


def test_concurrent_same_nullifier_has_exactly_one_winner(tmp_path) -> None:
    rendezvous = threading.Barrier(2)

    def proof_verifier(_statement, proof: bytes) -> bool:
        rendezvous.wait(timeout=10)
        return proof == VALID_PROOF

    ledger, *_ = make_environment(tmp_path, proof_verifier=proof_verifier)
    tx_a = statement_for(ledger, nullifier=NULLIFIER_A, output=OUTPUT_A)
    tx_b = statement_for(ledger, nullifier=NULLIFIER_A, output=OUTPUT_B)

    def submit(tx):
        try:
            return ledger.accept_spend(tx, proof=VALID_PROOF)
        except Exception as exc:  # collect the loser without hiding its exact type
            return exc

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, (tx_a, tx_b)))

    accepted = [result for result in results if not isinstance(result, Exception)]
    rejected = [result for result in results if isinstance(result, Exception)]
    assert len(accepted) == 1
    assert len(rejected) == 1
    assert isinstance(rejected[0], SQLiteV3DuplicateNullifier)
    snapshot = ledger.snapshot()
    assert snapshot.state_version == 1
    assert ledger.is_nullifier_spent(NULLIFIER_A)
    assert sum(ledger.contains_commitment(out) for out in (OUTPUT_A, OUTPUT_B)) == 1
    ledger.audit_integrity()


def test_audit_rejects_orphaned_spend_row_without_event(tmp_path) -> None:
    ledger, *_ = make_environment(tmp_path)
    ledger.accept_spend(statement_for(ledger, output=OUTPUT_A), proof=VALID_PROOF)

    with sqlite3.connect(tmp_path / "candidate.sqlite3") as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """INSERT INTO v3_spent_nullifiers(
                   namespace_id,nullifier,transaction_digest,transaction_fields,
                   proof_anchor_version,proof_root,proof_head,
                   commit_root_before,state_head_before,commit_root_after,state_head_after,
                   first_output_index,output_commitment,proof_fingerprint,state_version
               )
               SELECT namespace_id,?,transaction_digest,transaction_fields,
                      proof_anchor_version,proof_root,proof_head,
                      commit_root_before,state_head_before,commit_root_after,state_head_after,
                      first_output_index,output_commitment,proof_fingerprint,state_version+1
               FROM v3_spent_nullifiers WHERE nullifier=?""",
            (b"\xA1" * 48, NULLIFIER_A),
        )

    with pytest.raises(
        SQLiteV3LedgerIntegrityError,
        match="no matching ledger event",
    ):
        ledger.audit_integrity()

@pytest.mark.parametrize(
    ("column", "tampered"),
    [
        ("commit_root_after", bytes([0xE1]) * 48),
        ("state_head_after", bytes([0xE2]) * 48),
    ],
)
def test_audit_rejects_persisted_post_state_root_or_head_substitution(
    tmp_path,
    column: str,
    tampered: bytes,
) -> None:
    ledger, *_ = make_environment(tmp_path)
    ledger.accept_spend(statement_for(ledger, output=OUTPUT_A), proof=VALID_PROOF)

    # The table/column names come from this fixed test parametrization only.
    with sqlite3.connect(tmp_path / "candidate.sqlite3") as conn:
        conn.execute(
            f"UPDATE v3_spent_nullifiers SET {column}=? WHERE nullifier=?",
            (tampered, NULLIFIER_A),
        )

    with pytest.raises(
        SQLiteV3LedgerIntegrityError,
        match="post-state root/head mismatch",
    ):
        ledger.audit_integrity()
