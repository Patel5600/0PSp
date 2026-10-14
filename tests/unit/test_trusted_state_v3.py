from __future__ import annotations

from dataclasses import replace

import pytest

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.trusted_state_v3 import (
    StateAnchorEvidenceV3,
    TrustedStateRejected,
    VerifiedStateSnapshotV3,
    validate_transaction_state_binding_v3,
    verify_v3_candidate_spend_preflight,
)
from src.protocol.transaction_v3_candidate import (
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    TxFieldsV3Candidate,
    state_context_digest_v3_candidate,
)

PARAMS = b"candidate-v3"
NS = NamespaceIdV3(b"\x01" * 48)
ROOT = b"\x02" * 48
STATE_HEAD = b"\x03" * 48
SOURCE = b"evm-mainnet"
ANCHOR = b"finalized-block-hash-123"
FINALITY_POLICY = b"fixture-finalized-state-policy-v1"
EVIDENCE = StateAnchorEvidenceV3(
    source_id=SOURCE,
    finalized_anchor=ANCHOR,
    evidence=b"fixture-only-state-evidence",
)


def transaction(**overrides: object) -> TxFieldsV3Candidate:
    fields: dict[str, object] = {
        "params_id": PARAMS,
        "namespace_id": NS,
        "commitment_root": ROOT,
        "input_nullifier": NullifierV3(b"\x04" * 48),
        "ledger_state_head": STATE_HEAD,
        "state_context_digest": state_context_digest_v3_candidate(SOURCE, ANCHOR, FINALITY_POLICY),
        "authorization_policy_id": V3_NK_POSSESSION_POLICY_CANDIDATE,
        "fee": 9,
        "output_entropy": b"\x05" * 32,
        "output_commitments": (
            CoinCommitmentV3(b"\x06" * 48),
            CoinCommitmentV3(b"\x07" * 48),
        ),
    }
    fields.update(overrides)
    return TxFieldsV3Candidate(**fields)  # type: ignore[arg-type]


def snapshot_for(tx: TxFieldsV3Candidate | None = None, **overrides: object) -> VerifiedStateSnapshotV3:
    tx = tx or transaction()
    fields: dict[str, object] = {
        "source_id": SOURCE,
        "finalized_anchor": ANCHOR,
        "finality_policy_id": FINALITY_POLICY,
        "namespace_id": tx.namespace_id,
        "params_id": tx.params_id,
        "commitment_root": tx.commitment_root,
        "ledger_state_head": tx.ledger_state_head,
    }
    fields.update(overrides)
    return VerifiedStateSnapshotV3(**fields)  # type: ignore[arg-type]


def verifier_for(snapshot: VerifiedStateSnapshotV3):
    def verify(evidence: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        assert evidence == EVIDENCE
        return snapshot
    return verify


def test_trusted_state_binding_accepts_exact_snapshot_and_canonical_bytes() -> None:
    tx = transaction()
    binding = validate_transaction_state_binding_v3(
        tx.encode(), EVIDENCE, verifier_for(snapshot_for(tx))
    )
    assert binding.statement == tx
    assert binding.transaction_digest
    assert binding.source_id == SOURCE
    assert binding.finalized_anchor == ANCHOR
    assert binding.commitment_root == ROOT
    assert binding.ledger_state_head == STATE_HEAD


@pytest.mark.parametrize(
    ("field", "override", "message"),
    [
        ("commitment_root", b"\x12" * 48, "commitment_root"),
        ("ledger_state_head", b"\x13" * 48, "ledger_state_head"),
        ("params_id", b"different-params", "params_id"),
        ("namespace_id", NamespaceIdV3(b"\x14" * 48), "namespace_id"),
    ],
)
def test_transaction_cannot_substitute_authenticated_state_fields(
    field: str, override: object, message: str
) -> None:
    trusted_tx = transaction()
    mutated_tx = transaction(**{field: override})
    with pytest.raises(TrustedStateRejected, match=message):
        validate_transaction_state_binding_v3(
            mutated_tx, EVIDENCE, verifier_for(snapshot_for(trusted_tx))
        )


def test_state_verifier_false_or_none_fails_closed() -> None:
    tx = transaction()
    for result in (False, None):
        with pytest.raises(TrustedStateRejected, match="did not return"):
            validate_transaction_state_binding_v3(
                tx, EVIDENCE, lambda _evidence, result=result: result  # type: ignore[return-value]
            )


def test_state_verifier_exception_fails_closed() -> None:
    def fail(_evidence: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        raise RuntimeError("synthetic adapter failure")

    with pytest.raises(TrustedStateRejected, match="failed closed"):
        validate_transaction_state_binding_v3(transaction(), EVIDENCE, fail)


def test_snapshot_must_bind_exact_source_and_finalized_anchor() -> None:
    tx = transaction()
    wrong_source = snapshot_for(tx, source_id=b"other-source")
    with pytest.raises(TrustedStateRejected, match="exact supplied source"):
        validate_transaction_state_binding_v3(
            tx, EVIDENCE, verifier_for(wrong_source)
        )

    wrong_anchor = snapshot_for(tx, finalized_anchor=b"other-finalized-block")
    with pytest.raises(TrustedStateRejected, match="exact supplied source"):
        validate_transaction_state_binding_v3(
            tx, EVIDENCE, verifier_for(wrong_anchor)
        )


def test_bad_evidence_and_missing_verifier_fail_before_proof_verifier() -> None:
    tx = transaction()
    calls: list[str] = []
    with pytest.raises(TrustedStateRejected, match="state_evidence"):
        validate_transaction_state_binding_v3(
            tx, b"not evidence", verifier_for(snapshot_for(tx))  # type: ignore[arg-type]
        )
    with pytest.raises(TrustedStateRejected, match="verifier is required"):
        validate_transaction_state_binding_v3(
            tx, EVIDENCE, None  # type: ignore[arg-type]
        )
    assert calls == []


def test_proof_verifier_is_not_called_until_state_binding_succeeds() -> None:
    trusted_tx = transaction()
    altered_tx = transaction(commitment_root=b"\xff" * 48)
    calls: list[bytes] = []

    def proof_verifier(_statement: TxFieldsV3Candidate, proof: bytes) -> bool:
        calls.append(proof)
        return True

    with pytest.raises(TrustedStateRejected, match="commitment_root"):
        verify_v3_candidate_spend_preflight(
            altered_tx,
            proof=b"proof-bytes",
            state_evidence=EVIDENCE,
            verify_state_anchor=verifier_for(snapshot_for(trusted_tx)),
            verify_spend_proof=proof_verifier,
        )
    assert calls == []


def test_proof_verifier_receives_exact_bound_statement_and_proof() -> None:
    tx = transaction()
    seen: list[tuple[TxFieldsV3Candidate, bytes]] = []

    def proof_verifier(statement: TxFieldsV3Candidate, proof: bytes) -> bool:
        seen.append((statement, proof))
        return True

    binding = verify_v3_candidate_spend_preflight(
        tx.encode(),
        proof=b"synthetic-proof",
        state_evidence=EVIDENCE,
        verify_state_anchor=verifier_for(snapshot_for(tx)),
        verify_spend_proof=proof_verifier,
    )
    assert seen == [(tx, b"synthetic-proof")]
    assert binding.statement == tx


def test_proof_verifier_must_return_literal_true() -> None:
    tx = transaction()
    for result in (False, 1, None):
        with pytest.raises(TrustedStateRejected, match="proof rejected"):
            verify_v3_candidate_spend_preflight(
                tx,
                proof=b"proof",
                state_evidence=EVIDENCE,
                verify_state_anchor=verifier_for(snapshot_for(tx)),
                verify_spend_proof=lambda _statement, _proof, result=result: result,  # type: ignore[return-value]
            )


def test_proof_verifier_exception_fails_closed() -> None:
    tx = transaction()

    def fail(_statement: TxFieldsV3Candidate, _proof: bytes) -> bool:
        raise RuntimeError("synthetic proof verifier failure")

    with pytest.raises(TrustedStateRejected, match="proof verification failed closed"):
        verify_v3_candidate_spend_preflight(
            tx,
            proof=b"proof",
            state_evidence=EVIDENCE,
            verify_state_anchor=verifier_for(snapshot_for(tx)),
            verify_spend_proof=fail,
        )


@pytest.mark.parametrize("proof", [b"", "proof", None, b"x" * (2_000_001)])
def test_invalid_proof_encoding_rejected_after_state_binding(proof: object) -> None:
    tx = transaction()
    with pytest.raises(TrustedStateRejected, match="proof"):
        verify_v3_candidate_spend_preflight(
            tx,
            proof=proof,  # type: ignore[arg-type]
            state_evidence=EVIDENCE,
            verify_state_anchor=verifier_for(snapshot_for(tx)),
            verify_spend_proof=lambda _statement, _proof: True,
        )


def test_injected_adapter_must_return_snapshot_not_bare_boolean() -> None:
    with pytest.raises(TrustedStateRejected, match="canonical V3 snapshot"):
        validate_transaction_state_binding_v3(
            transaction(), EVIDENCE, lambda _evidence: True  # type: ignore[return-value]
        )


def test_state_snapshot_constructor_rejects_wrong_hash_widths() -> None:
    with pytest.raises(TrustedStateRejected, match="commitment_root"):
        snapshot_for(transaction(), commitment_root=b"short")
    with pytest.raises(TrustedStateRejected, match="ledger_state_head"):
        snapshot_for(transaction(), ledger_state_head=b"short")

def test_unknown_authorization_policy_fails_before_state_or_proof_verifier() -> None:
    from src.protocol.transaction_v3_candidate import TransactionV3CandidateError

    tx = transaction(authorization_policy_id=b"unreviewed-policy-v3")
    state_calls: list[bytes] = []
    proof_calls: list[bytes] = []

    def state_verifier(evidence: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        state_calls.append(evidence.evidence)
        return snapshot_for(tx)

    def proof_verifier(_statement: TxFieldsV3Candidate, proof: bytes) -> bool:
        proof_calls.append(proof)
        return True

    with pytest.raises(TrustedStateRejected, match="NK-possession policy"):
        validate_transaction_state_binding_v3(tx, EVIDENCE, state_verifier)

    with pytest.raises(TrustedStateRejected, match="NK-possession policy"):
        verify_v3_candidate_spend_preflight(
            tx,
            proof=b"dummy-proof",
            state_evidence=EVIDENCE,
            verify_state_anchor=state_verifier,
            verify_spend_proof=proof_verifier,
        )

    assert state_calls == []
    assert proof_calls == []


def test_state_context_digest_binds_source_anchor_and_finality_policy() -> None:
    tx = transaction()
    with pytest.raises(TrustedStateRejected, match="state_context_digest"):
        validate_transaction_state_binding_v3(
            replace(tx, state_context_digest=bytes([0xFF]) * 64),
            EVIDENCE,
            verifier_for(snapshot_for(tx)),
        )
    alternate_policy_snapshot = snapshot_for(tx, finality_policy_id=b"other-finality-policy-v1")
    with pytest.raises(TrustedStateRejected, match="state_context_digest"):
        validate_transaction_state_binding_v3(tx, EVIDENCE, verifier_for(alternate_policy_snapshot))


def test_exact_nk_possession_policy_is_preserved_in_bound_transaction() -> None:
    tx = transaction()
    binding = validate_transaction_state_binding_v3(
        tx, EVIDENCE, verifier_for(snapshot_for(tx))
    )
    assert binding.statement.authorization_policy_id == V3_NK_POSSESSION_POLICY_CANDIDATE

