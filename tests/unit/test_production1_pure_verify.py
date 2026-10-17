from __future__ import annotations

from src.protocol import production1_ledger
from src.protocol.production1_artifacts import Production1OpenVMProofVerifier
from src.protocol.v3_proof_worker import PRODUCTION1_CIRCUIT_ID
from src.primitives.note_types_v3 import CoinCommitmentV3
from tests.unit.test_spend_relation_v3 import _create_test_fixture


def test_pure_production1_verify_returns_statement_data_without_applying_state(monkeypatch) -> None:
    statement, _, *_ = _create_test_fixture()
    verifier = object.__new__(Production1OpenVMProofVerifier)
    monkeypatch.setattr(
        production1_ledger,
        "verify_production_proof_envelope",
        lambda envelope, **kwargs: envelope.statement is statement and envelope.proof == b"proof",
    )

    verified = production1_ledger.verify_production1_spend(
        statement, b"proof", proof_verifier=verifier
    )

    assert verified is not None
    assert verified.relation_id == PRODUCTION1_CIRCUIT_ID
    assert verified.params_id == statement.params_id
    assert verified.namespace_id == statement.namespace_id.data
    assert verified.commitment_root == statement.commitment_root
    assert verified.nullifier == statement.input_nullifier.value
    assert verified.output_commitments == tuple(x.value for x in statement.output_commitments)
    assert verified.fee == statement.fee


def test_pure_production1_verify_fails_closed_on_bad_proof_and_arity(monkeypatch) -> None:
    statement, _, *_ = _create_test_fixture()
    verifier = object.__new__(Production1OpenVMProofVerifier)
    monkeypatch.setattr(production1_ledger, "verify_production_proof_envelope", lambda *_a, **_k: False)
    assert production1_ledger.verify_production1_spend(
        statement, b"bad proof", proof_verifier=verifier
    ) is None

    # The sole accepted relation is 1-in/1-out; malformed public arity is rejected
    # before it can be confused with a proof of some other candidate profile.
    from dataclasses import replace

    malformed = replace(
        statement,
        output_commitments=(statement.output_commitments[0], CoinCommitmentV3(b"\x99" * 48)),
    )
    assert production1_ledger.verify_production1_spend(
        malformed, b"proof", proof_verifier=verifier
    ) is None
