"""Production-1 testnet composition over the append-only SQLite ledger.

This wrapper is the only spend-acceptance composition exposed to the CLI. It
requires the concrete pinned OpenVM verifier; tests and host predicate callbacks
cannot construct this profile.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.protocol.production1_artifacts import Production1OpenVMProofVerifier
from src.protocol.proof_backend_v3 import verify_production_proof_envelope
from src.protocol.sqlite_v3_candidate_ledger import SQLiteV3CandidateLedger
from src.protocol.transaction_v3_candidate import TxEnvelopeV3Candidate, TxFieldsV3Candidate
from src.protocol.v3_proof_worker import PRODUCTION1_CIRCUIT_ID


@dataclass(frozen=True, slots=True)
class VerifiedProduction1Spend:
    """Pure verifier output; applying it to state is a separate ledger operation."""

    relation_id: str
    params_id: bytes
    namespace_id: bytes
    commitment_root: bytes
    state_head: bytes
    state_context_digest: bytes
    nullifier: bytes
    output_commitments: tuple[bytes, ...]
    fee: int


def verify_production1_spend(
    statement: TxFieldsV3Candidate,
    proof: bytes,
    *,
    proof_verifier: Production1OpenVMProofVerifier,
) -> VerifiedProduction1Spend | None:
    """Verify a Production-1 proof without consulting or mutating ledger state.

    Anchor acceptance and nullifier/output uniqueness belong to the caller's
    state-transition policy. The pinned OpenVM verifier checks the proof and the
    canonical public statement digest; malformed profiles fail closed.
    """
    if not isinstance(statement, TxFieldsV3Candidate):
        return None
    if not isinstance(proof_verifier, Production1OpenVMProofVerifier):
        return None
    if len(statement.output_commitments) != 1:
        return None
    try:
        envelope = TxEnvelopeV3Candidate(
            statement=statement,
            auth_token=bytes(48),
            proof=proof,
        )
    except (TypeError, ValueError):
        return None
    if not verify_production_proof_envelope(
        envelope,
        proof_verifier=proof_verifier,
        profile="production1_testnet",
    ):
        return None
    return VerifiedProduction1Spend(
        relation_id=PRODUCTION1_CIRCUIT_ID,
        params_id=statement.params_id,
        namespace_id=statement.namespace_id.data,
        commitment_root=statement.commitment_root,
        state_head=statement.ledger_state_head,
        state_context_digest=statement.state_context_digest,
        nullifier=statement.input_nullifier.value,
        output_commitments=tuple(item.value for item in statement.output_commitments),
        fee=statement.fee,
    )


class SQLiteV3Production1TestnetLedger(SQLiteV3CandidateLedger):
    """Same state machine, with production1_testnet proof verification enforced."""

    def __init__(self, *args, proof_verifier: Production1OpenVMProofVerifier, **kwargs) -> None:
        if not isinstance(proof_verifier, Production1OpenVMProofVerifier):
            raise TypeError("Production-1 requires the verifier loaded from committed release pins")

        def verify(statement, proof: bytes) -> bool:
            # The pure cryptographic Verify result feeds the ledger's separate
            # atomic Apply transition; the ledger rechecks anchor and uniqueness.
            return verify_production1_spend(
                statement, proof, proof_verifier=proof_verifier
            ) is not None

        super().__init__(*args, verify_spend_proof=verify, **kwargs)


__all__ = [
    "SQLiteV3Production1TestnetLedger",
    "VerifiedProduction1Spend",
    "verify_production1_spend",
]
