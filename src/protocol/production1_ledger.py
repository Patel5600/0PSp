"""Production-1 testnet composition over the append-only SQLite ledger.

This wrapper is the only spend-acceptance composition exposed to the CLI. It
requires the concrete pinned OpenVM verifier; tests and host predicate callbacks
cannot construct this profile.
"""
from __future__ import annotations

from src.protocol.production1_artifacts import Production1OpenVMProofVerifier
from src.protocol.proof_backend_v3 import verify_production_proof_envelope
from src.protocol.sqlite_v3_candidate_ledger import SQLiteV3CandidateLedger
from src.protocol.transaction_v3_candidate import TxEnvelopeV3Candidate


class SQLiteV3Production1TestnetLedger(SQLiteV3CandidateLedger):
    """Same state machine, with production1_testnet proof verification enforced."""

    def __init__(self, *args, proof_verifier: Production1OpenVMProofVerifier, **kwargs) -> None:
        if not isinstance(proof_verifier, Production1OpenVMProofVerifier):
            raise TypeError("Production-1 requires the verifier loaded from committed release pins")

        def verify(statement, proof: bytes) -> bool:
            envelope = TxEnvelopeV3Candidate(
                statement=statement,
                auth_token=bytes(48),
                proof=proof,
            )
            return verify_production_proof_envelope(
                envelope,
                proof_verifier=proof_verifier,
                profile="production1_testnet",
            )

        super().__init__(*args, verify_spend_proof=verify, **kwargs)


__all__ = ["SQLiteV3Production1TestnetLedger"]
