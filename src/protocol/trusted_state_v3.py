"""Fail-closed trust-boundary contract for V3 transaction state binding.

This module does not authenticate chain state itself. A caller must inject a reviewed
StateAnchorVerifierV3 that validates evidence against an independently trusted,
finalized state source and returns the canonical snapshot authenticated by that evidence.
The module then enforces exact V3 transaction-to-snapshot equality before a proof
verifier is called. A mock/caller-controlled verifier is not a production trust source.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from src.primitives.namespace_v3 import NamespaceIdV3
from src.protocol.transaction_v3_candidate import (
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    TxFieldsV3Candidate,
    decode_tx_fields_v3_candidate,
    transaction_digest_v3_candidate,
    validate_nk_possession_policy_v3_candidate,
)

HASH_BYTES = 48
MAX_SOURCE_ID_BYTES = 128
MAX_FINALIZED_ANCHOR_BYTES = 256
MAX_STATE_EVIDENCE_BYTES = 2_000_000


class TrustedStateRejected(ValueError):
    """V3 state evidence or transaction-to-state binding failed closed."""


@dataclass(frozen=True, slots=True)
class StateAnchorEvidenceV3:
    """Untrusted source evidence presented to a trusted state adapter.

    Evidence must contain the source-specific material needed to authenticate a
    finalized root/head, such as a verified chain header plus state proof or a
    consensus-signed checkpoint. This class does not label caller roots as trusted.
    """

    source_id: bytes
    finalized_anchor: bytes
    evidence: bytes

    def __post_init__(self) -> None:
        _require_bytes("source_id", self.source_id, 1, MAX_SOURCE_ID_BYTES)
        _require_bytes("finalized_anchor", self.finalized_anchor, 1, MAX_FINALIZED_ANCHOR_BYTES)
        _require_bytes("state evidence", self.evidence, 1, MAX_STATE_EVIDENCE_BYTES)


@dataclass(frozen=True, slots=True)
class VerifiedStateSnapshotV3:
    """Canonical state facts returned by the injected evidence verifier.

    This is a return contract, not a cryptographic token. Only a reviewed adapter
    may be trusted to construct it after validating the supplied finalized evidence.
    """

    source_id: bytes
    finalized_anchor: bytes
    namespace_id: NamespaceIdV3
    params_id: bytes
    commitment_root: bytes
    ledger_state_head: bytes

    def __post_init__(self) -> None:
        _require_bytes("source_id", self.source_id, 1, MAX_SOURCE_ID_BYTES)
        _require_bytes("finalized_anchor", self.finalized_anchor, 1, MAX_FINALIZED_ANCHOR_BYTES)
        if not isinstance(self.namespace_id, NamespaceIdV3):
            raise TrustedStateRejected("verified snapshot namespace must be NamespaceIdV3")
        _require_bytes("params_id", self.params_id, 1, 0xFFFF)
        _require_bytes("commitment_root", self.commitment_root, HASH_BYTES, HASH_BYTES)
        _require_bytes("ledger_state_head", self.ledger_state_head, HASH_BYTES, HASH_BYTES)


@dataclass(frozen=True, slots=True)
class TrustedStateBindingV3:
    """Result of checking a candidate transaction against verified state evidence."""

    statement: TxFieldsV3Candidate
    transaction_digest: bytes
    source_id: bytes
    finalized_anchor: bytes
    commitment_root: bytes
    ledger_state_head: bytes


StateAnchorVerifierV3 = Callable[[StateAnchorEvidenceV3], VerifiedStateSnapshotV3 | None]
SpendProofVerifierV3 = Callable[[TxFieldsV3Candidate, bytes], bool]


def _require_bytes(name: str, value: object, min_len: int, max_len: int) -> bytes:
    if not isinstance(value, bytes) or not min_len <= len(value) <= max_len:
        raise TrustedStateRejected(
            f"{name} must be bytes with length in [{min_len}, {max_len}]"
        )
    return value


def _decode_statement(
    statement_or_encoded: TxFieldsV3Candidate | bytes,
) -> TxFieldsV3Candidate:
    if isinstance(statement_or_encoded, TxFieldsV3Candidate):
        statement = statement_or_encoded
    elif isinstance(statement_or_encoded, bytes):
        try:
            statement = decode_tx_fields_v3_candidate(statement_or_encoded)
        except (TypeError, ValueError) as exc:
            raise TrustedStateRejected("V3 candidate transaction is not canonical") from exc
    else:
        raise TrustedStateRejected(
            "transaction must be TxFieldsV3Candidate or canonical encoded bytes"
        )

    try:
        validate_nk_possession_policy_v3_candidate(statement)
    except (TypeError, ValueError) as exc:
        raise TrustedStateRejected(
            "V3 candidate spend must explicitly select the NK-possession policy "
            f"{V3_NK_POSSESSION_POLICY_CANDIDATE!r}"
        ) from exc
    return statement


def validate_transaction_state_binding_v3(
    statement_or_encoded: TxFieldsV3Candidate | bytes,
    state_evidence: StateAnchorEvidenceV3,
    verify_state_anchor: StateAnchorVerifierV3,
) -> TrustedStateBindingV3:
    """Authenticate finalized evidence then bind exact transaction state fields.

    Fail-closed order:
      1. Parse and validate the canonical V3 transaction/evidence shapes.
      2. Authenticate the supplied evidence using the independent state adapter.
      3. Require the returned snapshot to refer to the exact evidence source/anchor.
      4. Match namespace, params ID, commitment root and state head byte-for-byte.

    This prevents this preflight API from trusting a root/head copied from the
    transaction itself. It does not create a trusted provider or prove anything
    about an adapter implementation; production must supply and review that adapter.
    """
    statement = _decode_statement(statement_or_encoded)
    if not isinstance(state_evidence, StateAnchorEvidenceV3):
        raise TrustedStateRejected("state_evidence must be StateAnchorEvidenceV3")
    if not callable(verify_state_anchor):
        raise TrustedStateRejected("a trusted-state evidence verifier is required")

    try:
        snapshot = verify_state_anchor(state_evidence)
    except Exception as exc:
        raise TrustedStateRejected("trusted-state evidence verification failed closed") from exc
    if not isinstance(snapshot, VerifiedStateSnapshotV3):
        raise TrustedStateRejected(
            "state adapter did not return a verified canonical V3 snapshot"
        )
    if (
        snapshot.source_id != state_evidence.source_id
        or snapshot.finalized_anchor != state_evidence.finalized_anchor
    ):
        raise TrustedStateRejected(
            "verified snapshot does not bind the exact supplied source/finalized anchor"
        )

    mismatches: list[str] = []
    if statement.namespace_id != snapshot.namespace_id:
        mismatches.append("namespace_id")
    if statement.params_id != snapshot.params_id:
        mismatches.append("params_id")
    if statement.commitment_root != snapshot.commitment_root:
        mismatches.append("commitment_root")
    if statement.ledger_state_head != snapshot.ledger_state_head:
        mismatches.append("ledger_state_head")
    if mismatches:
        raise TrustedStateRejected(
            "V3 transaction does not match authenticated finalized state: "
            + ", ".join(mismatches)
        )

    return TrustedStateBindingV3(
        statement=statement,
        transaction_digest=transaction_digest_v3_candidate(statement),
        source_id=snapshot.source_id,
        finalized_anchor=snapshot.finalized_anchor,
        commitment_root=snapshot.commitment_root,
        ledger_state_head=snapshot.ledger_state_head,
    )


def verify_v3_candidate_spend_preflight(
    statement_or_encoded: TxFieldsV3Candidate | bytes,
    *,
    proof: bytes,
    state_evidence: StateAnchorEvidenceV3,
    verify_state_anchor: StateAnchorVerifierV3,
    verify_spend_proof: SpendProofVerifierV3,
) -> TrustedStateBindingV3:
    """Bind transaction to verified state before invoking the candidate proof verifier.

    The proof verifier must validate the complete proof against this exact statement,
    including all duplicated public inputs. A host-only predicate is not production
    proof enforcement. This function does not atomically consume nullifiers/anchors,
    append outputs, provide consensus, or recover from reorgs.
    """
    binding = validate_transaction_state_binding_v3(
        statement_or_encoded,
        state_evidence,
        verify_state_anchor,
    )
    _require_bytes("proof", proof, 1, 2_000_000)
    if not callable(verify_spend_proof):
        raise TrustedStateRejected("a V3 spend-proof verifier is required")
    try:
        proof_ok = verify_spend_proof(binding.statement, proof) is True
    except Exception as exc:
        raise TrustedStateRejected("V3 spend-proof verification failed closed") from exc
    if not proof_ok:
        raise TrustedStateRejected("V3 spend proof rejected")
    return binding
