"""Executable reference model for 0PSP issuance/spend state transitions.

SECURITY BOUNDARY
-----------------
This module is a single-process test/reference model, NOT a production ledger.
It provides no cryptographic proof system, no chain/deposit adapter, no Merkle
root, no persistence, no consensus/finality, and no crash/reorg recovery.

Every verifier is an explicit dependency and MUST be a reviewed implementation
before any production use. Tests in this repository use test doubles and prove
only that this model applies successful transitions atomically under its lock.
They do not prove issuance soundness, zero knowledge, spend soundness or safety
of any injected verifier.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Callable

from src.primitives.namespace_v3 import NamespaceIdV3
from src.protocol.transaction_v2 import CanonicalTransactionError, validate_spend_statement_transaction

NAMESPACE_BYTES = 48
COMMITMENT_BYTES = 48
NULLIFIER_BYTES = 48
U64_MAX = (1 << 64) - 1


class LedgerRejected(ValueError):
    """Base class for a rejected reference-model state transition."""


class InvalidInput(LedgerRejected):
    """An input does not satisfy this model's canonical shape checks."""


class DepositRejected(LedgerRejected):
    """The injected deposit adapter did not authorize a valid deposit."""


class NamespaceMismatch(LedgerRejected):
    """An issuance or spend is scoped to a different configured namespace."""


class ProofRejected(LedgerRejected):
    """An injected proof verifier rejected the statement/proof pair."""


class DuplicateDeposit(LedgerRejected):
    """A deposit identifier was already consumed for issuance."""


class DuplicateCommitment(LedgerRejected):
    """A commitment would be registered more than once in its namespace."""


class DuplicateNullifier(LedgerRejected):
    """A public nullifier has already been accepted in its namespace."""


@dataclass(frozen=True)
class DepositAuthorization:
    """Authenticated facts returned by an injected chain/deposit adapter.

    This value must be created from verified deposit evidence, not copied from
    untrusted request fields. deposit_id must be a canonical, stable identity
    for the deposit (including any chain-specific output/log index as needed).
    """

    namespace_id: NamespaceIdV3
    deposit_id: bytes
    authorized_value: int
    finalized_anchor: bytes
    beneficiary_address: bytes


@dataclass(frozen=True)
class IssuanceStatement:
    """Public statement presented to the issuance-proof verifier."""

    version: int
    namespace_id: NamespaceIdV3
    commitment: bytes
    authorized_value: int
    deposit_id: bytes
    finalized_anchor: bytes
    beneficiary_address: bytes
    params_id: bytes


@dataclass(frozen=True)
class IssuedRecord:
    namespace_id: NamespaceIdV3
    commitment: bytes
    value: int
    deposit_id: bytes
    finalized_anchor: bytes
    beneficiary_address: bytes
    params_id: bytes
    state_version: int


@dataclass(frozen=True)
class SpendStatement:
    """Public inputs passed to the spend-proof verifier.

    The verifier is responsible for enforcing the complete RFC-02 relation and
    proving that parsed new_commitments match transaction_fields/digest. This
    data class enforces shape only, not cryptographic relations.
    """

    version: int
    params_id: bytes
    namespace_id: NamespaceIdV3
    commitment_root: bytes
    nullifier: bytes
    transaction_fields: bytes
    transaction_digest: bytes
    ledger_state: bytes
    authorization_policy: bytes
    new_commitments: tuple[bytes, ...]


@dataclass(frozen=True)
class AcceptedSpend:
    namespace_id: NamespaceIdV3
    nullifier: bytes
    transaction_digest: bytes
    new_commitments: tuple[bytes, ...]
    state_version: int


DepositAuthorizer = Callable[[bytes], DepositAuthorization | None]
IssuanceProofVerifier = Callable[[IssuanceStatement, bytes], bool]
SpendProofVerifier = Callable[[SpendStatement, bytes], bool]


def _require_bytes(name: str, value: bytes, *, min_len: int = 1, max_len: int | None = None) -> None:
    if not isinstance(value, bytes):
        raise InvalidInput(f"{name} must be bytes")
    if len(value) < min_len or (max_len is not None and len(value) > max_len):
        limit = f"{min_len}..{max_len}" if max_len is not None else f">={min_len}"
        raise InvalidInput(f"{name} length must be {limit}; got {len(value)}")


def _validate_value(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= U64_MAX):
        raise InvalidInput("authorized_value must be an integer in [0, 2^64-1]")


class ReferenceLedger:
    """In-memory single-namespace reference model with injected verifiers.

    A successful operation is linearized under one lock. This models replay and
    duplicate protection for tests, but is neither persistent nor consensus-safe.
    The required expected namespace prevents the deposit adapter or spend caller
    from silently routing an operation into another deployment/asset scope.
    Verifier callbacks run outside the lock; uniqueness is rechecked while the
    lock is held immediately before state changes.
    """

    def __init__(
        self,
        *,
        expected_namespace_id: NamespaceIdV3,
        authorize_deposit: DepositAuthorizer,
        verify_issuance_proof: IssuanceProofVerifier,
        verify_spend_proof: SpendProofVerifier,
    ) -> None:
        if not isinstance(expected_namespace_id, NamespaceIdV3):
            raise InvalidInput("expected_namespace_id must be a NamespaceIdV3")
        if not callable(authorize_deposit) or not callable(verify_issuance_proof) or not callable(verify_spend_proof):
            raise TypeError("all authorization and proof-verifier dependencies are required")
        self._expected_namespace_id = expected_namespace_id
        self._authorize_deposit = authorize_deposit
        self._verify_issuance_proof = verify_issuance_proof
        self._verify_spend_proof = verify_spend_proof
        self._lock = RLock()
        self._consumed_deposits: set[tuple[bytes, bytes]] = set()
        self._issued: dict[tuple[bytes, bytes], IssuedRecord] = {}
        self._spent_nullifiers: set[tuple[bytes, bytes]] = set()
        self._commitments: set[tuple[bytes, bytes]] = set()
        self._state_version = 0

    def issue(self, *, deposit_evidence: bytes, commitment: bytes, params_id: bytes, proof: bytes) -> IssuedRecord:
        """Authorize one issuance; the value comes only from deposit evidence.

        There is deliberately no caller-supplied value argument. The injected
        issuance verifier receives the authenticated deposit value and must
        prove that the hidden V2 commitment opening contains that exact value.
        """
        _require_bytes("deposit_evidence", deposit_evidence)
        _require_bytes("commitment", commitment, min_len=COMMITMENT_BYTES, max_len=COMMITMENT_BYTES)
        _require_bytes("params_id", params_id, max_len=65535)
        _require_bytes("proof", proof)

        try:
            authorization = self._authorize_deposit(deposit_evidence)
        except Exception as exc:
            raise DepositRejected("deposit authorization failed closed") from exc
        if not isinstance(authorization, DepositAuthorization):
            raise DepositRejected("deposit adapter did not return authenticated deposit facts")

        if not isinstance(authorization.namespace_id, NamespaceIdV3):
            raise NamespaceMismatch("deposit authorization must carry a typed NamespaceIdV3")
        if authorization.namespace_id != self._expected_namespace_id:
            raise NamespaceMismatch("authorized deposit belongs to a different configured namespace")
        _require_bytes("authorized deposit_id", authorization.deposit_id, max_len=128)
        _require_bytes("finalized_anchor", authorization.finalized_anchor, max_len=256)
        _require_bytes("beneficiary_address", authorization.beneficiary_address,
                       min_len=20, max_len=20)
        if authorization.beneficiary_address == bytes(20):
            raise InvalidInput("beneficiary_address must not be the zero address")
        _validate_value(authorization.authorized_value)

        statement = IssuanceStatement(
            version=2,
            namespace_id=authorization.namespace_id,
            commitment=commitment,
            authorized_value=authorization.authorized_value,
            deposit_id=authorization.deposit_id,
            finalized_anchor=authorization.finalized_anchor,
            beneficiary_address=authorization.beneficiary_address,
            params_id=params_id,
        )
        try:
            proof_ok = self._verify_issuance_proof(statement, proof) is True
        except Exception as exc:
            raise ProofRejected("issuance verifier failed closed") from exc
        if not proof_ok:
            raise ProofRejected("issuance proof rejected")

        deposit_key = (statement.namespace_id.data, statement.deposit_id)
        commitment_key = (statement.namespace_id.data, statement.commitment)
        with self._lock:
            if deposit_key in self._consumed_deposits:
                raise DuplicateDeposit("deposit has already been consumed")
            if commitment_key in self._commitments:
                raise DuplicateCommitment("commitment is already registered")

            next_version = self._state_version + 1
            record = IssuedRecord(
                namespace_id=statement.namespace_id,
                commitment=statement.commitment,
                value=statement.authorized_value,
                deposit_id=statement.deposit_id,
                finalized_anchor=statement.finalized_anchor,
                beneficiary_address=statement.beneficiary_address,
                params_id=statement.params_id,
                state_version=next_version,
            )
            # All uniqueness checks precede mutation; the lock hides this update
            # from every reader of this model until the logical transition ends.
            self._consumed_deposits.add(deposit_key)
            self._commitments.add(commitment_key)
            self._issued[commitment_key] = record
            self._state_version = next_version
            return record

    def accept_spend(self, *, statement: SpendStatement, proof: bytes) -> AcceptedSpend:
        """Accept a spend only once and append its new commitments atomically.

        Cryptographic validity and value-conservation policy are delegated to the
        injected verifier. The model supplies only canonical-shape checks and
        in-process uniqueness/linearization semantics.
        """
        if not isinstance(statement, SpendStatement):
            raise InvalidInput("statement must be a SpendStatement")
        if statement.version != 2:
            raise InvalidInput("only explicitly versioned V2 statements are accepted by this model")
        _require_bytes("params_id", statement.params_id, max_len=65535)
        if not isinstance(statement.namespace_id, NamespaceIdV3):
            raise InvalidInput("namespace_id must be a NamespaceIdV3")
        if statement.namespace_id != self._expected_namespace_id:
            raise NamespaceMismatch("spend statement belongs to a different configured namespace")
        _require_bytes("commitment_root", statement.commitment_root, max_len=128)
        _require_bytes("nullifier", statement.nullifier,
                       min_len=NULLIFIER_BYTES, max_len=NULLIFIER_BYTES)
        _require_bytes("ledger_state", statement.ledger_state, max_len=256)
        _require_bytes("authorization_policy", statement.authorization_policy, max_len=128)
        _require_bytes("transaction_fields", statement.transaction_fields, max_len=1_000_000)
        _require_bytes("transaction_digest", statement.transaction_digest, max_len=128)
        _require_bytes("proof", proof)
        if not isinstance(statement.new_commitments, tuple):
            raise InvalidInput("new_commitments must be a tuple")
        for item in statement.new_commitments:
            _require_bytes("new commitment", item,
                           min_len=COMMITMENT_BYTES, max_len=COMMITMENT_BYTES)
        if len(set(statement.new_commitments)) != len(statement.new_commitments):
            raise DuplicateCommitment("transaction repeats a new output commitment")

        try:
            proof_ok = self._verify_spend_proof(statement, proof) is True
        except Exception as exc:
            raise ProofRejected("spend verifier failed closed") from exc
        if not proof_ok:
            raise ProofRejected("spend proof rejected")

        nullifier_key = (statement.namespace_id.data, statement.nullifier)
        output_keys = tuple((statement.namespace_id.data, item) for item in statement.new_commitments)
        with self._lock:
            if nullifier_key in self._spent_nullifiers:
                raise DuplicateNullifier("nullifier has already been accepted")
            if any(key in self._commitments for key in output_keys):
                raise DuplicateCommitment("new output commitment already exists")

            next_version = self._state_version + 1
            record = AcceptedSpend(
                namespace_id=statement.namespace_id,
                nullifier=statement.nullifier,
                transaction_digest=statement.transaction_digest,
                new_commitments=statement.new_commitments,
                state_version=next_version,
            )
            self._spent_nullifiers.add(nullifier_key)
            self._commitments.update(output_keys)
            self._state_version = next_version
            return record

    @property
    def expected_namespace_id(self) -> NamespaceIdV3:
        """The fixed 48-byte namespace this reference ledger instance accepts."""
        return self._expected_namespace_id

    @property
    def state_version(self) -> int:
        with self._lock:
            return self._state_version

    @property
    def issued_count(self) -> int:
        with self._lock:
            return len(self._issued)

    @property
    def spent_count(self) -> int:
        with self._lock:
            return len(self._spent_nullifiers)

    def contains_commitment(self, namespace_id: NamespaceIdV3, commitment: bytes) -> bool:
        if not isinstance(namespace_id, NamespaceIdV3):
            return False
        with self._lock:
            return (namespace_id.data, commitment) in self._commitments
