"""Durable single-namespace SQLite ledger with atomic replay protection.

This is the persistence/state-transition layer, not a cryptographic verifier.
It requires explicit deposit and proof-verifier dependencies, pins the namespace,
parameter ID, policy ID and deployment profile, validates the append-only Merkle
root plus state-chain head before spend verification, and rechecks both inside
the write transaction before committing a spend. A test double must never be
configured as a production verifier.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from src.primitives.namespace_v3 import NamespaceIdV3
from src.protocol.commitment_tree import (
    MAX_LEAVES,
    NODE_BYTES,
    TREE_DEPTH,
    CommitmentTree,
    CommitmentTreeError,
    empty_hashes,
    leaf_hash,
    node_hash,
)
from src.protocol.reference_ledger import (
    AcceptedSpend,
    DepositAuthorization,
    DepositAuthorizer,
    DuplicateCommitment,
    DuplicateDeposit,
    DuplicateNullifier,
    DepositRejected,
    InvalidInput,
    IssuanceProofVerifier,
    IssuanceStatement,
    IssuedRecord,
    LedgerRejected,
    NamespaceMismatch,
    ProofRejected,
    SpendProofVerifier,
    SpendStatement,
)

U64_MAX = (1 << 64) - 1
SQLITE_INDEX_MAX = (1 << 63) - 1
COMMITMENT_BYTES = 48
NULLIFIER_BYTES = 48
LEDGER_HEAD_BYTES = 48
PROFILE_ID_BYTES = 32
EVENT_DOMAIN = b"0PSP-LEDGER-EVENT-v1-SHAKE256"
STATE_DOMAIN = b"0PSP-LEDGER-STATE-v1-SHAKE256"
GENESIS_DOMAIN = b"0PSP-LEDGER-GENESIS-v1-SHAKE256"
EVIDENCE_DOMAIN = b"0PSP-DEPOSIT-EVIDENCE-FINGERPRINT-v1-SHAKE256"


class PersistentLedgerError(LedgerRejected):
    """Base failure for persistent ledger state transitions."""


class StaleLedgerState(PersistentLedgerError):
    """Proof references a state root/head that is no longer current."""


class LedgerConfigurationMismatch(PersistentLedgerError):
    """Database was initialized for another deployment or parameter profile."""


class LedgerIntegrityError(PersistentLedgerError):
    """The local event chain, schema metadata or persisted tree is inconsistent."""


@dataclass(frozen=True, slots=True)
class PersistentLedgerSnapshot:
    namespace_id: NamespaceIdV3
    state_version: int
    state_head: bytes
    commitment_count: int
    commitment_root: bytes


@dataclass(frozen=True, slots=True)
class PersistentIssuedRecord:
    namespace_id: NamespaceIdV3
    commitment: bytes
    value: int
    deposit_id: bytes
    finalized_anchor: bytes
    beneficiary_address: bytes
    params_id: bytes
    commitment_index: int
    state_version: int
    state_head: bytes
    commitment_root: bytes
    deposit_evidence_fingerprint: bytes


@dataclass(frozen=True, slots=True)
class PersistentAcceptedSpend:
    namespace_id: NamespaceIdV3
    nullifier: bytes
    transaction_digest: bytes
    transaction_fields: bytes
    new_commitments: tuple[bytes, ...]
    first_output_index: int
    state_version: int
    state_head: bytes
    commitment_root: bytes


def _shake384(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(48)


def _u16(value: bytes, field: str) -> bytes:
    if len(value) > 65535:
        raise InvalidInput(f"{field} exceeds 65535 bytes")
    return len(value).to_bytes(2, "big") + value


def _u32(value: bytes, field: str) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise InvalidInput(f"{field} exceeds uint32 length")
    return len(value).to_bytes(4, "big") + value


def _validate_value(value: int, field: str = "authorized_value") -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= U64_MAX:
        raise InvalidInput(f"{field} must be an integer in [0, 2^64-1]")


def _require_bytes(value: object, field: str, *, minimum: int = 1, maximum: int | None = None) -> bytes:
    if not isinstance(value, bytes) or len(value) < minimum or (maximum is not None and len(value) > maximum):
        limit = f"{minimum}..{maximum}" if maximum is not None else f">={minimum}"
        raise InvalidInput(f"{field} must be bytes with length {limit}")
    return value


def _genesis_head(namespace_id: NamespaceIdV3, params_id: bytes, policy_id: bytes, profile_id: bytes) -> bytes:
    return _shake384(
        GENESIS_DOMAIN + b"\x01" + namespace_id.data +
        _u16(params_id, "params_id") + _u16(policy_id, "authorization_policy_id") + profile_id
    )


def _event_digest(payload: bytes) -> bytes:
    return _shake384(EVENT_DOMAIN + b"\x01" + _u32(payload, "ledger event payload"))


def _next_head(version: int, previous: bytes, digest: bytes) -> bytes:
    return _shake384(STATE_DOMAIN + b"\x01" + version.to_bytes(8, "big") + previous + digest)


def _event_payload_issue(
    namespace_id: NamespaceIdV3,
    commitment: bytes,
    deposit_id: bytes,
    value: int,
    anchor: bytes,
    beneficiary: bytes,
    params_id: bytes,
    evidence_fingerprint: bytes,
    index: int,
) -> bytes:
    return (
        b"\x01I" + namespace_id.data + commitment +
        _u16(deposit_id, "deposit_id") + value.to_bytes(8, "big") +
        _u16(anchor, "finalized_anchor") + beneficiary +
        _u16(params_id, "params_id") + evidence_fingerprint + index.to_bytes(8, "big")
    )


def _event_payload_spend(
    namespace_id: NamespaceIdV3,
    nullifier: bytes,
    transaction_digest: bytes,
    transaction_fields: bytes,
    policy_id: bytes,
    prior_commitment_root: bytes,
    first_index: int,
    outputs: tuple[bytes, ...],
) -> bytes:
    return (
        b"\x01S" + namespace_id.data + nullifier +
        _u16(transaction_digest, "transaction_digest") +
        _u32(transaction_fields, "transaction_fields") +
        _u16(policy_id, "authorization_policy_id") + prior_commitment_root +
        first_index.to_bytes(8, "big") + len(outputs).to_bytes(4, "big") + b"".join(outputs)
    )


class SQLiteLedger:
    """Durable single-namespace state machine.

    Every issue/spend state transition is one SQLite IMMEDIATE transaction.
    Merkle commitments are append-only and ordered by insertion index. Spend
    proofs must bind both the current commitment root and the current 48-byte
    state-chain head; the values are rechecked after proof verification.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        expected_namespace_id: NamespaceIdV3,
        expected_params_id: bytes,
        authorization_policy_id: bytes,
        deployment_profile_id: bytes,
        authorize_deposit: DepositAuthorizer,
        verify_issuance_proof: IssuanceProofVerifier,
        verify_spend_proof: SpendProofVerifier,
        busy_timeout_seconds: float = 30.0,
    ) -> None:
        if not isinstance(expected_namespace_id, NamespaceIdV3):
            raise TypeError("expected_namespace_id must be NamespaceIdV3")
        self._namespace = expected_namespace_id
        self._params_id = _require_bytes(expected_params_id, "expected_params_id", maximum=65535)
        self._policy_id = _require_bytes(authorization_policy_id, "authorization_policy_id", maximum=65535)
        self._profile_id = _require_bytes(deployment_profile_id, "deployment_profile_id", minimum=PROFILE_ID_BYTES, maximum=PROFILE_ID_BYTES)
        if not callable(authorize_deposit) or not callable(verify_issuance_proof) or not callable(verify_spend_proof):
            raise TypeError("deposit authorization and both proof verifier dependencies are mandatory")
        if isinstance(busy_timeout_seconds, bool) or not isinstance(busy_timeout_seconds, (int, float)) or not 0.1 <= busy_timeout_seconds <= 300:
            raise ValueError("busy_timeout_seconds must be in [0.1, 300]")
        if not isinstance(database_path, (str, Path)) or not str(database_path).strip() or str(database_path) == ":memory:":
            raise ValueError("SQLite ledger requires a non-empty file-backed database path")
        self._path = Path(database_path).expanduser().absolute()
        self._busy_timeout_ms = int(busy_timeout_seconds * 1000)
        self._authorize_deposit = authorize_deposit
        self._verify_issuance_proof = verify_issuance_proof
        self._verify_spend_proof = verify_spend_proof
        self._defaults = empty_hashes(self._namespace)
        self._secure_database_file()
        self._ensure_schema()
        # Refuse to serve a persisted database with inconsistent event/tree state.
        self.audit_integrity()

    def _secure_database_file(self) -> None:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                descriptor = os.open(self._path, flags)
            except OSError:
                raise ValueError("database path must be a regular non-symlink file") from None
        except OSError:
            raise ValueError("database directory must exist and database file must be creatable") from None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("database path must be a regular file")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self._path), timeout=self._busy_timeout_ms / 1000,
            isolation_level=None, check_same_thread=False,
        )
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        return conn

    def _expected_meta(self) -> tuple[object, ...]:
        return (
            1, self._namespace.data, self._params_id, self._policy_id,
            self._profile_id, 0,
            _genesis_head(self._namespace, self._params_id, self._policy_id, self._profile_id),
            self._defaults[TREE_DEPTH],
        )

    def _ensure_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    namespace_id BLOB NOT NULL CHECK(length(namespace_id) = 48),
                    params_id BLOB NOT NULL,
                    policy_id BLOB NOT NULL,
                    profile_id BLOB NOT NULL CHECK(length(profile_id) = 32),
                    state_version INTEGER NOT NULL CHECK(state_version >= 0),
                    state_head BLOB NOT NULL CHECK(length(state_head) = 48),
                    commitment_count INTEGER NOT NULL CHECK(commitment_count >= 0),
                    commitment_root BLOB NOT NULL CHECK(length(commitment_root) = 48)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS commitments (
                    namespace_id BLOB NOT NULL CHECK(length(namespace_id) = 48),
                    commitment BLOB NOT NULL CHECK(length(commitment) = 48),
                    commitment_index INTEGER NOT NULL CHECK(commitment_index >= 0),
                    source_kind TEXT NOT NULL CHECK(source_kind IN ('issuance','spend')),
                    source_id BLOB NOT NULL,
                    state_version INTEGER NOT NULL CHECK(state_version > 0),
                    PRIMARY KEY(namespace_id, commitment),
                    UNIQUE(namespace_id, commitment_index)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS issuance_records (
                    namespace_id BLOB NOT NULL CHECK(length(namespace_id) = 48),
                    commitment BLOB NOT NULL CHECK(length(commitment) = 48),
                    deposit_id BLOB NOT NULL,
                    value_u64_be BLOB NOT NULL CHECK(length(value_u64_be) = 8),
                    finalized_anchor BLOB NOT NULL,
                    beneficiary_address BLOB NOT NULL CHECK(length(beneficiary_address) = 20),
                    params_id BLOB NOT NULL,
                    commitment_index INTEGER NOT NULL CHECK(commitment_index >= 0),
                    state_version INTEGER NOT NULL CHECK(state_version > 0),
                    evidence_fingerprint BLOB NOT NULL CHECK(length(evidence_fingerprint) = 48),
                    state_head_after BLOB NOT NULL CHECK(length(state_head_after) = 48),
                    commitment_root_after BLOB NOT NULL CHECK(length(commitment_root_after) = 48),
                    PRIMARY KEY(namespace_id, commitment),
                    UNIQUE(namespace_id, deposit_id),
                    FOREIGN KEY(namespace_id, commitment) REFERENCES commitments(namespace_id, commitment)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS spent_nullifiers (
                    namespace_id BLOB NOT NULL CHECK(length(namespace_id) = 48),
                    nullifier BLOB NOT NULL CHECK(length(nullifier) = 48),
                    transaction_digest BLOB NOT NULL,
                    transaction_fields BLOB NOT NULL,
                    commitment_root_before BLOB NOT NULL CHECK(length(commitment_root_before) = 48),
                    state_head_before BLOB NOT NULL CHECK(length(state_head_before) = 48),
                    state_head_after BLOB NOT NULL CHECK(length(state_head_after) = 48),
                    commitment_root_after BLOB NOT NULL CHECK(length(commitment_root_after) = 48),
                    state_version INTEGER NOT NULL CHECK(state_version > 0),
                    PRIMARY KEY(namespace_id, nullifier)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger_events (
                    state_version INTEGER PRIMARY KEY CHECK(state_version > 0),
                    event_type TEXT NOT NULL CHECK(event_type IN ('issue','spend')),
                    event_id BLOB NOT NULL,
                    event_payload BLOB NOT NULL,
                    event_digest BLOB NOT NULL CHECK(length(event_digest) = 48),
                    previous_head BLOB NOT NULL CHECK(length(previous_head) = 48),
                    new_head BLOB NOT NULL CHECK(length(new_head) = 48),
                    UNIQUE(event_type, event_id)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS merkle_nodes (
                    level INTEGER NOT NULL CHECK(level >= 0 AND level <= 63),
                    node_index INTEGER NOT NULL CHECK(node_index >= 0),
                    node_hash BLOB NOT NULL CHECK(length(node_hash) = 48),
                    PRIMARY KEY(level, node_index)
                )"""
            )
            row = conn.execute(
                "SELECT schema_version, namespace_id, params_id, policy_id, profile_id, state_version, state_head, commitment_root "
                "FROM ledger_meta WHERE singleton = 1"
            ).fetchone()
            if row is None:
                genesis = self._expected_meta()
                conn.execute(
                    "INSERT INTO ledger_meta (singleton, schema_version, namespace_id, params_id, policy_id, profile_id, "
                    "state_version, state_head, commitment_count, commitment_root) VALUES (1,?,?,?,?,?,?,?,0,?)",
                    genesis,
                )
            else:
                expected = self._expected_meta()
                if tuple(row[:5]) != expected[:5]:
                    raise LedgerConfigurationMismatch(
                        "existing database metadata differs from the pinned namespace, parameter, policy or profile"
                    )

    def _meta(self, conn: sqlite3.Connection) -> tuple[int, bytes, int, bytes]:
        row = conn.execute(
            "SELECT state_version, state_head, commitment_count, commitment_root FROM ledger_meta WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise LedgerIntegrityError("ledger metadata row is missing")
        version, head, count, root = row
        return int(version), bytes(head), int(count), bytes(root)

    def _node(self, conn: sqlite3.Connection, level: int, index: int) -> bytes:
        row = conn.execute(
            "SELECT node_hash FROM merkle_nodes WHERE level = ? AND node_index = ?",
            (level, index),
        ).fetchone()
        return self._defaults[level] if row is None else bytes(row[0])

    def _append_commitment(
        self,
        conn: sqlite3.Connection,
        commitment: bytes,
        index: int,
        state_version: int,
        source_kind: str,
        source_id: bytes,
    ) -> bytes:
        if not 0 <= index < MAX_LEAVES or index > SQLITE_INDEX_MAX:
            raise PersistentLedgerError("commitment tree index space is exhausted")
        if len(commitment) != COMMITMENT_BYTES:
            raise InvalidInput("commitment must be exactly 48 bytes")
        conn.execute(
            "INSERT INTO commitments(namespace_id, commitment, commitment_index, source_kind, source_id, state_version) "
            "VALUES(?,?,?,?,?,?)",
            (self._namespace.data, commitment, index, source_kind, source_id, state_version),
        )
        current = leaf_hash(self._namespace, index, commitment)
        conn.execute(
            "INSERT INTO merkle_nodes(level, node_index, node_hash) VALUES(0,?,?) "
            "ON CONFLICT(level,node_index) DO UPDATE SET node_hash=excluded.node_hash",
            (index, current),
        )
        cursor = index
        for level in range(TREE_DEPTH):
            sibling = self._node(conn, level, cursor ^ 1)
            if cursor & 1:
                current = node_hash(self._namespace, level, sibling, current)
            else:
                current = node_hash(self._namespace, level, current, sibling)
            cursor >>= 1
            conn.execute(
                "INSERT INTO merkle_nodes(level,node_index,node_hash) VALUES(?,?,?) "
                "ON CONFLICT(level,node_index) DO UPDATE SET node_hash=excluded.node_hash",
                (level + 1, cursor, current),
            )
        return current

    def _state_head(self, conn: sqlite3.Connection) -> tuple[int, bytes, int, bytes]:
        return self._meta(conn)

    def snapshot(self) -> PersistentLedgerSnapshot:
        with closing(self._connect()) as conn:
            version, head, count, root = self._meta(conn)
            return PersistentLedgerSnapshot(self._namespace, version, head, count, root)

    def issue(
        self,
        *,
        deposit_evidence: bytes,
        commitment: bytes,
        params_id: bytes,
        proof: bytes,
    ) -> PersistentIssuedRecord:
        _require_bytes(deposit_evidence, "deposit_evidence", maximum=2_000_000)
        _require_bytes(commitment, "commitment", minimum=48, maximum=48)
        _require_bytes(params_id, "params_id", maximum=65535)
        _require_bytes(proof, "proof", maximum=2_000_000)
        if params_id != self._params_id:
            raise InvalidInput("params_id differs from the ledger's pinned parameter set")
        try:
            authorization = self._authorize_deposit(deposit_evidence)
        except Exception:
            raise DepositRejected("deposit authorization failed closed") from None
        if not isinstance(authorization, DepositAuthorization):
            raise DepositRejected("deposit adapter did not return authenticated facts")
        if not isinstance(authorization.namespace_id, NamespaceIdV3) or authorization.namespace_id != self._namespace:
            raise NamespaceMismatch("authorized deposit does not match the configured Namespace V3")
        _require_bytes(authorization.deposit_id, "authorized deposit_id", maximum=128)
        _require_bytes(authorization.finalized_anchor, "finalized_anchor", maximum=256)
        _require_bytes(authorization.beneficiary_address, "beneficiary_address", minimum=20, maximum=20)
        if authorization.beneficiary_address == bytes(20):
            raise InvalidInput("beneficiary_address must not be zero")
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
            if self._verify_issuance_proof(statement, proof) is not True:
                raise ProofRejected("issuance proof rejected")
        except ProofRejected:
            raise
        except Exception:
            raise ProofRejected("issuance verifier failed closed") from None

        evidence_fingerprint = _shake384(EVIDENCE_DOMAIN + b"\x01" + _u32(deposit_evidence, "deposit_evidence"))
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            version, previous_head, count, prior_root = self._meta(conn)
            if version >= SQLITE_INDEX_MAX:
                raise PersistentLedgerError("ledger state version space is exhausted")
            if conn.execute(
                "SELECT 1 FROM issuance_records WHERE namespace_id = ? AND deposit_id = ?",
                (self._namespace.data, authorization.deposit_id),
            ).fetchone():
                raise DuplicateDeposit("deposit has already been consumed")
            if conn.execute(
                "SELECT 1 FROM commitments WHERE namespace_id = ? AND commitment = ?",
                (self._namespace.data, commitment),
            ).fetchone():
                raise DuplicateCommitment("commitment is already registered")
            next_version = version + 1
            index = count
            root = self._append_commitment(
                conn, commitment, index, next_version, "issuance", authorization.deposit_id
            )
            if root != self._node(conn, TREE_DEPTH, 0):
                raise LedgerIntegrityError("commitment-tree root disagrees with persisted root node")
            payload = _event_payload_issue(
                self._namespace, commitment, authorization.deposit_id,
                authorization.authorized_value, authorization.finalized_anchor,
                authorization.beneficiary_address, params_id, evidence_fingerprint, index,
            )
            digest = _event_digest(payload)
            new_head = _next_head(next_version, previous_head, digest)
            value_be = authorization.authorized_value.to_bytes(8, "big")
            conn.execute(
                "INSERT INTO issuance_records(namespace_id, commitment, deposit_id, value_u64_be, "
                "finalized_anchor, beneficiary_address, params_id, commitment_index, state_version, evidence_fingerprint, "
                "state_head_after, commitment_root_after) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (self._namespace.data, commitment, authorization.deposit_id, value_be,
                 authorization.finalized_anchor, authorization.beneficiary_address, params_id,
                 index, next_version, evidence_fingerprint, new_head, root),
            )
            conn.execute(
                "INSERT INTO ledger_events(state_version,event_type,event_id,event_payload,event_digest,previous_head,new_head) "
                "VALUES(?,?,?,?,?,?,?)",
                (next_version, "issue", authorization.deposit_id, payload, digest, previous_head, new_head),
            )
            conn.execute(
                "UPDATE ledger_meta SET state_version=?, state_head=?, commitment_count=?, commitment_root=? WHERE singleton=1",
                (next_version, new_head, count + 1, root),
            )
            conn.execute("COMMIT")
            return PersistentIssuedRecord(
                self._namespace, commitment, authorization.authorized_value,
                authorization.deposit_id, authorization.finalized_anchor,
                authorization.beneficiary_address, params_id, index, next_version,
                new_head, root, evidence_fingerprint,
            )
        except sqlite3.IntegrityError as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            text = str(exc).lower()
            if "commitment" in text:
                raise DuplicateCommitment("commitment or commitment index already exists") from None
            if "deposit" in text:
                raise DuplicateDeposit("deposit has already been consumed") from None
            raise PersistentLedgerError("database uniqueness constraint rejected the issuance") from None
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def accept_spend(self, *, statement: SpendStatement, proof: bytes) -> PersistentAcceptedSpend:
        if not isinstance(statement, SpendStatement):
            raise InvalidInput("statement must be a SpendStatement")
        if statement.version != 2:
            raise InvalidInput("only protocol V2 spend statements are accepted")
        if not isinstance(statement.namespace_id, NamespaceIdV3) or statement.namespace_id != self._namespace:
            raise NamespaceMismatch("spend statement namespace differs from the pinned namespace")
        if statement.params_id != self._params_id:
            raise InvalidInput("spend params_id differs from the pinned parameter set")
        if statement.authorization_policy != self._policy_id:
            raise InvalidInput("spend authorization policy differs from the pinned policy")
        _require_bytes(statement.nullifier, "nullifier", minimum=48, maximum=48)
        _require_bytes(statement.commitment_root, "commitment_root", minimum=48, maximum=48)
        _require_bytes(statement.ledger_state, "ledger_state", minimum=48, maximum=48)
        _require_bytes(statement.transaction_digest, "transaction_digest", maximum=128)
        _require_bytes(statement.transaction_fields, "transaction_fields", maximum=1_000_000)
        _require_bytes(proof, "proof", maximum=2_000_000)
        if not isinstance(statement.new_commitments, tuple):
            raise InvalidInput("new_commitments must be a tuple")
        if not 1 <= len(statement.new_commitments) <= 1024:
            raise InvalidInput("each spend must create between 1 and 1024 output commitments")
        if len(statement.new_commitments) > 1024:
            raise InvalidInput("transaction may create at most 1024 output commitments")
        for output in statement.new_commitments:
            _require_bytes(output, "new commitment", minimum=48, maximum=48)
        if len(set(statement.new_commitments)) != len(statement.new_commitments):
            raise DuplicateCommitment("transaction repeats a new output commitment")

        with closing(self._connect()) as conn:
            version, previous_head, count, current_root = self._meta(conn)
        if statement.ledger_state != previous_head or statement.commitment_root != current_root:
            raise StaleLedgerState("spend proof does not bind the currently committed state head and commitment root")
        try:
            if self._verify_spend_proof(statement, proof) is not True:
                raise ProofRejected("spend proof rejected")
        except ProofRejected:
            raise
        except Exception:
            raise ProofRejected("spend verifier failed closed") from None

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            version_now, previous_now, count_now, root_now = self._meta(conn)
            if (version_now, previous_now, count_now, root_now) != (version, previous_head, count, current_root):
                raise StaleLedgerState("ledger changed while spend proof was being verified")
            if conn.execute(
                "SELECT 1 FROM spent_nullifiers WHERE namespace_id=? AND nullifier=?",
                (self._namespace.data, statement.nullifier),
            ).fetchone():
                raise DuplicateNullifier("nullifier has already been accepted")
            if any(conn.execute(
                "SELECT 1 FROM commitments WHERE namespace_id=? AND commitment=?",
                (self._namespace.data, output),
            ).fetchone() for output in statement.new_commitments):
                raise DuplicateCommitment("an output commitment already exists")
            if version_now >= SQLITE_INDEX_MAX:
                raise PersistentLedgerError("ledger state version space is exhausted")
            next_version = version_now + 1
            first_index = count_now
            new_root = root_now
            for output_offset, output in enumerate(statement.new_commitments):
                index = first_index + output_offset
                new_root = self._append_commitment(
                    conn, output, index, next_version, "spend", statement.nullifier
                )
            payload = _event_payload_spend(
                self._namespace, statement.nullifier, statement.transaction_digest,
                statement.transaction_fields, self._policy_id, root_now, first_index,
                statement.new_commitments,
            )
            digest = _event_digest(payload)
            new_head = _next_head(next_version, previous_now, digest)
            conn.execute(
                "INSERT INTO spent_nullifiers(namespace_id,nullifier,transaction_digest,transaction_fields,"
                "commitment_root_before,state_head_before,state_head_after,commitment_root_after,state_version) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (self._namespace.data, statement.nullifier, statement.transaction_digest,
                 statement.transaction_fields, root_now, previous_now, new_head, new_root, next_version),
            )
            conn.execute(
                "INSERT INTO ledger_events(state_version,event_type,event_id,event_payload,event_digest,previous_head,new_head) "
                "VALUES(?,?,?,?,?,?,?)",
                (next_version, "spend", statement.nullifier, payload, digest, previous_now, new_head),
            )
            conn.execute(
                "UPDATE ledger_meta SET state_version=?, state_head=?, commitment_count=?, commitment_root=? WHERE singleton=1",
                (next_version, new_head, count_now + len(statement.new_commitments), new_root),
            )
            conn.execute("COMMIT")
            return PersistentAcceptedSpend(
                self._namespace, statement.nullifier, statement.transaction_digest,
                statement.transaction_fields, statement.new_commitments, first_index,
                next_version, new_head, new_root,
            )
        except sqlite3.IntegrityError:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise PersistentLedgerError("database uniqueness constraint rejected the spend") from None
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def membership_path(self, commitment: bytes) -> tuple[int, tuple[bytes, ...]]:
        _require_bytes(commitment, "commitment", minimum=48, maximum=48)
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT commitment_index FROM commitments WHERE namespace_id=? AND commitment=?",
                (self._namespace.data, commitment),
            ).fetchone()
            if row is None:
                raise KeyError("commitment is not registered")
            index = int(row[0])
            siblings = []
            cursor = index
            for level in range(TREE_DEPTH):
                siblings.append(self._node(conn, level, cursor ^ 1))
                cursor >>= 1
            return index, tuple(siblings)

    def snapshot(self) -> PersistentLedgerSnapshot:
        with closing(self._connect()) as conn:
            version, head, count, root = self._meta(conn)
            return PersistentLedgerSnapshot(self._namespace, version, head, count, root)

    def get_issued_record(self, commitment: bytes) -> PersistentIssuedRecord | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT deposit_id,value_u64_be,finalized_anchor,beneficiary_address,params_id,"
                "commitment_index,state_version,evidence_fingerprint,state_head_after,commitment_root_after "
                "FROM issuance_records "
                "WHERE namespace_id=? AND commitment=?",
                (self._namespace.data, commitment),
            ).fetchone()
            if row is None:
                return None
            snap = self._meta(conn)
            return PersistentIssuedRecord(
                self._namespace, commitment, int.from_bytes(row[1], "big"),
                bytes(row[0]), bytes(row[2]), bytes(row[3]), bytes(row[4]),
                int(row[5]), int(row[6]), bytes(row[8]), bytes(row[9]), bytes(row[7]),
            )

    def contains_commitment(self, commitment: bytes) -> bool:
        with closing(self._connect()) as conn:
            return conn.execute(
                "SELECT 1 FROM commitments WHERE namespace_id=? AND commitment=?",
                (self._namespace.data, commitment),
            ).fetchone() is not None

    def is_nullifier_spent(self, nullifier: bytes) -> bool:
        with closing(self._connect()) as conn:
            return conn.execute(
                "SELECT 1 FROM spent_nullifiers WHERE namespace_id=? AND nullifier=?",
                (self._namespace.data, nullifier),
            ).fetchone() is not None

    def issued_count(self) -> int:
        with closing(self._connect()) as conn:
            return int(conn.execute(
                "SELECT COUNT(*) FROM issuance_records WHERE namespace_id=?", (self._namespace.data,)
            ).fetchone()[0])

    def spent_count(self) -> int:
        with closing(self._connect()) as conn:
            return int(conn.execute(
                "SELECT COUNT(*) FROM spent_nullifiers WHERE namespace_id=?", (self._namespace.data,)
            ).fetchone()[0])

    def audit_integrity(self, *, rebuild_merkle_root: bool = True) -> None:
        """Reconcile metadata, every tree node, transition record, and event-chain entry.

        This detects accidental/torn edits and partial record corruption. Because
        the chain head is stored in the same local database, it cannot detect an
        attacker who rewrites every row and recomputes a new internally consistent
        database; use an external signed/anchored checkpoint for that threat model.
        """
        with closing(self._connect()) as conn:
            # The database is single-namespace by design. Unexpected rows scoped to
            # another namespace are corruption, not harmless unrelated records.
            expected_namespace = self._namespace.data
            for table in ("commitments", "issuance_records", "spent_nullifiers"):
                namespaces = {
                    bytes(row[0])
                    for row in conn.execute(f"SELECT DISTINCT namespace_id FROM {table}")
                }
                if any(value != expected_namespace for value in namespaces):
                    raise LedgerIntegrityError(f"{table} contains a row outside the pinned namespace")

            version, head, count, root = self._meta(conn)
            commitment_rows = conn.execute(
                "SELECT namespace_id,commitment,commitment_index,source_kind,source_id,state_version "
                "FROM commitments ORDER BY commitment_index"
            ).fetchall()
            if len(commitment_rows) != count:
                raise LedgerIntegrityError("commitment count differs from metadata")

            commitments_by_version: dict[int, list[tuple[bytes, int, str, bytes]]] = {}
            commitments_by_index: dict[int, tuple[bytes, str, bytes, int]] = {}
            tree = CommitmentTree(self._namespace)
            for expected_index, row in enumerate(commitment_rows):
                namespace, commitment, raw_index, source_kind, source_id, raw_version = row
                namespace, commitment, source_id = bytes(namespace), bytes(commitment), bytes(source_id)
                index, row_version = int(raw_index), int(raw_version)
                if namespace != expected_namespace:
                    raise LedgerIntegrityError("commitment row namespace differs from metadata")
                if index != expected_index:
                    raise LedgerIntegrityError("commitment indices are not contiguous and append-only")
                if source_kind not in {"issuance", "spend"}:
                    raise LedgerIntegrityError("commitment has an unknown source kind")
                if not 1 <= row_version <= version:
                    raise LedgerIntegrityError("commitment references an invalid state version")
                commitments_by_version.setdefault(row_version, []).append(
                    (commitment, index, source_kind, source_id)
                )
                commitments_by_index[index] = (commitment, source_kind, source_id, row_version)

            roots_by_version: dict[int, bytes] = {0: tree.root}
            for state_version in range(1, version + 1):
                entries = commitments_by_version.get(state_version)
                if not entries:
                    raise LedgerIntegrityError("a ledger state version contains no appended commitment")
                # Indices were checked globally above; every transition's outputs
                # therefore occupy one canonical contiguous interval.
                for commitment, index, _kind, _source_id in entries:
                    if tree.append(commitment) != index:
                        raise LedgerIntegrityError("reconstructed tree index differs from the persisted append index")
                roots_by_version[state_version] = tree.root
            if set(commitments_by_version) != set(range(1, version + 1)):
                raise LedgerIntegrityError("commitment rows refer to missing or unexpected state versions")
            if rebuild_merkle_root and tree.root != root:
                raise LedgerIntegrityError("recomputed commitment tree root differs from ledger metadata")

            # Do not check only the root node. A corrupted sibling node can leave
            # the stored root untouched while making membership witnesses invalid.
            expected_nodes = {
                (level, node_index): node_hash_value
                for level, level_nodes in enumerate(tree._levels)
                for node_index, node_hash_value in level_nodes.items()
            }
            stored_nodes = {
                (int(level), int(node_index)): bytes(node_hash_value)
                for level, node_index, node_hash_value in conn.execute(
                    "SELECT level,node_index,node_hash FROM merkle_nodes"
                )
            }
            if stored_nodes != expected_nodes:
                raise LedgerIntegrityError("persisted Merkle nodes differ from the reconstructed append-only tree")
            if self._node(conn, TREE_DEPTH, 0) != root:
                raise LedgerIntegrityError("persisted Merkle root node differs from ledger metadata")

            issue_rows = conn.execute(
                "SELECT namespace_id,commitment,deposit_id,value_u64_be,finalized_anchor,beneficiary_address,"
                "params_id,commitment_index,state_version,evidence_fingerprint,state_head_after,commitment_root_after "
                "FROM issuance_records ORDER BY state_version"
            ).fetchall()
            spend_rows = conn.execute(
                "SELECT namespace_id,nullifier,transaction_digest,transaction_fields,commitment_root_before,"
                "state_head_before,state_head_after,commitment_root_after,state_version "
                "FROM spent_nullifiers ORDER BY state_version"
            ).fetchall()
            issues_by_version: dict[int, tuple[object, ...]] = {}
            spends_by_version: dict[int, tuple[object, ...]] = {}
            for row in issue_rows:
                row_version = int(row[8])
                if row_version in issues_by_version or not 1 <= row_version <= version:
                    raise LedgerIntegrityError("issuance records contain a duplicate or invalid state version")
                issues_by_version[row_version] = row
            for row in spend_rows:
                row_version = int(row[8])
                if row_version in spends_by_version or not 1 <= row_version <= version:
                    raise LedgerIntegrityError("spend records contain a duplicate or invalid state version")
                spends_by_version[row_version] = row
            if len(issue_rows) + len(spend_rows) != version:
                raise LedgerIntegrityError("every ledger state version must map to exactly one issuance or spend record")

            event_rows = conn.execute(
                "SELECT state_version,event_type,event_id,event_payload,event_digest,previous_head,new_head "
                "FROM ledger_events ORDER BY state_version"
            ).fetchall()
            if len(event_rows) != version:
                raise LedgerIntegrityError("ledger event count differs from the state version")

            expected_head = _genesis_head(
                self._namespace, self._params_id, self._policy_id, self._profile_id
            )
            for expected_version, event in enumerate(event_rows, start=1):
                event_version, event_type, event_id, event_payload, event_digest, previous, new = event
                event_version = int(event_version)
                event_id, event_payload = bytes(event_id), bytes(event_payload)
                event_digest, previous, new = bytes(event_digest), bytes(previous), bytes(new)
                if event_version != expected_version:
                    raise LedgerIntegrityError("ledger event versions are not contiguous")
                if _event_digest(event_payload) != event_digest:
                    raise LedgerIntegrityError("ledger event digest does not match its canonical payload")
                if previous != expected_head:
                    raise LedgerIntegrityError("ledger event chain has a broken previous head")
                calculated_head = _next_head(expected_version, expected_head, event_digest)
                if new != calculated_head:
                    raise LedgerIntegrityError("ledger event chain head does not recompute")

                has_issue = expected_version in issues_by_version
                has_spend = expected_version in spends_by_version
                if has_issue == has_spend:
                    raise LedgerIntegrityError("state version must have exactly one matching transition record")

                entries = commitments_by_version.get(expected_version, [])
                if event_type == "issue":
                    if not has_issue or has_spend:
                        raise LedgerIntegrityError("issuance event has no unique issuance record")
                    row = issues_by_version[expected_version]
                    (namespace, commitment, deposit_id, value_be, anchor, beneficiary, params_id,
                     raw_index, raw_row_version, evidence_fingerprint, head_after, root_after) = row
                    namespace, commitment, deposit_id = bytes(namespace), bytes(commitment), bytes(deposit_id)
                    value_be, anchor, beneficiary, params_id = bytes(value_be), bytes(anchor), bytes(beneficiary), bytes(params_id)
                    evidence_fingerprint, head_after, root_after = bytes(evidence_fingerprint), bytes(head_after), bytes(root_after)
                    index, row_version = int(raw_index), int(raw_row_version)
                    if namespace != expected_namespace or params_id != self._params_id:
                        raise LedgerIntegrityError("issuance record namespace or parameter ID differs from pinned configuration")
                    if len(value_be) != 8 or len(beneficiary) != 20 or beneficiary == bytes(20):
                        raise LedgerIntegrityError("issuance record contains malformed value or beneficiary encoding")
                    if not anchor or len(anchor) > 256 or not deposit_id or len(deposit_id) > 128 or len(evidence_fingerprint) != 48:
                        raise LedgerIntegrityError("issuance record contains malformed deposit evidence metadata")
                    if row_version != expected_version or len(entries) != 1:
                        raise LedgerIntegrityError("issuance transition must append exactly one commitment at its state version")
                    if event_id != deposit_id:
                        raise LedgerIntegrityError("issuance event ID differs from its deposit record")
                    mapped = commitments_by_index.get(index)
                    if mapped != (commitment, "issuance", deposit_id, expected_version):
                        raise LedgerIntegrityError("issuance record does not match its commitment-tree leaf")
                    if head_after != new or root_after != roots_by_version[expected_version]:
                        raise LedgerIntegrityError("issuance record's post-state head/root differs from reconstructed state")
                    payload_expected = _event_payload_issue(
                        self._namespace, commitment, deposit_id, int.from_bytes(value_be, "big"),
                        anchor, beneficiary, params_id, evidence_fingerprint, index,
                    )
                elif event_type == "spend":
                    if not has_spend or has_issue:
                        raise LedgerIntegrityError("spend event has no unique spend record")
                    row = spends_by_version[expected_version]
                    (namespace, nullifier, transaction_digest, transaction_fields, root_before,
                     head_before, head_after, root_after, raw_row_version) = row
                    namespace, nullifier = bytes(namespace), bytes(nullifier)
                    transaction_digest, transaction_fields = bytes(transaction_digest), bytes(transaction_fields)
                    root_before, head_before, head_after, root_after = bytes(root_before), bytes(head_before), bytes(head_after), bytes(root_after)
                    row_version = int(raw_row_version)
                    if namespace != expected_namespace:
                        raise LedgerIntegrityError("spend record namespace differs from pinned namespace")
                    if len(nullifier) != 48 or not transaction_digest or len(transaction_digest) > 128:
                        raise LedgerIntegrityError("spend record contains malformed nullifier or transaction digest")
                    if row_version != expected_version or not entries:
                        raise LedgerIntegrityError("spend transition must append one or more output commitments")
                    if event_id != nullifier:
                        raise LedgerIntegrityError("spend event ID differs from its nullifier record")
                    if root_before != roots_by_version[expected_version - 1] or root_after != roots_by_version[expected_version]:
                        raise LedgerIntegrityError("spend record's before/after commitment root differs from reconstructed tree state")
                    if head_before != expected_head or head_after != new:
                        raise LedgerIntegrityError("spend record's before/after state head differs from reconstructed event chain")
                    first_index = entries[0][1]
                    outputs = tuple(entry[0] for entry in entries)
                    if any(entry[2] != "spend" or entry[3] != nullifier for entry in entries):
                        raise LedgerIntegrityError("spend outputs do not match their source nullifier")
                    payload_expected = _event_payload_spend(
                        self._namespace, nullifier, transaction_digest, transaction_fields,
                        self._policy_id, root_before, first_index, outputs,
                    )
                else:
                    raise LedgerIntegrityError("ledger event has an unknown transition type")

                if event_payload != payload_expected:
                    raise LedgerIntegrityError("ledger event payload does not match its issuance/spend record")
                expected_head = calculated_head

            if expected_head != head or len(event_rows) != version:
                raise LedgerIntegrityError("ledger meta head/version differs from reconstructed event chain")
