"""Single-node SQLite state machine for the non-normative V3 spend candidate.

The ledger accepts only the exact NK-possession candidate policy and only one-output
spends, matching proof/openvm/v3-nullifier-spike. Every proof is checked against a
retained root/head pair from this ledger, then its nullifier and output commitment are
committed atomically under BEGIN IMMEDIATE. Verifier callbacks are mandatory and run
outside the write transaction; roots, heads, anchors, and uniqueness are rechecked
under the transaction before the state transition.

TRUST BOUNDARY
--------------
This is a durable *single-node candidate* ledger, not a consensus ledger. Initial
commitments must be imported from a snapshot returned by an independently reviewed
state-evidence verifier. On restart the same bootstrap evidence is re-verified and
the append-only local event/tree state is audited. The local event chain cannot
prevent a privileged operator from rewriting the entire database and recomputing it;
an external checkpoint/consensus and reorg recovery remain required. The injected
spend verifier must check an actual proof against this exact transaction and expected
public digest; tests with callback doubles establish only state-machine behavior.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.commitment_tree import (
    MAX_LEAVES,
    TREE_DEPTH,
    CommitmentTree,
    CommitmentTreeError,
    empty_hashes,
    leaf_hash,
    node_hash,
)
from src.protocol.transaction_v3_candidate import (
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    TransactionV3CandidateError,
    TxFieldsV3Candidate,
    decode_tx_fields_v3_candidate,
    transaction_digest_v3_candidate,
    validate_nk_possession_policy_v3_candidate,
)
from src.protocol.trusted_state_v3 import (
    StateAnchorEvidenceV3,
    StateAnchorVerifierV3,
    TrustedStateRejected,
    VerifiedStateSnapshotV3,
    validate_transaction_state_binding_v3,
)

HASH_BYTES = 48
TRANSACTION_DIGEST_BYTES = 64
PROFILE_ID_BYTES = 32
LEDGER_ID_BYTES = 16
SQLITE_INDEX_MAX = (1 << 63) - 1
MAX_PROOF_BYTES = 2_000_000
MAX_TX_BYTES = 1_000_000
DEFAULT_ANCHOR_WINDOW = 256
LOCAL_FINALITY_POLICY_ID = b"0PSP-SQLITE-V3-CANDIDATE-LOCAL-STATE-NONFINAL-v1"

_EVENT_DOMAIN = b"0PSP-V3-CANDIDATE-LEDGER-EVENT-v1-SHAKE256"
_STATE_DOMAIN = b"0PSP-V3-CANDIDATE-LEDGER-STATE-v1-SHAKE256"
_SOURCE_DOMAIN = b"0PSP-SQLITE-V3-CANDIDATE-STATE-SOURCE-v1"
_LOCAL_EVIDENCE_DOMAIN = b"0PSP-SQLITE-V3-CANDIDATE-LOCAL-STATE-EVIDENCE-v1"
_SCHEMA_VERSION = 2


class SQLiteV3CandidateLedgerError(ValueError):
    """Base error for the V3 candidate SQLite state machine."""


class SQLiteV3StaleLedgerState(SQLiteV3CandidateLedgerError):
    """The proven root/head pair is unknown or no longer retained."""


class SQLiteV3DuplicateNullifier(SQLiteV3CandidateLedgerError):
    """The candidate nullifier was already consumed."""


class SQLiteV3DuplicateCommitment(SQLiteV3CandidateLedgerError):
    """An output commitment already exists in the local namespace."""


class SQLiteV3ProofRejected(SQLiteV3CandidateLedgerError):
    """The injected V3 candidate proof verifier failed closed."""


class SQLiteV3LedgerIntegrityError(SQLiteV3CandidateLedgerError):
    """Persisted V3 event/tree/anchor state failed its integrity audit."""


class SQLiteV3ConfigurationMismatch(SQLiteV3CandidateLedgerError):
    """The database is pinned to another V3 candidate deployment."""


@dataclass(frozen=True, slots=True)
class SQLiteV3CandidateSnapshot:
    namespace_id: NamespaceIdV3
    state_version: int
    ledger_state_head: bytes
    commitment_count: int
    commitment_root: bytes


@dataclass(frozen=True, slots=True)
class SQLiteV3AcceptedSpend:
    namespace_id: NamespaceIdV3
    nullifier: bytes
    transaction_digest: bytes
    transaction_fields: bytes
    output_commitment: bytes
    proof_anchor_version: int
    first_output_index: int
    state_version: int
    state_head_after: bytes
    commitment_root_after: bytes


V3CandidateSpendProofVerifier = Callable[[TxFieldsV3Candidate, bytes], bool]


def _require_bytes(
    name: str,
    value: object,
    minimum: int = 1,
    maximum: int | None = None,
) -> bytes:
    if not isinstance(value, bytes) or len(value) < minimum or (maximum is not None and len(value) > maximum):
        bound = f"{minimum}..{maximum}" if maximum is not None else f">={minimum}"
        raise SQLiteV3CandidateLedgerError(f"{name} must be bytes with length {bound}")
    return value


def _shake384(value: bytes) -> bytes:
    return hashlib.shake_256(value).digest(HASH_BYTES)


def _u16(value: bytes, name: str) -> bytes:
    if len(value) > 0xFFFF:
        raise SQLiteV3CandidateLedgerError(f"{name} exceeds uint16 length")
    return len(value).to_bytes(2, "big") + value


def _u32(value: bytes, name: str) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise SQLiteV3CandidateLedgerError(f"{name} exceeds uint32 length")
    return len(value).to_bytes(4, "big") + value


def _state_source_id(ledger_id: bytes) -> bytes:
    return _SOURCE_DOMAIN + ledger_id


def _local_evidence_payload(ledger_id: bytes, anchor_payload: bytes) -> bytes:
    return _LOCAL_EVIDENCE_DOMAIN + ledger_id + anchor_payload


def _anchor_payload(
    state_version: int,
    commitment_root: bytes,
    ledger_state_head: bytes,
    commitment_count: int,
) -> bytes:
    return (
        state_version.to_bytes(8, "big")
        + commitment_root
        + ledger_state_head
        + commitment_count.to_bytes(8, "big")
    )


def _event_digest(payload: bytes) -> bytes:
    return _shake384(_EVENT_DOMAIN + b"\x03" + _u32(payload, "event payload"))


def _next_head(state_version: int, previous_head: bytes, digest: bytes) -> bytes:
    return _shake384(
        _STATE_DOMAIN + b"\x03" + state_version.to_bytes(8, "big") + previous_head + digest
    )


def _event_payload(
    namespace_id: NamespaceIdV3,
    nullifier: bytes,
    transaction_digest: bytes,
    transaction_fields: bytes,
    prior_root: bytes,
    prior_head: bytes,
    proof_anchor_version: int,
    first_output_index: int,
    output_commitment: bytes,
    proof_fingerprint: bytes,
) -> bytes:
    return b"".join(
        (
            b"\x03S",
            namespace_id.data,
            nullifier,
            transaction_digest,
            _u32(transaction_fields, "transaction fields"),
            _u16(V3_NK_POSSESSION_POLICY_CANDIDATE, "authorization policy"),
            prior_root,
            prior_head,
            proof_anchor_version.to_bytes(8, "big"),
            first_output_index.to_bytes(8, "big"),
            output_commitment,
            proof_fingerprint,
        )
    )


class SQLiteV3CandidateLedger:
    """Atomic local state transitions for the one-input/one-output V3 candidate.

    The constructor requires an independently verified bootstrap snapshot. Its
    commitment list must reconstruct the verified root exactly. Each accepted spend
    can use any of the last 256 local root/head snapshots; the chosen anchor is checked
    both before proof verification and again inside the write transaction after the
    proof is verified. This prevents stale-moving-head races while retaining replay
    protection for older proofs.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        expected_namespace_id: NamespaceIdV3,
        expected_params_id: bytes,
        deployment_profile_id: bytes,
        bootstrap_evidence: StateAnchorEvidenceV3,
        verify_bootstrap_state: StateAnchorVerifierV3,
        verify_spend_proof: V3CandidateSpendProofVerifier,
        bootstrap_commitments: Sequence[bytes] | None = None,
        anchor_window: int = DEFAULT_ANCHOR_WINDOW,
        busy_timeout_seconds: float = 30.0,
    ) -> None:
        if not isinstance(expected_namespace_id, NamespaceIdV3):
            raise TypeError("expected_namespace_id must be NamespaceIdV3")
        self._namespace = expected_namespace_id
        self._params_id = _require_bytes("expected_params_id", expected_params_id, 1, 0xFFFF)
        self._profile_id = _require_bytes("deployment_profile_id", deployment_profile_id, PROFILE_ID_BYTES, PROFILE_ID_BYTES)
        self._policy_id = V3_NK_POSSESSION_POLICY_CANDIDATE
        if not isinstance(bootstrap_evidence, StateAnchorEvidenceV3):
            raise TypeError("bootstrap_evidence must be StateAnchorEvidenceV3")
        if not callable(verify_bootstrap_state):
            raise TypeError("an independent bootstrap state verifier is mandatory")
        if not callable(verify_spend_proof):
            raise TypeError("a V3 candidate proof verifier is mandatory")
        if isinstance(anchor_window, bool) or not isinstance(anchor_window, int) or not 2 <= anchor_window <= 4096:
            raise ValueError("anchor_window must be in [2, 4096]")
        if isinstance(busy_timeout_seconds, bool) or not isinstance(busy_timeout_seconds, (int, float)) or not 0.1 <= busy_timeout_seconds <= 300:
            raise ValueError("busy_timeout_seconds must be in [0.1, 300]")
        if not isinstance(database_path, (str, Path)) or not str(database_path).strip() or str(database_path) == ":memory:":
            raise ValueError("SQLite V3 candidate ledger requires a file-backed database path")
        self._path = Path(database_path).expanduser().absolute()
        self._busy_timeout_ms = int(busy_timeout_seconds * 1000)
        self._anchor_window = anchor_window
        self._verify_bootstrap_state = verify_bootstrap_state
        self._verify_spend_proof = verify_spend_proof
        self._defaults = empty_hashes(self._namespace)
        self._secure_database_file()
        self._ensure_schema(bootstrap_evidence, bootstrap_commitments)
        self._reauthenticate_bootstrap()
        self.audit_integrity()

    def _secure_database_file(self) -> None:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                descriptor = os.open(self._path, flags)
            except OSError:
                raise SQLiteV3CandidateLedgerError("database must be a regular non-symlink file") from None
        except OSError:
            raise SQLiteV3CandidateLedgerError("database directory must exist and be writable") from None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise SQLiteV3CandidateLedgerError("database path is not a regular file")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self._path),
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        return conn

    def _ensure_schema(
        self,
        bootstrap_evidence: StateAnchorEvidenceV3,
        bootstrap_commitments: Sequence[bytes] | None,
    ) -> None:
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS v3_ledger_meta (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    schema_version INTEGER NOT NULL,
                    namespace_id BLOB NOT NULL CHECK(length(namespace_id)=48),
                    params_id BLOB NOT NULL,
                    policy_id BLOB NOT NULL,
                    profile_id BLOB NOT NULL CHECK(length(profile_id)=32),
                    ledger_id BLOB NOT NULL CHECK(length(ledger_id)=16),
                    bootstrap_source_id BLOB NOT NULL,
                    bootstrap_finalized_anchor BLOB NOT NULL,
                    bootstrap_evidence BLOB NOT NULL,
                    bootstrap_root BLOB NOT NULL CHECK(length(bootstrap_root)=48),
                    bootstrap_head BLOB NOT NULL CHECK(length(bootstrap_head)=48),
                    bootstrap_count INTEGER NOT NULL CHECK(bootstrap_count>=0),
                    state_version INTEGER NOT NULL CHECK(state_version>=0),
                    state_head BLOB NOT NULL CHECK(length(state_head)=48),
                    commitment_count INTEGER NOT NULL CHECK(commitment_count>=0),
                    commitment_root BLOB NOT NULL CHECK(length(commitment_root)=48)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS v3_commitments (
                    namespace_id BLOB NOT NULL CHECK(length(namespace_id)=48),
                    commitment BLOB NOT NULL CHECK(length(commitment)=48),
                    commitment_index INTEGER NOT NULL CHECK(commitment_index>=0),
                    source_kind TEXT NOT NULL CHECK(source_kind IN ('bootstrap','spend')),
                    source_id BLOB NOT NULL,
                    state_version INTEGER NOT NULL CHECK(state_version>=0),
                    PRIMARY KEY(namespace_id,commitment),
                    UNIQUE(namespace_id,commitment_index)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS v3_spent_nullifiers (
                    namespace_id BLOB NOT NULL CHECK(length(namespace_id)=48),
                    nullifier BLOB NOT NULL CHECK(length(nullifier)=48),
                    transaction_digest BLOB NOT NULL CHECK(length(transaction_digest)=64),
                    transaction_fields BLOB NOT NULL,
                    proof_anchor_version INTEGER NOT NULL CHECK(proof_anchor_version>=0),
                    proof_root BLOB NOT NULL CHECK(length(proof_root)=48),
                    proof_head BLOB NOT NULL CHECK(length(proof_head)=48),
                    commit_root_before BLOB NOT NULL CHECK(length(commit_root_before)=48),
                    state_head_before BLOB NOT NULL CHECK(length(state_head_before)=48),
                    commit_root_after BLOB NOT NULL CHECK(length(commit_root_after)=48),
                    state_head_after BLOB NOT NULL CHECK(length(state_head_after)=48),
                    first_output_index INTEGER NOT NULL CHECK(first_output_index>=0),
                    output_commitment BLOB NOT NULL CHECK(length(output_commitment)=48),
                    proof_fingerprint BLOB NOT NULL CHECK(length(proof_fingerprint)=48),
                    state_version INTEGER NOT NULL UNIQUE CHECK(state_version>0),
                    PRIMARY KEY(namespace_id,nullifier),
                    FOREIGN KEY(namespace_id,output_commitment)
                        REFERENCES v3_commitments(namespace_id,commitment)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS v3_ledger_events (
                    state_version INTEGER PRIMARY KEY CHECK(state_version>0),
                    nullifier BLOB NOT NULL UNIQUE CHECK(length(nullifier)=48),
                    event_payload BLOB NOT NULL,
                    event_digest BLOB NOT NULL CHECK(length(event_digest)=48),
                    previous_head BLOB NOT NULL CHECK(length(previous_head)=48),
                    new_head BLOB NOT NULL CHECK(length(new_head)=48)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS v3_merkle_nodes (
                    level INTEGER NOT NULL CHECK(level>=0 AND level<=63),
                    node_index INTEGER NOT NULL CHECK(node_index>=0),
                    node_hash BLOB NOT NULL CHECK(length(node_hash)=48),
                    PRIMARY KEY(level,node_index)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS v3_commitment_anchors (
                    state_version INTEGER PRIMARY KEY CHECK(state_version>=0),
                    commitment_root BLOB NOT NULL CHECK(length(commitment_root)=48),
                    state_head BLOB NOT NULL CHECK(length(state_head)=48),
                    commitment_count INTEGER NOT NULL CHECK(commitment_count>=0),
                    UNIQUE(commitment_root,state_head)
                )"""
            )
            row = conn.execute(
                "SELECT schema_version, namespace_id, params_id, policy_id, profile_id "
                "FROM v3_ledger_meta WHERE singleton=1"
            ).fetchone()
            if row is not None:
                expected = (
                    _SCHEMA_VERSION,
                    self._namespace.data,
                    self._params_id,
                    self._policy_id,
                    self._profile_id,
                )
                if tuple(row) != expected:
                    raise SQLiteV3ConfigurationMismatch(
                        "existing candidate ledger uses another namespace/params/policy/profile"
                    )
                return

            if bootstrap_commitments is None:
                raise SQLiteV3CandidateLedgerError(
                    "new candidate ledger requires the complete commitment list for its authenticated bootstrap snapshot"
                )
            snapshot = self._verify_external_bootstrap(bootstrap_evidence)
            if snapshot.namespace_id != self._namespace or snapshot.params_id != self._params_id:
                raise SQLiteV3ConfigurationMismatch("bootstrap snapshot namespace/params do not match ledger configuration")
            normalized: list[bytes] = []
            for index, commitment in enumerate(bootstrap_commitments):
                normalized.append(_require_bytes(f"bootstrap commitment {index}", commitment, HASH_BYTES, HASH_BYTES))
            if len(set(normalized)) != len(normalized):
                raise SQLiteV3DuplicateCommitment("bootstrap snapshot repeats a commitment")
            if len(normalized) >= MAX_LEAVES:
                raise SQLiteV3CandidateLedgerError("bootstrap commitment count exceeds tree capacity")
            tree = CommitmentTree(self._namespace, normalized)
            if tree.root != snapshot.commitment_root:
                raise SQLiteV3LedgerIntegrityError("bootstrap commitment list does not reconstruct the authenticated root")
            ledger_id = secrets.token_bytes(LEDGER_ID_BYTES)
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """INSERT INTO v3_ledger_meta(
                        singleton,schema_version,namespace_id,params_id,policy_id,profile_id,ledger_id,
                        bootstrap_source_id,bootstrap_finalized_anchor,bootstrap_evidence,
                        bootstrap_root,bootstrap_head,bootstrap_count,state_version,state_head,
                        commitment_count,commitment_root
                    ) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                    (
                        _SCHEMA_VERSION,
                        self._namespace.data,
                        self._params_id,
                        self._policy_id,
                        self._profile_id,
                        ledger_id,
                        bootstrap_evidence.source_id,
                        bootstrap_evidence.finalized_anchor,
                        bootstrap_evidence.evidence,
                        snapshot.commitment_root,
                        snapshot.ledger_state_head,
                        len(normalized),
                        snapshot.ledger_state_head,
                        len(normalized),
                        snapshot.commitment_root,
                    ),
                )
                for index, commitment in enumerate(normalized):
                    current_root = self._append_commitment(
                        conn,
                        commitment,
                        index,
                        0,
                        "bootstrap",
                        bootstrap_evidence.finalized_anchor,
                    )
                    # _append_commitment returns the intermediate root after this leaf;
                    # the final leaf must reconstruct the independently authenticated root.
                    if index + 1 == len(normalized) and current_root != snapshot.commitment_root:
                        raise SQLiteV3LedgerIntegrityError("persisted bootstrap Merkle root mismatch")
                if not normalized and self._defaults[TREE_DEPTH] != snapshot.commitment_root:
                    raise SQLiteV3LedgerIntegrityError("empty bootstrap root does not match authenticated root")
                conn.execute(
                    "INSERT INTO v3_commitment_anchors(state_version,commitment_root,state_head,commitment_count) VALUES(0,?,?,?)",
                    (snapshot.commitment_root, snapshot.ledger_state_head, len(normalized)),
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def _verify_external_bootstrap(self, evidence: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        try:
            snapshot = self._verify_bootstrap_state(evidence)
        except Exception as exc:
            raise SQLiteV3LedgerIntegrityError("bootstrap evidence verifier failed closed") from exc
        if not isinstance(snapshot, VerifiedStateSnapshotV3):
            raise SQLiteV3LedgerIntegrityError("bootstrap evidence verifier returned no canonical verified snapshot")
        if snapshot.source_id != evidence.source_id or snapshot.finalized_anchor != evidence.finalized_anchor:
            raise SQLiteV3LedgerIntegrityError("bootstrap snapshot did not bind the exact source/finalized anchor")
        return snapshot

    def _reauthenticate_bootstrap(self) -> None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT bootstrap_source_id,bootstrap_finalized_anchor,bootstrap_evidence,"
                "bootstrap_root,bootstrap_head,bootstrap_count,namespace_id,params_id FROM v3_ledger_meta WHERE singleton=1"
            ).fetchone()
        if row is None:
            raise SQLiteV3LedgerIntegrityError("candidate ledger metadata row is missing")
        source_id, finalized_anchor, evidence_bytes, root, head, count, ns, params = row
        try:
            evidence = StateAnchorEvidenceV3(bytes(source_id), bytes(finalized_anchor), bytes(evidence_bytes))
        except Exception as exc:
            raise SQLiteV3LedgerIntegrityError("stored bootstrap evidence is malformed") from exc
        snapshot = self._verify_external_bootstrap(evidence)
        if (
            snapshot.namespace_id.data != bytes(ns)
            or snapshot.params_id != bytes(params)
            or snapshot.commitment_root != bytes(root)
            or snapshot.ledger_state_head != bytes(head)
            or int(count) < 0
        ):
            raise SQLiteV3LedgerIntegrityError("persisted bootstrap checkpoint no longer matches independently verified evidence")

    @property
    def namespace_id(self) -> NamespaceIdV3:
        return self._namespace

    @property
    def policy_id(self) -> bytes:
        return self._policy_id

    @property
    def anchor_window(self) -> int:
        return self._anchor_window

    @property
    def finality_policy_id(self) -> bytes:
        """Return the pinned local non-final candidate policy label."""
        return LOCAL_FINALITY_POLICY_ID

    def _meta(self, conn: sqlite3.Connection) -> tuple[int, bytes, int, bytes]:
        row = conn.execute(
            "SELECT state_version,state_head,commitment_count,commitment_root "
            "FROM v3_ledger_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise SQLiteV3LedgerIntegrityError("candidate ledger metadata row is missing")
        return int(row[0]), bytes(row[1]), int(row[2]), bytes(row[3])

    def snapshot(self) -> SQLiteV3CandidateSnapshot:
        with closing(self._connect()) as conn:
            version, head, count, root = self._meta(conn)
        return SQLiteV3CandidateSnapshot(self._namespace, version, head, count, root)

    def _ledger_id(self, conn: sqlite3.Connection) -> bytes:
        row = conn.execute("SELECT ledger_id FROM v3_ledger_meta WHERE singleton=1").fetchone()
        if row is None:
            raise SQLiteV3LedgerIntegrityError("candidate ledger metadata row is missing")
        return bytes(row[0])

    def state_evidence_for_version(self, state_version: int) -> StateAnchorEvidenceV3:
        if isinstance(state_version, bool) or not isinstance(state_version, int) or state_version < 0:
            raise SQLiteV3CandidateLedgerError("state_version must be a non-negative integer")
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT commitment_root,state_head,commitment_count FROM v3_commitment_anchors WHERE state_version=?",
                (state_version,),
            ).fetchone()
            if row is None:
                raise SQLiteV3StaleLedgerState("requested candidate state anchor is not retained")
            ledger_id = self._ledger_id(conn)
        root, head, count = bytes(row[0]), bytes(row[1]), int(row[2])
        anchor_payload = _anchor_payload(state_version, root, head, count)
        return StateAnchorEvidenceV3(
            source_id=_state_source_id(ledger_id),
            finalized_anchor=anchor_payload,
            evidence=_local_evidence_payload(ledger_id, anchor_payload),
        )

    def _evidence_for_transaction(self, statement: TxFieldsV3Candidate) -> tuple[StateAnchorEvidenceV3, int]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT state_version,commitment_count FROM v3_commitment_anchors "
                "WHERE commitment_root=? AND state_head=?",
                (statement.commitment_root, statement.ledger_state_head),
            ).fetchall()
            if len(rows) != 1:
                raise SQLiteV3StaleLedgerState(
                    "transaction root/head is not one unique retained candidate ledger anchor"
                )
            version = int(rows[0][0])
        return self.state_evidence_for_version(version), version

    def _verify_local_anchor(self, evidence: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        if not isinstance(evidence, StateAnchorEvidenceV3):
            raise TrustedStateRejected("local state evidence must be StateAnchorEvidenceV3")
        with closing(self._connect()) as conn:
            ledger_id = self._ledger_id(conn)
            source_id = _state_source_id(ledger_id)
            if evidence.source_id != source_id:
                raise TrustedStateRejected("local state evidence belongs to another ledger instance")
            expected_evidence_prefix = _LOCAL_EVIDENCE_DOMAIN + ledger_id
            if not evidence.evidence.startswith(expected_evidence_prefix):
                raise TrustedStateRejected("local state evidence domain/ledger ID mismatch")
            anchor_payload = evidence.finalized_anchor
            if evidence.evidence != _local_evidence_payload(ledger_id, anchor_payload):
                raise TrustedStateRejected("local state evidence does not bind the exact anchor payload")
            if len(anchor_payload) != 8 + HASH_BYTES + HASH_BYTES + 8:
                raise TrustedStateRejected("local state anchor payload has an invalid length")
            version = int.from_bytes(anchor_payload[:8], "big")
            root = anchor_payload[8:8 + HASH_BYTES]
            head = anchor_payload[8 + HASH_BYTES:8 + 2 * HASH_BYTES]
            count = int.from_bytes(anchor_payload[-8:], "big")
            row = conn.execute(
                "SELECT commitment_root,state_head,commitment_count FROM v3_commitment_anchors WHERE state_version=?",
                (version,),
            ).fetchone()
            if row is None:
                raise TrustedStateRejected("local state anchor expired or was not found")
            if (bytes(row[0]), bytes(row[1]), int(row[2])) != (root, head, count):
                raise TrustedStateRejected("local state anchor does not match the persisted snapshot")
            meta = conn.execute(
                "SELECT namespace_id,params_id FROM v3_ledger_meta WHERE singleton=1"
            ).fetchone()
            if meta is None:
                raise TrustedStateRejected("candidate ledger metadata row is missing")
            return VerifiedStateSnapshotV3(
                source_id=source_id,
                finalized_anchor=anchor_payload,
                finality_policy_id=LOCAL_FINALITY_POLICY_ID,
                namespace_id=NamespaceIdV3(bytes(meta[0])),
                params_id=bytes(meta[1]),
                commitment_root=root,
                ledger_state_head=head,
            )

    def _node(self, conn: sqlite3.Connection, level: int, index: int) -> bytes:
        row = conn.execute(
            "SELECT node_hash FROM v3_merkle_nodes WHERE level=? AND node_index=?",
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
        _require_bytes("commitment", commitment, HASH_BYTES, HASH_BYTES)
        if index < 0 or index >= MAX_LEAVES or index > SQLITE_INDEX_MAX:
            raise SQLiteV3CandidateLedgerError("commitment tree index space exhausted")
        conn.execute(
            "INSERT INTO v3_commitments(namespace_id,commitment,commitment_index,source_kind,source_id,state_version) "
            "VALUES(?,?,?,?,?,?)",
            (self._namespace.data, commitment, index, source_kind, source_id, state_version),
        )
        current = leaf_hash(self._namespace, index, commitment)
        conn.execute(
            "INSERT INTO v3_merkle_nodes(level,node_index,node_hash) VALUES(0,?,?) "
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
                "INSERT INTO v3_merkle_nodes(level,node_index,node_hash) VALUES(?,?,?) "
                "ON CONFLICT(level,node_index) DO UPDATE SET node_hash=excluded.node_hash",
                (level + 1, cursor, current),
            )
        return current

    def accept_spend(
        self,
        statement_or_encoded: TxFieldsV3Candidate | bytes,
        *,
        proof: bytes,
    ) -> SQLiteV3AcceptedSpend:
        if isinstance(statement_or_encoded, TxFieldsV3Candidate):
            statement = statement_or_encoded
        elif isinstance(statement_or_encoded, bytes):
            try:
                statement = decode_tx_fields_v3_candidate(statement_or_encoded)
            except (TypeError, ValueError) as exc:
                raise SQLiteV3CandidateLedgerError("transaction fields are not a canonical V3 candidate encoding") from exc
        else:
            raise SQLiteV3CandidateLedgerError("transaction must be typed V3 fields or canonical bytes")
        try:
            validate_nk_possession_policy_v3_candidate(statement)
        except (TypeError, ValueError) as exc:
            raise SQLiteV3CandidateLedgerError("transaction does not select the pinned NK-possession policy") from exc
        if statement.namespace_id != self._namespace:
            raise SQLiteV3ConfigurationMismatch("transaction namespace differs from the ledger namespace")
        if statement.params_id != self._params_id:
            raise SQLiteV3ConfigurationMismatch("transaction params ID differs from the pinned parameters")
        if len(statement.output_commitments) != 1:
            raise SQLiteV3CandidateLedgerError("this SQLite candidate ledger accepts exactly one output")
        _require_bytes("proof", proof, 1, MAX_PROOF_BYTES)
        try:
            evidence, proof_anchor_version = self._evidence_for_transaction(statement)
            binding = validate_transaction_state_binding_v3(
                statement,
                evidence,
                self._verify_local_anchor,
            )
        except (SQLiteV3CandidateLedgerError, TrustedStateRejected):
            raise
        except Exception as exc:
            raise SQLiteV3LedgerIntegrityError("candidate state-binding preflight failed closed") from exc

        try:
            if self._verify_spend_proof(binding.statement, proof) is not True:
                raise SQLiteV3ProofRejected("candidate V3 spend proof rejected")
        except SQLiteV3ProofRejected:
            raise
        except Exception as exc:
            raise SQLiteV3ProofRejected("candidate V3 proof verifier failed closed") from exc

        nullifier = statement.input_nullifier.value
        output_commitment = statement.output_commitments[0].value
        tx_fields = statement.encode()
        tx_digest = binding.transaction_digest
        proof_fingerprint = _shake384(b"0PSP-V3-CANDIDATE-PROOF-FINGERPRINT-v1" + proof)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            anchor = conn.execute(
                "SELECT commitment_root,state_head,commitment_count FROM v3_commitment_anchors WHERE state_version=?",
                (proof_anchor_version,),
            ).fetchone()
            if anchor is None or (bytes(anchor[0]), bytes(anchor[1])) != (
                statement.commitment_root, statement.ledger_state_head
            ):
                raise SQLiteV3StaleLedgerState("proof anchor expired while the proof was being verified")
            version, previous_head, count, current_root = self._meta(conn)
            if version >= SQLITE_INDEX_MAX or count >= MAX_LEAVES:
                raise SQLiteV3CandidateLedgerError("candidate ledger state/index space exhausted")
            if conn.execute(
                "SELECT 1 FROM v3_spent_nullifiers WHERE namespace_id=? AND nullifier=?",
                (self._namespace.data, nullifier),
            ).fetchone():
                raise SQLiteV3DuplicateNullifier("candidate V3 nullifier has already been accepted")
            if conn.execute(
                "SELECT 1 FROM v3_commitments WHERE namespace_id=? AND commitment=?",
                (self._namespace.data, output_commitment),
            ).fetchone():
                raise SQLiteV3DuplicateCommitment("candidate V3 output commitment already exists")
            next_version = version + 1
            first_output_index = count
            new_root = self._append_commitment(
                conn,
                output_commitment,
                first_output_index,
                next_version,
                "spend",
                nullifier,
            )
            payload = _event_payload(
                self._namespace,
                nullifier,
                tx_digest,
                tx_fields,
                current_root,
                previous_head,
                proof_anchor_version,
                first_output_index,
                output_commitment,
                proof_fingerprint,
            )
            digest = _event_digest(payload)
            new_head = _next_head(next_version, previous_head, digest)
            conn.execute(
                """INSERT INTO v3_spent_nullifiers(
                    namespace_id,nullifier,transaction_digest,transaction_fields,
                    proof_anchor_version,proof_root,proof_head,
                    commit_root_before,state_head_before,commit_root_after,state_head_after,
                    first_output_index,output_commitment,proof_fingerprint,state_version
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    self._namespace.data,
                    nullifier,
                    tx_digest,
                    tx_fields,
                    proof_anchor_version,
                    statement.commitment_root,
                    statement.ledger_state_head,
                    current_root,
                    previous_head,
                    new_root,
                    new_head,
                    first_output_index,
                    output_commitment,
                    proof_fingerprint,
                    next_version,
                ),
            )
            conn.execute(
                "INSERT INTO v3_ledger_events(state_version,nullifier,event_payload,event_digest,previous_head,new_head) "
                "VALUES(?,?,?,?,?,?)",
                (next_version, nullifier, payload, digest, previous_head, new_head),
            )
            conn.execute(
                "UPDATE v3_ledger_meta SET state_version=?,state_head=?,commitment_count=?,commitment_root=? WHERE singleton=1",
                (next_version, new_head, count + 1, new_root),
            )
            conn.execute(
                "INSERT INTO v3_commitment_anchors(state_version,commitment_root,state_head,commitment_count) VALUES(?,?,?,?)",
                (next_version, new_root, new_head, count + 1),
            )
            min_version = max(0, next_version - self._anchor_window + 1)
            conn.execute(
                "DELETE FROM v3_commitment_anchors WHERE state_version < ?",
                (min_version,),
            )
            conn.execute("COMMIT")
            return SQLiteV3AcceptedSpend(
                namespace_id=self._namespace,
                nullifier=nullifier,
                transaction_digest=tx_digest,
                transaction_fields=tx_fields,
                output_commitment=output_commitment,
                proof_anchor_version=proof_anchor_version,
                first_output_index=first_output_index,
                state_version=next_version,
                state_head_after=new_head,
                commitment_root_after=new_root,
            )
        except sqlite3.IntegrityError as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            text = str(exc).lower()
            if "nullifier" in text:
                raise SQLiteV3DuplicateNullifier("database rejected a duplicate candidate nullifier") from None
            if "commitment" in text:
                raise SQLiteV3DuplicateCommitment("database rejected a duplicate candidate output commitment") from None
            raise SQLiteV3CandidateLedgerError("database uniqueness constraint rejected the spend") from None
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def membership_path(self, commitment: bytes) -> tuple[int, tuple[bytes, ...]]:
        _require_bytes("commitment", commitment, HASH_BYTES, HASH_BYTES)
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT commitment_index FROM v3_commitments WHERE namespace_id=? AND commitment=?",
                (self._namespace.data, commitment),
            ).fetchone()
            if row is None:
                raise KeyError("candidate commitment is not registered")
            index = int(row[0])
            siblings: list[bytes] = []
            cursor = index
            for level in range(TREE_DEPTH):
                siblings.append(self._node(conn, level, cursor ^ 1))
                cursor >>= 1
            return index, tuple(siblings)

    def contains_commitment(self, commitment: bytes) -> bool:
        with closing(self._connect()) as conn:
            return conn.execute(
                "SELECT 1 FROM v3_commitments WHERE namespace_id=? AND commitment=?",
                (self._namespace.data, commitment),
            ).fetchone() is not None

    def is_nullifier_spent(self, nullifier: bytes) -> bool:
        with closing(self._connect()) as conn:
            return conn.execute(
                "SELECT 1 FROM v3_spent_nullifiers WHERE namespace_id=? AND nullifier=?",
                (self._namespace.data, nullifier),
            ).fetchone() is not None

    def audit_integrity(self) -> None:
        """Rebuild the complete local tree/event chain and check the retained anchors."""
        with closing(self._connect()) as conn:
            conn.execute("BEGIN")
            meta = conn.execute(
                """SELECT schema_version,namespace_id,params_id,policy_id,profile_id,
                          bootstrap_root,bootstrap_head,bootstrap_count,state_version,state_head,
                          commitment_count,commitment_root,bootstrap_finalized_anchor
                   FROM v3_ledger_meta WHERE singleton=1"""
            ).fetchone()
            if meta is None:
                raise SQLiteV3LedgerIntegrityError("candidate ledger metadata is missing")
            expected_prefix = (
                _SCHEMA_VERSION, self._namespace.data, self._params_id, self._policy_id, self._profile_id
            )
            if tuple(meta[:5]) != expected_prefix:
                raise SQLiteV3ConfigurationMismatch("candidate ledger configuration changed")
            bootstrap_root, bootstrap_head, bootstrap_count = bytes(meta[5]), bytes(meta[6]), int(meta[7])
            state_version, state_head, commitment_count, commitment_root = int(meta[8]), bytes(meta[9]), int(meta[10]), bytes(meta[11])
            bootstrap_finalized_anchor = bytes(meta[12])
            bootstrap_rows = conn.execute(
                "SELECT commitment,commitment_index FROM v3_commitments WHERE source_kind='bootstrap' ORDER BY commitment_index"
            ).fetchall()
            bootstrap_commitments = [bytes(row[0]) for row in bootstrap_rows]
            if [int(row[1]) for row in bootstrap_rows] != list(range(bootstrap_count)):
                raise SQLiteV3LedgerIntegrityError("bootstrap commitment indices are not canonical")
            if len(bootstrap_commitments) != bootstrap_count:
                raise SQLiteV3LedgerIntegrityError("bootstrap commitment count mismatches metadata")
            tree = CommitmentTree(self._namespace, bootstrap_commitments)
            if tree.root != bootstrap_root:
                raise SQLiteV3LedgerIntegrityError("bootstrap commitment list does not reconstruct the bootstrap root")

            snapshots: dict[int, tuple[bytes, bytes, int]] = {
                0: (bootstrap_root, bootstrap_head, bootstrap_count)
            }
            current_root, current_head, current_count = bootstrap_root, bootstrap_head, bootstrap_count
            current_version = 0
            events = conn.execute(
                "SELECT state_version,nullifier,event_payload,event_digest,previous_head,new_head "
                "FROM v3_ledger_events ORDER BY state_version"
            ).fetchall()
            orphan_spend = conn.execute(
                """SELECT 1
                   FROM v3_spent_nullifiers AS s
                   LEFT JOIN v3_ledger_events AS e
                     ON e.state_version=s.state_version AND e.nullifier=s.nullifier
                   WHERE e.state_version IS NULL
                   LIMIT 1"""
            ).fetchone()
            if orphan_spend is not None:
                raise SQLiteV3LedgerIntegrityError(
                    "V3 spent-nullifier record has no matching ledger event"
                )
            for event in events:
                event_version, event_nullifier, payload, event_digest, previous_head, new_head = event
                event_version = int(event_version)
                event_nullifier, payload, event_digest = bytes(event_nullifier), bytes(payload), bytes(event_digest)
                previous_head, new_head = bytes(previous_head), bytes(new_head)
                if event_version != current_version + 1 or previous_head != current_head:
                    raise SQLiteV3LedgerIntegrityError("V3 candidate event sequence or previous head is discontinuous")
                digest = _event_digest(payload)
                if digest != event_digest:
                    raise SQLiteV3LedgerIntegrityError("V3 candidate event digest mismatch")
                expected_head = _next_head(event_version, current_head, digest)
                if expected_head != new_head:
                    raise SQLiteV3LedgerIntegrityError("V3 candidate event head mismatch")
                spend = conn.execute(
                    """SELECT transaction_digest,transaction_fields,proof_anchor_version,proof_root,proof_head,
                              commit_root_before,state_head_before,commit_root_after,state_head_after,
                              first_output_index,output_commitment,proof_fingerprint
                       FROM v3_spent_nullifiers WHERE namespace_id=? AND nullifier=? AND state_version=?""",
                    (self._namespace.data, event_nullifier, event_version),
                ).fetchone()
                if spend is None:
                    raise SQLiteV3LedgerIntegrityError("V3 candidate event has no matching spent-nullifier record")
                (
                    tx_digest, tx_fields, proof_anchor_version, proof_root, proof_head,
                    root_before, head_before, root_after, head_after, first_index, output, proof_fp,
                ) = spend
                tx_digest, tx_fields = bytes(tx_digest), bytes(tx_fields)
                try:
                    statement = decode_tx_fields_v3_candidate(tx_fields)
                except Exception as exc:
                    raise SQLiteV3LedgerIntegrityError("persisted V3 candidate transaction is noncanonical") from exc
                if (
                    statement.namespace_id != self._namespace
                    or statement.params_id != self._params_id
                    or statement.authorization_policy_id != self._policy_id
                    or transaction_digest_v3_candidate(statement) != tx_digest
                    or statement.input_nullifier.value != event_nullifier
                    or len(statement.output_commitments) != 1
                    or statement.output_commitments[0].value != bytes(output)
                ):
                    raise SQLiteV3LedgerIntegrityError("persisted V3 transaction does not match spent/output record")
                anchor = snapshots.get(int(proof_anchor_version))
                if anchor is None or anchor != (bytes(proof_root), bytes(proof_head), anchor[2]):
                    raise SQLiteV3LedgerIntegrityError("spent record references a nonexistent historical root/head")
                if (bytes(root_before), bytes(head_before)) != (current_root, current_head):
                    raise SQLiteV3LedgerIntegrityError("V3 spend event current-state predecessor mismatch")
                if int(first_index) != current_count:
                    raise SQLiteV3LedgerIntegrityError("V3 output index is not append-only")
                tree.append(bytes(output))
                new_root = tree.root
                if tree.count != current_count + 1:
                    raise SQLiteV3LedgerIntegrityError("V3 output append/count mismatch")
                if (bytes(root_after), bytes(head_after)) != (new_root, new_head):
                    raise SQLiteV3LedgerIntegrityError(
                        "persisted V3 spend record post-state root/head mismatch"
                    )
                if (
                    statement.commitment_root != bytes(proof_root)
                    or statement.ledger_state_head != bytes(proof_head)
                ):
                    raise SQLiteV3LedgerIntegrityError(
                        "persisted V3 transaction root/head do not match its recorded proof anchor"
                    )
                # Recompute the event payload from the stored typed records, not from a supplied digest.
                expected_payload = _event_payload(
                    self._namespace,
                    event_nullifier,
                    tx_digest,
                    tx_fields,
                    current_root,
                    current_head,
                    int(proof_anchor_version),
                    int(first_index),
                    bytes(output),
                    bytes(proof_fp),
                )
                if expected_payload != payload:
                    raise SQLiteV3LedgerIntegrityError("V3 ledger event payload mismatch")
                current_version = event_version
                current_root = new_root
                current_head = new_head
                current_count += 1
                snapshots[current_version] = (current_root, current_head, current_count)

            if (current_version, current_head, current_count, current_root) != (
                state_version, state_head, commitment_count, commitment_root
            ):
                raise SQLiteV3LedgerIntegrityError("V3 candidate ledger metadata does not match rebuilt state")
            all_commitments = conn.execute(
                "SELECT commitment_index,commitment,source_kind,source_id,state_version "
                "FROM v3_commitments ORDER BY commitment_index"
            ).fetchall()
            if [int(row[0]) for row in all_commitments] != list(range(commitment_count)):
                raise SQLiteV3LedgerIntegrityError("candidate commitment indices are not contiguous")
            if [bytes(row[1]) for row in all_commitments] != [tree.commitment_at(i) for i in range(tree.count)]:
                raise SQLiteV3LedgerIntegrityError("candidate commitment table disagrees with rebuilt tree")
            expected_commitment_sources = [
                ("bootstrap", bootstrap_finalized_anchor, 0)
                for _ in range(bootstrap_count)
            ]
            expected_commitment_sources.extend(
                ("spend", bytes(event[1]), int(event[0]))
                for event in events
            )
            actual_commitment_sources = [
                (str(row[2]), bytes(row[3]), int(row[4]))
                for row in all_commitments
            ]
            if actual_commitment_sources != expected_commitment_sources:
                raise SQLiteV3LedgerIntegrityError(
                    "candidate commitment source metadata disagrees with bootstrap/event history"
                )
            actual_nodes = {
                (int(level), int(index), bytes(value))
                for level, index, value in conn.execute(
                    "SELECT level,node_index,node_hash FROM v3_merkle_nodes"
                ).fetchall()
            }
            expected_nodes = {
                (level, index, value)
                for level, level_nodes in enumerate(tree._levels)
                for index, value in level_nodes.items()
            }
            if actual_nodes != expected_nodes:
                raise SQLiteV3LedgerIntegrityError("candidate persisted Merkle nodes disagree with rebuilt tree")
            min_version = max(0, current_version - self._anchor_window + 1)
            retained_versions = set(range(min_version, current_version + 1))
            actual_anchors = {
                int(version): (bytes(root), bytes(head), int(count))
                for version, root, head, count in conn.execute(
                    "SELECT state_version,commitment_root,state_head,commitment_count FROM v3_commitment_anchors"
                ).fetchall()
            }
            expected_anchors = {v: snapshots[v] for v in retained_versions}
            if actual_anchors != expected_anchors:
                raise SQLiteV3LedgerIntegrityError("retained candidate anchor window mismatches event history")
            conn.execute("COMMIT")


__all__ = [
    "SQLiteV3CandidateLedger",
    "SQLiteV3CandidateSnapshot",
    "SQLiteV3AcceptedSpend",
    "SQLiteV3CandidateLedgerError",
    "SQLiteV3StaleLedgerState",
    "SQLiteV3DuplicateNullifier",
    "SQLiteV3DuplicateCommitment",
    "SQLiteV3ProofRejected",
    "SQLiteV3LedgerIntegrityError",
    "SQLiteV3ConfigurationMismatch",
]
