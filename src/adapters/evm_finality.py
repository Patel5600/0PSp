"""SQLite-backed, fail-closed journal for quorum-observed EVM finalized headers.

This persists a pinned checkpoint and checks the complete parent-hash chain from
that checkpoint to the provider quorum's finalized head. It detects observed
finality regressions and reorgs that conflict with the journal. It does not
cryptographically verify consensus and is not a light client or deposit verifier.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from src.primitives.namespace_v3 import NamespaceIdV3

_U64_MAX = (1 << 64) - 1
_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\\Z")
_DATA_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*\\Z")


class EvmFinalityError(RuntimeError):
    """Finality evidence is missing, invalid, inconsistent, or rolled back."""


class FinalityCatchupRequired(EvmFinalityError):
    """The pinned checkpoint is too far behind for the configured bounded sync."""


class ReadOnlyEvmRpc(Protocol):
    def call(self, method: str, params: list[object]) -> object:
        """Perform a read-only JSON-RPC call."""


@dataclass(frozen=True, slots=True)
class FinalizedHeader:
    number: int
    block_hash: bytes
    parent_hash: bytes | None


@dataclass(frozen=True, slots=True)
class FinalitySnapshot:
    chain_id: int
    namespace_id: NamespaceIdV3
    checkpoint_number: int
    stored_finalized_number: int
    stored_finalized_hash: bytes
    observed_finalized_number: int
    observed_finalized_hash: bytes
    caught_up: bool


def _parse_quantity(value: object, field: str) -> int:
    if not isinstance(value, str) or _QUANTITY_RE.fullmatch(value) is None:
        raise EvmFinalityError(f"{field} is not a canonical JSON-RPC QUANTITY")
    parsed = int(value[2:], 16)
    if parsed > _U64_MAX:
        raise EvmFinalityError(f"{field} exceeds this journal's uint64 height limit")
    return parsed


def _parse_data(value: object, field: str, expected_length: int) -> bytes:
    if not isinstance(value, str) or _DATA_RE.fullmatch(value) is None:
        raise EvmFinalityError(f"{field} is not canonical JSON-RPC DATA")
    raw = bytes.fromhex(value[2:])
    if len(raw) != expected_length:
        raise EvmFinalityError(f"{field} must be exactly {expected_length} bytes")
    return raw


def _read_header(rpc: ReadOnlyEvmRpc, block_tag: str) -> FinalizedHeader:
    try:
        result = rpc.call("eth_getBlockByNumber", [block_tag, False])
    except Exception:
        raise EvmFinalityError("could not obtain the required EVM block header") from None
    if not isinstance(result, dict):
        raise EvmFinalityError("EVM provider quorum returned no block header")
    number = _parse_quantity(result.get("number"), f"block {block_tag}.number")
    block_hash = _parse_data(result.get("hash"), f"block {block_tag}.hash", 32)
    if number == 0:
        parent_hash = None
    else:
        parent_hash = _parse_data(result.get("parentHash"), f"block {block_tag}.parentHash", 32)
    return FinalizedHeader(number, block_hash, parent_hash)


def _quantity_tag(number: int) -> str:
    return hex(number)


class SqliteEvmFinalityJournal:
    """Durably pin one Namespace V3 deployment to a finalized EVM header chain.

    The database is deliberately file-backed; ':memory:' is rejected because
    it would silently discard the recovery/reorg evidence when a connection closes.
    The checkpoint is a trust anchor sourced out-of-band. RPC finality tags are
    corroborated only when `rpc` is a configured quorum transport. Neither alone
    establishes cryptographic consensus verification.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        chain_id: int,
        genesis_hash: bytes,
        checkpoint_block_number: int,
        checkpoint_hash: bytes,
        namespace_id: NamespaceIdV3,
    ) -> None:
        if not isinstance(database_path, (str, Path)) or not str(database_path).strip():
            raise ValueError("database_path must be a non-empty filesystem path")
        if str(database_path) == ":memory:":
            raise ValueError("a file-backed SQLite path is required for durable finality state")
        if isinstance(chain_id, bool) or not isinstance(chain_id, int) or not 1 <= chain_id < (1 << 256):
            raise ValueError("chain_id must be an integer in [1, 2^256-1]")
        if not isinstance(genesis_hash, bytes) or len(genesis_hash) != 32:
            raise ValueError("genesis_hash must be exactly 32 bytes")
        if (
            isinstance(checkpoint_block_number, bool)
            or not isinstance(checkpoint_block_number, int)
            or not 0 <= checkpoint_block_number <= _U64_MAX
        ):
            raise ValueError("checkpoint_block_number must be uint64")
        if not isinstance(checkpoint_hash, bytes) or len(checkpoint_hash) != 32:
            raise ValueError("checkpoint_hash must be exactly 32 bytes")
        if checkpoint_block_number == 0 and checkpoint_hash != genesis_hash:
            raise ValueError("genesis checkpoint hash must equal genesis_hash")
        if not isinstance(namespace_id, NamespaceIdV3):
            raise TypeError("namespace_id must be NamespaceIdV3")
        self._path = str(database_path)
        self.chain_id = chain_id
        self.genesis_hash = genesis_hash
        self.checkpoint_block_number = checkpoint_block_number
        self.checkpoint_hash = checkpoint_hash
        self.namespace_id = namespace_id
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS namespace_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    chain_id TEXT NOT NULL,
                    genesis_hash BLOB NOT NULL CHECK (length(genesis_hash) = 32),
                    checkpoint_number INTEGER NOT NULL CHECK (checkpoint_number >= 0),
                    checkpoint_hash BLOB NOT NULL CHECK (length(checkpoint_hash) = 32),
                    namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 48)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS finalized_headers (
                    height INTEGER PRIMARY KEY CHECK (height >= 0),
                    block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
                    parent_hash BLOB,
                    CHECK (parent_hash IS NULL OR length(parent_hash) = 32)
                )"""
            )

    def _expected_metadata(self) -> tuple[object, ...]:
        return (
            str(self.chain_id),
            self.genesis_hash,
            self.checkpoint_block_number,
            self.checkpoint_hash,
            self.namespace_id.data,
        )

    def advance(self, rpc: ReadOnlyEvmRpc, *, max_headers: int = 4096) -> FinalitySnapshot:
        """Verify and persist the checkpoint-to-finalized-head hash chain atomically.

        Every header from the persisted tip to the observed finalized head is read
        and parent-linked before commit. Refuse oversized catch-up rather than
        advance a partial prefix that has not yet been linked to the finalized tag.
        """
        if not callable(getattr(rpc, "call", None)):
            raise TypeError("rpc must provide call(method, params)")
        if (
            isinstance(max_headers, bool)
            or not isinstance(max_headers, int)
            or not 1 <= max_headers <= 100_000
        ):
            raise ValueError("max_headers must be in [1, 100000]")
        try:
            observed_chain_id = _parse_quantity(rpc.call("eth_chainId", []), "eth_chainId")
        except EvmFinalityError:
            raise
        except Exception:
            raise EvmFinalityError("could not obtain the EVM chain ID") from None
        if observed_chain_id != self.chain_id:
            raise EvmFinalityError("observed EVM chain ID differs from the pinned configuration")

        genesis = _read_header(rpc, "0x0")
        if genesis.block_hash != self.genesis_hash:
            raise EvmFinalityError("observed genesis hash differs from the pinned configuration")
        checkpoint = (
            genesis
            if self.checkpoint_block_number == 0
            else _read_header(rpc, _quantity_tag(self.checkpoint_block_number))
        )
        if (
            checkpoint.number != self.checkpoint_block_number
            or checkpoint.block_hash != self.checkpoint_hash
        ):
            raise EvmFinalityError("observed checkpoint differs from the out-of-band trust anchor")
        finalized = _read_header(rpc, "finalized")
        if finalized.number < self.checkpoint_block_number:
            raise EvmFinalityError("provider-reported finalized height is below the trusted checkpoint")

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            meta = conn.execute(
                "SELECT chain_id, genesis_hash, checkpoint_number, checkpoint_hash, namespace_id "
                "FROM namespace_meta WHERE singleton = 1"
            ).fetchone()
            expected = self._expected_metadata()
            if meta is None:
                conn.execute(
                    "INSERT INTO namespace_meta "
                    "(singleton, chain_id, genesis_hash, checkpoint_number, checkpoint_hash, namespace_id) "
                    "VALUES (1, ?, ?, ?, ?, ?)",
                    expected,
                )
                conn.execute(
                    "INSERT INTO finalized_headers (height, block_hash, parent_hash) VALUES (?, ?, ?)",
                    (checkpoint.number, checkpoint.block_hash, checkpoint.parent_hash),
                )
                stored_tip = checkpoint
            else:
                if tuple(meta) != expected:
                    raise EvmFinalityError(
                        "finality database belongs to a different chain, checkpoint, or namespace"
                    )
                row = conn.execute(
                    "SELECT height, block_hash, parent_hash FROM finalized_headers ORDER BY height DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    raise EvmFinalityError("finality database has metadata but no checkpoint header")
                stored_tip = FinalizedHeader(row[0], bytes(row[1]), None if row[2] is None else bytes(row[2]))

            # A changed hash at the last durable finalized height indicates a reorg
            # or conflicting provider view. Freeze instead of silently rewinding state.
            live_tip = _read_header(rpc, _quantity_tag(stored_tip.number))
            if live_tip.block_hash != stored_tip.block_hash:
                raise EvmFinalityError(
                    "reorg/conflicting view detected at the durable finalized tip; operator recovery required"
                )
            if finalized.number < stored_tip.number:
                raise EvmFinalityError("provider-reported finalized height regressed below durable state")
            distance = finalized.number - stored_tip.number
            if distance > max_headers:
                raise FinalityCatchupRequired(
                    f"finalized catch-up requires {distance} headers; configured bound is {max_headers}"
                )
            previous = stored_tip
            for height in range(stored_tip.number + 1, finalized.number + 1):
                header = _read_header(rpc, _quantity_tag(height))
                if header.number != height:
                    raise EvmFinalityError("provider returned a header for the wrong height")
                if header.parent_hash != previous.block_hash:
                    raise EvmFinalityError(
                        f"parent hash mismatch at block {height}; refusing to persist a broken finalized chain"
                    )
                conn.execute(
                    "INSERT INTO finalized_headers (height, block_hash, parent_hash) VALUES (?, ?, ?)",
                    (header.number, header.block_hash, header.parent_hash),
                )
                previous = header
            if previous.number != finalized.number or previous.block_hash != finalized.block_hash:
                raise EvmFinalityError("numbered header chain does not terminate at the finalized tag")
            conn.execute("COMMIT")
            return FinalitySnapshot(
                chain_id=self.chain_id,
                namespace_id=self.namespace_id,
                checkpoint_number=self.checkpoint_block_number,
                stored_finalized_number=previous.number,
                stored_finalized_hash=previous.block_hash,
                observed_finalized_number=finalized.number,
                observed_finalized_hash=finalized.block_hash,
                caught_up=True,
            )
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def contains_finalized_header(self, block_number: int, block_hash: bytes) -> bool:
        """Check exact membership in the durable trusted-checkpoint ancestry."""
        if (
            isinstance(block_number, bool)
            or not isinstance(block_number, int)
            or block_number < self.checkpoint_block_number
            or block_number > _U64_MAX
            or not isinstance(block_hash, bytes)
            or len(block_hash) != 32
        ):
            return False
        with self._connect() as conn:
            row = conn.execute(
                "SELECT block_hash FROM finalized_headers WHERE height = ?",
                (block_number,),
            ).fetchone()
        return row is not None and bytes(row[0]) == block_hash
