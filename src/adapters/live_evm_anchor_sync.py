"""0PSP Live EVM Multi-RPC Finalized Anchor Synchronization Adapter.

Bridges live EVM JSON-RPC finality checkpoints and zero-dependency EIP-1186 MPT
state proofs (src/adapters/evm_state_proof.py) into the 4,096-state anchor ring
and fail-closed trusted-state verification (src/protocol/trusted_state_v3.py).

Features:
  1. Multi-RPC Quorum Consensus:
     Queries eth_getBlockByNumber("finalized", false) across M >= 3 independent RPC
     endpoints and verifies strict majority agreement on blockNumber, blockHash,
     and stateRoot before accepting an execution state root.
  2. EIP-1186 Merkle-Patricia Trie Proof Verification:
     Fetches eth_getProof for the 0PSP contract storage slots at that exact finalized
     block and verifies account + storage trie proofs against the authenticated header.
  3. 4,096-State SQLite WAL Anchor Ring Feed:
     Locks verified historical roots into the 4,096-state anchor ring and produces
     canonical StateAnchorEvidenceV3 and VerifiedStateSnapshotV3 instances for
     zero-leakage spend preflight validation.
  4. Zero External Dependencies:
     Uses Python standard library urllib.request for optional live HTTP JSON-RPC calls,
     fully compatible with offline mock/recorded fixtures.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from src.adapters.evm_state_proof import (
    EvmStateProofError,
    VerifiedEvmAccountState,
    verify_eip1186_account_proof,
)
from src.adapters.evm_trie import (
    keccak256,
    rlp_encode_bytes,
    rlp_encode_list,
    rlp_encode_uint,
)
from src.primitives.namespace_v3 import NamespaceIdV3
from src.protocol.trusted_state_v3 import (
    StateAnchorEvidenceV3,
    StateAnchorVerifierV3,
    VerifiedStateSnapshotV3,
    create_anchor_ring_state_verifier,
)

HASH_BYTES = 48
MAX_ANCHOR_RING_CAPACITY = 4096
LIVE_SOURCE_ID = b"0PSP-LIVE-EVM-FINALITY-SYNC-v1"
LIVE_FINALITY_POLICY_ID = b"0PSP-EVM-MULTI-RPC-FINALITY-QUORUM-v1"

_HEX_DATA_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_HEX_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")


class LiveEvmAnchorSyncError(ValueError):
    """Raised when live EVM RPC quorum, header parsing, or state proof verification fails."""


class RpcTransportProtocol(Protocol):
    """Protocol for an EVM JSON-RPC provider client."""
    def call(self, method: str, params: list[object]) -> object:
        """Execute JSON-RPC method with parameters."""
        ...


class HttpJsonRpcClient:
    """Zero-dependency HTTP JSON-RPC client using urllib.request."""

    def __init__(self, endpoint_url: str, *, timeout: float = 10.0) -> None:
        if not isinstance(endpoint_url, str) or not (
            endpoint_url.startswith("http://") or endpoint_url.startswith("https://")
        ):
            raise ValueError("endpoint_url must be an http:// or https:// URL")
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    def call(self, method: str, params: list[object]) -> object:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "0PSP-Live-Anchor-Sync/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise LiveEvmAnchorSyncError(f"HTTP JSON-RPC error for {method}: {exc}") from exc

        if not isinstance(data, dict):
            raise LiveEvmAnchorSyncError(f"RPC returned non-object response: {data}")
        if "error" in data:
            raise LiveEvmAnchorSyncError(f"RPC returned error: {data['error']}")
        return data.get("result")


@dataclass(frozen=True, slots=True)
class FinalizedHeaderConsensus:
    """Validated consensus on an EVM finalized block header across RPC quorum."""
    block_number: int
    block_hash: bytes
    state_root: bytes
    raw_header_rlp: bytes
    agreeing_providers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifiedLiveAnchor:
    """Result of multi-RPC finality synchronization and EIP-1186 state proof verification."""
    block_number: int
    block_hash: bytes
    state_root: bytes
    contract_address: bytes
    storage_root: bytes
    storage_values: tuple[tuple[bytes, int], ...]
    anchor_root: bytes
    ledger_state_head: bytes
    state_evidence: StateAnchorEvidenceV3
    verified_snapshot: VerifiedStateSnapshotV3


def _parse_quantity(val: object, name: str) -> int:
    if isinstance(val, int):
        return val
    if not isinstance(val, str) or _HEX_QUANTITY_RE.fullmatch(val) is None:
        raise LiveEvmAnchorSyncError(f"{name} must be canonical hex quantity")
    return int(val[2:], 16)


def _parse_data(val: object, name: str, expected_len: int | None = None) -> bytes:
    if isinstance(val, bytes):
        raw = val
    elif isinstance(val, str) and _HEX_DATA_RE.fullmatch(val) is not None:
        raw = bytes.fromhex(val[2:])
    else:
        raise LiveEvmAnchorSyncError(f"{name} must be canonical hex data")
    if expected_len is not None and len(raw) != expected_len:
        raise LiveEvmAnchorSyncError(f"{name} must be exactly {expected_len} bytes")
    return raw


def encode_execution_header_rlp(block_dict: dict[str, Any]) -> bytes:
    """Encode an execution block header dictionary into canonical RLP bytes.

    Supports pre-Shanghai (15/16 fields), post-Shanghai/Cancun (17/20 fields), and Prague (21 fields).
    """
    if not isinstance(block_dict, dict):
        raise LiveEvmAnchorSyncError("block_dict must be a dictionary")

    # If raw header RLP is directly provided (e.g., from light client or fixture)
    if "rawHeader" in block_dict:
        return _parse_data(block_dict["rawHeader"], "rawHeader")

    parent_hash = _parse_data(block_dict.get("parentHash", b"\x00" * 32), "parentHash", 32)
    sha3_uncles = _parse_data(block_dict.get("sha3Uncles", b"\x00" * 32), "sha3Uncles", 32)
    miner = _parse_data(block_dict.get("miner", b"\x00" * 20), "miner", 20)
    state_root = _parse_data(block_dict.get("stateRoot"), "stateRoot", 32)
    tx_root = _parse_data(block_dict.get("transactionsRoot", b"\x00" * 32), "transactionsRoot", 32)
    receipts_root = _parse_data(block_dict.get("receiptsRoot", b"\x00" * 32), "receiptsRoot", 32)
    logs_bloom = _parse_data(block_dict.get("logsBloom", b"\x00" * 256), "logsBloom", 256)
    difficulty = _parse_quantity(block_dict.get("difficulty", 0), "difficulty")
    number = _parse_quantity(block_dict.get("number"), "number")
    gas_limit = _parse_quantity(block_dict.get("gasLimit", 30_000_000), "gasLimit")
    gas_used = _parse_quantity(block_dict.get("gasUsed", 0), "gasUsed")
    timestamp = _parse_quantity(block_dict.get("timestamp", 0), "timestamp")
    extra_data = _parse_data(block_dict.get("extraData", b""), "extraData")
    mix_hash = _parse_data(block_dict.get("mixHash", b"\x00" * 32), "mixHash", 32)
    nonce = _parse_data(block_dict.get("nonce", b"\x00" * 8), "nonce", 8)

    fields = [
        rlp_encode_bytes(parent_hash),
        rlp_encode_bytes(sha3_uncles),
        rlp_encode_bytes(miner),
        rlp_encode_bytes(state_root),
        rlp_encode_bytes(tx_root),
        rlp_encode_bytes(receipts_root),
        rlp_encode_bytes(logs_bloom),
        rlp_encode_uint(difficulty),
        rlp_encode_uint(number),
        rlp_encode_uint(gas_limit),
        rlp_encode_uint(gas_used),
        rlp_encode_uint(timestamp),
        rlp_encode_bytes(extra_data),
        rlp_encode_bytes(mix_hash),
        rlp_encode_bytes(nonce),
    ]

    # Optional baseFeePerGas (EIP-1559)
    if "baseFeePerGas" in block_dict and block_dict["baseFeePerGas"] is not None:
        fields.append(rlp_encode_uint(_parse_quantity(block_dict["baseFeePerGas"], "baseFeePerGas")))

    # Optional withdrawalsRoot (EIP-4895)
    if "withdrawalsRoot" in block_dict and block_dict["withdrawalsRoot"] is not None:
        fields.append(rlp_encode_bytes(_parse_data(block_dict["withdrawalsRoot"], "withdrawalsRoot", 32)))

    # Optional blobGasUsed & excessBlobGas & parentBeaconBlockRoot (EIP-4844 / Cancun - 20 fields)
    has_cancun = any(
        k in block_dict and block_dict[k] is not None
        for k in ("blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot")
    )
    if has_cancun:
        blob_gas_used = _parse_quantity(block_dict.get("blobGasUsed", 0), "blobGasUsed")
        excess_blob_gas = _parse_quantity(block_dict.get("excessBlobGas", 0), "excessBlobGas")
        parent_beacon_root = _parse_data(
            block_dict.get("parentBeaconBlockRoot", b"\x00" * 32), "parentBeaconBlockRoot", 32
        )
        fields.append(rlp_encode_uint(blob_gas_used))
        fields.append(rlp_encode_uint(excess_blob_gas))
        fields.append(rlp_encode_bytes(parent_beacon_root))

    # Optional requestsHash / requestsRoot (EIP-7685 / Prague - 21 fields)
    if "requestsHash" in block_dict and block_dict["requestsHash"] is not None:
        fields.append(rlp_encode_bytes(_parse_data(block_dict["requestsHash"], "requestsHash", 32)))
    elif "requestsRoot" in block_dict and block_dict["requestsRoot"] is not None:
        fields.append(rlp_encode_bytes(_parse_data(block_dict["requestsRoot"], "requestsRoot", 32)))

    return rlp_encode_list(fields)


class LiveEvmAnchorSynchronizer:
    """Synchronizes finalized EVM chain state and verified EIP-1186 storage roots into anchor ring."""

    def __init__(
        self,
        providers: Mapping[str, RpcTransportProtocol],
        *,
        contract_address: bytes,
        storage_slots: Sequence[bytes],
        namespace_id: NamespaceIdV3,
        params_id: bytes,
        quorum: int | None = None,
        retained_capacity: int = MAX_ANCHOR_RING_CAPACITY,
        sqlite_path: str | Path | None = None,
    ) -> None:
        if not isinstance(providers, Mapping) or len(providers) < 3:
            raise LiveEvmAnchorSyncError("at least three independent RPC providers are required (M >= 3)")
        if any(
            not isinstance(name, str) or not name.strip() or not callable(getattr(p, "call", None))
            for name, p in providers.items()
        ):
            raise TypeError("providers must map non-empty names to call(method, params) transports")
        if not isinstance(contract_address, bytes) or len(contract_address) != 20:
            raise ValueError("contract_address must be 20 bytes")
        if not storage_slots or any(not isinstance(s, bytes) or len(s) != 32 for s in storage_slots):
            raise ValueError("storage_slots must be a non-empty sequence of 32-byte slots")
        if not isinstance(namespace_id, NamespaceIdV3):
            raise TypeError("namespace_id must be NamespaceIdV3")
        if not isinstance(params_id, bytes) or not 1 <= len(params_id) <= 0xFFFF:
            raise ValueError("params_id must be bytes with length in [1, 65535]")

        default_quorum = (len(providers) // 2) + 1
        req_quorum = default_quorum if quorum is None else quorum
        if req_quorum <= len(providers) // 2 or req_quorum > len(providers):
            raise ValueError(f"quorum must be a strict majority in [{(len(providers)//2)+1}, {len(providers)}]")

        self._providers = tuple(providers.items())
        self._contract_address = contract_address
        self._storage_slots = tuple(storage_slots)
        self._namespace_id = namespace_id
        self._params_id = params_id
        self._quorum = req_quorum
        self._retained_capacity = retained_capacity
        self._sqlite_path: Path | None = Path(sqlite_path) if sqlite_path is not None else None
        self._anchor_ring: list[tuple[bytes, bytes]] = []

        if self._sqlite_path is not None:
            self._init_sqlite_db()

    def _init_sqlite_db(self) -> None:
        if self._sqlite_path is None:
            return
        self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=FULL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS live_evm_anchor_ring (
                    ring_index INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_number INTEGER NOT NULL,
                    block_hash BLOB NOT NULL,
                    state_root BLOB NOT NULL,
                    anchor_root BLOB NOT NULL UNIQUE,
                    ledger_state_head BLOB NOT NULL,
                    storage_root BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anchor_root ON live_evm_anchor_ring(anchor_root);")
            rows = conn.execute(
                "SELECT anchor_root, ledger_state_head FROM live_evm_anchor_ring ORDER BY ring_index ASC LIMIT ?",
                (self._retained_capacity,),
            ).fetchall()
            for r in rows:
                pair = (bytes(r[0]), bytes(r[1]))
                if pair not in self._anchor_ring:
                    self._anchor_ring.append(pair)

    @property
    def sqlite_path(self) -> Path | None:
        return self._sqlite_path

    @property
    def quorum(self) -> int:
        return self._quorum

    @property
    def retained_anchors(self) -> tuple[tuple[bytes, bytes], ...]:
        return tuple(self._anchor_ring)

    def fetch_finalized_header_quorum(self) -> FinalizedHeaderConsensus:
        """Fetch eth_getBlockByNumber('finalized', false) across providers and verify consensus."""
        votes: dict[tuple[int, bytes, bytes], list[tuple[str, bytes]]] = {}
        errors: list[str] = []

        for name, provider in self._providers:
            try:
                res = provider.call("eth_getBlockByNumber", ["finalized", False])
                if not isinstance(res, dict):
                    raise LiveEvmAnchorSyncError(f"provider {name} returned non-object block result")
                number = _parse_quantity(res.get("number"), f"{name}.number")
                block_hash = _parse_data(res.get("hash"), f"{name}.hash", 32)
                state_root = _parse_data(res.get("stateRoot"), f"{name}.stateRoot", 32)
                raw_header = encode_execution_header_rlp(res)
                key = (number, block_hash, state_root)
                votes.setdefault(key, []).append((name, raw_header))
            except Exception as exc:
                errors.append(f"{name}: {exc}")

        if not votes:
            raise LiveEvmAnchorSyncError(f"all providers failed to return finalized block: {'; '.join(errors)}")

        winning_key, winning_entries = max(votes.items(), key=lambda item: len(item[1]))
        if len(winning_entries) < self._quorum:
            raise LiveEvmAnchorSyncError(
                f"quorum consensus not reached: largest agreement was {len(winning_entries)}/{len(self._providers)}, "
                f"required {self._quorum}. Errors: {'; '.join(errors)}"
            )

        number, block_hash, state_root = winning_key
        agreeing_names = tuple(name for name, _ in winning_entries)
        raw_header_rlp = winning_entries[0][1]

        return FinalizedHeaderConsensus(
            block_number=number,
            block_hash=block_hash,
            state_root=state_root,
            raw_header_rlp=raw_header_rlp,
            agreeing_providers=agreeing_names,
        )

    def fetch_and_verify_state_proof(
        self,
        consensus: FinalizedHeaderConsensus,
    ) -> VerifiedEvmAccountState:
        """Fetch eth_getProof at the finalized block and verify MPT inclusion/exclusion."""
        addr_hex = "0x" + self._contract_address.hex()
        slots_hex = ["0x" + s.hex() for s in self._storage_slots]
        block_hex = hex(consensus.block_number)

        provider_map = dict(self._providers)
        proof_verified = False
        last_error = ""

        # Try agreeing providers until proof validates
        for name in consensus.agreeing_providers:
            provider = provider_map[name]
            try:
                proof_resp = provider.call("eth_getProof", [addr_hex, slots_hex, block_hex])
                if not isinstance(proof_resp, dict):
                    continue
                verified_state = verify_eip1186_account_proof(
                    raw_header_rlp=consensus.raw_header_rlp,
                    address=self._contract_address,
                    response=proof_resp,
                    expected_storage_slots=self._storage_slots,
                )
                proof_verified = True
                return verified_state
            except (EvmStateProofError, Exception) as exc:
                last_error = f"{name}: {exc}"
                continue

        raise LiveEvmAnchorSyncError(f"EIP-1186 state proof verification failed: {last_error}")

    def sync_anchor(self) -> VerifiedLiveAnchor:
        """Full execution cycle: multi-RPC consensus -> EIP-1186 proof -> 4096-anchor ring commit."""
        consensus = self.fetch_finalized_header_quorum()
        verified_state = self.fetch_and_verify_state_proof(consensus)

        # Derive canonical 48-byte anchor commitment root and ledger state head
        # Bind: domain || state_root || storage_root
        anchor_root = hashlib.shake_256(
            b"0PSP-EVM-ANCHOR-ROOT-v1" + verified_state.state_root + verified_state.storage_root
        ).digest(HASH_BYTES)

        # Bind: domain || block_hash || block_number
        state_head = hashlib.shake_256(
            b"0PSP-EVM-STATE-HEAD-v1" + consensus.block_hash + consensus.block_number.to_bytes(8, "big")
        ).digest(HASH_BYTES)

        # Add to 4,096-state anchor ring buffer (FIFO)
        pair = (anchor_root, state_head)
        if pair not in self._anchor_ring:
            if len(self._anchor_ring) >= self._retained_capacity:
                self._anchor_ring.pop(0)
            self._anchor_ring.append(pair)

        # Commit to SQLite WAL storage if configured
        if self._sqlite_path is not None:
            with sqlite3.connect(self._sqlite_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("""
                    INSERT OR REPLACE INTO live_evm_anchor_ring(
                        block_number, block_hash, state_root, anchor_root, ledger_state_head, storage_root
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    consensus.block_number,
                    consensus.block_hash,
                    consensus.state_root,
                    anchor_root,
                    state_head,
                    verified_state.storage_root,
                ))
                conn.execute("""
                    DELETE FROM live_evm_anchor_ring WHERE ring_index NOT IN (
                        SELECT ring_index FROM live_evm_anchor_ring ORDER BY ring_index DESC LIMIT ?
                    )
                """, (self._retained_capacity,))
                conn.commit()

        evidence_payload = anchor_root + state_head
        state_evidence = StateAnchorEvidenceV3(
            source_id=LIVE_SOURCE_ID,
            finalized_anchor=consensus.block_hash,
            evidence=evidence_payload,
        )

        verified_snapshot = VerifiedStateSnapshotV3(
            source_id=LIVE_SOURCE_ID,
            finalized_anchor=consensus.block_hash,
            finality_policy_id=LIVE_FINALITY_POLICY_ID,
            namespace_id=self._namespace_id,
            params_id=self._params_id,
            commitment_root=anchor_root,
            ledger_state_head=state_head,
        )

        return VerifiedLiveAnchor(
            block_number=consensus.block_number,
            block_hash=consensus.block_hash,
            state_root=consensus.state_root,
            contract_address=self._contract_address,
            storage_root=verified_state.storage_root,
            storage_values=verified_state.storage_values,
            anchor_root=anchor_root,
            ledger_state_head=state_head,
            state_evidence=state_evidence,
            verified_snapshot=verified_snapshot,
        )

    def persist_to_sqlite(self, sqlite_path: str | Path) -> None:
        """Persist currently retained in-memory anchor ring to a SQLite WAL database."""
        path = Path(sqlite_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=FULL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS live_evm_anchor_ring (
                    ring_index INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_number INTEGER NOT NULL,
                    block_hash BLOB NOT NULL,
                    state_root BLOB NOT NULL,
                    anchor_root BLOB NOT NULL UNIQUE,
                    ledger_state_head BLOB NOT NULL,
                    storage_root BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anchor_root ON live_evm_anchor_ring(anchor_root);")
            for root, head in self._anchor_ring:
                conn.execute("""
                    INSERT OR IGNORE INTO live_evm_anchor_ring(
                        block_number, block_hash, state_root, anchor_root, ledger_state_head, storage_root
                    ) VALUES (0, x'00', x'00', ?, ?, x'00')
                """, (root, head))
            conn.commit()
        self._sqlite_path = path

    def create_anchor_ring_verifier(
        self,
        finalized_anchor: bytes,
    ) -> StateAnchorVerifierV3:
        """Create a callable StateAnchorVerifierV3 bound to the current retained anchor ring."""
        return create_anchor_ring_state_verifier(
            self.retained_anchors,
            source_id=LIVE_SOURCE_ID,
            finalized_anchor=finalized_anchor,
            finality_policy_id=LIVE_FINALITY_POLICY_ID,
            namespace_id=self._namespace_id,
            params_id=self._params_id,
        )
