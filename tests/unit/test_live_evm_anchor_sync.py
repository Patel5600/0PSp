"""Unit tests for the live EVM multi-RPC finalized anchor synchronization adapter."""
from __future__ import annotations

import os
import sqlite3
import pytest

from src.adapters.evm_state_proof import EMPTY_TRIE_ROOT
from src.adapters.evm_trie import (
    keccak256,
    rlp_encode_bytes,
    rlp_encode_list,
    rlp_encode_uint,
)
from src.adapters.live_evm_anchor_sync import (
    FinalizedHeaderConsensus,
    HttpJsonRpcClient,
    LiveEvmAnchorSyncError,
    LiveEvmAnchorSynchronizer,
    RpcTransportProtocol,
    encode_execution_header_rlp,
)
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.transaction_v3_candidate import (
    TxFieldsV3Candidate,
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    state_context_digest_v3_candidate,
)
from src.protocol.trusted_state_v3 import (
    validate_transaction_state_binding_v3,
)

ADDRESS = b"\x22" * 20
SLOT_1 = b"\x00" * 31 + b"\x01"
NAMESPACE = NamespaceIdV3(b"\x33" * 48)
PARAMS = b"test-live-anchor-params"


def compact_encode_path(key: bytes, *, leaf: bool) -> bytes:
    nibbles = [n for byte in key for n in (byte >> 4, byte & 15)]
    odd = len(nibbles) % 2
    encoded = [2 * int(leaf) + odd]
    if odd:
        encoded.extend(nibbles[:1])
        nibbles = nibbles[1:]
    else:
        encoded.append(0)
    encoded.extend(nibbles)
    return bytes((encoded[i] << 4) | encoded[i + 1] for i in range(0, len(encoded), 2))


def leaf_node(key: bytes, value: bytes) -> bytes:
    return rlp_encode_list([
        rlp_encode_bytes(compact_encode_path(key, leaf=True)),
        rlp_encode_bytes(value),
    ])


def build_mock_eth_fixture(*, block_number: int = 100, storage_val: int = 42):
    """Build a mathematically sound EVM block and EIP-1186 getProof fixture."""
    storage_key_hash = keccak256(SLOT_1)
    val_rlp = rlp_encode_uint(storage_val)
    storage_leaf = leaf_node(storage_key_hash, val_rlp)
    storage_root = keccak256(storage_leaf)

    account_val = rlp_encode_list([
        rlp_encode_uint(1),
        rlp_encode_uint(1000),
        rlp_encode_bytes(storage_root),
        rlp_encode_bytes(keccak256(b"code")),
    ])
    account_key_hash = keccak256(ADDRESS)
    account_leaf = leaf_node(account_key_hash, account_val)
    state_root = keccak256(account_leaf)

    block_dict = {
        "number": hex(block_number),
        "hash": "0x" + keccak256(b"block" + str(block_number).encode()).hex(),
        "parentHash": "0x" + b"\x01".hex() * 32,
        "sha3Uncles": "0x" + b"\x02".hex() * 32,
        "miner": "0x" + b"\x03".hex() * 20,
        "stateRoot": "0x" + state_root.hex(),
        "transactionsRoot": "0x" + b"\x04".hex() * 32,
        "receiptsRoot": "0x" + b"\x05".hex() * 32,
        "logsBloom": "0x" + ("00" * 256),
        "difficulty": "0x0",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x5208",
        "timestamp": "0x60000000",
        "extraData": "0x",
        "mixHash": "0x" + b"\x06".hex() * 32,
        "nonce": "0x" + b"\x00".hex() * 8,
    }

    raw_header_rlp = encode_execution_header_rlp(block_dict)
    block_dict["rawHeader"] = "0x" + raw_header_rlp.hex()

    proof_resp = {
        "address": "0x" + ADDRESS.hex(),
        "nonce": hex(1),
        "balance": hex(1000),
        "storageHash": "0x" + storage_root.hex(),
        "codeHash": "0x" + keccak256(b"code").hex(),
        "accountProof": ["0x" + account_leaf.hex()],
        "storageProof": [{
            "key": "0x" + SLOT_1.hex(),
            "value": hex(storage_val),
            "proof": ["0x" + storage_leaf.hex()],
        }],
    }

    return block_dict, proof_resp, state_root, storage_root


class MockRpcTransport:
    """Mock RPC transport returning predetermined responses for test methods."""

    def __init__(self, block_result: object, proof_result: object) -> None:
        self.block_result = block_result
        self.proof_result = proof_result
        self.calls: list[tuple[str, list[object]]] = []

    def call(self, method: str, params: list[object]) -> object:
        self.calls.append((method, params))
        if method == "eth_getBlockByNumber":
            if isinstance(self.block_result, Exception):
                raise self.block_result
            return self.block_result
        if method == "eth_getProof":
            if isinstance(self.proof_result, Exception):
                raise self.proof_result
            return self.proof_result
        raise ValueError(f"unexpected method: {method}")


def test_quorum_consensus_and_anchor_synchronization_success() -> None:
    """Verify 3-of-3 quorum consensus, state proof verification, and anchor ring commit."""
    block_dict, proof_resp, state_root, storage_root = build_mock_eth_fixture()

    providers = {
        "rpc1": MockRpcTransport(block_dict, proof_resp),
        "rpc2": MockRpcTransport(block_dict, proof_resp),
        "rpc3": MockRpcTransport(block_dict, proof_resp),
    }

    sync = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
    )

    assert sync.quorum == 2
    assert len(sync.retained_anchors) == 0

    verified_anchor = sync.sync_anchor()

    assert verified_anchor.block_number == 100
    assert verified_anchor.state_root == state_root
    assert verified_anchor.storage_root == storage_root
    assert len(verified_anchor.anchor_root) == 48
    assert len(verified_anchor.ledger_state_head) == 48
    assert len(sync.retained_anchors) == 1
    assert sync.retained_anchors[0] == (verified_anchor.anchor_root, verified_anchor.ledger_state_head)


def test_quorum_split_brain_disagreement_fails_closed() -> None:
    """Adversarial partition: providers return contradictory state roots -> fails closed."""
    b1, p1, _, _ = build_mock_eth_fixture(block_number=100, storage_val=1)
    b2, p2, _, _ = build_mock_eth_fixture(block_number=100, storage_val=2)
    b3, p3, _, _ = build_mock_eth_fixture(block_number=100, storage_val=3)

    providers = {
        "rpc1": MockRpcTransport(b1, p1),
        "rpc2": MockRpcTransport(b2, p2),
        "rpc3": MockRpcTransport(b3, p3),
    }

    sync = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
    )

    with pytest.raises(LiveEvmAnchorSyncError, match="quorum consensus not reached"):
        sync.sync_anchor()


def test_tampered_proof_node_rejected_by_state_verifier() -> None:
    """Attacking MPT Proof: tampered storage leaf node causes verification failure."""
    block_dict, proof_resp, _, _ = build_mock_eth_fixture()

    # Corrupt the proof node byte
    tampered_resp = dict(proof_resp)
    good_node_hex = tampered_resp["storageProof"][0]["proof"][0]
    bad_node = bytes.fromhex(good_node_hex[2:])
    bad_node_tampered = bytes([bad_node[0] ^ 0xFF]) + bad_node[1:]
    tampered_resp["storageProof"] = [{
        "key": tampered_resp["storageProof"][0]["key"],
        "value": tampered_resp["storageProof"][0]["value"],
        "proof": ["0x" + bad_node_tampered.hex()],
    }]

    providers = {
        "rpc1": MockRpcTransport(block_dict, tampered_resp),
        "rpc2": MockRpcTransport(block_dict, tampered_resp),
        "rpc3": MockRpcTransport(block_dict, tampered_resp),
    }

    sync = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
    )

    with pytest.raises(LiveEvmAnchorSyncError, match="EIP-1186 state proof verification failed"):
        sync.sync_anchor()


def test_anchor_ring_fifo_capacity_eviction() -> None:
    """Verify FIFO eviction when anchor ring reaches maximum capacity."""
    b, p, _, _ = build_mock_eth_fixture()
    providers = {
        "rpc1": MockRpcTransport(b, p),
        "rpc2": MockRpcTransport(b, p),
        "rpc3": MockRpcTransport(b, p),
    }

    # Test with capacity of 3
    sync = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
        retained_capacity=3,
    )

    # Add 4 distinct anchors
    anchors = []
    for i in range(4):
        b_i, p_i, _, _ = build_mock_eth_fixture(block_number=200 + i, storage_val=10 + i)
        providers["rpc1"].block_result = b_i
        providers["rpc1"].proof_result = p_i
        providers["rpc2"].block_result = b_i
        providers["rpc2"].proof_result = p_i
        providers["rpc3"].block_result = b_i
        providers["rpc3"].proof_result = p_i
        a = sync.sync_anchor()
        anchors.append((a.anchor_root, a.ledger_state_head))

    # Ring should have exactly 3 items: anchors[1], anchors[2], anchors[3] (anchors[0] evicted)
    assert len(sync.retained_anchors) == 3
    assert anchors[0] not in sync.retained_anchors
    assert anchors[1] in sync.retained_anchors
    assert anchors[2] in sync.retained_anchors
    assert anchors[3] in sync.retained_anchors


def test_trusted_state_binding_integration() -> None:
    """Verify end-to-end integration between LiveEvmAnchorSynchronizer and validate_transaction_state_binding_v3."""
    b, p, _, _ = build_mock_eth_fixture(block_number=500, storage_val=999)
    providers = {
        "rpc1": MockRpcTransport(b, p),
        "rpc2": MockRpcTransport(b, p),
        "rpc3": MockRpcTransport(b, p),
    }

    sync = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
    )

    anchor = sync.sync_anchor()

    # Create matching TxFieldsV3Candidate
    expected_context = state_context_digest_v3_candidate(
        anchor.verified_snapshot.source_id,
        anchor.verified_snapshot.finalized_anchor,
        anchor.verified_snapshot.finality_policy_id,
    )

    stmt = TxFieldsV3Candidate(
        params_id=PARAMS,
        namespace_id=NAMESPACE,
        commitment_root=anchor.anchor_root,
        input_nullifier=NullifierV3(b"\x55" * 48),
        ledger_state_head=anchor.ledger_state_head,
        state_context_digest=expected_context,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=10,
        output_entropy=b"\x66" * 32,
        output_commitments=(CoinCommitmentV3(b"\x77" * 48),),
    )

    verifier = sync.create_anchor_ring_verifier(anchor.verified_snapshot.finalized_anchor)

    # Validate transaction state binding against synchronized anchor
    binding = validate_transaction_state_binding_v3(stmt, anchor.state_evidence, verifier)
    assert binding.commitment_root == anchor.anchor_root
    assert binding.ledger_state_head == anchor.ledger_state_head


def test_sqlite_wal_anchor_ring_persistence_and_recovery(tmp_path) -> None:
    """Verify SQLite WAL persistence, journal mode, and restart recovery."""
    db_file = tmp_path / "anchors.sqlite3"
    b, p, state_root, storage_root = build_mock_eth_fixture(block_number=100, storage_val=42)
    providers = {
        "rpc1": MockRpcTransport(b, p),
        "rpc2": MockRpcTransport(b, p),
        "rpc3": MockRpcTransport(b, p),
    }

    # 1. Initialize synchronizer with SQLite path
    sync1 = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
        sqlite_path=db_file,
    )
    assert sync1.sqlite_path == db_file
    assert len(sync1.retained_anchors) == 0

    anchor1 = sync1.sync_anchor()
    assert len(sync1.retained_anchors) == 1

    # 2. Verify WAL mode in SQLite database
    with sqlite3.connect(db_file) as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.lower() == "wal"
        count = conn.execute("SELECT COUNT(*) FROM live_evm_anchor_ring").fetchone()[0]
        assert count == 1
        row = conn.execute(
            "SELECT block_number, anchor_root, ledger_state_head FROM live_evm_anchor_ring WHERE ring_index=1"
        ).fetchone()
        assert row[0] == 100
        assert bytes(row[1]) == anchor1.anchor_root
        assert bytes(row[2]) == anchor1.ledger_state_head

    # 3. Simulate process restart: instantiate new synchronizer on same db_file
    sync2 = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
        sqlite_path=db_file,
    )
    # Must have recovered anchor from SQLite WAL on startup
    assert len(sync2.retained_anchors) == 1
    assert sync2.retained_anchors[0] == (anchor1.anchor_root, anchor1.ledger_state_head)


def test_sqlite_wal_anchor_ring_fifo_capacity_eviction(tmp_path) -> None:
    """Verify FIFO eviction within SQLite WAL database when capacity is reached."""
    db_file = tmp_path / "fifo_anchors.sqlite3"
    providers = {
        "rpc1": MockRpcTransport(None, None),
        "rpc2": MockRpcTransport(None, None),
        "rpc3": MockRpcTransport(None, None),
    }

    sync = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=ADDRESS,
        storage_slots=[SLOT_1],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
        retained_capacity=3,
        sqlite_path=db_file,
    )

    anchors = []
    for i in range(4):
        b_i, p_i, _, _ = build_mock_eth_fixture(block_number=300 + i, storage_val=50 + i)
        providers["rpc1"].block_result = b_i
        providers["rpc1"].proof_result = p_i
        providers["rpc2"].block_result = b_i
        providers["rpc2"].proof_result = p_i
        providers["rpc3"].block_result = b_i
        providers["rpc3"].proof_result = p_i
        a = sync.sync_anchor()
        anchors.append((a.anchor_root, a.ledger_state_head))

    # In-memory and SQLite ring should both have exactly 3 anchors (anchors[0] evicted)
    assert len(sync.retained_anchors) == 3
    assert anchors[0] not in sync.retained_anchors

    with sqlite3.connect(db_file) as conn:
        count = conn.execute("SELECT COUNT(*) FROM live_evm_anchor_ring").fetchone()[0]
        assert count == 3
        stored_roots = [bytes(r[0]) for r in conn.execute("SELECT anchor_root FROM live_evm_anchor_ring").fetchall()]
        assert anchors[0][0] not in stored_roots
        assert anchors[1][0] in stored_roots
        assert anchors[2][0] in stored_roots
        assert anchors[3][0] in stored_roots


def test_cancun_execution_header_rlp_encoding() -> None:
    """Verify encode_execution_header_rlp preserves Cancun EIP-4844 / EIP-4788 fields (20 fields)."""
    from src.adapters.evm_state_proof import _header_fields

    block_dict = {
        "number": "0x1000",
        "hash": "0x" + b"\x01".hex() * 32,
        "parentHash": "0x" + b"\x02".hex() * 32,
        "sha3Uncles": "0x" + b"\x03".hex() * 32,
        "miner": "0x" + b"\x04".hex() * 20,
        "stateRoot": "0x" + b"\x05".hex() * 32,
        "transactionsRoot": "0x" + b"\x06".hex() * 32,
        "receiptsRoot": "0x" + b"\x07".hex() * 32,
        "logsBloom": "0x" + ("00" * 256),
        "difficulty": "0x0",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x5208",
        "timestamp": "0x66000000",
        "extraData": "0x",
        "mixHash": "0x" + b"\x08".hex() * 32,
        "nonce": "0x" + b"\x00".hex() * 8,
        "baseFeePerGas": "0x7",
        "withdrawalsRoot": "0x" + b"\x09".hex() * 32,
        "blobGasUsed": "0x20000",
        "excessBlobGas": "0x0",
        "parentBeaconBlockRoot": "0x" + b"\x0a".hex() * 32,
    }

    rlp_bytes = encode_execution_header_rlp(block_dict)
    num, blk_hash, state_rt = _header_fields(rlp_bytes)
    assert num == 0x1000
    assert state_rt == b"\x05" * 32
    assert len(blk_hash) == 32


@pytest.mark.skipif(
    not os.getenv("RUN_LIVE_TESTNET_TESTS"),
    reason="Live testnet tests disabled (set RUN_LIVE_TESTNET_TESTS=1 to run)",
)
def test_live_arbitrum_sepolia_rpc_connectivity() -> None:
    """Optional live integration test querying public Arbitrum Sepolia endpoints."""
    public_endpoints = [
        "https://sepolia-rollup.arbitrum.io/rpc",
        "https://arbitrum-sepolia-rpc.publicnode.com",
        "https://endpoints.omniatech.io/v1/arbitrum/sepolia/public",
    ]
    providers = {f"pub_{i}": HttpJsonRpcClient(url, timeout=5.0) for i, url in enumerate(public_endpoints)}
    sync = LiveEvmAnchorSynchronizer(
        providers,
        contract_address=b"\x00" * 20,
        storage_slots=[b"\x00" * 32],
        namespace_id=NAMESPACE,
        params_id=PARAMS,
    )
    consensus = sync.fetch_finalized_header_quorum()
    assert consensus.block_number > 0
    assert len(consensus.state_root) == 32
