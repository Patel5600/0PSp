from __future__ import annotations

from dataclasses import replace

import pytest

from src.adapters.evm_finality import (
    EvmFinalityError,
    FinalityCatchupRequired,
    SqliteEvmFinalityJournal,
)
from src.primitives.namespace_v3 import derive_namespace_id_v3

CHAIN_ID = 1
NAMESPACE = derive_namespace_id_v3(b"ledger", b"deployment", b"asset")


class HeaderRpc:
    def __init__(self, finalized_height=4):
        self.finalized_height = finalized_height
        self.headers = {}
        for height in range(12):
            block_hash = bytes([height + 1]) * 32
            parent_hash = None if height == 0 else self.headers[height - 1]["hash"]
            self.headers[height] = {
                "number": hex(height),
                "hash": "0x" + block_hash.hex(),
                "parentHash": None if parent_hash is None else "0x" + parent_hash.hex(),
            }

    def call(self, method, params):
        if method == "eth_chainId":
            return hex(CHAIN_ID)
        if method != "eth_getBlockByNumber":
            raise AssertionError(method)
        tag, _include_transactions = params
        height = self.finalized_height if tag == "finalized" else int(tag, 16)
        if height not in self.headers:
            return None
        return dict(self.headers[height])

    def rewrite_hash(self, height, block_hash, *, rewrite_descendants=False):
        self.headers[height]["hash"] = "0x" + block_hash.hex()
        if rewrite_descendants:
            for descendant in range(height + 1, max(self.headers) + 1):
                prior_hash = bytes.fromhex(self.headers[descendant - 1]["hash"][2:])
                self.headers[descendant]["parentHash"] = "0x" + prior_hash.hex()


def make_journal(path, rpc, *, namespace_id=NAMESPACE, checkpoint=2):
    return SqliteEvmFinalityJournal(
        path,
        chain_id=CHAIN_ID,
        genesis_hash=bytes.fromhex(rpc.headers[0]["hash"][2:]),
        checkpoint_block_number=checkpoint,
        checkpoint_hash=bytes.fromhex(rpc.headers[checkpoint]["hash"][2:]),
        namespace_id=namespace_id,
    )


def test_journal_persists_checkpoint_to_finalized_parent_chain(tmp_path):
    path = tmp_path / "finality.sqlite3"
    rpc = HeaderRpc(finalized_height=5)
    journal = make_journal(path, rpc)
    snapshot = journal.advance(rpc)
    assert snapshot.stored_finalized_number == 5
    assert snapshot.observed_finalized_number == 5
    assert snapshot.caught_up is True
    assert journal.contains_finalized_header(
        3, bytes.fromhex(rpc.headers[3]["hash"][2:])
    )
    assert not journal.contains_finalized_header(3, b"\xff" * 32)

    # Restart against the same file: durable state resumes without rollback.
    reopened = make_journal(path, rpc)
    next_snapshot = reopened.advance(rpc)
    assert next_snapshot.stored_finalized_number == 5


def test_journal_refuses_parent_hash_break_and_rolls_back_entire_update(tmp_path):
    path = tmp_path / "broken.sqlite3"
    rpc = HeaderRpc(finalized_height=4)
    rpc.headers[3]["parentHash"] = "0x" + (b"\xee" * 32).hex()
    journal = make_journal(path, rpc)
    with pytest.raises(EvmFinalityError, match="parent hash mismatch"):
        journal.advance(rpc)
    assert not journal.contains_finalized_header(2, bytes([3]) * 32)


def test_journal_detects_reorg_at_durable_tip_and_does_not_rewind(tmp_path):
    path = tmp_path / "reorg.sqlite3"
    rpc = HeaderRpc(finalized_height=4)
    journal = make_journal(path, rpc)
    journal.advance(rpc)
    rpc.rewrite_hash(4, b"\xfa" * 32)
    with pytest.raises(EvmFinalityError, match="reorg/conflicting view"):
        journal.advance(rpc)
    assert journal.contains_finalized_header(4, bytes([5]) * 32)
    assert not journal.contains_finalized_header(4, b"\xfa" * 32)


def test_journal_rejects_finality_regression_and_wrong_namespace(tmp_path):
    path = tmp_path / "regression.sqlite3"
    rpc = HeaderRpc(finalized_height=4)
    journal = make_journal(path, rpc)
    journal.advance(rpc)
    rpc.finalized_height = 3
    with pytest.raises(EvmFinalityError, match="regressed"):
        journal.advance(rpc)

    other = derive_namespace_id_v3(b"ledger", b"other-deployment", b"asset")
    wrong_scope = make_journal(path, rpc, namespace_id=other)
    with pytest.raises(EvmFinalityError, match="different chain, checkpoint, or namespace"):
        wrong_scope.advance(rpc)


def test_journal_rejects_unbounded_catchup_without_partial_commit(tmp_path):
    path = tmp_path / "catchup.sqlite3"
    rpc = HeaderRpc(finalized_height=6)
    journal = make_journal(path, rpc)
    with pytest.raises(FinalityCatchupRequired, match="requires 4 headers"):
        journal.advance(rpc, max_headers=3)
    assert not journal.contains_finalized_header(2, bytes([3]) * 32)


def test_journal_rejects_incompatible_configuration_and_memory_database(tmp_path):
    rpc = HeaderRpc(finalized_height=3)
    with pytest.raises(ValueError, match="file-backed"):
        make_journal(":memory:", rpc)
    with pytest.raises(ValueError, match="genesis checkpoint"):
        SqliteEvmFinalityJournal(
            tmp_path / "bad.sqlite3",
            chain_id=CHAIN_ID,
            genesis_hash=b"\x01" * 32,
            checkpoint_block_number=0,
            checkpoint_hash=b"\x02" * 32,
            namespace_id=NAMESPACE,
        )
