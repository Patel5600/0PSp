from __future__ import annotations

import pytest

from src.adapters.evm_namespace import EvmNamespaceConfig, runtime_code_fingerprint
from src.adapters.evm_namespace_runtime import EvmNamespaceRuntime, NamespaceRuntimeError

CHAIN_ID = 1
PROTOCOL_ADDRESS = b"\x11" * 20
PROTOCOL_CODE = bytes.fromhex("60006000556001600055")


class RuntimeRpc:
    def __init__(self, *, finalized_height=4, chain_id=CHAIN_ID, checkpoint_hash=None):
        self.chain_id = chain_id
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
        if checkpoint_hash is not None:
            self.headers[2]["hash"] = "0x" + checkpoint_hash.hex()

    def call(self, method, params):
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            tag, _ = params
            height = self.finalized_height if tag == "finalized" else int(tag, 16)
            if height not in self.headers:
                return None
            return dict(self.headers[height])
        if method == "eth_getCode":
            address, _tag = params
            if address == "0x" + PROTOCOL_ADDRESS.hex():
                return "0x" + PROTOCOL_CODE.hex()
            return "0x"
        raise AssertionError(method)


def make_config(rpc):
    return EvmNamespaceConfig(
        chain_id=CHAIN_ID,
        genesis_hash=bytes.fromhex(rpc.headers[0]["hash"][2:]),
        checkpoint_block_number=2,
        checkpoint_hash=bytes.fromhex(rpc.headers[2]["hash"][2:]),
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=None,
        expected_asset_code_fingerprint=None,
        code_block_tag="finalized",
    )


def test_runtime_combines_pinned_namespace_quorum_and_durable_finality(tmp_path):
    view = RuntimeRpc(finalized_height=5)
    runtime = EvmNamespaceRuntime(
        make_config(view),
        {"provider-a": RuntimeRpc(finalized_height=5),
         "provider-b": RuntimeRpc(finalized_height=5),
         "provider-c": RuntimeRpc(finalized_height=5)},
        tmp_path / "namespace-finality.sqlite3",
    )
    result = runtime.resolve()
    assert len(result.binding.namespace_id.data) == 48
    assert result.finality.stored_finalized_number == 5
    assert result.finality.caught_up is True


def test_runtime_rejects_latest_code_tag_and_insufficient_provider_count(tmp_path):
    view = RuntimeRpc()
    values = dict(
        chain_id=CHAIN_ID,
        genesis_hash=bytes.fromhex(view.headers[0]["hash"][2:]),
        checkpoint_block_number=2,
        checkpoint_hash=bytes.fromhex(view.headers[2]["hash"][2:]),
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=None,
        expected_asset_code_fingerprint=None,
    )
    weak_config = EvmNamespaceConfig(**values, code_block_tag="latest")
    with pytest.raises(ValueError, match="finalized"):
        EvmNamespaceRuntime(weak_config, {
            "a": RuntimeRpc(), "b": RuntimeRpc(), "c": RuntimeRpc()
        }, tmp_path / "weak.sqlite3")
    with pytest.raises(ValueError, match="at least three"):
        EvmNamespaceRuntime(make_config(view), {
            "a": RuntimeRpc(), "b": RuntimeRpc()
        }, tmp_path / "few.sqlite3")


def test_runtime_rejects_divergent_provider_checkpoint_views(tmp_path):
    good = RuntimeRpc(finalized_height=4)
    bad = RuntimeRpc(finalized_height=4, checkpoint_hash=b"\xff" * 32)
    runtime = EvmNamespaceRuntime(
        make_config(good),
        {"a": RuntimeRpc(finalized_height=4),
         "b": RuntimeRpc(finalized_height=4),
         "c": bad},
        tmp_path / "divergence.sqlite3",
    )
    # Two agreeing providers outvote one divergent endpoint. Replace one of the
    # agreeing endpoints with a different view to leave no strict majority.
    runtime = EvmNamespaceRuntime(
        make_config(good),
        {"a": RuntimeRpc(finalized_height=4),
         "b": RuntimeRpc(finalized_height=4, checkpoint_hash=b"\xaa" * 32),
         "c": RuntimeRpc(finalized_height=4, checkpoint_hash=b"\xbb" * 32)},
        tmp_path / "no-majority.sqlite3",
    )
    with pytest.raises(NamespaceRuntimeError, match="could not verify"):
        runtime.resolve()
