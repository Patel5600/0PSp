from __future__ import annotations

import pytest

from src.adapters.evm_namespace import EvmRpcError
from src.adapters.evm_rpc_policy import QuorumJsonRpcTransport


class ScriptedRpc:
    def __init__(self, responses=None, *, failure=False):
        self.responses = dict(responses or {})
        self.failure = failure
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if self.failure:
            raise RuntimeError("https://secret.example/rpc?apikey=do-not-leak")
        value = self.responses[method]
        return value(params) if callable(value) else value


def test_quorum_requires_three_distinct_provider_objects_and_majority():
    one = ScriptedRpc({"eth_chainId": "0x1"})
    with pytest.raises(ValueError, match="at least three"):
        QuorumJsonRpcTransport({"a": one, "b": ScriptedRpc({})})
    with pytest.raises(ValueError, match="distinct"):
        QuorumJsonRpcTransport({"a": one, "b": one, "c": ScriptedRpc({})})
    with pytest.raises(ValueError, match="strict majority"):
        QuorumJsonRpcTransport(
            {"a": ScriptedRpc({}), "b": ScriptedRpc({}), "c": ScriptedRpc({})},
            quorum=1,
        )


def test_quorum_normalizes_equivalent_quantity_and_data_encodings():
    rpc = QuorumJsonRpcTransport({
        "provider-a": ScriptedRpc({"eth_chainId": "0xA"}),
        "provider-b": ScriptedRpc({"eth_chainId": "0xa"}),
        "provider-c": ScriptedRpc({"eth_chainId": "0xb"}),
    })
    assert rpc.call("eth_chainId", []) in {"0xA", "0xa"}

    code = QuorumJsonRpcTransport({
        "provider-a": ScriptedRpc({"eth_getCode": "0xAaBb"}),
        "provider-b": ScriptedRpc({"eth_getCode": "0xaabb"}),
        "provider-c": ScriptedRpc({"eth_getCode": "0xccdd"}),
    })
    assert code.call("eth_getCode", ["0x" + "11" * 20, "finalized"]) in {
        "0xAaBb", "0xaabb"
    }


def test_quorum_uses_block_number_hash_and_parent_hash():
    common = {
        "number": "0xa",
        "hash": "0x" + "aa" * 32,
        "parentHash": "0x" + "bb" * 32,
    }
    rpc = QuorumJsonRpcTransport({
        "a": ScriptedRpc({"eth_getBlockByNumber": common}),
        "b": ScriptedRpc({"eth_getBlockByNumber": {
            "number": "0xA", "hash": "0x" + "AA" * 32,
            "parentHash": "0x" + "BB" * 32, "extra": "ignored",
        }}),
        "c": ScriptedRpc({"eth_getBlockByNumber": {
            "number": "0xa", "hash": "0x" + "cc" * 32,
            "parentHash": "0x" + "dd" * 32,
        }}),
    })
    result = rpc.call("eth_getBlockByNumber", ["0xa", False])
    assert result["hash"].lower() == common["hash"]


def test_quorum_fails_closed_when_no_strict_majority_and_sanitizes_errors():
    rpc = QuorumJsonRpcTransport({
        "a": ScriptedRpc({"eth_chainId": "0x1"}),
        "b": ScriptedRpc({"eth_chainId": "0x2"}),
        "c": ScriptedRpc({}, failure=True),
    })
    with pytest.raises(EvmRpcError, match="quorum unavailable") as exc:
        rpc.call("eth_chainId", [])
    assert "secret.example" not in str(exc.value)
    assert "apikey" not in str(exc.value)


def test_quorum_tolerates_one_provider_failure_when_remaining_majority_agrees():
    rpc = QuorumJsonRpcTransport({
        "a": ScriptedRpc({"eth_chainId": "0x1"}),
        "b": ScriptedRpc({"eth_chainId": "0x1"}),
        "c": ScriptedRpc({}, failure=True),
    })
    assert rpc.call("eth_chainId", []) == "0x1"


def test_quorum_rejects_malformed_data_and_unsupported_or_mutating_rpc_surface():
    rpc = QuorumJsonRpcTransport({
        "a": ScriptedRpc({"eth_chainId": "0x01"}),
        "b": ScriptedRpc({"eth_chainId": "0x01"}),
        "c": ScriptedRpc({"eth_chainId": "0x01"}),
    })
    with pytest.raises(EvmRpcError, match="quorum unavailable"):
        rpc.call("eth_chainId", [])
    with pytest.raises(EvmRpcError, match="does not permit"):
        rpc.call("eth_sendRawTransaction", ["0xdeadbeef"])
    with pytest.raises(EvmRpcError, match="malformed"):
        rpc.call("eth_getCode", ["0x1234", "latest"])
