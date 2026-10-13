from __future__ import annotations

import io
import json
from dataclasses import replace

import pytest

from src.adapters.evm_namespace import (
    EvmIdentityMismatch,
    EvmNamespaceAdapter,
    EvmNamespaceConfig,
    EvmRpcError,
    JsonRpcClient,
    runtime_code_fingerprint,
)

CHAIN_ID = 1
GENESIS = b"\x01" * 32
CHECKPOINT_HEIGHT = 12_345
CHECKPOINT_HASH = b"\x02" * 32
PROTOCOL_ADDRESS = b"\x11" * 20
PROTOCOL_CODE = bytes.fromhex("60006000556001600055")
ASSET_ADDRESS = b"\x22" * 20
ASSET_CODE = bytes.fromhex("6060604052")


class FakeRpc:
    def __init__(self, *, chain_id=CHAIN_ID, genesis=GENESIS,
                 checkpoint_height=CHECKPOINT_HEIGHT, checkpoint=CHECKPOINT_HASH,
                 code_by_address=None):
        self.chain_id = chain_id
        self.genesis = genesis
        self.checkpoint_height = checkpoint_height
        self.checkpoint = checkpoint
        self.code_by_address = dict(code_by_address or {
            PROTOCOL_ADDRESS: PROTOCOL_CODE,
            ASSET_ADDRESS: ASSET_CODE,
        })
        self.calls: list[tuple[str, list[object]]] = []

    def call(self, method: str, params: list[object]) -> object:
        self.calls.append((method, params))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            height = int(params[0], 16)
            if height == 0:
                return {"number": "0x0", "hash": "0x" + self.genesis.hex()}
            if height == self.checkpoint_height:
                return {"number": hex(height), "hash": "0x" + self.checkpoint.hex()}
            return None
        if method == "eth_getCode":
            address = bytes.fromhex(str(params[0])[2:])
            return "0x" + self.code_by_address.get(address, b"").hex()
        raise AssertionError(f"unexpected JSON-RPC method: {method}")


def build_adapter(*, asset_address=ASSET_ADDRESS, rpc=None, deployment_epoch=0, asset_epoch=0):
    code_by_address = {
        PROTOCOL_ADDRESS: PROTOCOL_CODE,
        ASSET_ADDRESS: ASSET_CODE,
    }
    rpc = rpc or FakeRpc(code_by_address=code_by_address)
    config = EvmNamespaceConfig(
        chain_id=CHAIN_ID,
        genesis_hash=GENESIS,
        checkpoint_block_number=CHECKPOINT_HEIGHT,
        checkpoint_hash=CHECKPOINT_HASH,
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=asset_address,
        expected_asset_code_fingerprint=(
            runtime_code_fingerprint(ASSET_CODE) if asset_address is not None else None
        ),
        deployment_epoch=deployment_epoch,
        asset_epoch=asset_epoch,
    )
    return config, rpc, EvmNamespaceAdapter(config, rpc)


def test_evm_erc20_namespace_v3_known_answer_vector() -> None:
    _, _, adapter = build_adapter()
    binding = adapter.resolve()
    assert len(binding.ledger_identity) == 92
    assert len(binding.deployment_identity) == 60
    assert len(binding.asset_identity) == 56
    assert binding.ledger_identity.hex() == (
        "305053502d45564d2d4c45444745522d4944454e544954592d7631"
        "01" + "00" * 31 + "01" + "01" * 32
    )
    assert binding.deployment_identity.hex() == (
        "305053502d45564d2d4445504c4f594d454e542d4944454e544954592d7631"
        "01" + "11" * 20 + "00" * 8
    )
    assert binding.asset_identity.hex() == (
        "305053502d45564d2d41535345542d4944454e544954592d7631"
        "01" + "01" + "22" * 20 + "00" * 8
    )
    # The descriptors are raw canonical bytes, not 256-bit intermediate hashes.
    assert binding.ledger_identity.startswith(b"0PSP-EVM-LEDGER-IDENTITY-v1\x01")
    assert binding.deployment_identity.startswith(b"0PSP-EVM-DEPLOYMENT-IDENTITY-v1\x01")
    assert binding.asset_identity.startswith(b"0PSP-EVM-ASSET-IDENTITY-v1\x01\x01")
    assert binding.protocol_code_fingerprint.hex() == (
        "f6a30183ff2cd81deaca7952b380a0d09c"
        "210d0696da997476e73905c810e744e1"
        "4a9af7ac732a49b49b6d419927d096"
    )
    assert binding.asset_code_fingerprint.hex() == (
        "4e74d89c3c892fb8809b154da5a6eb74"
        "0623db245b53a86280a8d5c964b7261f"
        "232d04292a7d54779dfeeb887687fbe9"
    )
    assert binding.namespace_id.data.hex() == (
        "d77ec0ca141c09b8249453a0aaded14b"
        "9fd3aefe2b90c8aafc1cf568d016bd56"
        "d063c3fe16f9a766663e686e9d298413"
    )
    assert binding.namespace_id.data == adapter.resolve().namespace_id.data


def test_resolver_checks_expected_chain_checkpoint_and_runtime_code() -> None:
    _, rpc, adapter = build_adapter()
    result = adapter.resolve()
    assert result.chain_id == CHAIN_ID
    assert result.genesis_hash == GENESIS
    assert result.checkpoint_block_number == CHECKPOINT_HEIGHT
    assert result.checkpoint_hash == CHECKPOINT_HASH
    assert result.protocol_address == PROTOCOL_ADDRESS
    assert result.protocol_code_fingerprint == runtime_code_fingerprint(PROTOCOL_CODE)
    assert result.asset_address == ASSET_ADDRESS
    assert result.asset_code_fingerprint == runtime_code_fingerprint(ASSET_CODE)
    assert ("eth_getCode", ["0x" + PROTOCOL_ADDRESS.hex(), "finalized"]) in rpc.calls
    assert ("eth_getCode", ["0x" + ASSET_ADDRESS.hex(), "finalized"]) in rpc.calls



def test_checkpoint_is_verified_but_does_not_split_logical_chain_namespace() -> None:
    _, _, base_adapter = build_adapter()
    base = base_adapter.resolve()

    alternate_height = 54_321
    alternate_checkpoint = b"\x77" * 32
    alternate_config = EvmNamespaceConfig(
        chain_id=CHAIN_ID,
        genesis_hash=GENESIS,
        checkpoint_block_number=alternate_height,
        checkpoint_hash=alternate_checkpoint,
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=ASSET_ADDRESS,
        expected_asset_code_fingerprint=runtime_code_fingerprint(ASSET_CODE),
    )
    alternate_rpc = FakeRpc(
        checkpoint_height=alternate_height,
        checkpoint=alternate_checkpoint,
        code_by_address={PROTOCOL_ADDRESS: PROTOCOL_CODE, ASSET_ADDRESS: ASSET_CODE},
    )
    alternate = EvmNamespaceAdapter(alternate_config, alternate_rpc).resolve()

    assert (base.checkpoint_block_number, base.checkpoint_hash) != (
        alternate.checkpoint_block_number, alternate.checkpoint_hash
    )
    assert alternate.ledger_identity == base.ledger_identity
    assert alternate.namespace_id == base.namespace_id


def test_native_asset_has_distinct_asset_component_and_no_token_rpc_call() -> None:
    _, _, erc20_adapter = build_adapter()
    _, native_rpc, native_adapter = build_adapter(asset_address=None)
    erc20 = erc20_adapter.resolve()
    native = native_adapter.resolve()
    assert native.asset_address is None
    assert native.asset_code_fingerprint is None
    assert native.asset_identity != erc20.asset_identity
    assert native.namespace_id != erc20.namespace_id
    assert not any(
        method == "eth_getCode" and params[0] == "0x" + ASSET_ADDRESS.hex()
        for method, params in native_rpc.calls
    )


def test_deployment_epoch_is_explicit_namespace_separation_for_upgrade_governance() -> None:
    _, _, first_adapter = build_adapter(deployment_epoch=0)
    _, _, next_adapter = build_adapter(deployment_epoch=1)
    assert first_adapter.resolve().namespace_id != next_adapter.resolve().namespace_id


def test_chain_id_is_part_of_ledger_component_identity() -> None:
    _, _, base_adapter = build_adapter()
    base = base_adapter.resolve()

    chain_id = 30_000
    config = EvmNamespaceConfig(
        chain_id=chain_id,
        genesis_hash=GENESIS,
        checkpoint_block_number=CHECKPOINT_HEIGHT,
        checkpoint_hash=CHECKPOINT_HASH,
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=ASSET_ADDRESS,
        expected_asset_code_fingerprint=runtime_code_fingerprint(ASSET_CODE),
    )
    rpc = FakeRpc(
        chain_id=chain_id,
        code_by_address={PROTOCOL_ADDRESS: PROTOCOL_CODE, ASSET_ADDRESS: ASSET_CODE},
    )
    alternate = EvmNamespaceAdapter(config, rpc).resolve()
    assert alternate.ledger_identity != base.ledger_identity
    assert alternate.namespace_id != base.namespace_id


def test_asset_epoch_explicitly_separates_asset_semantics() -> None:
    _, _, original_adapter = build_adapter(asset_epoch=0)
    _, _, upgraded_adapter = build_adapter(asset_epoch=1)
    original = original_adapter.resolve()
    upgraded = upgraded_adapter.resolve()
    assert original.asset_identity != upgraded.asset_identity
    assert original.namespace_id != upgraded.namespace_id


def test_protocol_address_is_part_of_deployment_component_identity() -> None:
    _, _, base_adapter = build_adapter()
    base = base_adapter.resolve()

    protocol_address = b"\x44" * 20
    config = EvmNamespaceConfig(
        chain_id=CHAIN_ID,
        genesis_hash=GENESIS,
        checkpoint_block_number=CHECKPOINT_HEIGHT,
        checkpoint_hash=CHECKPOINT_HASH,
        protocol_address=protocol_address,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=ASSET_ADDRESS,
        expected_asset_code_fingerprint=runtime_code_fingerprint(ASSET_CODE),
    )
    rpc = FakeRpc(
        code_by_address={protocol_address: PROTOCOL_CODE, ASSET_ADDRESS: ASSET_CODE},
    )
    alternate = EvmNamespaceAdapter(config, rpc).resolve()
    assert alternate.deployment_identity != base.deployment_identity
    assert alternate.namespace_id != base.namespace_id


@pytest.mark.parametrize("kwargs", [
    {"chain_id": True},
    {"chain_id": 0},
    {"chain_id": 1 << 256},
    {"genesis_hash": b"x" * 31},
    {"checkpoint_hash": b"x" * 33},
    {"protocol_address": b"x" * 19},
    {"protocol_address": bytes(20)},
    {"expected_protocol_code_fingerprint": b"x" * 31},
    {"deployment_epoch": True},
    {"deployment_epoch": -1},
    {"asset_epoch": True},
    {"asset_epoch": -1},
    {"code_block_tag": "pending"},
    {"code_block_tag": "0x00"},
    {"code_block_tag": "0X1"},
])
def test_manifest_rejects_noncanonical_configuration(kwargs) -> None:
    values = dict(
        chain_id=CHAIN_ID,
        genesis_hash=GENESIS,
        checkpoint_block_number=CHECKPOINT_HEIGHT,
        checkpoint_hash=CHECKPOINT_HASH,
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=ASSET_ADDRESS,
        expected_asset_code_fingerprint=runtime_code_fingerprint(ASSET_CODE),
    )
    values.update(kwargs)
    with pytest.raises(ValueError):
        EvmNamespaceConfig(**values)


def test_manifest_accepts_a_canonical_exact_block_tag_for_authenticated_code_binding() -> None:
    config, rpc, _adapter = build_adapter()
    exact_config = replace(config, code_block_tag=hex(CHECKPOINT_HEIGHT))

    binding = EvmNamespaceAdapter(exact_config, rpc).resolve()

    assert binding.namespace_id.data
    assert ("eth_getCode", ["0x" + PROTOCOL_ADDRESS.hex(), hex(CHECKPOINT_HEIGHT)]) in rpc.calls


def test_native_asset_rejects_token_fingerprint_and_token_requires_one() -> None:
    base = dict(
        chain_id=CHAIN_ID,
        genesis_hash=GENESIS,
        checkpoint_block_number=CHECKPOINT_HEIGHT,
        checkpoint_hash=CHECKPOINT_HASH,
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
    )
    with pytest.raises(ValueError, match="native asset"):
        EvmNamespaceConfig(**base, expected_asset_code_fingerprint=b"x" * 32)
    with pytest.raises(ValueError):
        EvmNamespaceConfig(**base, asset_address=ASSET_ADDRESS)


def test_genesis_checkpoint_zero_must_be_consistent() -> None:
    with pytest.raises(ValueError, match="block 0"):
        EvmNamespaceConfig(
            chain_id=CHAIN_ID,
            genesis_hash=GENESIS,
            checkpoint_block_number=0,
            checkpoint_hash=CHECKPOINT_HASH,
            protocol_address=PROTOCOL_ADDRESS,
            expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        )


def test_runtime_fingerprint_rejects_empty_and_oversized_code() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        runtime_code_fingerprint(b"")
    with pytest.raises(ValueError, match="safety bound"):
        runtime_code_fingerprint(b"x" * (1_000_000 + 1))


def test_json_rpc_client_disallows_http_unless_explicitly_enabled() -> None:
    with pytest.raises(ValueError, match="HTTP RPC is disabled"):
        JsonRpcClient("http://127.0.0.1:8545")
    client = JsonRpcClient("http://127.0.0.1:8545", allow_insecure_http=True)
    assert client is not None
    with pytest.raises(ValueError):
        JsonRpcClient("https://user:password@rpc.example")


def test_json_rpc_client_checks_response_id_and_result(monkeypatch) -> None:
    response = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":"0x1"}')
    seen = {}

    def fake_urlopen(request, timeout):
        seen["request"] = request
        seen["timeout"] = timeout
        return response

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = JsonRpcClient("https://rpc.example.test", timeout_seconds=2)
    assert client.call("eth_chainId", []) == "0x1"
    assert seen["timeout"] == 2.0
    request_body = json.loads(seen["request"].data.decode())
    assert request_body == {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}


def test_json_rpc_client_rejects_wrong_id_without_echoing_endpoint(monkeypatch) -> None:
    response = io.BytesIO(b'{"jsonrpc":"2.0","id":99,"result":"0x1"}')
    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: response)
    client = JsonRpcClient("https://rpc.example.test/secret-token")
    with pytest.raises(EvmRpcError, match="envelope mismatch") as error:
        client.call("eth_chainId", [])
    assert "secret-token" not in str(error.value)


def test_json_rpc_client_rejects_duplicate_json_members(monkeypatch) -> None:
    response = io.BytesIO(
        b'{"jsonrpc":"2.0","id":1,"result":"0x1","result":"0x2"}'
    )
    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: response)
    client = JsonRpcClient("https://rpc.example.test")
    with pytest.raises(EvmRpcError, match="ambiguous JSON"):
        client.call("eth_chainId", [])


def test_json_rpc_transport_error_fails_closed(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise OSError("secret endpoint credential leaked by transport error")

    monkeypatch.setattr("urllib.request.urlopen", fail)
    client = JsonRpcClient("https://rpc.example.test/secret-token")
    with pytest.raises(EvmRpcError, match="transport failed") as error:
        client.call("eth_chainId", [])
    assert "secret-token" not in str(error.value)
    assert "credential leaked" not in str(error.value)
