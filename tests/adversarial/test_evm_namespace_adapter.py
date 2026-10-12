from __future__ import annotations

from dataclasses import replace

import pytest

from src.adapters.evm_namespace import (
    EvmIdentityMismatch,
    EvmNamespaceAdapter,
    EvmNamespaceConfig,
    EvmRpcError,
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


class AttackerControlledRpc:
    """Controllable RPC response fixture for fail-closed identity tests."""

    def __init__(self):
        self.chain_id = CHAIN_ID
        self.genesis_hash = GENESIS
        self.checkpoint_hash = CHECKPOINT_HASH
        self.protocol_code = PROTOCOL_CODE
        self.asset_code = ASSET_CODE
        self.bad_quantity = False
        self.bad_block_height = False
        self.raise_rpc_error = False

    def call(self, method: str, params: list[object]) -> object:
        if self.raise_rpc_error:
            raise RuntimeError("transport/provider detail must not be trusted")
        if method == "eth_chainId":
            return "0x01" if self.bad_quantity else hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            height = int(params[0], 16)
            if self.bad_block_height:
                height += 1
            if int(params[0], 16) == 0:
                return {"number": hex(height), "hash": "0x" + self.genesis_hash.hex()}
            if int(params[0], 16) == CHECKPOINT_HEIGHT:
                return {"number": hex(height), "hash": "0x" + self.checkpoint_hash.hex()}
            return None
        if method == "eth_getCode":
            address = bytes.fromhex(str(params[0])[2:])
            code = self.protocol_code if address == PROTOCOL_ADDRESS else self.asset_code
            return "0x" + code.hex()
        raise AssertionError(f"unexpected method {method}")


def make_config(**overrides) -> EvmNamespaceConfig:
    data = dict(
        chain_id=CHAIN_ID,
        genesis_hash=GENESIS,
        checkpoint_block_number=CHECKPOINT_HEIGHT,
        checkpoint_hash=CHECKPOINT_HASH,
        protocol_address=PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
        asset_address=ASSET_ADDRESS,
        expected_asset_code_fingerprint=runtime_code_fingerprint(ASSET_CODE),
    )
    data.update(overrides)
    return EvmNamespaceConfig(**data)


@pytest.mark.parametrize("field, observed_value", [
    ("chain_id", 2),
    ("genesis_hash", b"\x03" * 32),
    ("checkpoint_hash", b"\x04" * 32),
])
def test_rpc_cannot_substitute_chain_identity(field, observed_value) -> None:
    rpc = AttackerControlledRpc()
    setattr(rpc, field if field != "genesis_hash" else "genesis_hash", observed_value)
    with pytest.raises(EvmIdentityMismatch):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_same_chain_id_and_genesis_with_wrong_checkpoint_is_rejected() -> None:
    rpc = AttackerControlledRpc()
    rpc.checkpoint_hash = b"\x99" * 32
    with pytest.raises(EvmIdentityMismatch, match="checkpoint"):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_unexpected_protocol_runtime_code_is_rejected() -> None:
    rpc = AttackerControlledRpc()
    rpc.protocol_code = bytes.fromhex("6001600055")
    with pytest.raises(EvmIdentityMismatch, match="protocol runtime code"):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_unexpected_token_runtime_code_is_rejected() -> None:
    rpc = AttackerControlledRpc()
    rpc.asset_code = bytes.fromhex("6002600055")
    with pytest.raises(EvmIdentityMismatch, match="asset runtime code"):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_eoa_or_unavailable_protocol_address_is_rejected() -> None:
    rpc = AttackerControlledRpc()
    rpc.protocol_code = b""
    with pytest.raises(EvmIdentityMismatch, match="no runtime code"):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_noncanonical_quantity_is_rejected_even_if_numeric_value_would_match() -> None:
    rpc = AttackerControlledRpc()
    rpc.bad_quantity = True
    with pytest.raises(EvmRpcError, match="QUANTITY"):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_block_height_substitution_is_rejected() -> None:
    rpc = AttackerControlledRpc()
    rpc.bad_block_height = True
    with pytest.raises(EvmIdentityMismatch, match="wrong block height"):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_rpc_exception_is_sanitized_and_fails_closed() -> None:
    rpc = AttackerControlledRpc()
    rpc.raise_rpc_error = True
    with pytest.raises(EvmRpcError, match="eth_chainId"):
        EvmNamespaceAdapter(make_config(), rpc).resolve()


def test_asset_and_deployment_manifest_changes_separate_namespaces() -> None:
    rpc = AttackerControlledRpc()
    baseline = EvmNamespaceAdapter(make_config(), rpc).resolve().namespace_id
    upgraded = EvmNamespaceAdapter(
        make_config(deployment_epoch=1), rpc
    ).resolve().namespace_id
    other_asset = EvmNamespaceAdapter(
        make_config(asset_address=b"\x33" * 20,
                    expected_asset_code_fingerprint=runtime_code_fingerprint(ASSET_CODE)),
        _AlternateAssetRpc(rpc, b"\x33" * 20),
    ).resolve().namespace_id
    assert baseline != upgraded
    assert baseline != other_asset

def test_asset_epoch_is_required_to_separate_same_address_semantic_upgrade() -> None:
    rpc = AttackerControlledRpc()
    original = EvmNamespaceAdapter(make_config(asset_epoch=0), rpc).resolve()
    upgraded = EvmNamespaceAdapter(make_config(asset_epoch=1), rpc).resolve()
    assert original.asset_address == upgraded.asset_address
    assert original.asset_identity != upgraded.asset_identity
    assert original.namespace_id != upgraded.namespace_id


def test_namespace_id_uses_typed_v3_not_plain_bytes() -> None:
    from src.primitives.namespace import NamespaceId

    binding = EvmNamespaceAdapter(make_config(), AttackerControlledRpc()).resolve()
    assert binding.namespace_id.__class__.__name__ == "NamespaceIdV3"
    assert not isinstance(binding.namespace_id, NamespaceId)


def test_code_fingerprint_manifest_requires_48_bytes() -> None:
    with pytest.raises(ValueError, match="expected_protocol_code_fingerprint"):
        make_config(expected_protocol_code_fingerprint=b"x" * 32)



class _AlternateAssetRpc:
    def __init__(self, source: AttackerControlledRpc, asset_address: bytes):
        self.source = source
        self.asset_address = asset_address

    def call(self, method: str, params: list[object]) -> object:
        if method == "eth_getCode" and bytes.fromhex(str(params[0])[2:]) == self.asset_address:
            return "0x" + ASSET_CODE.hex()
        return self.source.call(method, params)
