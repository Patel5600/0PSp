from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

import scripts.smoke_namespace_mainnet as smoke
from pathlib import Path

from src.adapters.evm_helios import ETHEREUM_MAINNET_GENESIS_HASH
from src.adapters.evm_namespace import runtime_code_fingerprint
from src.adapters.evm_trie import keccak256
from src.primitives.namespace_v3 import NamespaceIdV3


PROTOCOL_CODE = bytes.fromhex("60006000556001600055")
FINALIZED_NUMBER = 21_000_000
RAW_HEADER = b"fake-but-isolated-header-fixture"
FINALIZED_HASH = keccak256(RAW_HEADER)


def valid_env() -> dict[str, str]:
    return {
        "PSP_HELIOS_BINARY": "/opt/helios",
        "PSP_HELIOS_BINARY_SHA256": "11" * 32,
        "PSP_HELIOS_EXECUTION_RPC_URL": "https://execution.example.invalid",
        "PSP_HELIOS_CONSENSUS_RPC_URL": "https://consensus.example.invalid",
        "PSP_HELIOS_WEAK_SUBJECTIVITY_CHECKPOINT": "22" * 32,
        "PSP_MAINNET_EXECUTION_CHECKPOINT_NUMBER": "21000000",
        "PSP_MAINNET_EXECUTION_CHECKPOINT_HASH": "33" * 32,
        "PSP_PROTOCOL_ADDRESS": "44" * 20,
        "PSP_PROTOCOL_RUNTIME_FINGERPRINT": runtime_code_fingerprint(PROTOCOL_CODE).hex(),
        "PSP_EXPECTED_NAMESPACE_ID": "ab" * 48,
        "PSP_FINALITY_JOURNAL_PATH": str(Path("/tmp/0psp-mainnet-finality.sqlite3").resolve()),
    }


def test_config_is_explicitly_pinned_to_mainnet_and_finalized_code() -> None:
    config = smoke.load_configuration(valid_env())

    assert config.namespace.chain_id == 1
    assert config.namespace.genesis_hash == ETHEREUM_MAINNET_GENESIS_HASH
    assert config.namespace.code_block_tag == "finalized"
    assert config.namespace.expected_protocol_code_fingerprint == runtime_code_fingerprint(PROTOCOL_CODE)
    assert config.expected_namespace_id == bytes.fromhex("ab" * 48)
    assert config.namespace.asset_address is None
    assert config.max_headers_per_sync == 4096


@pytest.mark.parametrize(
    "name,value",
    [
        ("PSP_HELIOS_BINARY_SHA256", "11" * 31),
        ("PSP_HELIOS_WEAK_SUBJECTIVITY_CHECKPOINT", "22" * 31),
        ("PSP_MAINNET_EXECUTION_CHECKPOINT_HASH", "33" * 31),
        ("PSP_PROTOCOL_ADDRESS", "44" * 19),
        ("PSP_PROTOCOL_RUNTIME_FINGERPRINT", "55" * 32),
        ("PSP_EXPECTED_NAMESPACE_ID", "ab" * 47),
    ],
)
def test_config_rejects_wrong_sized_trust_pins(name: str, value: str) -> None:
    env = valid_env()
    env[name] = value
    with pytest.raises(smoke.SmokeConfigurationError, match=name):
        smoke.load_configuration(env)


@pytest.mark.parametrize(
    "value",
    ["+1", "-1", "0x1", "01", " 1", "1 "],
)
def test_execution_checkpoint_height_requires_canonical_decimal(value: str) -> None:
    env = valid_env()
    env["PSP_MAINNET_EXECUTION_CHECKPOINT_NUMBER"] = value
    with pytest.raises(smoke.SmokeConfigurationError, match="PSP_MAINNET_EXECUTION_CHECKPOINT_NUMBER"):
        smoke.load_configuration(env)


def test_token_address_and_fingerprint_must_be_pinned_together() -> None:
    env = valid_env()
    env["PSP_ASSET_ADDRESS"] = "66" * 20
    with pytest.raises(smoke.SmokeConfigurationError, match="must be set together"):
        smoke.load_configuration(env)

    env = valid_env()
    env["PSP_ASSET_RUNTIME_FINGERPRINT"] = "77" * 48
    with pytest.raises(smoke.SmokeConfigurationError, match="must be set together"):
        smoke.load_configuration(env)


@pytest.mark.parametrize("path", [":memory:", "relative.db"])
def test_finality_database_must_be_durable_and_absolute(path: str) -> None:
    env = valid_env()
    env["PSP_FINALITY_JOURNAL_PATH"] = path
    with pytest.raises(smoke.SmokeConfigurationError, match="absolute file-backed"):
        smoke.load_configuration(env)


def _install_fakes(monkeypatch, *, adapter_fails: bool = False):
    config = smoke.load_configuration(valid_env())
    namespace_id = NamespaceIdV3(bytes.fromhex("ab" * 48))
    state = {"started": False, "stopped": False}

    class FakeClient:
        def __init__(self, _config):
            pass

        def start(self):
            state["started"] = True

        def stop(self):
            state["stopped"] = True

        def call(self, method, params):
            if method == "eth_getBlockByNumber":
                return {"number": hex(FINALIZED_NUMBER), "hash": "0x" + FINALIZED_HASH.hex()}
            if method == "eth_getCode":
                return "0x" + PROTOCOL_CODE.hex()
            raise AssertionError(f"unexpected RPC method {method}")

    class FakeAdapter:
        def __init__(self, namespace_config, _client):
            assert namespace_config.code_block_tag == hex(FINALIZED_NUMBER)

        def resolve(self):
            if adapter_fails:
                raise RuntimeError("fixture mismatch")
            return SimpleNamespace(namespace_id=namespace_id)

    class FakeJournal:
        def __init__(self, _path, **kwargs):
            assert kwargs["namespace_id"] == namespace_id
            assert kwargs["namespace_config"].code_block_tag == hex(FINALIZED_NUMBER)

        def advance_to_finalized(self):
            return SimpleNamespace(number=FINALIZED_NUMBER + 10, block_hash=bytes.fromhex("88" * 32))

        def contains_finalized_header(self, _number, _block_hash):
            return True

        def verify_account_state(self, raw_header_rlp, address):
            assert raw_header_rlp == RAW_HEADER
            return SimpleNamespace(
                block_number=FINALIZED_NUMBER,
                block_hash=FINALIZED_HASH,
                address=address,
                code_hash=keccak256(PROTOCOL_CODE),
            )

    monkeypatch.setattr(smoke, "HeliosMainnetLightClient", FakeClient)
    monkeypatch.setattr(smoke, "EvmNamespaceAdapter", FakeAdapter)
    monkeypatch.setattr(smoke, "HeliosAuthenticatedHeaderJournal", FakeJournal)
    monkeypatch.setattr(smoke, "execution_header_rlp_from_json", lambda _value: RAW_HEADER)
    return config, state


def test_live_smoke_binds_exact_code_to_authenticated_state_and_keeps_composite_no_go(monkeypatch) -> None:
    config, state = _install_fakes(monkeypatch)

    report = smoke.run_live_smoke(config)

    assert state == {"started": True, "stopped": True}
    assert report["smoke_result"] == "PASS"
    assert report["namespace_mapping"] == "PASS_DIRECT_HASH_OF_CANONICAL_RAW_DESCRIPTORS"
    assert report["expected_namespace_id_match"] == "PASS"
    assert report["protocol_code_state_proof"] == "PASS_CODE_HASH_BOUND_TO_AUTHENTICATED_STATE_ROOT"
    assert report["durable_authenticated_ancestry"] == "PASS"
    assert report["proof_binding"] == "NO-GO_NOT_INSTANTIATED_BY_THIS_SMOKE"
    assert report["independent_security_review"] == "NOT_PERFORMED"
    assert report["external_cryptographic_audit"] == "NOT_PERFORMED"
    assert report["composite_production_gate"] == "NO-GO"



@pytest.mark.parametrize(
    "field,value,match",
    [
        ("block_number", FINALIZED_NUMBER + 1, "different block or address"),
        ("block_hash", bytes.fromhex("99" * 32), "different block or address"),
        ("address", bytes.fromhex("66" * 20), "different block or address"),
        ("code_hash", bytes.fromhex("77" * 32), "code hash differs"),
    ],
)
def test_live_smoke_fails_closed_on_mismatched_authenticated_account_state(
    monkeypatch, field: str, value: object, match: str
) -> None:
    config, state = _install_fakes(monkeypatch)

    original = smoke.HeliosAuthenticatedHeaderJournal

    class MutatedStateJournal(original):
        def verify_account_state(self, raw_header_rlp, address):
            verified = super().verify_account_state(raw_header_rlp, address)
            return SimpleNamespace(
                block_number=value if field == "block_number" else verified.block_number,
                block_hash=value if field == "block_hash" else verified.block_hash,
                address=value if field == "address" else verified.address,
                code_hash=value if field == "code_hash" else verified.code_hash,
            )

    monkeypatch.setattr(smoke, "HeliosAuthenticatedHeaderJournal", MutatedStateJournal)

    with pytest.raises(RuntimeError, match=match):
        smoke.run_live_smoke(config)
    assert state == {"started": True, "stopped": True}


def test_live_smoke_fails_closed_when_runtime_fingerprint_disagrees_with_manifest(monkeypatch) -> None:
    env = valid_env()
    env["PSP_PROTOCOL_RUNTIME_FINGERPRINT"] = "99" * 48
    config = smoke.load_configuration(env)
    state = {"started": False, "stopped": False}

    class FakeClient:
        def __init__(self, _config):
            pass

        def start(self):
            state["started"] = True

        def stop(self):
            state["stopped"] = True

        def call(self, method, params):
            if method == "eth_getBlockByNumber":
                return {"number": hex(FINALIZED_NUMBER), "hash": "0x" + FINALIZED_HASH.hex()}
            if method == "eth_getCode":
                return "0x" + PROTOCOL_CODE.hex()
            raise AssertionError(f"unexpected RPC method {method}")

    class FakeAdapter:
        def __init__(self, _config, _client):
            pass

        def resolve(self):
            return SimpleNamespace(namespace_id=NamespaceIdV3(bytes.fromhex("ab" * 48)))

    class FakeJournal:
        def __init__(self, _path, **kwargs):
            pass

        def advance_to_finalized(self):
            return SimpleNamespace(number=FINALIZED_NUMBER + 10, block_hash=bytes.fromhex("88" * 32))

        def contains_finalized_header(self, _number, _block_hash):
            return True

        def verify_account_state(self, raw_header_rlp, address):
            return SimpleNamespace(
                block_number=FINALIZED_NUMBER,
                block_hash=FINALIZED_HASH,
                address=address,
                code_hash=keccak256(PROTOCOL_CODE),
            )

    monkeypatch.setattr(smoke, "HeliosMainnetLightClient", FakeClient)
    monkeypatch.setattr(smoke, "EvmNamespaceAdapter", FakeAdapter)
    monkeypatch.setattr(smoke, "HeliosAuthenticatedHeaderJournal", FakeJournal)
    monkeypatch.setattr(smoke, "execution_header_rlp_from_json", lambda _value: RAW_HEADER)

    with pytest.raises(RuntimeError, match="fingerprint"):
        smoke.run_live_smoke(config)
    assert state == {"started": True, "stopped": True}


def test_live_smoke_rejects_namespace_id_that_differs_from_approved_manifest(monkeypatch) -> None:
    config, state = _install_fakes(monkeypatch)
    config = replace(config, expected_namespace_id=bytes.fromhex("cd" * 48))

    with pytest.raises(RuntimeError, match="differs from the independently pinned expected namespace ID"):
        smoke.run_live_smoke(config)
    assert state == {"started": True, "stopped": True}


def test_live_smoke_stops_client_if_namespace_resolution_fails(monkeypatch) -> None:
    config, state = _install_fakes(monkeypatch, adapter_fails=True)

    with pytest.raises(RuntimeError, match="fixture mismatch"):
        smoke.run_live_smoke(config)
    assert state == {"started": True, "stopped": True}
