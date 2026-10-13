from __future__ import annotations

from types import SimpleNamespace

import pytest

import scripts.smoke_namespace_mainnet as smoke
from src.adapters.evm_helios import ETHEREUM_MAINNET_GENESIS_HASH
from src.primitives.namespace_v3 import NamespaceIdV3


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
        "PSP_PROTOCOL_RUNTIME_FINGERPRINT": "55" * 48,
        "PSP_FINALITY_JOURNAL_PATH": "/tmp/0psp-mainnet-finality.sqlite3",
    }


def test_config_is_explicitly_pinned_to_mainnet_and_finalized_code() -> None:
    config = smoke.load_configuration(valid_env())

    assert config.namespace.chain_id == 1
    assert config.namespace.genesis_hash == ETHEREUM_MAINNET_GENESIS_HASH
    assert config.namespace.code_block_tag == "finalized"
    assert config.namespace.expected_protocol_code_fingerprint == bytes.fromhex("55" * 48)
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


def test_live_smoke_keeps_composite_gate_no_go_even_when_smoke_passes(monkeypatch) -> None:
    config = smoke.load_configuration(valid_env())
    namespace_id = NamespaceIdV3(bytes.fromhex("ab" * 48))
    started = {"value": False, "stopped": False}

    class FakeClient:
        def __init__(self, _config):
            pass

        def start(self):
            started["value"] = True

        def stop(self):
            started["stopped"] = True

    class FakeAdapter:
        def __init__(self, _config, _client):
            pass

        def resolve(self):
            return SimpleNamespace(namespace_id=namespace_id)

    class FakeJournal:
        def __init__(self, _path, **kwargs):
            assert kwargs["namespace_id"] == namespace_id
            assert kwargs["namespace_config"] == config.namespace

        def advance_to_finalized(self):
            return SimpleNamespace(number=21_000_010, block_hash=bytes.fromhex("88" * 32))

        def contains_finalized_header(self, number, block_hash):
            return number == 21_000_010 and block_hash == bytes.fromhex("88" * 32)

    monkeypatch.setattr(smoke, "HeliosMainnetLightClient", FakeClient)
    monkeypatch.setattr(smoke, "EvmNamespaceAdapter", FakeAdapter)
    monkeypatch.setattr(smoke, "HeliosAuthenticatedHeaderJournal", FakeJournal)

    report = smoke.run_live_smoke(config)

    assert started == {"value": True, "stopped": True}
    assert report["smoke_result"] == "PASS"
    assert report["namespace_mapping"] == "PASS_DIRECT_HASH_OF_CANONICAL_RAW_DESCRIPTORS"
    assert report["durable_authenticated_ancestry"] == "PASS"
    assert report["proof_binding"] == "NO-GO_NOT_INSTANTIATED_BY_THIS_SMOKE"
    assert report["independent_security_review"] == "NOT_PERFORMED"
    assert report["external_cryptographic_audit"] == "NOT_PERFORMED"
    assert report["composite_production_gate"] == "NO-GO"


def test_live_smoke_stops_client_if_namespace_resolution_fails(monkeypatch) -> None:
    config = smoke.load_configuration(valid_env())
    state = {"stopped": False}

    class FakeClient:
        def __init__(self, _config):
            pass

        def start(self):
            return None

        def stop(self):
            state["stopped"] = True

    class FailingAdapter:
        def __init__(self, _config, _client):
            pass

        def resolve(self):
            raise RuntimeError("fixture mismatch")

    monkeypatch.setattr(smoke, "HeliosMainnetLightClient", FakeClient)
    monkeypatch.setattr(smoke, "EvmNamespaceAdapter", FailingAdapter)

    with pytest.raises(RuntimeError, match="fixture mismatch"):
        smoke.run_live_smoke(config)
    assert state["stopped"] is True
