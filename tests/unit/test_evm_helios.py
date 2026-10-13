from __future__ import annotations

import hashlib
import os
import stat
from types import SimpleNamespace

import pytest

import src.adapters.evm_helios as helios_module
from src.adapters.evm_helios import (
    ETHEREUM_MAINNET_GENESIS_HASH,
    HeliosAuthenticatedDepositVerifier,
    HeliosAuthenticatedHeaderJournal,
    HeliosConsensusError,
    HeliosFinalityCatchupRequired,
    HeliosMainnetConfig,
    HeliosMainnetLightClient,
    execution_header_rlp_from_json,
)
from src.adapters.evm_deposit_evidence import EvmDepositEvidencePolicy
from src.adapters.evm_deposit_proof import ProvenEvmDepositInclusion
from src.adapters.evm_namespace import EvmNamespaceConfig, runtime_code_fingerprint
from src.adapters.evm_trie import keccak256, rlp_encode_bytes, rlp_encode_list
from src.primitives.namespace_v3 import derive_namespace_id_v3

EMPTY_TRIE_ROOT = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
EMPTY_OMMERS_HASH = bytes.fromhex("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
TEST_PROTOCOL_ADDRESS = b"\x22" * 20
TEST_PROTOCOL_CODE = bytes.fromhex("60006000556001600055")
TEST_EVENT_TOPIC = b"\x55" * 32
NS = derive_namespace_id_v3(b"ledger", b"deployment", b"asset")
ZERO32 = bytes(32)


def encode_header_fields(fields):
    return rlp_encode_list([rlp_encode_bytes(field) for field in fields])


def json_header_from_rlp(raw):
    from src.adapters.evm_trie import rlp_decode
    fields = rlp_decode(raw)
    number = int.from_bytes(fields[8], "big")
    result = {
        "parentHash": "0x" + fields[0].hex(),
        "sha3Uncles": "0x" + fields[1].hex(),
        "miner": "0x" + fields[2].hex(),
        "stateRoot": "0x" + fields[3].hex(),
        "transactionsRoot": "0x" + fields[4].hex(),
        "receiptsRoot": "0x" + fields[5].hex(),
        "logsBloom": "0x" + fields[6].hex(),
        "difficulty": hex(int.from_bytes(fields[7], "big")),
        "number": hex(number),
        "gasLimit": hex(int.from_bytes(fields[9], "big")),
        "gasUsed": hex(int.from_bytes(fields[10], "big")),
        "timestamp": hex(int.from_bytes(fields[11], "big")),
        "extraData": "0x" + fields[12].hex(),
        "mixHash": "0x" + fields[13].hex(),
        "nonce": "0x" + fields[14].hex(),
        "hash": "0x" + keccak256(raw).hex(),
    }
    if len(fields) >= 16:
        result["baseFeePerGas"] = hex(int.from_bytes(fields[15], "big"))
    if len(fields) >= 17:
        result["withdrawalsRoot"] = "0x" + fields[16].hex()
    if len(fields) >= 20:
        result["blobGasUsed"] = hex(int.from_bytes(fields[17], "big"))
        result["excessBlobGas"] = hex(int.from_bytes(fields[18], "big"))
        result["parentBeaconBlockRoot"] = "0x" + fields[19].hex()
    if len(fields) >= 21:
        result["requestsHash"] = "0x" + fields[20].hex()
    return result


def mainnet_genesis_json():
    fields = [
        bytes(32),
        EMPTY_OMMERS_HASH,
        bytes(20),
        bytes.fromhex("d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"),
        EMPTY_TRIE_ROOT,
        EMPTY_TRIE_ROOT,
        bytes(256),
        (1 << 34).to_bytes(5, "big"),
        b"",
        (5000).to_bytes(2, "big"),
        b"",
        b"",
        bytes.fromhex("11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
        bytes(32),
        bytes.fromhex("0000000000000042"),
    ]
    return json_header_from_rlp(encode_header_fields(fields))


def make_header(number, parent_hash):
    fields = [
        parent_hash,
        EMPTY_OMMERS_HASH,
        b"\x11" * 20,
        bytes([number + 1]) * 32,
        bytes([0x40 + number]) * 32,
        bytes([0x50 + number]) * 32,
        bytes(256),
        (131072).to_bytes(3, "big"),
        b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big"),
        (30_000_000).to_bytes(4, "big"),
        b"",
        number.to_bytes((number.bit_length() + 7) // 8, "big"),
        b"",
        bytes(32),
        bytes(8),
    ]
    raw = encode_header_fields(fields)
    return json_header_from_rlp(raw), raw, keccak256(raw)


class FakeProcess:
    def __init__(self):
        self.return_code = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.return_code

    def terminate(self):
        self.terminated = True
        self.return_code = 0

    def wait(self, timeout=None):
        return self.return_code

    def kill(self):
        self.killed = True
        self.return_code = -9


class FakeRpc:
    def __init__(self, blocks, *, final_height, chain_id=1, code=TEST_PROTOCOL_CODE):
        self.blocks = blocks
        self.final_height = final_height
        self.chain_id = chain_id
        self.code = code
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            tag, full_transactions = params
            assert full_transactions is False
            number = self.final_height if tag == "finalized" else int(tag, 16)
            return self.blocks.get(number)
        if method == "eth_getCode":
            return "0x" + self.code.hex()
        raise AssertionError(method)


def make_fake_chain(final_height=3):
    genesis = mainnet_genesis_json()
    genesis["hash"] = "0x" + ETHEREUM_MAINNET_GENESIS_HASH.hex()
    # The independently known Mainnet genesis hash is the root of this test chain.
    blocks = {0: genesis}
    parent = ETHEREUM_MAINNET_GENESIS_HASH
    for height in range(1, final_height + 1):
        block, _raw, block_hash = make_header(height, parent)
        blocks[height] = block
        parent = block_hash
    return blocks


def make_namespace_config(checkpoint_height, checkpoint_hash):
    return EvmNamespaceConfig(
        chain_id=1,
        genesis_hash=ETHEREUM_MAINNET_GENESIS_HASH,
        checkpoint_block_number=checkpoint_height,
        checkpoint_hash=checkpoint_hash,
        protocol_address=TEST_PROTOCOL_ADDRESS,
        expected_protocol_code_fingerprint=runtime_code_fingerprint(TEST_PROTOCOL_CODE),
        asset_address=None,
        expected_asset_code_fingerprint=None,
    )


def fake_light_client(tmp_path, blocks, *, final_height=3):
    binary = tmp_path / "helios"
    binary.write_bytes(b"test executable; the process is mocked")
    config = HeliosMainnetConfig(
        binary_path=binary,
        binary_sha256=hashlib.sha256(binary.read_bytes()).digest(),
        execution_rpc_url="https://execution.example.test/secret-token",
        consensus_rpc_url="https://consensus.example.test",
        weak_subjectivity_checkpoint=b"\x44" * 32,
    )
    light_client = HeliosMainnetLightClient(config)
    light_client._process = FakeProcess()
    light_client._rpc = FakeRpc(blocks, final_height=final_height)
    light_client._started = True
    return light_client


def test_reconstructs_known_ethereum_mainnet_genesis_header():
    header = mainnet_genesis_json()
    encoded = execution_header_rlp_from_json(header)
    assert keccak256(encoded) == ETHEREUM_MAINNET_GENESIS_HASH
    assert int(header["number"], 16) == 0


def test_execution_header_codec_rejects_hash_mismatch_and_incomplete_fork_fields():
    header = make_fake_chain()[2]
    altered = dict(header)
    altered["hash"] = "0x" + "aa" * 32
    with pytest.raises(HeliosConsensusError, match="hash does not match"):
        execution_header_rlp_from_json(altered)

    altered = dict(header)
    altered["blobGasUsed"] = "0x0"
    with pytest.raises(HeliosConsensusError, match="all three blob-era"):
        execution_header_rlp_from_json(altered)


def test_supervised_start_pins_binary_version_and_keeps_rpc_secrets_out_of_argv(tmp_path):
    blocks = make_fake_chain()
    binary = tmp_path / "helios"
    binary.write_bytes(b"trusted fake test binary")
    process = FakeProcess()
    seen = {}
    rpc = FakeRpc(blocks, final_height=3)

    def process_factory(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return process

    def rpc_factory(endpoint, **kwargs):
        seen["endpoint"] = endpoint
        return rpc

    client = HeliosMainnetLightClient(
        HeliosMainnetConfig(
            binary_path=binary,
            binary_sha256=hashlib.sha256(binary.read_bytes()).digest(),
            execution_rpc_url="https://exec.example.test/token-in-query",
            consensus_rpc_url="https://consensus.example.test",
            weak_subjectivity_checkpoint=b"\x44" * 32,
            startup_timeout_seconds=1,
        ),
        process_factory=process_factory,
        rpc_factory=rpc_factory,
        version_probe=lambda *args, **kwargs: SimpleNamespace(stdout="helios 0.12.0", returncode=0),
    ).start()
    try:
        assert client.started
        assert seen["endpoint"].startswith("http://127.0.0.1:")
        assert all("token-in-query" not in arg for arg in seen["command"])
        config_path = os.path.join(seen["kwargs"]["env"]["HOME"], ".helios", "helios.toml")
        assert stat.S_IMODE(os.stat(config_path).st_mode) == 0o600
        assert "token-in-query" in open(config_path, encoding="utf-8").read()
        assert "--strict-checkpoint-age" in seen["command"]
        assert "--rpc-bind-ip" in seen["command"]
    finally:
        client.stop()
    assert process.terminated
    assert not os.path.exists(config_path)


def test_light_client_rejects_binary_hash_mismatch_before_start(tmp_path):
    binary = tmp_path / "helios"
    binary.write_bytes(b"untrusted binary")
    config = HeliosMainnetConfig(
        binary_path=binary,
        binary_sha256=b"\x99" * 32,
        execution_rpc_url="https://exec.example.test",
        consensus_rpc_url="https://consensus.example.test",
        weak_subjectivity_checkpoint=b"\x44" * 32,
    )
    client = HeliosMainnetLightClient(config)
    with pytest.raises(HeliosConsensusError, match="SHA-256"):
        client.start()
    assert client._process is None


def test_authenticated_header_journal_syncs_parent_links_to_helios_finality(tmp_path):
    blocks = make_fake_chain(final_height=3)
    _header1, raw1, hash1 = make_header(1, ETHEREUM_MAINNET_GENESIS_HASH)
    config = make_namespace_config(1, hash1)
    light_client = fake_light_client(tmp_path, blocks, final_height=3)
    journal = HeliosAuthenticatedHeaderJournal(
        tmp_path / "helios-headers.sqlite3",
        namespace_config=config,
        namespace_id=NS,
        light_client=light_client,
        max_headers_per_sync=10,
    )
    _header2, raw2, hash2 = make_header(2, bytes.fromhex(blocks[1]["hash"][2:]))
    result = journal.authenticate_header(raw2)
    assert result.number == 2
    assert result.block_hash == hash2
    assert result.observed_finalized_number == 3
    assert result.assurance_level == "HELIOS_LIGHT_CLIENT_FINALIZED_ANCESTRY_AND_HEADER_RLP_VERIFIED"
    assert journal.contains_finalized_header(1, hash1)
    assert journal.contains_finalized_header(2, hash2)
    assert journal.contains_finalized_header(3, bytes.fromhex(blocks[3]["hash"][2:]))
    assert not journal.contains_finalized_header(2, b"\xff" * 32)

    reopened = HeliosAuthenticatedHeaderJournal(
        tmp_path / "helios-headers.sqlite3",
        namespace_config=config,
        namespace_id=NS,
        light_client=light_client,
        max_headers_per_sync=10,
    )
    assert reopened.authenticate_header(raw2).block_hash == hash2


def test_authenticated_journal_rejects_checkpoint_mismatch_and_old_headers(tmp_path):
    blocks = make_fake_chain(final_height=3)
    _header1, _raw1, hash1 = make_header(1, ETHEREUM_MAINNET_GENESIS_HASH)
    config = make_namespace_config(1, b"\x99" * 32)
    client = fake_light_client(tmp_path, blocks, final_height=3)
    journal = HeliosAuthenticatedHeaderJournal(
        tmp_path / "mismatch.sqlite3",
        namespace_config=config,
        namespace_id=NS,
        light_client=client,
        max_headers_per_sync=10,
    )
    with pytest.raises(HeliosConsensusError, match="execution checkpoint"):
        journal.advance_to_finalized()

    old_config = make_namespace_config(2, bytes.fromhex(blocks[2]["hash"][2:]))
    old_journal = HeliosAuthenticatedHeaderJournal(
        tmp_path / "old.sqlite3",
        namespace_config=old_config,
        namespace_id=NS,
        light_client=client,
        max_headers_per_sync=10,
    )
    with pytest.raises(HeliosConsensusError, match="outside the authenticated execution checkpoint"):
        # Header one is a valid header on the mock chain, but below the checkpoint.
        _header, raw1, _hash = make_header(1, ETHEREUM_MAINNET_GENESIS_HASH)
        old_journal.authenticate_header(raw1)


def test_authenticated_journal_fails_closed_on_finality_regression_reorg_and_catchup(tmp_path):
    blocks = make_fake_chain(final_height=3)
    _header1, _raw1, hash1 = make_header(1, ETHEREUM_MAINNET_GENESIS_HASH)
    config = make_namespace_config(1, hash1)
    client = fake_light_client(tmp_path, blocks, final_height=3)
    journal = HeliosAuthenticatedHeaderJournal(
        tmp_path / "reorg.sqlite3",
        namespace_config=config,
        namespace_id=NS,
        light_client=client,
        max_headers_per_sync=10,
    )
    journal.advance_to_finalized()
    rpc = client._rpc
    rpc.final_height = 2
    with pytest.raises(HeliosConsensusError, match="regressed"):
        journal.advance_to_finalized()

    # A fresh journal refuses a catch-up gap beyond the configured bound.
    limited = HeliosAuthenticatedHeaderJournal(
        tmp_path / "limited.sqlite3",
        namespace_config=config,
        namespace_id=NS,
        light_client=client,
        max_headers_per_sync=1,
    )
    rpc.final_height = 3
    with pytest.raises(HeliosFinalityCatchupRequired, match="catch-up requires"):
        limited.advance_to_finalized()

    # A change at the persisted tip is never auto-rewound or overwritten.
    rpc.final_height = 3
    journal.advance_to_finalized()
    original = rpc.blocks[3]
    alternate, _raw, _hash = make_header(3, b"\xfe" * 32)
    rpc.blocks[3] = alternate
    with pytest.raises(HeliosConsensusError, match="conflicts with durable authenticated history"):
        journal.advance_to_finalized()
    rpc.blocks[3] = original


def test_authenticated_deposit_verifier_checks_pinned_runtime_code_at_proven_block(tmp_path, monkeypatch):
    blocks = make_fake_chain(final_height=3)
    header2, raw2, hash2 = make_header(2, bytes.fromhex(blocks[1]["hash"][2:]))
    config = make_namespace_config(1, bytes.fromhex(blocks[1]["hash"][2:]))
    client = fake_light_client(tmp_path, blocks, final_height=3)
    journal = HeliosAuthenticatedHeaderJournal(
        tmp_path / "deposit-code.sqlite3",
        namespace_config=config,
        namespace_id=NS,
        light_client=client,
        max_headers_per_sync=10,
    )
    policy = EvmDepositEvidencePolicy(
        namespace_id=NS,
        chain_id=1,
        deposit_contract_address=config.protocol_address,
        expected_runtime_code_fingerprint=config.expected_protocol_code_fingerprint,
        event_topic0=TEST_EVENT_TOPIC,
        asset_address=None,
    )
    fake_inclusion = ProvenEvmDepositInclusion(
        namespace_id=NS,
        chain_id=1,
        deposit_id=b"\x61" * 36,
        transaction_hash=b"\x62" * 32,
        transaction_index=4,
        receipt_log_ordinal=0,
        block_number=2,
        block_hash=hash2,
        finalized_anchor=(2).to_bytes(8, "big") + hash2,
        deposit_contract_address=TEST_PROTOCOL_ADDRESS,
        asset_address=None,
        depositor=b"\x63" * 20,
        beneficiary=b"\x64" * 20,
        amount=12,
    )

    class FakeInclusionVerifier:
        def __init__(self, _policy, _journal):
            pass
        def verify(self, **_kwargs):
            return fake_inclusion

    monkeypatch.setattr(helios_module, "EvmDepositInclusionVerifier", FakeInclusionVerifier)
    verifier = HeliosAuthenticatedDepositVerifier(policy, config, journal)
    result = verifier.verify(
        raw_header_rlp=raw2,
        raw_transaction=b"raw tx fixture",
        transaction_proof=[b"tx proof fixture"],
        raw_receipt=b"raw receipt fixture",
        receipt_proof=[b"receipt proof fixture"],
        transaction_index=4,
        receipt_log_ordinal=0,
        expected_beneficiary=b"\x64" * 20,
    )
    assert result.inclusion == fake_inclusion
    assert result.authenticated_header.block_hash == hash2
    assert result.assurance_level == "HELIOS_FINALIZED_HEADER_ANCESTRY_AND_TRANSACTION_RECEIPT_TRIES_VERIFIED"

    # Wrong runtime at this historical block must fail closed even though the
    # header and trie verifier output are otherwise accepted.
    client._rpc.code = bytes.fromhex("6001600055")
    with pytest.raises(HeliosConsensusError, match="differs from the pinned manifest"):
        verifier.verify(
            raw_header_rlp=raw2,
            raw_transaction=b"raw tx fixture",
            transaction_proof=[b"tx proof fixture"],
            raw_receipt=b"raw receipt fixture",
            receipt_proof=[b"receipt proof fixture"],
            transaction_index=4,
            receipt_log_ordinal=0,
            expected_beneficiary=b"\x64" * 20,
        )


def test_authenticated_deposit_policy_must_match_pinned_namespace_manifest(tmp_path):
    blocks = make_fake_chain(final_height=3)
    checkpoint_hash = bytes.fromhex(blocks[1]["hash"][2:])
    config = make_namespace_config(1, checkpoint_hash)
    client = fake_light_client(tmp_path, blocks, final_height=3)
    journal = HeliosAuthenticatedHeaderJournal(
        tmp_path / "policy-mismatch.sqlite3",
        namespace_config=config,
        namespace_id=NS,
        light_client=client,
    )
    wrong_policy = EvmDepositEvidencePolicy(
        namespace_id=NS,
        chain_id=1,
        deposit_contract_address=b"\x99" * 20,
        expected_runtime_code_fingerprint=config.expected_protocol_code_fingerprint,
        event_topic0=TEST_EVENT_TOPIC,
        asset_address=None,
    )
    with pytest.raises(ValueError, match="must match the namespace's pinned protocol and asset"):
        HeliosAuthenticatedDepositVerifier(wrong_policy, config, journal)


def test_helios_rpc_adapter_allows_only_valid_historical_code_reads(tmp_path):
    blocks = make_fake_chain(final_height=3)
    client = fake_light_client(tmp_path, blocks, final_height=3)
    assert client.call("eth_getCode", ["0x" + TEST_PROTOCOL_ADDRESS.hex(), "0x2"]) == "0x" + TEST_PROTOCOL_CODE.hex()
    with pytest.raises(HeliosConsensusError, match="eth_getCode parameters are malformed"):
        client.call("eth_getCode", ["0x1234", "0x2"])
    with pytest.raises(HeliosConsensusError, match="does not permit"):
        client.call("eth_sendRawTransaction", ["0xdeadbeef"])
