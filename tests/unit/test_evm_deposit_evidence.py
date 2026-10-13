from __future__ import annotations

from copy import deepcopy

import pytest

from src.adapters.evm_deposit_evidence import (
    EvmDepositEvidenceError,
    EvmDepositEvidencePolicy,
    EvmDepositEvidenceReader,
)
from src.adapters.evm_rpc_policy import QuorumJsonRpcTransport
from src.adapters.evm_namespace import (
    EvmNamespaceAdapter,
    EvmNamespaceConfig,
    runtime_code_fingerprint,
)
from src.primitives.namespace_v3 import NamespaceIdV3

CHAIN_ID = 1
GENESIS = b"\x01" * 32
CHECKPOINT_HEIGHT = 5
CHECKPOINT_HASH = b"\x44" * 32
PROTOCOL_ADDRESS = b"\x11" * 20
PROTOCOL_CODE = bytes.fromhex("60006000556001600055")
ASSET_ADDRESS = b"\x22" * 20
TX_HASH = b"\x33" * 32
BLOCK_HASH = b"\x44" * 32
RECEIPTS_ROOT = b"\x88" * 32
TOPIC0 = b"\x55" * 32
DEPOSITOR = b"\x66" * 20
BENEFICIARY = b"\x77" * 20
AMOUNT = 123_456


def topic_address(address: bytes) -> str:
    return "0x" + (bytes(12) + address).hex()


def as_hex(value: bytes) -> str:
    return "0x" + value.hex()


class NamespaceRpc:
    def call(self, method, params):
        if method == "eth_chainId":
            return hex(CHAIN_ID)
        if method == "eth_getBlockByNumber":
            height = int(params[0], 16)
            if height == 0:
                return {"number": "0x0", "hash": as_hex(GENESIS)}
            if height == CHECKPOINT_HEIGHT:
                return {"number": hex(height), "hash": as_hex(CHECKPOINT_HASH)}
            return None
        if method == "eth_getCode":
            address = params[0]
            if address == "0x" + PROTOCOL_ADDRESS.hex():
                return as_hex(PROTOCOL_CODE)
            if address == "0x" + ASSET_ADDRESS.hex():
                return as_hex(bytes.fromhex("6060604052"))
            return "0x"
        raise AssertionError(method)


class DepositRpc:
    def __init__(self, receipt=None, *, code=PROTOCOL_CODE, failure=False):
        self.receipt = deepcopy(receipt if receipt is not None else make_receipt())
        self.code = code
        self.failure = failure
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if self.failure:
            raise RuntimeError("endpoint token must not escape")
        if method == "eth_getTransactionReceipt":
            return deepcopy(self.receipt)
        if method == "eth_getBlockByNumber":
            height = int(params[0], 16)
            return {
                "number": hex(height),
                "hash": self.receipt["blockHash"],
                "parentHash": as_hex(bytes([0x43]) * 32),
                "receiptsRoot": as_hex(RECEIPTS_ROOT),
                "transactionsRoot": as_hex(bytes([0x99]) * 32),
            }
        if method == "eth_getCode":
            return as_hex(self.code)
        raise AssertionError(method)


class FakeJournal:
    def __init__(self, namespace_id, *, chain_id=CHAIN_ID, accepted=None):
        self.namespace_id = namespace_id
        self.chain_id = chain_id
        self.accepted = set(accepted or {(CHECKPOINT_HEIGHT, CHECKPOINT_HASH)})

    def contains_finalized_header(self, block_number, block_hash):
        return (block_number, block_hash) in self.accepted


def make_receipt(*, status="0x1", block_number=CHECKPOINT_HEIGHT,
                 block_hash=BLOCK_HASH, tx_hash=TX_HASH, log_index=17,
                 address=PROTOCOL_ADDRESS, topic0=TOPIC0, asset=ASSET_ADDRESS,
                 beneficiary=BENEFICIARY, amount=AMOUNT, removed=False):
    log = {
        "address": as_hex(address),
        "topics": [
            as_hex(topic0),
            topic_address(DEPOSITOR),
            topic_address(asset),
            topic_address(beneficiary),
        ],
        "data": as_hex(amount.to_bytes(32, "big")),
        "logIndex": hex(log_index),
        "transactionIndex": "0x2",
        "blockNumber": hex(block_number),
        "blockHash": as_hex(block_hash),
        "transactionHash": as_hex(tx_hash),
        "removed": removed,
    }
    return {
        "transactionHash": as_hex(tx_hash),
        "transactionIndex": "0x2",
        "blockHash": as_hex(block_hash),
        "blockNumber": hex(block_number),
        "status": status,
        "logs": [log],
    }


def make_reader(*, receipt=None, asset_address=ASSET_ADDRESS, code=PROTOCOL_CODE,
                accepted=None, chain_id=CHAIN_ID):
    binding = EvmNamespaceAdapter(
        EvmNamespaceConfig(
            chain_id=CHAIN_ID,
            genesis_hash=GENESIS,
            checkpoint_block_number=CHECKPOINT_HEIGHT,
            checkpoint_hash=CHECKPOINT_HASH,
            protocol_address=PROTOCOL_ADDRESS,
            expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
            asset_address=asset_address,
            expected_asset_code_fingerprint=(
                runtime_code_fingerprint(bytes.fromhex("6060604052"))
                if asset_address is not None else None
            ),
        ),
        NamespaceRpc(),
    ).resolve()
    policy = EvmDepositEvidencePolicy.from_namespace_binding(
        binding, event_topic0=TOPIC0
    )
    providers = [
        DepositRpc(receipt=receipt, code=code),
        DepositRpc(receipt=receipt, code=code),
        DepositRpc(receipt=receipt, code=code),
    ]
    rpc = QuorumJsonRpcTransport({
        "provider-a": providers[0],
        "provider-b": providers[1],
        "provider-c": providers[2],
    })
    journal = FakeJournal(binding.namespace_id, chain_id=chain_id, accepted=accepted)
    reader = EvmDepositEvidenceReader(policy, rpc, journal)
    return binding, policy, rpc, journal, reader


def test_valid_receipt_yields_canonical_quorum_observation_not_authorization():
    binding, _policy, rpc, journal, reader = make_reader()
    observed = reader.inspect(
        transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY
    )
    assert observed.namespace_id == binding.namespace_id
    assert observed.chain_id == CHAIN_ID
    assert observed.amount == AMOUNT
    assert observed.depositor == DEPOSITOR
    assert observed.beneficiary == BENEFICIARY
    assert observed.receipt_log_ordinal == 0
    assert observed.log_index == 17
    assert observed.deposit_id == TX_HASH + (0).to_bytes(4, "big")
    assert observed.finalized_anchor == CHECKPOINT_HEIGHT.to_bytes(8, "big") + BLOCK_HASH
    assert observed.receipts_root == RECEIPTS_ROOT
    assert observed.transactions_root == bytes([0x99]) * 32
    assert observed.assurance_level == "QUORUM_OBSERVED_NOT_CRYPTOGRAPHICALLY_AUTHENTICATED"
    assert len(observed.evidence_digest) == 48
    assert observed.canonical_bytes() == reader.inspect(
        transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY
    ).canonical_bytes()
    assert all(
        ("eth_getCode", ["0x" + PROTOCOL_ADDRESS.hex(), hex(CHECKPOINT_HEIGHT)]) in provider.calls
        for _, provider in rpc._providers
    )
    assert journal.contains_finalized_header(CHECKPOINT_HEIGHT, BLOCK_HASH)


@pytest.mark.parametrize("kwargs,match", [
    ({"status": "0x0"}, "did not succeed"),
    ({"tx_hash": b"\x99" * 32}, "transaction hash"),
    ({"block_hash": b"\x98" * 32}, "not in the durable finalized-header"),
    ({"block_number": CHECKPOINT_HEIGHT + 1}, "not in the durable finalized-header"),
    ({"address": b"\x99" * 20}, "not emitted by the pinned protocol"),
    ({"topic0": b"\x98" * 32}, "event signature topic"),
    ({"asset": b"\x98" * 20}, "asset does not match"),
    ({"beneficiary": b"\x98" * 20}, "beneficiary does not match"),
    ({"amount": 0}, "outside the configured accepted range"),
    ({"removed": True}, "marked removed"),
])
def test_adversarial_receipt_claims_fail_closed(kwargs, match):
    binding, _policy, _rpc, _journal, reader = make_reader(receipt=make_receipt(**kwargs))
    with pytest.raises(EvmDepositEvidenceError, match=match):
        reader.inspect(
            transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY
        )


def test_reader_rejects_log_absence_duplicate_indices_and_metadata_substitution():
    receipt = make_receipt()
    receipt["logs"] = []
    _, _, _, _, reader = make_reader(receipt=receipt)
    with pytest.raises(EvmDepositEvidenceError, match="receipt_log_ordinal is outside"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)

    receipt = make_receipt()
    duplicate = deepcopy(receipt["logs"][0])
    receipt["logs"].append(duplicate)
    _, _, _, _, reader = make_reader(receipt=receipt)
    with pytest.raises(EvmDepositEvidenceError, match="duplicate global log indices"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)

    receipt = make_receipt()
    receipt["logs"][0]["transactionIndex"] = "0x3"
    _, _, _, _, reader = make_reader(receipt=receipt)
    with pytest.raises(EvmDepositEvidenceError, match="metadata does not match"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)


def test_reader_rejects_noncanonical_topics_data_and_amount_overflow():
    receipt = make_receipt()
    receipt["logs"][0]["topics"][2] = topic_address(b"\x98" * 20)
    _, _, _, _, reader = make_reader(receipt=receipt)
    with pytest.raises(EvmDepositEvidenceError, match="asset does not match"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)

    receipt = make_receipt()
    receipt["logs"][0]["data"] = "0x01"
    _, _, _, _, reader = make_reader(receipt=receipt)
    with pytest.raises(EvmDepositEvidenceError, match="exactly 32 bytes"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)

    receipt = make_receipt(amount=1 << 64)
    _, _, _, _, reader = make_reader(receipt=receipt)
    with pytest.raises(EvmDepositEvidenceError, match="outside the configured accepted range"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)


def test_reader_rejects_runtime_code_substitution_and_rpc_failure():
    _, _, _, _, reader = make_reader(code=bytes.fromhex("6001600055"))
    with pytest.raises(EvmDepositEvidenceError, match="runtime code at the deposit block"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)

    _, _, _, _, reader = make_reader()
    for _name, provider in reader._rpc._providers:
        provider.failure = True
    with pytest.raises(EvmDepositEvidenceError, match="quorum transaction receipt"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)


def test_native_asset_requires_zero_address_topic_and_is_encoded_distinctly():
    receipt = make_receipt(asset=bytes(20))
    binding, _, _, _, native_reader = make_reader(receipt=receipt, asset_address=None)
    native = native_reader.inspect(
        transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY
    )
    assert native.asset_address is None
    assert native.namespace_id == binding.namespace_id

    _, _, _, _, token_reader = make_reader(receipt=receipt, asset_address=ASSET_ADDRESS)
    with pytest.raises(EvmDepositEvidenceError, match="asset does not match"):
        token_reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)


def test_reader_input_and_policy_shapes_are_strict():
    _, policy, rpc, journal, reader = make_reader()
    with pytest.raises(ValueError, match="transaction_hash"):
        reader.inspect(transaction_hash=b"short", receipt_log_ordinal=0, expected_beneficiary=BENEFICIARY)
    with pytest.raises(ValueError, match="receipt_log_ordinal"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=True, expected_beneficiary=BENEFICIARY)
    with pytest.raises(ValueError, match="expected_beneficiary"):
        reader.inspect(transaction_hash=TX_HASH, receipt_log_ordinal=0, expected_beneficiary=bytes(20))
    with pytest.raises(ValueError, match="event_topic0"):
        EvmDepositEvidencePolicy.from_namespace_binding(
            EvmNamespaceAdapter(
                EvmNamespaceConfig(
                    chain_id=CHAIN_ID,
                    genesis_hash=GENESIS,
                    checkpoint_block_number=CHECKPOINT_HEIGHT,
                    checkpoint_hash=CHECKPOINT_HASH,
                    protocol_address=PROTOCOL_ADDRESS,
                    expected_protocol_code_fingerprint=runtime_code_fingerprint(PROTOCOL_CODE),
                ),
                NamespaceRpc(),
            ).resolve(),
            event_topic0=b"short",
        )
    wrong_namespace = type(policy)(
        namespace_id=NamespaceIdV3(b"\xaa" * 48),
        chain_id=policy.chain_id,
        deposit_contract_address=policy.deposit_contract_address,
        expected_runtime_code_fingerprint=policy.expected_runtime_code_fingerprint,
        event_topic0=policy.event_topic0,
        asset_address=policy.asset_address,
    )
    with pytest.raises(ValueError, match="namespace differ"):
        EvmDepositEvidenceReader(wrong_namespace, rpc, journal)
