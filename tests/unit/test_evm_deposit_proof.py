from __future__ import annotations

import pytest

from src.adapters.evm_deposit_evidence import EvmDepositEvidencePolicy
from src.adapters.evm_deposit_proof import (
    EvmDepositInclusionError,
    EvmDepositInclusionVerifier,
)
from src.adapters.evm_trie import (
    keccak256,
    rlp_decode,
    rlp_encode_bytes,
    rlp_encode_list,
    rlp_encode_uint,
)
from src.primitives.namespace_v3 import NamespaceIdV3

CHAIN_ID = 1
NS = NamespaceIdV3(b"\x11" * 48)
CONTRACT = b"\x22" * 20
ASSET = b"\x33" * 20
TOPIC0 = b"\x44" * 32
DEPOSITOR = b"\x55" * 20
BENEFICIARY = b"\x66" * 20
AMOUNT = 12345
INDEX = 2
BLOCK_NUMBER = 7


def enc(value):
    if isinstance(value, bytes):
        return rlp_encode_bytes(value)
    if isinstance(value, list):
        return rlp_encode_list([enc(item) for item in value])
    raise TypeError(value)


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


def leaf_proof(key: bytes, value: bytes):
    node = enc([compact_encode_path(key, leaf=True), value])
    return keccak256(node), [node]


def topic_address(address: bytes) -> bytes:
    return bytes(12) + address


class Journal:
    def __init__(self, block_hash):
        self.namespace_id = NS
        self.chain_id = CHAIN_ID
        self.accepted = {(BLOCK_NUMBER, block_hash)}

    def contains_finalized_header(self, block_number, block_hash):
        return (block_number, block_hash) in self.accepted


def make_case(*, beneficiary=BENEFICIARY, amount=AMOUNT, receipt_status=b"\x01", tx_type=None):
    topics = [TOPIC0, topic_address(DEPOSITOR), topic_address(ASSET), topic_address(beneficiary)]
    log = [CONTRACT, topics, amount.to_bytes(32, "big")]
    receipt_payload = [receipt_status, b"\x52\x08", bytes(256), [log]]
    if tx_type is None:
        raw_receipt = enc(receipt_payload)
        raw_tx = enc([b"", b"\x01", b"\x52\x08", CONTRACT, b"", b"", b"\x1c", b"\x01", b"\x01"])
    else:
        raw_receipt = bytes([tx_type]) + enc(receipt_payload)
        raw_tx = bytes([tx_type]) + enc([b"\x01"] * {1: 11, 2: 12, 3: 14, 4: 13}[tx_type])
    key = rlp_encode_uint(INDEX)
    tx_root, tx_proof = leaf_proof(key, raw_tx)
    receipt_root, receipt_proof = leaf_proof(key, raw_receipt)
    header_fields = [
        b"\x01" * 32, b"\x02" * 32, b"\x03" * 20, b"\x04" * 32,
        tx_root, receipt_root, bytes(256), b"\x01", BLOCK_NUMBER.to_bytes(1, "big"),
        b"\x01", b"\x01", b"\x01", b"", b"\x05" * 32, b"\x00" * 8,
    ]
    raw_header = enc(header_fields)
    block_hash = keccak256(raw_header)
    policy = EvmDepositEvidencePolicy(
        namespace_id=NS,
        chain_id=CHAIN_ID,
        deposit_contract_address=CONTRACT,
        expected_runtime_code_fingerprint=b"\x77" * 48,
        event_topic0=TOPIC0,
        asset_address=ASSET,
    )
    journal = Journal(block_hash)
    verifier = EvmDepositInclusionVerifier(policy, journal)
    args = dict(
        raw_header_rlp=raw_header,
        raw_transaction=raw_tx,
        transaction_proof=tx_proof,
        raw_receipt=raw_receipt,
        receipt_proof=receipt_proof,
        transaction_index=INDEX,
        receipt_log_ordinal=0,
        expected_beneficiary=BENEFICIARY,
    )
    return verifier, args, block_hash, raw_tx, raw_receipt, tx_proof, receipt_proof


def test_verifies_transaction_and_receipt_trie_inclusion_against_journaled_header():
    verifier, args, block_hash, raw_tx, _raw_receipt, _tp, _rp = make_case()
    result = verifier.verify(**args)
    tx_hash = keccak256(raw_tx)
    assert result.namespace_id == NS
    assert result.chain_id == CHAIN_ID
    assert result.transaction_hash == tx_hash
    assert result.transaction_index == INDEX
    assert result.receipt_log_ordinal == 0
    assert result.block_number == BLOCK_NUMBER
    assert result.block_hash == block_hash
    assert result.finalized_anchor == BLOCK_NUMBER.to_bytes(8, "big") + block_hash
    assert result.deposit_id == tx_hash + b"\x00\x00\x00\x00"
    assert result.depositor == DEPOSITOR
    assert result.beneficiary == BENEFICIARY
    assert result.amount == AMOUNT
    assert result.assurance_level == "TRIE_INCLUSION_VERIFIED_AGAINST_QUORUM_FINALIZED_HEADER"


@pytest.mark.parametrize("mutation,match", [
    ("transaction", "node hash|leaf value"),
    ("receipt", "node hash|leaf value"),
    ("header", "not present in the durable finalized-header"),
    ("index", "node hash|compact path"),
    ("beneficiary", "proven beneficiary"),
])
def test_rejects_proof_or_public_field_substitution(mutation, match):
    verifier, args, _hash, _tx, _receipt, _tp, _rp = make_case()
    args = dict(args)
    if mutation == "transaction":
        args["raw_transaction"] = enc([b"\x02"] * 9)
    elif mutation == "receipt":
        args["raw_receipt"] = enc([b"\x01", b"\x52\x08", bytes(256), []])
    elif mutation == "header":
        header_fields = rlp_decode(args["raw_header_rlp"])
        header_fields[11] = b"\x02"
        args["raw_header_rlp"] = enc(header_fields)
    elif mutation == "index":
        args["transaction_index"] = INDEX + 1
    elif mutation == "beneficiary":
        args["expected_beneficiary"] = b"\x99" * 20
    with pytest.raises(EvmDepositInclusionError, match=match):
        verifier.verify(**args)


def test_rejects_wrong_log_ordinal_failed_receipt_and_amount_overflow():
    verifier, args, *_ = make_case()
    with pytest.raises(EvmDepositInclusionError, match="outside the proven receipt logs"):
        verifier.verify(**{**args, "receipt_log_ordinal": 1})

    failed, failed_args, *_ = make_case(receipt_status=b"")
    with pytest.raises(EvmDepositInclusionError, match="status is not successful"):
        failed.verify(**failed_args)

    overflow, overflow_args, *_ = make_case(amount=1 << 64)
    with pytest.raises(EvmDepositInclusionError, match="outside the accepted range"):
        overflow.verify(**overflow_args)


@pytest.mark.parametrize("tx_type", [1, 2])
def test_supports_matching_known_typed_transaction_and_receipt_envelopes(tx_type):
    verifier, args, *_ = make_case(tx_type=tx_type)
    result = verifier.verify(**args)
    assert result.amount == AMOUNT


def test_rejects_mismatched_typed_transaction_and_receipt_envelopes():
    verifier, args, *_ = make_case(tx_type=2)
    args["raw_receipt"] = b"\x01" + args["raw_receipt"][1:]
    with pytest.raises(EvmDepositInclusionError, match="receipt trie inclusion|envelope types differ"):
        verifier.verify(**args)


def test_rejects_unjournaled_header_and_noncanonical_header_rlp():
    verifier, args, *_ = make_case()
    header_fields = rlp_decode(args["raw_header_rlp"])
    header_fields[11] = b"\x02"
    with pytest.raises(EvmDepositInclusionError, match="not present in the durable finalized-header"):
        verifier.verify(**{**args, "raw_header_rlp": enc(header_fields)})
    with pytest.raises(EvmDepositInclusionError, match="invalid raw execution header"):
        verifier.verify(**{**args, "raw_header_rlp": b"\x81\x01"})
