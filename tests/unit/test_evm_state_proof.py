from __future__ import annotations

import pytest

from src.adapters.evm_state_proof import (
    EMPTY_TRIE_ROOT,
    EvmStateProofError,
    solidity_address_mapping_slot,
    verify_eip1186_account_proof,
)
from src.adapters.evm_trie import (
    EthereumEncodingError,
    keccak256,
    rlp_encode_bytes,
    rlp_encode_list,
    rlp_encode_uint,
    verify_mpt_exclusion,
)

ADDRESS = b"\x11" * 20
CODE = b"\x60\x60\x60\x40\x52"
SLOT = b"\x00" * 31 + b"\x07"
STORAGE_VALUE = 42


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


def leaf_node(key: bytes, value: bytes) -> bytes:
    return enc([compact_encode_path(key, leaf=True), value])


def make_header(state_root: bytes, number: int = 7) -> bytes:
    fields = [
        b"\x01" * 32, b"\x02" * 32, b"\x03" * 20, state_root,
        b"\x04" * 32, b"\x05" * 32, bytes(256), b"", bytes([number]),
        b"\x01", b"", b"\x01", b"", b"\x06" * 32, b"\x00" * 8,
    ]
    return enc(fields)


def make_fixture(*, nonce=3, balance=1000, storage_value=STORAGE_VALUE, absent_slot=False):
    code_hash = keccak256(CODE)
    if absent_slot:
        other_key = keccak256(b"\x99" * 32)
        storage_leaf = leaf_node(other_key, rlp_encode_uint(9))
        storage_root = keccak256(storage_leaf)
        storage_proof = [storage_leaf]
        storage_value = 0
    elif storage_value == 0:
        storage_root = EMPTY_TRIE_ROOT
        storage_proof = []
    else:
        storage_leaf = leaf_node(keccak256(SLOT), rlp_encode_uint(storage_value))
        storage_root = keccak256(storage_leaf)
        storage_proof = [storage_leaf]

    account_value = enc([
        rlp_encode_uint(nonce),
        rlp_encode_uint(balance),
        rlp_encode_bytes(storage_root),
        rlp_encode_bytes(code_hash),
    ])
    account_leaf = leaf_node(keccak256(ADDRESS), account_value)
    state_root = keccak256(account_leaf)
    raw_header = make_header(state_root)
    response = {
        "address": "0x" + ADDRESS.hex(),
        "nonce": hex(nonce),
        "balance": hex(balance),
        "storageHash": "0x" + storage_root.hex(),
        "codeHash": "0x" + code_hash.hex(),
        "accountProof": ["0x" + account_leaf.hex()],
        "storageProof": [{
            "key": "0x" + SLOT.hex(),
            "value": hex(storage_value),
            "proof": ["0x" + node.hex() for node in storage_proof],
        }],
    }
    return raw_header, response


def test_verifies_account_and_nonzero_storage_proof_against_header_state_root():
    raw_header, response = make_fixture()
    result = verify_eip1186_account_proof(
        raw_header_rlp=raw_header,
        address=ADDRESS,
        response=response,
        expected_storage_slots=[SLOT],
        runtime_code=CODE,
    )
    assert result.block_number == 7
    assert result.block_hash == keccak256(raw_header)
    assert result.address == ADDRESS
    assert result.nonce == 3
    assert result.balance == 1000
    assert result.code_hash == keccak256(CODE)
    assert result.storage_value(SLOT) == STORAGE_VALUE
    assert result.assurance_level.startswith("EIP1186_ACCOUNT")


def test_verifies_zero_storage_using_authenticated_empty_trie():
    raw_header, response = make_fixture(storage_value=0)
    result = verify_eip1186_account_proof(
        raw_header_rlp=raw_header,
        address=ADDRESS,
        response=response,
        expected_storage_slots=[SLOT],
        runtime_code=CODE,
    )
    assert result.storage_value(SLOT) == 0


def test_verifies_zero_storage_using_divergent_leaf_exclusion_proof():
    raw_header, response = make_fixture(absent_slot=True)
    result = verify_eip1186_account_proof(
        raw_header_rlp=raw_header,
        address=ADDRESS,
        response=response,
        expected_storage_slots=[SLOT],
        runtime_code=CODE,
    )
    assert result.storage_value(SLOT) == 0


@pytest.mark.parametrize("mutation,match", [
    ("address", "differs from the requested account"),
    ("nonce", "account inclusion proof"),
    ("balance", "account inclusion proof"),
    ("storage_root", "account inclusion proof"),
    ("code_hash", "account inclusion proof"),
    ("storage_value", "storage inclusion proof"),
    ("storage_key", "unrequested or duplicate slot"),
    ("runtime_code", "do not match the account's proven codeHash"),
])
def test_rejects_tampered_eip1186_fields_and_code(mutation, match):
    raw_header, response = make_fixture()
    response = dict(response)
    response["storageProof"] = [dict(response["storageProof"][0])]
    runtime_code = CODE
    if mutation == "address":
        response["address"] = "0x" + (b"\x22" * 20).hex()
    elif mutation == "nonce":
        response["nonce"] = "0x4"
    elif mutation == "balance":
        response["balance"] = "0x3e9"
    elif mutation == "storage_root":
        response["storageHash"] = "0x" + (b"\x33" * 32).hex()
    elif mutation == "code_hash":
        response["codeHash"] = "0x" + (b"\x44" * 32).hex()
    elif mutation == "storage_value":
        response["storageProof"][0]["value"] = "0x2b"
    elif mutation == "storage_key":
        response["storageProof"][0]["key"] = "0x" + (b"\x08" * 32).hex()
    elif mutation == "runtime_code":
        runtime_code = b"\x60\x01"
    with pytest.raises(EvmStateProofError, match=match):
        verify_eip1186_account_proof(
            raw_header_rlp=raw_header,
            address=ADDRESS,
            response=response,
            expected_storage_slots=[SLOT],
            runtime_code=runtime_code,
        )


def test_rejects_missing_extra_duplicate_or_noncanonical_storage_proof_entries():
    raw_header, response = make_fixture()
    with pytest.raises(EvmStateProofError, match="exactly one entry"):
        verify_eip1186_account_proof(
            raw_header_rlp=raw_header, address=ADDRESS,
            response={**response, "storageProof": []},
            expected_storage_slots=[SLOT],
        )
    duplicate = dict(response["storageProof"][0])
    with pytest.raises(EvmStateProofError, match="repeats"):
        verify_eip1186_account_proof(
            raw_header_rlp=raw_header, address=ADDRESS,
            response={**response, "storageProof": [response["storageProof"][0], duplicate]},
            expected_storage_slots=[SLOT, SLOT],
        )
    noncanonical = dict(response)
    noncanonical["balance"] = "0x00"
    with pytest.raises(EvmStateProofError, match="canonical"):
        verify_eip1186_account_proof(
            raw_header_rlp=raw_header, address=ADDRESS, response=noncanonical,
            expected_storage_slots=[SLOT],
        )


def test_requires_unique_fixed_width_slots_and_proven_account():
    raw_header, response = make_fixture()
    with pytest.raises(ValueError, match="unique"):
        verify_eip1186_account_proof(
            raw_header_rlp=raw_header, address=ADDRESS, response=response,
            expected_storage_slots=[SLOT, SLOT],
        )
    with pytest.raises(EvmStateProofError, match="account inclusion proof"):
        verify_eip1186_account_proof(
            raw_header_rlp=make_header(b"\x99" * 32), address=ADDRESS,
            response=response, expected_storage_slots=[SLOT],
        )


def test_solidity_address_mapping_slot_uses_left_padded_address_and_uint256_slot():
    actual = solidity_address_mapping_slot(ADDRESS, 7)
    expected = keccak256(bytes(12) + ADDRESS + (7).to_bytes(32, "big"))
    assert actual == expected
    with pytest.raises(ValueError):
        solidity_address_mapping_slot(ADDRESS, True)
    with pytest.raises(ValueError):
        solidity_address_mapping_slot(b"\x01" * 19, 7)
