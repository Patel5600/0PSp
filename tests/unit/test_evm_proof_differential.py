from __future__ import annotations

import rlp
import pytest
from eth_hash.auto import keccak as reference_keccak
from trie import HexaryTrie

from src.adapters.evm_state_proof import EMPTY_TRIE_ROOT
from src.adapters.evm_trie import (
    EthereumEncodingError,
    keccak256,
    rlp_decode,
    rlp_encode_bytes,
    rlp_encode_list,
    verify_mpt_exclusion,
    verify_mpt_inclusion,
)


def _ours_encode(value):
    if isinstance(value, bytes):
        return rlp_encode_bytes(value)
    if isinstance(value, (list, tuple)):
        return rlp_encode_list([_ours_encode(item) for item in value])
    raise TypeError(type(value))


def _lists(value):
    if isinstance(value, (list, tuple)):
        return [_lists(item) for item in value]
    return value


def _proof_bytes(decoded_proof):
    return tuple(rlp.encode(_lists(node)) for node in decoded_proof)


@pytest.mark.parametrize("length", [0, 1, 2, 31, 32, 55, 56, 57, 135, 136, 137, 255, 1024, 4096])
def test_keccak_matches_independent_eth_hash_implementation(length):
    data = bytes((index * 31 + 7) & 0xFF for index in range(length))
    assert keccak256(data) == reference_keccak(data)


@pytest.mark.parametrize("value", [
    b"",
    b"\x00",
    b"\x7f",
    b"\x80",
    b"\xff",
    b"x" * 55,
    b"x" * 56,
    b"x" * 255,
    bytes(range(256)),
    [b"", b"\x01", [b"nested", b"\x80"]],
    [b"a" * 60, [b"b" * 70, [b"c" * 90]]],
])
def test_rlp_encoder_and_decoder_match_independent_rlp_library(value):
    expected = rlp.encode(value)
    assert _ours_encode(value) == expected
    assert rlp_decode(expected) == rlp.decode(expected, strict=True)


def test_empty_trie_root_matches_independent_hexary_trie():
    assert HexaryTrie({}).root_hash == EMPTY_TRIE_ROOT
    assert EMPTY_TRIE_ROOT == reference_keccak(rlp.encode(b""))


def test_inclusion_proofs_from_independent_hexary_trie_match_local_verifier():
    trie = HexaryTrie({})
    entries = {
        keccak256(b"account:alice"): b"account-leaf-value",
        keccak256(b"account:bob"): b"another-account-value",
        keccak256(b"storage:slot-1"): rlp.encode(b"\x2a"),
        keccak256(b"storage:slot-2"): rlp.encode(b"\x01\x00"),
        keccak256(b"long-value"): bytes((i * 13) & 0xFF for i in range(512)),
    }
    for key, value in entries.items():
        trie[key] = value

    for key, value in entries.items():
        proof = _proof_bytes(trie.get_proof(key))
        assert verify_mpt_inclusion(trie.root_hash, key, value, proof)


def test_absence_proofs_from_independent_hexary_trie_match_local_verifier():
    trie = HexaryTrie({})
    for label in (b"a", b"b", b"c", b"alpha", b"omega", b"long" * 20):
        trie[keccak256(label)] = b"value:" + label

    for missing in (keccak256(b"missing"), keccak256(b"delta"), keccak256(b"absent" * 8)):
        proof = _proof_bytes(trie.get_proof(missing))
        assert verify_mpt_exclusion(trie.root_hash, missing, proof)


def test_embedded_and_hashed_child_proofs_are_cross_checked_against_hexary_trie():
    trie = HexaryTrie({})
    for index in range(24):
        key = keccak256(b"key-" + index.to_bytes(2, "big"))
        value = (b"v" + index.to_bytes(2, "big")) if index % 2 else bytes([index]) * 100
        trie[key] = value

    for index in (0, 1, 7, 12, 23):
        key = keccak256(b"key-" + index.to_bytes(2, "big"))
        proof = _proof_bytes(trie.get_proof(key))
        assert verify_mpt_inclusion(trie.root_hash, key, trie[key], proof)


def test_differential_fixture_proof_tampering_fails_closed():
    trie = HexaryTrie({})
    key = keccak256(b"protected-key")
    value = b"authentic-value"
    trie[key] = value
    proof = list(_proof_bytes(trie.get_proof(key)))
    assert verify_mpt_inclusion(trie.root_hash, key, value, proof)
    with pytest.raises(EthereumEncodingError):
        verify_mpt_inclusion(trie.root_hash, key, b"substituted-value", proof)
    with pytest.raises(EthereumEncodingError):
        verify_mpt_inclusion(b"\x99" * 32, key, value, proof)
