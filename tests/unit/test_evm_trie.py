from __future__ import annotations

import pytest

from src.adapters.evm_trie import (
    EthereumEncodingError,
    compact_decode_path,
    keccak256,
    rlp_decode,
    rlp_encode_bytes,
    rlp_encode_list,
    rlp_encode_uint,
    verify_mpt_inclusion,
)


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
    node = rlp_encode_list([
        rlp_encode_bytes(compact_encode_path(key, leaf=True)),
        rlp_encode_bytes(value),
    ])
    return keccak256(node), [node]


def test_ethereum_keccak256_known_vectors_are_not_sha3_256():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


@pytest.mark.parametrize("value", [b"", b"\x00", b"\x7f", b"hello", b"x" * 56, bytes(range(256))])
def test_rlp_roundtrip_canonical_byte_strings(value):
    assert rlp_decode(rlp_encode_bytes(value)) == value


def test_rlp_integer_encoding_is_canonical_for_trie_keys():
    assert rlp_encode_uint(0) == b"\x80"
    assert rlp_encode_uint(1) == b"\x01"
    assert rlp_encode_uint(127) == b"\x7f"
    assert rlp_encode_uint(128) == b"\x81\x80"
    with pytest.raises(ValueError):
        rlp_encode_uint(True)


@pytest.mark.parametrize("encoded", [
    b"",
    b"\x81\x01",  # single byte encoded with an unnecessary string prefix
    b"\xb8\x01x",  # long string form below 56 bytes
    b"\xb9\x00\x38" + b"x" * 56,  # leading zero in length-of-length
    b"\x82x",  # truncated string
    b"\xc2\x01",  # truncated list
    b"\x01\x02",  # trailing bytes
])
def test_rlp_rejects_malformed_or_noncanonical_input(encoded):
    with pytest.raises(EthereumEncodingError):
        rlp_decode(encoded)


def test_hex_prefix_path_even_odd_extension_and_leaf_flags():
    for key in (b"", b"\x00", b"\x01", b"\x12\x34", b"\xff\x00\x0a"):
        for leaf in (False, True):
            encoded = compact_encode_path(key, leaf=leaf)
            assert compact_decode_path(encoded) == (
                leaf, tuple(n for byte in key for n in (byte >> 4, byte & 15))
            )


def test_single_leaf_mpt_inclusion_and_adversarial_substitution():
    key = rlp_encode_uint(7)
    value = b"authenticated receipt bytes"
    root, proof = leaf_proof(key, value)
    assert verify_mpt_inclusion(root, key, value, proof)
    with pytest.raises(EthereumEncodingError, match="leaf value"):
        verify_mpt_inclusion(root, key, b"substituted", proof)
    with pytest.raises(EthereumEncodingError, match="node hash"):
        verify_mpt_inclusion(b"\x00" * 32, key, value, proof)
    with pytest.raises(EthereumEncodingError, match="compact path"):
        verify_mpt_inclusion(root, rlp_encode_uint(8), value, proof)
    with pytest.raises(EthereumEncodingError, match="unused trailing"):
        verify_mpt_inclusion(root, key, value, proof + proof)


def test_mpt_rejects_empty_and_wrong_shape_proofs():
    with pytest.raises(ValueError, match="non-empty"):
        verify_mpt_inclusion(b"\x00" * 32, b"k", b"v", [])
    root, proof = leaf_proof(b"k", b"v")
    malformed = [rlp_encode_list([rlp_encode_bytes(b"not-a-valid-path"), rlp_encode_bytes(b"v"), rlp_encode_bytes(b"extra")])]
    with pytest.raises(EthereumEncodingError):
        verify_mpt_inclusion(root, b"k", b"v", malformed)

@pytest.mark.parametrize("value", [b"small", b"V" * 80])
def test_branch_node_verifies_embedded_and_hashed_child_references(value):
    key = b"\x12"  # nibble path [1, 2]
    leaf = rlp_encode_list([
        rlp_encode_bytes(bytes([0x32])),  # odd leaf path: flag 3, nibble 2
        rlp_encode_bytes(value),
    ])
    branch_items = [rlp_encode_bytes(b"") for _ in range(17)]
    if len(leaf) < 32:
        branch_items[1] = leaf  # Embedded child is an RLP list, not a byte string.
    else:
        branch_items[1] = rlp_encode_bytes(keccak256(leaf))
    branch = rlp_encode_list(branch_items)
    assert verify_mpt_inclusion(keccak256(branch), key, value, [branch, leaf])


def test_branch_node_rejects_missing_nibble_child():
    key = b"\x12"
    branch = rlp_encode_list([rlp_encode_bytes(b"") for _ in range(17)])
    with pytest.raises(EthereumEncodingError, match="does not contain"):
        verify_mpt_inclusion(keccak256(branch), key, b"value", [branch])

def test_mpt_enforces_bounded_proof_and_key_sizes():
    root, proof = leaf_proof(b"k", b"value")
    with pytest.raises(ValueError, match="key exceeds"):
        verify_mpt_inclusion(root, b"k" * 1025, b"value", proof)
    with pytest.raises(ValueError, match="must be non-empty"):
        verify_mpt_inclusion(root, b"k", b"", proof)
    with pytest.raises(ValueError, match="more than 128"):
        verify_mpt_inclusion(root, b"k", b"value", proof * 129)
