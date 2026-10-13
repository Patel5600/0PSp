"""Strict Ethereum RLP, Keccak-256, and Merkle-Patricia inclusion primitives.

Research implementation: this module verifies an inclusion path against a supplied
root. It does not authenticate that root as a canonical/finalized chain header.
"""
from __future__ import annotations

from collections.abc import Sequence

_MASK64 = (1 << 64) - 1
_RATE_KECCAK256 = 136
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


class EthereumEncodingError(ValueError):
    """An RLP or trie proof is malformed or non-canonical."""


def _rol64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state: list[int]) -> None:
    for rc in _ROUND_CONSTANTS:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for y in range(5):
            for x in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(state[x + 5 * y], _ROTATION[x][y])
        for y in range(5):
            row = 5 * y
            for x in range(5):
                state[row + x] = b[row + x] ^ ((~b[row + (x + 1) % 5]) & b[row + (x + 2) % 5])
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256 (legacy 0x01 padding), not hashlib.sha3_256."""
    if not isinstance(data, bytes):
        raise TypeError("Keccak-256 input must be bytes")
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(bytes((_RATE_KECCAK256 - (len(padded) % _RATE_KECCAK256)) % _RATE_KECCAK256))
    padded[-1] ^= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), _RATE_KECCAK256):
        block = padded[offset:offset + _RATE_KECCAK256]
        for i in range(_RATE_KECCAK256 // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(word.to_bytes(8, "little") for word in state)[:32]


def rlp_encode_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("RLP byte string input must be bytes")
    if len(value) == 1 and value[0] < 0x80:
        return value
    if len(value) <= 55:
        return bytes([0x80 + len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(length)]) + length + value


def rlp_encode_list(items: Sequence[bytes]) -> bytes:
    if not isinstance(items, (list, tuple)) or any(not isinstance(item, bytes) for item in items):
        raise TypeError("RLP list encoder expects a sequence of already encoded items")
    payload = b"".join(items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + payload


def rlp_encode_uint(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("RLP integer must be a non-negative integer")
    if value == 0:
        return rlp_encode_bytes(b"")
    return rlp_encode_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _read_length(data: bytes, offset: int, length_of_length: int) -> tuple[int, int]:
    end = offset + length_of_length
    if length_of_length < 1 or end > len(data):
        raise EthereumEncodingError("RLP length-of-length is truncated")
    raw = data[offset:end]
    if raw[0] == 0:
        raise EthereumEncodingError("RLP length is not minimally encoded")
    length = int.from_bytes(raw, "big")
    if length < 56:
        raise EthereumEncodingError("RLP long form used for payload shorter than 56 bytes")
    return length, end


def _decode_one(data: bytes, offset: int, depth: int, max_depth: int) -> tuple[bytes | list[object], int]:
    if depth > max_depth:
        raise EthereumEncodingError("RLP nesting depth exceeds configured bound")
    if offset >= len(data):
        raise EthereumEncodingError("RLP item is truncated")
    prefix = data[offset]
    if prefix <= 0x7F:
        return bytes([prefix]), offset + 1
    if prefix <= 0xB7:
        length = prefix - 0x80
        start, end = offset + 1, offset + 1 + length
        if end > len(data):
            raise EthereumEncodingError("RLP string is truncated")
        raw = data[start:end]
        if length == 1 and raw[0] < 0x80:
            raise EthereumEncodingError("RLP single byte used a non-canonical string prefix")
        return raw, end
    if prefix <= 0xBF:
        length, start = _read_length(data, offset + 1, prefix - 0xB7)
        end = start + length
        if end > len(data):
            raise EthereumEncodingError("RLP long string is truncated")
        return data[start:end], end
    if prefix <= 0xF7:
        length, start = prefix - 0xC0, offset + 1
    else:
        length, start = _read_length(data, offset + 1, prefix - 0xF7)
    end = start + length
    if end > len(data):
        raise EthereumEncodingError("RLP list is truncated")
    items: list[object] = []
    cursor = start
    while cursor < end:
        item, cursor = _decode_one(data, cursor, depth + 1, max_depth)
        items.append(item)
    if cursor != end:
        raise EthereumEncodingError("RLP list payload length mismatch")
    return items, end


def rlp_decode(data: bytes, *, max_depth: int = 64) -> bytes | list[object]:
    """Decode exactly one canonical RLP item; reject trailing bytes and truncation."""
    if not isinstance(data, bytes):
        raise TypeError("RLP input must be bytes")
    if not data:
        raise EthereumEncodingError("RLP input is empty")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")
    value, end = _decode_one(data, 0, 0, max_depth)
    if end != len(data):
        raise EthereumEncodingError("RLP input contains trailing bytes")
    return value


def rlp_integer(value: object, field: str) -> int:
    if not isinstance(value, bytes):
        raise EthereumEncodingError(f"{field} must be an RLP byte string")
    if value and value[0] == 0:
        raise EthereumEncodingError(f"{field} integer is not minimally encoded")
    return int.from_bytes(value, "big")


def bytes_to_nibbles(value: bytes) -> tuple[int, ...]:
    return tuple(n for byte in value for n in (byte >> 4, byte & 0x0F))


def compact_decode_path(encoded: bytes) -> tuple[bool, tuple[int, ...]]:
    if not isinstance(encoded, bytes) or not encoded:
        raise EthereumEncodingError("hex-prefix path must be a non-empty byte string")
    nibbles = bytes_to_nibbles(encoded)
    flag = nibbles[0]
    if flag > 3:
        raise EthereumEncodingError("hex-prefix path has invalid flag nibble")
    is_leaf = bool(flag & 2)
    odd = bool(flag & 1)
    if not odd and nibbles[1] != 0:
        raise EthereumEncodingError("even hex-prefix path has non-zero padding nibble")
    path = nibbles[1:] if odd else nibbles[2:]
    return is_leaf, path


def _child_reference(value: object) -> bytes:
    if isinstance(value, bytes):
        if value and len(value) != 32:
            raise EthereumEncodingError("trie child reference must be empty, a 32-byte hash, or an embedded node")
        return value
    if isinstance(value, list):
        encoded = rlp_encode_list([_encode_decoded(item) for item in value])
        if len(encoded) >= 32:
            raise EthereumEncodingError("embedded trie child must encode to fewer than 32 bytes")
        return encoded
    raise EthereumEncodingError("invalid trie child reference type")


def _encode_decoded(value: object) -> bytes:
    if isinstance(value, bytes):
        return rlp_encode_bytes(value)
    if isinstance(value, list):
        return rlp_encode_list([_encode_decoded(item) for item in value])
    raise EthereumEncodingError("invalid decoded RLP value")


def verify_mpt_inclusion(root_hash: bytes, key: bytes, expected_value: bytes, proof_nodes: Sequence[bytes]) -> bool:
    """Verify a Merkle-Patricia trie inclusion proof against a supplied root.

    The proof is a sequence of raw RLP-encoded trie nodes. Extra nodes, malformed
    nodes, non-canonical RLP, wrong child references and mismatched leaf values
    are rejected. This function authenticates membership relative to root_hash;
    it does not authenticate the source or finality of that root.
    """
    if not isinstance(root_hash, bytes) or len(root_hash) != 32:
        raise ValueError("root_hash must be exactly 32 bytes")
    if not isinstance(key, bytes) or not isinstance(expected_value, bytes):
        raise TypeError("key and expected_value must be bytes")
    if len(key) > 1024:
        raise ValueError("trie key exceeds the 1024-byte safety bound")
    if not expected_value:
        raise ValueError("Ethereum trie inclusion value must be non-empty")
    if not isinstance(proof_nodes, (list, tuple)) or not proof_nodes:
        raise ValueError("proof_nodes must be a non-empty list or tuple")
    if len(proof_nodes) > 128:
        raise ValueError("proof contains more than 128 trie nodes")
    if any(not isinstance(node, bytes) or not node for node in proof_nodes):
        raise ValueError("each proof node must be non-empty encoded bytes")
    path = bytes_to_nibbles(key)
    path_offset = 0
    expected_ref = root_hash
    for node_index, encoded_node in enumerate(proof_nodes):
        if len(expected_ref) == 32:
            if node_index > 0 and len(encoded_node) < 32:
                raise EthereumEncodingError("short trie child must be embedded rather than hash-referenced")
            if keccak256(encoded_node) != expected_ref:
                raise EthereumEncodingError("trie proof node hash does not match its parent reference")
        elif encoded_node != expected_ref:
            raise EthereumEncodingError("embedded trie proof node does not match its parent reference")
        decoded = rlp_decode(encoded_node)
        if not isinstance(decoded, list):
            raise EthereumEncodingError("trie node must be an RLP list")
        if len(decoded) == 17:
            if path_offset == len(path):
                value = decoded[16]
                if not isinstance(value, bytes) or value != expected_value:
                    raise EthereumEncodingError("branch node value does not match expected trie value")
                if node_index != len(proof_nodes) - 1:
                    raise EthereumEncodingError("trie proof contains unused trailing nodes")
                return True
            child = _child_reference(decoded[path[path_offset]])
            if not child:
                raise EthereumEncodingError("trie branch does not contain the requested key")
            path_offset += 1
            expected_ref = child
            continue
        if len(decoded) == 2:
            encoded_path, child_or_value = decoded
            if not isinstance(encoded_path, bytes):
                raise EthereumEncodingError("trie compact path must be a byte string")
            is_leaf, partial_path = compact_decode_path(encoded_path)
            if not is_leaf and not partial_path:
                raise EthereumEncodingError("trie extension path must not be empty")
            if path[path_offset:path_offset + len(partial_path)] != partial_path:
                raise EthereumEncodingError("trie compact path does not match the requested key")
            path_offset += len(partial_path)
            if is_leaf:
                if path_offset != len(path):
                    raise EthereumEncodingError("trie leaf ends before the requested key")
                if not isinstance(child_or_value, bytes) or child_or_value != expected_value:
                    raise EthereumEncodingError("trie leaf value does not match expected value")
                if node_index != len(proof_nodes) - 1:
                    raise EthereumEncodingError("trie proof contains unused trailing nodes")
                return True
            expected_ref = _child_reference(child_or_value)
            if not expected_ref:
                raise EthereumEncodingError("trie extension has an empty child")
            continue
        raise EthereumEncodingError("trie node must contain 2 or 17 elements")
    raise EthereumEncodingError("trie proof ended before an inclusion value was reached")


def verify_mpt_exclusion(root_hash: bytes, key: bytes, proof_nodes: Sequence[bytes]) -> bool:
    """Verify that a key is absent from a Merkle-Patricia trie.

    A valid absence proof terminates at an authenticated empty branch child, a
    divergent extension/leaf path, or the empty-trie root. It must not contain
    unused trailing nodes. This is a proof relative to root_hash only.
    """
    if not isinstance(root_hash, bytes) or len(root_hash) != 32:
        raise ValueError("root_hash must be exactly 32 bytes")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(proof_nodes, (list, tuple)):
        raise TypeError("proof_nodes must be a list or tuple")
    if len(key) > 1024:
        raise ValueError("key exceeds the configured 1024-byte proof bound")
    if len(proof_nodes) > 128:
        raise ValueError("proof contains more than 128 nodes")
    if any(not isinstance(node, bytes) or not node for node in proof_nodes):
        raise ValueError("each supplied proof node must be non-empty encoded bytes")
    if root_hash == keccak256(rlp_encode_bytes(b"")):
        if proof_nodes:
            raise EthereumEncodingError("empty trie root must use an empty absence proof")
        return True
    if not proof_nodes:
        raise EthereumEncodingError("non-empty trie requires an absence proof path")

    path = bytes_to_nibbles(key)
    path_offset = 0
    expected_ref = root_hash

    def finish_absence(node_index: int) -> bool:
        if node_index != len(proof_nodes) - 1:
            raise EthereumEncodingError("trie absence proof contains unused trailing nodes")
        return True

    for node_index, encoded_node in enumerate(proof_nodes):
        if len(expected_ref) == 32:
            if node_index > 0 and len(encoded_node) < 32:
                raise EthereumEncodingError("short trie child must be embedded rather than hash-referenced")
            if keccak256(encoded_node) != expected_ref:
                raise EthereumEncodingError("trie proof node hash does not match its parent reference")
        elif encoded_node != expected_ref:
            raise EthereumEncodingError("embedded trie proof node does not match its parent reference")

        decoded = rlp_decode(encoded_node)
        if not isinstance(decoded, list):
            raise EthereumEncodingError("trie node must be an RLP list")

        if len(decoded) == 17:
            if path_offset == len(path):
                value = decoded[16]
                if not isinstance(value, bytes):
                    raise EthereumEncodingError("branch value must be a byte string")
                if value:
                    raise EthereumEncodingError("absence proof reaches an existing branch value")
                return finish_absence(node_index)
            child = _child_reference(decoded[path[path_offset]])
            if not child:
                return finish_absence(node_index)
            path_offset += 1
            expected_ref = child
            continue

        if len(decoded) == 2:
            encoded_path, child_or_value = decoded
            if not isinstance(encoded_path, bytes):
                raise EthereumEncodingError("trie compact path must be a byte string")
            is_leaf, partial_path = compact_decode_path(encoded_path)
            remaining = path[path_offset:]
            common = min(len(remaining), len(partial_path))
            if remaining[:common] != partial_path[:common]:
                return finish_absence(node_index)
            if len(remaining) < len(partial_path):
                return finish_absence(node_index)
            path_offset += len(partial_path)
            if is_leaf:
                if path_offset == len(path):
                    raise EthereumEncodingError("absence proof reaches an existing leaf value")
                return finish_absence(node_index)
            expected_ref = _child_reference(child_or_value)
            if not expected_ref:
                raise EthereumEncodingError("trie extension has an empty child")
            continue

        raise EthereumEncodingError("trie node must contain 2 or 17 elements")

    raise EthereumEncodingError("trie absence proof ended before absence was established")
