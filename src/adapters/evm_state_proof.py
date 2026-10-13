"""EIP-1186 account/storage proof verification against an execution state root.

This verifies state claims against a supplied header. Callers must first obtain the
header through the authenticated Helios ancestry journal. State at block boundaries
does not, by itself, prove which transaction caused a state change or that funds
were retained under reviewed contract semantics.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from src.adapters.evm_trie import (
    EthereumEncodingError,
    keccak256,
    rlp_decode,
    rlp_encode_bytes,
    rlp_encode_list,
    rlp_encode_uint,
    rlp_integer,
    verify_mpt_exclusion,
    verify_mpt_inclusion,
)

_HEX_DATA_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_HEX_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")
_U256_MAX = (1 << 256) - 1
EMPTY_TRIE_ROOT = keccak256(rlp_encode_bytes(b""))


class EvmStateProofError(ValueError):
    """Malformed EIP-1186 response or failed state-trie proof."""


@dataclass(frozen=True, slots=True)
class VerifiedEvmAccountState:
    block_number: int
    block_hash: bytes
    state_root: bytes
    address: bytes
    nonce: int
    balance: int
    storage_root: bytes
    code_hash: bytes
    storage_values: tuple[tuple[bytes, int], ...]

    @property
    def assurance_level(self) -> str:
        return "EIP1186_ACCOUNT_AND_REQUESTED_STORAGE_PROOFS_VERIFIED_AGAINST_AUTHENTICATED_HEADER"

    def storage_value(self, slot: bytes) -> int:
        for proven_slot, value in self.storage_values:
            if proven_slot == slot:
                return value
        raise KeyError("storage slot was not requested and verified")


def _quantity(value: object, field: str) -> int:
    if not isinstance(value, str) or _HEX_QUANTITY_RE.fullmatch(value) is None:
        raise EvmStateProofError(f"{field} must be a canonical JSON-RPC QUANTITY")
    number = int(value[2:], 16)
    if number > _U256_MAX:
        raise EvmStateProofError(f"{field} exceeds uint256")
    return number


def _data(value: object, field: str, *, length: int | None = None) -> bytes:
    if not isinstance(value, str) or _HEX_DATA_RE.fullmatch(value) is None:
        raise EvmStateProofError(f"{field} must be canonical even-length JSON-RPC DATA")
    result = bytes.fromhex(value[2:])
    if length is not None and len(result) != length:
        raise EvmStateProofError(f"{field} must be exactly {length} bytes")
    return result


def _proof_nodes(value: object, field: str) -> tuple[bytes, ...]:
    if not isinstance(value, list) or not value:
        raise EvmStateProofError(f"{field} must be a non-empty list of encoded trie nodes")
    nodes = tuple(_data(node, f"{field}[{index}]") for index, node in enumerate(value))
    if any(not node for node in nodes):
        raise EvmStateProofError(f"{field} contains an empty trie node")
    if any(len(node) > 64 * 1024 for node in nodes) or sum(map(len, nodes)) > 2 * 1024 * 1024:
        raise EvmStateProofError(f"{field} exceeds the configured encoded-byte safety bound")
    return nodes


def _header_fields(raw_header_rlp: bytes) -> tuple[int, bytes, bytes]:
    try:
        decoded = rlp_decode(raw_header_rlp)
        if not isinstance(decoded, list) or len(decoded) not in {15, 16, 17, 20, 21}:
            raise EthereumEncodingError("unsupported execution-header field count")
        if any(not isinstance(field, bytes) for field in decoded):
            raise EthereumEncodingError("execution-header fields must be byte strings")
        number = rlp_integer(decoded[8], "header.number")
        if number > (1 << 64) - 1:
            raise EthereumEncodingError("header.number exceeds uint64")
        if len(decoded[3]) != 32:
            raise EthereumEncodingError("header.stateRoot must be 32 bytes")
        return number, keccak256(raw_header_rlp), decoded[3]
    except (EthereumEncodingError, TypeError, ValueError, IndexError) as exc:
        raise EvmStateProofError(f"invalid raw execution header: {exc}") from None


def solidity_address_mapping_slot(address: bytes, mapping_slot: int) -> bytes:
    """Derive keccak256(left_pad32(address) || uint256(mapping_slot)).

    This is correct only when a reviewed Solidity storage layout establishes that
    the mapping is keyed directly by address at the supplied base slot.
    """
    if not isinstance(address, bytes) or len(address) != 20:
        raise ValueError("address must be exactly 20 bytes")
    if isinstance(mapping_slot, bool) or not isinstance(mapping_slot, int) or not 0 <= mapping_slot <= _U256_MAX:
        raise ValueError("mapping_slot must be a uint256 integer")
    return keccak256(bytes(12) + address + mapping_slot.to_bytes(32, "big"))


def verify_eip1186_account_proof(
    *,
    raw_header_rlp: bytes,
    address: bytes,
    response: object,
    expected_storage_slots: tuple[bytes, ...] | list[bytes] = (),
    runtime_code: bytes | None = None,
) -> VerifiedEvmAccountState:
    """Verify an EIP-1186 account proof and the exact requested storage slots.

    raw_header_rlp must come from HeliosAuthenticatedHeaderJournal.authenticate_header,
    not directly from an untrusted JSON-RPC provider. All JSON convenience fields are
    checked against the proven account leaf. A zero storage value must be backed by
    an exclusion proof (or the authenticated empty-trie root), not an invented leaf.
    """
    if not isinstance(address, bytes) or len(address) != 20:
        raise ValueError("address must be exactly 20 bytes")
    if not isinstance(expected_storage_slots, (tuple, list)):
        raise TypeError("expected_storage_slots must be a tuple or list of 32-byte slots")
    slots = tuple(expected_storage_slots)
    if any(not isinstance(slot, bytes) or len(slot) != 32 for slot in slots):
        raise ValueError("each requested storage slot must be exactly 32 bytes")
    if len(slots) > 128:
        raise ValueError("at most 128 storage slots may be requested in one proof")
    if len(set(slots)) != len(slots):
        raise ValueError("requested storage slots must be unique")
    if not isinstance(response, dict):
        raise EvmStateProofError("eth_getProof response must be an object")

    block_number, block_hash, state_root = _header_fields(raw_header_rlp)
    response_address = _data(response.get("address"), "address", length=20)
    if response_address != address:
        raise EvmStateProofError("eth_getProof address differs from the requested account")

    nonce = _quantity(response.get("nonce"), "nonce")
    balance = _quantity(response.get("balance"), "balance")
    storage_root = _data(response.get("storageHash"), "storageHash", length=32)
    code_hash = _data(response.get("codeHash"), "codeHash", length=32)
    account_proof = _proof_nodes(response.get("accountProof"), "accountProof")

    account_value = rlp_encode_list([
        rlp_encode_uint(nonce),
        rlp_encode_uint(balance),
        rlp_encode_bytes(storage_root),
        rlp_encode_bytes(code_hash),
    ])
    try:
        if not verify_mpt_inclusion(state_root, keccak256(address), account_value, account_proof):
            raise EvmStateProofError("account inclusion proof did not verify")
    except EthereumEncodingError as exc:
        raise EvmStateProofError(f"account inclusion proof failed: {exc}") from None

    if runtime_code is not None:
        if not isinstance(runtime_code, bytes):
            raise TypeError("runtime_code must be bytes when supplied")
        if keccak256(runtime_code) != code_hash:
            raise EvmStateProofError("runtime code bytes do not match the account's proven codeHash")

    storage_entries = response.get("storageProof")
    if not isinstance(storage_entries, list) or len(storage_entries) != len(slots):
        raise EvmStateProofError("storageProof must contain exactly one entry per requested slot")
    by_slot: dict[bytes, int] = {}
    for index, entry in enumerate(storage_entries):
        if not isinstance(entry, dict):
            raise EvmStateProofError(f"storageProof[{index}] must be an object")
        slot = _data(entry.get("key"), f"storageProof[{index}].key", length=32)
        if slot not in slots:
            raise EvmStateProofError("storage proof contains an unrequested or duplicate slot")
        if slot in by_slot:
            raise EvmStateProofError("storage proof repeats a requested slot")
        value = _quantity(entry.get("value"), f"storageProof[{index}].value")
        nodes_value = entry.get("proof")
        if storage_root == EMPTY_TRIE_ROOT:
            if nodes_value not in ([], ()):
                raise EvmStateProofError("empty storage trie must not supply fabricated proof nodes")
            if value != 0:
                raise EvmStateProofError("non-zero storage value cannot exist in the empty storage trie")
        else:
            nodes = _proof_nodes(nodes_value, f"storageProof[{index}].proof")
            secure_key = keccak256(slot)
            try:
                if value == 0:
                    if not verify_mpt_exclusion(storage_root, secure_key, nodes):
                        raise EvmStateProofError("zero storage value lacks a valid exclusion proof")
                else:
                    if not verify_mpt_inclusion(storage_root, secure_key, rlp_encode_uint(value), nodes):
                        raise EvmStateProofError("storage inclusion proof did not verify")
            except EthereumEncodingError as exc:
                raise EvmStateProofError(f"storage proof failed: {exc}") from None
        by_slot[slot] = value

    if set(by_slot) != set(slots):
        raise EvmStateProofError("storage proof set does not exactly match requested slots")
    return VerifiedEvmAccountState(
        block_number=block_number,
        block_hash=block_hash,
        state_root=state_root,
        address=address,
        nonce=nonce,
        balance=balance,
        storage_root=storage_root,
        code_hash=code_hash,
        storage_values=tuple((slot, by_slot[slot]) for slot in slots),
    )
