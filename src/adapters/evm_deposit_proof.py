"""Cryptographic transaction/receipt inclusion checks for the EVM deposit boundary.

This verifies raw transaction and typed/legacy receipt values against Merkle-Patricia
proofs and roots extracted from the exact header RLP whose hash is present in the
durable finalized-header journal. The journal currently reflects RPC quorum, not
authenticated chain consensus, so this module does NOT produce DepositAuthorization.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Protocol

from src.adapters.evm_deposit_evidence import (
    EvmDepositEvidenceError,
    EvmDepositEvidencePolicy,
    ZERO_ADDRESS,
    _address_topic,
)
from src.adapters.evm_trie import (
    EthereumEncodingError,
    keccak256,
    rlp_decode,
    rlp_encode_uint,
    rlp_integer,
    verify_mpt_inclusion,
)
from src.adapters.evm_namespace import EVM_ADDRESS_BYTES, EVM_HASH_BYTES
from src.primitives.namespace_v3 import NamespaceIdV3

U64_MAX = (1 << 64) - 1
KNOWN_TYPED_ENVELOPES = frozenset({1, 2, 3, 4})
_TYPED_TRANSACTION_FIELD_COUNTS = {1: 11, 2: 12, 3: 14, 4: 13}


class EvmDepositInclusionError(RuntimeError):
    """Raw transaction, receipt, trie proof, header, or deposit event is invalid."""


class FinalizedHeaderLookup(Protocol):
    def contains_finalized_header(self, block_number: int, block_hash: bytes) -> bool:
        """Return true only for exact header membership in the durable ancestry journal."""


@dataclass(frozen=True, slots=True)
class ProvenEvmDepositInclusion:
    """Trie-proven deposit facts relative to a journaled header, not consensus-authenticated."""

    namespace_id: NamespaceIdV3
    chain_id: int
    deposit_id: bytes
    transaction_hash: bytes
    transaction_index: int
    receipt_log_ordinal: int
    block_number: int
    block_hash: bytes
    finalized_anchor: bytes
    deposit_contract_address: bytes
    asset_address: bytes | None
    depositor: bytes
    beneficiary: bytes
    amount: int

    @property
    def assurance_level(self) -> str:
        return "TRIE_INCLUSION_VERIFIED_AGAINST_QUORUM_FINALIZED_HEADER"


@dataclass(frozen=True, slots=True)
class _Envelope:
    tx_type: int | None
    payload: list[object]


@dataclass(frozen=True, slots=True)
class _Receipt:
    status: int
    logs: tuple[tuple[bytes, tuple[bytes, ...], bytes], ...]


def _envelope(raw: bytes, field: str) -> _Envelope:
    if not isinstance(raw, bytes) or not raw:
        raise EvmDepositInclusionError(f"{field} must be non-empty raw bytes")
    if raw[0] >= 0xC0:
        decoded = rlp_decode(raw)
        tx_type = None
    elif 1 <= raw[0] <= 0x7F:
        tx_type = raw[0]
        if tx_type not in KNOWN_TYPED_ENVELOPES:
            raise EvmDepositInclusionError(f"{field} uses an unsupported typed envelope")
        decoded = rlp_decode(raw[1:])
    else:
        raise EvmDepositInclusionError(f"{field} has an invalid EIP-2718 envelope prefix")
    if not isinstance(decoded, list):
        raise EvmDepositInclusionError(f"{field} envelope payload must be an RLP list")
    if field == "raw transaction":
        expected_count = 9 if tx_type is None else _TYPED_TRANSACTION_FIELD_COUNTS[tx_type]
        if len(decoded) != expected_count:
            raise EvmDepositInclusionError(
                f"{field} envelope has {len(decoded)} fields; expected {expected_count} for its type"
            )
    return _Envelope(tx_type=tx_type, payload=decoded)


def _parse_header(raw_header_rlp: bytes) -> tuple[int, bytes, bytes, bytes]:
    try:
        decoded = rlp_decode(raw_header_rlp)
        if not isinstance(decoded, list) or len(decoded) not in {15, 16, 17, 20, 21}:
            raise EthereumEncodingError("block header field count is not a supported pre-London through Prague schema")
        if any(not isinstance(field, bytes) for field in decoded):
            raise EthereumEncodingError("block header fields must all be RLP byte strings")
        fixed_lengths = {0: 32, 1: 32, 2: 20, 3: 32, 4: 32, 5: 32, 6: 256, 13: 32, 14: 8}
        for index, expected_length in fixed_lengths.items():
            if len(decoded[index]) != expected_length:
                raise EthereumEncodingError(f"header field {index} must be exactly {expected_length} bytes")
        if len(decoded[12]) > 32:
            raise EthereumEncodingError("header.extraData must not exceed 32 bytes")
        integer_fields = [7, 8, 9, 10, 11]
        integer_fields.extend(index for index in (15, 17, 18) if index < len(decoded))
        for index in integer_fields:
            rlp_integer(decoded[index], f"header.field[{index}]")
        number = rlp_integer(decoded[8], "header.number")
        if number > U64_MAX:
            raise EthereumEncodingError("header.number exceeds uint64 bound")
        if len(decoded) >= 17 and len(decoded[16]) != 32:
            raise EthereumEncodingError("header.withdrawalsRoot must be exactly 32 bytes")
        if len(decoded) >= 20 and len(decoded[19]) != 32:
            raise EthereumEncodingError("header.parentBeaconBlockRoot must be exactly 32 bytes")
        if len(decoded) >= 21 and len(decoded[20]) != 32:
            raise EthereumEncodingError("header.requestsHash must be exactly 32 bytes")
        transactions_root = decoded[4]
        receipts_root = decoded[5]
        block_hash = keccak256(raw_header_rlp)
        return number, block_hash, transactions_root, receipts_root
    except (EthereumEncodingError, TypeError, ValueError, IndexError) as exc:
        raise EvmDepositInclusionError(f"invalid raw execution header: {exc}") from None


def _parse_receipt(raw_receipt: bytes, expected_type: int | None) -> _Receipt:
    try:
        envelope = _envelope(raw_receipt, "raw receipt")
        if envelope.tx_type != expected_type:
            raise EthereumEncodingError("transaction and receipt envelope types differ")
        fields = envelope.payload
        if len(fields) != 4:
            raise EthereumEncodingError("receipt payload must contain exactly four fields")
        status_field, cumulative_gas, bloom, logs_value = fields
        if not isinstance(status_field, bytes) or not isinstance(cumulative_gas, bytes):
            raise EthereumEncodingError("receipt status and cumulative gas must be byte strings")
        if not isinstance(bloom, bytes) or len(bloom) != 256:
            raise EthereumEncodingError("receipt logs bloom must be exactly 256 bytes")
        rlp_integer(cumulative_gas, "receipt.cumulativeGasUsed")
        # This profile accepts post-Byzantium status receipts only. Pre-Byzantium
        # state-root receipts need a separately specified historical policy.
        if status_field != b"\x01":
            raise EthereumEncodingError("receipt status is not successful post-Byzantium status 1")
        if not isinstance(logs_value, list):
            raise EthereumEncodingError("receipt logs field must be a list")
        parsed_logs = []
        for index, log in enumerate(logs_value):
            if not isinstance(log, list) or len(log) != 3:
                raise EthereumEncodingError(f"receipt log {index} must contain address, topics, data")
            address, topics, data = log
            if not isinstance(address, bytes) or len(address) != 20:
                raise EthereumEncodingError(f"receipt log {index} address must be 20 bytes")
            if not isinstance(topics, list) or any(not isinstance(topic, bytes) or len(topic) != 32 for topic in topics):
                raise EthereumEncodingError(f"receipt log {index} topics must each be 32 bytes")
            if not isinstance(data, bytes):
                raise EthereumEncodingError(f"receipt log {index} data must be bytes")
            parsed_logs.append((address, tuple(topics), data))
        return _Receipt(status=1, logs=tuple(parsed_logs))
    except (EthereumEncodingError, TypeError, ValueError, IndexError) as exc:
        raise EvmDepositInclusionError(f"invalid raw receipt: {exc}") from None


class EvmDepositInclusionVerifier:
    """Verify raw transaction + receipt inclusion against roots in the raw journaled header."""

    def __init__(self, policy: EvmDepositEvidencePolicy, finality_journal: FinalizedHeaderLookup) -> None:
        if not isinstance(policy, EvmDepositEvidencePolicy):
            raise TypeError("policy must be an EvmDepositEvidencePolicy")
        if not callable(getattr(finality_journal, "contains_finalized_header", None)):
            raise TypeError("finality_journal must provide contains_finalized_header(height, hash)")
        journal_namespace = getattr(finality_journal, "namespace_id", None)
        journal_chain_id = getattr(finality_journal, "chain_id", None)
        if journal_namespace is not None and journal_namespace != policy.namespace_id:
            raise ValueError("deposit policy and finality journal namespace differ")
        if journal_chain_id is not None and journal_chain_id != policy.chain_id:
            raise ValueError("deposit policy and finality journal chain differ")
        self._policy = policy
        self._journal = finality_journal

    def verify(
        self,
        *,
        raw_header_rlp: bytes,
        raw_transaction: bytes,
        transaction_proof: tuple[bytes, ...] | list[bytes],
        raw_receipt: bytes,
        receipt_proof: tuple[bytes, ...] | list[bytes],
        transaction_index: int,
        receipt_log_ordinal: int,
        expected_beneficiary: bytes,
    ) -> ProvenEvmDepositInclusion:
        """Verify both trie paths and derive the event solely from the proven raw receipt."""
        if isinstance(transaction_index, bool) or not isinstance(transaction_index, int) or not 0 <= transaction_index <= U64_MAX:
            raise ValueError("transaction_index must be a uint64 integer")
        if isinstance(receipt_log_ordinal, bool) or not isinstance(receipt_log_ordinal, int) or not 0 <= receipt_log_ordinal < (1 << 32):
            raise ValueError("receipt_log_ordinal must be a uint32 integer")
        if not isinstance(expected_beneficiary, bytes) or len(expected_beneficiary) != EVM_ADDRESS_BYTES or expected_beneficiary == ZERO_ADDRESS:
            raise ValueError("expected_beneficiary must be a non-zero 20-byte address")
        try:
            block_number, block_hash, transactions_root, receipts_root = _parse_header(raw_header_rlp)
            if not self._journal.contains_finalized_header(block_number, block_hash):
                raise EvmDepositInclusionError("raw header hash is not present in the durable finalized-header journal")
            tx_envelope = _envelope(raw_transaction, "raw transaction")
            transaction_hash = keccak256(raw_transaction)
            trie_key = rlp_encode_uint(transaction_index)
            if not verify_mpt_inclusion(transactions_root, trie_key, raw_transaction, transaction_proof):
                raise EvmDepositInclusionError("transaction trie inclusion proof did not verify")
            if not verify_mpt_inclusion(receipts_root, trie_key, raw_receipt, receipt_proof):
                raise EvmDepositInclusionError("receipt trie inclusion proof did not verify")
            receipt = _parse_receipt(raw_receipt, tx_envelope.tx_type)
            if receipt_log_ordinal >= len(receipt.logs):
                raise EvmDepositInclusionError("receipt_log_ordinal is outside the proven receipt logs")
            emitter, topics, data = receipt.logs[receipt_log_ordinal]
            if emitter != self._policy.deposit_contract_address:
                raise EvmDepositInclusionError("proven log was not emitted by the pinned protocol contract")
            if len(topics) != 4 or not hmac.compare_digest(topics[0], self._policy.event_topic0):
                raise EvmDepositInclusionError("proven log does not match the pinned Deposit event signature/layout")
            depositor = _address_topic(topics[1], "proven depositor")
            expected_asset = self._policy.asset_address if self._policy.asset_address is not None else ZERO_ADDRESS
            asset = _address_topic(topics[2], "proven asset", allow_zero=True)
            if not hmac.compare_digest(asset, expected_asset):
                raise EvmDepositInclusionError("proven deposit asset does not match the namespace policy")
            beneficiary = _address_topic(topics[3], "proven beneficiary")
            if not hmac.compare_digest(beneficiary, expected_beneficiary):
                raise EvmDepositInclusionError("proven beneficiary does not match the expected beneficiary")
            if len(data) != 32:
                raise EvmDepositInclusionError("proven Deposit event data must be exactly one uint256 word")
            amount = int.from_bytes(data, "big")
            if not self._policy.min_amount <= amount <= self._policy.max_amount or amount > U64_MAX:
                raise EvmDepositInclusionError("proven deposit amount is outside the accepted range")
            return ProvenEvmDepositInclusion(
                namespace_id=self._policy.namespace_id,
                chain_id=self._policy.chain_id,
                deposit_id=transaction_hash + receipt_log_ordinal.to_bytes(4, "big"),
                transaction_hash=transaction_hash,
                transaction_index=transaction_index,
                receipt_log_ordinal=receipt_log_ordinal,
                block_number=block_number,
                block_hash=block_hash,
                finalized_anchor=block_number.to_bytes(8, "big") + block_hash,
                deposit_contract_address=emitter,
                asset_address=self._policy.asset_address,
                depositor=depositor,
                beneficiary=beneficiary,
                amount=amount,
            )
        except EvmDepositInclusionError:
            raise
        except EvmDepositEvidenceError as exc:
            raise EvmDepositInclusionError(str(exc)) from None
        except (EthereumEncodingError, TypeError, ValueError, IndexError) as exc:
            raise EvmDepositInclusionError(f"deposit inclusion verification failed: {exc}") from None
