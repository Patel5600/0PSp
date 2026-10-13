"""Canonical EVM deposit-observation evidence for the RFC-01 issuance boundary.

The reader validates a deposit-shaped event against a pinned Namespace V3 binding,
a majority-observed receipt, an independently pinned event/code policy, and the
durable finalized-header journal. The result is explicitly NOT cryptographically
authenticated deposit authorization: no receipt-trie proof or light client exists.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from src.adapters.evm_namespace import (
    EVM_ADDRESS_BYTES,
    EVM_HASH_BYTES,
    EVM_CODE_FINGERPRINT_BYTES,
    EvmNamespaceBinding,
    runtime_code_fingerprint,
)
from src.adapters.evm_rpc_policy import QuorumJsonRpcTransport
from src.primitives.namespace_v3 import NamespaceIdV3

U64_MAX = (1 << 64) - 1
ZERO_ADDRESS = bytes(EVM_ADDRESS_BYTES)
DEPOSIT_EVIDENCE_VERSION = b"\x01"
DOMAIN_EVM_DEPOSIT_OBSERVATION = b"0PSP-EVM-DEPOSIT-OBSERVATION-v1"
DEPOSIT_EVENT_DATA_BYTES = 32


class EvmDepositEvidenceError(RuntimeError):
    """A candidate EVM deposit observation is malformed or violates pinned policy."""


class FinalizedHeaderLookup(Protocol):
    def contains_finalized_header(self, block_number: int, block_hash: bytes) -> bool:
        """Return true only for exact header membership in the durable ancestry journal."""


def _quantity(value: object, field: str, *, max_value: int = U64_MAX) -> int:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
        raise EvmDepositEvidenceError(f"{field} is not a canonical JSON-RPC QUANTITY")
    digits = value[2:]
    if digits != "0" and digits.startswith("0"):
        raise EvmDepositEvidenceError(f"{field} is not a canonical JSON-RPC QUANTITY")
    try:
        parsed = int(digits, 16)
    except ValueError:
        raise EvmDepositEvidenceError(f"{field} is not a canonical JSON-RPC QUANTITY") from None
    if parsed < 0 or parsed > max_value or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
        raise EvmDepositEvidenceError(f"{field} exceeds its canonical integer bounds")
    return parsed


def _data(value: object, field: str, *, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise EvmDepositEvidenceError(f"{field} is not JSON-RPC DATA")
    raw_hex = value[2:]
    if len(raw_hex) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in raw_hex):
        raise EvmDepositEvidenceError(f"{field} is not canonical even-length JSON-RPC DATA")
    raw = bytes.fromhex(raw_hex)
    if expected_length is not None and len(raw) != expected_length:
        raise EvmDepositEvidenceError(f"{field} must be exactly {expected_length} bytes")
    return raw


def _address_topic(topic: bytes, field: str, *, allow_zero: bool = False) -> bytes:
    if len(topic) != 32 or topic[:12] != bytes(12):
        raise EvmDepositEvidenceError(f"{field} is not a canonical ABI-encoded address topic")
    address = topic[12:]
    if not allow_zero and address == ZERO_ADDRESS:
        raise EvmDepositEvidenceError(f"{field} must not be the zero address")
    return address


@dataclass(frozen=True, slots=True)
class EvmDepositEvidencePolicy:
    """Pinned event rule for the protocol contract bound by Namespace V3.

    This v1 policy intentionally supports one fixed ABI layout:
      event Deposit(address indexed depositor,
                    address indexed asset,
                    address indexed beneficiary,
                    uint256 amount);

    Thus topics are [topic0, depositor, asset, beneficiary] and data is exactly
    one 32-byte uint256 amount. event_topic0 must be computed from the exact ABI
    canonical signature using Ethereum Keccak-256 and pinned from reviewed
    contract artifacts. It must not be produced with standardized SHA3-256.
    """

    namespace_id: NamespaceIdV3
    chain_id: int
    deposit_contract_address: bytes
    expected_runtime_code_fingerprint: bytes
    event_topic0: bytes
    asset_address: bytes | None
    min_amount: int = 1
    max_amount: int = U64_MAX

    def __post_init__(self) -> None:
        if not isinstance(self.namespace_id, NamespaceIdV3):
            raise TypeError("namespace_id must be NamespaceIdV3")
        if isinstance(self.chain_id, bool) or not isinstance(self.chain_id, int) or not 1 <= self.chain_id < (1 << 256):
            raise ValueError("chain_id must be in [1, 2^256-1]")
        if not isinstance(self.deposit_contract_address, bytes) or len(self.deposit_contract_address) != EVM_ADDRESS_BYTES or self.deposit_contract_address == ZERO_ADDRESS:
            raise ValueError("deposit_contract_address must be a non-zero 20-byte EVM address")
        if not isinstance(self.expected_runtime_code_fingerprint, bytes) or len(self.expected_runtime_code_fingerprint) != EVM_CODE_FINGERPRINT_BYTES:
            raise ValueError("expected_runtime_code_fingerprint must be 48 bytes")
        if not isinstance(self.event_topic0, bytes) or len(self.event_topic0) != EVM_HASH_BYTES:
            raise ValueError("event_topic0 must be exactly 32 bytes")
        if self.asset_address is not None and (
            not isinstance(self.asset_address, bytes)
            or len(self.asset_address) != EVM_ADDRESS_BYTES
            or self.asset_address == ZERO_ADDRESS
        ):
            raise ValueError("asset_address must be None for native asset or a non-zero 20-byte token address")
        if (
            isinstance(self.min_amount, bool)
            or not isinstance(self.min_amount, int)
            or not 1 <= self.min_amount <= U64_MAX
        ):
            raise ValueError("min_amount must be in [1, 2^64-1]")
        if (
            isinstance(self.max_amount, bool)
            or not isinstance(self.max_amount, int)
            or not self.min_amount <= self.max_amount <= U64_MAX
        ):
            raise ValueError("max_amount must be in [min_amount, 2^64-1]")

    @classmethod
    def from_namespace_binding(
        cls,
        binding: EvmNamespaceBinding,
        *,
        event_topic0: bytes,
        min_amount: int = 1,
        max_amount: int = U64_MAX,
    ) -> "EvmDepositEvidencePolicy":
        """Bind deposit policy to the protocol address and asset already in V3.

        This v1 contract requires deposits to be emitted by the same protocol
        address whose identity is in Namespace V3. A separate deposit contract
        needs a separately reviewed namespace/protocol version; do not silently
        accept an unbound emitter under an existing namespace.
        """
        if not isinstance(binding, EvmNamespaceBinding):
            raise TypeError("binding must be an EvmNamespaceBinding")
        return cls(
            namespace_id=binding.namespace_id,
            chain_id=binding.chain_id,
            deposit_contract_address=binding.protocol_address,
            expected_runtime_code_fingerprint=binding.protocol_code_fingerprint,
            event_topic0=event_topic0,
            asset_address=binding.asset_address,
            min_amount=min_amount,
            max_amount=max_amount,
        )


@dataclass(frozen=True, slots=True)
class QuorumObservedEvmDeposit:
    """Canonical audit record for a deposit-shaped event observed through RPC quorum.

    This type deliberately has no method that converts it to DepositAuthorization.
    Quorum consensus, a finalized-header journal and a code fingerprint are not a
    receipt inclusion proof, an authenticated consensus proof, or an asset-transfer
    proof. Use this record as input/evidence for a separate trusted verifier.
    """

    namespace_id: NamespaceIdV3
    chain_id: int
    deposit_contract_address: bytes
    asset_address: bytes | None
    transaction_hash: bytes
    block_number: int
    block_hash: bytes
    receipts_root: bytes
    transactions_root: bytes
    transaction_index: int
    receipt_log_ordinal: int
    log_index: int
    depositor: bytes
    beneficiary: bytes
    amount: int
    event_topic0: bytes
    contract_code_fingerprint: bytes

    @property
    def assurance_level(self) -> str:
        return "QUORUM_OBSERVED_NOT_CRYPTOGRAPHICALLY_AUTHENTICATED"

    @property
    def deposit_id(self) -> bytes:
        """Namespace-scoped stable ID for one log, not a transaction-level ID."""
        return self.transaction_hash + self.receipt_log_ordinal.to_bytes(4, "big")

    @property
    def finalized_anchor(self) -> bytes:
        """Canonical anchor: block number BE64 followed by block hash."""
        return self.block_number.to_bytes(8, "big") + self.block_hash

    def canonical_bytes(self) -> bytes:
        """Exact fixed-width encoding of the normalized observed facts."""
        return (
            DOMAIN_EVM_DEPOSIT_OBSERVATION
            + DEPOSIT_EVIDENCE_VERSION
            + self.namespace_id.data
            + self.chain_id.to_bytes(32, "big")
            + self.deposit_contract_address
            + (self.asset_address if self.asset_address is not None else ZERO_ADDRESS)
            + self.event_topic0
            + self.transaction_hash
            + self.block_number.to_bytes(8, "big")
            + self.block_hash
            + self.transactions_root
            + self.receipts_root
            + self.transaction_index.to_bytes(8, "big")
            + self.receipt_log_ordinal.to_bytes(4, "big")
            + self.log_index.to_bytes(8, "big")
            + self.depositor
            + self.beneficiary
            + self.amount.to_bytes(8, "big")
            + self.contract_code_fingerprint
        )

    @property
    def evidence_digest(self) -> bytes:
        """Stable 48-byte audit fingerprint; it does not authenticate the evidence."""
        return hashlib.shake_256(self.canonical_bytes()).digest(48)


class EvmDepositEvidenceReader:
    """Inspect one selected deposit log under a pinned policy and finalized journal.

    A normal RPC receipt is not independently authenticated. This reader relies
    on rpc providing strict-majority normalized answers and on finality_journal
    containing verified-by-policy header ancestry. Even if both checks succeed,
    output remains an observation until a separate receipt/consensus verifier
    establishes cryptographic authenticity.
    """

    def __init__(
        self,
        policy: EvmDepositEvidencePolicy,
        rpc: QuorumJsonRpcTransport,
        finality_journal: FinalizedHeaderLookup,
    ) -> None:
        if not isinstance(policy, EvmDepositEvidencePolicy):
            raise TypeError("policy must be an EvmDepositEvidencePolicy")
        if not isinstance(rpc, QuorumJsonRpcTransport):
            raise TypeError("rpc must be a QuorumJsonRpcTransport; a single endpoint is not accepted")
        if not callable(getattr(finality_journal, "contains_finalized_header", None)):
            raise TypeError("finality_journal must provide contains_finalized_header(height, hash)")
        journal_namespace = getattr(finality_journal, "namespace_id", None)
        journal_chain_id = getattr(finality_journal, "chain_id", None)
        if journal_namespace is not None and journal_namespace != policy.namespace_id:
            raise ValueError("deposit policy and finality journal namespace differ")
        if journal_chain_id is not None and journal_chain_id != policy.chain_id:
            raise ValueError("deposit policy and finality journal chain differ")
        self._policy = policy
        self._rpc = rpc
        self._journal = finality_journal

    def inspect(
        self,
        *,
        transaction_hash: bytes,
        receipt_log_ordinal: int,
        expected_beneficiary: bytes,
    ) -> QuorumObservedEvmDeposit:
        """Return a normalized candidate only if all pinned local checks succeed."""
        if not isinstance(transaction_hash, bytes) or len(transaction_hash) != EVM_HASH_BYTES:
            raise ValueError("transaction_hash must be exactly 32 bytes")
        if (
            isinstance(receipt_log_ordinal, bool)
            or not isinstance(receipt_log_ordinal, int)
            or not 0 <= receipt_log_ordinal < (1 << 32)
        ):
            raise ValueError("receipt_log_ordinal must be a uint32 integer")
        if (
            not isinstance(expected_beneficiary, bytes)
            or len(expected_beneficiary) != EVM_ADDRESS_BYTES
            or expected_beneficiary == ZERO_ADDRESS
        ):
            raise ValueError("expected_beneficiary must be a non-zero 20-byte address")

        try:
            observed_chain_id = _quantity(
                self._rpc.call("eth_chainId", []),
                "eth_chainId",
                max_value=(1 << 256) - 1,
            )
        except Exception:
            raise EvmDepositEvidenceError("could not establish the RPC quorum chain ID") from None
        if observed_chain_id != self._policy.chain_id:
            raise EvmDepositEvidenceError("RPC quorum chain ID does not match the pinned Namespace V3 binding")

        try:
            receipt = self._rpc.call("eth_getTransactionReceipt", ["0x" + transaction_hash.hex()])
        except Exception:
            raise EvmDepositEvidenceError("could not obtain a quorum transaction receipt") from None
        if not isinstance(receipt, dict):
            raise EvmDepositEvidenceError("transaction receipt is absent or malformed")

        receipt_tx_hash = _data(receipt.get("transactionHash"), "receipt.transactionHash", expected_length=32)
        if not hmac.compare_digest(receipt_tx_hash, transaction_hash):
            raise EvmDepositEvidenceError("receipt transaction hash does not match the requested transaction")
        status = _quantity(receipt.get("status"), "receipt.status")
        if status != 1:
            raise EvmDepositEvidenceError("transaction did not succeed")
        block_number = _quantity(receipt.get("blockNumber"), "receipt.blockNumber")
        block_hash = _data(receipt.get("blockHash"), "receipt.blockHash", expected_length=32)
        transaction_index = _quantity(receipt.get("transactionIndex"), "receipt.transactionIndex")
        logs = receipt.get("logs")
        if not isinstance(logs, list):
            raise EvmDepositEvidenceError("receipt.logs must be a list")

        # A later inclusion-proof implementation must bind a raw receipt trie
        # proof to the receiptsRoot authenticated by the finalized execution header.
        try:
            header = self._rpc.call("eth_getBlockByNumber", [hex(block_number), False])
        except Exception:
            raise EvmDepositEvidenceError("could not obtain the receipt block header from the RPC quorum") from None
        if not isinstance(header, dict):
            raise EvmDepositEvidenceError("receipt block header is absent")
        if _quantity(header.get("number"), "header.number") != block_number:
            raise EvmDepositEvidenceError("header number does not match the receipt block number")
        header_hash = _data(header.get("hash"), "header.hash", expected_length=32)
        receipts_root = _data(header.get("receiptsRoot"), "header.receiptsRoot", expected_length=32)
        transactions_root = _data(header.get("transactionsRoot"), "header.transactionsRoot", expected_length=32)
        if not hmac.compare_digest(header_hash, block_hash):
            raise EvmDepositEvidenceError("header hash does not match the receipt block hash")
        if block_number > 0:
            _data(header.get("parentHash"), "header.parentHash", expected_length=32)
        if not self._journal.contains_finalized_header(block_number, block_hash):
            raise EvmDepositEvidenceError("receipt block is not in the durable finalized-header ancestry")

        if receipt_log_ordinal >= len(logs):
            raise EvmDepositEvidenceError("receipt_log_ordinal is outside the receipt's log array")
        selected: dict[str, object] | None = None
        seen_indices: set[int] = set()
        for i, log in enumerate(logs):
            if not isinstance(log, dict):
                raise EvmDepositEvidenceError(f"receipt log {i} is malformed")
            log_tx_hash = _data(log.get("transactionHash"), f"log[{i}].transactionHash", expected_length=32)
            log_block_hash = _data(log.get("blockHash"), f"log[{i}].blockHash", expected_length=32)
            log_block_number = _quantity(log.get("blockNumber"), f"log[{i}].blockNumber")
            log_transaction_index = _quantity(log.get("transactionIndex"), f"log[{i}].transactionIndex")
            current_index = _quantity(log.get("logIndex"), f"log[{i}].logIndex")
            removed = log.get("removed")
            if type(removed) is not bool:
                raise EvmDepositEvidenceError(f"log[{i}].removed must be boolean")
            if removed:
                raise EvmDepositEvidenceError("receipt contains a log marked removed")
            if current_index in seen_indices:
                raise EvmDepositEvidenceError("receipt contains duplicate global log indices")
            seen_indices.add(current_index)
            if (
                log_tx_hash != receipt_tx_hash
                or log_block_hash != block_hash
                or log_block_number != block_number
                or log_transaction_index != transaction_index
            ):
                raise EvmDepositEvidenceError("receipt log metadata does not match its containing receipt")
            if i == receipt_log_ordinal:
                selected = log

        if selected is None:
            raise EvmDepositEvidenceError("requested receipt_log_ordinal is absent from the transaction receipt")

        emitter = _data(selected.get("address"), "deposit log address", expected_length=EVM_ADDRESS_BYTES)
        if not hmac.compare_digest(emitter, self._policy.deposit_contract_address):
            raise EvmDepositEvidenceError("selected log was not emitted by the pinned protocol contract")
        topics_value = selected.get("topics")
        if not isinstance(topics_value, list) or len(topics_value) != 4:
            raise EvmDepositEvidenceError("deposit log must have exactly four topics for the pinned event schema")
        topics = tuple(_data(topic, f"deposit topics[{i}]", expected_length=32) for i, topic in enumerate(topics_value))
        if not hmac.compare_digest(topics[0], self._policy.event_topic0):
            raise EvmDepositEvidenceError("deposit event signature topic does not match the pinned policy")
        depositor = _address_topic(topics[1], "depositor")
        expected_asset = self._policy.asset_address if self._policy.asset_address is not None else ZERO_ADDRESS
        actual_asset = _address_topic(topics[2], "asset", allow_zero=True)
        if not hmac.compare_digest(actual_asset, expected_asset):
            raise EvmDepositEvidenceError("deposit asset does not match the configured Namespace V3 asset")
        beneficiary = _address_topic(topics[3], "beneficiary")
        if not hmac.compare_digest(beneficiary, expected_beneficiary):
            raise EvmDepositEvidenceError("deposit beneficiary does not match the requested beneficiary")

        data = _data(selected.get("data"), "deposit event data", expected_length=DEPOSIT_EVENT_DATA_BYTES)
        amount = int.from_bytes(data, "big")
        if amount < self._policy.min_amount or amount > self._policy.max_amount or amount > U64_MAX:
            raise EvmDepositEvidenceError("deposit amount is outside the configured accepted range")

        try:
            code = self._rpc.call(
                "eth_getCode",
                ["0x" + self._policy.deposit_contract_address.hex(), hex(block_number)],
            )
            runtime_fingerprint = runtime_code_fingerprint(_data(code, "protocol runtime code"))
        except Exception:
            raise EvmDepositEvidenceError("could not validate the protocol contract code at the deposit block") from None
        if not hmac.compare_digest(runtime_fingerprint, self._policy.expected_runtime_code_fingerprint):
            raise EvmDepositEvidenceError("protocol runtime code at the deposit block does not match the pinned policy")

        return QuorumObservedEvmDeposit(
            namespace_id=self._policy.namespace_id,
            chain_id=self._policy.chain_id,
            deposit_contract_address=emitter,
            asset_address=self._policy.asset_address,
            transaction_hash=receipt_tx_hash,
            block_number=block_number,
            block_hash=block_hash,
            receipts_root=receipts_root,
            transactions_root=transactions_root,
            transaction_index=transaction_index,
            receipt_log_ordinal=receipt_log_ordinal,
            log_index=_quantity(selected.get("logIndex"), "selected log.logIndex"),
            depositor=depositor,
            beneficiary=beneficiary,
            amount=amount,
            event_topic0=self._policy.event_topic0,
            contract_code_fingerprint=runtime_fingerprint,
        )
