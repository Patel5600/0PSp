"""Fail-closed majority-quorum policy for the EVM namespace RPC surface.

This adapter reduces dependence on one RPC endpoint; it is NOT a light client.
The caller must configure independently operated providers and must still pin
chain/deployment manifests. A provider majority can agree on a wrong chain view.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Mapping, Protocol

from src.adapters.evm_namespace import EvmRpcError

_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")
_DATA_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_BLOCK_TAGS = frozenset({"latest", "safe", "finalized"})


class RpcTransport(Protocol):
    def call(self, method: str, params: list[object]) -> object:
        """Perform a JSON-RPC request and return its result."""


def _quantity(value: object, field: str) -> int:
    if not isinstance(value, str) or _QUANTITY_RE.fullmatch(value) is None:
        raise ValueError(f"{field} is not a canonical JSON-RPC QUANTITY")
    return int(value[2:], 16)


def _data(value: object, field: str, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str) or _DATA_RE.fullmatch(value) is None:
        raise ValueError(f"{field} is not canonical even-length JSON-RPC DATA")
    raw = bytes.fromhex(value[2:])
    if expected_length is not None and len(raw) != expected_length:
        raise ValueError(f"{field} must be {expected_length} bytes")
    return raw


def _validate_request(method: str, params: list[object]) -> None:
    """Restrict this transport to the small read-only identity/finality surface."""
    if method == "eth_chainId":
        if params:
            raise EvmRpcError("quorum transport rejected malformed eth_chainId parameters")
        return
    if method == "eth_getBlockByNumber":
        if (
            len(params) != 2
            or type(params[1]) is not bool
            or not isinstance(params[0], str)
            or not (
                params[0] in _BLOCK_TAGS
                or _QUANTITY_RE.fullmatch(params[0]) is not None
            )
        ):
            raise EvmRpcError("quorum transport rejected malformed eth_getBlockByNumber parameters")
        return
    if method == "eth_getCode":
        if (
            len(params) != 2
            or not isinstance(params[0], str)
            or re.fullmatch(r"0x[0-9a-fA-F]{40}", params[0]) is None
            or not isinstance(params[1], str)
            or not (
                params[1] in _BLOCK_TAGS
                or _QUANTITY_RE.fullmatch(params[1]) is not None
            )
        ):
            raise EvmRpcError("quorum transport rejected malformed eth_getCode parameters")
        return
    if method == "eth_getTransactionReceipt":
        if (
            len(params) != 1
            or not isinstance(params[0], str)
            or re.fullmatch(r"0x[0-9a-fA-F]{64}", params[0]) is None
        ):
            raise EvmRpcError("quorum transport rejected malformed eth_getTransactionReceipt parameters")
        return
    raise EvmRpcError(f"quorum transport does not permit RPC method {method!r}")


def _vote_key(method: str, result: object) -> tuple[object, ...]:
    """Canonicalize only the fields used by the namespace/finality policy."""
    if method == "eth_chainId":
        return ("quantity", _quantity(result, "eth_chainId result"))
    if method == "eth_getCode":
        return ("data", _data(result, "eth_getCode result"))
    if method == "eth_getBlockByNumber":
        if result is None:
            return ("missing-block",)
        if not isinstance(result, dict):
            raise ValueError("block result is not an object")
        number = _quantity(result.get("number"), "block.number")
        block_hash = _data(result.get("hash"), "block.hash", 32)
        parent_value = result.get("parentHash")
        parent_hash = None if parent_value is None else _data(parent_value, "block.parentHash", 32)
        receipts_root_value = result.get("receiptsRoot")
        receipts_root = (
            None if receipts_root_value is None
            else _data(receipts_root_value, "block.receiptsRoot", 32)
        )
        transactions_root_value = result.get("transactionsRoot")
        transactions_root = (
            None if transactions_root_value is None
            else _data(transactions_root_value, "block.transactionsRoot", 32)
        )
        return ("block", number, block_hash, parent_hash, receipts_root, transactions_root)
    if method == "eth_getTransactionReceipt":
        if result is None:
            return ("missing-receipt",)
        if not isinstance(result, dict):
            raise ValueError("receipt result is not an object")
        tx_hash = _data(result.get("transactionHash"), "receipt.transactionHash", 32)
        block_hash = _data(result.get("blockHash"), "receipt.blockHash", 32)
        block_number = _quantity(result.get("blockNumber"), "receipt.blockNumber")
        tx_index = _quantity(result.get("transactionIndex"), "receipt.transactionIndex")
        status = _quantity(result.get("status"), "receipt.status")
        logs_value = result.get("logs")
        if not isinstance(logs_value, list):
            raise ValueError("receipt.logs is not a list")
        normalized_logs = []
        seen_indices: set[int] = set()
        for i, log in enumerate(logs_value):
            if not isinstance(log, dict):
                raise ValueError(f"receipt.logs[{i}] is not an object")
            address = _data(log.get("address"), f"receipt.logs[{i}].address", 20)
            topics_value = log.get("topics")
            if not isinstance(topics_value, list) or len(topics_value) > 4:
                raise ValueError(f"receipt.logs[{i}].topics is not a valid topic list")
            topics = tuple(
                _data(topic, f"receipt.logs[{i}].topics[{j}]", 32)
                for j, topic in enumerate(topics_value)
            )
            data = _data(log.get("data"), f"receipt.logs[{i}].data")
            log_index = _quantity(log.get("logIndex"), f"receipt.logs[{i}].logIndex")
            log_tx_index = _quantity(log.get("transactionIndex"), f"receipt.logs[{i}].transactionIndex")
            log_block_number = _quantity(log.get("blockNumber"), f"receipt.logs[{i}].blockNumber")
            log_block_hash = _data(log.get("blockHash"), f"receipt.logs[{i}].blockHash", 32)
            log_tx_hash = _data(log.get("transactionHash"), f"receipt.logs[{i}].transactionHash", 32)
            removed = log.get("removed")
            if type(removed) is not bool:
                raise ValueError(f"receipt.logs[{i}].removed is not boolean")
            if log_index in seen_indices:
                raise ValueError("receipt contains duplicate log indices")
            seen_indices.add(log_index)
            normalized_logs.append((
                address, topics, data, log_index, log_tx_index,
                log_block_number, log_block_hash, log_tx_hash, removed,
            ))
        return ("receipt", tx_hash, block_hash, block_number, tx_index, status, tuple(normalized_logs))
    raise ValueError("unsupported method")


class QuorumJsonRpcTransport:
    """Require a strict majority of at least three distinct RPC transports.

    `providers` maps operator-chosen labels to transport objects. Each object
    must represent a separately administered endpoint/provider; unique labels
    cannot prove operational independence. The default is strict majority
    (2-of-3, 3-of-4, etc.). Quorum agreement is corroboration, not consensus proof.
    """

    def __init__(
        self,
        providers: Mapping[str, RpcTransport],
        *,
        quorum: int | None = None,
    ) -> None:
        if not isinstance(providers, Mapping) or len(providers) < 3:
            raise ValueError("at least three named RPC providers are required")
        if any(
            not isinstance(name, str)
            or not name.strip()
            or not callable(getattr(provider, "call", None))
            for name, provider in providers.items()
        ):
            raise TypeError("providers must map non-empty names to call(method, params) transports")
        if len({id(provider) for provider in providers.values()}) != len(providers):
            raise ValueError("each provider entry must use a distinct transport object")
        required = (len(providers) // 2) + 1 if quorum is None else quorum
        if (
            isinstance(required, bool)
            or not isinstance(required, int)
            or required <= len(providers) // 2
            or required > len(providers)
        ):
            raise ValueError("quorum must be a strict majority no larger than provider count")
        self._providers = tuple(providers.items())
        self._quorum = required

    @property
    def provider_names(self) -> tuple[str, ...]:
        """Operator-chosen labels for audit/logging; endpoint URLs are not exposed."""
        return tuple(name for name, _ in self._providers)

    @property
    def quorum(self) -> int:
        return self._quorum

    def call(self, method: str, params: list[object]) -> object:
        if not isinstance(method, str) or not isinstance(params, list):
            raise TypeError("method must be a string and params must be a list")
        _validate_request(method, params)
        votes: dict[tuple[object, ...], list[object]] = defaultdict(list)
        failures = 0
        for _, provider in self._providers:
            try:
                result = provider.call(method, params)
                key = _vote_key(method, result)
            except Exception:
                # Avoid leaking endpoint URLs, credentials, RPC bodies, or exception text.
                failures += 1
                continue
            votes[key].append(result)
        if votes:
            winning_key, winning_results = max(votes.items(), key=lambda item: len(item[1]))
            if len(winning_results) >= self._quorum:
                return winning_results[0]
        largest_group = max((len(results) for results in votes.values()), default=0)
        raise EvmRpcError(
            f"RPC quorum unavailable for {method}: largest agreement "
            f"{largest_group}/{len(self._providers)}, required {self._quorum}; "
            f"failed or malformed providers {failures}"
        )
