"""Fail-closed startup wiring for a production-shaped EVM namespace context.

This combines the pinned manifest, strict-majority RPC surface, and durable
finalized-header journal into one API. It intentionally does not claim that the
provider quorum verifies EVM consensus or authenticates deposit events.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from src.adapters.evm_finality import FinalitySnapshot, SqliteEvmFinalityJournal
from src.adapters.evm_namespace import EvmNamespaceAdapter, EvmNamespaceBinding, EvmNamespaceConfig
from src.adapters.evm_rpc_policy import QuorumJsonRpcTransport, RpcTransport


class NamespaceRuntimeError(RuntimeError):
    """Namespace startup could not establish the required fail-closed context."""


@dataclass(frozen=True, slots=True)
class EvmNamespaceRuntimeSnapshot:
    binding: EvmNamespaceBinding
    finality: FinalitySnapshot

    def __post_init__(self) -> None:
        if self.binding.namespace_id != self.finality.namespace_id:
            raise ValueError("namespace binding and finality journal scope differ")
        if self.binding.chain_id != self.finality.chain_id:
            raise ValueError("namespace binding and finality journal chain differ")
        if not self.finality.caught_up:
            raise ValueError("namespace runtime cannot start before finalized-chain sync completes")


class EvmNamespaceRuntime:
    """Resolve namespace only after RPC quorum and durable finality checks succeed.

    Create this at process startup with three or more separately administered
    JSON-RPC transports and an out-of-band pinned manifest. The configured
    checkpoint must be recent enough to synchronize within `max_headers`.
    """

    def __init__(
        self,
        config: EvmNamespaceConfig,
        providers: Mapping[str, RpcTransport],
        database_path: str | Path,
        *,
        quorum: int | None = None,
        max_headers: int = 4096,
    ) -> None:
        if not isinstance(config, EvmNamespaceConfig):
            raise TypeError("config must be an EvmNamespaceConfig")
        if config.code_block_tag != "finalized":
            raise ValueError("namespace runtime requires code_block_tag='finalized'")
        if (
            isinstance(max_headers, bool)
            or not isinstance(max_headers, int)
            or not 1 <= max_headers <= 100_000
        ):
            raise ValueError("max_headers must be in [1, 100000]")
        self._config = config
        self._rpc = QuorumJsonRpcTransport(providers, quorum=quorum)
        self._database_path = database_path
        self._max_headers = max_headers

    def resolve(self) -> EvmNamespaceRuntimeSnapshot:
        """Fail closed unless manifest checks and finalized ancestry both pass."""
        try:
            binding = EvmNamespaceAdapter(self._config, self._rpc).resolve()
            journal = SqliteEvmFinalityJournal(
                self._database_path,
                chain_id=self._config.chain_id,
                genesis_hash=self._config.genesis_hash,
                checkpoint_block_number=self._config.checkpoint_block_number,
                checkpoint_hash=self._config.checkpoint_hash,
                namespace_id=binding.namespace_id,
            )
            finality = journal.advance(self._rpc, max_headers=self._max_headers)
            if not journal.contains_finalized_header(
                self._config.checkpoint_block_number,
                self._config.checkpoint_hash,
            ):
                raise NamespaceRuntimeError("trusted checkpoint is absent from the durable finality journal")
            return EvmNamespaceRuntimeSnapshot(binding=binding, finality=finality)
        except NamespaceRuntimeError:
            raise
        except Exception:
            # Do not return a partially trusted namespace or expose RPC endpoint details.
            raise NamespaceRuntimeError(
                "namespace runtime could not verify its pinned manifest and finalized ancestry"
            ) from None
