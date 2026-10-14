"""Production pipeline converting authenticated EVM deposit evidence into DepositAuthorization.

Composes:
1. Canonical event observation (QuorumObservedEvmDeposit).
2. MPT receipt trie inclusion proof against block receiptsRoot.
3. Light-client verified finalized block header (Helios checkpoint ancestry).
4. Strict custody solvency invariant (contract_balance >= total_minted + amount).
5. Fail-closed conversion producing immutable DepositAuthorization for the ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from src.adapters.evm_deposit_evidence import QuorumObservedEvmDeposit
from src.adapters.evm_deposit_proof import verify_mpt_inclusion
from src.adapters.evm_helios import AuthenticatedExecutionHeader
from src.primitives.namespace_v3 import NamespaceIdV3
from src.protocol.reference_ledger import DepositAuthorization


class DepositAuthorizationRejected(ValueError):
    """Deposit evidence or custody invariants failed closed."""


@dataclass(frozen=True, slots=True)
class CustodySolvencySnapshot:
    """Proof of on-chain reserve backing for 0PSP custody."""

    contract_address: bytes
    contract_balance: int
    total_minted_prior: int

    def __post_init__(self) -> None:
        if not isinstance(self.contract_balance, int) or self.contract_balance < 0:
            raise DepositAuthorizationRejected("contract_balance must be a non-negative integer")
        if not isinstance(self.total_minted_prior, int) or self.total_minted_prior < 0:
            raise DepositAuthorizationRejected("total_minted_prior must be a non-negative integer")


class TrustedDepositAuthorizer:
    """Fail-closed engine that validates all four pillars of EVM deposit security."""

    def __init__(
        self,
        *,
        expected_namespace_id: NamespaceIdV3,
        pinned_custody_contract: bytes,
        min_confirmations: int = 64,
    ) -> None:
        if not isinstance(expected_namespace_id, NamespaceIdV3):
            raise TypeError("expected_namespace_id must be NamespaceIdV3")
        if not isinstance(pinned_custody_contract, bytes) or len(pinned_custody_contract) != 20:
            raise ValueError("pinned_custody_contract must be a 20-byte address")
        if min_confirmations < 1:
            raise ValueError("min_confirmations must be at least 1")

        self._namespace = expected_namespace_id
        self._custody_contract = pinned_custody_contract
        self._min_confirmations = min_confirmations

    def authorize(
        self,
        *,
        observed_deposit: QuorumObservedEvmDeposit,
        finalized_header: AuthenticatedExecutionHeader,
        receipt_rlp: bytes,
        receipt_mpt_proof: bytes,
        receipt_path_rlp: bytes,
        custody_snapshot: CustodySolvencySnapshot,
        current_finalized_block_number: int,
    ) -> DepositAuthorization:
        """Validate evidence and return DepositAuthorization, or raise DepositAuthorizationRejected."""
        if not isinstance(observed_deposit, QuorumObservedEvmDeposit):
            raise DepositAuthorizationRejected("observed_deposit must be QuorumObservedEvmDeposit")
        if not isinstance(finalized_header, AuthenticatedExecutionHeader):
            raise DepositAuthorizationRejected("finalized_header must be AuthenticatedExecutionHeader")
        if not isinstance(custody_snapshot, CustodySolvencySnapshot):
            raise DepositAuthorizationRejected("custody_snapshot must be CustodySolvencySnapshot")
        if not isinstance(receipt_rlp, bytes) or not receipt_rlp:
            raise DepositAuthorizationRejected("receipt_rlp must be non-empty bytes")

        # 1. Pinned contract address binding
        if observed_deposit.deposit_contract_address != self._custody_contract:
            raise DepositAuthorizationRejected(
                f"deposit destination {observed_deposit.deposit_contract_address.hex()} differs from pinned custody contract {self._custody_contract.hex()}"
            )
        if custody_snapshot.contract_address != self._custody_contract:
            raise DepositAuthorizationRejected("custody snapshot address differs from pinned contract")

        # 2. Block header binding
        if finalized_header.number != observed_deposit.block_number:
            raise DepositAuthorizationRejected("finalized header block number mismatch")
        if finalized_header.block_hash != observed_deposit.block_hash:
            raise DepositAuthorizationRejected("finalized header block hash mismatch")

        # 3. Finality depth enforcement
        confirmations = current_finalized_block_number - finalized_header.number
        if confirmations < self._min_confirmations:
            raise DepositAuthorizationRejected(
                f"insufficient finality confirmations: {confirmations} < {self._min_confirmations}"
            )

        # 4. Custody solvency invariant: contract_balance >= total_minted_prior + deposit_amount
        required_reserve = custody_snapshot.total_minted_prior + observed_deposit.amount
        if custody_snapshot.contract_balance < required_reserve:
            raise DepositAuthorizationRejected(
                f"custody insolvency: reserve {custody_snapshot.contract_balance} < required {required_reserve}"
            )

        # 5. MPT receipt trie inclusion check
        try:
            nodes = [receipt_mpt_proof] if isinstance(receipt_mpt_proof, bytes) else list(receipt_mpt_proof)
            inclusion_valid = verify_mpt_inclusion(
                root_hash=finalized_header.receipts_root,
                key=receipt_path_rlp,
                expected_value=receipt_rlp,
                proof_nodes=nodes,
            )
            if not inclusion_valid:
                raise DepositAuthorizationRejected("MPT receipt trie inclusion check returned False")
        except Exception as exc:
            raise DepositAuthorizationRejected(f"receipt inclusion proof failed closed: {exc}") from exc

        # 6. Canonical deposit ID calculation
        canonical_deposit_id = (
            b"EVM-DEPOSIT-v1:"
            + observed_deposit.transaction_hash
            + b":"
            + observed_deposit.receipt_log_ordinal.to_bytes(4, "big")
        )

        return DepositAuthorization(
            namespace_id=self._namespace,
            deposit_id=canonical_deposit_id,
            authorized_value=observed_deposit.amount,
            finalized_anchor=finalized_header.block_hash,
            beneficiary_address=observed_deposit.depositor,
        )
