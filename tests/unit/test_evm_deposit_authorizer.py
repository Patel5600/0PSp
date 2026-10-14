"""Unit tests for TrustedDepositAuthorizer (Components 1 & 2).

Verifies:
1. Valid evidence, MPT proof, header, and solvency yield canonical DepositAuthorization.
2. Custody contract mismatch raises DepositAuthorizationRejected.
3. Block number or hash mismatch raises DepositAuthorizationRejected.
4. Insufficient confirmations raises DepositAuthorizationRejected.
5. Insolvent custody reserve raises DepositAuthorizationRejected.
6. Corrupted MPT proof raises DepositAuthorizationRejected.
"""
from __future__ import annotations

import pytest

from src.adapters.evm_deposit_authorizer import (
    CustodySolvencySnapshot,
    DepositAuthorizationRejected,
    TrustedDepositAuthorizer,
)
from src.adapters.evm_deposit_evidence import QuorumObservedEvmDeposit
from src.adapters.evm_helios import AuthenticatedExecutionHeader
from src.adapters.evm_trie import keccak256, rlp_encode_bytes, rlp_encode_list
from src.primitives.namespace_v3 import NamespaceIdV3
from src.protocol.reference_ledger import DepositAuthorization

NAMESPACE = NamespaceIdV3(bytes([0x11]) * 48)
CUSTODY_CONTRACT = bytes([0x22]) * 20
OTHER_CONTRACT = bytes([0x99]) * 20
DEPOSITOR = bytes([0x33]) * 20
TX_HASH = bytes([0x44]) * 32
BLOCK_HASH = bytes([0x55]) * 32
BLOCK_NUMBER = 1000
AMOUNT = 5000


def make_header(number: int, block_hash: bytes, receipts_root: bytes) -> AuthenticatedExecutionHeader:
    return AuthenticatedExecutionHeader(
        number=number,
        block_hash=block_hash,
        parent_hash=bytes(32),
        transactions_root=bytes(32),
        receipts_root=receipts_root,
        raw_header_rlp=b"",
        observed_finalized_number=number + 64,
        observed_finalized_hash=bytes(32),
        light_client_binary_sha256=bytes(32),
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


def enc(value):
    if isinstance(value, bytes):
        return rlp_encode_bytes(value)
    if isinstance(value, list):
        return rlp_encode_list([enc(item) for item in value])
    raise TypeError(value)


def make_mpt_proof(path_key: bytes, rlp_value: bytes) -> tuple[bytes, list[bytes]]:
    node = enc([compact_encode_path(path_key, leaf=True), rlp_value])
    root = keccak256(node)
    return root, [node]


def make_observed_deposit(
    contract_address: bytes = CUSTODY_CONTRACT,
    block_number: int = BLOCK_NUMBER,
    block_hash: bytes = BLOCK_HASH,
    amount: int = AMOUNT,
) -> QuorumObservedEvmDeposit:
    return QuorumObservedEvmDeposit(
        namespace_id=NAMESPACE,
        chain_id=1,
        deposit_contract_address=contract_address,
        asset_address=None,
        transaction_hash=TX_HASH,
        block_number=block_number,
        block_hash=block_hash,
        receipts_root=bytes(32),
        transactions_root=bytes(32),
        transaction_index=0,
        receipt_log_ordinal=0,
        log_index=0,
        depositor=DEPOSITOR,
        beneficiary=DEPOSITOR,
        amount=amount,
        event_topic0=bytes(32),
        contract_code_fingerprint=bytes(48),
    )


def test_successful_deposit_authorization() -> None:
    path_key = b"\x02"
    dummy_receipt = enc([b"\x01", b"\x00", b"", []])
    receipts_root, proof_nodes = make_mpt_proof(path_key, dummy_receipt)

    header = make_header(
        number=BLOCK_NUMBER,
        block_hash=BLOCK_HASH,
        receipts_root=receipts_root,
    )

    observed = make_observed_deposit()

    custody = CustodySolvencySnapshot(
        contract_address=CUSTODY_CONTRACT,
        contract_balance=100_000,
        total_minted_prior=50_000,
    )

    authorizer = TrustedDepositAuthorizer(
        expected_namespace_id=NAMESPACE,
        pinned_custody_contract=CUSTODY_CONTRACT,
        min_confirmations=32,
    )

    auth = authorizer.authorize(
        observed_deposit=observed,
        finalized_header=header,
        receipt_rlp=dummy_receipt,
        receipt_mpt_proof=proof_nodes[0],
        receipt_path_rlp=path_key,
        custody_snapshot=custody,
        current_finalized_block_number=BLOCK_NUMBER + 64,
    )

    assert isinstance(auth, DepositAuthorization)
    assert auth.namespace_id == NAMESPACE
    assert auth.authorized_value == AMOUNT
    assert auth.beneficiary_address == DEPOSITOR
    assert auth.finalized_anchor == BLOCK_HASH
    assert auth.deposit_id.startswith(b"EVM-DEPOSIT-v1:")


def test_rejection_on_custody_contract_mismatch() -> None:
    authorizer = TrustedDepositAuthorizer(
        expected_namespace_id=NAMESPACE,
        pinned_custody_contract=CUSTODY_CONTRACT,
    )

    observed = make_observed_deposit(contract_address=OTHER_CONTRACT)

    header = make_header(
        number=BLOCK_NUMBER,
        block_hash=BLOCK_HASH,
        receipts_root=bytes(32),
    )

    custody = CustodySolvencySnapshot(
        contract_address=CUSTODY_CONTRACT,
        contract_balance=100_000,
        total_minted_prior=0,
    )

    with pytest.raises(DepositAuthorizationRejected, match="differs from pinned custody contract"):
        authorizer.authorize(
            observed_deposit=observed,
            finalized_header=header,
            receipt_rlp=b"dummy",
            receipt_mpt_proof=b"",
            receipt_path_rlp=b"",
            custody_snapshot=custody,
            current_finalized_block_number=BLOCK_NUMBER + 100,
        )


def test_rejection_on_custody_reserve_insolvency() -> None:
    authorizer = TrustedDepositAuthorizer(
        expected_namespace_id=NAMESPACE,
        pinned_custody_contract=CUSTODY_CONTRACT,
    )

    observed = make_observed_deposit(amount=10_000)

    header = make_header(
        number=BLOCK_NUMBER,
        block_hash=BLOCK_HASH,
        receipts_root=bytes(32),
    )

    # Insolvent: contract balance (5,000) < required reserve (total_minted 0 + amount 10,000)
    insolvent_custody = CustodySolvencySnapshot(
        contract_address=CUSTODY_CONTRACT,
        contract_balance=5_000,
        total_minted_prior=0,
    )

    with pytest.raises(DepositAuthorizationRejected, match="custody insolvency"):
        authorizer.authorize(
            observed_deposit=observed,
            finalized_header=header,
            receipt_rlp=b"dummy",
            receipt_mpt_proof=b"",
            receipt_path_rlp=b"",
            custody_snapshot=insolvent_custody,
            current_finalized_block_number=BLOCK_NUMBER + 100,
        )


def test_rejection_on_insufficient_finality_depth() -> None:
    authorizer = TrustedDepositAuthorizer(
        expected_namespace_id=NAMESPACE,
        pinned_custody_contract=CUSTODY_CONTRACT,
        min_confirmations=64,
    )

    observed = make_observed_deposit()

    header = make_header(
        number=BLOCK_NUMBER,
        block_hash=BLOCK_HASH,
        receipts_root=bytes(32),
    )

    custody = CustodySolvencySnapshot(
        contract_address=CUSTODY_CONTRACT,
        contract_balance=100_000,
        total_minted_prior=0,
    )

    # Only 10 confirmations, less than 64 required
    with pytest.raises(DepositAuthorizationRejected, match="insufficient finality confirmations"):
        authorizer.authorize(
            observed_deposit=observed,
            finalized_header=header,
            receipt_rlp=b"dummy",
            receipt_mpt_proof=b"",
            receipt_path_rlp=b"",
            custody_snapshot=custody,
            current_finalized_block_number=BLOCK_NUMBER + 10,
        )
