"""Adversarial replay tests for the CHp4.1 state-transition reference model.

The proof callbacks are test doubles. This file tests state-machine replay
behavior, not cryptographic issuance-proof verification.
"""
from __future__ import annotations

import pytest

from src.primitives.namespace_v3 import derive_namespace_id_v3
from src.protocol.reference_ledger import (
    DepositAuthorization,
    DuplicateDeposit,
    ReferenceLedger,
)

NS = derive_namespace_id_v3(b"adversarial-ledger", b"test-deployment", b"test-asset")
ANCHOR = bytes([0x61]) * 32
PARAMS = b"v2-adversarial-params"


def _ledger() -> ReferenceLedger:
    def authorize(evidence: bytes):
        if evidence != b"authenticated-deposit":
            return None
        return DepositAuthorization(
            namespace_id=NS,
            deposit_id=b"chain-id:tx-hash:output-index:7",
            authorized_value=10,
            finalized_anchor=ANCHOR,
            beneficiary_address=bytes([0x55]) * 20,
        )

    # Explicitly a test double. A production verifier must enforce R_mint and
    # prove the hidden opening contains authorized_value without exposing it.
    return ReferenceLedger(
        expected_namespace_id=NS,
        authorize_deposit=authorize,
        verify_issuance_proof=lambda statement, proof: (
            statement.version == 2 and statement.authorized_value == 10 and proof == b"test-only-proof"
        ),
        verify_spend_proof=lambda _statement, _proof: False,
    )


def test_same_deposit_cannot_mint_a_second_commitment() -> None:
    ledger = _ledger()
    ledger.issue(
        deposit_evidence=b"authenticated-deposit",
        commitment=b"\xA1" * 48,
        params_id=PARAMS,
        proof=b"test-only-proof",
    )
    with pytest.raises(DuplicateDeposit):
        ledger.issue(
            deposit_evidence=b"authenticated-deposit",
            commitment=b"\xB2" * 48,
            params_id=PARAMS,
            proof=b"test-only-proof",
        )
    assert ledger.issued_count == 1
    assert ledger.state_version == 1


def test_untrusted_or_unknown_deposit_is_not_authorized() -> None:
    ledger = _ledger()
    with pytest.raises(ValueError, match="deposit"):
        ledger.issue(
            deposit_evidence=b"user-supplied-deposit-claim",
            commitment=b"\xC3" * 48,
            params_id=PARAMS,
            proof=b"test-only-proof",
        )
    assert ledger.issued_count == 0
    assert ledger.state_version == 0
