from __future__ import annotations

import pytest

from src.protocol.production1_ledger import SQLiteV3Production1TestnetLedger


def test_production1_ledger_refuses_injected_predicate_verifier() -> None:
    with pytest.raises(TypeError, match="committed release pins"):
        SQLiteV3Production1TestnetLedger(proof_verifier=lambda *_args: True)
