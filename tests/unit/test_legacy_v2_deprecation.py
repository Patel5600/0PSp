"""Tests asserting deprecation guard behavior for legacy V2 nullifiers."""

import os
from unittest.mock import patch
import pytest

from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import (
    DeprecatedPrimitiveError,
    NullifierSecret,
    compute_nullifier_v2,
    compute_nullifier_v2_native,
)


def test_v2_nullifier_deprecated_by_default() -> None:
    ns = NamespaceId(b"\x01" * 48)
    coin_id = ScopedCoinId(b"\x02" * 32)
    r_nf = NullifierSecret(b"\x03" * 36)

    # When ALLOW_LEGACY_V2_KATS is not 1, must raise DeprecatedPrimitiveError
    with patch.dict(os.environ, {"ALLOW_LEGACY_V2_KATS": "0"}):
        with pytest.raises(DeprecatedPrimitiveError, match="compute_nullifier_v2 is deprecated"):
            compute_nullifier_v2(ns, coin_id, r_nf)


def test_v2_nullifier_allowed_when_flag_set() -> None:
    ns = NamespaceId(b"\x01" * 48)
    coin_id = ScopedCoinId(b"\x02" * 32)
    r_nf = NullifierSecret(b"\x03" * 36)

    # When ALLOW_LEGACY_V2_KATS is 1, succeeds
    with patch.dict(os.environ, {"ALLOW_LEGACY_V2_KATS": "1"}):
        nf = compute_nullifier_v2(ns, coin_id, r_nf)
        assert len(nf.value) == 48
