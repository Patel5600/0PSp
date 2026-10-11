from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from src.primitives.namespace import (
    NAMESPACE_COMPONENT_BYTES,
    NAMESPACE_ID_BYTES,
    SCOPED_COIN_ID_BYTES,
    MintRegistryModel,
    NamespaceId,
    ScopedCoinId,
    derive_namespace_id,
)


def _components():
    return bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))


def test_namespace_v2_known_answer_vector() -> None:
    ledger_id, deployment_id, asset_id = _components()
    namespace = derive_namespace_id(ledger_id, deployment_id, asset_id)
    assert len(namespace.data) == NAMESPACE_ID_BYTES == 48
    assert namespace.data.hex() == (
        "04c0037350b1b2551c5b7f8b19642abd"
        "e118113083130340a0986aacfaad3d7d"
        "38c96dac07c80e9c3d45e0a1111279d2"
    )


@pytest.mark.parametrize("which", [0, 1, 2])
def test_namespace_binds_each_canonical_component(which: int) -> None:
    parts = list(_components())
    base = derive_namespace_id(*parts)
    changed = bytearray(parts[which])
    changed[0] ^= 1
    parts[which] = bytes(changed)
    assert derive_namespace_id(*parts) != base


def test_namespace_requires_canonical_32_byte_components() -> None:
    for bad in (b"", b"x" * 31, b"x" * 33, "x" * 32, None):
        with pytest.raises(ValueError, match="canonical bytes"):
            derive_namespace_id(bad, b"y" * 32, b"z" * 32)  # type: ignore[arg-type]


def test_scoped_coin_id_fixed_size_and_redacted_repr() -> None:
    coin = ScopedCoinId(bytes(range(SCOPED_COIN_ID_BYTES)))
    assert len(coin.data) == 32
    assert repr(coin) == "ScopedCoinId(<redacted>)"
    with pytest.raises(ValueError, match="coin_id_v2 must be exactly 32 bytes"):
        ScopedCoinId(b"x" * 31)


def test_mint_registry_model_atomically_rejects_same_scoped_coin() -> None:
    namespace_a = derive_namespace_id(*_components())
    ledger, deployment, asset = _components()
    changed_asset = bytes([asset[0] ^ 1]) + asset[1:]
    namespace_b = derive_namespace_id(ledger, deployment, changed_asset)
    coin_id = ScopedCoinId(b"c" * 32)
    registry = MintRegistryModel()
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: registry.try_mint(namespace_a, coin_id), range(64)))
    assert sum(results) == 1
    # The same raw 32-byte ID denotes a different identity in another namespace.
    assert registry.try_mint(namespace_b, coin_id)
    assert len(registry) == 2
