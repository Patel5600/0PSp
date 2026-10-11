"""Canonical 0PSP namespace identifiers and per-namespace coin IDs.

This module defines byte-level research primitives, not a minting ledger.
A namespace is the tuple (ledger, deployment, asset). The SHAKE-derived
NamespaceId is 48 bytes to retain a 128-bit generic quantum collision target
under the usual idealized quantum collision-search estimate. The CoinId is a
fresh 32-byte opaque identifier, unique within that namespace by an atomic
ledger invariant; it is not a truncated hash output.

No chain-specific address encoding is guessed here. Adapters must convert
native ledger, deployment and asset identifiers to canonical 32-byte values.
"""
from __future__ import annotations

import ctypes
import hashlib
from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Final

NAMESPACE_COMPONENT_BYTES: Final = 32
NAMESPACE_ID_BYTES: Final = 48
SCOPED_COIN_ID_BYTES: Final = 32
NAMESPACE_V2_VERSION: Final = b"\x02"
DOMAIN_NAMESPACE_V2: Final = b"0PSP-NAMESPACE-v2-SHAKE256"


@dataclass(frozen=True, slots=True)
class NamespaceId:
    """Public 48-byte digest binding a ledger, deployment and asset."""

    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) != NAMESPACE_ID_BYTES:
            raise ValueError(f"namespace_id must be exactly {NAMESPACE_ID_BYTES} bytes")

    def __repr__(self) -> str:
        return f"NamespaceId({self.data.hex()[:16]}…)"


@dataclass(frozen=True, slots=True)
class ScopedCoinId:
    """32-byte opaque coin identifier; identity is (namespace_id, coin_id)."""

    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) != SCOPED_COIN_ID_BYTES:
            raise ValueError(f"coin_id_v2 must be exactly {SCOPED_COIN_ID_BYTES} bytes")

    def __repr__(self) -> str:
        # A coin ID can be sensitive metadata before it is intentionally disclosed.
        return "ScopedCoinId(<redacted>)"


def _require_component(value: bytes, name: str) -> None:
    if not isinstance(value, bytes) or len(value) != NAMESPACE_COMPONENT_BYTES:
        raise ValueError(f"{name} must be exactly {NAMESPACE_COMPONENT_BYTES} canonical bytes")


def derive_namespace_id(
    ledger_id: bytes,
    deployment_id: bytes,
    asset_id: bytes,
) -> NamespaceId:
    """Derive a versioned 48-byte namespace ID from three canonical 32-byte IDs.

    ledger_id should bind to the actual ledger/network instance (prefer a stable
    genesis/network identifier, not a short display chain name). deployment_id
    identifies the relevant deployed protocol instance. asset_id identifies
    the canonical asset, not its display ticker. Chain adapters own the canonical
    conversion of these values into 32-byte identifiers.
    """
    _require_component(ledger_id, "ledger_id")
    _require_component(deployment_id, "deployment_id")
    _require_component(asset_id, "asset_id")
    size = NAMESPACE_COMPONENT_BYTES.to_bytes(2, "little")
    preimage = b"".join((
        DOMAIN_NAMESPACE_V2,
        NAMESPACE_V2_VERSION,
        size, ledger_id,
        size, deployment_id,
        size, asset_id,
    ))
    return NamespaceId(hashlib.shake_256(preimage).digest(NAMESPACE_ID_BYTES))


def generate_scoped_coin_id_native_buffer(*, library_path: str | Path) -> bytearray:
    """Generate a mutable 32-byte coin-ID buffer through native OS-backed RNG.

    Prefer this form when the coin ID is still a private witness and will be
    passed directly to the native nullifier/commitment functions. The caller
    owns the returned buffer and should clear it after use. The actual mint
    ledger must atomically reject duplicate (namespace_id, coin_id) pairs.
    """
    try:
        # Hold the GIL while native code writes into the borrowed bytearray.
        library = ctypes.PyDLL(str(Path(library_path)))
    except OSError as exc:
        raise RuntimeError(f"cannot load native 0PSP library: {library_path}") from exc
    function = library.psp_coin_id_v2_generate
    byte_p = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [byte_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    raw = bytearray(SCOPED_COIN_ID_BYTES)
    out = (ctypes.c_ubyte * SCOPED_COIN_ID_BYTES).from_buffer(raw)
    status = function(out, SCOPED_COIN_ID_BYTES)
    if status != 0:
        raw[:] = bytes(SCOPED_COIN_ID_BYTES)
        raise RuntimeError(f"native coin-ID generation failed with status {status}")
    return raw


def generate_scoped_coin_id_native(*, library_path: str | Path) -> ScopedCoinId:
    """Convenience wrapper for tests/reference code; returns an immutable ID.

    For secret handling prefer generate_scoped_coin_id_native_buffer and keep
    the result mutable. This compatibility helper necessarily creates an
    immutable copy and must not be treated as a secret-safe boundary.
    """
    raw = generate_scoped_coin_id_native_buffer(library_path=library_path)
    try:
        return ScopedCoinId(bytes(raw))
    finally:
        raw[:] = bytes(SCOPED_COIN_ID_BYTES)


class MintRegistryModel:
    """Thread-safe in-memory model of atomic per-namespace mint uniqueness.

    This is a test model only. Production must enforce the same invariant in
    durable consensus/ledger state, transactionally, including reorg handling.
    """

    def __init__(self) -> None:
        self._minted: set[tuple[bytes, bytes]] = set()
        self._lock = threading.Lock()

    def try_mint(self, namespace_id: NamespaceId, coin_id: ScopedCoinId) -> bool:
        if not isinstance(namespace_id, NamespaceId):
            raise TypeError("namespace_id must be a NamespaceId")
        if not isinstance(coin_id, ScopedCoinId):
            raise TypeError("coin_id must be a ScopedCoinId")
        key = (namespace_id.data, coin_id.data)
        with self._lock:
            if key in self._minted:
                return False
            self._minted.add(key)
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._minted)
