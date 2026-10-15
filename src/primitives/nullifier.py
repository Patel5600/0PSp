"""0PSP nullifier interfaces.

V2 is the active namespace-bound **byte-contract target**, not a production-safe
recipient-privacy construction. Its nullifier preimage includes the note's
coin_id and r_nf but no recipient-held secret. A party that creates/knows those
opening values can precompute and recognize the resulting V2 nullifier; the
V2 API must not be represented as protecting recipients from their note creator.
Keep the V2 bytes frozen for compatibility, but do not use them to authorize a
production private-spend deployment. PR #10's recipient-keyed V3 is a separate,
unmerged candidate and does not become safe merely by adding its hash helper.

The old compute_nullifier API and its 99-byte V1 input remain only for historical
vectors and must not be used for new scoped spends. Python routines are functional
references, not constant-time paths. Native functional agreement does not prove
a spend, mint correctness, commitment security, QROM security or absence of side
channels.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Final


class DeprecatedPrimitiveError(RuntimeError):
    """Raised when deprecated V2 nullifier primitive is invoked outside KAT test suite."""

from .namespace import (
    NAMESPACE_ID_BYTES,
    NamespaceId,
    ScopedCoinId,
)

COIN_ID_BYTES: Final = 32
NULLIFIER_SECRET_BYTES: Final = 36
NULLIFIER_BYTES: Final = 48
DOMAIN_NULLIFIER: Final = b"0PSP-NULLIFIER-v1-SHAKE256"
PROTOCOL_VERSION: Final = b"\x01"
NULLIFIER_INPUT_BYTES: Final = (
    len(DOMAIN_NULLIFIER) + len(PROTOCOL_VERSION) + 2 + COIN_ID_BYTES + 2 + NULLIFIER_SECRET_BYTES
)


@dataclass(frozen=True, slots=True)
class CoinId:
    """Canonical 32-byte coin identifier, scoped at mint to one ledger and asset.

    The nullifier function does not take a separate network/asset namespace;
    minting must enforce this scope before the ID becomes a coin commitment.
    """
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) != COIN_ID_BYTES:
            raise ValueError(f"coin_id must be exactly {COIN_ID_BYTES} bytes")

    def __repr__(self) -> str:
        return "CoinId(<redacted>)"


@dataclass(frozen=True, slots=True)
class NullifierSecret:
    """Per-coin 288-bit secret, separate from commitment salt and wallet keys."""
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) != NULLIFIER_SECRET_BYTES:
            raise ValueError(f"r_nf must be exactly {NULLIFIER_SECRET_BYTES} bytes")

    def __repr__(self) -> str:
        return "NullifierSecret(<redacted>)"


@dataclass(frozen=True, slots=True)
class Nullifier:
    """Canonical 48-byte public nullifier."""
    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes) or len(self.value) != NULLIFIER_BYTES:
            raise ValueError(f"nullifier must be exactly {NULLIFIER_BYTES} bytes")

    def __repr__(self) -> str:
        return f"Nullifier({self.value.hex()[:16]}…)"


def _hash_input(coin_id: CoinId, r_nf: NullifierSecret) -> bytes:
    """Build the frozen fixed-width preimage used by the reference implementation."""
    if not isinstance(coin_id, CoinId):
        raise TypeError("coin_id must be a CoinId")
    if not isinstance(r_nf, NullifierSecret):
        raise TypeError("r_nf must be a NullifierSecret")
    return (
        DOMAIN_NULLIFIER
        + PROTOCOL_VERSION
        + len(coin_id.data).to_bytes(2, "little")
        + coin_id.data
        + len(r_nf.data).to_bytes(2, "little")
        + r_nf.data
    )


def compute_nullifier(coin_id: CoinId, r_nf: NullifierSecret) -> Nullifier:
    """Compute deterministic candidate nullifier; this does not validate a coin."""
    h = hashlib.shake_256()
    h.update(_hash_input(coin_id, r_nf))
    return Nullifier(h.digest(NULLIFIER_BYTES))


def _load_native_library(library_path: str | Path):
    try:
        # PyDLL retains the GIL across a call so another Python thread cannot
        # mutate a borrowed secret bytearray while the native function reads it.
        # This does not protect against native threads or establish constant time.
        return ctypes.PyDLL(str(Path(library_path)))
    except OSError as exc:
        raise RuntimeError(f"cannot load native nullifier library: {library_path}") from exc


def generate_nullifier_secret_native(*, library_path: str | Path) -> bytearray:
    """Generate 36 per-coin secret bytes with OpenSSL RAND_bytes.

    No fallback RNG is used. The mutable buffer is returned to the caller so
    the native hashing path can borrow it without first copying it into a
    Python immutable-bytes object. The caller owns the secret lifecycle and
    must not reuse the result for another coin. CPython and the OS can still
    create copies outside this wrapper's control.
    """
    library = _load_native_library(library_path)
    function = library.psp_nullifier_v1_generate_secret
    byte_p = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [byte_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    secret = bytearray(NULLIFIER_SECRET_BYTES)
    out_buf = (ctypes.c_ubyte * NULLIFIER_SECRET_BYTES).from_buffer(secret)
    status = function(out_buf, NULLIFIER_SECRET_BYTES)
    if status != 0:
        secret[:] = bytes(NULLIFIER_SECRET_BYTES)
        raise RuntimeError(f"native nullifier secret generation failed with status {status}")
    return secret


def compute_nullifier_native(
    coin_id: CoinId,
    r_nf: bytearray,
    *,
    library_path: str | Path,
) -> Nullifier:
    """Call the native OpenSSL SHAKE256 implementation with a borrowed secret buffer.

    Requires a caller-owned mutable 36-byte buffer. It deliberately does not
    silently fall back to Python if loading or native execution fails. This
    ctypes API is a test/integration boundary, not itself a whole-process CT
    guarantee; production callers should manage secrets in a reviewed native
    or Rust layer without implicit copies.
    """
    if not isinstance(coin_id, CoinId):
        raise TypeError("coin_id must be a CoinId")
    if not isinstance(r_nf, bytearray) or len(r_nf) != NULLIFIER_SECRET_BYTES:
        raise ValueError(f"native r_nf must be a bytearray of exactly {NULLIFIER_SECRET_BYTES} bytes")

    library = _load_native_library(library_path)
    function = library.psp_nullifier_v1
    byte_p = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [
        byte_p, ctypes.c_size_t, byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int

    coin_buf = (ctypes.c_ubyte * COIN_ID_BYTES).from_buffer_copy(coin_id.data)
    secret_buf = (ctypes.c_ubyte * NULLIFIER_SECRET_BYTES).from_buffer(r_nf)
    output_buf = (ctypes.c_ubyte * NULLIFIER_BYTES)()
    status = function(
        coin_buf, COIN_ID_BYTES, secret_buf, NULLIFIER_SECRET_BYTES,
        output_buf, NULLIFIER_BYTES,
    )
    if status != 0:
        raise RuntimeError(f"native nullifier derivation failed with status {status}")
    return Nullifier(bytes(output_buf))


def verify_nullifier_consistency(
    nullifier: Nullifier, coin_id: CoinId, r_nf: NullifierSecret
) -> bool:
    """Functional consistency check; not a ZK verifier."""
    if not isinstance(nullifier, Nullifier):
        raise TypeError("nullifier must be a Nullifier")
    return hmac.compare_digest(compute_nullifier(coin_id, r_nf).value, nullifier.value)


class NullifierSet:
    """Thread-safe in-memory replay model; not a durable consensus ledger."""
    def __init__(self) -> None:
        self._spent: set[bytes] = set()
        self._lock = threading.Lock()

    def add(self, nullifier: Nullifier) -> None:
        if not isinstance(nullifier, Nullifier):
            raise TypeError("nullifier must be a Nullifier")
        with self._lock:
            self._spent.add(nullifier.value)

    def is_spent(self, nullifier: Nullifier) -> bool:
        if not isinstance(nullifier, Nullifier):
            raise TypeError("nullifier must be a Nullifier")
        with self._lock:
            return nullifier.value in self._spent

    def try_spend(self, nullifier: Nullifier) -> bool:
        """Atomically accept first use and reject repeats within this process."""
        if not isinstance(nullifier, Nullifier):
            raise TypeError("nullifier must be a Nullifier")
        with self._lock:
            if nullifier.value in self._spent:
                return False
            self._spent.add(nullifier.value)
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._spent)

    def __repr__(self) -> str:
        return f"NullifierSet(spent={len(self)})"


# Namespace-bound V2 is the active protocol target. V1 remains only for the
# frozen legacy component vectors and must not be used for new scoped spends.
DOMAIN_NULLIFIER_V2: Final = b"0PSP-NULLIFIER-v2-SHAKE256"
NULLIFIER_V2_VERSION: Final = b"\x02"
NULLIFIER_V2_INPUT_BYTES: Final = (
    len(DOMAIN_NULLIFIER_V2) + len(NULLIFIER_V2_VERSION)
    + 2 + NAMESPACE_ID_BYTES + 2 + 32 + 2 + NULLIFIER_SECRET_BYTES
)


def _nullifier_v2_preimage(
    namespace_id: NamespaceId,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
) -> bytes:
    if not isinstance(namespace_id, NamespaceId):
        raise TypeError("namespace_id must be a NamespaceId")
    if not isinstance(coin_id, ScopedCoinId):
        raise TypeError("coin_id must be a ScopedCoinId")
    if not isinstance(r_nf, NullifierSecret):
        raise TypeError("r_nf must be a NullifierSecret")
    return b"".join((
        DOMAIN_NULLIFIER_V2,
        NULLIFIER_V2_VERSION,
        len(namespace_id.data).to_bytes(2, "little"),
        namespace_id.data,
        len(coin_id.data).to_bytes(2, "little"),
        coin_id.data,
        len(r_nf.data).to_bytes(2, "little"),
        r_nf.data,
    ))


def generate_nullifier_secret_v2_native(*, library_path: str | Path) -> bytearray:
    """Generate a fresh 36-byte V2 nullifier secret with no Python fallback.

    Returns a mutable caller-owned buffer. Clear it after use. This helper is
    a FFI boundary for tests/research; it does not make the Python process a
    constant-time or zero-copy secret-handling environment.
    """
    library = _load_native_library(library_path)
    function = library.psp_nullifier_v2_generate_secret
    byte_p = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [byte_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    secret = bytearray(NULLIFIER_SECRET_BYTES)
    out_buf = (ctypes.c_ubyte * NULLIFIER_SECRET_BYTES).from_buffer(secret)
    status = function(out_buf, NULLIFIER_SECRET_BYTES)
    if status != 0:
        secret[:] = bytes(NULLIFIER_SECRET_BYTES)
        raise RuntimeError(f"native V2 nullifier secret generation failed with status {status}")
    return secret


def compute_nullifier_v2(
    namespace_id: NamespaceId,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
) -> Nullifier:
    """Compute a namespace-bound V2 nullifier reference.

    The public namespace_id and scoped coin_id must also be bound by the coin
    commitment and the full proof relation. This helper alone validates neither
    minting nor spend eligibility.
    """
    if os.environ.get("ALLOW_LEGACY_V2_KATS", "0") != "1":
        raise DeprecatedPrimitiveError(
            "compute_nullifier_v2 is deprecated due to V2 sender-linkability. "
            "Use V3 recipient-keyed nullifier for production spends. "
            "Set ALLOW_LEGACY_V2_KATS=1 to run legacy regression tests."
        )
    preimage = _nullifier_v2_preimage(namespace_id, coin_id, r_nf)
    return Nullifier(hashlib.shake_256(preimage).digest(NULLIFIER_BYTES))


def compute_nullifier_v2_native(
    namespace_id: NamespaceId,
    coin_id: ScopedCoinId | bytearray,
    r_nf: bytearray,
    *,
    library_path: str | Path,
) -> Nullifier:
    """Use the native namespace-bound V2 implementation, without fallback.

    Passing a mutable 32-byte bytearray lets the native function borrow the
    coin ID directly. Passing ScopedCoinId is convenient for tests, but copies
    its immutable bytes into a ctypes buffer.
    """
    if os.environ.get("ALLOW_LEGACY_V2_KATS", "0") != "1":
        raise DeprecatedPrimitiveError(
            "compute_nullifier_v2_native is deprecated due to V2 sender-linkability. "
            "Use V3 recipient-keyed nullifier for production spends. "
            "Set ALLOW_LEGACY_V2_KATS=1 to run legacy regression tests."
        )
    if not isinstance(namespace_id, NamespaceId):
        raise TypeError("namespace_id must be a NamespaceId")
    if isinstance(coin_id, bytearray):
        if len(coin_id) != 32:
            raise ValueError("native coin_id buffer must be exactly 32 bytes")
        coin_id_len = len(coin_id)
        coin_buf = (ctypes.c_ubyte * coin_id_len).from_buffer(coin_id)
    elif isinstance(coin_id, ScopedCoinId):
        coin_id_len = len(coin_id.data)
        coin_buf = (ctypes.c_ubyte * coin_id_len).from_buffer_copy(coin_id.data)
    else:
        raise TypeError("coin_id must be a ScopedCoinId or bytearray")
    if not isinstance(r_nf, bytearray) or len(r_nf) != NULLIFIER_SECRET_BYTES:
        raise ValueError(
            f"native r_nf must be a bytearray of exactly {NULLIFIER_SECRET_BYTES} bytes"
        )

    library = _load_native_library(library_path)
    function = library.psp_nullifier_v2
    byte_p = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int
    namespace_buf = (ctypes.c_ubyte * NAMESPACE_ID_BYTES).from_buffer_copy(namespace_id.data)
    secret_buf = (ctypes.c_ubyte * NULLIFIER_SECRET_BYTES).from_buffer(r_nf)
    output_buf = (ctypes.c_ubyte * NULLIFIER_BYTES)()
    status = function(
        namespace_buf, NAMESPACE_ID_BYTES,
        coin_buf, coin_id_len,
        secret_buf, NULLIFIER_SECRET_BYTES,
        output_buf, NULLIFIER_BYTES,
    )
    if status != 0:
        raise RuntimeError(f"native nullifier-v2 derivation failed with status {status}")
    return Nullifier(bytes(output_buf))


def verify_nullifier_v2_consistency(
    nullifier: Nullifier,
    namespace_id: NamespaceId,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
) -> bool:
    """Functional V2 consistency check; not a proof-system verifier."""
    if not isinstance(nullifier, Nullifier):
        raise TypeError("nullifier must be a Nullifier")
    return hmac.compare_digest(
        compute_nullifier_v2(namespace_id, coin_id, r_nf).value,
        nullifier.value,
    )
