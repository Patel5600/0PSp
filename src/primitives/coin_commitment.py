"""0PSP coin-commitment V2 reference and legacy V1 helper.

V2 explicitly commits to a 48-byte namespace ID and 32-byte coin ID. V1 is
retained only for historical vectors. These functions implement byte encodings
and opening recomputation; they do not implement a commitment proof or a
complete hiding/binding theorem. Canonical public-key encoding still depends
on the signature scheme/parameters, and a real mint ledger must enforce
namespace-scoped coin-ID uniqueness atomically.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

from .nullifier import (
    COIN_ID_BYTES,
    NULLIFIER_SECRET_BYTES,
    CoinId,
    NullifierSecret,
)
from .namespace import NAMESPACE_ID_BYTES, NamespaceId, ScopedCoinId

COMMITMENT_BYTES = 48
COMMITMENT_RANDOMNESS_BYTES = 36
DOMAIN_COIN_COMMITMENT = b"0PSP-COIN-COMMIT-v1-SHAKE256"
PROTOCOL_VERSION = b"\x01"


@dataclass(frozen=True)
class CoinCommitment:
    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes) or len(self.value) != COMMITMENT_BYTES:
            raise ValueError(f"coin commitment must be exactly {COMMITMENT_BYTES} bytes")


def _encode_commitment_input(
    public_key: bytes,
    value: int,
    coin_id: CoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> bytes:
    if not isinstance(public_key, bytes) or not public_key:
        raise ValueError("public_key must be non-empty canonical bytes")
    if len(public_key) >= 2**32:
        raise ValueError("public_key encoding is too large")
    if not isinstance(params_id, bytes) or not params_id or len(params_id) >= 2**16:
        raise ValueError("params_id must be 1..65535 bytes")
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**64:
        raise ValueError("value must be an unsigned 64-bit integer")
    if not isinstance(coin_id, CoinId):
        raise TypeError("coin_id must be a CoinId")
    if not isinstance(r_nf, NullifierSecret):
        raise TypeError("r_nf must be a NullifierSecret")
    if not isinstance(rho_coin, bytes) or len(rho_coin) != COMMITMENT_RANDOMNESS_BYTES:
        raise ValueError(
            f"rho_coin must be exactly {COMMITMENT_RANDOMNESS_BYTES} bytes"
        )

    # Every variable-length field has an explicit length prefix. The public
    # key encoding must be canonical for the selected threshold-signature scheme.
    return b"".join((
        DOMAIN_COIN_COMMITMENT,
        PROTOCOL_VERSION,
        len(params_id).to_bytes(2, "little"),
        params_id,
        len(public_key).to_bytes(4, "little"),
        public_key,
        value.to_bytes(8, "little"),
        len(coin_id.data).to_bytes(2, "little"),
        coin_id.data,
        len(r_nf.data).to_bytes(2, "little"),
        r_nf.data,
        len(rho_coin).to_bytes(2, "little"),
        rho_coin,
    ))


def commit_coin(
    public_key: bytes,
    value: int,
    coin_id: CoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> CoinCommitment:
    """Compute a 48-byte domain-separated SHAKE256 commitment candidate."""
    preimage = _encode_commitment_input(
        public_key, value, coin_id, r_nf, rho_coin, params_id
    )
    return CoinCommitment(hashlib.shake_256(preimage).digest(COMMITMENT_BYTES))


def verify_coin_opening(
    commitment: CoinCommitment,
    public_key: bytes,
    value: int,
    coin_id: CoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> bool:
    """Recompute an opening for functional tests; not a ZK proof verifier."""
    expected = commit_coin(
        public_key, value, coin_id, r_nf, rho_coin, params_id
    )
    return hmac.compare_digest(commitment.value, expected.value)


# V2 explicitly binds the public namespace. V1 stays available only to preserve
# historical vectors; new protocol statements must use V2.
DOMAIN_COIN_COMMITMENT_V2 = b"0PSP-COIN-COMMIT-v2-SHAKE256"
COMMITMENT_V2_VERSION = b"\x02"


def _encode_commitment_input_v2(
    namespace_id: NamespaceId,
    public_key: bytes,
    value: int,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> bytes:
    if not isinstance(namespace_id, NamespaceId):
        raise TypeError("namespace_id must be a NamespaceId")
    if not isinstance(public_key, bytes) or not public_key:
        raise ValueError("public_key must be non-empty canonical bytes")
    if len(public_key) >= 2**32:
        raise ValueError("public_key encoding is too large")
    if not isinstance(params_id, bytes) or not params_id or len(params_id) >= 2**16:
        raise ValueError("params_id must be 1..65535 bytes")
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**64:
        raise ValueError("value must be an unsigned 64-bit integer")
    if not isinstance(coin_id, ScopedCoinId):
        raise TypeError("coin_id must be a ScopedCoinId")
    if not isinstance(r_nf, NullifierSecret):
        raise TypeError("r_nf must be a NullifierSecret")
    if not isinstance(rho_coin, bytes) or len(rho_coin) != COMMITMENT_RANDOMNESS_BYTES:
        raise ValueError(
            f"rho_coin must be exactly {COMMITMENT_RANDOMNESS_BYTES} bytes"
        )

    return b"".join((
        DOMAIN_COIN_COMMITMENT_V2,
        COMMITMENT_V2_VERSION,
        len(params_id).to_bytes(2, "little"),
        params_id,
        len(public_key).to_bytes(4, "little"),
        public_key,
        value.to_bytes(8, "little"),
        len(namespace_id.data).to_bytes(2, "little"),
        namespace_id.data,
        len(coin_id.data).to_bytes(2, "little"),
        coin_id.data,
        len(r_nf.data).to_bytes(2, "little"),
        r_nf.data,
        len(rho_coin).to_bytes(2, "little"),
        rho_coin,
    ))


def commit_coin_v2(
    namespace_id: NamespaceId,
    public_key: bytes,
    value: int,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> CoinCommitment:
    """Compute a namespace-bound 48-byte commitment candidate, not a proof."""
    preimage = _encode_commitment_input_v2(
        namespace_id, public_key, value, coin_id, r_nf, rho_coin, params_id
    )
    return CoinCommitment(hashlib.shake_256(preimage).digest(COMMITMENT_BYTES))


def verify_coin_opening_v2(
    commitment: CoinCommitment,
    namespace_id: NamespaceId,
    public_key: bytes,
    value: int,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> bool:
    """Recompute a V2 opening for tests; this is not a ZK proof verifier."""
    if not isinstance(commitment, CoinCommitment):
        raise TypeError("commitment must be a CoinCommitment")
    expected = commit_coin_v2(
        namespace_id, public_key, value, coin_id, r_nf, rho_coin, params_id
    )
    return hmac.compare_digest(commitment.value, expected.value)


def commit_coin_v2_native(
    namespace_id: NamespaceId,
    public_key: bytes,
    value: int,
    coin_id: ScopedCoinId,
    r_nf: bytearray,
    rho_coin: bytearray,
    params_id: bytes,
    *,
    library_path: str | Path,
) -> CoinCommitment:
    """Compute V2 commitment in the native helper without a Python hash fallback.

    Secret inputs must be caller-owned bytearrays so this adapter can borrow
    their buffers instead of first converting them to immutable Python bytes.
    The ctypes boundary still does not establish zero-copy handling of all
    surrounding data or constant-time behavior for the process.
    """
    if not isinstance(namespace_id, NamespaceId):
        raise TypeError("namespace_id must be a NamespaceId")
    if not isinstance(coin_id, ScopedCoinId):
        raise TypeError("coin_id must be a ScopedCoinId")
    if not isinstance(public_key, bytes) or not public_key or len(public_key) >= 2**32:
        raise ValueError("public_key must be non-empty canonical bytes")
    if not isinstance(params_id, bytes) or not params_id or len(params_id) >= 2**16:
        raise ValueError("params_id must be 1..65535 bytes")
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**64:
        raise ValueError("value must be an unsigned 64-bit integer")
    if not isinstance(r_nf, bytearray) or len(r_nf) != NULLIFIER_SECRET_BYTES:
        raise ValueError(f"r_nf must be a bytearray of exactly {NULLIFIER_SECRET_BYTES} bytes")
    if not isinstance(rho_coin, bytearray) or len(rho_coin) != COMMITMENT_RANDOMNESS_BYTES:
        raise ValueError(
            f"rho_coin must be a bytearray of exactly {COMMITMENT_RANDOMNESS_BYTES} bytes"
        )
    try:
        library = ctypes.CDLL(str(Path(library_path)))
    except OSError as exc:
        raise RuntimeError(f"cannot load native 0PSP library: {library_path}") from exc

    function = library.psp_coin_commitment_v2
    byte_p = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
        ctypes.c_uint64,
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
        byte_p, ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int
    params_buf = (ctypes.c_ubyte * len(params_id)).from_buffer_copy(params_id)
    public_key_buf = (ctypes.c_ubyte * len(public_key)).from_buffer_copy(public_key)
    namespace_buf = (ctypes.c_ubyte * NAMESPACE_ID_BYTES).from_buffer_copy(namespace_id.data)
    coin_buf = (ctypes.c_ubyte * len(coin_id.data)).from_buffer_copy(coin_id.data)
    secret_buf = (ctypes.c_ubyte * NULLIFIER_SECRET_BYTES).from_buffer(r_nf)
    salt_buf = (ctypes.c_ubyte * COMMITMENT_RANDOMNESS_BYTES).from_buffer(rho_coin)
    output_buf = (ctypes.c_ubyte * COMMITMENT_BYTES)()
    status = function(
        params_buf, len(params_id),
        public_key_buf, len(public_key),
        value,
        namespace_buf, NAMESPACE_ID_BYTES,
        coin_buf, len(coin_id.data),
        secret_buf, NULLIFIER_SECRET_BYTES,
        salt_buf, COMMITMENT_RANDOMNESS_BYTES,
        output_buf, COMMITMENT_BYTES,
    )
    if status != 0:
        raise RuntimeError(f"native V2 coin commitment failed with status {status}")
    return CoinCommitment(bytes(output_buf))


def generate_commitment_salt_v2_native(*, library_path: str | Path) -> bytearray:
    """Generate an independent 36-byte commitment salt through the native RNG.

    No Python RNG fallback is used. The caller owns the mutable buffer and
    should clear it after use. This function is a research/FFI helper, not a
    proof that the whole caller path is constant-time or copy-free.
    """
    try:
        library = ctypes.CDLL(str(Path(library_path)))
    except OSError as exc:
        raise RuntimeError(f"cannot load native 0PSP library: {library_path}") from exc
    function = library.psp_coin_commitment_v2_generate_salt
    byte_p = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [byte_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    salt = bytearray(COMMITMENT_RANDOMNESS_BYTES)
    out_buf = (ctypes.c_ubyte * COMMITMENT_RANDOMNESS_BYTES).from_buffer(salt)
    status = function(out_buf, COMMITMENT_RANDOMNESS_BYTES)
    if status != 0:
        salt[:] = bytes(COMMITMENT_RANDOMNESS_BYTES)
        raise RuntimeError(f"native V2 commitment salt generation failed with status {status}")
    return salt
