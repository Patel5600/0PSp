"""Additive V3 note-commitment candidate.

V1/V2 functions, domains and vectors remain untouched. V3 uses a distinct domain
and version and is intended to commit to a canonical NotePublicKeyBundleV3 in
the public_key field. It is a reference hash function, not a proof verifier.
"""
from __future__ import annotations

import hashlib
import hmac

from src.primitives.coin_commitment import (
    COMMITMENT_BYTES,
    COMMITMENT_RANDOMNESS_BYTES,
)
from src.primitives.namespace import ScopedCoinId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.nullifier import NullifierSecret
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.protocol.note_public_key_bundle_v3 import decode_note_public_key_bundle_v3

DOMAIN_COIN_COMMITMENT_V3 = b"0PSP-COIN-COMMIT-v3-SHAKE256"
COIN_COMMITMENT_V3_VERSION = b"\x03"


def _encode_commitment_input_v3(
    namespace_id: NamespaceIdV3,
    public_key_bundle: bytes,
    value: int,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> bytes:
    if not isinstance(namespace_id, NamespaceIdV3):
        raise TypeError("namespace_id must be a NamespaceIdV3")
    if not isinstance(public_key_bundle, bytes) or not public_key_bundle:
        raise ValueError("public_key_bundle must be non-empty canonical bytes")
    decode_note_public_key_bundle_v3(public_key_bundle)
    if len(public_key_bundle) >= (1 << 32):
        raise ValueError("public_key_bundle encoding is too large")
    if not isinstance(params_id, bytes) or not 1 <= len(params_id) < (1 << 16):
        raise ValueError("params_id must be 1..65535 bytes")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 64):
        raise ValueError("value must be an unsigned 64-bit integer")
    if not isinstance(coin_id, ScopedCoinId):
        raise TypeError("coin_id must be a ScopedCoinId")
    if not isinstance(r_nf, NullifierSecret):
        raise TypeError("r_nf must be a NullifierSecret")
    if not isinstance(rho_coin, bytes) or len(rho_coin) != COMMITMENT_RANDOMNESS_BYTES:
        raise ValueError(f"rho_coin must be exactly {COMMITMENT_RANDOMNESS_BYTES} bytes")

    return b"".join((
        DOMAIN_COIN_COMMITMENT_V3,
        COIN_COMMITMENT_V3_VERSION,
        len(params_id).to_bytes(2, "little"),
        params_id,
        len(public_key_bundle).to_bytes(4, "little"),
        public_key_bundle,
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


def commit_coin_v3(
    namespace_id: NamespaceIdV3,
    public_key_bundle: bytes,
    value: int,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> CoinCommitmentV3:
    """Compute the 48-byte V3 commitment candidate over a canonical key bundle."""
    encoded = _encode_commitment_input_v3(
        namespace_id, public_key_bundle, value, coin_id, r_nf, rho_coin, params_id
    )
    return CoinCommitmentV3(hashlib.shake_256(encoded).digest(COMMITMENT_BYTES))


def verify_coin_opening_v3(
    commitment: CoinCommitmentV3,
    namespace_id: NamespaceIdV3,
    public_key_bundle: bytes,
    value: int,
    coin_id: ScopedCoinId,
    r_nf: NullifierSecret,
    rho_coin: bytes,
    params_id: bytes,
) -> bool:
    """Recompute the V3 opening for tests; this is not a ZK proof verifier."""
    if not isinstance(commitment, CoinCommitmentV3):
        raise TypeError("commitment must be a CoinCommitmentV3")
    expected = commit_coin_v3(
        namespace_id, public_key_bundle, value, coin_id, r_nf, rho_coin, params_id
    )
    return hmac.compare_digest(commitment.value, expected.value)
