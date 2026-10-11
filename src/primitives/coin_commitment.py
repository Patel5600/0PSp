"""Hash-based coin commitment candidate for the 0PSP single-proof prototype.

This is a concrete functional construction, not a proven commitment scheme. The helper assumes coin_id was already created/validated in a canonical ledger/deployment-and-asset namespace; it only commits to the supplied 32-byte value and does not enforce minting uniqueness or namespace correctness.
Candidate security model: SHAKE256 modeled as a quantum-accessible random
oracle; a 36-byte random salt is used to make guessing the commitment input
expensive under the project's stated query budget. The spend proof must prove
the opening relation. This module alone proves no hiding/binding theorem.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

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
