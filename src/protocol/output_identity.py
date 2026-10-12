"""CHp4.6 hidden-witness output-identity derivation candidate.

This deterministic Python reference helper is NOT a zero-knowledge constraint
system or a production security fix. A future relation must bind the key
witness to the input public key and constrain these exact derivations for every
output and its commitment opening. The scheme-specific key encoding is unfrozen.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import (
    NULLIFIER_BYTES,
    NULLIFIER_SECRET_BYTES,
    NullifierSecret,
    compute_nullifier_v2,
)

OUTPUT_ID_BYTES = 32
TRANSACTION_ENTROPY_BYTES = 32
OUTPUT_INDEX_MAX = (1 << 16) - 1
OUTPUT_ID_DERIVATION_VERSION = b"\x01"
DOMAIN_OUTPUT_COIN_ID = b"0PSP-OUTPUT-COIN-ID-CANDIDATE-v1"
DOMAIN_OUTPUT_RNF = b"0PSP-OUTPUT-RNF-CANDIDATE-v1"


@dataclass(frozen=True, slots=True)
class OutputIdentityCandidate:
    """Candidate output identity with canonical repository field widths."""

    coin_id: ScopedCoinId
    r_nf: NullifierSecret

    def __repr__(self) -> str:
        return "OutputIdentityCandidate(<redacted>)"


def _validate_inputs(
    namespace_id: NamespaceId,
    parent_coin_id: ScopedCoinId,
    parent_r_nf: NullifierSecret,
    spend_key_witness: bytes,
    transaction_entropy: bytes,
    output_index: int,
    params_id: bytes,
) -> None:
    if not isinstance(namespace_id, NamespaceId):
        raise TypeError("namespace_id must be a NamespaceId")
    if not isinstance(parent_coin_id, ScopedCoinId):
        raise TypeError("parent_coin_id must be a ScopedCoinId")
    if not isinstance(parent_r_nf, NullifierSecret):
        raise TypeError("parent_r_nf must be a NullifierSecret")
    if not isinstance(spend_key_witness, bytes) or not spend_key_witness:
        raise ValueError("spend_key_witness must be non-empty canonical secret bytes")
    if len(spend_key_witness) >= (1 << 32):
        raise ValueError("spend_key_witness encoding is too large")
    if not isinstance(transaction_entropy, bytes) or len(transaction_entropy) != TRANSACTION_ENTROPY_BYTES:
        raise ValueError(
            f"transaction_entropy must be exactly {TRANSACTION_ENTROPY_BYTES} bytes"
        )
    if not isinstance(params_id, bytes) or not params_id or len(params_id) >= (1 << 16):
        raise ValueError("params_id must be 1..65535 bytes")
    if (
        isinstance(output_index, bool)
        or not isinstance(output_index, int)
        or not 0 <= output_index <= OUTPUT_INDEX_MAX
    ):
        raise ValueError(f"output_index must be an integer in [0, {OUTPUT_INDEX_MAX}]")


def _preimage(
    domain: bytes,
    namespace_id: NamespaceId,
    parent_coin_id: ScopedCoinId,
    parent_r_nf: NullifierSecret,
    spend_key_witness: bytes,
    transaction_entropy: bytes,
    output_index: int,
    params_id: bytes,
) -> bytes:
    """Canonical candidate encoding; fixed-size fields need no length prefix."""
    parent_nullifier = compute_nullifier_v2(
        namespace_id, parent_coin_id, parent_r_nf
    ).value
    return b"".join((
        domain,
        OUTPUT_ID_DERIVATION_VERSION,
        len(params_id).to_bytes(2, "little"),
        params_id,
        namespace_id.data,
        parent_nullifier,
        parent_coin_id.data,
        parent_r_nf.data,
        len(spend_key_witness).to_bytes(4, "little"),
        spend_key_witness,
        transaction_entropy,
        output_index.to_bytes(2, "big"),
    ))


def derive_output_identity_candidate(
    *,
    namespace_id: NamespaceId,
    parent_coin_id: ScopedCoinId,
    parent_r_nf: NullifierSecret,
    spend_key_witness: bytes,
    transaction_entropy: bytes,
    output_index: int,
    params_id: bytes,
) -> OutputIdentityCandidate:
    """Derive a 32-byte coin ID and 36-byte nullifier secret for an output.

    The candidate encoding binds parameter ID, namespace, the actual parent
    V2 nullifier and its hidden tuple, scheme-canonical spend-key witness,
    transaction entropy, and uint16 big-endian output index. Each field is
    derived with a separate domain tag.

    This helper cannot prove key-witness consistency, honest entropy sampling,
    circuit enforcement, or privacy. Those are independent proof obligations.
    """
    _validate_inputs(
        namespace_id, parent_coin_id, parent_r_nf, spend_key_witness,
        transaction_entropy, output_index, params_id,
    )
    coin_id = hashlib.shake_256(_preimage(
        DOMAIN_OUTPUT_COIN_ID, namespace_id, parent_coin_id, parent_r_nf,
        spend_key_witness, transaction_entropy, output_index, params_id,
    )).digest(OUTPUT_ID_BYTES)
    r_nf = hashlib.shake_256(_preimage(
        DOMAIN_OUTPUT_RNF, namespace_id, parent_coin_id, parent_r_nf,
        spend_key_witness, transaction_entropy, output_index, params_id,
    )).digest(NULLIFIER_SECRET_BYTES)
    assert len(coin_id) == OUTPUT_ID_BYTES
    assert len(r_nf) == NULLIFIER_SECRET_BYTES
    return OutputIdentityCandidate(
        coin_id=ScopedCoinId(coin_id),
        r_nf=NullifierSecret(r_nf),
    )


def verify_output_identity_candidate(
    *,
    output_coin_id: ScopedCoinId,
    output_r_nf: NullifierSecret,
    namespace_id: NamespaceId,
    parent_coin_id: ScopedCoinId,
    parent_r_nf: NullifierSecret,
    spend_key_witness: bytes,
    transaction_entropy: bytes,
    output_index: int,
    params_id: bytes,
) -> bool:
    """Reference equality predicate for tests; not a circuit/proof verifier."""
    if not isinstance(output_coin_id, ScopedCoinId):
        raise TypeError("output_coin_id must be a ScopedCoinId")
    if not isinstance(output_r_nf, NullifierSecret):
        raise TypeError("output_r_nf must be a NullifierSecret")
    expected = derive_output_identity_candidate(
        namespace_id=namespace_id,
        parent_coin_id=parent_coin_id,
        parent_r_nf=parent_r_nf,
        spend_key_witness=spend_key_witness,
        transaction_entropy=transaction_entropy,
        output_index=output_index,
        params_id=params_id,
    )
    return (
        hmac.compare_digest(expected.coin_id.data, output_coin_id.data)
        and hmac.compare_digest(expected.r_nf.data, output_r_nf.data)
    )
