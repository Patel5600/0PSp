"""CHp4.6 transfer and CHp4.7 issuance output-identity candidates.

These deterministic helpers are reference functions, not circuit constraints.
The CHp4.6 transfer candidate binds a tuple to parent state and output index,
but its tuple is known to the creator/prover. Therefore it MUST NOT be paired
with the unkeyed V2 nullifier when sender-unlinkability is required: the sender
can compute the recipient's future nullifier. A recipient-keyed nullifier
candidate is defined separately in src/primitives/nullifier_v3.py.

A production relation must bind each derivation to an authenticated one-use
anchor, canonical global output index, the corresponding commitment opening,
the recipient key bundle and the V3 nullifier. None of that is enforced by
this Python helper. The scheme-specific authorization key codec remains unfrozen.
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
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    compute_nullifier_v3,
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

# Issuance identity uses the canonical deposit event as its one-use anchor.
# The deposit ID must come from authenticated chain-adapter evidence; this
# reference helper cannot establish that the caller supplied a canonical ID.
DOMAIN_ISSUANCE_COIN_ID = b"0PSP-ISSUANCE-COIN-ID-CANDIDATE-v1"
DOMAIN_ISSUANCE_RNF = b"0PSP-ISSUANCE-RNF-CANDIDATE-v1"
DOMAIN_OUTPUT_COIN_ID_V3 = b"0PSP-OUTPUT-COIN-ID-v3"
DOMAIN_OUTPUT_RNF_V3 = b"0PSP-OUTPUT-RNF-v3"
DOMAIN_ISSUANCE_COIN_ID_V3 = b"0PSP-ISSUANCE-COIN-ID-v3"
DOMAIN_ISSUANCE_RNF_V3 = b"0PSP-ISSUANCE-RNF-v3"
ISSUANCE_ENTROPY_BYTES = 32
DEPOSIT_ID_MAX_BYTES = 128


def derive_issuance_output_identity_candidate(
    *,
    namespace_id: NamespaceId,
    deposit_id: bytes,
    recipient_key_bundle: bytes,
    issuance_entropy: bytes,
    output_index: int,
    params_id: bytes,
) -> OutputIdentityCandidate:
    """Derive a hidden issuance identity from a one-use deposit anchor.

    The deposit anchor plus canonical output index provides the uniqueness
    structure. issuance_entropy is private witness material and is not a
    uniqueness substitute. The issuance proof must bind the exact authenticated
    deposit ID and each output index to the hidden commitment opening; the
    ledger must atomically consume the deposit ID.

    This is a reference candidate, not a proof-system constraint or a
    production minting implementation.
    """
    if not isinstance(namespace_id, NamespaceId):
        raise TypeError("namespace_id must be a NamespaceId")
    if (
        not isinstance(deposit_id, bytes)
        or not 1 <= len(deposit_id) <= DEPOSIT_ID_MAX_BYTES
    ):
        raise ValueError(
            f"deposit_id must be canonical bytes of length 1..{DEPOSIT_ID_MAX_BYTES}"
        )
    if (
        not isinstance(recipient_key_bundle, bytes)
        or not recipient_key_bundle
        or len(recipient_key_bundle) >= (1 << 32)
    ):
        raise ValueError("recipient_key_bundle must be non-empty canonical bytes")
    if (
        not isinstance(issuance_entropy, bytes)
        or len(issuance_entropy) != ISSUANCE_ENTROPY_BYTES
    ):
        raise ValueError(
            f"issuance_entropy must be exactly {ISSUANCE_ENTROPY_BYTES} bytes"
        )
    if not isinstance(params_id, bytes) or not 1 <= len(params_id) < (1 << 16):
        raise ValueError("params_id must be 1..65535 bytes")
    if (
        isinstance(output_index, bool)
        or not isinstance(output_index, int)
        or not 0 <= output_index <= OUTPUT_INDEX_MAX
    ):
        raise ValueError(f"output_index must be an integer in [0, {OUTPUT_INDEX_MAX}]")

    def encode(domain: bytes) -> bytes:
        return b"".join((
            domain,
            OUTPUT_ID_DERIVATION_VERSION,
            len(params_id).to_bytes(2, "little"),
            params_id,
            namespace_id.data,
            len(deposit_id).to_bytes(2, "little"),
            deposit_id,
            len(recipient_key_bundle).to_bytes(4, "little"),
            recipient_key_bundle,
            len(issuance_entropy).to_bytes(2, "little"),
            issuance_entropy,
            output_index.to_bytes(2, "big"),
        ))

    coin_id = hashlib.shake_256(
        encode(DOMAIN_ISSUANCE_COIN_ID)
    ).digest(OUTPUT_ID_BYTES)
    r_nf = hashlib.shake_256(
        encode(DOMAIN_ISSUANCE_RNF)
    ).digest(NULLIFIER_SECRET_BYTES)
    assert len(coin_id) == OUTPUT_ID_BYTES
    assert len(r_nf) == NULLIFIER_SECRET_BYTES
    return OutputIdentityCandidate(
        coin_id=ScopedCoinId(coin_id),
        r_nf=NullifierSecret(r_nf),
    )


def derive_output_identity_v3_candidate(
    *,
    namespace_id: NamespaceId,
    parent_coin_id: ScopedCoinId,
    parent_r_nf: NullifierSecret,
    parent_public_key_bundle: bytes,
    parent_nullifier_key: NullifierDerivingKeyV3,
    spend_key_witness: bytes,
    recipient_key_bundle: bytes,
    transaction_entropy: bytes,
    output_index: int,
    params_id: bytes,
) -> OutputIdentityCandidate:
    """Derive a V3 transfer output identity bound to a recipient key bundle.

    This remains a reference candidate, not a ZK relation. The eventual proof
    must tie the parent tuple to the input commitment and public nullifier,
    prove authorization-key witness consistency, constrain the canonical
    global output index and bind both derived outputs into the V3 commitment.
    Recipient nullifier-key privacy relies on NullifierV3, not this helper.
    """
    _validate_inputs(
        namespace_id, parent_coin_id, parent_r_nf, spend_key_witness,
        transaction_entropy, output_index, params_id,
    )
    if (
        not isinstance(parent_public_key_bundle, bytes)
        or not parent_public_key_bundle
        or len(parent_public_key_bundle) >= (1 << 32)
    ):
        raise ValueError("parent_public_key_bundle must be non-empty canonical bytes")
    if not isinstance(parent_nullifier_key, NullifierDerivingKeyV3):
        raise TypeError("parent_nullifier_key must be a NullifierDerivingKeyV3")
    if (
        not isinstance(recipient_key_bundle, bytes)
        or not recipient_key_bundle
        or len(recipient_key_bundle) >= (1 << 32)
    ):
        raise ValueError("recipient_key_bundle must be non-empty canonical bytes")
    parent_nullifier = compute_nullifier_v3(
        namespace_id, parent_public_key_bundle, parent_coin_id,
        parent_r_nf, parent_nullifier_key,
    ).value

    def encode(domain: bytes) -> bytes:
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
            len(recipient_key_bundle).to_bytes(4, "little"),
            recipient_key_bundle,
            transaction_entropy,
            output_index.to_bytes(2, "big"),
        ))

    coin_id = hashlib.shake_256(
        encode(DOMAIN_OUTPUT_COIN_ID_V3)
    ).digest(OUTPUT_ID_BYTES)
    r_nf = hashlib.shake_256(
        encode(DOMAIN_OUTPUT_RNF_V3)
    ).digest(NULLIFIER_SECRET_BYTES)
    return OutputIdentityCandidate(
        coin_id=ScopedCoinId(coin_id),
        r_nf=NullifierSecret(r_nf),
    )


def derive_issuance_output_identity_v3_candidate(
    *,
    namespace_id: NamespaceId,
    deposit_id: bytes,
    recipient_key_bundle: bytes,
    issuance_entropy: bytes,
    output_index: int,
    params_id: bytes,
) -> OutputIdentityCandidate:
    """Versioned V3 issuance identity bound to authenticated anchor + recipient.

    The deposit identifier must be normalized by the trusted chain adapter.
    Reuse is prevented by the durable ledger's atomic one-use deposit rule,
    not by entropy. Different output slots and recipients have distinct encoded
    inputs; hash outputs remain computational, not mathematically injective.
    """
    if not isinstance(namespace_id, NamespaceId):
        raise TypeError("namespace_id must be a NamespaceId")
    if not isinstance(deposit_id, bytes) or not 1 <= len(deposit_id) <= DEPOSIT_ID_MAX_BYTES:
        raise ValueError(f"deposit_id must be canonical bytes of length 1..{DEPOSIT_ID_MAX_BYTES}")
    if not isinstance(recipient_key_bundle, bytes) or not recipient_key_bundle or len(recipient_key_bundle) >= (1 << 32):
        raise ValueError("recipient_key_bundle must be non-empty canonical bytes")
    if not isinstance(issuance_entropy, bytes) or len(issuance_entropy) != ISSUANCE_ENTROPY_BYTES:
        raise ValueError(f"issuance_entropy must be exactly {ISSUANCE_ENTROPY_BYTES} bytes")
    if not isinstance(params_id, bytes) or not 1 <= len(params_id) < (1 << 16):
        raise ValueError("params_id must be 1..65535 bytes")
    if isinstance(output_index, bool) or not isinstance(output_index, int) or not 0 <= output_index <= OUTPUT_INDEX_MAX:
        raise ValueError(f"output_index must be an integer in [0, {OUTPUT_INDEX_MAX}]")

    def encode(domain: bytes) -> bytes:
        return b"".join((
            domain,
            OUTPUT_ID_DERIVATION_VERSION,
            len(params_id).to_bytes(2, "little"),
            params_id,
            namespace_id.data,
            len(deposit_id).to_bytes(2, "little"),
            deposit_id,
            len(recipient_key_bundle).to_bytes(4, "little"),
            recipient_key_bundle,
            len(issuance_entropy).to_bytes(2, "little"),
            issuance_entropy,
            output_index.to_bytes(2, "big"),
        ))

    coin_id = hashlib.shake_256(
        encode(DOMAIN_ISSUANCE_COIN_ID_V3)
    ).digest(OUTPUT_ID_BYTES)
    r_nf = hashlib.shake_256(
        encode(DOMAIN_ISSUANCE_RNF_V3)
    ).digest(NULLIFIER_SECRET_BYTES)
    return OutputIdentityCandidate(
        coin_id=ScopedCoinId(coin_id),
        r_nf=NullifierSecret(r_nf),
    )

