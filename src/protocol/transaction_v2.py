"""Canonical public transaction-field codec for the frozen V2 spend relation.

This module fills RFC-02's previously unspecified TxDigestV2 encoding. It does not
prove value conservation or authorization; the eventual ZK backend must constrain
the exact same field encoding and digest computation over the shared private witness.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from src.primitives.namespace_v3 import NamespaceIdV3

TX_FIELDS_DOMAIN = b"0PSP-TX-FIELDS-v2-SHAKE256"
TX_DIGEST_DOMAIN = b"0PSP-TX-DIGEST-v2-SHAKE256"
TX_VERSION = 2
DIGEST_BYTES = 48
ROOT_BYTES = 48
NULLIFIER_BYTES = 48
COMMITMENT_BYTES = 48
MAX_OUTPUTS = 1024
U64_MAX = (1 << 64) - 1


class CanonicalTransactionError(ValueError):
    """Transaction fields are malformed, non-canonical, or inconsistent."""


def _require_bytes(value: object, field: str, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, bytes) or not minimum <= len(value) <= maximum:
        raise CanonicalTransactionError(f"{field} must be bytes with length {minimum}..{maximum}")
    return value


def _read_u16(raw: bytes, offset: int, field: str) -> tuple[int, int]:
    end = offset + 2
    if end > len(raw):
        raise CanonicalTransactionError(f"truncated {field} length")
    return int.from_bytes(raw[offset:end], "little"), end


def _read_exact(raw: bytes, offset: int, length: int, field: str) -> tuple[bytes, int]:
    end = offset + length
    if end > len(raw):
        raise CanonicalTransactionError(f"truncated {field}")
    return raw[offset:end], end


@dataclass(frozen=True, slots=True)
class SpendTransactionV2:
    """Public transaction fields committed by TxDigestV2.

    Values for output notes remain hidden in output commitment openings; this
    codec includes the commitments but never their private values/opening secrets.
    """

    params_id: bytes
    namespace_id: NamespaceIdV3
    commitment_root: bytes
    nullifier: bytes
    ledger_state: bytes
    authorization_policy_id: bytes
    fee: int
    new_commitments: tuple[bytes, ...]

    def __post_init__(self) -> None:
        _require_bytes(self.params_id, "params_id", minimum=1, maximum=65535)
        if not isinstance(self.namespace_id, NamespaceIdV3):
            raise CanonicalTransactionError("namespace_id must be NamespaceIdV3")
        _require_bytes(self.commitment_root, "commitment_root", minimum=ROOT_BYTES, maximum=ROOT_BYTES)
        _require_bytes(self.nullifier, "nullifier", minimum=NULLIFIER_BYTES, maximum=NULLIFIER_BYTES)
        _require_bytes(self.ledger_state, "ledger_state", minimum=48, maximum=48)
        _require_bytes(
            self.authorization_policy_id, "authorization_policy_id", minimum=1, maximum=65535
        )
        if isinstance(self.fee, bool) or not isinstance(self.fee, int) or not 0 <= self.fee <= U64_MAX:
            raise CanonicalTransactionError("fee must be an unsigned 64-bit integer")
        if not isinstance(self.new_commitments, tuple):
            raise CanonicalTransactionError("new_commitments must be a tuple")
        if not 1 <= len(self.new_commitments) <= MAX_OUTPUTS:
            raise CanonicalTransactionError(f"new_commitments must contain 1..{MAX_OUTPUTS} outputs")
        for index, commitment in enumerate(self.new_commitments):
            _require_bytes(commitment, f"new_commitments[{index}]", minimum=COMMITMENT_BYTES, maximum=COMMITMENT_BYTES)
        if len(set(self.new_commitments)) != len(self.new_commitments):
            raise CanonicalTransactionError("new_commitments repeats a commitment")

    def canonical_fields(self) -> bytes:
        output_count = len(self.new_commitments)
        return (
            TX_FIELDS_DOMAIN + bytes([TX_VERSION])
            + len(self.params_id).to_bytes(2, "little") + self.params_id
            + self.namespace_id.data
            + self.commitment_root
            + self.nullifier
            + self.ledger_state
            + len(self.authorization_policy_id).to_bytes(2, "little")
            + self.authorization_policy_id
            + self.fee.to_bytes(8, "little")
            + output_count.to_bytes(4, "little")
            + b"".join(self.new_commitments)
        )

    @property
    def digest(self) -> bytes:
        fields = self.canonical_fields()
        return hashlib.shake_256(
            TX_DIGEST_DOMAIN + bytes([TX_VERSION])
            + len(fields).to_bytes(4, "little") + fields
        ).digest(DIGEST_BYTES)


def encode_spend_transaction_v2(
    *,
    params_id: bytes,
    namespace_id: NamespaceIdV3,
    commitment_root: bytes,
    nullifier: bytes,
    ledger_state: bytes,
    authorization_policy_id: bytes,
    fee: int,
    new_commitments: tuple[bytes, ...],
) -> tuple[bytes, bytes]:
    """Return the exact canonical transaction fields and 48-byte TxDigestV2."""
    transaction = SpendTransactionV2(
        params_id=params_id,
        namespace_id=namespace_id,
        commitment_root=commitment_root,
        nullifier=nullifier,
        ledger_state=ledger_state,
        authorization_policy_id=authorization_policy_id,
        fee=fee,
        new_commitments=new_commitments,
    )
    return transaction.canonical_fields(), transaction.digest


def decode_spend_transaction_v2(encoded: bytes) -> SpendTransactionV2:
    """Decode only the unique V2 wire format; reject prefixes, truncation and trailing bytes."""
    if not isinstance(encoded, bytes):
        raise TypeError("encoded transaction fields must be bytes")
    if len(encoded) > 1_000_000:
        raise CanonicalTransactionError("transaction fields exceed the 1,000,000-byte safety limit")
    prefix = TX_FIELDS_DOMAIN + bytes([TX_VERSION])
    if not encoded.startswith(prefix):
        raise CanonicalTransactionError("transaction fields have the wrong V2 domain/version prefix")
    offset = len(prefix)
    params_len, offset = _read_u16(encoded, offset, "params_id")
    if not 1 <= params_len <= 65535:
        raise CanonicalTransactionError("params_id length must be in 1..65535")
    params_id, offset = _read_exact(encoded, offset, params_len, "params_id")
    namespace_data, offset = _read_exact(encoded, offset, 48, "namespace_id")
    commitment_root, offset = _read_exact(encoded, offset, 48, "commitment_root")
    nullifier, offset = _read_exact(encoded, offset, 48, "nullifier")
    ledger_state, offset = _read_exact(encoded, offset, 48, "ledger_state")
    policy_len, offset = _read_u16(encoded, offset, "authorization_policy_id")
    if not 1 <= policy_len <= 65535:
        raise CanonicalTransactionError("authorization_policy_id length must be in 1..65535")
    policy_id, offset = _read_exact(encoded, offset, policy_len, "authorization_policy_id")
    fee_bytes, offset = _read_exact(encoded, offset, 8, "fee")
    fee = int.from_bytes(fee_bytes, "little")
    count_bytes, offset = _read_exact(encoded, offset, 4, "output_count")
    count = int.from_bytes(count_bytes, "little")
    if not 1 <= count <= MAX_OUTPUTS:
        raise CanonicalTransactionError(f"output_count must be in 1..{MAX_OUTPUTS}")
    outputs_bytes, offset = _read_exact(encoded, offset, count * COMMITMENT_BYTES, "output commitments")
    if offset != len(encoded):
        raise CanonicalTransactionError("transaction fields contain trailing bytes")
    outputs = tuple(
        outputs_bytes[index:index + COMMITMENT_BYTES]
        for index in range(0, len(outputs_bytes), COMMITMENT_BYTES)
    )
    try:
        namespace = NamespaceIdV3(namespace_data)
        transaction = SpendTransactionV2(
            params_id=params_id,
            namespace_id=namespace,
            commitment_root=commitment_root,
            nullifier=nullifier,
            ledger_state=ledger_state,
            authorization_policy_id=policy_id,
            fee=fee,
            new_commitments=outputs,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalTransactionError(f"decoded transaction violates V2 field constraints: {exc}") from None
    if transaction.canonical_fields() != encoded:
        raise CanonicalTransactionError("transaction fields are not the unique canonical V2 encoding")
    return transaction


def validate_spend_statement_transaction(statement: object) -> SpendTransactionV2:
    """Require every duplicate public field to match the canonical field bytes and digest."""
    from src.protocol.reference_ledger import SpendStatement

    if not isinstance(statement, SpendStatement):
        raise CanonicalTransactionError("statement must be a SpendStatement")
    transaction = decode_spend_transaction_v2(statement.transaction_fields)
    expected_fields = {
        "params_id": statement.params_id,
        "namespace_id": statement.namespace_id,
        "commitment_root": statement.commitment_root,
        "nullifier": statement.nullifier,
        "ledger_state": statement.ledger_state,
        "authorization_policy_id": statement.authorization_policy,
        "new_commitments": statement.new_commitments,
    }
    for field, actual in expected_fields.items():
        if getattr(transaction, field) != actual:
            raise CanonicalTransactionError(
                f"transaction {field} differs from the corresponding spend-statement field"
            )
    if statement.version != TX_VERSION:
        raise CanonicalTransactionError("spend statement version differs from the transaction version")
    if not isinstance(statement.transaction_digest, bytes) or len(statement.transaction_digest) != DIGEST_BYTES:
        raise CanonicalTransactionError("transaction_digest must be exactly 48 bytes")
    if transaction.digest != statement.transaction_digest:
        raise CanonicalTransactionError("transaction_digest does not match canonical TxDigestV2")
    return transaction
