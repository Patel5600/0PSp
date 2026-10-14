"""Canonical but non-normative V3 transaction encoding candidate.

This module defines the public message that a future V3 authorization predicate
must bind. It is not a production transaction codec, proof verifier, or ledger
acceptance path. V2 encodings are unchanged; the V2 ledger rejects version 3.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.note_public_key_bundle_v3 import (
    NotePublicKeyBundleV3,
    decode_note_public_key_bundle_v3,
)

TX_FIELDS_V3_CANDIDATE_DOMAIN = b"0PSP-TX-FIELDS-v3-CANDIDATE-v2-SHAKE256"
TX_DIGEST_V3_CANDIDATE_DOMAIN = b"0PSP-TX-DIGEST-v3-CANDIDATE-v2-SHAKE256"
STATE_CONTEXT_V3_CANDIDATE_DOMAIN = b"0PSP-V3-STATE-CONTEXT-CANDIDATE-v1-SHAKE256"
STATE_CONTEXT_BYTES = 64
MAX_FINALITY_POLICY_ID_BYTES = 128
TX_V3_CANDIDATE_VERSION = b"\x03"
HASH_BYTES = 48
OUTPUT_ENTROPY_BYTES = 32
MAX_OUTPUTS_V3_CANDIDATE = 1024
MAX_TX_FIELDS_V3_CANDIDATE_BYTES = 1_000_000
# Prefix for a candidate ML-DSA-style context. The canonical auth_scheme_id is
# appended with a uint16 little-endian length; the final context must be <=255 B.
# This is candidate-only and is not an approved V3 suite.
TX_AUTH_CONTEXT_V3_CANDIDATE = b"0PSP-TX-AUTH-v3-CANDIDATE"
# Candidate core-spend policy: the proof must demonstrate possession of nk by
# opening BundleV3.nullifier_key_commitment and using the same nk to derive nu3.
# This is an API/spec target only; the complete relation and ZK backend must enforce it.
V3_NK_POSSESSION_POLICY_CANDIDATE = b"0PSP-V3-NK-POSSESSION-CANDIDATE-v1"


class TransactionV3CandidateError(ValueError):
    """A V3 candidate transaction violates its canonical byte contract."""


def _require_bytes(value: object, field: str, *, min_len: int, max_len: int) -> bytes:
    if not isinstance(value, bytes) or not min_len <= len(value) <= max_len:
        raise TransactionV3CandidateError(
            f"{field} must be bytes with length in [{min_len}, {max_len}]"
        )
    return value


def _require_hash(value: object, field: str) -> bytes:
    return _require_bytes(value, field, min_len=HASH_BYTES, max_len=HASH_BYTES)


def state_context_digest_v3_candidate(source_id: bytes, finalized_anchor: bytes, finality_policy_id: bytes) -> bytes:
    """Bind a candidate statement to source, anchor and finality-policy identifiers."""
    _require_bytes(source_id, "state source ID", min_len=1, max_len=128)
    _require_bytes(finalized_anchor, "finalized anchor", min_len=1, max_len=256)
    _require_bytes(finality_policy_id, "finality policy ID", min_len=1, max_len=MAX_FINALITY_POLICY_ID_BYTES)
    preimage = b"".join((
        STATE_CONTEXT_V3_CANDIDATE_DOMAIN, b"\x01",
        len(source_id).to_bytes(2, "little"), source_id,
        len(finalized_anchor).to_bytes(2, "little"), finalized_anchor,
        len(finality_policy_id).to_bytes(2, "little"), finality_policy_id,
    ))
    return hashlib.shake_256(preimage).digest(STATE_CONTEXT_BYTES)


@dataclass(frozen=True, slots=True)
class TxFieldsV3Candidate:
    """Single-input candidate statement; output tuple order defines global slots.

    The authorization message is the digest returned by
    :func:`transaction_digest_v3_candidate`. The digest binds the exact
    canonical fields, including the public output entropy consumed by transfer
    output-identity derivation. This schema remains a versioned candidate until
    the authorization scheme and proof backend are selected.
    """

    params_id: bytes
    namespace_id: NamespaceIdV3
    commitment_root: bytes
    input_nullifier: NullifierV3
    ledger_state_head: bytes
    state_context_digest: bytes
    authorization_policy_id: bytes
    fee: int
    output_entropy: bytes
    output_commitments: tuple[CoinCommitmentV3, ...]

    def __post_init__(self) -> None:
        _require_bytes(self.params_id, "params_id", min_len=1, max_len=0xFFFF)
        if not isinstance(self.namespace_id, NamespaceIdV3):
            raise TransactionV3CandidateError("namespace_id must be NamespaceIdV3")
        _require_hash(self.commitment_root, "commitment_root")
        if not isinstance(self.input_nullifier, NullifierV3):
            raise TransactionV3CandidateError("input_nullifier must be NullifierV3")
        _require_hash(self.ledger_state_head, "ledger_state_head")
        _require_bytes(self.state_context_digest, "state_context_digest", min_len=STATE_CONTEXT_BYTES, max_len=STATE_CONTEXT_BYTES)
        _require_bytes(
            self.authorization_policy_id,
            "authorization_policy_id",
            min_len=1,
            max_len=0xFFFF,
        )
        if (
            isinstance(self.fee, bool)
            or not isinstance(self.fee, int)
            or not 0 <= self.fee <= 0xFFFFFFFFFFFFFFFF
        ):
            raise TransactionV3CandidateError("fee must be an unsigned 64-bit integer")
        _require_bytes(
            self.output_entropy,
            "output_entropy",
            min_len=OUTPUT_ENTROPY_BYTES,
            max_len=OUTPUT_ENTROPY_BYTES,
        )
        if not isinstance(self.output_commitments, tuple):
            raise TransactionV3CandidateError("output_commitments must be a tuple")
        if not 1 <= len(self.output_commitments) <= MAX_OUTPUTS_V3_CANDIDATE:
            raise TransactionV3CandidateError(
                f"output_commitments count must be in [1, {MAX_OUTPUTS_V3_CANDIDATE}]"
            )
        for output in self.output_commitments:
            if not isinstance(output, CoinCommitmentV3):
                raise TransactionV3CandidateError(
                    "every output commitment must be a CoinCommitmentV3"
                )
        raw_outputs = tuple(output.value for output in self.output_commitments)
        if len(set(raw_outputs)) != len(raw_outputs):
            raise TransactionV3CandidateError("transaction repeats an output commitment")

    def encode(self) -> bytes:
        """Encode the exact V3 candidate byte sequence, with no optional fields."""
        fields = b"".join(
            (
                TX_FIELDS_V3_CANDIDATE_DOMAIN,
                TX_V3_CANDIDATE_VERSION,
                len(self.params_id).to_bytes(2, "little"),
                self.params_id,
                self.namespace_id.data,
                self.commitment_root,
                self.input_nullifier.value,
                self.ledger_state_head,
                self.state_context_digest,
                len(self.authorization_policy_id).to_bytes(2, "little"),
                self.authorization_policy_id,
                self.fee.to_bytes(8, "little"),
                self.output_entropy,
                len(self.output_commitments).to_bytes(4, "little"),
                *(output.value for output in self.output_commitments),
            )
        )
        if len(fields) > MAX_TX_FIELDS_V3_CANDIDATE_BYTES:
            raise TransactionV3CandidateError("V3 candidate transaction exceeds byte limit")
        return fields


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, size: int, field: str) -> bytes:
        end = self.offset + size
        if size < 0 or end < self.offset or end > len(self.data):
            raise TransactionV3CandidateError(f"truncated {field}")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def u16_le(self, field: str) -> int:
        return int.from_bytes(self.take(2, field), "little")

    def u32_le(self, field: str) -> int:
        return int.from_bytes(self.take(4, field), "little")

    def u64_le(self, field: str) -> int:
        return int.from_bytes(self.take(8, field), "little")

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise TransactionV3CandidateError("V3 candidate transaction has trailing bytes")


def decode_tx_fields_v3_candidate(encoded: bytes) -> TxFieldsV3Candidate:
    """Decode one candidate encoding; reject malformed and trailing bytes."""
    if not isinstance(encoded, bytes):
        raise TransactionV3CandidateError("encoded transaction must be bytes")
    if not encoded or len(encoded) > MAX_TX_FIELDS_V3_CANDIDATE_BYTES:
        raise TransactionV3CandidateError("encoded transaction length is outside configured bounds")
    reader = _Reader(encoded)
    if reader.take(len(TX_FIELDS_V3_CANDIDATE_DOMAIN), "domain") != TX_FIELDS_V3_CANDIDATE_DOMAIN:
        raise TransactionV3CandidateError("V3 candidate transaction domain mismatch")
    if reader.take(1, "version") != TX_V3_CANDIDATE_VERSION:
        raise TransactionV3CandidateError("V3 candidate transaction version mismatch")
    params_len = reader.u16_le("params_id length")
    if not 1 <= params_len <= 0xFFFF:
        raise TransactionV3CandidateError("params_id length must be in [1, 65535]")
    params_id = reader.take(params_len, "params_id")
    namespace_id = NamespaceIdV3(reader.take(HASH_BYTES, "namespace_id"))
    commitment_root = reader.take(HASH_BYTES, "commitment_root")
    input_nullifier = NullifierV3(reader.take(HASH_BYTES, "input_nullifier"))
    ledger_state_head = reader.take(HASH_BYTES, "ledger_state_head")
    state_context_digest = reader.take(STATE_CONTEXT_BYTES, "state_context_digest")
    policy_len = reader.u16_le("authorization_policy_id length")
    if not 1 <= policy_len <= 0xFFFF:
        raise TransactionV3CandidateError(
            "authorization_policy_id length must be in [1, 65535]"
        )
    authorization_policy_id = reader.take(policy_len, "authorization_policy_id")
    fee = reader.u64_le("fee")
    output_entropy = reader.take(OUTPUT_ENTROPY_BYTES, "output_entropy")
    output_count = reader.u32_le("output count")
    if not 1 <= output_count <= MAX_OUTPUTS_V3_CANDIDATE:
        raise TransactionV3CandidateError(
            f"output count must be in [1, {MAX_OUTPUTS_V3_CANDIDATE}]"
        )
    outputs = tuple(
        CoinCommitmentV3(reader.take(HASH_BYTES, f"output commitment {index}"))
        for index in range(output_count)
    )
    reader.finish()
    statement = TxFieldsV3Candidate(
        params_id=params_id,
        namespace_id=namespace_id,
        commitment_root=commitment_root,
        input_nullifier=input_nullifier,
        ledger_state_head=ledger_state_head,
        state_context_digest=state_context_digest,
        authorization_policy_id=authorization_policy_id,
        fee=fee,
        output_entropy=output_entropy,
        output_commitments=outputs,
    )
    if statement.encode() != encoded:
        raise TransactionV3CandidateError("V3 candidate transaction is not canonical")
    return statement


def transaction_digest_v3_candidate(
    statement_or_encoded: TxFieldsV3Candidate | bytes,
) -> bytes:
    """Return the 64-byte domain-separated candidate digest used in authorization binding."""
    if isinstance(statement_or_encoded, TxFieldsV3Candidate):
        fields = statement_or_encoded.encode()
    elif isinstance(statement_or_encoded, bytes):
        # Parse and re-encode to reject noncanonical byte strings before hashing.
        fields = decode_tx_fields_v3_candidate(statement_or_encoded).encode()
    else:
        raise TransactionV3CandidateError(
            "input must be TxFieldsV3Candidate or canonical encoded bytes"
        )
    preimage = (
        TX_DIGEST_V3_CANDIDATE_DOMAIN
        + TX_V3_CANDIDATE_VERSION
        + len(fields).to_bytes(4, "little")
        + fields
    )
    return hashlib.shake_256(preimage).digest(64)

def authorization_input_v3_candidate(
    statement_or_encoded: TxFieldsV3Candidate | bytes,
    note_public_key_bundle: NotePublicKeyBundleV3 | bytes,
) -> tuple[bytes, bytes]:
    """Return (message, scheme-bound context) for authorization experiments only.

    The message is the canonical transaction digest. The context binds the
    exact auth_scheme_id parsed from the same canonical BundleV3 whose key the
    eventual proof must use. This prevents a host caller from silently
    selecting a different signature suite while reusing the same context.

    The candidate does not select or validate a signature scheme, verify a
    signature, authenticate the recipient bundle, or define a production
    verifier. The complete relation must still prove that the bundle is
    committed in the spent note and verify authorization under that exact key.
    """
    message = transaction_digest_v3_candidate(statement_or_encoded)
    if isinstance(note_public_key_bundle, NotePublicKeyBundleV3):
        encoded_bundle = note_public_key_bundle.encode()
    elif isinstance(note_public_key_bundle, bytes):
        encoded_bundle = note_public_key_bundle
    else:
        raise TransactionV3CandidateError(
            "note_public_key_bundle must be a NotePublicKeyBundleV3 or canonical bytes"
        )
    try:
        bundle = decode_note_public_key_bundle_v3(encoded_bundle)
    except (TypeError, ValueError) as exc:
        raise TransactionV3CandidateError(
            "note_public_key_bundle must be canonical V3 bundle bytes"
        ) from exc

    scheme_id = bundle.auth_scheme_id
    context = (
        TX_AUTH_CONTEXT_V3_CANDIDATE
        + len(scheme_id).to_bytes(2, "little")
        + scheme_id
    )
    if len(context) > 255:
        raise TransactionV3CandidateError(
            "candidate authorization context exceeds 255 bytes for auth_scheme_id"
        )
    return message, context

def validate_nk_possession_policy_v3_candidate(
    statement_or_encoded: TxFieldsV3Candidate | bytes,
) -> TxFieldsV3Candidate:
    """Require the explicit per-note nullifier-key-possession policy candidate.

    This selects the core spend-authority semantics without a separate signature
    scheme: the eventual shared-witness proof must prove knowledge of nk opening
    the exact BundleV3 key commitment and must use that same nk in NullifierV3,
    while binding the exact transaction digest, membership, outputs and trusted
    state. A host-side policy check is not proof enforcement.

    The bundle auth_public_key/auth_scheme_id are not spend authority under this
    policy. They cannot be treated as intended-payee authentication unless a
    separate independently anchored address-auth predicate is implemented.
    """
    if isinstance(statement_or_encoded, TxFieldsV3Candidate):
        statement = statement_or_encoded
    elif isinstance(statement_or_encoded, bytes):
        statement = decode_tx_fields_v3_candidate(statement_or_encoded)
    else:
        raise TransactionV3CandidateError(
            "input must be TxFieldsV3Candidate or canonical encoded bytes"
        )
    if statement.authorization_policy_id != V3_NK_POSSESSION_POLICY_CANDIDATE:
        raise TransactionV3CandidateError(
            "authorization_policy_id does not select the V3 nk-possession candidate"
        )
    return statement

