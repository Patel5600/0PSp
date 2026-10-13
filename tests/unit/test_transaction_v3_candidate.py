"""Adversarial reference tests for the non-normative V3 transaction candidate.

These tests validate host canonicalization and digest binding only. They do not
prove that a ZK backend constrains the same fields or that any signature is valid.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from src.primitives.namespace import NamespaceId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.nullifier import Nullifier as NullifierV2
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.transaction_v3_candidate import (
    TX_AUTH_CONTEXT_V3_CANDIDATE,
    TX_FIELDS_V3_CANDIDATE_DOMAIN,
    TransactionV3CandidateError,
    TxFieldsV3Candidate,
    authorization_input_v3_candidate,
    decode_tx_fields_v3_candidate,
    transaction_digest_v3_candidate,
)

PARAMS = b"candidate-v3"
NS = NamespaceIdV3(bytes([0x01]) * 48)
ROOT = bytes([0x02]) * 48
INPUT_NULLIFIER = NullifierV3(bytes([0x03]) * 48)
STATE_HEAD = bytes([0x04]) * 48
POLICY = b"candidate-threshold-v1"
OUTPUT_ENTROPY = bytes([0x05]) * 32
OUTPUT_A = CoinCommitmentV3(bytes([0x06]) * 48)
OUTPUT_B = CoinCommitmentV3(bytes([0x07]) * 48)


def statement(**overrides: object) -> TxFieldsV3Candidate:
    fields: dict[str, object] = {
        "params_id": PARAMS,
        "namespace_id": NS,
        "commitment_root": ROOT,
        "input_nullifier": INPUT_NULLIFIER,
        "ledger_state_head": STATE_HEAD,
        "authorization_policy_id": POLICY,
        "fee": 7,
        "output_entropy": OUTPUT_ENTROPY,
        "output_commitments": (OUTPUT_A, OUTPUT_B),
    }
    fields.update(overrides)
    return TxFieldsV3Candidate(**fields)  # type: ignore[arg-type]


def test_v3_candidate_roundtrip_and_digest_known_answer() -> None:
    tx = statement()
    encoded = tx.encode()
    assert len(encoded) == 407
    assert encoded.startswith(TX_FIELDS_V3_CANDIDATE_DOMAIN + b"\x03")
    assert decode_tx_fields_v3_candidate(encoded) == tx
    assert decode_tx_fields_v3_candidate(encoded).encode() == encoded
    expected_digest = (
        "4653bd7615487423cf9f90e71bc09d7e2d1246d7aa4e82033d6ba4c909a67edef"
        "2082c822064788a2c0249d6b2fbaaaa"
    )
    assert transaction_digest_v3_candidate(tx).hex() == expected_digest
    assert transaction_digest_v3_candidate(encoded) == transaction_digest_v3_candidate(tx)


@pytest.mark.parametrize(
    "mutated",
    [
        {"params_id": b"another-params"},
        {"namespace_id": NamespaceIdV3(bytes([0x11]) * 48)},
        {"commitment_root": bytes([0x12]) * 48},
        {"input_nullifier": NullifierV3(bytes([0x13]) * 48)},
        {"ledger_state_head": bytes([0x14]) * 48},
        {"authorization_policy_id": b"another-policy"},
        {"fee": 8},
        {"output_entropy": bytes([0x15]) * 32},
        {"output_commitments": (OUTPUT_B, OUTPUT_A)},
        {"output_commitments": (CoinCommitmentV3(bytes([0x16]) * 48), OUTPUT_B)},
        {"output_commitments": (OUTPUT_A,)},
    ],
)
def test_authorization_digest_binds_every_public_transaction_dimension(
    mutated: dict[str, object],
) -> None:
    base = statement()
    altered = statement(**mutated)
    assert transaction_digest_v3_candidate(base) != transaction_digest_v3_candidate(altered)


def test_authorization_input_uses_digest_and_fixed_versioned_context() -> None:
    tx = statement()
    message, context = authorization_input_v3_candidate(tx)

    assert message == transaction_digest_v3_candidate(tx)
    assert context == TX_AUTH_CONTEXT_V3_CANDIDATE
    assert context == b"0PSP-TX-AUTH-v3-CANDIDATE"
    assert 0 < len(context) <= 255
    assert authorization_input_v3_candidate(tx.encode()) == (message, context)

    altered = statement(fee=tx.fee + 1)
    assert authorization_input_v3_candidate(altered)[0] != message
    # The context is protocol-domain separation and does not vary by field.
    assert authorization_input_v3_candidate(altered)[1] == context


def test_decoder_rejects_trailing_bytes_wrong_version_and_wrong_domain() -> None:
    encoded = statement().encode()
    with pytest.raises(TransactionV3CandidateError, match="trailing bytes"):
        decode_tx_fields_v3_candidate(encoded + b"junk")

    wrong_version = encoded[:len(TX_FIELDS_V3_CANDIDATE_DOMAIN)] + b"\x02" + encoded[len(TX_FIELDS_V3_CANDIDATE_DOMAIN) + 1:]
    with pytest.raises(TransactionV3CandidateError, match="version mismatch"):
        decode_tx_fields_v3_candidate(wrong_version)

    wrong_domain = b"X" + encoded[1:]
    with pytest.raises(TransactionV3CandidateError, match="domain mismatch"):
        decode_tx_fields_v3_candidate(wrong_domain)


def test_decoder_rejects_zero_output_count() -> None:
    encoded = bytearray(statement(output_commitments=(OUTPUT_A,)).encode())
    # output_count is the final 4-byte integer before the 48-byte output value.
    encoded[-52:-48] = (0).to_bytes(4, "little")
    encoded = encoded[:-48]
    with pytest.raises(TransactionV3CandidateError, match="output count"):
        decode_tx_fields_v3_candidate(bytes(encoded))


def test_constructor_rejects_v2_typed_values_duplicates_and_bad_ranges() -> None:
    namespace_v2 = NamespaceId(bytes([0x01]) * 48)
    nullifier_v2 = NullifierV2(bytes([0x03]) * 48)
    with pytest.raises(TransactionV3CandidateError, match="NamespaceIdV3"):
        statement(namespace_id=namespace_v2)
    with pytest.raises(TransactionV3CandidateError, match="NullifierV3"):
        statement(input_nullifier=nullifier_v2)
    with pytest.raises(TransactionV3CandidateError, match="CoinCommitmentV3"):
        statement(output_commitments=(OUTPUT_A, b"not-a-v3-commitment"))
    with pytest.raises(TransactionV3CandidateError, match="repeats"):
        statement(output_commitments=(OUTPUT_A, OUTPUT_A))
    with pytest.raises(TransactionV3CandidateError, match="unsigned 64-bit"):
        statement(fee=True)
    with pytest.raises(TransactionV3CandidateError, match="unsigned 64-bit"):
        statement(fee=-1)
    with pytest.raises(TransactionV3CandidateError, match="output_entropy"):
        statement(output_entropy=b"short")
    with pytest.raises(TransactionV3CandidateError, match="must be a tuple"):
        statement(output_commitments=[OUTPUT_A])  # type: ignore[arg-type]


def test_digest_refuses_noncanonical_bytes_and_wrong_input_type() -> None:
    with pytest.raises(TransactionV3CandidateError, match="trailing bytes"):
        transaction_digest_v3_candidate(statement().encode() + b"\x00")
    with pytest.raises(TransactionV3CandidateError, match="input must be"):
        transaction_digest_v3_candidate(17)  # type: ignore[arg-type]
