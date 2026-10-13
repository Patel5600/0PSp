from __future__ import annotations

from dataclasses import replace

import pytest

from src.primitives.namespace_v3 import derive_namespace_id_v3
from src.protocol.reference_ledger import SpendStatement
from src.protocol.transaction_v2 import (
    CanonicalTransactionError,
    SpendTransactionV2,
    decode_spend_transaction_v2,
    encode_spend_transaction_v2,
    validate_spend_statement_transaction,
)

NS = derive_namespace_id_v3(b"ledger", b"deployment", b"asset")
PARAMS = b"params-v2-test-2026"
POLICY = b"policy-self-spend-v1"
ROOT = b"\x01" * 48
NULLIFIER = b"\x02" * 48
STATE = b"\x03" * 48
OUTPUTS = (b"\x44" * 48, b"\x55" * 48)
KAT_DIGEST = "5bdbb402db099432d745fa39d652e06b83792ba0b7a2828bef2028fa0aa5012caade55ae7ce811012f44f2772e9e9e87"


def build(fee=123, outputs=OUTPUTS):
    return encode_spend_transaction_v2(
        params_id=PARAMS,
        namespace_id=NS,
        commitment_root=ROOT,
        nullifier=NULLIFIER,
        ledger_state=STATE,
        authorization_policy_id=POLICY,
        fee=fee,
        new_commitments=outputs,
    )


def statement(fields=None, digest=None):
    canonical_fields, canonical_digest = build()
    return SpendStatement(
        version=2,
        params_id=PARAMS,
        namespace_id=NS,
        commitment_root=ROOT,
        nullifier=NULLIFIER,
        transaction_fields=canonical_fields if fields is None else fields,
        transaction_digest=canonical_digest if digest is None else digest,
        ledger_state=STATE,
        authorization_policy=POLICY,
        new_commitments=OUTPUTS,
    )


def test_v2_transaction_encoding_known_answer_and_round_trip():
    fields, digest = build()
    assert len(fields) == 370
    assert digest.hex() == KAT_DIGEST
    tx = decode_spend_transaction_v2(fields)
    assert tx == SpendTransactionV2(
        params_id=PARAMS,
        namespace_id=NS,
        commitment_root=ROOT,
        nullifier=NULLIFIER,
        ledger_state=STATE,
        authorization_policy_id=POLICY,
        fee=123,
        new_commitments=OUTPUTS,
    )
    assert tx.canonical_fields() == fields
    assert tx.digest == digest


def test_tx_digest_separates_every_public_field():
    baseline_fields, baseline_digest = build()
    alternatives = [
        encode_spend_transaction_v2(
            params_id=b"other-params", namespace_id=NS, commitment_root=ROOT,
            nullifier=NULLIFIER, ledger_state=STATE, authorization_policy_id=POLICY,
            fee=123, new_commitments=OUTPUTS,
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=derive_namespace_id_v3(b"other", b"deployment", b"asset"),
            commitment_root=ROOT, nullifier=NULLIFIER, ledger_state=STATE,
            authorization_policy_id=POLICY, fee=123, new_commitments=OUTPUTS,
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=NS, commitment_root=b"\x09" * 48,
            nullifier=NULLIFIER, ledger_state=STATE, authorization_policy_id=POLICY,
            fee=123, new_commitments=OUTPUTS,
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=NS, commitment_root=ROOT,
            nullifier=b"\x08" * 48, ledger_state=STATE, authorization_policy_id=POLICY,
            fee=123, new_commitments=OUTPUTS,
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=NS, commitment_root=ROOT,
            nullifier=NULLIFIER, ledger_state=b"\x07" * 48, authorization_policy_id=POLICY,
            fee=123, new_commitments=OUTPUTS,
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=NS, commitment_root=ROOT,
            nullifier=NULLIFIER, ledger_state=STATE, authorization_policy_id=b"other-policy",
            fee=123, new_commitments=OUTPUTS,
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=NS, commitment_root=ROOT,
            nullifier=NULLIFIER, ledger_state=STATE, authorization_policy_id=POLICY,
            fee=124, new_commitments=OUTPUTS,
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=NS, commitment_root=ROOT,
            nullifier=NULLIFIER, ledger_state=STATE, authorization_policy_id=POLICY,
            fee=123, new_commitments=(b"\x66" * 48, b"\x55" * 48),
        ),
        encode_spend_transaction_v2(
            params_id=PARAMS, namespace_id=NS, commitment_root=ROOT,
            nullifier=NULLIFIER, ledger_state=STATE, authorization_policy_id=POLICY,
            fee=123, new_commitments=(b"\x44" * 48,),
        ),
    ]
    assert all(fields != baseline_fields and digest != baseline_digest for fields, digest in alternatives)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw + b"\x00",
        lambda raw: raw[:-1],
        lambda raw: b"X" + raw[1:],
        lambda raw: raw[:len(b"0PSP-TX-FIELDS-v2-SHAKE256") + 1] + b"\x00\x00" + raw[len(b"0PSP-TX-FIELDS-v2-SHAKE256") + 3:],
    ],
)
def test_decoder_rejects_trailing_truncated_wrong_prefix_and_zero_parameter_length(mutation):
    fields, _ = build()
    with pytest.raises(CanonicalTransactionError):
        decode_spend_transaction_v2(mutation(fields))


def test_decoder_rejects_changed_output_count_and_truncated_output():
    fields, _ = build()
    output_count_offset = (
        len(b"0PSP-TX-FIELDS-v2-SHAKE256") + 1 + 2 + len(PARAMS)
        + 48 + 48 + 48 + 48 + 2 + len(POLICY) + 8
    )
    changed_count = bytearray(fields)
    changed_count[output_count_offset:output_count_offset + 4] = (3).to_bytes(4, "little")
    with pytest.raises(CanonicalTransactionError, match="truncated output commitments"):
        decode_spend_transaction_v2(bytes(changed_count))
    with pytest.raises(CanonicalTransactionError, match="truncated output commitments"):
        decode_spend_transaction_v2(fields[:-1])


@pytest.mark.parametrize("kwargs", [
    {"fee": True},
    {"fee": -1},
    {"fee": 1 << 64},
    {"outputs": ()},
    {"outputs": (b"\x44" * 48, b"\x44" * 48)},
    {"outputs": (b"\x01" * 47,)},
])
def test_builder_rejects_invalid_fee_or_output_shape(kwargs):
    with pytest.raises(CanonicalTransactionError):
        build(**kwargs)


def test_statement_validator_rejects_public_field_substitution():
    base = statement()
    bad_values = [
        replace(base, params_id=b"other-params"),
        replace(base, namespace_id=derive_namespace_id_v3(b"other", b"deployment", b"asset")),
        replace(base, commitment_root=b"\x08" * 48),
        replace(base, nullifier=b"\x08" * 48),
        replace(base, ledger_state=b"\x08" * 48),
        replace(base, authorization_policy=b"other-policy"),
        replace(base, new_commitments=(b"\x66" * 48, b"\x55" * 48)),
        replace(base, transaction_digest=b"\xff" * 48),
        replace(base, transaction_fields=base.transaction_fields + b"\x00"),
    ]
    for bad in bad_values:
        with pytest.raises(CanonicalTransactionError):
            validate_spend_statement_transaction(bad)


def test_statement_validator_accepts_exact_matching_public_statement():
    base = statement()
    tx = validate_spend_statement_transaction(base)
    assert tx.namespace_id == base.namespace_id
    assert tx.new_commitments == base.new_commitments
    assert tx.digest == base.transaction_digest
