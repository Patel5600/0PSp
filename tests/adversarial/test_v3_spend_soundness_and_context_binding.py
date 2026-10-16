"""V3 candidate payout-context and Merkle-profile adversarial tests."""
from __future__ import annotations

from dataclasses import replace

import pytest

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.commitment_tree import CommitmentTree, CommitmentTreeError, V3_TREE_DEPTH, leaf_hash, root_from_path, verify_member
from src.protocol.transaction_v3_candidate import (
    V3_NK_POSSESSION_POLICY_CANDIDATE, TransactionV3CandidateError,
    TxFieldsV3Candidate, decode_tx_fields_v3_candidate,
    payout_context_digest_v3_candidate, transaction_digest_v3_candidate,
)

NS = NamespaceIdV3(b"\x11" * 48)
OUT = CoinCommitmentV3(b"\x66" * 48)


def statement(**overrides: object) -> TxFieldsV3Candidate:
    fields: dict[str, object] = {
        "params_id": b"p0-audit-v3", "namespace_id": NS,
        "commitment_root": b"\x22" * 48, "input_nullifier": NullifierV3(b"\x33" * 48),
        "ledger_state_head": b"\x44" * 48, "state_context_digest": b"\x55" * 64,
        "authorization_policy_id": V3_NK_POSSESSION_POLICY_CANDIDATE,
        "fee": 3, "output_entropy": b"\x77" * 32, "output_commitments": (OUT,),
        "chain_id": (1).to_bytes(32, "big"), "recipient_address": b"\xA1" * 20,
        "withdraw_value": 0, "relayer_address": b"\xB2" * 20,
    }
    fields.update(overrides)
    return TxFieldsV3Candidate(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field_name,mutated",
    [
        ("chain_id", (2).to_bytes(32, "big")),
        ("recipient_address", b"\xA2" * 20),
        ("relayer_address", b"\xB3" * 20),
        ("fee", 4),
        ("withdraw_value", 1),
    ],
)
def test_context_mutation_changes_context_and_transaction_digest(field_name, mutated):
    original = statement()
    modified = replace(original, **{field_name: mutated})
    assert payout_context_digest_v3_candidate(modified) != payout_context_digest_v3_candidate(original)
    assert transaction_digest_v3_candidate(modified) != transaction_digest_v3_candidate(original)


def test_decoder_rejects_an_opaque_or_mutated_payout_digest():
    raw = statement().encode()
    tampered = raw[:-1] + bytes([raw[-1] ^ 1])
    with pytest.raises(TransactionV3CandidateError, match="payout context digest mismatch"):
        decode_tx_fields_v3_candidate(tampered)


def test_v3_tree_is_depth32_and_rejects_indices_outside_u32():
    tree = CommitmentTree(NS, [OUT.value], depth=V3_TREE_DEPTH)
    path = tree.membership_path(0)
    assert len(path) == 32
    assert verify_member(NS, tree.root, 0, OUT.value, path, tree_depth=32)
    with pytest.raises(CommitmentTreeError, match="exactly 32 siblings"):
        root_from_path(NS, 0, OUT.value, path + (bytes(48),) * 31, tree_depth=32)
    with pytest.raises(CommitmentTreeError, match="leaf index"):
        leaf_hash(NS, 1 << 32, OUT.value, tree_depth=32)
