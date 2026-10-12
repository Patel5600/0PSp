"""Regression for hidden tuple reuse under frozen V2 reference primitives.

Vectors are loaded from tests/fixtures/hidden_tuple_reuse.json. These finite
checks are not a ZK proof, collision-resistance proof, recipient-safety proof,
or production-ledger test.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.primitives.coin_commitment import commit_coin_v2
from src.primitives.namespace import NamespaceId, ScopedCoinId
from src.primitives.nullifier import NullifierSecret, compute_nullifier_v2

_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "hidden_tuple_reuse.json"
_FIXTURE = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
_COMMON = _FIXTURE["common"]

NS = NamespaceId(bytes.fromhex(_COMMON["namespace_id_hex"]))
COIN = ScopedCoinId(bytes.fromhex(_COMMON["coin_id_hex"]))
R_NF = NullifierSecret(bytes.fromhex(_COMMON["r_nf_hex"]))
PK = _COMMON["public_key_utf8"].encode("utf-8")
PARAMS = _COMMON["params_id_utf8"].encode("utf-8")
VALUE = _COMMON["value"]


def _case(case_id: str) -> dict:
    return next(case for case in _FIXTURE["cases"] if case["id"] == case_id)


def test_same_hidden_tuple_can_make_distinct_commitments_with_same_nullifier() -> None:
    """A new commitment salt does not change V2 nullifier identity."""
    case = _case("same_tuple_different_salt")
    rho_a = bytes.fromhex(case["rho_a_hex"])
    rho_b = bytes.fromhex(case["rho_b_hex"])

    commitment_a = commit_coin_v2(NS, PK, VALUE, COIN, R_NF, rho_a, PARAMS)
    commitment_b = commit_coin_v2(NS, PK, VALUE, COIN, R_NF, rho_b, PARAMS)
    nullifier_a = compute_nullifier_v2(NS, COIN, R_NF)
    nullifier_b = compute_nullifier_v2(NS, COIN, R_NF)

    assert (commitment_a != commitment_b) is case["expected"]["commitments_differ"]
    assert (nullifier_a == nullifier_b) is case["expected"]["nullifiers_equal"]


def test_same_coin_id_with_new_nullifier_secret_changes_selected_vector() -> None:
    """A selected vector only; not a global uniqueness or collision proof."""
    case = _case("same_coin_id_different_rnf")
    rho = bytes.fromhex(case["rho_hex"])
    other_secret = NullifierSecret(bytes.fromhex(case["other_r_nf_hex"]))

    commitment_a = commit_coin_v2(NS, PK, VALUE, COIN, R_NF, rho, PARAMS)
    commitment_b = commit_coin_v2(NS, PK, VALUE, COIN, other_secret, rho, PARAMS)
    nullifier_a = compute_nullifier_v2(NS, COIN, R_NF)
    nullifier_b = compute_nullifier_v2(NS, COIN, other_secret)

    assert (commitment_a != commitment_b) is case["expected"]["commitments_differ"]
    assert (nullifier_a != nullifier_b) is case["expected"]["nullifiers_differ"]
