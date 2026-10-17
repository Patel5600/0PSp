#!/usr/bin/env python3
"""Create deterministic non-production fixtures for the V3 nullifier and spend spikes."""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.primitives.namespace import ScopedCoinId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.nullifier import NullifierSecret
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    NullifierV3,
    compute_nullifier_key_commitment_v3,
    compute_nullifier_v3,
)
from src.primitives.coin_commitment_v3 import commit_coin_v3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.protocol.commitment_tree import CommitmentTree
from src.protocol.note_public_key_bundle_v3 import NotePublicKeyBundleV3
from src.protocol.output_identity import derive_output_identity_v3_production1
from src.protocol.transaction_v3_candidate import (
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    TxFieldsV3Candidate,
    state_context_digest_v3_candidate,
    transaction_digest_v3_candidate,
)

# The first group remains the narrow nullifier-relation regression fixture.
MAGIC = b"0PSP-OPENVM-V3-NULLIFIER-SPIKE-WITNESS-v1"
PUBLIC_STATEMENT_DOMAIN = b"0PSP-OPENVM-V3-NULLIFIER-PUBLIC-STATEMENT-v2"
PARAMS_ID = b"v3-candidate-params"
NAMESPACE_BYTES = bytes([0x11]) * 48
COIN_ID_BYTES_VALUE = bytes([0x22]) * 32
R_NF_BYTES_VALUE = bytes([0x33]) * 36
KEY_BYTES_VALUE = bytes([0x44]) * 48
RHO_A = bytes([0xA1]) * 36
RHO_B = bytes([0xA2]) * 36
AUTH_SCHEME_ID = b"test-auth-scheme-v1"
AUTH_PUBLIC_KEY = b"test-recipient-public-key"

BUNDLE = bytes.fromhex(
    "305053502d4e4f54452d504b2d42554e444c452d763303"
    "1300746573742d617574682d736368656d652d7631"
    "19000000746573742d726563697069656e742d7075626c69632d6b6579"
    "300075e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95"
    "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8"
)
COMMITMENT = bytes.fromhex(
    "7c29d710d6a81bed4f3df766421d66fa497072be7513022487eb55c8d4839f82"
    "a9cf6dd11105ce21602715f0644f99d0"
)
NULLIFIER = bytes.fromhex(
    "5309bdb17ad1527c06763ae96dfd806520132899bbdbc6519070883abb568a1"
    "af3bc2a43c3a965325df2ba084bcf6f93"
)
EXPECTED_KEY_COMMITMENT = bytes.fromhex(
    "75e79fc862d236ecb76a362a08edd81c910aaf660d5cb9d95"
    "fabe8a8f35cfa67fee3371e044cd7abc802c655de4ccde8"
)

SPEND_MAGIC = b"0PSP-OPENVM-V3-SPEND-CANDIDATE-WITNESS-v1"
SPEND_PUBLIC_DOMAIN = b"0PSP-OPENVM-V3-SPEND-PUBLIC-STATEMENT-CANDIDATE-v2"
SPEND_VALUE_IN = 500
SPEND_FEE = 3
SPEND_VALUE_OUT = 497
SPEND_OUTPUT_ENTROPY = bytes([0x66]) * 32
SPEND_STATE_HEAD = bytes([0x77]) * 48
SPEND_STATE_SOURCE = b"openvm-ci-fixture-state-source"
SPEND_FINALIZED_ANCHOR = b"openvm-ci-fixture-finalized-anchor-v1"
SPEND_FINALITY_POLICY = b"nonprod-openvm-fixture-finality-v1"
SPEND_INPUT_RHO = RHO_A
SPEND_OUTPUT_RHO = bytes([0xB1]) * 36
SPEND_OUTPUT_KEY = bytes([0x55]) * 48


def witness(
    *,
    bundle: bytes = BUNDLE,
    value: int = 500,
    rho: bytes = RHO_A,
    key: bytes = KEY_BYTES_VALUE,
    commitment: bytes = COMMITMENT,
    nullifier: bytes = NULLIFIER,
    trailing: bytes = b"",
) -> bytes:
    encoded = b"".join(
        (
            MAGIC,
            len(PARAMS_ID).to_bytes(2, "little"),
            PARAMS_ID,
            NAMESPACE_BYTES,
            len(bundle).to_bytes(4, "little"),
            bundle,
            value.to_bytes(8, "little"),
            COIN_ID_BYTES_VALUE,
            R_NF_BYTES_VALUE,
            rho,
            key,
            commitment,
            nullifier,
            trailing,
        )
    )
    if len(encoded) > 2_000_000:
        raise ValueError("fixture exceeds configured guest bound")
    return encoded


def openvm_input(payload: bytes) -> str:
    # OpenVM v2 byte-oriented stdin is selected by the 0x01 input tag.
    return json.dumps({"input": ["01" + payload.hex()]}) + "\n"


def make_spend_context():
    namespace = NamespaceIdV3(NAMESPACE_BYTES)
    input_key = NullifierDerivingKeyV3(KEY_BYTES_VALUE)
    input_bundle_obj = NotePublicKeyBundleV3(
        auth_scheme_id=AUTH_SCHEME_ID,
        auth_public_key=AUTH_PUBLIC_KEY,
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(input_key),
    )
    input_bundle = input_bundle_obj.encode()
    input_coin_id = ScopedCoinId(COIN_ID_BYTES_VALUE)
    input_r_nf = NullifierSecret(R_NF_BYTES_VALUE)
    input_commitment = commit_coin_v3(
        namespace, input_bundle, SPEND_VALUE_IN, input_coin_id,
        input_r_nf, SPEND_INPUT_RHO, PARAMS_ID,
    )
    input_nullifier = compute_nullifier_v3(
        namespace, PARAMS_ID, input_bundle, input_commitment,
        input_coin_id, input_r_nf, input_key,
    )
    tree = CommitmentTree(namespace, [input_commitment.value])
    state_context_digest = state_context_digest_v3_candidate(
        SPEND_STATE_SOURCE, SPEND_FINALIZED_ANCHOR, SPEND_FINALITY_POLICY
    )

    output_key = NullifierDerivingKeyV3(SPEND_OUTPUT_KEY)
    output_bundle_obj = NotePublicKeyBundleV3(
        auth_scheme_id=AUTH_SCHEME_ID,
        auth_public_key=b"test-output-recipient-public-key",
        nullifier_key_commitment=compute_nullifier_key_commitment_v3(output_key),
    )
    output_bundle = output_bundle_obj.encode()
    output_identity = derive_output_identity_v3_production1(
        namespace_id=namespace,
        anchor_context=tree.root + SPEND_STATE_HEAD + state_context_digest,
        parent_coin_id=input_coin_id,
        parent_r_nf=input_r_nf,
        parent_public_key_bundle=input_bundle,
        parent_commitment=input_commitment,
        parent_nullifier_key=input_key,
        recipient_key_bundle=output_bundle,
        transaction_entropy=SPEND_OUTPUT_ENTROPY,
        output_index=0,
        params_id=PARAMS_ID,
    )
    output_commitment = commit_coin_v3(
        namespace, output_bundle, SPEND_VALUE_OUT,
        output_identity.coin_id, output_identity.r_nf,
        SPEND_OUTPUT_RHO, PARAMS_ID,
    )
    tx = TxFieldsV3Candidate(
        params_id=PARAMS_ID,
        namespace_id=namespace,
        commitment_root=tree.root,
        input_nullifier=input_nullifier,
        ledger_state_head=SPEND_STATE_HEAD,
        state_context_digest=state_context_digest,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=SPEND_FEE,
        output_entropy=SPEND_OUTPUT_ENTROPY,
        output_commitments=(output_commitment,),
    )
    return {
        "namespace": namespace,
        "input_key": input_key,
        "input_bundle": input_bundle,
        "input_commitment": input_commitment,
        "input_nullifier": input_nullifier,
        "input_coin_id": input_coin_id,
        "input_r_nf": input_r_nf,
        "input_rho": SPEND_INPUT_RHO,
        "input_value": SPEND_VALUE_IN,
        "tree": tree,
        "siblings": tree.membership_path(0),
        "output_bundle": output_bundle,
        "output_rho": SPEND_OUTPUT_RHO,
        "output_value": SPEND_VALUE_OUT,
        "tx": tx,
    }


def encode_spend_witness(
    ctx: dict,
    *,
    tx: TxFieldsV3Candidate | None = None,
    input_bundle: bytes | None = None,
    input_value: int | None = None,
    input_coin_id: bytes | None = None,
    input_r_nf: bytes | None = None,
    input_rho: bytes | None = None,
    input_key: bytes | None = None,
    leaf_index: int = 0,
    siblings: tuple[bytes, ...] | None = None,
    output_bundle: bytes | None = None,
    output_value: int | None = None,
    output_rho: bytes | None = None,
    trailing: bytes = b"",
) -> bytes:
    tx = tx or ctx["tx"]
    input_bundle = input_bundle if input_bundle is not None else ctx["input_bundle"]
    input_value = input_value if input_value is not None else ctx["input_value"]
    input_coin_id = input_coin_id if input_coin_id is not None else ctx["input_coin_id"].data
    input_r_nf = input_r_nf if input_r_nf is not None else ctx["input_r_nf"].data
    input_rho = input_rho if input_rho is not None else ctx["input_rho"]
    input_key = input_key if input_key is not None else ctx["input_key"].data
    siblings = siblings if siblings is not None else ctx["siblings"]
    output_bundle = output_bundle if output_bundle is not None else ctx["output_bundle"]
    output_value = output_value if output_value is not None else ctx["output_value"]
    output_rho = output_rho if output_rho is not None else ctx["output_rho"]

    if len(siblings) != 63:
        raise ValueError("V3 spend fixture requires exactly 63 Merkle siblings")
    encoded_tx = tx.encode()
    encoded = b"".join(
        (
            SPEND_MAGIC,
            len(encoded_tx).to_bytes(4, "little"),
            encoded_tx,
            len(input_bundle).to_bytes(4, "little"),
            input_bundle,
            input_value.to_bytes(8, "little"),
            input_coin_id,
            input_r_nf,
            input_rho,
            input_key,
            leaf_index.to_bytes(8, "little"),
            *siblings,
            len(output_bundle).to_bytes(4, "little"),
            output_bundle,
            output_value.to_bytes(8, "little"),
            output_rho,
            trailing,
        )
    )
    if len(encoded) > 2_000_000:
        raise ValueError("V3 spend witness exceeds configured guest limit")
    return encoded


def expected_spend_digest(tx: TxFieldsV3Candidate) -> bytes:
    tx_digest = transaction_digest_v3_candidate(tx)
    return hashlib.shake_256(
        SPEND_PUBLIC_DOMAIN + b"\x03" + tx_digest
    ).digest(64)


def write_case(output: Path, name: str, payload: bytes) -> None:
    (output / f"{name}.witness").write_bytes(payload)
    (output / f"{name}.json").write_text(openvm_input(payload), encoding="ascii")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_witnesses.py OUTPUT_DIRECTORY", file=sys.stderr)
        return 2
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)

    # Existing narrow V3-nullifier conformance fixtures.
    valid = witness()
    narrow_cases = {
        "valid": valid,
        "wrong-key": witness(key=bytes([0x45]) * 48),
        "changed-value": witness(value=501),
        "changed-salt": witness(rho=RHO_B),
        "wrong-nullifier": witness(nullifier=bytes([NULLIFIER[0] ^ 1]) + NULLIFIER[1:]),
        "bad-bundle": witness(bundle=bytes([BUNDLE[0] ^ 1]) + BUNDLE[1:]),
        "trailing-data": witness(trailing=b"\x00"),
    }
    for name, payload in narrow_cases.items():
        write_case(output, name, payload)

    public_statement = b"".join(
        (
            PUBLIC_STATEMENT_DOMAIN,
            b"\x03",
            len(PARAMS_ID).to_bytes(2, "little"),
            PARAMS_ID,
            NAMESPACE_BYTES,
            COMMITMENT,
            NULLIFIER,
        )
    )
    public_digest = hashlib.shake_256(public_statement).digest(64)
    expected_digest_kat = "82ec02fc6689a4c56038463a780a9d3e75d5075043645cdb754a4d9c73b21df665303861e54f2a07876f811f1fdb38f353f1572367db5fb4a36f27672983b5ee"
    if public_digest.hex() != expected_digest_kat:
        raise ValueError("public statement digest KAT mismatch")
    (output / "expected-public-digest.txt").write_text(public_digest.hex() + "\n", encoding="ascii")

    derived_key_commitment = hashlib.shake_256(
        b"0PSP-NULLIFIER-KEY-COMMIT-v3-SHAKE256"
        + b"\x03"
        + len(KEY_BYTES_VALUE).to_bytes(2, "little")
        + KEY_BYTES_VALUE
    ).digest(48)
    if derived_key_commitment != EXPECTED_KEY_COMMITMENT:
        raise ValueError("fixed nullifier-key commitment KAT no longer matches")
    if BUNDLE[-48:] != derived_key_commitment or len(BUNDLE) != 123:
        raise ValueError("canonical BundleV3 fixture is inconsistent")
    if len(COMMITMENT) != 48 or len(NULLIFIER) != 48:
        raise ValueError("commitment/nullifier KAT length is inconsistent")
    if len(valid) != len(witness()):
        raise ValueError("valid witness is not deterministic")

    # Build the full one-input/one-output spend candidate from the Python reference.
    ctx = make_spend_context()
    tx = ctx["tx"]
    valid_spend = encode_spend_witness(ctx)
    write_case(output, "spend-valid", valid_spend)
    spend_digest = expected_spend_digest(tx)
    expected_spend_digest_kat = "aa7b029542a3d75bc6dee7d9927b9efa10e5fc45a5ff1eb19745ec9357733e32cd4974e83b050bbbd14a2c36c141bfee99e833d7030ce1657c3a727039c53f0f"
    if spend_digest.hex() != expected_spend_digest_kat:
        raise ValueError("spend public statement digest KAT mismatch")
    (output / "expected-spend-public-digest.txt").write_text(
        spend_digest.hex() + "\n", encoding="ascii"
    )

    spend_cases: dict[str, bytes] = {}
    spend_cases["spend-wrong-key"] = encode_spend_witness(
        ctx, input_key=bytes([0x45]) * 48
    )
    spend_cases["spend-changed-value"] = encode_spend_witness(
        ctx, input_value=SPEND_VALUE_IN + 1
    )
    spend_cases["spend-changed-salt"] = encode_spend_witness(
        ctx, input_rho=bytes([0xA2]) * 36
    )
    wrong_nullifier = bytes([ctx["input_nullifier"].value[0] ^ 1]) + ctx["input_nullifier"].value[1:]
    spend_cases["spend-wrong-nullifier"] = encode_spend_witness(
        ctx,
        tx=replace(tx, input_nullifier=NullifierV3(wrong_nullifier)),
    )
    bad_bundle = bytes([ctx["input_bundle"][0] ^ 1]) + ctx["input_bundle"][1:]
    spend_cases["spend-bad-bundle"] = encode_spend_witness(ctx, input_bundle=bad_bundle)
    spend_cases["spend-trailing-data"] = encode_spend_witness(ctx, trailing=b"\x00")
    wrong_root = bytes([tx.commitment_root[0] ^ 1]) + tx.commitment_root[1:]
    spend_cases["spend-bad-root"] = encode_spend_witness(
        ctx, tx=replace(tx, commitment_root=wrong_root)
    )
    bad_siblings = list(ctx["siblings"])
    bad_siblings[0] = bytes([bad_siblings[0][0] ^ 1]) + bad_siblings[0][1:]
    spend_cases["spend-bad-path"] = encode_spend_witness(ctx, siblings=tuple(bad_siblings))
    spend_cases["spend-changed-output-entropy"] = encode_spend_witness(
        ctx, tx=replace(tx, output_entropy=bytes([0x67]) * 32)
    )
    spend_cases["spend-changed-state-head"] = encode_spend_witness(
        ctx, tx=replace(tx, ledger_state_head=bytes([0x78]) * 48)
    )
    spend_cases["spend-changed-state-context"] = encode_spend_witness(
        ctx, tx=replace(tx, state_context_digest=bytes([0x79]) * 64)
    )
    spend_cases["spend-unknown-policy"] = encode_spend_witness(
        ctx, tx=replace(tx, authorization_policy_id=b"unknown-policy-v1")
    )
    spend_cases["spend-value-conservation"] = encode_spend_witness(
        ctx, tx=replace(tx, fee=SPEND_FEE - 1)
    )
    for name, payload in spend_cases.items():
        write_case(output, name, payload)

    print(
        f"created {len(narrow_cases)} narrow and {1 + len(spend_cases)} spend witnesses; "
        f"nullifier_digest={public_digest.hex()} spend_digest={expected_spend_digest(tx).hex()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
