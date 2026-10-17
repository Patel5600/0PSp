#!/usr/bin/env python3
"""Synthetic local spend CLI using the TLS worker and local OpenVM verifier."""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from make_witnesses import (
    PARAMS_ID,
    SPEND_FINALITY_POLICY,
    SPEND_FINALIZED_ANCHOR,
    SPEND_STATE_HEAD,
    SPEND_STATE_SOURCE,
    encode_spend_witness,
    expected_spend_digest,
    make_spend_context,
)
from src.protocol.production1_artifacts import load_production1_verifier
from src.protocol.production1_ledger import SQLiteV3Production1TestnetLedger
from src.protocol.sqlite_v3_candidate_ledger import SQLiteV3DuplicateNullifier
from src.protocol.trusted_state_v3 import StateAnchorEvidenceV3, VerifiedStateSnapshotV3
from src.protocol.v3_proof_client import request_and_verify_spend_proof


def main() -> int:
    if os.environ.get("PROFILE") != "production1_testnet":
        raise SystemExit("client ledger PROFILE must be production1_testnet; mainnet_live is disabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-url", required=True)
    parser.add_argument("--ca-certificate", required=True)
    parser.add_argument("--checker", required=True)
    parser.add_argument("--app-vk", required=True)
    parser.add_argument("--pins", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument(
        "--allow-synthetic-bootstrap",
        action="store_true",
        help="explicitly opt into the deterministic CI/test bootstrap fixture",
    )
    args = parser.parse_args()
    if not args.allow_synthetic_bootstrap:
        parser.error("local demo requires --allow-synthetic-bootstrap; it uses no external finality source")
    api_key = os.environ.get("WORKER_API_KEY", "").encode("ascii", errors="strict")
    checker = Path(args.checker)
    app_vk = Path(args.app_vk)
    # The note commitment and membership path are constructed locally before the
    # ledger is initialized. Secret openings stay in this client process.
    context = make_spend_context()
    namespace = context["namespace"]
    evidence = StateAnchorEvidenceV3(
        source_id=SPEND_STATE_SOURCE,
        finalized_anchor=SPEND_FINALIZED_ANCHOR,
        evidence=b"deterministic synthetic fixture; not chain finality evidence",
    )
    snapshot = VerifiedStateSnapshotV3(
        source_id=SPEND_STATE_SOURCE,
        finalized_anchor=SPEND_FINALIZED_ANCHOR,
        finality_policy_id=SPEND_FINALITY_POLICY,
        namespace_id=namespace,
        params_id=PARAMS_ID,
        commitment_root=context["tree"].root,
        ledger_state_head=SPEND_STATE_HEAD,
    )

    def verify_bootstrap(received: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        if received != evidence:
            raise ValueError("synthetic bootstrap evidence mismatch")
        return snapshot

    verifier = load_production1_verifier(
        checker_executable=checker,
        app_verifying_key=app_vk,
        pins_file=args.pins,
    )
    ledger = SQLiteV3Production1TestnetLedger(
        args.ledger,
        expected_namespace_id=namespace,
        expected_params_id=PARAMS_ID,
        deployment_profile_id=hashlib.sha256(b"0PSP local synthetic spend demo").digest(),
        bootstrap_evidence=evidence,
        verify_bootstrap_state=verify_bootstrap,
        proof_verifier=verifier,
        bootstrap_commitments=(context["input_commitment"].value,),
        anchor_window=256,
    )
    statement = context["tx"]
    if ledger.state_context_digest_for_version(0) != statement.state_context_digest:
        raise SystemExit("fixture transaction is not bound to the ledger bootstrap checkpoint")
    witness = bytearray(encode_spend_witness(context))
    try:
        public_inputs, proof, prove_ms, verify_ms, peak_rss_kib = request_and_verify_spend_proof(
            worker_url=args.worker_url,
            api_key=api_key,
            ca_certificate=args.ca_certificate,
            witness=witness,
            statement=statement,
            verifier=verifier,
            allow_non_zk_test_value=True,
        )
    finally:
        witness[:] = b"\x00" * len(witness)

    accepted = ledger.accept_spend(statement, proof=proof)
    if public_inputs != expected_spend_digest(statement):
        raise SystemExit("locally verified public statement digest changed before ledger submit")
    balance_before = context["input_value"]
    balance_after = context["output_value"]
    if balance_before != balance_after + statement.fee:
        raise SystemExit("local wallet balance does not reconcile with the proved fee")
    if not ledger.is_nullifier_spent(statement.input_nullifier.value):
        raise SystemExit("ledger did not consume the spent input nullifier")
    if not ledger.contains_commitment(statement.output_commitments[0].value):
        raise SystemExit("ledger did not append the proved output commitment")
    try:
        ledger.accept_spend(statement, proof=proof)
    except SQLiteV3DuplicateNullifier:
        double_spend_rejected = True
    else:
        raise SystemExit("ledger accepted a second spend of the same note")
    if not double_spend_rejected:
        raise SystemExit("ledger did not reject the second spend")
    ledger.audit_integrity()
    print(
        "PASS: local OpenVM proof verified and spend committed; "
        f"balance_before={balance_before} balance_after={balance_after} fee={statement.fee} "
        f"state_version={accepted.state_version} proof_anchor={accepted.proof_anchor_version} "
        "double_spend=REJECTED"
        f" proof_bytes={len(proof)} prove_ms={prove_ms:.3f} "
        f"verify_ms={verify_ms:.3f} peak_rss_kib={peak_rss_kib}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
