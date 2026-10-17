#!/usr/bin/env python3
"""Exercise the real OpenVM spend proof through the SQLite acceptance path."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from make_witnesses import SPEND_FINALITY_POLICY, SPEND_FINALIZED_ANCHOR, SPEND_STATE_SOURCE, make_spend_context, expected_spend_digest
from src.protocol.production1_artifacts import load_production1_verifier
from src.protocol.production1_ledger import SQLiteV3Production1TestnetLedger
from src.protocol.sqlite_v3_candidate_ledger import (
    SQLiteV3DuplicateNullifier,
)
from src.protocol.trusted_state_v3 import StateAnchorEvidenceV3, VerifiedStateSnapshotV3


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: openvm_ledger_integration.py CHECKER APP_VK PROOF PINS PUBLIC_DIGEST",
            file=sys.stderr,
        )
        return 2

    checker, app_vk, proof_path, pins_path, public_digest_path = map(Path, sys.argv[1:])
    context = make_spend_context()
    statement = context["tx"]
    if bytes.fromhex(public_digest_path.read_text(encoding="ascii").strip()) != expected_spend_digest(statement):
        raise SystemExit("generated spend statement differs from the pinned public digest")

    namespace = context["namespace"]
    tree = context["tree"]
    evidence = StateAnchorEvidenceV3(
        source_id=SPEND_STATE_SOURCE,
        finalized_anchor=SPEND_FINALIZED_ANCHOR,
        evidence=b"local integration fixture; not external finality evidence",
    )
    snapshot = VerifiedStateSnapshotV3(
        source_id=SPEND_STATE_SOURCE,
        finalized_anchor=SPEND_FINALIZED_ANCHOR,
        finality_policy_id=SPEND_FINALITY_POLICY,
        namespace_id=namespace,
        params_id=statement.params_id,
        commitment_root=tree.root,
        ledger_state_head=statement.ledger_state_head,
    )

    def verify_bootstrap(received: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        if received != evidence:
            raise ValueError("bootstrap evidence mismatch")
        return snapshot

    proof_verifier = load_production1_verifier(
        checker_executable=checker,
        app_verifying_key=app_vk,
        pins_file=pins_path,
    )

    with tempfile.TemporaryDirectory(prefix="0psp-openvm-ledger-integration-") as directory:
        ledger = SQLiteV3Production1TestnetLedger(
            Path(directory) / "ledger.sqlite3",
            expected_namespace_id=namespace,
            expected_params_id=statement.params_id,
            deployment_profile_id=bytes.fromhex("502d51f75b71a43852d972cd27c23c9a4ee74a83d4af52e44f9ba0b4f63c9201"),
            bootstrap_evidence=evidence,
            verify_bootstrap_state=verify_bootstrap,
            proof_verifier=proof_verifier,
            bootstrap_commitments=(context["input_commitment"].value,),
            anchor_window=256,
        )
        if ledger.state_context_digest_for_version(0) != statement.state_context_digest:
            raise SystemExit("generated proof statement is not bound to the ledger's authenticated bootstrap anchor")
        proof = proof_path.read_bytes()
        accepted = ledger.accept_spend(statement, proof=proof)
        before_replay = ledger.snapshot()
        try:
            ledger.accept_spend(statement, proof=proof)
        except SQLiteV3DuplicateNullifier:
            pass
        else:
            raise SystemExit("ledger accepted the same cryptographically verified spend twice")

        if ledger.snapshot() != before_replay:
            raise SystemExit("rejected replay changed persisted ledger state")
        if not ledger.is_nullifier_spent(statement.input_nullifier.value):
            raise SystemExit("accepted spend did not append its nullifier")
        if not ledger.contains_commitment(statement.output_commitments[0].value):
            raise SystemExit("accepted spend did not append its output commitment")
        if accepted.proof_anchor_version != 0 or accepted.state_version != 1:
            raise SystemExit("accepted spend was not bound to the expected bootstrap anchor")
        ledger.audit_integrity()

    print("PASS: real OpenVM spend proof accepted once; cryptographic replay rejected atomically")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
