#!/usr/bin/env python3
"""Prove a ledger-generated statement with OpenVM, then submit it to SQLite candidate ledger.

The bootstrap verifier is deliberately synthetic CI fixture code. This checks the
real proof -> pinned Rust checker -> ledger callback -> atomic local state transition
wiring only; it does not provide external consensus/finality or production approval.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from make_witnesses import PARAMS_ID, encode_spend_witness, expected_spend_digest, make_spend_context
from src.protocol.openvm_v3_candidate_verifier import OpenVMV3CandidateProofVerifier
from src.protocol.sqlite_v3_candidate_ledger import (
    SQLiteV3CandidateLedger,
    SQLiteV3DuplicateNullifier,
    SQLiteV3ProofRejected,
)
from src.protocol.transaction_v3_candidate import state_context_digest_v3_candidate
from src.protocol.trusted_state_v3 import StateAnchorEvidenceV3, VerifiedStateSnapshotV3


def read_lower_hex(path: Path, expected_bytes: int, field: str) -> bytes:
    raw = path.read_text(encoding="ascii").strip()
    if len(raw) != expected_bytes * 2:
        raise ValueError(f"{field} must contain exactly {expected_bytes * 2} hex characters")
    if any(ch not in "0123456789abcdef" for ch in raw):
        raise ValueError(f"{field} must contain lowercase hexadecimal only")
    return bytes.fromhex(raw)


def write_integration_evidence(evidence_dir: Path, evidence: dict[str, object]) -> Path:
    """Write machine-readable ledger test evidence and assert valid JSON encoding."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / "ledger-integration.json"
    serialized = json.dumps(evidence, sort_keys=True, indent=2) + "\n"
    if json.loads(serialized) != evidence:
        raise RuntimeError("serialized ledger integration evidence failed JSON round-trip")
    evidence_path.write_text(serialized, encoding="utf-8")
    return evidence_path


def main() -> int:
    if len(sys.argv) != 7:
        print(
            "usage: verify_candidate_sqlite_ledger_integration.py RUNNER CONFIG ELF "
            "CHECKER EXPECTED_EXE_COMMIT_HEX EVIDENCE_DIR",
            file=sys.stderr,
        )
        return 2

    runner, config, elf, checker, expected_commit_path, evidence_dir = (
        Path(value).absolute() for value in sys.argv[1:]
    )
    for path, label in (
        (runner, "OpenVM SDK runner"),
        (config, "OpenVM config"),
        (elf, "guest ELF"),
        (checker, "proof checker"),
        (expected_commit_path, "expected executable commitment"),
    ):
        if not path.is_file():
            raise FileNotFoundError(f"{label} not found: {path}")

    evidence_dir.mkdir(parents=True, exist_ok=True)
    ledger_dir = evidence_dir / "sqlite-ledger-integration"
    ledger_dir.mkdir(parents=True, exist_ok=True)
    ledger_dir.chmod(0o700)

    context = make_spend_context()
    namespace = context["namespace"]
    input_commitment = context["input_commitment"].value
    output_commitment = context["tx"].output_commitments[0].value
    nullifier = context["tx"].input_nullifier.value
    bootstrap_commitments = (input_commitment,)
    bootstrap_source = b"openvm-ledger-ci-bootstrap-source-v1"
    bootstrap_anchor = b"openvm-ledger-ci-bootstrap-anchor-v1"
    bootstrap_payload = b"SYNTHETIC CI ONLY: not cryptographic external-state evidence"
    bootstrap_evidence = StateAnchorEvidenceV3(
        source_id=bootstrap_source,
        finalized_anchor=bootstrap_anchor,
        evidence=bootstrap_payload,
    )
    bootstrap_snapshot = VerifiedStateSnapshotV3(
        source_id=bootstrap_source,
        finalized_anchor=bootstrap_anchor,
        finality_policy_id=b"synthetic-bootstrap-finality-policy-v1",
        namespace_id=namespace,
        params_id=PARAMS_ID,
        commitment_root=context["tree"].root,
        ledger_state_head=bytes([0x44]) * 48,
    )

    def verify_bootstrap(received: StateAnchorEvidenceV3) -> VerifiedStateSnapshotV3:
        if received != bootstrap_evidence:
            raise ValueError("bootstrap evidence does not match the fixed synthetic CI fixture")
        return bootstrap_snapshot

    verifier_holder: dict[str, OpenVMV3CandidateProofVerifier] = {}

    def verify_real_proof(statement, proof: bytes) -> bool:
        verifier = verifier_holder.get("verifier")
        return False if verifier is None else verifier(statement, proof)

    database_path = ledger_dir / "candidate.sqlite3"
    ledger = SQLiteV3CandidateLedger(
        database_path,
        expected_namespace_id=namespace,
        expected_params_id=PARAMS_ID,
        deployment_profile_id=bytes([0x22]) * 32,
        bootstrap_evidence=bootstrap_evidence,
        verify_bootstrap_state=verify_bootstrap,
        verify_spend_proof=verify_real_proof,
        bootstrap_commitments=bootstrap_commitments,
    )
    initial = ledger.snapshot()
    if initial.commitment_root != context["tree"].root:
        raise RuntimeError("SQLite bootstrap root does not match the witness Merkle tree")

    local_anchor = ledger.state_evidence_for_version(initial.state_version)
    dynamic_statement = replace(
        context["tx"],
        commitment_root=initial.commitment_root,
        ledger_state_head=initial.ledger_state_head,
        state_context_digest=state_context_digest_v3_candidate(
            local_anchor.source_id,
            local_anchor.finalized_anchor,
            ledger.finality_policy_id,
        ),
    )

    witness_path = ledger_dir / "dynamic-spend.witness"
    digest_path = ledger_dir / "expected-public-digest.txt"
    proof_path = ledger_dir / "dynamic-spend.app.proof"
    app_vk_path = ledger_dir / "dynamic-app.vk"
    witness_path.write_bytes(encode_spend_witness(context, tx=dynamic_statement))
    expected_digest = expected_spend_digest(dynamic_statement)
    digest_path.write_text(expected_digest.hex() + "\n", encoding="ascii")
    if len(expected_digest) != 64:
        raise RuntimeError("candidate public statement digest must be exactly 64 bytes")

    sdk_evidence = ledger_dir / "sdk-evidence"
    command = [
        str(runner),
        "prove-one",
        str(config),
        str(elf),
        str(witness_path),
        str(digest_path),
        str(proof_path),
        str(app_vk_path),
        str(expected_commit_path),
        str(sdk_evidence),
    ]
    process = subprocess.run(
        command,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    if process.returncode != 0:
        raise RuntimeError(
            "OpenVM failed to generate/verify the proof for the live SQLite anchor.\n"
            + process.stdout[-6000:]
            + "\n"
            + process.stderr[-6000:]
        )
    print(process.stdout.rstrip())
    if not proof_path.is_file() or proof_path.stat().st_size == 0:
        raise RuntimeError("OpenVM runner did not materialize the dynamic ledger proof")

    proof_bytes = proof_path.read_bytes()
    checker_sha = hashlib.sha256(checker.read_bytes()).digest()
    vk_sha = hashlib.sha256(app_vk_path.read_bytes()).digest()
    expected_exe_commitment = read_lower_hex(
        expected_commit_path, 32, "pinned app executable commitment"
    )
    verifier_holder["verifier"] = OpenVMV3CandidateProofVerifier(
        checker_executable=checker,
        app_verifying_key=app_vk_path,
        expected_checker_sha256=checker_sha,
        expected_app_verifying_key_sha256=vk_sha,
        app_executable_commitment=expected_exe_commitment,
        timeout_seconds=300,
        max_proof_bytes=2_000_000,
    )

    # Prove fail-closed behavior before the valid transaction mutates state.
    before_bad_proof = ledger.snapshot()
    mutated_proof = bytearray(proof_bytes)
    mutated_proof[len(mutated_proof) // 2] ^= 0x01
    try:
        ledger.accept_spend(dynamic_statement, proof=bytes(mutated_proof))
    except SQLiteV3ProofRejected:
        print("PASS: SQLite candidate ledger rejected a byte-mutated real proof")
    else:
        raise RuntimeError("SQLite ledger accepted a mutated OpenVM proof")
    if ledger.snapshot() != before_bad_proof:
        raise RuntimeError("rejected proof changed SQLite ledger state")
    if ledger.is_nullifier_spent(nullifier) or ledger.contains_commitment(output_commitment):
        raise RuntimeError("rejected proof partially changed nullifier/output state")

    accepted = ledger.accept_spend(dynamic_statement, proof=proof_bytes)
    if (
        accepted.state_version != 1
        or accepted.output_commitment != output_commitment
        or accepted.nullifier != nullifier
        or not ledger.is_nullifier_spent(nullifier)
        or not ledger.contains_commitment(output_commitment)
    ):
        raise RuntimeError("real-proof acceptance did not commit the expected spend transition")
    after_accept = ledger.snapshot()
    ledger.audit_integrity()
    print(
        "PASS: real OpenVM proof accepted through SQLiteV3CandidateLedger.accept_spend; "
        f"state_version={after_accept.state_version} "
        f"proof_bytes={len(proof_bytes)} "
        f"nullifier={nullifier.hex()} output={output_commitment.hex()}"
    )

    # An otherwise valid replay cannot apply a second atomic state transition.
    try:
        ledger.accept_spend(dynamic_statement, proof=proof_bytes)
    except SQLiteV3DuplicateNullifier:
        print("PASS: actual OpenVM proof replay rejected as duplicate nullifier")
    else:
        raise RuntimeError("SQLite ledger accepted the same spend/nullifier twice")
    if ledger.snapshot() != after_accept:
        raise RuntimeError("duplicate-nullifier rejection changed the SQLite state")
    ledger.audit_integrity()

    reopened = SQLiteV3CandidateLedger(
        database_path,
        expected_namespace_id=namespace,
        expected_params_id=PARAMS_ID,
        deployment_profile_id=bytes([0x22]) * 32,
        bootstrap_evidence=bootstrap_evidence,
        verify_bootstrap_state=verify_bootstrap,
        verify_spend_proof=verify_real_proof,
        bootstrap_commitments=None,
    )
    if reopened.snapshot() != after_accept:
        raise RuntimeError("persisted real-proof spend changed after ledger restart")
    reopened.audit_integrity()

    integration_evidence = {
        "schema_version": 1,
        "status": "PASS",
        "scope": "non-production OpenVM candidate proof to local SQLite transition",
        "dynamic_statement_proof_generated_and_verified": True,
        "mutated_proof_rejected_without_state_change": True,
        "valid_proof_accepted_as_atomic_state_transition": True,
        "duplicate_nullifier_replay_rejected_without_state_change": True,
        "restart_and_integrity_audit_passed": True,
        "proof_size_bytes": len(proof_bytes),
        "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
        "checker_sha256": checker_sha.hex(),
        "app_verifying_key_sha256": vk_sha.hex(),
        "app_executable_commitment": expected_exe_commitment.hex(),
        "public_statement_digest": expected_digest.hex(),
        "state_version_after_accept": after_accept.state_version,
        "bootstrap_state_evidence_is_synthetic": True,
        "external_finality_established": False,
        "end_to_end_witness_hiding_established": False,
        "composite_post_quantum_security_bits": None,
        "required_composite_post_quantum_security_bits": 128,
        "production_acceptance_enabled": False,
        "release_status": "NO-GO",
    }
    evidence_path = write_integration_evidence(evidence_dir, integration_evidence)
    print(f"LEDGER_INTEGRATION_EVIDENCE={evidence_path}")
    print(
        "PASS: SQLite candidate ledger restarted and audited after the real-proof spend; "
        f"checker_sha256={checker_sha.hex()} app_vk_sha256={vk_sha.hex()} "
        f"app_exe_commitment={expected_exe_commitment.hex()} "
        f"public_digest={expected_digest.hex()}"
    )
    print(
        "LIMIT: bootstrap evidence in this test is synthetic and the SQLite finality policy "
        "is explicitly non-final. This does not authorize production/Mainnet spends."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
