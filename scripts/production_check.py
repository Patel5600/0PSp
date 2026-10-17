#!/usr/bin/env python3
"""Production-1 release gate: truth checks plus real OpenVM worker/ledger e2e."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.protocol.proof_backend_v3 import (
    MAINNET_LIVE_SPEND_VERIFICATION_ENABLED,
    PRODUCTION_SPEND_VERIFICATION_ENABLED,
    PRODUCTION1_TESTNET_SPEND_VERIFICATION_ENABLED,
)
from src.protocol.v3_proof_worker import PRODUCTION1_CIRCUIT_ID


def main() -> int:
    blockers: list[str] = []
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    limitations = (ROOT / "docs/LIMITATIONS.md").read_text(encoding="utf-8")
    matrix = (ROOT / "docs/security/production-gate-matrix.md").read_text(encoding="utf-8")
    relation = (ROOT / "proof/openvm/v3-nullifier-spike/src/spend_v3.rs").read_text(encoding="utf-8")
    client = (ROOT / "src/protocol/v3_proof_client.py").read_text(encoding="utf-8")
    worker = (ROOT / "src/protocol/v3_proof_worker.py").read_text(encoding="utf-8")

    if not PRODUCTION1_TESTNET_SPEND_VERIFICATION_ENABLED:
        blockers.append("production1_testnet verifier latch is disabled")
    if MAINNET_LIVE_SPEND_VERIFICATION_ENABLED:
        blockers.append("mainnet_live verifier latch must remain disabled")
    if PRODUCTION_SPEND_VERIFICATION_ENABLED:
        blockers.append("legacy mainnet production latch must remain disabled")
    if "allow_non_zk_test_value: bool = False" not in client:
        blockers.append("proof client must refuse non-ZK proofs by default")
    if '"proof_privacy": PROOF_PRIVACY_STATUS' not in worker:
        blockers.append("worker response must expose the pinned proof-privacy status")
    if 'PROOF_PRIVACY_STATUS = "witness_hiding_not_established"' not in worker:
        blockers.append("worker must not claim unsupported witness hiding")
    if "Production-1 local synthetic test value: GO" not in readme:
        blockers.append("README does not declare the limited local synthetic test-value status")
    if "Public testnet value: NO-GO" not in readme:
        blockers.append("README does not keep public testnet value NO-GO")
    if "Mainnet live value: NO-GO" not in readme:
        blockers.append("README does not declare mainnet live value NO-GO")
    if "Phase A" not in limitations or "operator" not in limitations.lower():
        blockers.append("LIMITATIONS.md does not state the Phase A operator trust model")
    forbidden_claims = ("Monero-equivalent", "threshold complete", "128-bit PQ security", "full witness zero knowledge")
    for claim in forbidden_claims:
        if claim.lower() in readme.lower() and claim.lower() not in limitations.lower():
            blockers.append(f"README claim has no matching limitation disclosure: {claim}")
    for marker in ("SPIKE STATUS", "spend_v3 spike is production-ready"):
        if marker.lower() in readme.lower():
            blockers.append(f"stale spike release marker remains: {marker}")
    if "mainnet_live" not in matrix or "production1_testnet" not in matrix:
        blockers.append("gate matrix is missing the explicit profile latch evidence")
    if "Public testnet value is **NO-GO**" not in matrix:
        blockers.append("gate matrix does not keep public testnet value NO-GO")
    if "relation_id" not in limitations or "local synthetic" not in limitations:
        blockers.append("LIMITATIONS.md is missing relation identity or local-only scope")
    for path in (
        ROOT / "src/protocol/v3_proof_worker.py",
        ROOT / "proof/openvm/v3-nullifier-spike/scripts/openvm_local_spend.py",
    ):
        if 'os.environ.get("PROFILE") != "production1_testnet"' not in path.read_text(encoding="utf-8"):
            blockers.append(f"{path.relative_to(ROOT)} does not enforce PROFILE=production1_testnet")
    if 'if profile != "production1_testnet"' not in (ROOT / "src/protocol/proof_backend_v3.py").read_text(encoding="utf-8"):
        blockers.append("production verifier profile selection is not explicit")
    for required in (
        "verify_membership(&tx.namespace, &tx.root",
        "hmac_sha3_384(&input_nk, &input_nullifier_message)",
        "input_value) != total_out",
        "input nk does not open",
        "state_context_digest",
    ):
        if required not in relation:
            blockers.append(f"active OpenVM spend relation is missing: {required}")

    proof_root = ROOT / "proof/openvm/v3-nullifier-spike"
    pins_path = proof_root / "production1-pins.json"
    vk_path = proof_root / "openvm/production1-app.vk"
    if not pins_path.is_file() or not vk_path.is_file():
        blockers.append("source-controlled Production-1 OpenVM app VK/pins are missing")
    else:
        try:
            pins = json.loads(pins_path.read_text(encoding="utf-8"))
            if pins.get("circuit_id") != PRODUCTION1_CIRCUIT_ID:
                blockers.append("artifact pin circuit_id does not match the worker relation")
            if pins.get("profile") != "production1_testnet":
                blockers.append("artifact pins do not select production1_testnet")
        except Exception:
            blockers.append("artifact pin manifest is malformed")

    if blockers:
        print("production-check: FAIL")
        for item in blockers:
            print(f"BLOCKER: {item}")
        return 1

    e2e = subprocess.run(
        [sys.executable, str(ROOT / "scripts/production1_e2e.py")],
        cwd=ROOT,
        check=False,
    )
    if e2e.returncode != 0:
        print("production-check: FAIL (Production-1 OpenVM e2e rejected)")
        return e2e.returncode or 1
    print("production-check: PASS (OpenVM prove/verify, SQLite accept, double-spend rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
