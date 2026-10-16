"""Serialization tests for real-proof SQLite integration evidence."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = (
    REPO_ROOT / "proof" / "openvm" / "v3-nullifier-spike" / "scripts"
)
SCRIPT_PATH = SCRIPT_DIR / "verify_candidate_sqlite_ledger_integration.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

SPEC = importlib.util.spec_from_file_location(
    "openvm_sqlite_ledger_integration", SCRIPT_PATH
)
assert SPEC is not None and SPEC.loader is not None
INTEGRATION_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INTEGRATION_MODULE)


def test_ledger_integration_evidence_is_valid_json_with_real_trailing_newline(
    tmp_path: Path,
) -> None:
    evidence = {
        "schema_version": 1,
        "status": "PASS",
        "valid_proof_accepted_as_atomic_state_transition": True,
        "composite_post_quantum_security_bits": None,
        "required_composite_post_quantum_security_bits": 128,
        "production_acceptance_enabled": False,
        "release_status": "NO-GO",
    }

    output = INTEGRATION_MODULE.write_integration_evidence(tmp_path, evidence)
    serialized = output.read_text(encoding="utf-8")

    assert output.name == "ledger-integration.json"
    assert serialized.endswith("\n")
    assert not serialized.endswith("\\n")
    assert json.loads(serialized) == evidence
