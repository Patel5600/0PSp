from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTOR_DIR = ROOT / "tests" / "vectors" / "production1-spend-v3"
SCRIPT = ROOT / "proof" / "openvm" / "v3-nullifier-spike" / "scripts" / "make_witnesses.py"


def _fixture_module():
    spec = importlib.util.spec_from_file_location("production1_make_witnesses", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_production1_golden_vectors_match_generator_and_checksums() -> None:
    manifest = json.loads((VECTOR_DIR / "manifest.json").read_text(encoding="utf-8"))
    module = _fixture_module()
    context = module.make_spend_context()
    expected_valid = module.encode_spend_witness(context)
    expected_wrong_head = module.encode_spend_witness(
        context,
        tx=replace(context["tx"], ledger_state_head=bytes([0x78]) * 48),
    )
    expected_wrong_context = module.encode_spend_witness(
        context,
        tx=replace(context["tx"], state_context_digest=bytes([0x79]) * 64),
    )
    generated = {
        "valid.witness": expected_valid,
        "wrong-state-head.witness": expected_wrong_head,
        "wrong-state-context.witness": expected_wrong_context,
    }
    for vector in manifest["vectors"]:
        payload = (VECTOR_DIR / vector["file"]).read_bytes()
        assert payload == generated[vector["file"]]
        assert hashlib.sha256(payload).hexdigest() == vector["sha256"]
        assert vector["expected"] in {"accept", "reject"}

    assert module.expected_spend_digest(context["tx"]).hex() == manifest["public_digest"]
