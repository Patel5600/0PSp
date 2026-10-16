"""Unit tests for 0PSP Production Proof Backend Specification & Verification (V3)."""
from __future__ import annotations

import pytest

from src.primitives.keys_v3 import compute_spend_auth_token_v3
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.proof_backend_v3 import (
    ProofBackendError,
    ProofBackendProfileV3,
    TIER1_MOBILE_PROFILE,
    TIER2_SERVER_PROFILE,
    verify_production_proof_envelope,
    verify_public_statement_digest,
)
from src.protocol.spend_relation_v3 import verify_spend_relation_v3_reference
from src.protocol.transaction_v3_candidate import (
    TxEnvelopeV3Candidate,
    TxFieldsV3Candidate,
    V3_SPEND_AUTH_TOKEN_POLICY_CANDIDATE,
    transaction_digest_v3_candidate,
)

NAMESPACE = NamespaceIdV3(b"\x11" * 48)
PARAMS = b"proof-backend-test-params"
COMMIT_ROOT = b"\x22" * 48
NULLIFIER = NullifierV3(b"\x33" * 48)
STATE_HEAD = b"\x44" * 48
STATE_CONTEXT = b"\x55" * 64
OUTPUT_ENTROPY = b"\x66" * 32
OUT_COMM = CoinCommitmentV3(b"\x77" * 48)


def create_statement() -> TxFieldsV3Candidate:
    return TxFieldsV3Candidate(
        params_id=PARAMS,
        namespace_id=NAMESPACE,
        commitment_root=COMMIT_ROOT,
        input_nullifier=NULLIFIER,
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=V3_SPEND_AUTH_TOKEN_POLICY_CANDIDATE,
        fee=10,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUT_COMM,),
    )


def test_canonical_proof_backend_profiles_are_valid() -> None:
    TIER1_MOBILE_PROFILE.validate()
    TIER2_SERVER_PROFILE.validate()
    assert TIER1_MOBILE_PROFILE.proven_security_bits >= 128.0
    assert TIER2_SERVER_PROFILE.proven_security_bits >= 128.0
    assert TIER1_MOBILE_PROFILE.blinding_rows == 39
    assert TIER1_MOBILE_PROFILE.leaf_salt_bytes == 32


def test_invalid_proof_backend_profiles_fail_validation() -> None:
    # 1. Non-ZK profile must be rejected
    bad_zk = ProofBackendProfileV3(
        backend_name="Non-ZK",
        is_zero_knowledge=False,
        blinding_rows=39,
        leaf_salt_bytes=32,
        extension_degree=5,
        fri_queries=38,
        fri_blowup_factor=16,
        pow_grinding_bits=20,
        proven_security_bits=130.0,
    )
    with pytest.raises(ProofBackendError, match="must enforce zero-knowledge"):
        bad_zk.validate()

    # 2. Insufficient blinding rows rejected
    bad_blinding = ProofBackendProfileV3(
        backend_name="Weak-Blinding",
        is_zero_knowledge=True,
        blinding_rows=10,
        leaf_salt_bytes=32,
        extension_degree=5,
        fri_queries=38,
        fri_blowup_factor=16,
        pow_grinding_bits=20,
        proven_security_bits=130.0,
    )
    with pytest.raises(ProofBackendError, match="blinding rows .* below required minimum"):
        bad_blinding.validate()

    # 3. Insufficient security level rejected
    bad_sec = ProofBackendProfileV3(
        backend_name="Low-Security",
        is_zero_knowledge=True,
        blinding_rows=39,
        leaf_salt_bytes=32,
        extension_degree=5,
        fri_queries=38,
        fri_blowup_factor=16,
        pow_grinding_bits=20,
        proven_security_bits=96.0,
    )
    with pytest.raises(ProofBackendError, match="security level .* below target"):
        bad_sec.validate()


def test_verify_public_statement_digest_matching() -> None:
    stmt = create_statement()
    # Compute genuine public statement digest using reference relation
    from src.protocol.spend_relation_v3 import (
        PUBLIC_DIGEST_BYTES,
        PUBLIC_STATEMENT_DOMAIN_V3,
        TX_V3_CANDIDATE_VERSION,
    )
    import hashlib

    tx_digest = transaction_digest_v3_candidate(stmt)
    preimage = PUBLIC_STATEMENT_DOMAIN_V3 + TX_V3_CANDIDATE_VERSION + tx_digest
    canonical_public_digest = hashlib.shake_256(preimage).digest(PUBLIC_DIGEST_BYTES)

    assert verify_public_statement_digest(stmt, canonical_public_digest) is True
    assert verify_public_statement_digest(stmt, bytes([0x00] * 64)) is False
    assert verify_public_statement_digest(stmt, bytes([0x00] * 32)) is False


def test_verify_production_proof_envelope_lifecycle() -> None:
    stmt = create_statement()
    sk_spend = bytes([0xAA]) * 48
    spent_commitment = bytes([0xBB]) * 48
    tx_digest = transaction_digest_v3_candidate(stmt)

    auth_token = compute_spend_auth_token_v3(sk_spend, tx_digest, spent_commitment)
    proof_bytes = b"openvm-stark-proof-artifact-v3"

    envelope = TxEnvelopeV3Candidate(
        statement=stmt,
        auth_token=auth_token,
        proof=proof_bytes,
    )

    # 1. Valid envelope verifies cleanly
    assert verify_production_proof_envelope(
        envelope,
        spent_commitment=spent_commitment,
        sk_spend=sk_spend,
        profile=TIER1_MOBILE_PROFILE,
    ) is True

    # 2. Tampered auth_token fails closed
    bad_token_envelope = TxEnvelopeV3Candidate(
        statement=stmt,
        auth_token=bytes([0x00]) * 48,
        proof=proof_bytes,
    )
    assert verify_production_proof_envelope(
        bad_token_envelope,
        spent_commitment=spent_commitment,
        sk_spend=sk_spend,
    ) is False

    # 3. Wrong spent commitment fails closed
    assert verify_production_proof_envelope(
        envelope,
        spent_commitment=bytes([0x99]) * 48,
        sk_spend=sk_spend,
    ) is False
