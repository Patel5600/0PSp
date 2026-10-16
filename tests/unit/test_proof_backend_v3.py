"""Unit tests for V3 proof-verifier integration boundaries.

The test-only adapter below verifies call plumbing only. It is not a STARK/zkVM
verifier and its acceptance must never be used as cryptographic evidence.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.proof_backend_v3 import (
    MAX_PROOF_BYTES,
    ProofBackendError,
    ProofBackendProfileV3,
    OPENVM_V2_CANDIDATE_PROFILE,
    TIER2_SERVER_PROFILE,
    ZERO_AUTH_TOKEN,
    PRODUCTION_SPEND_VERIFICATION_ENABLED,
    public_statement_digest_v3,
    verify_candidate_proof_envelope,
    verify_production_proof_envelope,
    verify_public_statement_digest,
)
from src.protocol.transaction_v3_candidate import (
    TxEnvelopeV3Candidate,
    TxFieldsV3Candidate,
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    V3_SPEND_AUTH_TOKEN_POLICY_CANDIDATE,
)

NAMESPACE = NamespaceIdV3(b"\x11" * 48)
PARAMS = b"proof-backend-test-params"
COMMIT_ROOT = b"\x22" * 48
NULLIFIER = NullifierV3(b"\x33" * 48)
STATE_HEAD = b"\x44" * 48
STATE_CONTEXT = b"\x55" * 64
OUTPUT_ENTROPY = b"\x66" * 32
OUT_COMM = CoinCommitmentV3(b"\x77" * 48)
CANDIDATE_PROOF = b"test-only-placeholder-proof"


def create_statement() -> TxFieldsV3Candidate:
    return TxFieldsV3Candidate(
        params_id=PARAMS,
        namespace_id=NAMESPACE,
        commitment_root=COMMIT_ROOT,
        input_nullifier=NULLIFIER,
        ledger_state_head=STATE_HEAD,
        state_context_digest=STATE_CONTEXT,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=10,
        output_entropy=OUTPUT_ENTROPY,
        output_commitments=(OUT_COMM,),
    )


def test_declared_profile_configuration_is_structurally_valid() -> None:
    OPENVM_V2_CANDIDATE_PROFILE.validate()
    TIER2_SERVER_PROFILE.validate()
    # These are configuration declarations, not cryptographic security evidence. The composed bound remains unestablished.
    assert OPENVM_V2_CANDIDATE_PROFILE.claimed_security_bits == 0.0
    assert OPENVM_V2_CANDIDATE_PROFILE.claimed_security_bits < 128.0
    assert OPENVM_V2_CANDIDATE_PROFILE.is_zero_knowledge is False
    assert OPENVM_V2_CANDIDATE_PROFILE.blinding_rows == 0
    assert OPENVM_V2_CANDIDATE_PROFILE.leaf_salt_bytes == 0
    assert OPENVM_V2_CANDIDATE_PROFILE.extension_degree == 4
    assert OPENVM_V2_CANDIDATE_PROFILE.fri_queries == 0
    assert OPENVM_V2_CANDIDATE_PROFILE.fri_blowup_factor == 2
    assert OPENVM_V2_CANDIDATE_PROFILE.is_deprecated is False
    assert TIER2_SERVER_PROFILE.is_deprecated is True


def test_profile_validation_checks_shape_without_claiming_zero_knowledge() -> None:
    # A non-ZK profile is structurally valid; ZK is an evidence status, not a
    # validation requirement for candidate backend metadata.
    non_zk = ProofBackendProfileV3(
        backend_name="Experimental non-ZK",
        is_zero_knowledge=False,
        blinding_rows=0,
        leaf_salt_bytes=0,
        extension_degree=4,
        fri_queries=0,
        fri_blowup_factor=2,
        pow_grinding_bits=0,
        proven_security_bits=0.0,
    )
    non_zk.validate()
    assert non_zk.is_zero_knowledge is False

    invalid = replace(non_zk, backend_name=" ", extension_degree=0)
    with pytest.raises(ProofBackendError, match="backend_name"):
        invalid.validate()

    invalid_numeric = replace(non_zk, proven_security_bits=float("nan"))
    with pytest.raises(ProofBackendError, match="finite and non-negative"):
        invalid_numeric.validate()


def test_public_statement_digest_checks_only_byte_binding() -> None:
    statement = create_statement()
    expected = public_statement_digest_v3(statement)

    assert len(expected) == 64
    assert verify_public_statement_digest(statement, expected) is True
    assert verify_public_statement_digest(statement, bytes(64)) is False
    assert verify_public_statement_digest(statement, bytes(32)) is False
    assert verify_public_statement_digest(statement, bytearray(expected)) is False


class _TestOnlyProofVerifier:
    """A test double for API wiring, not a proof-system implementation."""

    def __init__(self, result: object = True) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def verify_proof(
        self,
        envelope: TxEnvelopeV3Candidate,
        *,
        expected_public_digest: bytes,
        profile: ProofBackendProfileV3,
    ) -> bool:
        self.calls.append({
            "envelope": envelope,
            "expected_public_digest": expected_public_digest,
            "profile": profile,
        })
        return self.result  # type: ignore[return-value]


def create_envelope(
    *,
    statement: TxFieldsV3Candidate | None = None,
    auth_token: bytes = ZERO_AUTH_TOKEN,
    proof: bytes = CANDIDATE_PROOF,
) -> TxEnvelopeV3Candidate:
    return TxEnvelopeV3Candidate(
        statement=statement or create_statement(),
        auth_token=auth_token,
        proof=proof,
    )


def test_candidate_envelope_rejects_when_verifier_is_not_configured() -> None:
    # Regression for the old critical bug: any non-empty byte string previously
    # returned True when sk_spend was omitted. No verifier means no acceptance.
    assert verify_candidate_proof_envelope(
        create_envelope(),
    ) is False


def test_production_envelope_is_hard_locked_while_security_gates_are_open() -> None:
    assert PRODUCTION_SPEND_VERIFICATION_ENABLED is False
    verifier = _TestOnlyProofVerifier(True)
    # Even a fake adapter that returns literal True cannot cross the release latch.
    assert verify_production_proof_envelope(
        create_envelope(),
        proof_verifier=verifier,
    ) is False
    assert verifier.calls == []


def test_caller_manufactured_high_security_profile_cannot_override_release_latch() -> None:
    forged_profile = replace(
        OPENVM_V2_CANDIDATE_PROFILE,
        backend_name="Caller-Claimed-Production-Backend",
        proven_security_bits=256.0,
    )
    verifier = _TestOnlyProofVerifier(True)
    assert verify_production_proof_envelope(
        create_envelope(),
        proof_verifier=verifier,
        profile=forged_profile,
    ) is False
    assert verifier.calls == []


def test_envelope_delegates_exact_statement_to_configured_verifier() -> None:
    # This confirms adapter wiring only. The test double is not cryptographic
    # evidence and must never be wired into a deployment.
    envelope = create_envelope()
    verifier = _TestOnlyProofVerifier(True)

    assert verify_candidate_proof_envelope(
        envelope,
        proof_verifier=verifier,
    ) is True

    assert len(verifier.calls) == 1
    call = verifier.calls[0]
    assert call["envelope"] is envelope
    assert call["expected_public_digest"] == public_statement_digest_v3(envelope.statement)
    assert call["profile"] is OPENVM_V2_CANDIDATE_PROFILE


@pytest.mark.parametrize(
    ("kwargs", "expected_reason"),
    [
        ({"auth_token": b"\x01" * 48}, "unbound auth token"),
        ({"proof": b""}, "envelope rejects empty proof at construction"),
    ],
)
def test_unbound_or_malformed_envelope_fields_are_rejected(
    kwargs: dict[str, bytes],
    expected_reason: str,
) -> None:
    if expected_reason == "envelope rejects empty proof at construction":
        with pytest.raises(ValueError, match="proof must be non-empty"):
            create_envelope(**kwargs)
        return

    verifier = _TestOnlyProofVerifier(True)
    assert verify_candidate_proof_envelope(
        create_envelope(**kwargs),
        proof_verifier=verifier,
    ) is False
    assert verifier.calls == []


def test_legacy_secret_mac_policy_is_not_accepted_as_public_proof_authorization() -> None:
    statement = replace(
        create_statement(),
        authorization_policy_id=V3_SPEND_AUTH_TOKEN_POLICY_CANDIDATE,
    )
    verifier = _TestOnlyProofVerifier(True)

    assert verify_candidate_proof_envelope(
        create_envelope(statement=statement),
        proof_verifier=verifier,
    ) is False
    assert verifier.calls == []


def test_noncanonical_profile_is_rejected_by_candidate_envelope() -> None:
    forged_profile = replace(OPENVM_V2_CANDIDATE_PROFILE, backend_name="different backend")
    verifier = _TestOnlyProofVerifier(True)
    assert verify_candidate_proof_envelope(
        create_envelope(),
        proof_verifier=verifier,
        profile=forged_profile,
    ) is False
    assert verifier.calls == []


def test_rejects_backend_false_and_non_boolean_truthy_results() -> None:
    envelope = create_envelope()
    for result in (False, None, 1, "verified"):
        verifier = _TestOnlyProofVerifier(result)
        assert verify_candidate_proof_envelope(
            envelope,
                proof_verifier=verifier,
        ) is False


def test_backend_exception_fails_closed() -> None:
    class RaisingVerifier:
        def verify_proof(self, *_args: object, **_kwargs: object) -> bool:
            raise RuntimeError("internal verifier diagnostic should not escape")

    assert verify_candidate_proof_envelope(
        create_envelope(),
        proof_verifier=RaisingVerifier(),
    ) is False


def test_deprecated_backend_is_never_used_for_production_envelope() -> None:
    verifier = _TestOnlyProofVerifier(True)
    assert verify_candidate_proof_envelope(
        create_envelope(),
        proof_verifier=verifier,
        profile=TIER2_SERVER_PROFILE,
    ) is False
    assert verifier.calls == []
