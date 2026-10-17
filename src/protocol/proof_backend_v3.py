"""Candidate V3 proof-backend profiles and fail-closed proof verification.

This module does not implement a STARK/zkVM verifier. Profile metadata and Python
trace-blinding experiments are not proof of zero knowledge or a soundness bound.
No envelope is accepted unless an explicitly configured, trusted backend adapter
cryptographically verifies the proof against the exact canonical statement digest.

Trust boundary: the caller must construct `proof_verifier` from a reviewed,
pinned backend implementation and immutable verification parameters. Never supply
a test double, a host predicate, or a boolean callback in a production composition.
"""
from __future__ import annotations

import hashlib
import math
import hmac
from dataclasses import dataclass
from typing import Final, Protocol

from src.core.zk_trace_blinding import (
    CANONICAL_ZK_BLINDING_ROWS,
    DEFAULT_ZK_BLINDING_ROWS,
    LEAF_SALT_BYTES,
)
from src.protocol.spend_relation_v3 import (
    PUBLIC_DIGEST_BYTES,
    PUBLIC_STATEMENT_DOMAIN_V3,
    TX_V3_CANDIDATE_VERSION,
)
from src.protocol.transaction_v3_candidate import (
    TxEnvelopeV3Candidate,
    TxFieldsV3Candidate,
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    transaction_digest_v3_candidate,
)

# These values describe a proposed configuration, not a proved security result.
CANONICAL_MAINNET_PROVER_NAME: Final[str] = "0PSP-Tier1-Mobile-Edge-AIR"
SERVER_PROVER_STATUS: Final[str] = "OPTIONAL / DEPRECATED"
PINNED_OPENVM_COMMIT: Final[str] = "59a69b8b0cbee7011ac978e4cc07707ee3681944"
TIER1_NATIVE_AIR_ROWS: Final[int] = 1 << 17
TIER2_OPENVM_MAX_ROWS: Final[int] = 1 << 24
TARGET_PQ_SOUNDNESS_BITS: Final[float] = 128.0
DECLARED_COMPOSITE_SOUNDNESS_BITS: Final[float] = 0.0
# Backwards-compatible legacy name: zero means no composed bound is established.
# Do not restore a positive value until it is justified for the exact accepted backend.
PROVEN_COMPOSITE_SOUNDNESS_BITS: Final[float] = 0.0
# Hard release latch: no accepted verifier currently establishes the complete relation,
# end-to-end witness hiding, and composed >=128-bit security profile. Do not enable
# until those gates have reproducible evidence on one exact release commit.
PRODUCTION1_TESTNET_SPEND_VERIFICATION_ENABLED: Final[bool] = True
MAINNET_LIVE_SPEND_VERIFICATION_ENABLED: Final[bool] = False
# Compatibility name remains the mainnet-live latch.
PRODUCTION_SPEND_VERIFICATION_ENABLED: Final[bool] = MAINNET_LIVE_SPEND_VERIFICATION_ENABLED
MAX_PROOF_BYTES: Final[int] = 2_000_000
HASH_BYTES: Final[int] = 48
ZERO_AUTH_TOKEN: Final[bytes] = bytes(HASH_BYTES)


class ProofBackendError(ValueError):
    """Raised when candidate backend configuration is malformed."""


@dataclass(frozen=True, slots=True)
class ProofBackendProfileV3:
    """Declared backend parameters. These fields alone cannot certify security."""

    backend_name: str
    is_zero_knowledge: bool
    blinding_rows: int
    leaf_salt_bytes: int
    extension_degree: int
    fri_queries: int
    fri_blowup_factor: int
    pow_grinding_bits: int
    proven_security_bits: float
    is_deprecated: bool = False

    @property
    def claimed_security_bits(self) -> float:
        """Alias clarifying that the stored number is a claim, not a proof."""
        return self.proven_security_bits

    def validate(self) -> None:
        """Validate declared parameter shape only; this does not prove soundness/ZK."""
        if not isinstance(self.backend_name, str) or not self.backend_name.strip():
            raise ProofBackendError("backend_name must be a non-empty string")
        if not isinstance(self.is_zero_knowledge, bool):
            raise ProofBackendError("is_zero_knowledge must be a boolean declaration")
        if not isinstance(self.is_deprecated, bool):
            raise ProofBackendError("is_deprecated must be a boolean")
        integer_fields = {
            "blinding_rows": self.blinding_rows,
            "leaf_salt_bytes": self.leaf_salt_bytes,
            "extension_degree": self.extension_degree,
            "fri_queries": self.fri_queries,
            "fri_blowup_factor": self.fri_blowup_factor,
            "pow_grinding_bits": self.pow_grinding_bits,
        }
        for name, value in integer_fields.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ProofBackendError(f"{name} must be a non-negative integer")
        if not self.is_zero_knowledge:
            raise ProofBackendError("candidate profile declares no zero-knowledge witness hiding")
        if self.blinding_rows < DEFAULT_ZK_BLINDING_ROWS:
            raise ProofBackendError(
                f"blinding rows ({self.blinding_rows}) below declared minimum ({DEFAULT_ZK_BLINDING_ROWS})"
            )
        if self.leaf_salt_bytes < LEAF_SALT_BYTES:
            raise ProofBackendError(
                f"leaf salt width ({self.leaf_salt_bytes}) below declared minimum ({LEAF_SALT_BYTES})"
            )
        if self.extension_degree < 1 or self.fri_queries < 1 or self.fri_blowup_factor < 2:
            raise ProofBackendError("extension degree, FRI query count, and blowup factor are invalid")
        if not isinstance(self.proven_security_bits, (int, float)) or isinstance(self.proven_security_bits, bool):
            raise ProofBackendError("security-bit declaration must be numeric")
        if not math.isfinite(float(self.proven_security_bits)) or self.proven_security_bits < 0:
            raise ProofBackendError("security-bit declaration must be finite and non-negative")
        # Deliberately do not treat claimed security bits as an acceptance criterion.
        # Only a real verifier for an exact, reviewed parameter set can establish that.


TIER1_MOBILE_PROFILE = ProofBackendProfileV3(
    backend_name=CANONICAL_MAINNET_PROVER_NAME,
    is_zero_knowledge=True,
    blinding_rows=CANONICAL_ZK_BLINDING_ROWS,
    leaf_salt_bytes=32,
    extension_degree=5,
    fri_queries=38,
    fri_blowup_factor=16,
    pow_grinding_bits=20,
    proven_security_bits=DECLARED_COMPOSITE_SOUNDNESS_BITS,
    is_deprecated=False,
)

TIER2_SERVER_PROFILE = ProofBackendProfileV3(
    backend_name="0PSP-Tier2-OpenVM-v2.0.2 (OPTIONAL / DEPRECATED)",
    is_zero_knowledge=True,
    blinding_rows=CANONICAL_ZK_BLINDING_ROWS,
    leaf_salt_bytes=32,
    extension_degree=5,
    fri_queries=38,
    fri_blowup_factor=16,
    pow_grinding_bits=20,
    proven_security_bits=DECLARED_COMPOSITE_SOUNDNESS_BITS,
    is_deprecated=True,
)

PRIMARY_PROVER_PROFILE: Final[ProofBackendProfileV3] = TIER1_MOBILE_PROFILE


class ProofArtifactVerifier(Protocol):
    """Trusted adapter contract for a *real* proof-system verifier.

    A production implementation must verify the cryptographic proof, pin and
    validate its backend/verifying key/executable configuration, enforce the
    complete accepted spend relation, and compare the proof's actual public output
    with `expected_public_digest`. It must not implement this contract by checking
    a host predicate or by returning a constant. The current repository does not
    provide a reviewed Tier-1 implementation satisfying this contract.
    """

    def verify_proof(
        self,
        envelope: TxEnvelopeV3Candidate,
        *,
        expected_public_digest: bytes,
        spent_commitment: bytes,
        profile: ProofBackendProfileV3,
    ) -> bool:
        """Cryptographically verify this proof and all statement/policy bindings."""
        ...


def public_statement_digest_v3(statement: TxFieldsV3Candidate) -> bytes:
    """Compute the canonical public statement digest expected from the proof."""
    if not isinstance(statement, TxFieldsV3Candidate):
        raise TypeError("statement must be TxFieldsV3Candidate")
    tx_digest = transaction_digest_v3_candidate(statement)
    preimage = PUBLIC_STATEMENT_DOMAIN_V3 + TX_V3_CANDIDATE_VERSION + tx_digest
    return hashlib.shake_256(preimage).digest(PUBLIC_DIGEST_BYTES)


def verify_public_statement_digest(
    statement: TxFieldsV3Candidate,
    claimed_public_digest: bytes,
) -> bool:
    """Compare a public digest with the canonical statement digest.

    This checks byte binding only. It does not verify a proof or establish a
    zero-knowledge/soundness guarantee.
    """
    if not isinstance(claimed_public_digest, bytes) or len(claimed_public_digest) != PUBLIC_DIGEST_BYTES:
        return False
    try:
        expected = public_statement_digest_v3(statement)
    except (TypeError, ValueError, OverflowError):
        return False
    return hmac.compare_digest(expected, claimed_public_digest)


def verify_candidate_proof_envelope(
    envelope: TxEnvelopeV3Candidate,
    *,
    spent_commitment: bytes,
    proof_verifier: ProofArtifactVerifier | None = None,
    profile: ProofBackendProfileV3 = TIER1_MOBILE_PROFILE,
) -> bool:
    """Verify a *candidate* envelope through an explicitly trusted proof adapter.

    This is an integration helper, not the production acceptance API. Never use its
    result to authorize a live-value spend. Candidate verifier integration can be
    tested without falsely implying that the complete production gates are closed.

    Fail-closed invariants:
    - absence of a real verifier rejects every envelope;
    - deprecated server profile and unsupported authorization policies reject;
    - nonzero auth_token is rejected because it is not part of the current V3
      public statement or the active candidate guest's public digest;
    - the adapter receives the exact statement digest and is responsible for
      actual proof verification under the pinned backend configuration;
    - adapter errors and non-boolean/truthy values are rejection, not success.

    This function is not evidence that the current repository has a production
    verifier. No reviewed Tier-1 proof adapter is currently integrated.
    """
    if not isinstance(envelope, TxEnvelopeV3Candidate):
        return False
    if proof_verifier is None or not callable(getattr(proof_verifier, "verify_proof", None)):
        return False
    if not isinstance(profile, ProofBackendProfileV3) or profile.is_deprecated:
        return False
    try:
        profile.validate()
    except (TypeError, ValueError, OverflowError):
        return False

    if envelope.statement.authorization_policy_id != V3_NK_POSSESSION_POLICY_CANDIDATE:
        return False
    if envelope.auth_token != ZERO_AUTH_TOKEN:
        # Legacy MAC token is not bound by the candidate proof's public statement.
        return False
    if not isinstance(spent_commitment, bytes) or len(spent_commitment) != HASH_BYTES:
        return False
    if not isinstance(envelope.proof, bytes) or not 1 <= len(envelope.proof) <= MAX_PROOF_BYTES:
        return False

    try:
        expected_digest = public_statement_digest_v3(envelope.statement)
        result = proof_verifier.verify_proof(
            envelope,
            expected_public_digest=expected_digest,
            spent_commitment=spent_commitment,
            profile=profile,
        )
    except Exception:
        # Verification is an untrusted boundary: parser, subprocess, or adapter
        # errors must fail closed and must not leak sensitive exception content.
        return False
    return result is True



def verify_production_proof_envelope(
    envelope: TxEnvelopeV3Candidate,
    *,
    spent_commitment: bytes | None = None,
    proof_verifier: ProofArtifactVerifier | None = None,
    profile: str = "mainnet_live",
) -> bool:
    """Verify only for the explicit testnet profile; mainnet remains hard-disabled.

    Testnet requires the concrete OpenVM adapter (never a test callback). This
    profile does not claim witness hiding or a 128-bit composed security bound.
    """
    if profile == "mainnet_live":
        return False
    if profile != "production1_testnet" or not PRODUCTION1_TESTNET_SPEND_VERIFICATION_ENABLED:
        return False
    if proof_verifier is None:
        return False
    from src.protocol.production1_artifacts import Production1OpenVMProofVerifier

    if not isinstance(proof_verifier, Production1OpenVMProofVerifier):
        return False
    if not isinstance(envelope, TxEnvelopeV3Candidate):
        return False
    if envelope.statement.authorization_policy_id != V3_NK_POSSESSION_POLICY_CANDIDATE:
        return False
    if envelope.auth_token != ZERO_AUTH_TOKEN:
        return False
    if spent_commitment is not None and (
        not isinstance(spent_commitment, bytes) or len(spent_commitment) != HASH_BYTES
    ):
        return False
    try:
        return proof_verifier(envelope.statement, envelope.proof) is True
    except Exception:
        return False
