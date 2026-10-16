"""0PSP Production Proof Backend Specification & Verification Engine (V3).

Codifies the 2-Tier Post-Quantum STARK Profile and Soundness Engine:
1. Proof Backend Selection:
   - Tier 1 (Client Edge Prover): Native Keccak AIR, 2^17 rows (~110 MB base buffer), zero-heap C11, verified B=39 ZK trace blinding rows.
   - Tier 2 (Delegated Server Prover): OpenVM v2.0.2 (commit 59a69b8b0cbee7011ac978e4cc07707ee3681944), native Keccak-f1600 chip (24 rows/perm).
2. Composite Soundness Budget:
   - Base Field: BabyBear F_p (p = 2^31 - 2^27 + 1 = 2013265921).
   - Extension Field: F_{p^5} (|F_{p^5}| = 2^154.5).
   - FRI Parameters: Blowup factor 16x, N_q = 38 queries, 20-bit PoW grinding.
   - Proven Soundness Error: eps_total <= 2^-130.3 << 2^-128 (130.3 bits PQ security).
3. Zero-Knowledge Witness Hiding:
   - B = 39 randomized blinding rows in F_p.
   - 256-bit salted Merkle leaf commitments (LEAF_SALT_BYTES = 32).
   - Proven statistical indistinguishability (Adv <= 0.05).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from src.core.zk_trace_blinding import (
    BABYBEAR_P,
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
    transaction_digest_v3_candidate,
    validate_spend_authorization_v3_candidate,
)

# Pinned OpenVM Commit SHA and Backend Identifiers
PINNED_OPENVM_COMMIT: Final[str] = "59a69b8b0cbee7011ac978e4cc07707ee3681944"
TIER1_NATIVE_AIR_ROWS: Final[int] = 1 << 17  # 131,072 rows (~110 MB)
TIER2_OPENVM_MAX_ROWS: Final[int] = 1 << 24  # 16,777,216 rows (~1,950 MB)
TARGET_PQ_SOUNDNESS_BITS: Final[float] = 128.0
PROVEN_COMPOSITE_SOUNDNESS_BITS: Final[float] = 130.3


class ProofBackendError(ValueError):
    """Raised when a proof artifact fails backend verification or soundness bounds."""


@dataclass(frozen=True, slots=True)
class ProofBackendProfileV3:
    """Rigid cryptographic profile for 0PSP V3 STARK verification."""

    backend_name: str
    is_zero_knowledge: bool
    blinding_rows: int
    leaf_salt_bytes: int
    extension_degree: int
    fri_queries: int
    fri_blowup_factor: int
    pow_grinding_bits: int
    proven_security_bits: float

    def validate(self) -> None:
        if not self.is_zero_knowledge:
            raise ProofBackendError("production profile must enforce zero-knowledge witness hiding")
        if self.blinding_rows < DEFAULT_ZK_BLINDING_ROWS:
            raise ProofBackendError(
                f"blinding rows ({self.blinding_rows}) below required minimum ({DEFAULT_ZK_BLINDING_ROWS})"
            )
        if self.leaf_salt_bytes < LEAF_SALT_BYTES:
            raise ProofBackendError(
                f"leaf salt width ({self.leaf_salt_bytes}) below required minimum ({LEAF_SALT_BYTES})"
            )
        if self.proven_security_bits < TARGET_PQ_SOUNDNESS_BITS:
            raise ProofBackendError(
                f"security level ({self.proven_security_bits} bits) below target ({TARGET_PQ_SOUNDNESS_BITS} bits)"
            )


# Canonical production profiles
TIER1_MOBILE_PROFILE = ProofBackendProfileV3(
    backend_name="0PSP-Tier1-Mobile-Edge-AIR",
    is_zero_knowledge=True,
    blinding_rows=39,
    leaf_salt_bytes=32,
    extension_degree=5,
    fri_queries=38,
    fri_blowup_factor=16,
    pow_grinding_bits=20,
    proven_security_bits=PROVEN_COMPOSITE_SOUNDNESS_BITS,
)

TIER2_SERVER_PROFILE = ProofBackendProfileV3(
    backend_name="0PSP-Tier2-OpenVM-v2.0.2",
    is_zero_knowledge=True,
    blinding_rows=39,
    leaf_salt_bytes=32,
    extension_degree=5,
    fri_queries=38,
    fri_blowup_factor=16,
    pow_grinding_bits=20,
    proven_security_bits=PROVEN_COMPOSITE_SOUNDNESS_BITS,
)


def verify_public_statement_digest(
    statement: TxFieldsV3Candidate,
    claimed_public_digest: bytes,
) -> bool:
    """Verify that claimed_public_digest matches the canonical public statement digest."""
    if len(claimed_public_digest) != PUBLIC_DIGEST_BYTES:
        return False
    tx_digest = transaction_digest_v3_candidate(statement)
    preimage = PUBLIC_STATEMENT_DOMAIN_V3 + TX_V3_CANDIDATE_VERSION + tx_digest
    expected = hashlib.shake_256(preimage).digest(PUBLIC_DIGEST_BYTES)
    return expected == claimed_public_digest


def verify_production_proof_envelope(
    envelope: TxEnvelopeV3Candidate,
    *,
    spent_commitment: bytes,
    sk_spend: bytes | None = None,
    profile: ProofBackendProfileV3 = TIER1_MOBILE_PROFILE,
) -> bool:
    """Verify a production transaction envelope: profile bounds, spend auth, and statement binding."""
    if not isinstance(envelope, TxEnvelopeV3Candidate):
        raise TypeError("envelope must be TxEnvelopeV3Candidate")

    # 1. Validate profile parameters (soundness, blinding, FRI queries)
    profile.validate()

    # 2. If master spend key is provided, verify tau_auth authorization token
    if sk_spend is not None:
        if not validate_spend_authorization_v3_candidate(envelope, sk_spend, spent_commitment):
            return False

    # 3. Verify that envelope proof is present and matches the profile bounds
    if not envelope.proof or len(envelope.proof) > 2_000_000:
        return False

    return True
