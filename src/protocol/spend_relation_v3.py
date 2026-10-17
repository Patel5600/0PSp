"""0PSP Complete V3 Spend Relation and Recipient Privacy Specification (P0 Issue #33).

Formalizes and validates the complete single-witness spend relation R_spend_v3:
1. Authorization Policy: Enforces canonical 0PSP-V3-NK-POSSESSION-CANDIDATE-v1 policy.
2. Note Commitment Opening: Recomputes input commitment C_in via CommitV3(params, bundle, v, ns, coin_id, r_nf, rho).
3. Recipient-Keyed Nullifier: Verifies N_V3 = HMAC-SHA3-384(nk, M_nf) using recipient's secret nk,
   strictly eliminating V2 sender-linkability.
4. Key Possession Authentication: Proves input_nk opens the nullifier key commitment committed in input_bundle.
5. Authenticated Membership: Verifies Merkle tree inclusion path against commitment_root.
6. Anchored Output Identity: Derives (coin_id_out, r_nf_out) deterministically from consumed parent anchor.
7. Output Commitment Matching: Verifies C_out matches the exact output commitment in the transaction statement.
8. Strict Value Conservation: Enforces v_in = v_out + fee using non-overflowing 64-bit integer arithmetic.
9. Statement Digest Binding: Derives and binds the canonical 64-byte public statement digest.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Sequence

from src.primitives.coin_commitment_v3 import commit_coin_v3
from src.primitives.namespace import ScopedCoinId
from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier import NullifierSecret
from src.primitives.nullifier_v3 import (
    NullifierDerivingKeyV3,
    NullifierKeyCommitmentV3,
    NullifierV3,
    compute_nullifier_key_commitment_v3,
    compute_nullifier_v3,
)
from src.protocol.commitment_tree import leaf_hash, node_hash
from src.protocol.note_public_key_bundle_v3 import (
    NotePublicKeyBundleV3,
    decode_note_public_key_bundle_v3,
)
from src.protocol.output_identity import (
    derive_output_identity_v3_candidate,
    derive_output_identity_v3_production1,
)
from src.protocol.transaction_v3_candidate import (
    TX_V3_CANDIDATE_VERSION,
    TxFieldsV3Candidate,
    V3_NK_POSSESSION_POLICY_CANDIDATE,
    V3_SPEND_AUTH_TOKEN_POLICY_CANDIDATE,
    transaction_digest_v3_candidate,
    validate_nk_possession_policy_v3_candidate,
    validate_spend_auth_policy_v3_candidate,
)

PUBLIC_STATEMENT_DOMAIN_V3: Final[bytes] = (
    b"0PSP-OPENVM-V3-SPEND-PUBLIC-STATEMENT-CANDIDATE-v2"
)
PUBLIC_DIGEST_BYTES: Final[int] = 64
MAX_VALUE_U64: Final[int] = (1 << 64) - 1


class SpendRelationV3Error(ValueError):
    """Raised when a candidate witness fails any constraint of R_spend_v3."""


@dataclass(frozen=True, slots=True)
class OutputWitnessV3:
    """Private witness for an individual output note in a V3 spend transaction."""

    recipient_bundle: bytes
    output_value: int
    output_rho: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.output_value <= MAX_VALUE_U64:
            raise ValueError("output_value outside valid u64 range")
        if len(self.output_rho) != 36:
            raise ValueError("output_rho must be 36 bytes")


@dataclass(frozen=True, slots=True)
class SpendWitnessV3:
    """Full private witness for a 1-input / 1-output V3 spend."""

    input_bundle: bytes
    input_value: int
    input_coin_id: ScopedCoinId
    input_r_nf: NullifierSecret
    input_rho: bytes
    input_nk: NullifierDerivingKeyV3
    leaf_index: int
    merkle_siblings: tuple[bytes, ...]
    recipient_bundle: bytes
    output_value: int
    output_rho: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.input_value <= MAX_VALUE_U64:
            raise ValueError("input_value outside valid u64 range")
        if not 0 <= self.output_value <= MAX_VALUE_U64:
            raise ValueError("output_value outside valid u64 range")
        if len(self.input_rho) != 36:
            raise ValueError("input_rho must be 36 bytes")
        if len(self.output_rho) != 36:
            raise ValueError("output_rho must be 36 bytes")
        if len(self.merkle_siblings) not in (32, 63):
            raise ValueError("merkle_siblings length must be 32 or 63")


@dataclass(frozen=True, slots=True)
class MultiOutputSpendWitnessV3:
    """Full private witness for a 1-input / m-output V3 spend transaction (P0 Issue #42)."""

    input_bundle: bytes
    input_value: int
    input_coin_id: ScopedCoinId
    input_r_nf: NullifierSecret
    input_rho: bytes
    input_nk: NullifierDerivingKeyV3
    leaf_index: int
    merkle_siblings: tuple[bytes, ...]
    outputs: tuple[OutputWitnessV3, ...]

    def __post_init__(self) -> None:
        if not 0 <= self.input_value <= MAX_VALUE_U64:
            raise ValueError("input_value outside valid u64 range")
        if len(self.input_rho) != 36:
            raise ValueError("input_rho must be 36 bytes")
        if len(self.merkle_siblings) not in (32, 63):
            raise ValueError("merkle_siblings length must be 32 or 63")
        if not isinstance(self.outputs, tuple) or not self.outputs:
            raise ValueError("outputs must be a non-empty tuple of OutputWitnessV3")
        for out in self.outputs:
            if not isinstance(out, OutputWitnessV3):
                raise ValueError("all elements in outputs must be OutputWitnessV3")


def verify_spend_relation_v3_reference(
    statement: TxFieldsV3Candidate,
    witness: SpendWitnessV3 | MultiOutputSpendWitnessV3,
) -> bytes:
    """Verify all constraints of the 0PSP V3 spend relation over one consistent witness.

    Supports both single-output (SpendWitnessV3) and multi-output (MultiOutputSpendWitnessV3) transactions.

    Returns:
      The 64-byte public statement digest upon successful verification.

    Raises:
      SpendRelationV3Error if any predicate fails.
    """
    if not isinstance(statement, TxFieldsV3Candidate):
        raise TypeError("statement must be a TxFieldsV3Candidate")
    if not isinstance(witness, (SpendWitnessV3, MultiOutputSpendWitnessV3)):
        raise TypeError("witness must be a SpendWitnessV3 or MultiOutputSpendWitnessV3")

    # 1. Authorization Policy Constraint
    try:
        validate_spend_auth_policy_v3_candidate(statement)
    except Exception as exc:
        raise SpendRelationV3Error(f"invalid authorization policy: {exc}") from exc

    if isinstance(witness, SpendWitnessV3):
        outputs = (OutputWitnessV3(witness.recipient_bundle, witness.output_value, witness.output_rho),)
    else:
        outputs = witness.outputs

    if len(statement.output_commitments) != len(outputs):
        raise SpendRelationV3Error(
            f"output commitments count mismatch: statement has {len(statement.output_commitments)}, witness has {len(outputs)}"
        )

    # 2. Key Possession Authentication
    decoded_bundle = decode_note_public_key_bundle_v3(witness.input_bundle)
    derived_nk_commit = compute_nullifier_key_commitment_v3(witness.input_nk)
    if derived_nk_commit != decoded_bundle.nullifier_key_commitment:
        raise SpendRelationV3Error(
            "input_nk does not match the nullifier_key_commitment in input_bundle"
        )

    # 3. Input Note Commitment Opening
    input_commitment = commit_coin_v3(
        namespace_id=statement.namespace_id,
        public_key_bundle=witness.input_bundle,
        value=witness.input_value,
        coin_id=witness.input_coin_id,
        r_nf=witness.input_r_nf,
        rho_coin=witness.input_rho,
        params_id=statement.params_id,
    )

    # 4. Same-Witness Recipient-Keyed Nullifier Derivation
    expected_nullifier = compute_nullifier_v3(
        namespace_id=statement.namespace_id,
        params_id=statement.params_id,
        public_key_bundle=witness.input_bundle,
        commitment=input_commitment,
        coin_id=witness.input_coin_id,
        r_nf=witness.input_r_nf,
        nullifier_key=witness.input_nk,
    )
    if expected_nullifier != statement.input_nullifier:
        raise SpendRelationV3Error(
            "input NullifierV3 does not match transaction statement nullifier"
        )

    # 5. Authenticated Merkle Membership Path (Depth 32 or 63)
    current_node = leaf_hash(
        statement.namespace_id, witness.leaf_index, input_commitment.value
    )
    for level, sibling in enumerate(witness.merkle_siblings):
        if (witness.leaf_index >> level) & 1:
            current_node = node_hash(
                statement.namespace_id, level, sibling, current_node
            )
        else:
            current_node = node_hash(
                statement.namespace_id, level, current_node, sibling
            )
    if current_node != statement.commitment_root:
        raise SpendRelationV3Error(
            "input commitment is not a valid member of statement commitment_root"
        )

    # 6 & 7. Output Identity Derivation & Commitment Matching for every output
    for idx, out_w in enumerate(outputs):
        identity_inputs = dict(
            namespace_id=statement.namespace_id,
            parent_coin_id=witness.input_coin_id,
            parent_r_nf=witness.input_r_nf,
            parent_public_key_bundle=witness.input_bundle,
            parent_commitment=input_commitment,
            parent_nullifier_key=witness.input_nk,
            recipient_key_bundle=out_w.recipient_bundle,
            transaction_entropy=statement.output_entropy,
            output_index=idx,
            params_id=statement.params_id,
        )
        if len(outputs) == 1 and len(witness.merkle_siblings) == 63:
            derived_output_identity = derive_output_identity_v3_production1(
                **identity_inputs,
                anchor_context=(
                    statement.commitment_root
                    + statement.ledger_state_head
                    + statement.state_context_digest
                ),
            )
        else:
            # Legacy host-only reference vectors are not the Production-1 accepted profile.
            derived_output_identity = derive_output_identity_v3_candidate(**identity_inputs)

        expected_output_commitment = commit_coin_v3(
            namespace_id=statement.namespace_id,
            public_key_bundle=out_w.recipient_bundle,
            value=out_w.output_value,
            coin_id=derived_output_identity.coin_id,
            r_nf=derived_output_identity.r_nf,
            rho_coin=out_w.output_rho,
            params_id=statement.params_id,
        )
        if expected_output_commitment != statement.output_commitments[idx]:
            raise SpendRelationV3Error(
                f"derived output commitment does not match statement output commitment (slot {idx})"
            )

    # 8. Strict Multi-Output Value Conservation (64-Bit Checked Arithmetic, No Wraparound)
    total_out = statement.fee
    for idx, out_w in enumerate(outputs):
        total_out += out_w.output_value
        if total_out > MAX_VALUE_U64:
            raise SpendRelationV3Error("total output value overflows u64")

    if witness.input_value != total_out:
        raise SpendRelationV3Error(
            f"value conservation violated: in ({witness.input_value}) != sum(out) + fee ({total_out})"
        )

    # 9. Statement Public Digest
    tx_digest = transaction_digest_v3_candidate(statement)
    preimage = PUBLIC_STATEMENT_DOMAIN_V3 + TX_V3_CANDIDATE_VERSION + tx_digest
    return hashlib.shake_256(preimage).digest(PUBLIC_DIGEST_BYTES)

