# 0PSP Constructionable V0 — Single-Relation Spend Proof

**Status:** Executable research target; not a completed or security-proven construction.

## Decision

Retire the active plan combining an extended LoTRS selection proof, separate SHAKE STARK, and custom lattice bridge commitment. The bridge had no established hiding/binding theorem and the two proof systems had no compiled common relation.

V0 targets **one anonymous proof-of-knowledge / signature-of-knowledge relation for the complete spend statement**. The exact backend (including whether it is STARK-based) is not selected or integrated. Threshold authorization is a private witness inside that proof. The public deterministic nullifier supplies replay linkability. There is no separate LRS tag requirement, public bridge commitment, or cross-layer equality argument.

## Concrete byte-level relations

### Coin commitment candidate

Let the coin opening contain canonical public-key bytes pk, value v, 32-byte coin ID, 36-byte nullifier secret r_nf, and an independent uniform 36-byte commitment salt rho_C. Define:

    C = SHAKE256-384(
        "0PSP-COIN-COMMIT-v1-SHAKE256" || version ||
        len(params_id) || params_id ||
        len(pk) || pk || uint64_le(v) ||
        coin_id || r_nf || rho_C
    )

All length prefixes are fixed-width little-endian; pk serialization is canonical for the chosen threshold-signature scheme. The output C is 48 bytes. This is a **QROM hash-commitment candidate**, not a proven commitment scheme: binding reduces to finding a SHAKE output collision for distinct canonical openings, and hiding relies on the secret 288-bit salt under the specified random-oracle model. The proof must establish the exact opening relation. The code helper only computes and checks openings.

### Nullifier

    nu = SHAKE256-384(
        "0PSP-NULLIFIER-v1-SHAKE256" || version ||
        len(coin_id) || coin_id || len(r_nf) || r_nf
    )

The nullifier output is 48 bytes. The 36-byte secret gives 288 bits of input entropy. Under the illustrative query budget q_H <= 2^64, the hidden-point guessing bound is still only conditional arithmetic (roughly 2^-155.7 under the cited compressed-oracle expression); it is not an unlinkability theorem. The 384-bit output targets 128-bit generic quantum collision resistance, subject to the SHAKE model.

## Component choices

1. **Threshold authorization:** use the Ringtail two-round lattice threshold-signature interface. A qualified t-of-n group produces an ordinary signature that verifies under the coin's public key. Pin an immutable upstream revision and parameter manifest. The published prototype uses dealer-based key sharing; V0 explicitly assumes a trusted dealer unless DKG is added.
2. **Single proof:** implement one ZK argument for the full NP relation. The generic post-quantum SoK/LRS implementation by Xue, Lu, Au and Zhang (ESORICS 2024) is a possible code scaffold because it targets NP statements, but its repository warns the implementation is experimental and its ZK enhancement informal. Do not inherit a security claim from that implementation.
3. **Commitment:** use the SHAKE commitment candidate above for the first functional integration. It replaces the uninstantiated lattice bridge; it is not a lattice commitment and its QROM hiding/binding proof remains a formal task.
4. **Ledger:** the eligible commitment set and spent-nullifier set are public state. Verification atomically rejects a previously spent nullifier.

Sources:
- Ringtail: https://eprint.iacr.org/2024/1113 and https://github.com/daryakaviani/ringtail
- Generic PQ SoK/LRS scaffold: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature
- SHAKE: https://csrc.nist.gov/pubs/fips/202/final
- LoTRS comparator: https://zenodo.org/records/22807126

## Public statement and witness

Public: x = (R_C, nu, M, state, params_id)

Witness: w = (j, C_j, pk_j, v, coin_id, r_nf, rho_C, sigma)

The one proof must establish all predicates using the same hidden j:

1. j is in [N] and C_j = R_C[j], without revealing j.
2. C_j equals the coin commitment computed from the same pk_j, value, coin_id, r_nf and rho_C.
3. Verify_Ringtail(pk_j, M, sigma) = 1.
4. nu equals the deterministic nullifier equation above.
5. The coin is eligible and unspent; transaction value and policy constraints hold.

No separate Layer 1/Layer 2 proof pair or bridge value B is required. The selected index, opening and threshold signature stay hidden.

## Implementation sequence

### C0 — Component conformance
- Pin upstream revisions and licenses.
- Pass upstream test vectors before changing the relation.
- Run coin-commitment and nullifier unit tests.
- Keep ML-DSA-like ring helpers isolated; do not call them LoTRS or Ringtail arithmetic.

### C1 — Small-ring prototype
- Start with N=2,4,8; then measure N=16,32,64.
- Test valid spend, replay, wrong key, invalid threshold signature, wrong opening, wrong nullifier, malformed encoding and stale state.
- Keep the threshold signature private inside the proof witness.

### C2 — Proof-system feasibility
- Implement the full relation in one chosen ZK proof backend.
- Ensure commitment hash, nullifier hash, threshold-signature verification and range constraints are enforced in the proof trace.
- Establish actual zero knowledge and quantum soundness; the upstream prototype's informal ZK enhancement is insufficient for a security claim.
- Measure proof bytes, proving/verifying time and peak memory. Previous 60–120 KiB figures remain unverified.

### C3 — Security review
Prove or reduce spend soundness, threshold authorization, commitment hiding/binding, knowledge soundness, duplicate-nullifier rejection and unlinkability under a fully specified quantum-adversary game.

## Limitations

- V0 inherits Ringtail's dealer model unless DKG is added.
- The generic SoK/LRS repository is research code and its ZK implementation is not independently audited.
- No end-to-end proof or benchmark exists yet.
- Novelty is not claimed; compare with generic SoK/LRS, Ringtail, LoTRS, Obscura-PQ and the 2024 identity-based threshold linkable dual-ring scheme.
- Production remains NO-GO.

This architecture is implementable as a staged research prototype. It is not blocker-free in the sense of already having cryptographic proofs; those are explicit C2/C3 deliverables.
