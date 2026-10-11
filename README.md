# 0PSP — Post-Quantum Private Spend Primitive

> Mathematics first. Blockchain only if the cryptography survives.

**Research status:** Phase 1 feasibility and falsification. Not production cryptography.  
**Security status:** No complete 0PSP construction or end-to-end security theorem has been established. Do not use this code to hold or transfer assets.

## Research question

Can a post-quantum private-spend protocol combine threshold-controlled authorization, hidden coin selection, deterministic asset-bound nullifiers, and practical proof costs under one explicit threat model?

This is a hypothesis, not a novelty claim. Related post-quantum ring signatures, threshold signatures, and linkable spend protocols already exist. The contribution must be demonstrated against those constructions, not inferred from a feature checklist.

## Current architecture under investigation

- Layer 1 candidate: a lattice-based hidden-selection and threshold-authorization relation inspired by structured threshold ring-signature work.
- Layer 2 candidate: a zero-knowledge proof that the public nullifier is correctly derived from the same hidden coin data.
- Cross-layer interface: a fresh bridge commitment, referenced by both proofs.

The bridge commitment, extended Layer 1 relation, and zero-knowledge Layer 2 proof are **not yet instantiated as one working, security-reviewed construction**. Existing LoTRS code is a research baseline, not a drop-in generic 0PSP proof system.

## Current status

| Area | Status |
|---|---|
| Literature and artifact review | Under revision; source and version discrepancies recorded |
| Canonical byte-to-polynomial encoding | Functional helper with unit tests; not a secure commitment |
| LoTRS-compatible extended lattice proof | Not implemented or demonstrated |
| Bridge commitment with proven hiding and binding | Not selected; open blocker |
| SHAKE nullifier computation | Deterministic function is testable; protocol unlinkability unproved |
| Layer 2 AIR / STARK | Mathematical design notes only; no compiled 0PSP STARK |
| Cross-layer composition | Conditional proof outline only; not an established theorem |
| Proof-size and runtime figures | Analytical projections only, not benchmarks |
| Production readiness | **NO-GO** |

## Critical distinctions

1. LoTRS uses two distinct moduli in its construction: the main modulus \(q=2^{43}-67\) and the binary-proof modulus \(\hat q=2^{35}-451\). They must not be collapsed into one generic ring parameter.
2. The current Python ring and bridge-encoding helpers use the ML-DSA-like modulus \(q=8{,}380{,}417\). They do not implement a LoTRS-compatible bridge commitment.
3. The proposed expression \(B=A_1m_x+A_2\tau_B\) is only an algebraic candidate. A hiding or binding theorem does not follow from that expression by naming Module-LWE or Module-SIS.
4. Plonky3 provides multiple proof backends with different zero-knowledge and soundness properties. A hiding polynomial commitment alone does not prove that the complete application transcript is zero knowledge.
5. Passing unit tests establishes only the tested behavior. It does not establish collision resistance, quantum security, zero knowledge, extractability, or anonymity.

The authoritative current status and exact unresolved obligations are recorded in the [Phase 1 consistency audit](docs/audit/phase1-consistency-audit.md) and [CHP3 research corrections](docs/audit/chp3-research-corrections.md).

## Run local functional checks

Python 3.11 or newer:

    python -m pip install -e ".[dev]"
    python scripts/verify_nullifier_relation.py
    python scripts/security_budget_evaluator.py
    python -m pytest tests/ -q

The security-budget script is a numeric consistency diagnostic only. Its success exit code is not a cryptographic security result. GitHub Actions runs the same functional checks; all cryptographic claims remain independently gated.

## Related primary sources

- LoTRS paper and implementation: https://eprint.iacr.org/2026/974 and https://github.com/lotrs-sig/lotrs
- LoTRS v2 artifact: https://zenodo.org/records/22807126
- NIST FIPS 202 (SHA-3 / SHAKE): https://csrc.nist.gov/pubs/fips/202/final
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- Plonky3 architecture and backend obligations: https://github.com/Plonky3/Plonky3/blob/main/docs/architecture.md
- Plonky3 binary proof and security configuration: https://github.com/Plonky3/Plonky3/blob/main/README.md
- BLAKE3 security notes: https://github.com/BLAKE3-team/BLAKE3/blob/master/c/README.md
- Ringtail: https://eprint.iacr.org/2024/1113
- Obscura-PQ: https://arxiv.org/abs/2608.22645

## License and usage

Research only. No production use until a concrete construction has undergone formal review, independent cryptanalysis, reproducible parameter estimation, and end-to-end implementation testing.
