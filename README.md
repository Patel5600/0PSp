# 0PSP — Post-Quantum Private Spend Primitive

> Mathematics first. A working prototype before a novelty claim. No production assets.

**CHP3 decision:** retire the uninstantiated LoTRS + separate STARK + bridge-commitment stack. V0 targets one zero-knowledge argument of knowledge for the complete spend relation.

## Constructionable V0

- **Threshold authorization:** Ringtail supplies an ordinary threshold signature under the selected coin's public key. V0 explicitly assumes its published dealer-based key generation unless DKG is added.
- **Single anonymous proof:** one generic ZK-STARK / signature-of-knowledge proves selected-coin membership, coin commitment opening, threshold-signature validity, and nullifier correctness with the same hidden witness. The nullifier itself supplies replay linkability; no extra LRS link tag is required by the protocol statement.
- **Concrete coin commitment candidate:** SHAKE256-384 over a domain-separated, length-prefixed encoding of the public key, value, coin ID, nullifier secret and fresh 36-byte commitment salt.
- **Nullifier:** SHAKE256-384 over a separate domain, version, 32-byte coin ID and 36-byte per-coin nullifier secret.
- **Ledger:** reject a nullifier already spent, atomically.
- **No bridge commitment:** all predicates are proven in one relation; there is no separate Layer 1/Layer 2 witness-matching step.

See [Constructionable V0](docs/theory/constructionable-v0.md) and [CHP3 construction pivot](docs/audit/chp3-construction-pivot.md).

## Exact target relation

Public statement: (x=(R_C,\nu,M,\mathsf{state},\mathsf{params\_id}))

Hidden witness: (w=(j,C_j,pk_j,v,coin\_id,r_{\mathrm{nf}},\rho_C,\sigma))

One proof must establish, for the same hidden j: selected-coin membership; the exact coin commitment opening; a valid Ringtail threshold signature under the same hidden key on transaction digest M; the nullifier equation; and eligible/unspent state. The selected index, opening and threshold signature remain hidden.

## Status

| Component | Status |
|---|---|
| SHAKE nullifier helper | Functional reference code and tests |
| SHAKE coin-commitment candidate | Functional helper and tests; QROM hiding/binding theorem not proved |
| Ringtail adapter | Not integrated |
| Single-relation ZK proof | Not instantiated |
| Complete ZK / quantum soundness | OPEN |
| End-to-end benchmark | Not measured |
| Production | **NO-GO** |

The architecture is staged for implementation; cryptographic blockers are not declared solved by documentation or smoke tests.

## Functional checks

    python -m pip install -e ".[dev]"
    python scripts/verify_nullifier_relation.py
    python scripts/security_budget_evaluator.py
    python scripts/audit_phase1_claims.py
    python -m pytest tests/ -q

These checks establish code behavior and arithmetic identities only, not cryptographic security.

## Research sources

- Ringtail paper and prototype: https://eprint.iacr.org/2024/1113 and https://github.com/daryakaviani/ringtail
- Generic post-quantum SoK/LRS research scaffold: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature
- LoTRS comparator: https://eprint.iacr.org/2026/974 and https://zenodo.org/records/22807126
- Obscura-PQ: https://arxiv.org/abs/2608.22645 and https://github.com/n-azimi/Obscura-PQ
- 2024 ID-based threshold linkable dual-ring signature: https://www.mdpi.com/2410-387X/8/4/48
- NIST FIPS 202: https://csrc.nist.gov/pubs/fips/202/final

Research only. No production use until the concrete relation, proof backend, security reductions, parameter estimates and independent review are complete.
