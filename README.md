# 0PSP — Post-Quantum Private Spend Primitive

> Mathematics first. A working prototype before a novelty claim. No production assets.

**CHP3 decision:** retire the uninstantiated LoTRS + separate STARK + bridge-commitment stack. V0 targets one zero-knowledge argument of knowledge for the complete spend relation.

## Constructionable V0

- **Threshold authorization:** Ringtail supplies an ordinary threshold signature under the selected coin's public key. V0 explicitly assumes its published dealer-based key generation unless DKG is added.
- **Single anonymous proof (target):** one proof-of-knowledge / signature-of-knowledge relation is intended to establish selected-coin membership, coin commitment opening, threshold-signature validity, and nullifier correctness with the same hidden witness. The concrete backend is not yet selected or integrated. The nullifier itself supplies replay linkability; no extra LRS link tag is required by the protocol statement.
- **Concrete coin commitment candidate:** SHAKE256-384 over a domain-separated, length-prefixed encoding of the public key, value, coin ID, nullifier secret and fresh 36-byte commitment salt.
- **Nullifier:** SHAKE256-384 over a separate domain, version, 32-byte coin ID and 36-byte per-coin nullifier secret.
- **Ledger:** reject a nullifier already spent, atomically.
- **No bridge commitment:** all predicates are proven in one relation; there is no separate Layer 1/Layer 2 witness-matching step.

See [Constructionable V0](docs/theory/constructionable-v0.md), [CHP3 construction pivot](docs/audit/chp3-construction-pivot.md), and the [CHP4 construction-readiness record](docs/security/chp4-construction-readiness.md).

## Exact target relation

Public statement: (x=(R_C,\nu,M,\mathsf{state},\mathsf{params\_id}))

Hidden witness: (w=(j,C_j,pk_j,v,coin\_id,r_{\mathrm{nf}},\rho_C,\sigma))

One proof must establish, for the same hidden j: selected-coin membership; the exact coin commitment opening; a valid Ringtail threshold signature under the same hidden key on transaction digest M; the nullifier equation; and eligible/unspent state. The selected index, opening and threshold signature remain hidden.

## Status

| Component | Status |
|---|---|
| SHAKE nullifier helper | Python reference, 36-byte secret, 48-byte output, native OpenSSL implementation candidate and fixed known-answer tests |
| SHAKE coin-commitment candidate | Functional helper and tests; QROM hiding/binding theorem not proved |
| Ringtail adapter | Not integrated |
| Single-relation ZK proof | Not instantiated |
| Complete ZK / quantum soundness | OPEN |
| End-to-end benchmark | Not measured |
| Production | **NO-GO** |

The constructionable V0 target is active, but the single-relation proof backend, security reductions, complete zero knowledge and independent cryptanalysis remain OPEN. The native nullifier is the first fixed-width secret-processing component, not a completed protocol.

## Functional and native checks

Python 3.11+, a C compiler, OpenSSL development headers and binutils are required for the native component:

    python -m pip install -e ".[dev]"
    make -C native test
    make -C native audit
    export PSP_NULLIFIER_LIBRARY="$PWD/native/build/libpsp_nullifier.so"
    python scripts/verify_nullifier_relation.py
    python scripts/security_budget_evaluator.py
    python scripts/audit_phase1_claims.py
    python -m pytest tests/ -q

The security-budget and carry arithmetic scripts are retained as **historical CHP3 diagnostics** for the retired split-layer proposal; their successful exit status does not evaluate V0 security or proof cost.

The nullifier input contains no separate chain/asset field, so `coin_id` must be minted and validated within one canonical ledger/deployment-and-asset namespace; this minting invariant remains an open full-construction gate. The fixed nullifier preimage is 99 bytes: `DOMAIN_NULLIFIER[26] || version[1] || uint16_le(32) || coin_id[32] || uint16_le(36) || r_nf[36]`; SHAKE256 returns 48 bytes. `r_nf` is a per-coin secret generated through OpenSSL `RAND_bytes` by the native helper and is distinct from the commitment salt. `make -C native timing` runs a preliminary local probe only; it is not dudect and is not a release gate.

The Python function is a reference, not a constant-time path. CI compiles the native C wrapper with warnings as errors, checks known-answer vectors, captures its optimized wrapper disassembly and runs reference/native agreement tests. Neither the wrapper artifact nor timing probe establishes constant-time execution, and full protocol production status stays NO-GO.

## Research sources

- [Versioned upstream source manifest and evidence boundaries](docs/related-work/upstream-source-manifest.md)
- [Constructionable V0](docs/theory/constructionable-v0.md)
- [Nullifier v1 component contract](docs/theory/nullifier-v1-construction.md)
- [Constant-time and side-channel release gates](docs/security/chp4-constant-time-and-side-channel-spec.md)

- Ringtail paper and prototype: https://eprint.iacr.org/2024/1113 and https://github.com/daryakaviani/ringtail
- Generic post-quantum SoK/LRS research scaffold: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature
- LoTRS comparator: https://eprint.iacr.org/2026/974 and https://zenodo.org/records/22807126
- Obscura-PQ: https://arxiv.org/abs/2608.22645 and https://github.com/n-azimi/Obscura-PQ
- 2024 ID-based threshold linkable dual-ring signature: https://www.mdpi.com/2410-387X/8/4/48
- NIST FIPS 202: https://csrc.nist.gov/pubs/fips/202/final

Research only. No production use until the concrete relation, proof backend, security reductions, parameter estimates and independent review are complete.
