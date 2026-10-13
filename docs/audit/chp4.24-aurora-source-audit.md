# CHp4.24 — Aurora/libiop source-level integration gate

**Scope:** source/documentation triage only; this is not an implementation, cryptographic proof, or completed internal security audit.  
**0PSP release:** **NO-GO**.  
**Aurora/libiop candidate:** **NO-GO pending isolated executable evidence and parameter review**.  
**External cryptographic audit:** **NOT PERFORMED**.

## Pinned source examined

- Repository: https://github.com/scipr-lab/libiop
- Revision: `a2ed2ec2f3e85f29b6035951553b02cb737c817a`
- README at that immutable revision: https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/README.md
- README blob SHA returned by GitHub: `7679a6177bc1d4958abb8d52098590997d1a2a07`

This revision is pinned for investigation only. It is not approved as a dependency.

## Findings established from the pinned upstream README

1. The project describes itself as a C++ library implementing Ligero, Aurora, and Fractal constructions. Its README explicitly calls the code an academic proof-of-concept prototype, says it has not received careful code review, and says it is **not ready for production use**.
2. The README states that the constructions support R1CS over smooth prime fields and binary extension fields. This is enough to justify investigating characteristic-two arithmetization, but it does not prove that the exact selected Aurora configuration works with the 0PSP circuit or has acceptable resource use.
3. The README says the BCS transformation is post-quantum in the quantum random oracle model and preserves zero knowledge only when the underlying IOP is zero knowledge. These are construction-level descriptions, not a security assessment of this pinned implementation/configuration.
4. The README exposes a `make_zk` option: setting it indicates that the transformation should preserve zero knowledge. The production harness must prove that this flag reaches the actual intended protocol path and that all masking/degree-bound requirements are met. A CLI flag alone is not evidence of a correct ZK implementation.
5. The README's example profiling commands use a 181-bit prime field. Those examples do not establish binary-extension-field behavior, QROM security, or feasibility for the 0PSP SHAKE256-384 relation.
6. The README provides profiling tools for timing and argument-size traces, but the documented traces are single-threaded. No performance conclusion about the 0PSP target can be inferred without measurements on the pinned binary-field configuration and target machine.

## Security boundary

The protocol's use of SHAKE256 does not automatically secure the proof transcript. The proof system's transcript hash, query parameters, field choice, FRI parameters, masking, and QROM security calculation must be pinned and analyzed together. Do not accept default transcript hashes or heuristic security settings without a concrete calculation.

The recent analysis *A note on adding zero-knowledge to STARKs* (IACR ePrint 2024/1037) specifically discusses pitfalls in zero-knowledge for small-field STARKs, including polynomial randomization and quotient decomposition. This is a mandatory review input, not evidence that Aurora/libiop is vulnerable: https://eprint.iacr.org/2024/1037.

## Required executable work, in serial order

### 1. Dependency and build closure

- Fetch the pinned revision into an isolated worktree.
- Record all submodules, transitive dependencies, compiler and linker versions, flags, build options, and license notices.
- Produce a reproducible clean build and run upstream tests.
- Verify the build actually uses the intended Aurora SNARK path, binary extension field, and zero-knowledge mode.
- Archive the exact commands, logs, source hashes, and environment.

**Gate: NO-GO** until the clean build and tests pass on the exact pinned source.

### 2. Trace the zero-knowledge configuration through code

Trace the `make_zk` parameter from CLI/test entry point through BCS, Aurora, polynomial commitments, masking, and verifier reconstruction. Record every default and every place where a caller can omit or override it. Identify the exact implementation of transcript hashing and Fiat-Shamir challenge derivation. Review random sampling, domain separation, field encodings, and failure behavior.

Compare the implemented masking and degree-bound argument against ePrint 2024/1037 and the relevant Aurora/BCS proof arguments. This must be a code-path review, not a README-only conclusion.

**Gate: NO-GO** if any proof path can silently run without required masking, if verifier/prover settings can disagree, or if the concrete soundness/privacy argument cannot be established.

### 3. Tiny real proof vertical slice

Construct one minimal binary-field R1CS statement and prove/verify it through the actual pinned Aurora SNARK with ZK explicitly enabled. The statement must bind the witness and public input in the relation itself.

Required negative tests include: incorrect witness, altered public input, altered digest, malformed proof bytes, truncated proof, wrong field/parameter configuration, non-Boolean source bits, mutated SHAKE padding/domain bytes, and mismatched prover/verifier settings. Preserve the failing cases as regression tests.

**Gate: NO-GO** until correct statements verify and every invalid mutation is rejected on the exact pinned build. Passing these tests does not establish soundness or zero knowledge by itself.

### 4. Security parameter worksheet

Before scaling, freeze and independently recalculate:

- binary extension field polynomial and field size;
- FRI domain/expansion and query parameters;
- soundness error and union bounds across all checks;
- transcript hash, digest size, domain separation, and quantum random-oracle assumptions;
- ZK masking parameters and degree bounds;
- proof-of-knowledge assumptions and all required reductions;
- concrete security under the stated quantum adversary model.

Document the derivation and executable parameter checks. Do not describe a nominal field bit size as the proof system's security level.

**Gate: NO-GO** until the calculation is complete, reproducible, and consistent with the pinned implementation.

### 5. Actual 0PSP relation scaling

Proceed only after the previous gates pass:

1. one real SHAKE256-384 preimage;
2. complete NullifierV2;
3. CommitV2 opening;
4. depth-63 namespace-bound Merkle membership;
5. canonical TxFieldsV2/TxDigestV2 binding;
6. range-safe value conservation and output-opening consistency;
7. the selected authorization predicate;
8. the complete shared-witness relation.

At each stage record real constraint counts, peak RSS, prover wall/CPU time, verifier time, proof bytes, and all parameters. Use clean cold runs and repeated measurements. Compare measured data with CHp4.21/CHp4.23 estimates, explaining every discrepancy. Do not extrapolate a tiny hash demo into a full-relation GO.

**Gate: NO-GO** until the full relation is instantiated, measured within the declared deployment envelope, and passes adversarial substitution tests.

## Current binary decisions

| Gate | Status | Evidence/condition |
|---|---|---|
| Pinned upstream README/source identity | **GO for source identification only** | Immutable repository revision and README blob recorded |
| Reproducible clean build | **NO-GO** | Not run in this environment |
| Binary-field Aurora R1CS | **NO-GO** | Upstream says supported; exact pinned configuration not exercised |
| Zero-knowledge code-path review | **NO-GO** | `make_zk` documented; implementation trace and masking review not performed |
| Concrete quantum security | **NO-GO** | No completed parameter worksheet |
| Tiny proof and adversarial tests | **NO-GO** | No executable harness evidence yet |
| Full 0PSP relation and benchmarks | **NO-GO** | No instantiated relation or measurements |
| Complete 0PSP production release | **NO-GO** | Multiple mandatory cryptographic and custody gates remain open |
| External cryptographic audit | **NOT PERFORMED** | No external audit claimed |

## Decision

Aurora/libiop remains a feasibility candidate, not a production selection. This checkpoint advances the evidence plan by narrowing the required source-level and executable work; it does not change any production gate to GO. If the pinned code cannot support a concrete, post-quantum, zero-knowledge configuration for the exact relation, reject it and return to backend selection without weakening 0PSP's security requirements.
