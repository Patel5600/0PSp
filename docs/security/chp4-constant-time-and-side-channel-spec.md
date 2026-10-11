# CHP4 — Constant-Time and Side-Channel Security Specification

**Status:** specification and release-gate proposal  
**Applies to:** 0PSP research implementation  
**Security claim:** none. This document does not assert that the current code is constant-time or side-channel resistant.  
**Production decision:** NO-GO until the construction and the implementation both satisfy their independent security gates.

## 1. Purpose and non-claims

CHP4 establishes a concrete implementation-security contract for any future component that processes 0PSP secrets. It does not implement a proof system, choose missing cryptographic constructions, or discharge Phase 1 cryptographic obligations.

The current repository contains research helpers and simulated encodings. Passing Python functional tests, arithmetic assertions, or CI is not evidence of constant-time execution. Python runtime behavior, the selected hash implementation, a compiler, and target hardware have not been assessed together.

The engineering objective is:

> For each declared secret-processing routine, keep observable execution behavior independent of secret values for fixed public inputs, within a documented platform and attacker model; then collect reproducible evidence for every supported build.

Do not claim “no side channels” without qualification. Side-channel resistance is a property of the deployed program, compiler output, dependencies, operating system, and hardware, not source code alone. This limitation is also explicit in the RustCrypto `subtle` documentation: https://docs.rs/subtle/latest/subtle/.

## 2. Assets and information classification

Every implementation interface must distinguish public inputs from secrets. Classification is part of the API contract, not a comment added after implementation.

| Asset | Classification | Requirements |
|---|---|---|
| Wallet/lattice secret keys and threshold shares | Secret | Never log, serialize to diagnostics, index memory with, or branch on |
| Coin opening, private witness and hidden-selection data | Secret | Prover execution must not expose witness-dependent traces beyond the declared public protocol output |
| Nullifier secret `r_nf` and private random coins | Secret | Fixed or explicitly public length; erase/reduce copies where practical; no secret-dependent control flow |
| Rejection-sampling state/noise | Sensitive secret-derived state | Analyze iteration counts and the sampler's exact distribution |
| Public parameters and public keys | Public, unless a protocol explicitly says otherwise | Public-driven branches are permitted only when classification is correct |
| Public statement, asset identifier, serialized public nullifier | Public protocol data | Canonical, domain-separated encoding; invalid encodings rejected deterministically |
| Error details, logs, metrics, crash output | Potential side channel | Must not reveal secret values, witness validity distinctions, or partial transcripts beyond the protocol contract |

A value derived from a secret remains secret unless a written proof or the protocol definition explicitly permits disclosure. “Hashed” does not mean “public.”

## 3. Threat model

### In-scope for the software constant-time target

1. **Remote timing observer:** can repeat protocol operations and measure response times.
2. **Local timing observer:** can measure a routine or exploit scheduling/interleaving to distinguish execution paths.
3. **Co-resident observer:** can attempt to infer secret-dependent cache, branch-predictor, or memory-access behavior on shared hardware.
4. **Operational observer:** can inspect logs, metrics, error classes, crash artifacts, allocations, file accesses, and partial outputs.

### Not covered by the constant-time claim alone

- Physical power or electromagnetic analysis.
- Fault injection, voltage/clock manipulation, invasive attacks, or device tampering.
- A compromised OS, hypervisor, firmware, compiler supply chain, or malicious hardware.
- Complete elimination of speculative-execution vulnerabilities for an entire process.
- Network-level metadata such as sender IP address, transaction timing, volume, and peer relationships.

Those need separate mitigations, testing, and assurance. A deployment that uses shared or untrusted hardware must document the residual risk rather than silently assuming isolation.

## 4. Constant-time contract

For any sensitive routine, hold all declared public inputs fixed and vary its secrets over the supported domain. The implementation must not expose secret-dependent differences in:

- branch/control-flow decisions or loop iteration counts;
- memory addresses, table indices, allocation sizes, or memory-access patterns;
- early exits, error categories, logging, I/O, or partial result publication;
- algorithm choice, operation count, or public-visible retry count;
- serialization length or formatting, unless that length is explicitly public by protocol design.

Randomized algorithms must be analyzed as distributions of observable traces. “Same average runtime” is not sufficient. The claim is limited to a specified compiler/build/architecture combination and the stated threat model.

Branches and loops on public values may be allowed after public/secret classification is reviewed. The code must not convert a secret predicate into an ordinary Boolean controlling execution. A secret-dependent conditional select is acceptable only when its implementation and generated machine code have been reviewed for the exact target.

## 5. Component requirements and current blockers

### 5.1 Lattice arithmetic and threshold authorization

Before implementation, select and document the exact construction and parameter set. Do not mix the LoTRS main modulus, LoTRS binary-proof modulus, and ML-DSA toy arithmetic.

Requirements:
- Use fixed public loop bounds and fixed-size buffers in secret paths wherever the selected construction permits.
- Ensure modular reduction, normalization, comparison, conditional negation, and sign handling do not introduce secret-dependent branches or memory accesses.
- No secret-indexed lookup tables. Public-indexed twiddle tables are allowed only if indexing is exclusively public and memory behaviour is fixed.
- Specify coefficient ranges and canonical encodings mathematically before selecting a codec.
- Use a vetted sampler with a documented distribution and implementation analysis. Rejection sampling can have variable iteration counts; do not replace it with clipping, truncation, or a constant-iteration approximation unless the resulting distribution and security argument are proved acceptable.
- Define threshold-share handling, zeroization limits, share-combination errors, and fault behaviour.

**Current status:** no complete 0PSP threshold/lattice relation has been implemented or demonstrated; constant-time status is unassessed.

### 5.2 Nullifier and transcript hashing

- Use a domain-separated, length-unambiguous canonical encoding for all inputs.
- Require fixed or protocol-public lengths on secret-processing paths.
- Avoid early-exit equality comparisons over secrets or secret-derived tags.
- Document the selected SHAKE256 implementation, OpenSSL provider/backend and supported build targets; do not infer implementation security from the algorithm name.
- Separate functional determinism from collision resistance, unlinkability, and timing security.

**Current implementation checkpoint:** `native/nullifier_v1.c` calls OpenSSL EVP SHAKE256 using fixed public lengths for the 32-byte coin ID, 36-byte nullifier secret and 48-byte output. It also obtains 36-byte secret material from OpenSSL `RAND_bytes`. The wrapper has no source-level branch or memory index controlled by the secret bytes; its checks and error branches use public pointer/length metadata or API status. On error, its fixed-size output buffer is cleared.

This is a component-level source observation, not a constant-time claim. The Python reference and `ctypes` path are not the production timing-security boundary. CI emits optimized wrapper disassembly, but OpenSSL internals, generated code, hardware behavior, FFI, secret lifetimes and the full prover path have not been independently reviewed. A small custom timing probe exists for preliminary debugging only; it is not a reviewed statistical release test and is not run as a security gate.

### 5.3 Layer 2 prover and AIR

- The full witness-to-trace path is sensitive, not just the hash permutation.
- Trace construction, field conversions, lookup arguments, memory access, witness validation, proving, transcript operations, and error paths all need a secret-flow review.
- Public proof size and protocol-defined public output may be disclosed; hidden witness values or unintended witness-dependent metadata may not.
- A zero-knowledge proof system does not automatically make the prover implementation side-channel resistant.
- No AIR may be treated as validated until bit/limb/range constraints, canonical top limbs, terminal carries, residual bounds, and field-wraparound prevention are fully specified and tested.

**Current status:** design notes only; no compiled end-to-end 0PSP AIR. Constant-time analysis cannot be completed yet.

### 5.4 Memory and failures

- Minimize secret copies and lifetime; avoid implicit secret formatting/debugging and secret-bearing panic messages.
- Use an explicitly reviewed zeroization strategy and test the generated code. Do not promise that zeroization defeats swap, crash dumps, register copies, allocator copies, or an attacker-controlled OS.
- Do not emit partial proof/transcript material before all protocol checks that must precede publication have succeeded.
- Externally visible failure behaviour must follow the protocol contract and must not become a secret-validity oracle.
- Allocator choice, locking, page faults, and process isolation must be recorded for deployment targets.

## 6. Rust implementation rules

Rust is a reasonable implementation language, but Rust does not guarantee constant-time execution.

1. Prefer audited implementations for established primitives. Do not invent a new hash, sampler, lattice primitive, or low-level constant-time abstraction merely to avoid dependencies.
2. Review each dependency version, enabled feature, backend, build flag, and target. Pin and reproduce the dependency graph for release evidence.
3. Keep secret-bearing types distinct from public types. Do not implement casual `Debug`, `Display`, or general-purpose serialization for secret types.
4. Treat conversions from constant-time predicates to `bool`, branching, indexing, variable-time comparison, and early return as security-review events.
5. Review optimized release machine code for supported target triples. Debug-build behaviour is not release evidence.
6. Use explicit public/secret comments backed by code review; comments alone are not taint tracking or proof.
7. Keep unsafe code narrowly scoped, justified, tested, and audited. Avoid exposing raw secret buffers across module boundaries.
8. Any assembly, SIMD, or architecture-specific backend is a separate security target and requires separate binary and leakage evidence.

The RustCrypto `subtle` crate supplies constant-time-oriented primitives such as `Choice` and conditional selection, but its documentation calls the approach best-effort and notes compiler/hardware limitations. It can be evaluated for suitable operations, not treated as a project-wide security guarantee: https://docs.rs/subtle/latest/subtle/ and https://github.com/dalek-cryptography/subtle.

## 7. Required validation evidence

No single test establishes absence of side channels. Release evidence must combine independent methods.

### Gate A — source and dependency review
- Complete secret/public data-flow inventory for every sensitive routine.
- Review of all secret-dependent branches, loop bounds, indices, reductions, retries, allocations, errors, and debug paths.
- Dependency provenance, version, feature flags, target and build configuration recorded.
- Explicitly documented exceptions, residual risks, and owner for each open issue.

### Gate B — generated code
- Release assembly or disassembly collected for every supported target/compiler/build profile.
- Review of conditional branches, loads/stores, addresses, calls, and operation counts in the secret-processing paths.
- Build configuration and artifacts reproducible from recorded inputs.
- Repeat inspection after compiler, dependency, feature, or target changes.

### Gate C — timing leakage testing
- Use a statistical timing test harness such as dudect or a reviewed equivalent with documented input classes and public-input controls.
- Measure multiple secret classes chosen to expose suspected leaks; document sample counts, test environment, CPU state, compiler flags, and results.
- Run repeated tests on each supported target. A detected statistical difference is a blocker pending explanation.
- A clean result is evidence only for those experiments; it is not proof of constant-time execution.

Reference: dudect explicitly describes its method as timing-leakage detection, not a formal proof, and warns that compiler versions, flags, architecture and microcode affect the result: https://github.com/oreparaz/dudect.

### Gate D — protocol and operations
- Verify no witness-dependent transcript, proof-size, log, error or retry leakage beyond the documented public outputs.
- Test malformed inputs, invalid witnesses, sampler edge cases, process crashes, partial output, and cleanup paths.
- Review concurrency and shared-resource assumptions.
- Obtain independent cryptographic and implementation-security review before any production security claim.

## 8. Release gates

| Gate | Required evidence | Current state |
|---|---|---|
| Concrete cryptographic construction | Complete specification and applicable proof obligations | V0 is a staged target; proof backend and reductions OPEN |
| Secret/public classification | Reviewed asset and data-flow inventory | NOT STARTED |
| Constant-time source review | All sensitive routines reviewed | PARTIAL: native wrapper only; full path OPEN |
| Binary review | Release disassembly per supported target | CI artifact produced for the wrapper; review OPEN |
| Statistical timing evaluation | Reproducible per-target leakage tests | NOT STARTED; custom probe is non-gating only |
| Memory/failure handling | Secret lifetime, error and crash analysis | NOT STARTED |
| End-to-end zero knowledge and soundness | Fully constrained AIR/backend and security arguments | OPEN |
| Independent audit | Findings tracked and blockers resolved | NOT STARTED |

**No-go invariant:** a successful CI run, passing arithmetic tests, or a clean timing experiment never closes an unproven cryptographic construction gate. Do not label 0PSP constant-time, side-channel-free, zero-knowledge, quantum-secure, or production-ready until the applicable evidence exists.

## 9. Execution order

1. Finish the protocol construction and parameter-domain decisions; keep security claims open.
2. Establish the secret/public classification and threat model.
3. Select concrete primitives and sampler implementations with documented properties.
4. Implement one isolated secret-processing component at a time with functional reference tests.
5. Review release machine code and run timing leakage tests for each supported target.
6. Integrate the complete proof system only after component invariants are stable.
7. Run end-to-end security review and independent cryptanalysis before a production go decision.

## 10. References

- RustCrypto `subtle` constant-time-oriented primitives and limitations: https://docs.rs/subtle/latest/subtle/
- `subtle` source and design notes: https://github.com/dalek-cryptography/subtle
- dudect statistical timing-leakage testing: https://github.com/oreparaz/dudect
- NIST FIPS 202 (SHA-3/SHAKE specification): https://csrc.nist.gov/pubs/fips/202/final
- 0PSP Phase 1 consistency audit: https://github.com/Patel5600/PSp/blob/main/docs/audit/phase1-consistency-audit.md
- CHP3 mathematical consistency review: https://github.com/Patel5600/PSp/blob/main/docs/audit/chp3-mathematical-review.md
