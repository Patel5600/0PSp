# CHp4.24 — Aurora/libiop source-level integration gate

**Scope:** pinned-source audit and documentation triage only; no local compilation or execution was performed. This is not a complete internal security audit.
**0PSP release:** **NO-GO**.
**Aurora/libiop candidate:** **NO-GO**.
**External cryptographic audit:** **NOT PERFORMED**.

## Pinned source examined

- Repository: https://github.com/scipr-lab/libiop
- Revision: `a2ed2ec2f3e85f29b6035951553b02cb737c817a`
- README blob SHA: `7679a6177bc1d4958abb8d52098590997d1a2a07`
- Aurora test blob SHA: `cc39a42d8bd9b1518d692375c65ae5311e60ec19`
- Transcript serializer blob SHA: `a17a51d5d3ca5e025012351fc31068cc6f9ba8ce`
- BCS hash-type declarations blob SHA: `29473a1cd4e3f39fb6de82040ed5a35365738aa8`

This revision is pinned for investigation only. It is not approved as a dependency.

## New source findings

### F1. Native transcript serialization is explicitly unimplemented for the binary-field/hash pairing used by the Aurora binary-field test

The pinned source defines `binary_hash_digest` as `std::string` in `libiop/bcs/hashing/hashing.hpp`. The Aurora test in `libiop/tests/snark/test_aurora_snark.cpp` uses `FieldT = libff::gf64` and `hash_type = binary_hash_digest`.

In `libiop/bcs/bcs_common.tcc`, the transcript serializer/deserializer overload for a non-multiplicative field whose Merkle-root hash type differs from the field type prints:

- `Serializing on binary fields or non-algebraic hashes is not implemented`
- `Deserializing on binary fields or non-algebraic hashes is not implemented`

Both functions then return the stream without encoding or decoding the transcript fields. The public `serialize()` and `deserialize()` methods dispatch to these functions. See the immutable source range: https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/bcs/bcs_common.tcc#L359-L389.

**Impact:** the native proof-transcript transport/round-trip path is unusable for the binary-field plus `binary_hash_digest` configuration exercised by the upstream Aurora test. In-memory proof generation and verification do not remedy this. No custom alternative proof wire format was established in the source reviewed here.

**Gate: NO-GO** until a canonical, bounded, versioned serializer/deserializer is implemented for this pairing and round-trip tests verify that it preserves the transcript and rejects truncation, trailing bytes, oversized lengths, malformed elements, and malformed Merkle paths. The encoding must be unambiguous and must not rely on assertions for hostile input.

### F2. Existing Aurora SNARK test is a smoke test, not a concrete post-quantum or adversarial-security demonstration

The pinned `test_aurora_snark.cpp` constructs an R1CS example with 8,192 constraints and 8,191 variables, selects `gf64`, requests a nominal security parameter of 128, sets LDT reducer soundness to `optimistic_heuristic` and FRI soundness to `heuristic`, and tests both `make_zk=false` and `make_zk=true`. It then checks that the generated proof verifies. It does not serialize the proof, mutate the witness/public input/proof, or establish a concrete quantum security bound. Immutable source: https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/tests/snark/test_aurora_snark.cpp.

The adjacent `test_serialization.cpp` exercises transcript serialization using `alt_bn128_Fr` as both the field and hash type, with `make_zk=false`; it therefore does not cover the binary-field plus non-algebraic-hash pairing above. Immutable source: https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/tests/snark/test_serialization.cpp.

**Impact:** upstream test names and passing assumptions cannot be treated as proof of 0PSP-compatible serialization, complete ZK privacy, soundness under quantum adversaries, or application-level relation soundness.

**Gate: NO-GO** pending a real build, binary-field/ZK proof round-trip tests, adversarial negative tests, and a separately derived concrete security worksheet.

### F3. The `make_zk` flag has a visible path into protocol parameters and Merkle leaf masking, but that is not a complete ZK proof

In the pinned source, `aurora_snark_parameters` passes `make_zk` to `aurora_iop_parameters`; the latter adjusts systematic dimensions and configures degree/LDT/FRI parameters. BCS constructs a ZK Merkle tree when at least one oracle in the tree is registered as ZK, and `merkle_tree.tcc` samples per-leaf randomness and calls the ZK leaf-hash path.

Relevant immutable sources:

- https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/snark/aurora_snark.tcc
- https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/protocols/aurora_iop.tcc
- https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/bcs/bcs_common.tcc
- https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/bcs/merkle_tree.tcc

This establishes partial control-flow tracing only. It does **not** establish that all oracle masking, degree bounds, transcript challenge derivation, serialization, or verifier checks meet a concrete zero-knowledge proof. The library's README itself calls the code an academic proof-of-concept, says it has not received careful code review, and explicitly says it is not ready for production: https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/README.md.

**Gate: NO-GO** until the entire prover/verifier path and parameters are reviewed against the applicable proof arguments and tested.

## Previously established upstream facts

1. The README claims support for R1CS over smooth prime and binary extension fields. This does not prove that the target 0PSP relation is practical, complete, secure, or serializable under the selected binary-field/hash configuration.
2. The README describes the BCS transformation as post-quantum in the quantum random oracle model and says zero knowledge is preserved only when the underlying IOP is zero knowledge. These are construction-level statements, not a concrete security analysis of this implementation/configuration.
3. The README's shown profiling command uses `--field_size=181` and a prime-field configuration, so the documented example does not establish binary-field feasibility for 0PSP.
4. `test_aurora_snark` is an in-memory proof/verification test with heuristic soundness settings, not an adversarial integration harness.
5. The current evidence does not identify a production-ready accepted backend.

The analysis *A note on adding zero-knowledge to STARKs* (IACR ePrint 2024/1037) is a required review input for small-field ZK masking and degree-bound pitfalls. It is not evidence by itself that this pinned Aurora implementation is exploitable: https://eprint.iacr.org/2024/1037.

## Required executable work, serial order

### 1. Dependency and build closure

- Fetch the pinned revision into an isolated worktree.
- Record submodules, transitive dependencies, compiler/linker versions, build options, flags, and license notices.
- Produce a reproducible clean build and run upstream tests.
- Preserve exact commands, logs, source hashes, and environment.

**Gate: NO-GO** until build and test results are produced from the pinned source.

### 2. Fix and test proof-transcript serialization

- Implement a canonical binary-field/non-algebraic-hash transcript wire format, or document and review a supported alternative.
- Use bounded lengths and checked arithmetic; reject malformed field encodings, invalid tree paths, truncation, extra trailing bytes, and oversized allocation requests.
- Add round-trip tests for ZK and non-ZK transcripts, including the exact `gf64 + binary_hash_digest` pairing, followed by verifier acceptance.
- Add fuzz/property tests and mutated/transposed/truncated transcript rejection tests.

**Gate: NO-GO** until the binary-field ZK proof can be serialized, transported, deserialized, and correctly verified.

### 3. Trace the complete zero-knowledge path

Trace `make_zk` from caller entry point through oracle registration, BCS, Merkle masking, degree bounds, LDT/FRI, transcript generation, and verifier reconstruction. Record every default and override. Review randomness, domain separation, field encodings, challenge derivation, and failure behavior against the published proof arguments and ePrint 2024/1037.

**Gate: NO-GO** if required masking can be bypassed, prover/verifier parameters can disagree, or the privacy argument cannot be established.

### 4. Tiny proof vertical slice and adversarial tests

Construct a minimal binary-field R1CS statement and prove/verify it with ZK enabled through the exact pinned build. Bind the witness and public inputs inside the relation. Test incorrect witness, changed public input, altered digest, malformed/truncated proof bytes, wrong field/parameters, non-Boolean input bits, altered SHAKE padding/domain bytes, and prover/verifier parameter mismatch. Preserve every negative case as a regression test.

**Gate: NO-GO** until correct proofs verify and every invalid mutation is rejected. Passing tests alone does not establish cryptographic soundness or zero knowledge.

### 5. Concrete post-quantum security worksheet

Freeze and independently recalculate the binary extension field and polynomial, FRI domains/expansion/query parameters, combined soundness bounds, transcript hash and digest size, domain separation, QROM assumptions, ZK masking and degree bounds, proof-of-knowledge assumptions, and concrete security under the stated quantum adversary model. Include reproducible parameter-checking code. Do not equate the nominal `security_parameter` or field bit size with the achieved quantum security level.

**Gate: NO-GO** until the derivation is complete, reproducible, and consistent with the implementation.

### 6. Full 0PSP relation and measured feasibility

Proceed only after the preceding gates pass. Instantiate and bind, in one witness/relation:

1. SHAKE256-384 preimage;
2. complete NullifierV2;
3. CommitV2 opening;
4. depth-63 namespace-bound Merkle membership;
5. canonical TxFieldsV2/TxDigestV2 binding;
6. range-safe value conservation and output-opening consistency;
7. the chosen authorization predicate.

Measure real constraint counts, peak RSS, prover wall/CPU time, verifier time, proof bytes, and all parameters over repeatable cold runs. Compare with CHp4.21/CHp4.23 models and explain discrepancies. Tiny examples do not clear the full relation.

**Gate: NO-GO** until the complete relation is instantiated, measured in the declared deployment envelope, and passes adversarial substitution tests.

## Current binary decisions

| Gate | Status | Evidence/condition |
|---|---|---|
| Binary-field circuit-shape estimate | **GO for deterministic model logic only** | Does not constitute an executable circuit or proof |
| SmallWood Python adapter at evaluated scaling target | **NO-GO** | Evaluated representation has unacceptable memory scaling |
| Aurora source identity and partial configuration trace | **GO for source identification/partial trace only** | Immutable revision and code path located |
| Aurora native proof serialization for binary field + binary hash | **NO-GO** | Pinned serializer/deserializer explicitly unimplemented for this pairing |
| Reproducible Aurora build | **NO-GO** | Not built in this environment |
| Binary-field ZK proof with transport round-trip | **NO-GO** | No executable end-to-end evidence |
| Concrete post-quantum security | **NO-GO** | Heuristic test modes; no completed independent parameter worksheet |
| Complete shared-witness spend proof | **NO-GO** | No instantiated full relation |
| Trusted deposit, authorization, and production composition | **NO-GO** | Application/custody gates unresolved |
| Complete 0PSP production release | **NO-GO** | Mandatory cryptographic and operational gates remain open |
| External cryptographic audit | **NOT PERFORMED** | No external audit claimed |

## Decision

The newly identified serialization gap is an implementation-level blocker, not merely a missing benchmark. Aurora/libiop stays a feasibility candidate and must not be selected for production until the binary-field proof transport path is fixed and tested, the exact ZK and quantum-security claims are established, and the full shared-witness relation is instantiated. If any condition fails, reject the candidate rather than weakening 0PSP's requirements.

No local build, proof run, or external audit is claimed in this checkpoint.
