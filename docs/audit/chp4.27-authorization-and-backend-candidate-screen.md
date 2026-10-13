# CHp4.27 — Authorization and proof-backend candidate screen

**Status:** candidate screen only; authorization and proof backend remain **NO-GO**.  
**Reviewed:** 2026-10-13.  
**Scope:** choose the next falsifiable experiment, not a production primitive by paperwork.

## 1. Decision

Do not freeze a V3 authorization scheme or approve a production proof backend yet. The nearest available evidence rules out two tempting shortcuts:

- **Ringtail reference implementation:** its public Go repository explicitly says it is an academic proof-of-concept, has not received careful code review, and is not ready for production. The scheme is a plausible threshold-signature research candidate, but its existence is not a reviewed implementation or a complete 0PSP authorization path.
- **LoTRS implementation:** its 2026 artifact includes Python and Rust implementations, reproducible interoperability tests and parameter-estimation scripts, which is stronger reproducibility evidence. But its own README reports a production-profile estimate of **100.7978 bits** for one listed post-quantum ASIS variant, with other variants materially lower. Those figures do not substantiate the project's stated 128-bit post-quantum target. LoTRS is also a **structured** threshold ring signature, where signers form a hidden column in a table, not a generic drop-in replacement for Ringtail or an arbitrary wallet policy.

The correct decision is **no scheme selected** until the policy model, security target, relation integration, parameters and verifier cost are evaluated together.

## 2. Evidence and limitations

### Ringtail

Public implementation: https://github.com/daryakaviani/ringtail  
Paper: https://eprint.iacr.org/2024/1113

The implementation's README warns that the code is an academic proof of concept, has not received careful code review and is not production-ready. Its documented implementation is Go; the main path is full-threshold, with a separate configurable threshold mode. That does not by itself establish that a particular instantiation, key-generation/dealer model, encoding, nonce lifecycle or verifier is appropriate for this protocol.

**Decision:** retain as research prior art only. Do not copy or wrap the proof-of-concept into the production trust boundary.

### LoTRS

Artifact: https://github.com/lotrs-sig/lotrs  
Paper: https://eprint.iacr.org/2026/974 (IACR ePrint 2026/974)

The artifact README states that it includes Python/Rust implementations, parameter-estimation scripts, deterministic interoperability tests and a benchmark harness. For its `N=100,T=50` production profile, it reports:
- analytic signature estimate: 52.6574 KiB;
- measured Rice-encoded signature: 53.53 KiB;
- ring public-key table estimate: 47,031.25 KiB;
- binary-proof PQ ASIS cost, variant 0: 100.7978 bits;
- other published ASIS variants and the listed DualMS estimate are lower.

The README itself warns that the attack-cost figures do **not** substantiate 128-bit post-quantum security. Also, this scheme's structured hidden-column semantics must match the intended participant/key-table model; that correspondence has not been shown for 0PSP. Raw artifact reproducibility does not equal an independent implementation audit or 0PSP composition proof.

**Decision:** useful comparison baseline, not an approved authorization scheme for the current target.

### OpenVM 2.0 as a proof-backend candidate

Pinned upstream release used by the partial research guest: https://github.com/openvm-org/openvm/tree/v2.0.2  
Official release announcement: https://blog.openvm.dev/2.0-production  
Official application and proof CLI documentation: https://docs.openvm.dev/book/writing-apps/verifying-proofs/

OpenVM's July 2026 release announcement reports an external zkSecurity audit for v2.0.0, formal-verification coverage for core extensions, and **100 bits** of provable post-quantum security in its stated profile. The existing 0PSP branch pins OpenVM v2.0.2 and has passed a guest-build CI run for a **partial NOAUTH** relation. That is concrete progress for evaluating a maintained Rust zkVM, but it is not end-to-end 0PSP proof evidence, does not establish 128-bit PQ security, and does not close authorization.

The OpenVM CLI distinguishes application-level, aggregated STARK and EVM proof paths. Under a post-quantum requirement, assess the exact STARK configuration first. Do not assume the EVM/Halo2 wrapping path inherits the STARK path's post-quantum claim; its verifier and setup assumptions require a separate security argument.

**Decision:** OpenVM 2.0 is now a concrete feasibility candidate worth testing against the actual relation, but its reported 100-bit profile is below the current 128-bit research target. Do not silently lower that target. The experiment must show whether a documented configuration meets the required security target without trading away witness hiding, soundness, transparency, or reproducibility.

## 3. The next experiment

Use immutable sources and one explicit security profile. No broad production refactor should begin before this short feasibility spike passes.

1. Check in the generated Cargo lockfile for the existing OpenVM guest and record the exact OpenVM, Rust toolchain, extension and dependency graph versions.
2. Generate and verify an actual **application/STARK proof**, not just a guest build. Use a deterministic valid fixture and demonstrate that mutations to the public digest, witness, domain/padding, root or membership path cause proving or verification to fail.
3. Create isolated benchmark guests for the actual V3 components: SHAKE256-384 commitment, recipient key-commitment opening, HMAC-SHA3-384 NullifierV3, and anchored output derivation. Use the same backend configuration and public-input model.
4. Measure prover wall time, verifier wall time, peak resident memory, execution/trace size, proof size and reproducibility on the target CPU. State exactly what was included and what remained outside the guest.
5. Compare the measured profile against the stated post-quantum and zero-knowledge security arguments. A public benchmark or a successful arbitrary-program proof is not evidence that the full relation hides its witness.
6. Only after the hash/membership path passes should the team integrate a candidate threshold verifier and measure the complete relation. The authorization test must prove that a valid spend signed by a different key, an insufficient signer quorum, or an altered transaction digest is rejected.

## 4. Required authorization semantics

Before accepting any concrete scheme, the protocol specification must define:
- whether every note requires a (t)-of-(n) threshold or some explicitly different policy;
- the adversary's corruption threshold, collusion assumptions and key-generation/dealer trust;
- the exact message to be signed, including protocol version, namespace, input commitment/nullifier, transaction digest, output list and state anchor;
- canonical key/signature codecs, parameter identifier and transcript;
- how the authorization public key in BundleV3 is authenticated and proven to be the same key used by the spend predicate;
- whether the key and signer identity remain hidden in the actual proof transcript;
- classical and quantum security estimates for both the signature scheme and the complete proof system.

The proof relation must enforce authorization over the **same witness** as the exact registered commitment, recipient bundle, nullifier, transaction, state root/head, output identities and range-safe value-conservation predicates. A host signature check plus an unrelated zero-knowledge proof is not equivalent unless the composition formally binds both statements.

## 5. Acceptance criteria and kill conditions

**Advance** only when a pinned configuration generates and verifies the actual proof, adversarial mutations reject, private inputs are shown not to leak through all published proof artifacts, measurements are reproducible, and its stated security meets the agreed target.

**Kill or redesign** if the candidate cannot substantiate the 128-bit post-quantum target, if the required hiding guarantee depends on an unsupported masking assumption, if the proof path exposes the authorization key or tuple, or if the full relation exceeds target hardware/resource limits.

A build passes only a build gate. A hash microbenchmark passes only a hash benchmark. Neither closes the authorization gate.

**Current result:** no authorization scheme selected; no production proof backend selected; V3 remains non-normative; complete 0PSP production remains **NO-GO**. External cryptographic audit remains **NOT PERFORMED**.
