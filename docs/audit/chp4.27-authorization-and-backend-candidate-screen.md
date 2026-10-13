# CHp4.27 — Authorization and proof-backend candidate screen

**Status:** candidate screen only; authorization and proof backend remain **NO-GO**.  
**Reviewed:** 2026-10-13.  
**Scope:** choose the next falsifiable experiment, not a production primitive by paperwork.

## 1. Decision

Do not freeze a V3 authorization scheme or approve a production proof backend yet. The nearest available evidence rules out two tempting shortcuts:

- **Ringtail reference implementation:** its public Go repository explicitly says it is an academic proof-of-concept, has not received careful code review, and is not ready for production. The scheme is a plausible threshold-signature research candidate, but its existence is not a reviewed implementation or a complete 0PSP authorization path.
- **LoTRS implementation:** its 2026 artifact includes Python and Rust implementations, reproducible interoperability tests and parameter-estimation scripts, which is stronger reproducibility evidence. But its own README reports a production-profile estimate of **100.7978 bits** for one listed post-quantum ASIS variant, with other variants materially lower. Those figures do not substantiate the project's stated 128-bit post-quantum target. LoTRS is also a **structured** threshold ring signature, where signers form a hidden column in a table, not a generic drop-in replacement for Ringtail or an arbitrary wallet policy.

The current V3 candidate now separates core spend authority from intended-payee identity. The lowest-dependency core-spend experiment is a proof of knowledge of the recipient-generated nullifier key nk, explicitly selected by authorization_policy_id = 0PSP-V3-NK-POSSESSION-CANDIDATE-v1. It requires the same hidden nk to open the bundle key commitment and derive NullifierV3, inside one knowledge-sound, witness-hiding relation. This avoids making threshold signatures a mandatory core-spend dependency, but it does not authenticate an intended payee, and it is not production authorization until the complete proof binds membership, trusted state, transaction/output constraints and the exact policy. Threshold ML-DSA-87 remains an optional signature-policy experiment, not the default core-spend policy; its audit-scope and license issues still preclude production use.

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

### Threshold ML-DSA-87 — optional signature-policy experiment, not core spend default

Pinned upstream release: [`threshold-v3.0.0`](https://github.com/Quantus-Network/qp-rusty-crystals/tree/threshold-v3.0.0), commit [`5d3d252fbc7975586e13e7576652f37ad1395c05`](https://github.com/Quantus-Network/qp-rusty-crystals/commit/5d3d252fbc7975586e13e7576652f37ad1395c05). Crate: [`qp-rusty-crystals-threshold 3.0.0`](https://docs.rs/crate/qp-rusty-crystals-threshold/3.0.0).

This is a materially better candidate for the next authorization experiment than the Ringtail proof-of-concept or LoTRS's presently reported sub-128-bit estimates:
- The tagged README says the implementation uses FIPS 204 ML-DSA and that the produced signature is compatible with a standard ML-DSA verifier.
- The release exposes ML-DSA-87 by default and documents threshold signing/DKG for that profile, with configurations (2 \le t \le n \le 6).
- The API explicitly takes both a message and a context (maximum 255 bytes); signature verification rejects an overlong context and malformed public key/signature encodings.
- The tagged source contains a critical warning that reusing a per-round seed can enable full key recovery. A production adapter would need a reviewed OS-CSPRNG/nonce lifecycle and must never expose deterministic caller-controlled signing seeds.

**Important evidence conflict:** the same tagged `threshold/README.md` claims the threshold signing protocol and DKG have been audited for ML-DSA-87, but `threshold/src/lib.rs` in that exact release still says the implementation “has not undergone a security audit” and is for research/experimentation only. Until the audit report, scope, commit and findings can be mapped to this exact release and reconciled with that warning, treat the project’s audit claim as vendor-reported, not as independently established acceptance evidence. The README also says resharing is not audited; 0PSP must not require that feature in its first integration.

**License blocker:** the tagged `threshold/Cargo.toml` declares `GPL-3.0`, while the same repository-root `LICENSE` file is Apache-2.0. This metadata conflict must be resolved with the maintainers/legal review before adding a dependency. No code from this crate has been copied into 0PSP, and it has not been added to Cargo dependencies.

**Protocol-fit blocker:** a standard ML-DSA signature can be verified outside a proof only when its public key is available. 0PSP intends the note's authorization key to remain hidden inside the note bundle, so the selected proof must constrain verification of the threshold signature against that *same hidden key* and the exact canonical V3 authorization message. Separately, a signature by the bundled key is only proof of key control; it is not proof that the key belongs to the sender's intended payee. If intended-payee authenticity is required, define an independent recipient/address/invoice or authenticated recovery-key anchor and bind it to the bundle/output inside the proof. That identity/recovery anchor is not specified today. Signature verification cost, witness-hiding behavior, canonical public-key encoding, signature serialization, concrete 128-bit post-quantum security claim for the selected configuration, and full 0PSP integration are all unmeasured. The library's availability does not solve those composition obligations.

**Decision:** make ML-DSA-87 threshold signing the **leading experiment candidate, not the selected production scheme**. Freeze no scheme ID or key codec yet. Next evidence must include the exact audit report, license reconciliation, pinned clean-build/conformance run, signature/context KATs, adversarial threshold/seed-reuse/session tests, and a measured proof of signature verification against the hidden note key.

### Core spend authority candidate: proof of nk possession

The V3 reference now defines the explicit policy ID 0PSP-V3-NK-POSSESSION-CANDIDATE-v1 and a host validator that rejects any different policy ID. Under this candidate, spend authority is a proof of knowledge of the 48-byte recipient-generated nk, established by all three relations holding over the same witness:

- KeyCommitV3(nk) equals the key commitment encoded in the exact canonical BundleV3.
- CommitV3 opens the exact registered input commitment with the same BundleV3, value, namespace and hidden tuple.
- NullifierV3 equals HMAC-SHA3-384 under that same nk, over the exact commitment and hidden tuple.

The canonical transaction digest must bind the policy ID, the exact consumed nullifier, root/state head, fee, public entropy and ordered output commitments. The eventual proof must additionally enforce the authenticated membership path, output identity derivation, all output openings, range-safe value conservation and exact transaction-byte/public-input binding. A host-level policy check or the current OpenVM hash-slice guest is not this complete proof.

The model assumes the note recipient generates nk independently and the output creator never learns it. A public NullifierV3 is not enough to spend: under the candidate policy the accepted proof must demonstrate knowledge of the key opening the note's committed key hash and used by the nullifier predicate. However, this authorization only works if the actual proof is knowledge-sound and hides nk from verifiers. The current OpenVM profile is reported at 100-bit post-quantum security, below the project's 128-bit target, and its witness-hiding properties for this construction have not been independently established. Therefore this policy is the most practical next experiment, not a production-selected authorizer.

Intended-payee authentication remains a distinct gate. BundleV3 auth_public_key/auth_scheme_id are self-asserted unless tied to an independent address, invoice or authenticated recovery-key anchor. The nk-possession policy does not prove that the bundle belongs to the intended payee, and must not be advertised as doing so.

### Candidate authorization message and context

The host-only module `src/protocol/transaction_v3_candidate.py` defines a canonical V3 candidate field encoding and a domain-separated 48-byte SHAKE256 digest. `authorization_input_v3_candidate()` parses the canonical BundleV3 and appends its exact `auth_scheme_id` to the context prefix using a uint16 little-endian length. It rejects malformed bundles and any scheme ID that would exceed ML-DSA's 255-byte context bound. This prevents a caller from reusing an identical context while silently changing the declared scheme ID. Tests cover transaction-field mutation, scheme-ID context separation, malformed bundle bytes and oversized contexts.

This defines an explicit host/API contract for the next threshold-signature experiment, **not** a frozen signature scheme or proof. It does not validate any signature and no V3 circuit/guest constrains these fields. The eventual proof must check the signature against the exact hidden authorization public key committed by BundleV3 and the same message/context; a standalone host check is not sufficient where the key is hidden.

### OpenVM 2.0 as a proof-backend candidate

Pinned upstream release used by the partial research guest: https://github.com/openvm-org/openvm/tree/v2.0.2  
Official release announcement: https://blog.openvm.dev/2.0-production  
Official application and proof CLI documentation: https://docs.openvm.dev/book/writing-apps/verifying-proofs/

OpenVM's July 2026 release announcement reports an external zkSecurity audit for v2.0.0, formal-verification coverage for core extensions, and **100 bits** of provable post-quantum security in its stated profile. The existing 0PSP branch pins OpenVM v2.0.2 and has passed a guest-build CI run for a **partial NOAUTH** relation. That is concrete progress for evaluating a maintained Rust zkVM, but it is not end-to-end 0PSP proof evidence, does not establish 128-bit PQ security, and does not close authorization.

The OpenVM CLI distinguishes application-level, aggregated STARK and EVM proof paths. Under a post-quantum requirement, assess the exact STARK configuration first. Do not assume the EVM/Halo2 wrapping path inherits the STARK path's post-quantum claim; its verifier and setup assumptions require a separate security argument.

**Decision:** OpenVM 2.0 is now a concrete feasibility candidate worth testing against the actual relation, but its reported 100-bit profile is below the current 128-bit research target. Do not silently lower that target. The experiment must show whether a documented configuration meets the required security target without trading away witness hiding, soundness, transparency, or reproducibility.

### OpenVM V3 NullifierV3 predicate slice — execution and app-proof evidence

At code head `5d79a1b66cb2fe595d6d4f9dc7c1fe5b92a48503`, the separate experimental path `proof/openvm/v3-nullifier-spike` passed [OpenVM feasibility workflow run #19](https://github.com/Patel5600/0PSp/actions/runs/38415678950). The same predicate code passed again on docs-updated PR #10 head `ad7fd8c3a502d227bd6379a9522c66574e02882b`: [OpenVM feasibility run #21](https://github.com/Patel5600/0PSp/actions/runs/38416261510), [Functional Checks #464](https://github.com/Patel5600/0PSp/actions/runs/38416261530), and [Repository Integrity Watch #336](https://github.com/Patel5600/0PSp/actions/runs/38416261460).

The guest checks just this predicate slice: canonical BundleV3 parsing; opening the recipient-held 48-byte nullifier-key commitment; recomputing the exact CommitV3 opening; computing HMAC-SHA3-384 NullifierV3; and revealing a domain-separated public statement digest. The run passed five host known-answer/adversarial tests, a public-output digest KAT, valid guest execution, rejection of six invalid witnesses (wrong key, changed value, changed salt, wrong nullifier, malformed bundle and trailing bytes), app-proof generation/verification, and the Cargo.lock non-mutation check.

Measured on GitHub-hosted runners for this **slice only**:
- Earlier run: app proof generation **79.63 s**, peak RSS **2,732,600 KiB**; verification **0.06 s**, peak RSS **45,632 KiB**.
- Latest docs-updated head: app proof generation **137.69 s**, peak RSS **2,732,080 KiB**; verification **0.10 s**, peak RSS **45,016 KiB**.
- Serialized app proof size was **645,001 bytes** in both runs.

The proving-time variation across these two CI runs shows why this is a feasibility datapoint, not a reproducible target-hardware benchmark.

These measurements are not target-laptop benchmarks. More importantly, a verified OpenVM app proof is evidence for execution of this guest program, not a complete 0PSP spend proof and not, by itself, a proof of witness hiding or a ≥128-bit post-quantum bound. This guest does **not** constrain Merkle membership or a trusted/finalized root, anchored output identity, full transaction/value conservation, spend authorization, intended-payee authentication, durable ledger transition, or recovery. The separate PR #31 guest remains **NOAUTH**. The OpenVM profile's published 100-bit PQ claim remains below the project's 128-bit target. Do not use this experiment to freeze the HMAC byte contract or authorize spends.

## FRI query-count sanity check (not a security approval)

The upstream [Plonky3 FRI prover source](https://github.com/Plonky3/Plonky3/blob/main/fri/src/prover.rs) documents two Reed–Solomon proximity terms: `rate^num_queries` under the conjectured proximity bound, or `rate^(num_queries/2)` under the proven bound. For rate \(\rho=1/8\), the FRI term alone is:

| Query count \(N_q\) | Conjectured term \(\rho^{N_q}\) | Proven term \(\rho^{N_q/2}\) |
|---:|---:|---:|
| 80 | \(2^{-240}\) | \(2^{-120}\) |
| 86 | \(2^{-258}\) | \(2^{-129}\) |
| 88 | \(2^{-264}\) | \(2^{-132}\) |
| 96 | \(2^{-288}\) | \(2^{-144}\) |

This table is **not** a composed soundness theorem. The proven \(2^{-129}\) FRI proximity term at \(N_q=86\) leaves essentially no margin for the other soundness terms and cannot, by itself, substantiate a 128-bit post-quantum claim. The total analysis must also account for constraint-composition error, extension-field/challenge collisions, commitment binding, transcript/Fiat–Shamir security in the stated quantum random-oracle model, grinding under a quantum adversary, batched-query collisions, and the actual zero-knowledge masking mechanism. Plonky3 explicitly recommends query-count margin for shared challenge batching and birthday collisions.

A \(2^{-16}\) proof-of-work target must not be mechanically added as “16 more security bits.” Its attack cost and its effect in the proof's soundness reduction differ, and a quantum search can change the work factor. The exact transcript schedule, allowed adversary query budget, grinding placement, hash output size, extension field and reduction theorem must be included in the concrete calculation.

The CI step `scripts/security_budget_evaluator.py` is explicitly historical numeric-consistency diagnostics for the retired CHP3 design. Its BabyBear/LoTRS figures and `N=86` FRI arithmetic are conditional arithmetic only, not an active V0 carry-overflow proof or a composed soundness calculation. Do not mark BabyBear carry containment as a frozen protocol invariant based on that output; closure requires relation-specific range/carry constraints, adversarial overflow witnesses, and evidence that the selected backend enforces them.

**Current status:** 0PSP has not parameterized or verified a Plonky3 FRI profile for the complete relation. PR #31 uses the OpenVM v2.0.2 partial NOAUTH guest; the project’s existing candidate screen records OpenVM's stated 100-bit PQ profile as below the current 128-bit target. No FRI setting change, field-extension choice, or PoW arithmetic closes this gate without a pinned build, full composed bound and an end-to-end proof/verification test. See the upstream [FRI parameter implementation](https://github.com/Plonky3/Plonky3/blob/main/fri/src/prover.rs) and the [Fiat–Shamir-in-QROM analysis](https://eprint.iacr.org/2023/1071.pdf).

## 3. The next experiment

The isolated V3 nullifier predicate spike has passed execution and app-proof verification; the next experiment is now the complete shared-witness relation, not another claim based on guest compilation alone. Use immutable sources and one explicit security profile. No production gate advances until the complete relation passes.

1. Retain the checked-in, locked dependency graph for the V3 predicate spike. Separately add and verify a generated Cargo.lock to PR #31's NOAUTH guest; it is still missing there. Record exact OpenVM, Rust toolchain, extension and dependency versions for both trees.
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
- how the authorization public key in BundleV3 is authenticated and proven to be the same key used by the spend predicate; a signature by that same self-asserted key proves key possession only, not intended-payee identity, so define an independent recipient/address anchor or disclaim intended-payee authenticity;
- whether the key and signer identity remain hidden in the actual proof transcript;
- classical and quantum security estimates for both the signature scheme and the complete proof system.

The proof relation must enforce authorization over the **same witness** as the exact registered commitment, recipient bundle, nullifier, transaction, state root/head, output identities and range-safe value-conservation predicates. A host signature check plus an unrelated zero-knowledge proof is not equivalent unless the composition formally binds both statements.

## 5. Acceptance criteria and kill conditions

**Advance** only when a pinned configuration generates and verifies the actual proof, adversarial mutations reject, private inputs are shown not to leak through all published proof artifacts, measurements are reproducible, and its stated security meets the agreed target.

**Kill or redesign** if the candidate cannot substantiate the 128-bit post-quantum target, if the required hiding guarantee depends on an unsupported masking assumption, if the proof path exposes the authorization key or tuple, or if the full relation exceeds target hardware/resource limits.

A build passes only a build gate. A hash microbenchmark passes only a hash benchmark. Neither closes the authorization gate.

**Current result:** ML-DSA-87 threshold signing is the leading experiment candidate, but no production authorization scheme is selected; the exact-release audit claim is internally inconsistent, license scope needs clarification, and no signature verifier is integrated into a ZK relation. No production proof backend is selected; V3 remains non-normative; complete 0PSP production remains **NO-GO**. External audit of 0PSP remains **NOT PERFORMED**.
