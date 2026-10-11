# 0PSP Dependency-Minimization and Construction Roadmap

**Plan date:** 2026-10-11  
**Baseline:** `Patel5600/PSp` main at `3116a8dc90c6e8828c988f77a7bc013434d27cba`  
**Status:** Planning and audit only; no cryptographic backend was switched by this plan.  
**Security decision:** Research only; complete protocol remains **NO-GO**.

## Executive decision

Minimize the trusted computing base and runtime link dependencies, but do not replace a reviewed library with unverified hand-written crypto merely to make the dependency list shorter.

MAMA40 is a **candidate source for an isolated SHAKE256 + OS-entropy backend**, not a solution for the missing protocol construction. Do not add the entire MAMA40 suite as a linked dependency or private Git submodule. Audit and, only after the gates below, vendor the smallest useful subset behind a 0PSP-owned C interface.

MAMA40 does **not** currently provide:
- the Ringtail threshold-signature protocol required by 0PSP;
- a proof backend for the complete hidden-spend relation;
- a proof that the commitment construction is hiding and binding;
- a full security reduction for 0PSP.

Its ML-KEM implementation is a key-encapsulation mechanism, not a threshold signature. Do not substitute one for the other.

## Why MAMA40 is only a candidate

Audit reference: [MAMA40 source at commit `01c3f452a2ab384ab7e048cd43e56b2969c35a47`](https://github.com/Patel5600/Mama40/tree/01c3f452a2ab384ab7e048cd43e56b2969c35a47).

Potentially reusable:
- `mama_shake256(out, out_len, in, in_len)` is exposed in `include/mama_mlkem.h`.
- `mama_random_bytes(out, len)` is exposed in `include/mama_random.h`; its contract says it uses operating-system entropy and fails on error.
- Existing SHAKE known-answer tests, CSPRNG checks, and a dudect-style harness provide material for independent re-testing.

Reasons not to trust it as a drop-in replacement today:
1. MAMA40's own `SECURITY.md` says there has been no completed formal verification or third-party audit and states that constant-time behaviour has not been independently measured.
2. Its latest scheduled fuzzing run failed: [run 38124497645](https://github.com/Patel5600/Mama40/actions/runs/38124497645). Its 2026-10-07 main CI run also failed: [run 37660898655](https://github.com/Patel5600/Mama40/actions/runs/37660898655). Failure causes must be triaged before relying on any affected code.
3. MAMA40 is a **private repository**. A public 0PSP CI job or a clean downstream build cannot depend on fetching it using private credentials. A pinned, self-contained source subset is required if it passes review.
4. MAMA40 is AGPL-3.0 licensed. Before copying source into 0PSP, resolve 0PSP's licensing/redistribution terms and retain the required notices. Do not silently paste code across repositories.
5. A passing timing test is evidence only for the tested binary, target, input classes and measurement conditions. It is not a general proof of constant-time execution or absence of side channels.

## Target dependency policy

**Production/runtime target:** no mandatory OpenSSL linkage for the fixed-width nullifier component, provided a replacement backend passes all gates below. A C compiler and the target operating system remain build/platform requirements; “zero dependencies” does not mean zero trusted code.

**Development-only tools:** keep test and analysis tools out of runtime dependencies. `pytest` and `hypothesis` are valuable test tools and should remain development dependencies. Audit actual import/use sites before moving or removing `numpy`, `sympy`, `pytest-benchmark`, or `rich`; do not remove a dependency from its manifest until CI proves it is unnecessary.

**Cryptographic rule:** preserve at least one independent oracle for differential testing. It need not be dynamically linked into the shipped nullifier library. Never claim that a source-tree vendoring operation, hand-written assembly, or known-answer tests alone establishes security.

## Execution phases

### Phase 0 — Freeze a reproducible baseline

- Keep `main` as the integration branch and pin the exact starting commit in every audit report.
- Record current CI outcomes, build flags, binary linkage, supported architectures, native test vectors and Python/native agreement.
- Audit every non-`main` branch against `main`; preserve any unique required commit before deleting stale refs. Closing a pull request or moving a branch does not delete it. The target is one branch, `main`, after the ancestry/content check is complete.
- Preserve the current OpenSSL-backed nullifier until an alternate backend passes parity tests; no flag-day replacement.

**Gate:** the baseline build and tests are reproducible from a clean checkout.

### Phase 1 — Inventory and remove unnecessary dependencies

- Inspect every Python import and script entry point. Determine whether `numpy` and `sympy` are imported by the supported runtime package or only by retired CHP3 diagnostics.
- Move packages used only by tests, benchmarks or research scripts into explicit development/research extras. Remove only demonstrably unused packages.
- Build the native nullifier and inspect dynamic symbols with `ldd`/equivalent, `nm -D`, and link-map output. Record exactly why every non-platform library is present.
- Separate the nullifier library's production dependency list from CI tooling and historical research scripts.

**Gate:** a clean dependency report states each remaining runtime, build and development dependency with the file/target that uses it.

### Phase 2 — Evaluate a minimal MAMA40 backend in isolation

- Pin the exact audited MAMA40 source revision; do not consume an unpinned branch or remote runtime dependency.
- Identify the minimum files needed for Keccak-f[1600]/SHAKE256, ABI glue and OS entropy. Do not vendor ML-KEM, ratchets, X25519, signatures or messaging code into 0PSP unless a future protocol requirement independently justifies them.
- Keep the interface owned by 0PSP, e.g. a narrow `psp_crypto_backend` with fixed-size inputs, explicit errors, deterministic SHAKE and fail-closed random generation.
- Resolve the AGPL-3.0 source/notices and 0PSP license boundary before copying. Record file provenance and hashes.
- Test the candidate independently before wiring it into production code.

**Required tests before integration:**
1. FIPS 202 SHAKE256 known-answer vectors, including empty input, rate-boundary inputs, multi-block inputs and output lengths crossing the 136-byte rate.
2. Byte-for-byte comparison with the existing OpenSSL backend and an independent test oracle.
3. Nullifier fixed vectors unchanged across backend switches; output must remain exactly 48 bytes for the existing 99-byte input contract.
4. RNG success, failure injection, short-write/error handling where applicable, output clearing, repeated generation and no weak fallback.
5. ASan/UBSan, fuzzing of public argument/error paths, ABI and optimized-disassembly review.
6. Timing tests on an idle target using randomized/interleaved classes and negative controls. Report inconclusive runs as inconclusive; never turn a non-detection into a security proof.
7. CI on every supported architecture/ABI. Do not claim ARM64, Windows or fallback-path support unless it actually runs there.

**Gate:** no regressions, independent parity, reviewed source provenance/licensing, reproducible CI and an evidence-based side-channel note. Otherwise retain OpenSSL.

### Phase 3 — Canonical minting and asset/deployment isolation

- Specify one canonical coin-ID derivation using an explicit domain and unambiguous encoding of the ledger/network, deployment, asset, and unique mint serial/nonce.
- Define duplicate prevention, migration rules, and what happens when two deployments reuse IDs.
- Make minting and ledger validation enforce the same invariant. If needed, revise the nullifier statement/preimage to include the namespace explicitly; changing this requires a protocol version bump and new vectors.
- Prove inside the spend relation that the hidden coin ID belongs to the selected coin commitment and is consistent with the namespace rule.

**Gate:** cross-chain/cross-deployment/cross-asset collision and replay tests pass, with a specification and invariant proof. Documentation alone is not enforcement.

### Phase 4 — Freeze and prove the commitment contract

- Replace the current “candidate” status only after specifying byte-level encoding, domains, public parameters, salt generation, output size and parameter/version binding.
- State the exact hiding and binding notions and assumptions, including the quantum random-oracle model if SHAKE is modeled as an oracle.
- Show the reduction and concrete security loss; cover malformed encodings, repeated salts, field/range constraints and cross-protocol domain separation.
- Use known-answer vectors and mutation/property tests for all encodings.

**Gate:** a reviewable commitment specification and reduction. Passing helper tests alone does not satisfy this gate.

### Phase 5 — Integrate the threshold-signature layer

- Pin the Ringtail paper, implementation revision, license, parameters, transcript encoding and key-generation model. The current design assumes dealer-based key generation unless a DKG is separately designed and proven.
- Treat the upstream Ringtail code as an academic prototype until reviewed; its own upstream README warns that the code has not received careful review and is not production-ready.
- Build a minimal adapter with explicit serialization, transcript/domain separation, key validation, signature verification and negative tests.
- Decide how the signature-verification relation is represented inside the proof backend before declaring the adapter integrated.

**Gate:** reproducible threshold signing/verification vectors and a security-reviewed adapter contract. A standalone signature verifier is not enough if the full anonymous proof cannot establish its validity for the same hidden witness.

### Phase 6 — Select and instantiate one post-quantum proof system

- Compare viable transparent proof systems against one required relation: hidden membership, exact commitment opening, Ringtail signature validity under the same hidden key, nullifier equation, and state/policy eligibility.
- Specify the full relation mathematically before choosing a backend. Measure whether the lattice-signature relation is efficiently expressible; do not assume a generic SNARK makes it cheap or post-quantum secure.
- Define setup assumptions, transcript challenge generation, Fiat–Shamir/QROM treatment where applicable, soundness/knowledge error, zero knowledge, proof size, prover memory, verifier time and side-channel scope.
- Instantiate the entire relation as one proof statement. Avoid recreating the retired multi-proof/bridge-commitment design.
- Reject a backend if the proof is classical-only but the protocol claims post-quantum security, relies on an undocumented trusted setup, or cannot bind every predicate to the same hidden coin.

**Gate:** an executable end-to-end proof with soundness/zero-knowledge arguments and malicious-witness tests. No backend selected means construction remains NO-GO.

### Phase 7 — Full security and implementation review

- Write games and proofs for spend soundness, nullifier uniqueness/replay resistance, anonymity/unlinkability, commitment binding/hiding, threshold authorization, protocol composition and post-quantum adversaries.
- Document trust assumptions for minting, ledger state, dealer/key holders, parameter distribution, RNG, compiler, ABI, OS and hardware.
- Audit secret lifetime, errors, memory clearing, compiler output, CPU-feature dispatch, cache/timing risks, fault behavior and cross-platform divergence.
- Commission an independent review of the concrete construction. Do not self-award “formally verified” status for tests of invariants.

**Gate:** all claims are mapped to proof, test, audit or explicit assumption; no unqualified security claim is based solely on CI.

### Phase 8 — End-to-end cost and release gate

- Measure key setup, minting, proof generation, proof verification, signature rounds, proof size, throughput and peak memory on declared hardware.
- Include worst-case and adversarial inputs; compare the final relation, not isolated SHAKE microbenchmarks.
- Publish exact toolchain/commit/CPU configuration and artifacts.
- Keep release status **NO-GO** until every mandatory mathematical, protocol, implementation and review gate is closed.

## Dependency removal order

1. Remove unused Python runtime packages after import/use-site audit.
2. Remove OpenSSL from the **native nullifier runtime link** only after Phase 2 passes. Retain independent test-oracle coverage.
3. Avoid adding a ZK framework or threshold-signature package until Phases 5–6 establish exactly what interface and security model are needed.
4. Avoid network services, cloud dependencies, private Git dependencies and runtime downloads. Vendor only pinned, license-compatible source that is necessary.
5. Recompute and publish the dependency inventory after every integration.

## Current facts to preserve

- The nullifier input is currently 99 bytes and the output is 48 bytes.
- The current native helper uses OpenSSL for SHAKE256, random generation and output cleansing.
- The nullifier itself has no separate asset/deployment field; the minting invariant remains open.
- Ringtail is not integrated. The single-relation proof backend is not instantiated.
- The latest 0PSP functional CI passed at the baseline commit, but it does not prove the complete construction secure.
- No timing result currently establishes constant-time behavior or absence of exploitable side channels.

## References

- [NIST FIPS 202: SHA-3, SHAKE128 and SHAKE256](https://csrc.nist.gov/pubs/fips/202/final)
- [Ringtail paper, ePrint 2024/1113](https://eprint.iacr.org/2024/1113)
- [Upstream Ringtail academic prototype](https://github.com/daryakaviani/ringtail)
- [MAMA40 security policy](https://github.com/Patel5600/Mama40/blob/master/SECURITY.md)
- [MAMA40 source at the pinned audit revision](https://github.com/Patel5600/Mama40/tree/01c3f452a2ab384ab7e048cd43e56b2969c35a47)
- [MAMA40 main CI run](https://github.com/Patel5600/Mama40/actions/runs/37660898655)
- [MAMA40 scheduled fuzzing run](https://github.com/Patel5600/Mama40/actions/runs/38124497645)
- [0PSP construction-readiness record](../security/chp4-construction-readiness.md)
