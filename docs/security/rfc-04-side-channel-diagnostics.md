# RFC-04 — Native Memory Discipline and Side-Channel Diagnostics

**Status:** diagnostics plan; **not a constant-time certification**.  
**Production:** **NO-GO** until the full implementation gate is met.  
**Normative index:** [Evidence-first RFC register](evidence-first-rfc-register.md).  
**Detailed baseline:** [CHP4 constant-time and side-channel specification](chp4-constant-time-and-side-channel-spec.md).

## 1. Scope and non-goals

Keep the zero-dependency C11 native core for this work package. Do not rewrite it in another language merely to assume memory safety or zeroization. Do not change the current CI to make noisy timing observations a blocking release condition.

The native implementation uses `psp_secure_zero` (volatile compiler memory-barrier scrubbing) and physical RAM locking (`VirtualLock` on Windows, `mlock` on Linux), with sanitizer plus optimized-wrapper-disassembly build targets. These are defense-in-depth controls but do not establish that all copies disappear, that compiler/runtime internals are constant-time, or that Python/ctypes has not made other copies.

## 2. Compiler/platform API inventory

At build/configure time, check the actual target environment for:
1. C23 `memset_explicit` when the compiler and C library support it;
2. `explicit_bzero` when the target platform provides it;
3. `psp_secure_zero` and platform-specific physical RAM locking (`VirtualLock` / `mlock`).

Select an explicit, reviewed supported primitive based on platform guarantees. Do not silently treat a bare unverified pointer loop as a universally equivalent fallback. If the target has no reviewed mechanism, fail the production readiness gate; a research diagnostic build may still run with an explicit warning.

The current native implementation calls `psp_secure_zero` across all secret zeroization boundaries; do not remove or bypass these calls.

## 3. Optional disassembly audit

The diagnostic script `scripts/audit_disasm_bzero.sh` is intended to inspect the compiled wrapper and report whether expected explicit-cleansing call sites are still visible in selected exported functions. Example:

```sh
make -C native clean test
make -C native audit
bash scripts/audit_disasm_bzero.sh native/build/libpsp_nullifier.so
```

The script is advisory. A visible call reference does not prove that every temporary/copy is cleared; an absent direct symbol can result from inlining or wrapper changes and requires manual review. It does not inspect compiler runtime machine code, allocator remnants, Python runtime/FFI copies, core dumps, swap, or the full prover. Save disassembly and tool/compiler metadata with the result.

## 4. Timing leakage assessment

The current fixed-versus-random C screens are not the official dudect framework and must not be called a TVLA certification. A future controlled-hardware harness should pin source revision, optimization flags, CPU/governor, input class definition, sample procedure and binary. It should report the Welch t-statistic and distributions, not only a pass/fail label.

Use `|t| ≥ 4.5` as a diagnostic alert for the predefined experiment, not a universal security boundary. A result below the threshold means only that the chosen experiment did not detect leakage at that sensitivity. It does not prove constant time. A shared GitHub runner is noisy and stays non-blocking; reproducible dedicated hardware evidence is required before any release claim.

## 5. Required audit scope

For each sensitive routine, document the secrets and public inputs, source revision, function entry/exit paths, compiler/toolchain, C standard library, binary hash, target CPU and observed leakage. At minimum review:
- namespace-scoped commitment and nullifier routines;
- random generation and error paths;
- key-generation/signing/proof routines once integrated;
- buffers and copies across Python/native or future Rust/native boundaries;
- errors, logs, crash dumps and time-dependent state transitions.

No result from a primitive-only test can be promoted to a full-prover claim.

## 6. Release criteria

- [ ] Every target build has an explicit cleansing API selection, availability evidence and negative/failure-path tests.
- [ ] Optimized disassembly reviewed per sensitive function; expected wipe calls and temporary-buffer lifecycle documented.
- [ ] Sanitizer/fuzz/error-path tests pass on the pinned build.
- [ ] Controlled timing/leakage runs are reproducible on each claimed hardware class.
- [ ] Compiler/runtime, memory allocation, and FFI copies are included in the review.
- [ ] Complete proof-generation and signing path is assessed after those components exist.
- [ ] Independent review signs off on the exact binary/build matrix.

**No-go note:** the optional script and a clean timing run are diagnostic evidence only. Neither is a constant-time theorem or production approval.
