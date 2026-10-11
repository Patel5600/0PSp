# RFC-03 — Hash / Circuit Benchmark Matrix

**Status:** benchmark protocol only; **NO MEASUREMENTS CLAIMED**. No proof backend adapter is currently integrated.  
**Production hash change:** prohibited until data and security review.  
**Normative index:** [Evidence-first RFC register](../security/evidence-first-rfc-register.md).

## 1. Purpose

Replace unsupported estimates with reproducible measurements. This work package does not select a new hash and does not claim that either candidate is cryptographically suitable for 0PSP.

The primary benchmark target is the 149-byte V2 nullifier preimage: with SHAKE256's 136-byte rate, it crosses the rate boundary. Measure the exact implementation in the selected proof backend. Do not infer arithmetic constraints solely from the native C runtime.

## 2. Required backend adapter

The benchmark must identify and pin the backend, source revision, field/constraint model, compiler, proving system and all relevant parameters. Until a backend that can express both candidate constructions is selected, the harness is a design task only. Do not publish made-up R1CS constraints, AIR rows, or proving times.

Each backend adapter must expose equivalent operations:

- create the fixed test input with the canonical bytes and domain/version used by the protocol;
- compile/build the relevant circuit or trace;
- report native backend measures (constraints, rows, gates, trace length or a documented equivalent);
- generate witness and proof, verify proof;
- report peak resident memory and all elapsed times;
- fail closed if parameters or adapter version do not match the recorded configuration.

If one primitive cannot be faithfully expressed or fairly compared in the backend, record the comparison as not comparable rather than manufacturing a conversion factor.

## 3. Candidates and configuration freeze

### Candidate A — SHAKE256-384

- Protocol input: exact canonical 149-byte V2 nullifier preimage.
- Output: 48 bytes (384 output bits).
- Absorption: input spans two SHAKE256 rate blocks (rate 136 bytes); record the selected hash gadget's padding and output squeezing details.
- Required checks: byte-for-byte parity with the existing reference/native known-answer vector, boundary tests at lengths 135, 136, 137, 148, 149 and 150 bytes where the gadget API allows, plus malformed/alternate input rejection at the relation layer.

### Candidate B — Poseidon2 over Goldilocks

The tuple `t=16, R_F=8, R_P=22, S-box x^7` is recorded as **an unvalidated candidate proposal only**. Before benchmarking, confirm it against an authoritative specification and a concrete security analysis for the actual field, capacity/rate, output encoding and adversary model. A Goldilocks field plus those parameter symbols does **not** by itself establish 384-bit capacity or 384-bit classical/quantum security.

To compare against a 384-bit SHAKE output, define and analyze exactly how the Poseidon2 result is expanded/encoded and how many field outputs are used. Do not silently equate a field element with a 384-bit digest. Any internal hash that differs from the published commitment/nullifier contract is a protocol redesign requiring new vectors and proof arguments.

## 4. Environment record

Each CSV row/report must record:
- timestamp (UTC) and run ID;
- git commit and dirty-tree status;
- backend name/version/commit, adapter commit and proof mode;
- exact hash parameters and canonical input vector digest;
- OS/kernel, CPU model/core count, RAM, compiler/runtime and relevant flags;
- cold/warm status, thread count, sample/repetition count;
- compile time, witness-generation time, prove time, verify time;
- constraints/gates/rows/trace length and any other backend-native metric;
- proof/transcript byte size and peak RSS;
- output correctness / verification result;
- warnings, failed runs and whether comparison is security-comparable.

Store raw per-run output as CSV or JSON in a non-production artifact, plus a human-readable summary. Report median and dispersion (not a single best run). No result should include witness secrets.

## 5. Execution protocol

1. Pin the backend and source/adapter revision.
2. Run existing repository tests and native/reference known-answer checks first.
3. Compile each candidate with identical compiler settings and declared public inputs.
4. Verify the gadget's output byte-for-byte against its reference model.
5. Run a pilot to size time/RAM, then a predeclared number of full repetitions.
6. Capture per-run environment and raw measurements.
7. Independently reproduce the result on the declared target class.
8. Review the security model before interpreting speed.

## 6. Performance budget, not security gate

The proposed 1.5-second target and 5-second / 4-GB warning boundaries may be used as engineering budget indicators only, after the measured workload and hardware are fixed. They are not cryptographic acceptance thresholds. A run under 1.5 seconds does not approve a primitive; a run over 5 seconds does not mandate replacing it.

Do not benchmark just the hash and call it the whole proof. End-to-end performance must eventually include membership, authorization, transaction policy, witness generation, proving, verification, network/committee protocol if any, and memory.

## 7. Current result

**Not run:** backend and adapter are not instantiated in this repository. There are no validated constraint counts, proving times, proof sizes, or peak-RAM measurements to report. Production SHAKE256 implementations remain unchanged.
