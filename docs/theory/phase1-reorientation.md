# Phase 1 Reorientation — Falsification Before Construction

**Status:** Historical decision record, updated for CHP3. Phase 1 remains open.

## Why the plan changed

The original implementation direction bundled representation, threshold signing, key rerandomization, related-key security, anonymity and nullifier correctness. These must be treated as separate claims so a failed assumption cannot be hidden by a passing test.

## Current order of work

1. Fix the system model, threat assumptions, public statement and witness.
2. Separate the ML-DSA parameter experiment from the LoTRS parameter set, which uses two distinct moduli.
3. Select actual coin and bridge commitments and prove their hiding/binding properties under explicit assumptions.
4. Specify the hidden selection and threshold authorization relation for the same coin/key.
5. Define a complete Layer 2 AIR, canonical encoding, range/carry rules, and a backend that genuinely provides zero knowledge.
6. Prove the composition game by game and reconcile all advantage terms and quantum query bounds.
7. Only then implement an end-to-end prototype, run independent tests and measure proof size/runtime/memory.

## Decision terminology

- **Go for specification:** a candidate relation is precise enough to analyze.
- **Go for prototype:** primitives and proof interfaces are concretely specified, and their security assumptions match the intended implementation.
- **No-go:** an explicit counterexample or a proven incompatibility defeats a defined target.
- **Not established:** a calculation, heuristic, incomplete relation, or untested architecture is insufficient to make a security claim.

Design B is the leading research hypothesis, not a proven construction. SCRL remains a separate research track. No token, chain, production deployment or novelty claim is in scope until cryptographic and implementation gates are passed.
