# CHP3 Carry-Recurrence Regression Check

**Scope:** arithmetic helper and bounded regression coverage only.  
**Security status:** this is not an AIR implementation, STARK proof, or cryptographic audit.

## Corrected identity

For radix/base \(W\), the intended limb equation is

\[
\sum_{j=0}^{i} k_jq_{i-j}+b_i+c_{i-1}=v_i+Wc_i,
\]

so the residual must be

\[
r_i=v_i-\sum_{j=0}^{i} k_jq_{i-j}-b_i-c_{i-1}+Wc_i.
\]

For conventional nonnegative carries, require \(0\le v_i<W\) and \(c_{i-1},c_i\ge 0\). An exact input sum equal to \(W\) must produce output digit \(0\) and outgoing carry \(1\). The previous opposite-sign candidate does not satisfy that boundary.

## Regression coverage added

- The standalone arithmetic audit checks the corrected exact-limb boundary and exercises a bounded exhaustive grid for radices 2 through 8.
- Pytest checks the same bounded exhaustive helper, radix-boundary cases including the configured \(2^{14}\) radix, a no-carry top digit, the prior incorrect sign candidate, and invalid radix input.
- The repository's existing CI workflow already runs both the standalone audit script and the pytest suite for pull requests.

## What this does not establish

The exhaustive grid is finite and deliberately small. It establishes that the arithmetic helper encodes the stated recurrence for the tested domain; it does not establish that a proposed AIR constrains the correct values.

This repository checkpoint still does not include a compiled, fully constrained Layer 2 AIR. In particular, these tests do not validate:
- all field-to-integer limb constraints and canonical ranges;
- signed or nonnegative carry bounds for a concrete trace;
- top-limb and terminal-carry constraints;
- residual bounds and prevention of field-wraparound for every AIR expression;
- polynomial constraints' equivalence to the intended integer relation;
- STARK soundness, zero knowledge, post-quantum security, or cross-layer composition.

## Next technical gate

When an actual AIR is selected and implemented, add constraint-level tests against a reference integer evaluator. Include valid and adversarial traces, boundary values, negative/wrapped encodings, malformed carries, noncanonical limbs, and mutations that must be rejected. Keep the protocol-security status open until the complete AIR and proof backend are reviewed independently.
