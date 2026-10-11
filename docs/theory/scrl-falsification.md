# SCRL Falsification — Scope and Corrected Claims

**Status:** Research notes. The stated calculations are not a general impossibility theorem.

## 1. Scope of the finding

The prior statement “Shamir sharing is incompatible with lattice keys” was too broad. Ringtail uses Shamir secret sharing for LWE secrets represented as vectors over the scalar field. A polynomial quotient ring having zero divisors does not by itself prevent coordinate-wise Shamir sharing.

The narrow candidate failure is **naive interpolation of bounded signature responses without the masks/protocol steps required by the threshold signature scheme**. That is distinct from the feasibility of sharing a secret and distinct from whether a complete threshold signature can be built.

## 2. Why a simple norm argument is not yet a proof of negligible acceptance

Large centered Lagrange coefficients can amplify bounded integer representatives. However, response arithmetic is modular, and reducing a sum modulo \(q\) produces a representative in a bounded interval. Therefore, an unmodded upper bound exceeding a signature rejection bound is a warning but not, by itself, a proof that the final distribution is uniform or that the acceptance probability equals a product of independent coordinate probabilities.

The expression \(P_{\mathrm{accept}}\approx(2(\gamma_1-\beta)/q)^d\) assumes a specific pseudorandom independent-coefficient model. That distributional premise has not been derived for the concrete interpolated response. The previous claim of an established \(2^{-3840}\) acceptance probability and “infinite rejection loop” is withdrawn.

A valid rejection analysis must define the exact threshold signing protocol, share and nonce distributions, challenge correlations, centered representatives, modular reduction, rejection rule, and induced output distribution. Use an adversarial counterexample or a rigorously derived bound, not a heuristic probability raised to a large dimension.

## 3. Formal sub-claims

- **SC-1, representation/correctness:** Specify the scalar field, ring/module representation, share generation and reconstruction.
- **SC-2, response distribution:** Derive the exact distribution of aggregated responses and rejection probability for a specified signing protocol.
- **SC-3, share-compatible key transformation:** Give a concrete transformation, or a counterexample under explicit constraints.
- **SC-4, related-key security:** Define the adversary, oracle access, corruption model and leakage, then prove a reduction or demonstrate an attack.

These claims are logically distinct. Failure of one proposed map does not establish an impossibility for every lattice-threshold construction.

## 4. Parameters and sources

Do not mix FIPS 204 ML-DSA parameters with LoTRS parameters. ML-DSA uses \(q=8{,}380{,}417\). The LoTRS v2 source uses \(q=2^{43}-67\) and \(\hat q=2^{35}-451\). Calculations must identify which protocol and parameter set they concern.

Sources:
- Ringtail: https://eprint.iacr.org/2024/1113
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- LoTRS parameter source: https://github.com/lotrs-sig/lotrs/blob/main/lotrs-py/params.py

## 5. Decision

SCRL remains an open research line and is not a dependency of the current Design B baseline. Do not claim that Shamir sharing is impossible, that all naive constructions fail with a specific astronomically small probability, or that a general impossibility theorem has been proved.
