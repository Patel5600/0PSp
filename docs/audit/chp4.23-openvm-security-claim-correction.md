# OpenVM candidate security-claim correction

**Review date:** 2026-10-16  
**Status:** **NO-GO** for the required composed 128-bit post-quantum security target.  
**Scope:** Pinned OpenVM v2.0.2 feasibility guest and SDK runner; not an external audit.

## Decision

The previous `scripts/verify_composite_soundness.py` did not calculate the soundness of the pinned OpenVM profile. It assumed a degree-5 extension, hard-coded a per-query FRI bound, added hand-selected error terms, and reported a post-quantum bit count and blinding-row requirement without a derivation tied to the actual OpenVM configuration. Those outputs were not valid evidence and have been removed.

The replacement report is deliberately fail-closed. It records the pinned backend facts, sets the composed post-quantum security result to **UNKNOWN**, sets end-to-end witness hiding to **NOT ESTABLISHED**, and returns a failing exit status until reproducible, reviewable evidence is supplied.

## Source evidence

1. The application runner pins OpenVM source revision `59a69b8b0cbee7011ac978e4cc07707ee3681944`. The pinned OpenVM workspace selects `openvm-stark-sdk` from the `openvm-org/stark-backend` repository at tag `v2.0.1`: [OpenVM Cargo.toml at the pinned revision](https://github.com/openvm-org/openvm/blob/59a69b8b0cbee7011ac978e4cc07707ee3681944/Cargo.toml).
2. The upstream Stark SDK defines `SECURITY_BITS_TARGET = 100` and documents the production presets as targeting 100-bit proven round-by-round security. The `app_params_with_100_bits_security` constructor calls the parameter builder with that target: [upstream security parameter presets](https://github.com/openvm-org/stark-backend/blob/v2.0.1/crates/stark-sdk/src/config/mod.rs).
3. The same upstream source says the application preset's 100-bit analysis assumes bounds on trace height, constraints, AIR count, interactions, and trace columns. The current candidate has not supplied a complete profile-bound proof that its exact generated application satisfies those assumptions and the project's separate post-quantum target.
4. The backend's `SystemParams::new` documentation explicitly warns that its `security_bits` argument selects WHIR query parameters but **does not guarantee** that the overall protocol reaches that level; it directs users to the backend soundness calculator: [SystemParams implementation](https://github.com/openvm-org/stark-backend/blob/v2.0.1/crates/stark-backend/src/config.rs). The upstream tests separately check their 100-bit production configurations: [upstream soundness tests](https://github.com/openvm-org/stark-backend/blob/v2.0.1/crates/stark-backend/tests/soundness.rs).
5. The pinned Stark configuration uses BabyBear as the base field and a degree-4 extension for challenge values. The idealized field cardinality is `p^4`, with `p = 2,013,265,921` and approximately 123.6 bits of field cardinality. That number is **not** a proof-system soundness result and especially not a quantum security result: finite-field sampling, query bounds, composition, transcript assumptions, grinding, and the adversary model all still require their own analysis.

## What is and is not established

| Item | Evidence status |
|---|---|
| Source revision and upstream parameter constructor | Pinned |
| Upstream target | 100-bit RBR preset |
| Current candidate's composed post-quantum bound | **Unknown / not established** |
| End-to-end zero knowledge / witness hiding | **Not established** |
| Full production spend relation and production trusted-state integration | **Not established** |
| Required >=128-bit post-quantum target | **NO-GO** |
| Production spend acceptance | **Disabled** |

A larger query count or changed PoW setting alone cannot be called a fix. Any proposed replacement must use the exact release parameters and the upstream soundness calculator over documented worst-case application bounds, then provide a separate defensible quantum-security reduction for that exact construction. Witness-hiding evidence must also correspond to the actual compiled guest/proof profile rather than a Python blinding-row estimate.

## Release gate

Do not enable production acceptance or claim Mainnet readiness until one exact release SHA contains (a) the complete relation and trusted-state/atomic transition integration, (b) a defensible composed >=128-bit post-quantum soundness argument, (c) end-to-end witness-hiding evidence, (d) reproducible proof/prover/verifier/resource measurements, and (e) adversarial regression tests reviewed against the exact deployed parameters.

This record corrects a claim in the repository. It is not an external audit and does not certify the current candidate as secure.
