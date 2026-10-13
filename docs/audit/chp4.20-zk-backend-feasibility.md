# CHp4.20 — Proof-backend feasibility gate and selection record

**Status:** backend not selected; production **NO-GO**.  
**Reviewed against main:** `f81673c374c5ba5e8025fcddbc37619751a2d396` (CHp4.19).  
**External audit:** NOT PERFORMED.  
**Purpose:** prevent an attractive STARK demo from being misrepresented as a private, sound production spend proof.

## Decision

Do not adopt a proof backend for production until the exact pinned version demonstrates all of the following in this repository:

1. Transparent setup and a defensible post-quantum security argument for the complete proof system, including field, FRI/PCS, transcript, Merkle hash and Fiat–Shamir transform.
2. Actual zero-knowledge hiding for every witness-dependent trace/query, with a documented hiding mechanism and negative leakage tests. A STARK is not automatically zero-knowledge merely because it is transparent or hash-based.
3. An implementable AIR/circuit for the exact frozen relation below, with public-input byte encoding matching `TxFieldsV2` and `TxDigestV2`.
4. Sound range constraints and non-wrapping arithmetic for values, fees and output sums.
5. Auditable implementation, deterministic proof serialization, malformed-proof rejection, mutation tests, cross-implementation verification and reproducible builds.
6. Measured proof-generation time, peak memory, proof size and verification time on the project's actual target hardware, including adversarial worst-case bounds.
7. No production callback, mock verifier or host-only predicate can bypass the selected verifier.

## Candidates reviewed and not approved

### Winterfell

Winterfell is a transparent Rust STARK framework and is a reasonable research prototype candidate. Its upstream repository explicitly warns that it is a research project, is not audited/production-ready, and that perfect zero knowledge is not currently provided. Therefore the upstream library alone does **not** satisfy 0PSP's private-witness requirement. Adding an ad hoc masking layer would create a new protocol requiring a separate leakage argument and adversarial testing; it is not accepted as a shortcut.

Reference: https://github.com/facebook/winterfell

### lib-Q ZKP / Plonky3-derived STARK stack

The surfaced `lib-q-zkp` documentation describes a SHAKE256-based, post-quantum-oriented STARK stack, but also explicitly marks some membership-proof arms experimental/RED and says the PCS-layer security estimate does not establish the soundness of all AIR gadgets. That is not enough evidence to accept it as the 0PSP backend. It may be investigated at a pinned version, but no RED/experimental component may be used to authorize spends.

References:
- https://docs.rs/lib-q-zkp/latest/lib_q_zkp/
- https://docs.rs/lib-q-stark/latest/lib_q_stark/

### Custom proof system

Rejected. Building a bespoke STARK/FRI/zero-knowledge scheme inside this repository would expand the cryptographic attack surface and cannot be internally validated merely by writing unit tests. The project should instantiate and constrain a maintained framework, not invent a proof system.

## Exact relation the backend must enforce

For one accepted input note and an ordered list of outputs, the proof must bind the same private witness across every predicate:

- **Input opening:** recompute the frozen namespace-bound CommitV2 from the input public key, value, coin ID, 36-byte nullifier secret, commitment randomness, and parameter ID.
- **Membership:** prove the exact input commitment is present at the selected index in the frozen depth-63 namespace-bound append-only Merkle tree, using the canonical sibling ordering and node domains.
- **Nullifier:** compute NullifierV2 from the exact same `(namespace_id, coin_id, r_nf)` used by the accepted commitment opening; bind its 48-byte result to the public transaction field.
- **Canonical public statement:** constrain the exact TxFieldsV2 byte layout and TxDigestV2 digest, including namespace, parameter ID, prior root, ledger-state head, authorization policy, fee and ordered output commitments.
- **Value conservation:** constrain `input_value = fee + sum(output_values)` with explicit range checks and no modular wraparound. Each output value must be part of the same output opening used to compute its commitment.
- **Output identity:** constrain the selected output-identity derivation candidate, canonical primary-input selection, transaction entropy policy, output index, output recipient key and output commitment opening. A host helper or KAT is not a proof.
- **Authorization:** verify the selected authorization predicate against the exact input public key and the exact TxDigestV2 or a precisely specified policy statement. No unrelated-key or signature-substitution acceptance.
- **Public-input binding:** all namespaces, roots, heads, IDs, nullifier, policy, fee and output commitments must be the exact same bytes seen by the host ledger and verifier.

## Feasibility experiment required before implementation approval

Create a separate non-production benchmark harness with:
- the exact pinned candidate crate versions and lockfile;
- a small positive proof and one mutation per public field and witness relationship;
- invalid-range, overflow, wrong-root, wrong-index, wrong-namespace, different-`r_nf`, different-`coin_id`, output substitution, authorization substitution and malformed-proof cases;
- a witness-leakage test against proof bytes and every exposed transcript artifact;
- cross-process and clean-build reproducibility;
- resource measurements on the target laptop and a documented scaling estimate for 1, 2 and maximum configured outputs.

The harness must state exactly which relations are constrained. A proof for a simplified arithmetic toy is not evidence that the 0PSP spend relation is implemented.

## Current gate decisions

| Gate | Status | Reason |
|---|---|---|
| Select production proof backend | **NO-GO** | Candidate properties and version are not approved for 0PSP's full relation |
| ZK witness hiding | **NO-GO** | No accepted implementation and proof/leakage argument is integrated |
| TxFieldsV2 / TxDigestV2 inside proof | **NO-GO** | Host/API validation exists; no AIR constraints |
| CommitV2 opening + membership | **NO-GO** | Reference hashes/tree exist; no proof relation |
| Same-witness NullifierV2 | **NO-GO** | No proof constraint ties the exact same private tuple across commitment and nullifier |
| Value conservation and output openings | **NO-GO** | No circuit/AIR constraints |
| Authorization predicate | **NO-GO** | Policy/key codec and in-proof relation are not frozen |
| Coin-ID uniqueness / recipient safety | **NO-GO** | Output identity helper is a reference candidate; no proof enforcement or complete privacy analysis |
| Full internal security audit | **NO-GO** | There is no complete production proof/authorization composition to audit yet |
| External audit | **NO-GO — NOT PERFORMED** | Explicitly deferred; must remain visible in release record |
| Complete 0PSP production | **NO-GO** | Core spend soundness and witness privacy are not implemented |

## Acceptance rule

A backend is not approved by popularity, a passing toy circuit, a crate's “post-quantum” label, or a benchmark. The exact pinned implementation must pass the feasibility matrix above, and the complete 0PSP relation must be constrained before the corresponding production gates can change to GO. Until then, no proof generated by this experiment may authorize issuance or spending.
