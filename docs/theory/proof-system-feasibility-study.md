# Proof-System Feasibility — V2 Relation and Backend Selection

**Status:** Feasibility decision record. No backend has been instantiated; no proof-system impossibility is claimed. Overall construction remains **NO-GO**.

> **Authorization-mode update (2026-10-11):** This study's Ringtail-verification-in-circuit discussion is a candidate path, not a frozen design decision. The [RFC-02 spend relation](spend-relation-spec.md) now records both the committee-signature relation and a policy-limited self-spend key-knowledge alternative. The latter must bind the full transaction statement and cannot replace committee approval if the protocol policy requires it. Circuit costs are unknown until the exact backend and relation are implemented and benchmarked.

## Executive decision

V2 has a single intended proof statement. It must bind hidden membership, namespace-bound commitment opening, Ringtail threshold-signature validity, namespace-bound nullifier correctness, and policy/state eligibility to the **same hidden coin and key**.

Do not return to a split LoTRS selection proof plus separate SHAKE STARK and an unproven bridge commitment merely because those pieces have individual demos. The current selected direction is one post-quantum zero-knowledge argument. This is an architectural target, not evidence that a practical backend has been found.

## Exact relation to encode

Public statement:

    x = (namespace_id, R_C, nu, M, state, params_id)

Witness:

    w = (j, C_j, pk_j, value, coin_id, r_nf, rho_C, sigma_th)

The proof must establish:

1. j is in range and C_j = R_C[j].
2. C_j is the V2 SHAKE256-384 commitment opening over the canonical parameter ID, public key, value, namespace ID, coin ID, nullifier secret and independent salt.
3. Ringtail verifies sigma_th under the same pk_j on transaction digest M.
4. nu equals the V2 nullifier over namespace ID, coin ID and r_nf.
5. State, unspent status, value conservation, outputs, fees and policy are valid.
6. The transcript hides the selected index, opening and threshold signature except for explicitly allowed leakage.

The V2 namespace ID is 48 bytes, coin ID 32 bytes, nullifier secret 36 bytes, and nullifier preimage 149 bytes. The commitment preimage is variable-length but canonical and length-prefixed. Both hashes use SHAKE256-384 and must be constrained as real computations in the proof. A standalone helper result or a public host-side check does not prove these statements.

The transaction digest M must bind protocol version, namespace, nullifier, inputs, outputs, fees and ledger context. The proof must not let the membership predicate select one key while the threshold-signature predicate verifies against another.

## Candidate comparison

| Candidate | Potential value | Blocking question | Current decision |
|---|---|---|---|
| SmallWood (hash-based ZK argument) | Designed for small-to-medium statements; paper discusses hash-preimage and lattice-based relations | Can the exact V2 relation, including Ringtail verification, fit practical soundness, proof-size and memory limits? Code is a prototype and unaudited | **First feasibility prototype**, not a production dependency |
| Generic post-quantum SoK/LRS research scaffold | Related anonymous-signature relation and code to inspect | The available ZK enhancement is informal and the complete V2 relation/quantum security is not established | Comparator only |
| Extended LoTRS plus STARK | Each layer can express some specialized relations | Requires a concrete bridge commitment, cross-proof witness binding and full composition proof; SHAKE is not proven by a linear LoTRS relation alone | Retired active path |
| Generic classical SNARK stack | Potentially mature developer tooling | Classical curve assumptions may invalidate a post-quantum security claim; a hash PCS alone does not establish zero knowledge of the whole witness | Reject unless the exact security model supports the protocol goal |
| Custom proof system | Could be tailored to the relation | Highest risk: new protocol, soundness, zero knowledge, quantum model and implementation all need independent proof/review | Do not build from scratch without a specific theorem/feasibility rationale |

Sources:
- SmallWood paper: https://eprint.iacr.org/2025/1085
- SmallWood implementation and its unaudited-prototype warning: https://github.com/CryptoExperts/smallwood
- Generic post-quantum SoK/LRS scaffold: https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature
- LoTRS: https://eprint.iacr.org/2026/974 and https://github.com/lotrs-sig/lotrs
- SHAKE specification: https://csrc.nist.gov/pubs/fips/202/final

## Why the old linear proof cannot be extended by append-only encoding

The old LoTRS selection relation proves a specialized algebraic statement. Appending a coin ID or commitment column may bind more linear data to a selected index, but it does not prove that a SHAKE256 output is the hash of a hidden 149-byte input. Keccak-f[1600] contains nonlinear bit-level operations. Such a hash requires its gates/trace to be explicitly represented by the selected proof system, or a different nullifier construction with its own security argument.

This is a scope statement about the documented relation, not an impossibility theorem for lattice ZK.

## Ringtail constraint

Ringtail is a two-round lattice threshold signature whose paper states security from LWE in the random-oracle model. The current upstream Go code explicitly labels itself an academic proof-of-concept that has not received careful code review and is not production-ready.

Required before proof integration:
- Pin the source revision, license, concrete parameter set and canonical key/signature serialization.
- State whether dealer-based key generation is trusted; if not, separately design and prove a DKG.
- Run upstream vectors and independent malformed-signature/encoding tests.
- Translate the exact verification predicate into the proof representation.
- Demonstrate the verifier checks the same hidden pk bound by the commitment, and the signature binds the same M/namespace.
- Do not link the upstream networking demo as part of ledger acceptance.

Ordinary threshold signing/verification is a necessary test, not a ZK integration.

Source: https://eprint.iacr.org/2024/1113 and https://github.com/daryakaviani/ringtail.

## Required feasibility experiment

### Stage 1: backend sanity
- Reproduce the selected backend's upstream examples and test vectors from a clean, pinned checkout.
- Record license, transitive dependencies, compiler/toolchain, parameter choices and known caveats.
- Confirm the exact configuration offers zero knowledge and post-quantum security for the intended adversary model. A marketing description is not a proof.

### Stage 2: minimal end-to-end relation
Use N=2 commitments first. Create valid and invalid test cases covering:
- correct witness and signature;
- wrong namespace;
- wrong coin ID, nullifier secret or salt;
- wrong commitment opening;
- signature valid under a different public key;
- invalid threshold signature and malformed key/signature encoding;
- stale state, missing membership and already-spent nullifier;
- cross-asset and cross-deployment substitution attempts.

The backend must reject each invalid witness through the proof relation, not through a separate trusted side check.

### Stage 3: cost and soundness
Measure actual proof bytes, prover time, verifier time, peak memory and failure behavior. State the soundness/knowledge error, transcript derivation, oracle model, setup assumptions and concrete post-quantum security. Do not revive previous estimated proof-size numbers unless they come from a reproducible build and serialized proof.

### Stage 4: scale and review
Increase N only after the full relation is correct at N=2. Obtain independent review of the proof relation and reduction before increasing security claims.

## Release gates

A backend is accepted only if it satisfies all of the following:
1. One proof binds every predicate to one hidden witness.
2. The exact instantiation has a documented zero-knowledge and knowledge-soundness argument.
3. The full proof composition matches the claimed post-quantum model.
4. Namespace, commitment and nullifier byte encodings match test vectors exactly.
5. Ringtail verification has been integrated as a proven relation, not just a host-side function.
6. State eligibility and atomic replay handling are correctly bound.
7. Reproducible measurements and independent security review exist.

**Current decision:** SmallWood is the first experimental candidate because it is explicitly aimed at hash-based ZK for moderate statements and discusses hash-preimage and lattice relations. Its prototype is not trusted for production. Ringtail remains an unaudited prototype target. The actual V2 proof remains unimplemented, and the overall protocol remains **NO-GO**.
