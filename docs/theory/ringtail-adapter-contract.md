# Ringtail Adapter Contract for 0PSP V2

**Status:** interface/verification contract only. Ringtail is not integrated into 0PSP. Do not describe a host-side verifier as part of the zero-knowledge proof.

> **RFC-02 decision boundary (2026-10-11):** Treat this as the committee-signature authorization path only. The repository's policy has not yet frozen that every spend must require a committee signature. If that policy is required, the spend proof must bind verification to the same hidden `pk` committed by the coin. If a self-spend mode is considered, this adapter contract does not prove that it is an equivalent substitute. Use [the current spend relation specification](spend-relation-spec.md); no Ringtail production adapter or in-circuit verifier exists.

## Pinned upstream snapshot and boundary

Current upstream snapshot inspected: [daryakaviani/ringtail commit 1e181c356492e9360765cf27d58497018172ba3c](https://github.com/daryakaviani/ringtail/commit/1e181c356492e9360765cf27d58497018172ba3c). License: Apache-2.0. Its README explicitly warns that the implementation is an academic proof-of-concept, has not received careful code review and is not ready for production.

The checked snapshot contains `sign.Gen`, `Party.SignRound1`, `Party.SignRound2Preprocess`, `Party.SignRound2`, `Party.SignFinalize`, and `sign.Verify`. The high-level local runner uses mutable package-level `sign.K` and `sign.Threshold` configuration. The API is research-oriented; it is not a frozen production SDK.

Upstream imports Lattigo v5.0.2, BLAKE3 v0.2.3, Gonum v0.15.0 and stats v0.7.1 (plus transitive Go modules). Any integration must vendor/pin the exact source and lockfile, produce a reproducible offline build, and inventory all dependencies. Do not fetch mutable `main` at runtime. Do not import the `networking/` demonstration into a ledger verifier.

## Critical constraints

1. **Do not copy the local demo's key setup.** The checked local runner creates a zero-initialized `randomKey := make([]byte, KeySize)` and uses it as `trustedDealerKey`. That is demonstration wiring, not a safe deployment entropy procedure. The adapter must supply fresh, OS-backed, fail-closed entropy to a reviewed key-generation implementation.
2. **Dealer model must be explicit.** The current 0PSP V0 target assumes the Ringtail paper's dealer-based key generation unless a DKG is designed and proved. Never imply distributed dealerless key generation exists in this adapter.
3. **Signature/public-key wire format must be specified.** In the source, `Verify` takes `A`, `bTilde`, message `mu`, challenge `c`, response vector `z` and rounded `Delta` as separate arguments. 0PSP needs a canonical versioned encoding for public key and signature, coefficient ranges, dimensions, modulus/parameter IDs, endianness and lengths. Go's in-memory ring structures are not a wire format.
4. **The exact message must be fixed.** Map the 32-byte 0PSP transaction digest to the Ringtail `mu` byte string exactly and preserve those bytes. `M` must bind protocol version, namespace ID, nullifier, inputs, outputs, fees and ledger context. Ambiguous stringification, display text, JSON field order or variable-length concatenation is forbidden.
5. **A host-side signature check is not the ZK predicate.** The full proof must enforce verification against the same hidden public key that opens the selected coin commitment, over the same message digest. Calling `sign.Verify` outside the proof only confirms a public check; it does not establish hidden-witness consistency. A proof backend may require an explicit arithmetic/gate representation of every verification operation.
6. **No production constant-time claim.** Ringtail's Go prototype has not had careful code review. Go runtime/GC, big-integer operations, map iteration, allocation, panic/logging paths, native library routines and generated code must all be reviewed for the chosen threat model. No claim can be inherited from the paper or from a successful signing test.

## 0PSP adapter surface

The adapter must expose an 0PSP-owned, versioned API conceptually equivalent to:

- `keygen(parameters, entropy_source) -> (public_key, secret_shares, transcript)`
- `sign_rounds(session_id, transaction_digest, qualified_parties) -> signature`
- `verify(public_key, transaction_digest, signature) -> bool`
- `encode_public_key_v1 / decode_public_key_v1`
- `encode_signature_v1 / decode_signature_v1`

This list is a target contract, not code that exists today. Interfaces must not leak the upstream ring types or mutable package globals. Errors must be typed, deterministic where appropriate, and must not log shares or secret-dependent material. The signer round state must be bound to a fresh unique session ID and the exact participant set, message and parameter set to prevent cross-session replay/mix-and-match.

## Required integration tests

1. Reproducible key generation only for test vectors; production entropy must not be hard-coded.
2. Threshold signing and verification with the pinned parameter set, plus deterministic interoperability vectors where the primitive permits them.
3. Wrong message, wrong key, altered challenge/response/Delta, malformed encodings, noncanonical coefficients, wrong dimensions, wrong parameter ID and truncation all reject safely.
4. Two independent valid sessions must not reuse signing-session randomness/state; session or participant substitution must fail.
5. Exhaustive dimension/length/range tests, fuzzing, Go race detector, ASan/UBSan for native boundary code if any, and independent differential checks where a second implementation exists.
6. Document the trusted dealer, participant corruption model, authentication, transport, abort/restart, timeout, replay and state-recovery requirements. Do not rely on the repository demo's TCP transport.
7. Demonstrate the exact signature verification predicate can be enforced inside the chosen proof backend for the same hidden public key and transaction digest. This is a hard gate, not optional future polish.
8. Review parameters/concrete security, licenses, dependencies and source before accepting any claim. The upstream code's academic prototype warning remains in force.

## Proof relation integration

The single V2 relation is:

    public = (namespace_id, R_C, nu, M, state, params_id)
    witness = (j, C_j, pk_j, value, coin_id, r_nf, rho_C, sigma_th)

The proof must enforce membership, the V2 commitment opening, Ringtail verification under that same `pk_j`, V2 nullifier correctness, state eligibility and transaction policy. There must be one shared witness; a valid signature under an unrelated key cannot authorize a selected coin.

## Release gates

| Gate | Required evidence | Status |
|---|---|---|
| Source pin/license | Immutable commit, Apache-2.0 notices, reproducible offline build | Snapshot identified; no 0PSP vendoring |
| Key generation | Reviewed entropy, explicit dealer/DKG model | OPEN |
| Signature/public-key encoding | Canonical versioned spec plus vectors | OPEN |
| Host-side threshold signature adapter | All rounds, session binding, negative tests | NOT IMPLEMENTED |
| Hidden-key verification predicate | Exact verification relation represented inside proof backend | OPEN |
| Implementation security | Source/binary/side-channel review | OPEN |
| Independent cryptographic review | Findings resolved | OPEN |

## Sources

- Ringtail paper: https://eprint.iacr.org/2024/1113
- Pinned upstream source: https://github.com/daryakaviani/ringtail/tree/1e181c356492e9360765cf27d58497018172ba3c
- Current upstream warning and module inventory: https://github.com/daryakaviani/ringtail/blob/main/README.md and https://github.com/daryakaviani/ringtail/blob/main/go.mod
- V2 relation and security gates: ../security/v2-protocol-security-argument.md

**Decision:** prepare the adapter against this contract only after the proof backend feasibility test confirms how it can represent Ringtail verification. A working standalone Go demo is not a 0PSP integration.
