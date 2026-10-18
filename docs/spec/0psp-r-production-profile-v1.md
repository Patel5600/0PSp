# 0PSP-R Production Profile v1 — Scope Freeze

**Decision status:** ACCEPTED / SCOPE LOCKED  
**Decision date:** 2026-10-18  
**Protocol/product name:** **0PSP-R**  
**Profile identifier:** `0PSP-R-PRODUCTION-V1`  
**Default cryptographic posture:** Classical-default, ratcheted sessions; optional, versioned PQ extension later.  
**Implementation status:** NOT COMPLETE. This document locks intended scope and release semantics; it is not implementation evidence, a deployment approval, or a security certification.

This specification is the source of truth for the 0PSP-R product boundary. Production-1 is still the repository's local synthetic test-value spend milestone. It must not be described as the completed 0PSP-R channel product.

## 1. Product contract

**0PSP-R = private value-note and ledger rules + encrypted ratchet sessions + funded bilateral channels and one-time settlement.**

The product optimizes for mobile practicality and an operable production state machine. Continuous OpenVM/full post-quantum proof generation for every spend is explicitly outside the default production profile. It remains a separate research/Vault Max track.

This is a scope freeze, not permission to weaken note integrity, channel authorization, state recovery, replay prevention, or value conservation. Those remain mandatory release requirements.

### 1.1 What belongs in the default release

| Layer | Default release target | Explicit boundary |
|---|---|---|
| Private value notes, commitments, nullifiers and tree rules | In scope | Each byte contract, hash domain and tree profile is versioned; a hash commitment does not by itself prove membership, value conservation or authorization. |
| Session establishment and payload protection | Ratchet + AEAD | Classical-default for v1. Authenticated identity binding, nonce/key discipline, replay and out-of-order handling are required. |
| Bilateral payment channel | Funded opening, monotonically sequenced state, dual authorization, timeout, dispute and one close | Off-chain messages do not independently change ledger state. Only a valid state transition/settlement can do that. |
| Settlement | Bound to the exact funded opening and accepted channel state | A channel ID/opening ID can be consumed only once. State rollback, stale close, replay and duplicate close must reject. |
| Settlement validation | Two-party signatures for explicitly public balance/state fields; a separately reviewed light proof where hidden values require it | Signature-only authorization does not prove a hidden arithmetic relation. Do not call a signature a zero-knowledge proof. |
| Optional sparse PQ session epoch | Future, separately versioned profile | Not enabled by default and not implemented merely because this specification mentions it. |
| Full OpenVM proof on every spend | Out of default production scope | Research/Vault Max only until a separate approved profile meets its own security, privacy and resource gates. |

### 1.2 What is not promised

0PSP-R v1 does not promise anonymity against network observers, unlinkability across every funding/settlement event, hidden public settlement amounts, perfect future quantum confidentiality of classical session recordings, or universal privacy comparable to a fully shielded pool with a complete zero-knowledge proof for every spend.

A relay, timing, participant metadata, funding path, dispute, or close transaction can reveal information even when session payloads are encrypted. The threat model must list the exact visible fields for the selected ledger and deployment.

## 2. Ratchet sessions: separate from settlement proofs

### 2.1 Default classical session profile

The intended default session profile is:

- X25519-based classical key agreement and a reviewed Double Ratchet construction.
- HKDF-SHA-256 with distinct, versioned protocol/context labels for root and chain derivation.
- ChaCha20-Poly1305 AEAD for session payloads, with correct per-message key/nonce handling.
- Associated data binds the protocol/profile version, session identifier, direction and canonical message header/counter.
- Message keys are single-use; skipped/out-of-order keys are bounded and expired; replays and authentication failures do not advance channel state.
- A ratchet message can carry a proposed channel update, but the channel update takes effect only after the channel's required authorization and validation succeeds.

This section is the suite target, not a claim that the current repository already implements it. Exact library versions, key encodings, transcript binding, nonce construction, state persistence and secure-erasure behavior must be pinned and tested before release.

**A ratchet is not a settlement proof.** It protects session message payloads under its cryptographic assumptions. It does not prove that a note exists, that a channel is funded, that a hidden balance is conserved, or that a ledger should consume a nullifier.

### 2.2 Optional sparse post-quantum sessions

A later optional PQ session profile may combine a classical ratchet with an audited sparse post-quantum key-agreement/ratchet construction. ML-KEM is a KEM, not a signature and not a complete authenticated messaging protocol. An eventual implementation must use an exact versioned KEM/ratchet specification and reviewed implementation, combine the classical and PQ secret material using a domain-separated KDF, bind the suite negotiation into authenticated context, and define epoch rotation, replay handling, missed epochs, key deletion and compromise recovery.

The first research candidate is a standardized ML-KEM suite, with parameter set, library, interoperability and current errata review to be pinned before implementation. Do not write a bespoke “occasional KEM mix” and call it SPQR. Evaluate the published Signal Double Ratchet revision 4 material on Sparse Post-Quantum Ratchet (SPQR), Triple Ratchet and PQXDH; adopt or adapt only through a separate review and versioned profile. PQXDH and the post-quantum ratchet are distinct protocol layers and must not be conflated with OpenVM.

PQ capability negotiation must be authenticated and explicit. A PQ-required profile must fail closed if the peer cannot negotiate its pinned PQ suite; there must be no silent fallback. The v1 classical-default profile openly selects classical-only protection and must report that profile, rather than pretending a PQ session is active.

## 3. Channel state machine

Every channel uses canonical, versioned encodings. A channel state minimally binds:

- protocol/version and authorization-policy identifiers;
- network/ledger identity and namespace;
- unique channel ID and funded-opening reference/hash;
- participants and the exact authorization keys/policy;
- asset identifier and funding reference/commitment(s);
- sequence number, previous-state hash and canonical current-state hash;
- balances or note commitments, fee and outputs as applicable;
- timeout/dispute policy and close mode.

The state hash and both parties' signatures cover the complete canonical state and the funded-opening hash. A signature over a display string, ratchet message, or incomplete field set is not sufficient.

### 3.1 Required state transitions

`UNFUNDED → OPEN → ACTIVE → (COOPERATIVE_CLOSE | DISPUTE) → CLOSED`

A separate funding/open timeout can move an unfunded or incompletely funded attempt into `EXPIRED/REFUNDABLE` only under the configured ledger policy. `CLOSED`, `EXPIRED` and a safety `FROZEN` state are terminal until a versioned recovery procedure allows otherwise.

- **UNFUNDED:** a proposed opening is not yet spendable. No channel balance may be settled.
- **OPEN:** the exact funding evidence/commitment and both participants' opening authorization are validated. The opening state hash is immutable.
- **ACTIVE:** updates are accepted only if the channel is open, `seq = previous seq + 1`, the previous-state hash is correct, the state satisfies the declared conservation/asset rules, and the required dual authorization is valid.
- **COOPERATIVE_CLOSE:** both parties authorize the exact final state and opening reference. It can finalize only if no pending ledger condition blocks close and the one-close invariant is satisfied.
- **DISPUTE:** a valid close/state is submitted unilaterally or a conflict is reported. A fixed challenge deadline begins. A counterparty can submit a newer valid, dual-authorized state before the deadline. The verifier enforces sequence monotonicity and the specified state-continuity rule.
- **CLOSED:** a single atomic ledger transition consumes the channel ID/opening close token, records the selected settlement state, and applies outputs/nullifiers exactly once. All later close attempts reject.
- **FROZEN:** inconsistent funding/state evidence, impossible transitions, finality rollback, corrupt persisted state or unresolvable authorization inconsistency stops settlement. Do not silently choose a convenient state or reopen a closed channel.

### 3.2 Conflict, timeout, offline and rollback rules

These rules are mandatory behavior, not optional implementation details.

1. **Rollback:** a lower-sequence state cannot replace a higher accepted candidate. A stale close is challengeable during the dispute window. Ledger restart/restore must revalidate state version, opening reference, unique channel ID, close record and accepted state hash.
2. **Conflicts:** two different state hashes at the same sequence are detected as a conflict, not resolved by network/mempool arrival order. The settlement profile must specify a deterministic arbitration rule or fail closed into `FROZEN` pending an explicitly defined recovery procedure. This decision must be implemented and tested before a channel is production-enabled.
3. **Offline peer:** a party may present a previously dual-authorized state only through the unilateral dispute flow. The counterparty gets the full configured challenge period to present a newer valid state. An unsent, unsigned or merely ratchet-encrypted payment message is not an authorized channel update.
4. **Timeout:** funding, dispute and finalization deadlines use the deployment's declared clock/block policy. Missing, stale or untrusted time/finality information must not auto-finalize a close.
5. **Double-close/replay:** each channel ID/opening close token is consumed exactly once, atomically with its outputs/nullifiers. Duplicate concurrent closes have at most one winner and no partial state updates.
6. **Conservation:** every accepted state must obey the asset's range and conservation rules. If values are hidden, the proof must establish those predicates; two signatures alone do not establish hidden arithmetic correctness.
7. **Reorg/recovery:** until a real finality source and reorg policy are implemented, this state machine is supported only against the currently declared local/test-value trust boundary. A local SQLite anchor window is not external consensus.

### 3.3 Funded-opening binding

The opening identity is a versioned digest of the network/ledger, namespace, channel ID, participant identities/keys, asset, canonical funding reference/commitments, initial state hash, authorization policy, parameter identifiers and timeout/dispute profile.

Every update and settlement binds that exact opening digest. The final close artifact binds at least `channel_id`, `opening_hash`, `state_seq`, `state_hash`, `close_mode`, `authorization_policy_id` and any required root/head/finality reference. The ledger consumes the channel/opening ID once even if the application retries a network request.

A close is invalid if the funding reference, participant/asset scope, namespace, state hash, sequence, authorization policy or required root/head differs from the opened channel.

## 4. Settlement proof policy

A settlement proof, a ratchet key agreement and an OpenVM proof have different jobs.

- **Public-balance close:** a dual signature over the canonical funded opening and final state can be sufficient for authorization only when all value/state predicates are publicly checkable and independently enforced by the ledger/contract.
- **Hidden-balance/note close:** a proof is required if the settlement must hide amounts or prove commitment openings, membership, value conservation or nullifier/output relations that the verifier cannot check publicly. Select and review a light classical proof system before enabling this profile. It must bind the same opening, state hash, asset, sequence, authorization and ledger effects.
- **Signature-only is not zero knowledge.** It cannot establish a hidden statement's truth when the verifier has no way to check the hidden predicate.
- **OpenVM is not the default settlement backend.** The current Production-1 OpenVM relation is a local synthetic test-value milestone with explicit witness-hiding and composed-security limitations. Any future Vault Max profile is separately named, opt-in and gated.
- **No settle-on-message:** a decrypted ratchet payload must never directly mutate ledger state without the signed state-transition/settlement checks and atomic one-close rule.

No light proof backend is selected by this scope decision. If hidden amount settlement is a hard product requirement, its implementation remains a release blocker until a candidate is selected, reviewed, measured and integrated.

## 5. Accepted post-quantum trade-off — normative limitation

The following limitation block is accepted as part of the 0PSP-R v1 product contract:

> **WE AGREE**
>
> 1. The default path optimizes mobile UX and production operability.
> 2. Continuous post-quantum proof-per-spend is OUT of production scope.
> 3. Ratchet + AEAD do NOT by themselves provide post-quantum confidentiality of past session keys against a future quantum adversary.
> 4. Ledger nullifiers/commitments use hash-based objects where specified; settlement authorization uses classical signatures/proofs unless a versioned PQ suite is negotiated and pinned.
> 5. “Harvest now, decrypt later” on classical session traffic remains a residual risk until a PQ session handshake + rekey policy is implemented and enabled.
> 6. Optional PQ epoch / vault mode may be added later without changing the default production threat model above.

This trade-off is deliberately explicit. Classical ratchet key evolution can offer forward secrecy and recovery properties under classical assumptions; it must not be described as quantum-resistant. Hash-based objects do not make classical signatures, X25519 session establishment, the entire protocol, or the selected proof system post-quantum. The accepted trade-off applies to 0PSP-R v1 only; it does not waive ordinary cryptographic correctness, key management, implementation safety or authorization requirements.

### 5.1 Versioning and downgrade requirements for future PQ support

- Classical v1 and any PQ/hybrid epoch have distinct protocol/profile IDs and canonical encoding.
- Authentication covers the negotiated profile/capability set, protocol version, KEM suite, epoch number and transcript context.
- Unknown versions, malformed encapsulations, key/epoch replay and suite mismatch reject fail-closed.
- A user/account/channel policy that requires PQ must never silently downgrade. Classical-only use is permitted only under an explicit classical-default policy and must be visible as such.
- Mixing classical and PQ secrets must follow a reviewed hybrid combiner/KDF specification. Do not invent a combiner or assume that merely concatenating secrets is automatically secure.
- Replacing the classical default with PQ-required behavior is a new release profile decision and needs interoperability, performance, security and migration tests.
- Until the future profile is implemented and enabled, do not advertise 0PSP-R default session payloads as PQ-protected.

## 6. OpenVM / Vault Max boundary

OpenVM continuous proof-per-spend remains **research / Vault Max**, not the default production route. It may later provide a separately versioned proof profile after the exact guest, transcript, verifier, witness-hiding properties, full relation, soundness analysis and resource budget are established.

The present OpenVM work remains useful research. The repository's current Production-1 local synthetic test-value path is not equivalent to a complete 0PSP-R deployment. It does not by itself implement the ratchet, channel state machine, a funded production opening, public-chain issuance/finality, or the future PQ session extension.

## 7. Release acceptance checklist

No one may call the 0PSP-R production profile implemented until all applicable checklist items have evidence on the same release candidate SHA.

### Channel / ledger
- [ ] Opening binds the exact verified funding reference, network/namespace, asset, parties, auth policy and initial state.
- [ ] State hashes are canonical and link to the previous state; sequence is monotonic and fully dual-authorized.
- [ ] Rollback, stale close, same-sequence conflict, timeout, offline-peer dispute, duplicate/replayed close and concurrent close tests pass.
- [ ] Exactly one close token/channel ID is consumed atomically with ledger outputs and nullifiers.
- [ ] Crash/restart, corrupted state, backup/restore and supported reorg/finality failure modes are tested.
- [ ] Every failure rejects without partial ledger or value/accounting changes.

### Session / ratchet
- [ ] Standard ratchet and AEAD implementation, exact suite/version and dependency pins are declared.
- [ ] Handshake identity/authentication and transcript binding are reviewed.
- [ ] Replay, out-of-order messages, skipped-key bounds, key deletion, corrupted ciphertext, altered associated data and state rollback are tested.
- [ ] Ratchet payload processing cannot bypass channel sequence, dual auth or settlement validation.
- [ ] Logs, crash artifacts and worker APIs do not unintentionally expose session secrets, message keys or plaintext payment content.

### Settlement / cryptographic honesty
- [ ] Signature-only settlement is used only for public, independently verifiable value/state predicates.
- [ ] Any hidden amount/note profile has a separately selected light proof with explicit relation, binding and security claims; OpenVM is not silently used as default.
- [ ] Hash-based commitment/nullifier claims are scoped to their exact constructions; no unsupported composite PQ or zero-knowledge claim is made.
- [ ] Classical session, signature and proof residual risk is included in user/deployment documentation.

### Optional PQ / Vault Max
- [ ] Not required for the classical-default v1 release.
- [ ] If enabled in a future profile: exact ML-KEM parameter set/library, current errata review, hybrid combiner, authenticated capability negotiation, sparse rekey/epoch recovery, downgrade/replay tests and interoperability results are pinned.
- [ ] OpenVM/Vault Max has its own full relation, witness-hiding, soundness and resource gates; passing the session KEM tests does not close those gates.

## 8. Scope-change control

The following are locked for 0PSP-R v1: classical-default ratcheted sessions; AEAD-only message payload protection; dual-authorized, sequence-bound channel states; one-time settlement tied to a funded opening; signature-only close only for independently checkable public state; optional light proof only when hidden-state predicates require it; continuous OpenVM/full PQ proof-per-spend outside the default profile; and explicit acceptance of the six PQ limitations above.

Any change to the default trust model, channel authorization, state machine, settlement privacy, session suite, PQ downgrade policy or proof backend requires a versioned decision, updated limitations, adversarial tests and a release-gate review. This scope decision does not close implementation blockers or enable Mainnet/public testnet value.

## 9. Implementation tracking

- **[Issue #62 — implement 0PSP-R ratchet sessions, funded channels and one-time settlement](https://github.com/Patel5600/0PSp/issues/62):** P0 implementation gate for the locked v1 profile. It covers the classical-default ratchet/session, channel state machine, settlement binding, conflict/rollback/offline/timeout behavior and one-close ledger rule.
- **[Issue #63 — research optional sparse PQ session epoch after v1](https://github.com/Patel5600/0PSp/issues/63):** future/P2 track. Do not start it as a prerequisite to v1 and do not mix it with ZK settlement or OpenVM proof-per-spend work.

Issue #62 and the existing gates in #33–#47/#42 must be evidenced on one exact release candidate before anyone describes the 0PSP-R product as production-ready.

## 10. Design references

These upstream documents inform future implementation and are not proof that 0PSP-R currently inherits their security properties:

- NIST, [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final). NIST's publication page records a planning note dated 2025-11-17 describing an issue to be corrected in a future revision; check the current errata before pinning an implementation.
- Signal, [The Double Ratchet Algorithm, revision 4 (2025-11-04)](https://signal.org/docs/specifications/doubleratchet/), including the Sparse Post-Quantum Ratchet and Triple Ratchet sections.
- Signal, [PQXDH Key Agreement Protocol](https://signal.org/docs/specifications/pqxdh/). PQXDH is a key-agreement protocol, not a substitute for the Double Ratchet or settlement proof. Its described revision retains a classical discrete-log assumption for mutual authentication.
- The repository's [Production-1 limitations](../LIMITATIONS.md), [Production gate matrix](../security/production-gate-matrix.md), [Production-1 gap report](../security/PRODUCTION1_GAP.md) and [master release tracker](https://github.com/Patel5600/0PSp/issues/42).

**Final status:** scope locked; implementation incomplete; current test-value profile only. Public testnet value and Mainnet live value remain NO-GO until their separate release gates pass.
