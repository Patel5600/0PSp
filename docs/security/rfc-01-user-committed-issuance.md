# RFC-01 — User-Committed Issuance with Issuer Privacy

**Status:** design candidate; **BLOCKED**. No live mint implementation is proposed by this RFC.  
**Security status:** this document is not a proof of hiding, binding, issuance correctness or unlinkability.  
**Normative companion:** [Evidence-first RFC register](evidence-first-rfc-register.md).

## 1. Problem and objective

The mint must not learn the wallet's per-coin `coin_id` or nullifier secret `r_nf`, because knowing both lets it compute the public nullifier and match a later spend to an issuance record. The client can generate these values locally and commit to them before issuance.

The candidate must also bind the value and deposit accepted by the mint to the value used in the spend relation. Issuer privacy must not create an unverified value gap.

## 2. Existing V2 commitment candidate

The repository already implements the following 48-byte candidate commitment in Python and native OpenSSL code:

```text
C = SHAKE256-384(
  "0PSP-COIN-COMMIT-v2-SHAKE256" || 0x02 ||
  u16le(len(params_id)) || params_id ||
  u32le(len(canonical_pk)) || canonical_pk ||
  u64le(value) ||
  u16le(48) || namespace_id[48] ||
  u16le(32) || coin_id[32] ||
  u16le(36) || r_nf[36] ||
  u16le(36) || rho_C[36])
```

The present code has fixed Python/native vectors and opening-substitution tests. The exact public-key encoding is not frozen until a signature scheme/parameter codec is selected. The 36-byte `rho_C` must be fresh and independently generated; never reuse it as `r_nf` or across coins.

This is a **single-commitment candidate**, not evidence of a fully specified blind issuance protocol. No additional `C_spend` layer is added by this RFC. That would add complexity without a demonstrated role.

For the current EVM mapping, the 48-byte namespace field is the output of the direct-hash Namespace V3 construction. “V2” in CommitV2 names the commitment encoding and does not select the namespace-derivation version. A future issuance proof and accepted parameter set must pin Namespace V3 and bind these exact 48 bytes to the authenticated chain/deployment/asset context. A raw 48-byte value or a legacy V2 namespace must not be silently accepted as interchangeable. The reference ledger now requires the typed NamespaceIdV3 at its API boundary, but no cryptographic issuance verifier is integrated.

## 3. Candidate message flow

### Wallet

1. Generate `coin_id`, `r_nf` and `rho_C` using a reviewed fail-closed CSPRNG path.
2. Construct `C` using the frozen V2 byte contract.
3. Obtain a proof `pi_issue` for the issuance statement below, without disclosing the opening.
4. Submit `(namespace_id, C, v, deposit_tx, pi_issue)` to the mint.

### Mint

1. Validate the deposit and determine the amount authorized by the trusted ledger/asset adapter.
2. Verify that the stated `v` equals the value authorized by `deposit_tx`.
3. Verify `pi_issue`, which must bind `C`'s hidden opening to that exact `v`, namespace and accepted parameter set.
4. Enforce deposit replay protection and the defined uniqueness policy atomically.
5. Commit `(namespace_id, C, v, deposit_tx, protocol_version)` and the state update in one durable transaction.
6. Return a receipt over the canonical record and the committed state version/root.

The mint never receives `coin_id`, `r_nf`, `rho_C`, or the hidden key opening in the intended privacy model. This is a target, not current repository behavior.

## 4. Blocking gap: how does the mint verify value binding?

The mint cannot hash a hidden opening it does not know. Seeing a 48-byte `C` and a separate public `v` is not enough to confirm that the hidden opening of `C` contains that `v`.

A signed receipt over `(C, v, deposit_tx)` proves only that the mint recorded those fields. It does not prove that the commitment opens to the recorded value.

A required issuance relation has at least this structure:

```text
Public statement:
  x_issue = (protocol_version, namespace_id, C, v,
             deposit_tx, ledger_state, params_id)

Witness:
  w_issue = (canonical_pk, coin_id, r_nf, rho_C,
             any required private deposit/ownership witness)

Relation:
  1. C = CommitV2(namespace_id, canonical_pk, v,
                  coin_id, r_nf, rho_C, params_id)
  2. deposit_tx authorizes exactly v for this namespace/asset
  3. the deposit/receipt has not been replayed
  4. any required ownership, eligibility, and issuance policy holds
```

The proof must be zero knowledge for the specified adversary model and sound for the exact relation. A general-purpose proof backend is not integrated, so `pi_issue` is currently unavailable. Until that is solved, issuance is blocked. The alternative is a different reviewed issuance construction; simply trusting the caller is not an acceptable implicit substitute.

If `v` is intentionally public, the statement may expose it. If value confidentiality is required, the asset/deposit interface and relation must be redesigned rather than assuming the current public-`v` flow hides amounts.

## 5. State invariants

- The mint records the namespace and canonical commitment.
- The accepted public value must equal both the deposit-authorized value and the value constrained by the commitment opening in `pi_issue`.
- A deposit identifier cannot be consumed twice.
- The same accepted coin cannot be registered under multiple accepted records through a replay, alternate encoding, or state race.
- Every valid spend relation opens the exact registered `C` and uses the committed `coin_id` and `r_nf`.
- The nullifier is deterministic for that opening; the durable ledger atomically rejects a repeated public nullifier.
- Reorg, migration, recovery and concurrent writes must preserve the same invariants.

**Critical unresolved identity-policy decision (CHp4.3):** the issuer cannot directly compare a hidden `coin_id` against a plaintext registry without learning it. Global uniqueness therefore remains either (a) a requirement to satisfy through a reviewed privacy-preserving mechanism, or (b) an invariant to revise through an explicit, reviewed policy decision. The second option is not approved by this RFC. See [CHp4.3 identity-invariant review](../audit/chp4.3-identity-invariant-decision-review.md).

Deposit replay protection and hidden-ID uniqueness are different properties. Enforcing one accepted issuance per canonical deposit does not imply global uniqueness of hidden IDs, because valid transfer transactions can create multiple outputs without each output representing a new external deposit.

A further risk must be analyzed: two distinct commitments may use the same hidden `(namespace_id, coin_id, r_nf)` but different commitment salts. The commitments can differ while the deterministic V2 nullifier is the same. The nullifier set can reject a second spend, but then one of the distinct notes may be unspendable. It is not valid to assert that an attacker necessarily harms only themself; outputs can be created for recipients. The wallet/output relation, recipient threat model, and malicious-witness constraints must address this before any global-uniqueness reduction is accepted.

Do not derive `coin_id` from public deposit identifiers under the current issuer-private target. Keep the existing V2 commitment and nullifier byte contracts frozen. This document does not decide the identity policy, and production remains **NO-GO**.

## 6. Privacy claims and limits

The desired claim is **cryptographic issuer unlinkability under an explicit leakage model**, not “100% unlinkable”. The model must account for deposit/spend amounts, timestamps, network metadata, anonymity-set size, public outputs, corrupted parties and whether the issuer colludes with observers.

Keeping `coin_id` and `r_nf` from the issuer removes the direct nullifier-precomputation link. It does not prove transcript unlinkability. The commitment's quantum-random-oracle-model hiding argument and the end-to-end proof/metadata game remain open.

## 7. Test plan and what existing tests mean

The primitive-level test file `tests/unit/test_issuance_commitment_invariants.py` checks:

- the same opening verifies for the same commitment;
- changing `coin_id`, `r_nf`, value, namespace, key bytes, salt, or parameters does not verify as the same opening;
- the same nullifier inputs produce the same result.

The CHp4.1 file `tests/unit/test_reference_ledger_state_machine.py` checks the in-memory state model with injected test doubles: authenticated-value plumbing, proof-rejection non-mutation, deposit replay, duplicate commitments/nullifiers, and concurrent attempts.

CHp4.2 adds `tests/adversarial/test_v2_witness_substitutions.py` for real Python V2 reference primitive substitutions and `tests/adversarial/test_issuance_replay.py` for the in-memory duplicate-deposit transition. The latter uses a test-double verifier. These are regression tests, not proof verifiers.

Neither file implements a cryptographic issuance verifier. These tests do **not** prove:
- issuance value/deposit binding without revealing the opening;
- absence of a collision across all inputs;
- a ZK proof rejects alternate witnesses;
- atomic duplicate-deposit or spent-nullifier prevention in a durable/consensus ledger;
- issuer unlinkability in the full transcript.

### Required tests before implementation

1. Fixed independent known-answer vectors for the new issuance relation and all canonical encodings.
2. Negative proof tests for altered value, deposit, namespace, commitment, parameters, coin ID and `r_nf`.
3. Replay and duplicate-record tests against the actual ledger state machine.
4. Concurrency test proving at most one successful transition for the same deposit and for the same nullifier in a local model, followed by durable-ledger tests under the chosen chain's consensus model.
5. Adversarial issuer/observer unlinkability game with explicit corruption and leakage model.
6. End-to-end native/reference/proof-backend parity tests.

## 8. Acceptance and decision

**Accept the RFC as a design/work package, not as an implemented protocol.** CHp4.1 supplies a testable local state-transition model only. It does not satisfy the issuance-proof, real deposit-adapter, durable ledger, finality/reorg, or independent-review gates. Production status remains **NO-GO**.
