# CHp4.26 — Historical Anchor Window and Concurrent Spend Remediation

**Status:** implementation candidate on `fix/historical-anchor-concurrency-2026-10-13`; exact-head CI is required and PR #32 is the current status source.  
**Scope:** SQLite state progression and the host/API anchor contract only.  
**Production decision:** **NO-GO**. This change does not instantiate or prove the spend relation.

## 1. Finding and invariant

The previous SQLite candidate required a spend statement's state head and commitment root to equal the current ledger head/root both before proof verification and again after proof verification. Since proving/verifying may overlap with unrelated accepted transitions, valid in-flight transactions could repeatedly fail with `StaleLedgerState`. Deleting those checks outright would be unsafe: the ledger still needs to know that the submitted root/head pair was actually published, and the transition must consume nullifiers atomically.

The remediation uses a bounded historical anchor set. The invariant is:

> A spend may be accepted only if its exact `(commitment_root, ledger_state_head)` pair is in the retained anchor history at initial validation and remains retained at the atomic commit point. Its nullifier and every output commitment must be unused in the current durable state. Outputs append to the latest tree, never to a stale tree snapshot.

## 2. Bounded anchor semantics

- `ANCHOR_WINDOW = 256` counts **committed local ledger state versions**, not Ethereum blocks or seconds.
- If current version is (v), the retained inclusive range is ([\max(0, v-255), v]). The table retains at most 256 exact tuples `(state_version, state_head, commitment_count, commitment_root)`.
- The root and head must match the same recorded anchor row. A root from one version combined with a head from another is invalid.
- The submitted pair is checked before expensive proof verification and rechecked inside `BEGIN IMMEDIATE`. If it expires while verification runs, the operation fails closed and the caller must obtain a newer anchor and produce a new proof.
- If unrelated transactions advance the ledger but the anchor remains retained, they do not alone invalidate the spend. Inside the write transaction, the implementation uses the latest root/head/count to append outputs and update state.
- Duplicate nullifiers and duplicate output commitments are checked against current durable rows while the write transaction holds the write lock. Their uniqueness constraints remain the replay-protection boundary. Two spends attempting to consume the same nullifier cannot both commit.

The historical membership path is checked against the root named by the transaction, not silently rewritten to the latest root. The commitment tree is append-only, so earlier leaves remain in later roots, but the proof must still bind the exact anchor/path/witness semantics defined by the selected proof system.

## 3. State machine

1. Decode canonical TxFieldsV2, reject duplicated-public-field mismatches, and recompute TxDigestV2.
2. Look up the exact root/head pair in the retained anchor table. Reject missing, mismatched or expired anchors.
3. Invoke the configured proof verifier. This callback remains an injected interface; the repository does not yet provide an accepted production verifier.
4. Start `BEGIN IMMEDIATE` and check the same root/head pair against the current retained range. Do not require the entire state version to remain unchanged.
5. Reject an already-spent nullifier and any output commitment already present.
6. Append outputs in canonical order to the current Merkle root; insert the spent-nullifier record and event-chain event; update metadata; insert the new anchor and trim the ring; commit everything atomically.

The issuance path also records the new state anchor in the same database transaction as its issuance/event/tree mutation. Anchor history is not an independently trusted source: startup `audit_integrity()` reconstructs state heads, roots and counts from the canonical transition/event history and rejects an anchor table that differs from the derived last-256 window.

## 4. Schema migration and recovery

The schema version advances from 1 to 2 with an additive `commitment_anchors` table. When upgrading a pre-anchor database, the implementation reconstructs the ring from its existing event and transition records. Table creation, schema-version change and anchor backfill run in one SQLite transaction so a process crash cannot commit a partially populated migration. A subsequent startup still runs `audit_integrity()` before accepting new transitions.

The new `SQLiteLedger.spend_context(commitment)` operation obtains the current snapshot and the commitment's Merkle membership path in one read transaction. Wallet/prover callers should use it rather than reading a snapshot and path separately, which could otherwise mix data from two tree versions.

## 5. Regression evidence required

The remediation branch adds or updates tests for:

- both unrelated spends succeeding when verified concurrently against the same retained anchor;
- only one of two concurrent spends with the same nullifier committing;
- successful spend verification against an older but retained root/head pair after an unrelated state advance;
- rejection when the anchor has expired;
- schema-v1 anchor-history migration with unchanged ledger snapshot;
- atomic snapshot plus membership-path consistency;
- full integrity reconstruction after transitions.

These are code-level state-machine tests, not a cryptographic proof. Exact-head CI must pass before merge; the workflow result applies only to the exact commit shown in PR #32, and any subsequent commit requires fresh checks.

## 6. What this does not fix

This change addresses the stale-moving-head concurrency defect only. It does **not** remediate the audit's other major findings:

- **V2 nullifier privacy/front-running:** the frozen V2 nullifier does not include a recipient-held secret. The V3 candidate in PR #10 changes the protocol contract, remains unmerged, and lacks enforcement in a complete accepted ZK relation. It must not be merged or deployed as a primitive-only patch.
- **Composite STARK/FRI soundness:** the full bound must be derived for one pinned proof composition, field/extension, trace, FRI rate/query count, transcript, masking and quantum Fiat–Shamir model. A proof-of-work multiplier cannot be asserted by itself.
- **OpenVM NOAUTH:** PR #31 is explicitly research-only. No production authorization, trusted root/finality binding, complete relation or end-to-end proof is established.
- **Backend feasibility:** the dense SmallWood adapter memory model and unbuilt/unreviewed Aurora/libiop candidate remain NO-GO until an actual backend is pinned, built, constrained, adversarially tested and benchmarked.
- **Issuance/custody/value binding, authorization, privacy, side-channel behavior, distributed consensus, reorg/backup/power-loss recovery and external review:** still open production gates.

## 7. Audit finding disposition

| Finding in the supplied audit | Action in this remediation branch | Remaining disposition |
|---|---|---|
| Composite BabyBear STARK/FRI and Fiat-Shamir soundness claim | No numeric multiplier or extension-field parameter was guessed. The checked-in historical evaluator explicitly labels the quotient and FRI expressions as isolated arithmetic scenarios, not a composite bound. | **OPEN / NO-GO.** Pin the actual AIR, backend commit, field/extension, FRI rate/queries, transcript, masking and quantum Fiat-Shamir model, then prove the exact composed bound. Do not claim 128-bit PQ soundness from an arbitrary 16-bit grind factor or a query-count formula alone. |
| LoTRS v2 lattice parameters and old 128-bit claims | Existing related-work calibration labels the parameters as evidence, not a security baseline, and explicitly says its estimator outputs do not substantiate 128-bit post-quantum security. The LoTRS Layer-2 design is marked historical/not active V0. | **RETIRED / NO-GO for active use.** No LoTRS parameter or historical ring-signature claim is adopted by this branch. |
| V2 sender-linkable nullifier / front-running risk | Added explicit warnings to the Python API module, native V2 header and V2 security argument. The byte contract is not changed. | **OPEN / NO-GO.** PR #10's recipient-keyed V3 is unmerged and its complete proof relation is absent. Do not mark privacy fixed by merging a primitive alone. |
| SQLite stale-moving-head race | Added retained historical anchor validation, atomic commit-time revalidation, current-state append, audit reconstruction, transactional migration, consistent spend-context API and concurrency/expiry/migration tests. | Candidate state-machine fix; require exact-head CI and review. Anchor expiry is intentionally bounded. |
| OpenVM guest authorization and trusted-root binding | No unsafe NOAUTH guest was promoted into the accepted ledger path. PR #31 remains explicitly NOAUTH, with incomplete root/consensus binding and missing lockfile/e2e proof evidence noted in its own review. | **OPEN / NO-GO.** Require full authorization, trusted anchor binding, reproducible dependency lock and end-to-end proof/verification evidence. |
| Keccak proving cost, SmallWood dense memory blowout, Aurora/libiop readiness | Kept them classified as static estimates or infeasible/unvalidated backend candidates; no synthetic benchmark or code stub was substituted for a real proof. | **OPEN / NO-GO.** Choose and pin a maintained backend, implement the complete relation, run adversarial proof tests and measure memory/time/proof size on target hardware. |
| Carry recurrence and EVM MPT/state proofs cited positively in the audit | Kept the carry AIR marked historical/not active V0 with no compiled proof. Existing MPT/EIP-1186 tests remain scoped conformance evidence only. | No production assurance inferred: consensus finality, full proof relation, custody, external anchoring and independent review remain separate gates. |

## 8. Release decision

The SQLite candidate remains single-node persistence. The local event hash chain and anchor ring do not provide distributed consensus or external protection against a privileged actor rewriting the complete database. The full protocol remains **NO-GO** until the exact proof relation, recipient authorization policy, trusted deposit/custody adapter, anchor/finality contract and recovery model are instantiated and independently reviewed. External cryptographic audit remains **NOT PERFORMED**.
