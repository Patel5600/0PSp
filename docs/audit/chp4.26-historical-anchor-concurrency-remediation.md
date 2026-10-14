# CHp4.26 — Historical Anchor Window and Concurrent Spend Remediation

**Status:** local SQLite remediation candidate on `fix/historical-anchor-concurrency-2026-10-13`; code-bearing commit `37e9412a7c7f8111ebee5a1fd707a463a24339df` passed Functional Checks (475 tests) and Repository Integrity Watch. This proves only the exercised local-ledger behavior. Any subsequent code or documentation commit needs fresh exact-head checks. PR #32 remains draft pending review.  
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

The new `SQLiteLedger.spend_context(commitment)` operation obtains the current snapshot and the commitment's Merkle membership path in one read transaction. Wallet/prover callers should use it rather than reading a snapshot and path separately, which could otherwise mix data from two tree versions. `audit_integrity()` also uses one explicit read transaction across its reconciliation queries; otherwise a concurrent write could make separate SELECT statements observe different committed states and produce a false audit failure. Because this project uses rollback-journal mode, a long audit can delay a concurrent writer's commit. Target-ledger-scale audit latency has not been measured, so startup/maintenance contention remains an operational limit to test before production.

## 5. Regression coverage and exact-head CI evidence

The remediation branch adds or updates tests for:

- both unrelated spends succeeding when verified concurrently against the same retained anchor;
- only one of two concurrent spends with the same nullifier committing;
- successful spend verification against an older but retained root/head pair after an unrelated state advance;
- rejection when the anchor has expired;
- schema-v1 anchor-history migration with unchanged ledger snapshot;
- atomic snapshot plus membership-path consistency;
- concurrent first-open initialization, forcing two openers to race on schema/anchor-table detection;
- an explicit assertion that integrity reconstruction runs inside one consistent SQLite read transaction;
- rejection of a valid-length but tampered historical anchor root;
- full integrity reconstruction after transitions.

These are code-level state-machine tests, not a cryptographic proof. At code-bearing commit `37e9412a7c7f8111ebee5a1fd707a463a24339df`, [Functional Checks run 38528642753](https://github.com/Patel5600/0PSp/actions/runs/38528642753) passed with `475 passed in 8.99s`; [Repository Integrity Watch run 38528642727](https://github.com/Patel5600/0PSp/actions/runs/38528642727) succeeded. The tests cover retained-anchor accept/expiry, concurrent spends, duplicate-nullifier race, schema-v1 migration, concurrent fresh initialization, single-snapshot audit and a valid-length corrupted anchor. Results apply to that exact code-bearing SHA only.

## 6. What this does not fix

This change addresses the stale-moving-head concurrency defect only. It does **not** remediate the audit's other major findings:

- **V2 nullifier privacy/front-running:** the frozen V2 nullifier does not include a recipient-held secret. The V3 candidate in PR #10 changes the protocol contract, remains unmerged, and lacks enforcement in a complete accepted ZK relation. It must not be merged or deployed as a primitive-only patch.
- **Composite STARK/FRI soundness:** the full bound must be derived for one pinned proof composition, field/extension, trace, FRI rate/query count, transcript, masking and quantum Fiat–Shamir model. A proof-of-work multiplier cannot be asserted by itself.
- **OpenVM NOAUTH:** PR #31 is explicitly research-only. No production authorization, trusted root/finality binding, complete relation or end-to-end proof is established.
- **Backend feasibility:** the dense SmallWood adapter memory model and unbuilt/unreviewed Aurora/libiop candidate remain NO-GO until an actual backend is pinned, built, constrained, adversarially tested and benchmarked.
- **Issuance/custody/value binding, authorization, privacy, side-channel behavior, distributed consensus, reorg/backup/power-loss recovery and full internal composition review:** still open production gates. External cryptographic audit is intentionally deferred until after launch and is not a pre-launch gate.

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

The SQLite candidate remains single-node persistence. The local event hash chain and anchor ring do not provide distributed consensus or external protection against a privileged actor rewriting the complete database. The full protocol remains **NO-GO** until the exact proof relation, recipient authorization policy, trusted deposit/custody adapter, anchor/finality contract and recovery model are instantiated, exercised adversarially and internally reviewed with reproducible evidence. External cryptographic audit remains **NOT PERFORMED** and is a separate post-launch milestone, not a launch gate.


## 9. CI and evidence chronology — 2026-10-14

Failed attempts are retained in the record; they are not rewritten as successes:

- PR #32 head `ac6b4908622aa12d124c1a968e511e388da0ed08` had Functional Checks [run 38526541253](https://github.com/Patel5600/0PSp/actions/runs/38526541253) fail during pytest collection because a V3 candidate test imported implementation modules missing from the base branch. Repository Integrity Watch [run 38526541334](https://github.com/Patel5600/0PSp/actions/runs/38526541334) passed. This was a test/source placement defect, not evidence for or against the SQLite code.
- PR #48 removed that orphaned test from `main` and merged as `b13368326b8a515b4efd762efb0d5ee1237060a3`. The test was added with the V3 candidate implementation on PR #10; its exact head passed [Functional Checks run 38527035073](https://github.com/Patel5600/0PSp/actions/runs/38527035073) with 594 tests and [Repository Integrity Watch run 38527035065](https://github.com/Patel5600/0PSp/actions/runs/38527035065). The separate OpenVM feasibility job remains non-production and must not be treated as the full spend relation.
- The first anchor-ring tamper test on head `d811426ff341049f31256df79b58614743229fa8` failed because the test supplied a wrong-length byte string, correctly rejected by SQLite before the audit ran. That was a **test-fixture defect**, not a successful security check. The corrected 48-byte fixture at `9c24eecc306475e2f5fa47485901197d519f6680` passed [Functional Checks run 38527806198](https://github.com/Patel5600/0PSp/actions/runs/38527806198) with 473 tests and [Repository Integrity Watch run 38527806232](https://github.com/Patel5600/0PSp/actions/runs/38527806232).
- Strict follow-up review then found a TOCTOU in fresh schema initialization: the anchor-table existence query ran before `BEGIN IMMEDIATE`. The query was moved under the write lock, and a deterministic concurrent-first-open regression was added. Functional Checks [run 38528394760](https://github.com/Patel5600/0PSp/actions/runs/38528394760) passed 474 tests; Repository Integrity Watch [run 38528394756](https://github.com/Patel5600/0PSp/actions/runs/38528394756) succeeded.
- Further review found that multi-query `audit_integrity()` did not pin a single read snapshot. The audit now runs in one read transaction and an invariant test checks that boundary. At code-bearing commit `37e9412a7c7f8111ebee5a1fd707a463a24339df`, [Functional Checks run 38528642753](https://github.com/Patel5600/0PSp/actions/runs/38528642753) passed `475 passed in 8.99s`; [Repository Integrity Watch run 38528642727](https://github.com/Patel5600/0PSp/actions/runs/38528642727) succeeded.

All cited runs are tied to the exact code SHA just named. Any later commit needs its own checks. These are internal software-regression evidence only; they do not prove cryptographic soundness, complete proof enforcement, production authorization or launch readiness. External cryptographic audit is **NOT PERFORMED**, intentionally deferred, and not a pre-launch gate.
