# 0PSP Production Gate Matrix

**Maintained against:** main at CHp4.17 plus the CHp4.18 canonical-transaction candidate.  
**Current overall production status: NO-GO.**  
**External cryptographic audit:** NOT PERFORMED, and deliberately tracked separately as requested. That does not convert missing implementation or proof obligations into GO.

## Status rule

Every gate below has a binary production status. **GO** means the exact gate described has adequate implementation and evidence for its limited scope. It does not automatically approve the complete protocol. **NO-GO** means the release criterion is not met; a green unit-test job, user risk acceptance, or an external-audit deferral cannot substitute for missing security behavior.

## Gate register

| Gate | Production status | Evidence currently available | Condition required to change status |
|---|---|---|---|
| Namespace V2 frozen core | **GO** | Frozen formula and known-answer tests; unchanged by CHp4.9+ | No change planned; any formula change requires a new version and review |
| Namespace V3 direct-hash EVM descriptor encoding | **GO** for the deterministic codec only | Canonical length-prefixed tuple, typed NamespaceIdV3, Python/native KAT parity | A real deployment manifest is a separate gate; no collision-free claim is made |
| CommitV2 / NullifierV2 host/native byte contracts | **GO** for the primitive APIs | Fixed vectors and Python/native parity | The proof backend must still enforce one shared opening; see separate gate |
| Ethereum Keccak/RLP/MPT reference implementation | **GO** for conformance-tested library behavior only | CHp4.16 differential tests against independent test libraries; substitution and malformed-input tests | No claim of complete cryptographic audit; production composition requires authenticated headers and the approved deployment policy |
| EIP-1186 account/storage proof algorithm | **GO** for the tested proof function only | CHp4.15 account/storage inclusion/exclusion tests and state-root binding | Live Mainnet proof acquisition and authenticated-header integration are separate NO-GO gates |
| Durable single-node SQLite issue/spend state transitions | **GO** for the isolated single-node persistence contract | CHp4.17 atomic transitions, uniqueness constraints, tree/event-chain audit on startup, concurrency/corruption regressions | No distributed consensus claim; integrate trusted authorization and actual proof verifier before live assets |
| Canonical TxFieldsV2 host codec and TxDigestV2 | **NO-GO** until CHp4.18 exact-head CI is green | Candidate codec, KAT, strict decoder, both ledgers reject mismatches before callback | Pass exact-head CI; independent implementation/circuit must reproduce the exact encoding |
| ZK transaction-digest binding | **NO-GO** | Host validates public bytes only | Actual proof backend constrains the exact TxFieldsV2 bytes/digest as public inputs |
| CommitV2 opening and commitment membership inside one proof | **NO-GO** | Host hash helpers and reference depth-63 tree exist | Backend proves the exact CommitV2 opening plus the 63-level namespace-bound membership path |
| Same-witness NullifierV2 binding | **NO-GO** | Nullifier primitive and finite substitution tests exist | Backend proves the nullifier uses the identical coin_id and r_nf used by the accepted commitment opening |
| Value conservation / output-opening relation | **NO-GO** | Requirement documented in RFC-02; host statement shape only | Backend proves input value = all output values + fee with range/overflow checks and every output value bound to its commitment |
| Authorization mode and canonical public-key codec | **NO-GO** | Ringtail adapter contract and research notes | Freeze the supported policy, exact codecs/parameters, key generation/dealer model, transaction message, and verifier behavior |
| Authorization predicate inside the accepted spend relation | **NO-GO** | No production Ringtail adapter or instantiated hidden-key predicate | The actual proof or an explicitly approved public authorization rule must bind the exact transaction digest to the selected policy; no unrelated-key authorization |
| Trusted EVM DepositAuthorization | **NO-GO** | Helios header path, transaction/receipt inclusion, event policy, movement signals and state proofs exist as separate components | One fail-closed composition must verify a real deposit under an explicitly reviewed custody contract/asset policy and be the only path accepted by the ledger |
| Contract/token custody semantics and upgrades | **NO-GO** | Event/value/Transfer/code-fingerprint consistency checks | Pin and review actual deployed source/build artifacts, proxy/admin/implementation history and the custody invariant; no generic Transfer-log assumption |
| Coin-ID reuse and same-nullifier output policy | **NO-GO** | OS-backed RNG; CHp4.3 review describes the identity/aliasing risk | Resolve global hidden-ID policy and prove recipient spendability/output identity behavior; random generation alone is not enforcement |
| Issuer privacy, commitment hiding and linkability model | **NO-GO** | Candidate commitment includes independent salt; threat-model notes exist | Define games and leakage model, then analyze/prove the full issuance and spend transcript under the selected adversary model |
| Durable replay protection across one local database | **GO** for single-node operation under tested assumptions | Unique deposit/commitment/nullifier constraints, SQLite atomic transactions, restart audit tests | Production deployment remains blocked by trusted callbacks and backup/recovery/reorg policy |
| Distributed ledger consensus / external state-head anchoring | **NO-GO** | Local event hash chain detects internal inconsistency; it is not tamper-proof against a privileged database rewrite | Define a consensus/anchoring and recovery model, including equivocation, fork choice, backups and rollback protection |
| Reorg, restart, disk-full and power-loss recovery for live deposits | **NO-GO** | Unit-tested journal rollback behavior; no complete end-to-end recovery runbook or live evidence | Add and test a reconciled recovery state machine across finalized deposit, authorization, issuance record and external state anchor |
| Real Ethereum Mainnet smoke test | **NO-GO** | CI uses synthetic headers and mocked Helios process/RPC | Verify pinned binary digest/version, fresh independently sourced checkpoint, provider configuration, eth_getProof capability and a real finalized deposit end to end |
| Whole-protocol internally audited composition | **NO-GO** | Individual increments and internal regression suites; core callbacks still injectable | Compose the sole accepted authorization and proof implementations, run a full threat-model-based internal audit, fix all P0/P1 findings, then rerun the full suite on one exact release commit |
| External audit | **NO-GO — not performed** | None claimed | Explicitly remains deferred as requested; record future findings separately. This status does not erase implementation blockers above |
| **Complete 0PSP production release** | **NO-GO** | Multiple real engineering components exist, but core proof/authorization/custody gates remain absent | Every mandatory production gate above is GO on one release SHA, with evidence and no test-only verifier/authorizer in the production composition |

## Immediate next sequence

1. Finish CHp4.18 canonical transaction codec and run exact-head CI; then mark only the host/API codec gate GO.
2. Freeze the authorization policy and canonical public-key/signature codec, based on an explicit security model rather than leaving both open.
3. Select, pin and instantiate a transparent zero-knowledge backend; prove feasibility of the full relation including the actual post-quantum authorization predicate before calling it implemented.
4. Build the only permitted production composition: authenticated deposit/custody verifier -> DepositAuthorization -> proof verifier -> SQLite ledger, with no test callback path enabled by production configuration.
5. Conduct the internal audit against the completed composition, resolve findings, run live-chain and crash/reorg tests, and stamp the resulting release commit.

**Current decision remains NO-GO.** The way to change it is evidence that closes each required gate, not stronger wording in a README. External audit may remain unperformed, but missing proof soundness, custody authorization, or value conservation cannot be waived while still honestly describing the system as end-to-end private spend.
