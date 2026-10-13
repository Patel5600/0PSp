# CHp4.17 — Durable State Transitions and Canonical Commitment Merkle Tree

**Status:** implementation candidate; CI and code review required.  
**Namespace V2/V3:** unchanged.  
**New state contract:** an append-only depth-63 commitment Merkle tree and a single-namespace, file-backed SQLite ledger with atomic issuance/spend state transitions.  
**Production:** **NO-GO**. This closes the persistence/unique-state-transition prototype gap only. It does not supply a real ZK prover/verifier, a trusted production deposit policy, multi-node consensus, or an independently audited cryptographic construction.

## 1. Why this increment matters

An in-memory set cannot enforce replay protection across process restarts or safely coordinate separate processes. The prior spend relation also named a commitment Merkle path without freezing its encoding. CHp4.17 makes those two engineering contracts explicit while preserving the existing Namespace V2/V3 and commitment/nullifier KATs.

## 2. Canonical append-only tree contract

The module src/protocol/commitment_tree.py defines a 63-level binary tree; indices are unsigned integers in [0, 2^63-1], matching SQLite's signed 64-bit index representation. Each successful issuance appends one commitment. Each accepted spend appends its output commitments in canonical transaction order. Committed leaves cannot be replaced or removed.

Let H(x) = SHAKE256(x, 48 bytes) and let ns be the exact 48-byte Namespace V3 identifier.

- Empty leaf: Z[0] = H("0PSP-COMMITMENT-EMPTY-LEAF-v1-SHAKE256" || 0x01 || ns).
- Real leaf at index j: L(j,C) = H("0PSP-COMMITMENT-LEAF-v1-SHAKE256" || 0x01 || ns || BE64(j) || C[48]).
- Internal node at level l, counting upward from zero: N(l,a,b) = H("0PSP-COMMITMENT-NODE-v1-SHAKE256" || 0x01 || BE32(l) || ns || a[48] || b[48]).
- Empty subtree defaults: Z[l+1] = N(l,Z[l],Z[l]), for l = 0..62.
- A membership witness has exactly 63 bottom-up 48-byte sibling hashes. At each level, bit l of the leaf index selects whether the current hash is the left or right child.
- The root is the value at level 63, index zero; before any leaves, it is Z[63].

The params_id accepted by a real proof backend must pin this exact Merkle suite and version along with the commitment/nullifier codecs, proof parameters, and authorization mode. The reference tree implementation and its tests are not a substitute for constraining the same equations in the ZK proof.

## 3. SQLite transition and durability contract

The module src/protocol/sqlite_ledger.py provides a single-namespace file-backed persistence layer:

- It pins Namespace V3, the exact params_id, authorization-policy ID and deployment-profile digest in database metadata. Reopening the file with different values fails closed.
- The database file is created/forced to owner-only 0600 permissions and symlink database paths are rejected. SQLite uses file-backed journaling and synchronous=FULL.
- Issuance obtains the amount, deposit ID, finalized anchor and beneficiary only from the injected deposit-authorizer dependency. There is no caller-provided amount. Proof acceptance and uniqueness checks precede the atomic state transition.
- A single SQLite BEGIN IMMEDIATE transaction consumes the deposit ID, inserts the commitment and issuance record, updates the Merkle path/root, appends a domain-separated state event, and updates the state head/version.
- **CHp4.26 remediation branch:** spend statements bind a matching retained historical (48-byte Merkle root, 48-byte state-chain head) anchor from the last 256 state versions. The anchor is checked before proof verification and rechecked inside the final write transaction. A concurrent state advance does not alone reject an otherwise eligible anchor. If the anchor ages out while verification runs, the spend is rejected. Outputs append to the current root, not the historical root. The ring-buffer metadata is written atomically with the state transition and reconstructed/checked by `audit_integrity()`.
- Nullifier consumption, transaction fields/digest, output commitment insertion, Merkle root update, event-chain update and metadata version change are committed in one database transaction. Unique constraints and explicit checks reject duplicate nullifiers, commitments and deposit IDs.
- UInt64 values are stored as fixed-width 8-byte big-endian BLOBs because SQLite INTEGER is signed and cannot represent all uint64 values.
- audit_integrity() runs at startup and recomputes the append-only Merkle root, compares every persisted Merkle node, and reconciles each issuance/spend record with its canonical event payload and state-head chain. This catches local record/node corruption before the ledger accepts a new transition. It is not tamper-proof storage: an attacker with unrestricted write access to the entire database can rewrite and recompute unanchored hashes.

## 4. Evidence and adversarial coverage

The new tests exercise:
- exact empty-tree and multi-leaf known-answer roots;
- membership under valid paths and rejection of wrong index, namespace, commitment, root or sibling;
- issue value provenance, persisted record reload and membership-path generation after restart;
- duplicate deposit/commitment rejection without partial mutation;
- wrong namespace, parameter set, authorization result and proof rejection;
- atomic nullifier consumption and append of multiple outputs;
- invalid, mismatched, and expired historical anchor rejection; schema-v1-to-v2 anchor-history migration; atomic snapshot-plus-membership-path retrieval;
- competing spends against one retained snapshot, with both unrelated spends able to commit; duplicate nullifiers must still be rejected atomically;
- concurrent issuance replay, where only one transaction consumes a deposit;
- configuration mismatch, in-memory database and symlink rejection, owner-only permissions, and modified-head/root detection.

CI must run on the exact branch/PR head. Passing tests demonstrate only the exercised implementation paths. They do not prove a production proof verifier, authorization callback, independent deployment digest provenance, storage resilience against a privileged attacker, or network consensus.

## 5. Honest limitations

This code does not mark a deposit trusted merely because DepositAuthorization is a Python data class. The constructor's injected authorizer and proof verifiers remain trusted dependencies. A production composition root must supply the specific CHp4.13/14/15 evidence adapter and the actual accepted proof backend, and there is currently no such fully instantiated composition.

The ledger is single-node SQLite. It provides transactional atomicity for cooperating local processes, not distributed consensus. Multi-host replicas must not independently accept spends. Backup/restore, disk-full behavior, fsync/power-loss testing, operational recovery and an external state-head checkpoint remain unimplemented.

No value-conservation policy can be inferred from a SpendStatement shape; the proof verifier must bind the same commitment opening, nullifier witness, transaction digest, all outputs, fees, authorization witness and exact public roots/head. The configured callback is an interface, not evidence that this relation exists.

## 6. Decision

CHp4.17 defines the tree encoding and adds durable, replay-protected single-node state transitions with deterministic internal audit checks. The CHp4.26 remediation candidate adds a 256-version historical-anchor ring to avoid rejecting proofs solely because unrelated transactions advanced the ledger while preserving atomic nullifier/commitment uniqueness checks. **The complete protocol remains NO-GO** until the production deposit/custody adapter, actual zero-knowledge proof backend, authorization mode, full spend/issuance relation, live-chain operational verification and production recovery/security tests are integrated. External audit is an additional later step, not a replacement for those implementation gates.
