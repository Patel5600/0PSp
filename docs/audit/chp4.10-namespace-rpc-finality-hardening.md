# CHp4.10 — Namespace RPC Quorum and Durable Finality Journal

**Status:** implementation candidate on branch `chp4.10-namespace-rpc-finality-hardening`; production approval is not implied.  
**Namespace V2:** frozen; known-answer vectors and formula are unchanged.  
**Namespace V3:** canonical direct-hash mapping from CHp4.9 is unchanged.  
**New scope:** fail-closed read-only RPC majority policy, SQLite-backed finalized-header ancestry journal, and startup wiring that requires the quorum plus durable journal.  
**Production:** **NO-GO** pending the intended-chain smoke test, authenticated consensus/light-client strategy, chain-specific deposit-event verification, actual proof-relation binding, and independent review.

This startup hardening is **not a light client** and does not establish cryptographic consensus.

## 1. What changed

CHp4.9 fixed the namespace identity derivation itself: full canonical chain, deployment and asset descriptors are length-prefixed and fed directly into one SHAKE256-384 digest. CHp4.10 hardens the surrounding trust boundary without changing any identity bytes or the frozen V2 core.

New code:

- `src/adapters/evm_rpc_policy.py`: `QuorumJsonRpcTransport` only permits `eth_chainId`, `eth_getBlockByNumber`, and `eth_getCode`. It needs at least three distinct transport objects and a strict majority (default 2-of-3). It canonicalizes vote material for chain IDs, block number/hash/parentHash and runtime code, tolerates a minority failure, and fails closed if no quorum agrees. Error messages exclude endpoint strings and provider exception details.
- `src/adapters/evm_finality.py`: `SqliteEvmFinalityJournal` pins the chain, namespace, out-of-band checkpoint and checkpoint hash to a file-backed SQLite database. It validates the provider-reported finalized head and walks every numbered header from the persisted tip to that head, checking each parent hash. The update commits atomically with full SQLite synchronous mode. Conflicting hashes at the stored tip, finality-height regression, metadata mismatch, a broken ancestry, missing/malformed headers and oversized catch-up fail closed. The journal never silently rewinds.
- `src/adapters/evm_namespace_runtime.py`: `EvmNamespaceRuntime` wires the pinned EVM manifest, strict-majority RPC transport and durable finality journal into one startup operation. It refuses the weaker `latest` code tag. It returns a binding only after manifest and finalized ancestry checks succeed.
- New unit tests cover quorum normalization, divergent providers, a failed provider, malformed responses, restricted RPC methods, persistence/restart, wrong ancestry, a changed finalized tip, finality regression, wrong namespace scope and bounded catch-up.

## 2. Configuration contract

Construct one `JsonRpcClient` per separately administered endpoint, give each a distinct operator label, and pass that mapping to `EvmNamespaceRuntime`. Endpoint object uniqueness is a programming safeguard; it does **not** establish operational independence. Operators must verify the providers use meaningfully independent operators, infrastructure and client implementations. Three URLs backed by the same hosted RPC fleet are not three independent trust domains.

Pin these values out-of-band and review their provenance:

- EVM chain ID and genesis hash.
- Recent trusted checkpoint number and hash.
- Protocol address and independently reviewed 48-byte runtime-code fingerprint.
- Optional asset address and corresponding fingerprint.
- Explicit deployment and asset epochs for semantic changes that do not change contract address/code.
- A local durable database path dedicated to this namespace.

The checkpoint must be close enough to the provider's current finalized head to synchronize within the configured `max_headers` bound (default 4096 per startup operation). Use a maintained, reviewed checkpoint. Do not “fix” a failed reorg check by deleting the journal or changing its trust anchor without an explicit incident/recovery procedure.

## 3. Security boundaries and limits

### RPC quorum is not consensus verification

A strict majority reduces single-provider dependence, but providers can share upstream infrastructure, disagree in correlated ways, or return a coordinated false view. The code does not implement an execution/consensus light client, verify sync-committee signatures, validate a proof of finalized headers, or certify the meaning of a chain's `finalized` tag. An independently specified trust model is still required for production.

### The journal records observed finality; it is not the mint ledger

The journal provides durable, namespace-scoped header ancestry and detects a later RPC view that conflicts with the stored finalized tip. It does not verify receipt inclusion, log inclusion, deposit value, emitter authorization, asset transfer semantics or deposit replay. It is not a replacement for a durable transactional mint ledger. A chain-specific deposit adapter must bind a canonical deposit identifier (including the log index where applicable), emitting contract, event signature, asset, value, block hash and namespace to verified finalized evidence.

### Typed namespace fields do not instantiate the proof

The reference ledger rejects mismatched `NamespaceIdV3` values before injected callbacks. The actual issuance/spend proof must bind the exact canonical 48 bytes into the accepted public statement, commitment/nullifier relation, proof parameters and verifier configuration. No proof backend is currently instantiated, so this is an unresolved release blocker.

### No rollback or fork recovery is automated

If a header recorded as finalized changes, this implementation freezes and raises an error. It deliberately does not delete or rewind already-recorded history. A production operator needs a reviewed incident-response and recovery process, and must reconcile any dependent deposit/issuance state before resuming.

## 4. Evidence and acceptance

The new unit tests are regression evidence for the local algorithms. After CI completes, record its exact commit and run status here; do not infer tests from code presence alone. Tests do not prove consensus, RPC independence, contract correctness, deposit soundness, proof soundness, ZK, or production availability.

Required before this component can be called production-complete:

1. Select the intended EVM chain and run a smoke test against independently operated providers with reviewed, real chain/deployment manifests.
2. Choose and implement a concrete authenticated consensus strategy (for example, a reviewed light client) or explicitly approve a threat model for provider-quorum trust.
3. Freeze the deposit contract ABI/event policy and implement receipt/log verification tied to the finalized header chain and durable mint-ledger transaction.
4. Instantiate the proof system and prove the exact Namespace V3 public value is bound to the accepted issuance/spend relations and parameters.
5. Perform independent security review, including crash recovery, storage rollback, RPC equivocation, reorg handling, provider correlation and operational key/manifest provenance.

**Current decision: Namespace V3 derivation and API mapping are complete as an engineering primitive; the production chain-to-proof namespace path remains NO-GO.** Do not move the release gate to GO merely because these local hardening tests pass.
