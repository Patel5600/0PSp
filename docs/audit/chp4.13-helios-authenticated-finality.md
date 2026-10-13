# CHp4.13 — Authenticated Ethereum Mainnet Finality for Deposit Evidence

**Status:** implementation candidate; CI and intended-environment smoke test required.  
**Namespace V2 / V3:** unchanged.  
**Deposit evidence:** CHp4.12 transaction and receipt trie inclusion is now wired to a concrete Mainnet light-client profile.  
**Production:** **NO-GO**. The upstream light client has not been independently reviewed for this project; deposit custody semantics, durable atomic minting, issuance proof binding and an independent end-to-end audit remain mandatory.

## 1. What this closes

CHp4.12 proved a raw transaction and raw receipt are members of the tries committed by one raw execution header. The unresolved question was whether the header itself was on the finalized intended chain, rather than a root supplied by an arbitrary RPC node.

CHp4.13 adds src/adapters/evm_helios.py, which uses a supervised, digest-pinned Helios 0.12.0 light client for **Ethereum Mainnet only**. It does not accept an arbitrary remote RPC as a consensus source. A caller must provide both a trusted beacon weak-subjectivity checkpoint and an independently pinned execution checkpoint.

At startup, the supervisor verifies the installed binary's SHA-256 against the supplied pin and checks its reported version. RPC provider URLs are written to a private temporary TOML file instead of process arguments; the Helios JSON-RPC server is restricted to loopback. Its strict-checkpoint-age option is enabled so a stale beacon checkpoint fails closed.

## 2. Execution-header ancestry rule

The local journal starts from the out-of-band execution checkpoint already configured in EvmNamespaceConfig. It checks that Helios reports that exact block hash at that height, then verifies every numbered execution header through Helios's finalized block:

~~~text
H_checkpoint.hash == pinned_checkpoint_hash
H_(n+1).parentHash == H_n.hash, for each n
H_finalized.hash == Helios("finalized").hash
~~~

Every header's JSON representation is reconstructed into canonical execution-header RLP; the computed Ethereum Keccak-256 hash must match the returned header hash. The transaction and receipt roots later used by CHp4.12 are taken from that exact RLP. Every accepted height/hash and its roots are persisted in a namespace-scoped SQLite journal with full synchronous mode. Metadata also binds the chain, genesis, execution checkpoint, Namespace V3 ID, Helios binary pin, and beacon checkpoint.

A conflict at any stored height, finality regression, wrong genesis/checkpoint, malformed header, broken parent link, or catch-up gap beyond the configured bound fails closed. The journal does not silently rewind. The service accepts deposits only in the authenticated ancestry window beginning at the pinned execution checkpoint. Keep that checkpoint before the first deposit the mint must accept, and keep it recent enough to sync within the configured bound.

## 3. End-to-end verifier API

HeliosAuthenticatedDepositVerifier.verify:

1. asks the supervised Mainnet light client for its finalized header;
2. advances the durable parent-linked header journal to that finality point;
3. confirms that the exact supplied raw header RLP is stored at its height and matches its authenticated ancestry;
4. delegates to the CHp4.12 verifier, which proves raw transaction inclusion in transactionsRoot and raw receipt inclusion in receiptsRoot at the same RLP(transaction_index);
5. decodes the deposit event from the proven receipt and enforces the pinned emitter, event, asset, beneficiary and amount rules.

The result is HeliosAuthenticatedEvmDeposit, not DepositAuthorization. It proves the current code path has authenticated finalized-header ancestry and transaction/receipt trie inclusion under the configured assumptions. It does not prove that a contract event means the intended asset was actually transferred or is held in custody.

## 4. Trust configuration and operational contract

- **Chain:** this profile only accepts chain ID 1 and the pinned Ethereum Mainnet genesis hash. Other EVM chains must not reuse this profile.
- **Helios binary:** install the pinned Linux x86_64 release with the command bash scripts/install_helios_mainnet.sh, then configure its emitted executable SHA-256 as HeliosMainnetConfig.binary_sha256. The installer pins the official 0.12.0 Linux x86_64 release archive SHA-256 before extraction. Do not take the executable pin from an untrusted mirror.
- **Beacon checkpoint:** obtain a recent weak-subjectivity checkpoint from a source the operator trusts independently of the execution RPC. The code enables Helios strict checkpoint-age checking. A malicious initial checkpoint can select the wrong chain; the light client cannot repair a malicious trust anchor.
- **Execution RPC:** must support eth_getProof for Helios's verification path. It may provide data and withhold service, but it must not be trusted to establish consensus.
- **Execution checkpoint:** EvmNamespaceConfig.checkpoint_block_number/hash must be pinned out-of-band and match a block reported by Helios. It is also the lower boundary of the persisted deposit-evidence history.
- **Catch-up:** if the finality gap exceeds max_headers_per_sync, the update fails closed. Operators must restore the service and catch up under a reviewed bounded-sync/recovery policy; never delete or rewrite the journal just to make startup pass.

Helios describes itself as a trustless Rust light client, but its own repository also supplies a no-warranty, unaudited-software disclaimer. This integration is therefore a concrete consensus-verification dependency, not a claim that the upstream implementation has passed an independent audit. Pinning a release and checking its hash prevents substitution after approval; it does not itself prove the implementation correct.

## 5. Remaining P0 blockers

1. Run a smoke test using the pinned binary, a fresh independently sourced beacon checkpoint, and an execution RPC that supports eth_getProof; confirm chain ID, genesis, finalized header, checkpoint ancestry and raw-trie proof verification against a real finalized deposit.
2. Independently differential-test the local Keccak, RLP, header reconstruction and MPT implementation against a mature pinned Ethereum implementation and external test vectors.
3. Review the exact protocol deployment, proxy/upgrade authority, event semantics, token behavior and custody. A hash-pinned event source alone does not prove custody, especially for fee-on-transfer/rebasing/non-standard tokens.
4. Add a trusted conversion to DepositAuthorization only after those policies are verified, and atomically consume the canonical deposit ID in the durable mint ledger.
5. Instantiate the issuance proof and bind its hidden commitment opening to the exact authorized amount, Namespace V3 ID and beneficiary.
6. Independently audit the complete light-client process, checkpoint provenance, persistence/rollback behavior, trie proofs, contract semantics, issuance relation and recovery procedure.

**Decision:** CHp4.13 supplies a concrete Mainnet light-client integration and ancestry journal. Deposit inclusion can now be checked against authenticated finalized ancestry in the configured deployment path, but no production mint authorization or complete protocol security claim is approved. **Production remains NO-GO.**
