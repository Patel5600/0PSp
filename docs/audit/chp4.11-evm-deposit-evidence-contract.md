# CHp4.11 — EVM Deposit Evidence Contract

**Status:** implementation candidate on branch \`chp4.11-evm-deposit-evidence-contract\`; production approval is not implied.  
**Namespace V2 / V3:** formulas and Namespace V3 identity bytes unchanged.  
**New API:** canonical EVM deposit-observation record, quorum-restricted receipt reads, receipt-local log selection and beneficiary binding in the issuance reference model.  
**Production:** **NO-GO**. The current reader does not verify transaction/receipt trie inclusion or authenticated chain consensus and must not produce trusted mint authorization.

## 1. Design decision: three trust levels

The word “deposit evidence” must not silently mix three different things.

1. **RPC observation:** JSON-RPC reports a transaction receipt and an event-shaped log.
2. **Canonical candidate observation (CHp4.11):** the implementation validates encodings, strict-majority provider agreement, the pinned Namespace V3 emitter/asset/event/code policy, receipt/log metadata consistency and membership of the receipt block in the durable finalized-header journal. Its return type is named \`QuorumObservedEvmDeposit\` and labels itself \`QUORUM_OBSERVED_NOT_CRYPTOGRAPHICALLY_AUTHENTICATED\`.
3. **Authenticated deposit authorization (required, not implemented):** a verifier must authenticate the EVM execution header under the selected chain's consensus/trust policy, cryptographically bind the raw transaction and receipt to the same transaction index in the authenticated header's transaction/receipt tries, decode the proven receipt, apply the reviewed contract/asset semantics, and return the exact namespace, canonical deposit ID, amount, beneficiary and finalized anchor to the mint ledger.

Only level 3 may produce \`DepositAuthorization\`. CHp4.11 deliberately provides no conversion method from level 2 to level 3. Provider agreement is not a consensus proof, and an event is not by itself proof that assets reached custody.

## 2. Canonical event profile

The initial v1 profile requires the protocol contract already bound into Namespace V3 to emit this event layout:

~~~solidity
event Deposit(
    address indexed depositor,
    address indexed asset,
    address indexed beneficiary,
    uint256 amount
);
~~~

The canonical signature string is \`Deposit(address,address,address,uint256)\`. The \`indexed\` modifiers do not appear in the canonical signature. Configuration must pin \`topic0 = Keccak256(canonical_signature)\` using Ethereum Keccak-256, derived from independently reviewed ABI/deployment artifacts. Standardized SHA3-256 is not interchangeable with Ethereum Keccak-256.

The exact shape is:

- \`topics[0]\`: the pinned event signature hash, 32 bytes.
- \`topics[1]\`: ABI-padded depositor address.
- \`topics[2]\`: ABI-padded asset address. The native asset uses the zero address; a token asset uses the exact token address in the namespace binding.
- \`topics[3]\`: ABI-padded beneficiary address.
- \`data\`: exactly one 32-byte big-endian ABI word containing \`uint256 amount\`.

An address topic must have 12 zero padding bytes followed by 20 address bytes. The depositor and beneficiary must be non-zero. The amount must be non-zero and fit the current reference ledger's uint64 value range. Amounts denote integer asset base units, not formatted human-readable currency. Decimals and display symbols are not part of deposit identity.

This first profile intentionally requires \`deposit_contract_address == EvmNamespaceBinding.protocol_address\`. A separate deposit contract is not bound by the current Namespace V3 deployment component; accepting it under the same namespace without an explicit protocol-version change would create an unreviewed identity dependency.

## 3. Required observed fields

The normalizer binds these fields into one immutable record:

| Field | Source / rule |
|---|---|
| \`namespace_id\` | Typed 48-byte Namespace V3 ID from the pinned EVM binding |
| \`chain_id\` | Chain ID from the binding; RPC must agree by quorum in the surrounding runtime |
| \`deposit_contract_address\` | Must equal the protocol address in Namespace V3 |
| \`asset_address\` | Exact Namespace V3 asset; native asset encoded as the zero address in the log |
| \`event_topic0\` | Pinned topic hash for the reviewed event ABI |
| \`transaction_hash\` | 32-byte hash requested by the caller and returned by receipt RPC |
| \`transaction_index\` | Canonical uint64 index from receipt; required later as the trie lookup index |
| \`receipt_log_ordinal\` | Zero-based position in the receipt's ordered log array; canonical local log selector |
| \`log_index\` | Global index returned by RPC; retained only as observation/diagnostic metadata |
| \`block_number\`, \`block_hash\` | Must match receipt and log fields and an exact member of the durable finality journal |
| \`transactions_root\`, \`receipts_root\` | Reported in the matching quorum-observed block header; retained for future trie-proof validation, not authenticated by this reader |
| \`depositor\`, \`beneficiary\`, \`amount\` | Decoded only from the exact pinned event layout; beneficiary must equal the requested beneficiary |
| \`contract_code_fingerprint\` | 48-byte runtime fingerprint of the protocol address queried at the deposit block; must equal the independently pinned policy |

The reader also requires a successful receipt, no log marked removed, unique global log indexes within the returned receipt, consistent block/transaction metadata across receipt and logs, an exact matching emitter/topic/asset, canonical address topics and an accepted amount.

### Why identity uses receipt-local log ordinal

The JSON-RPC \`logIndex\` is a global block-level index. It is not encoded in the transaction receipt itself. A receipt-trie proof for one transaction cannot by itself establish the global index without evidence about logs from earlier receipts in that block. Therefore v1 defines:

~~~text
deposit_id = transaction_hash[32] || BE32(receipt_log_ordinal)
finalized_anchor = BE64(block_number) || block_hash[32]
~~~

The ledger scopes \`deposit_id\` by \`namespace_id\`. This gives every selected log in a transaction a unique position under that transaction without relying on the RPC-only global index. The normalizer retains \`log_index\` for audits but does not use it as the deposit identifier.

## 4. Canonical audit bytes

\`QuorumObservedEvmDeposit.canonical_bytes()\` is the following fixed-width, big-endian schema. It is deterministic for normalized fields and contains no free-form JSON:

~~~text
"0PSP-EVM-DEPOSIT-OBSERVATION-v1" || 0x01 ||
namespace_id[48] ||
BE256(chain_id) ||
deposit_contract_address[20] ||
asset_address_or_zero[20] ||
event_topic0[32] ||
transaction_hash[32] ||
BE64(block_number) ||
block_hash[32] ||
transactions_root[32] ||
receipts_root[32] ||
BE64(transaction_index) ||
BE32(receipt_log_ordinal) ||
BE64(global_log_index) ||
depositor[20] ||
beneficiary[20] ||
BE64(amount) ||
contract_code_fingerprint[48]
~~~

\`evidence_digest = SHAKE256-384(canonical_bytes)\` is an audit fingerprint only. It is not a signature, a Merkle proof, a consensus proof or evidence that the fields came from a valid chain.

The reference ledger was updated to require a non-zero 20-byte \`beneficiary_address\` inside \`DepositAuthorization\`, to pass that same value into the public \`IssuanceStatement\`, and to retain it in \`IssuedRecord\`. Its issuance verifier must bind the beneficiary under the selected authorization policy. This prevents the state model from silently dropping recipient identity, but does not itself establish that a claimant controls the address or that the deposit is cryptographically authenticated.

## 5. Required cryptographic path to trusted authorization

A production adapter must not trust JSON-RPC fields just because several endpoints agree. It must prove or explicitly trust the following chain:

1. **Authenticated execution header.** Select the target EVM chain, fork rules, trusted checkpoint and consensus/light-client or oracle trust model. The header hash must be cryptographically bound to the trusted finalized execution block.
2. **Transaction inclusion.** Obtain canonical raw transaction bytes, establish \`Keccak256(raw_transaction) == transaction_hash\`, and verify its Merkle-Patricia trie inclusion at key \`RLP(transaction_index)\` against the authenticated \`transactionsRoot\`.
3. **Receipt inclusion.** Obtain canonical raw receipt bytes and verify receipt-trie inclusion at the same key \`RLP(transaction_index)\` against the authenticated \`receiptsRoot\`. Parse legacy and typed receipt envelopes according to the chain's fork rules. Verify transaction and receipt index match.
4. **Proven log.** Select the decoded receipt log by the receipt-local ordinal and validate emitter, exact event topic, asset, beneficiary, amount and address padding. Do not treat the JSON-RPC global \`logIndex\` as a cryptographic inclusion field.
5. **Contract and asset semantics.** Review/verify the contract's behavior, proxy implementation and relevant storage/governance. Confirm that an accepted event means the intended asset was actually received. For tokens, define transfer-fee/rebasing/non-standard-token behavior explicitly; code-hash equality alone does not establish custody or event meaning.
6. **Authorization binding.** Produce one trusted \`DepositAuthorization\` that binds the current Namespace V3 ID, canonical receipt-log deposit ID, amount, beneficiary and finalized anchor. The issuance proof must prove the commitment opening uses exactly the authorized amount and namespace and that the beneficiary claim satisfies policy.
7. **Atomic replay protection.** The durable mint ledger must consume this deposit ID in the same transaction that records the issuance. A repeated request, different commitment or race must not consume the same deposit twice.

Ethereum defines the receipt root as a Merkle-Patricia trie over \`RLP(transaction_index) => receipt\`, with typed receipt envelopes distinguished by the type prefix. See [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718), the [Merkle Patricia Trie documentation](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/) and the [execution API receipt schema](https://ethereum.github.io/execution-apis/api/methods/eth_getTransactionReceipt/). These are implementation specifications; citing them does not mean 0PSP has implemented their proof verifier.

## 6. Validation evidence and remaining gates

CHp4.11 adds:

- a read-only quorum allowlist for \`eth_getTransactionReceipt\` and canonical majority-vote normalization over receipt fields and nested logs;
- a typed policy tied to the Namespace V3 protocol address and configured asset;
- strict receipt status, block/hash, receipt-log ordinal, topic layout, beneficiary, amount, code-fingerprint, and finality-journal checks;
- deterministic audit bytes and a stable 48-byte fingerprint, explicitly not claimed as authentication;
- adversarial unit tests for failed receipts, wrong transaction/block/emitter/topic/asset/beneficiary, removed or duplicate logs, malformed metadata, wrong code fingerprint, provider failure, invalid ordinal, and amount overflow;
- required beneficiary binding through the issuance reference model and updated RFC-01/RFC-02 text.

These tests show selected local invariants only. They do not prove consensus, provider independence, transaction/receipt trie inclusion, code semantics, asset custody, issuer unlinkability, issuance-proof soundness or durable ledger safety.

**Remaining P0 gates:** implement and independently test canonical RLP/typed transaction and receipt parsing; transaction and receipt MPT proof verification; an authenticated execution-header/finality source for the intended chain; audited deposit-contract/asset semantics; a real authorization adapter that emits trusted DepositAuthorization only after verification; the actual issuance proof binding value and beneficiary; and a durable atomic mint ledger with incident/reorg recovery.

**Current decision: CHp4.11 defines and normalizes a useful evidence envelope. It does not close deposit authentication. Production remains NO-GO.**
