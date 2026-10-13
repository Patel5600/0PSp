# CHp4.14 — Bind Deposit Events to Proven Asset-Movement Signals

**Status:** implementation candidate; CI and independent review required.  
**Namespace V2 / V3:** unchanged.  
**Deposit proof path:** CHp4.11 canonical observation, CHp4.12 raw transaction/receipt MPT inclusion, CHp4.13 Mainnet finalized-header and runtime-code checks, and CHp4.14 movement-signal consistency.  
**Production:** **NO-GO**. Event and token Transfer logs are not a generic proof of custody; no trusted DepositAuthorization conversion, audited custody policy, durable mint ledger, or issuance proof is implemented.

## 1. Why this increment exists

A cryptographically included event can still report a value that disagrees with the transaction or with a token Transfer event. CHp4.14 adds explicit consistency rules over the raw transaction and receipt bytes already proven by the CHp4.12 verifier. The event is not accepted in isolation.

The result type remains ProvenEvmDepositInclusion wrapped by HeliosAuthenticatedEvmDeposit. The assurance label says movement signal, not custody authorization. No function creates a DepositAuthorization.

## 2. Profile A: native-asset deposit

For the fixed Deposit event profile, the proven raw transaction must target the exact protocol address pinned by Namespace V3. If the namespace asset is native ETH:

- the asset topic in the proven Deposit event must be the zero address;
- the raw transaction destination must be the pinned protocol address;
- the transaction value decoded from the raw legacy or typed transaction must equal the event amount exactly;
- the receipt must be successful and both transaction and receipt trie proofs must verify at the same transaction index;
- the exact raw execution header must be in the Helios-authenticated checkpoint-to-finalized ancestry window;
- protocol runtime code at the deposit block must match its pinned fingerprint.

The amount comparison is over integer wei/base units, never a display-formatted amount. A transaction that sends zero or a different native value cannot use an event alone to claim the configured deposit amount.

This still does not establish that the contract retains the funds or credits the intended balance. An accepted transaction could call code that forwards or refunds the value. Contract logic, storage/accounting semantics, and the exact deployed code/upgrade policy must be reviewed before authorization.

## 3. Profile B: ERC-20 Transfer signal

If Namespace V3 pins a non-native token address:

- the transaction value must be zero;
- the proven receipt must contain exactly one ERC-20 Transfer event emitted by the configured token address;
- its canonical Transfer topics must encode from = the Deposit event's depositor and to = the pinned protocol contract;
- its uint256 data word must equal the Deposit event amount exactly;
- the token runtime-code fingerprint at the deposit block must match the independently pinned Namespace V3 asset fingerprint;
- the proven Deposit event must still match the configured protocol emitter, event topic, expected beneficiary, and accepted amount bounds.

The standard Transfer signature topic is derived with Ethereum Keccak-256 from Transfer(address,address,uint256). The code rejects malformed topic/data layouts, zero/non-canonical addresses, missing or multiple matching transfers, a mismatched amount, a transfer to another address, a different transaction destination, or non-zero native transaction value.

This profile deliberately does not silently support fee-on-transfer, rebasing, reflection, callback-controlled, bridged, or otherwise non-standard tokens. A standard-looking Transfer log is still a statement from token code. A malicious token can emit false logs; a proxy can preserve the same proxy bytecode while switching implementation. The pinned code fingerprint is an integrity check against a reviewed manifest, not a proof that the token semantics are honest or immutable.

## 4. What the evidence record now means

ProvenEvmDepositInclusion now carries:

- transaction destination and transaction value decoded from the raw proven transaction;
- an asset movement kind label, either NATIVE_TX_VALUE_MATCHED or ERC20_TRANSFER_LOG_MATCHED;
- the proven Deposit log's namespace, amount, depositor, beneficiary, transaction/log identity and finalized anchor.

HeliosAuthenticatedDepositVerifier additionally queries protocol code at the deposit block and checks the configured protocol fingerprint. For ERC-20 deposits it also queries the token code at the same block and checks the pinned asset fingerprint. Both reads are made through the supervised Helios local RPC, whose execution-state proof path requires a compatible execution RPC that provides eth_getProof.

No asset-movement label bypasses the contract policy. The verifier still cannot infer a generic custody invariant from a log. Production custody authorization needs an independently reviewed contract profile, explicit upgrade/admin rules, and a defined state/custody predicate for that exact protocol and asset.

## 5. Tests and evidence

Regression tests cover:

- native deposit event amount equal to transaction value, and mismatch rejection;
- destination-address substitution;
- ERC-20 Transfer from/to/amount matching within the proven receipt;
- wrong transfer amount, transfer destination, duplicate matching Transfer logs, and non-zero tx.value;
- legacy and type-1/type-2 transaction decoding;
- protocol runtime-code mismatch and ERC-20 token runtime-code mismatch at the deposit block;
- policy-to-namespace binding, finality regression, checkpoint mismatch and durable ancestry checks from CHp4.13.

Passing tests prove only the encoded predicates for the test vectors. They do not prove the intended contract received or retained funds, verify an arbitrary token's balances, prove proxy implementation history, authenticate an unknown deployment, or authorize minting.

## 6. Remaining P0 gates

1. Run a real Mainnet smoke test against an independently configured Helios binary, fresh beacon checkpoint, execution RPC with eth_getProof, intended EVM manifest and real finalized deposit.
2. Differential-test Keccak, RLP, header reconstruction and MPT code against a mature pinned Ethereum implementation and external vectors.
3. Review and pin the exact protocol contract, compiler/artifact, proxy and implementation/admin slots, relevant storage behavior, upgrade authority, and intended custody predicate.
4. Approve a specific asset profile. For tokens, review the token implementation and transfer semantics; do not approve arbitrary token contracts based only on a Transfer log or code hash.
5. Only then create a trusted adapter that produces DepositAuthorization from the verified inclusion plus approved custody policy, and consume its canonical deposit ID atomically in a durable mint ledger.
6. Bind namespace, value, beneficiary, deposit ID and finalized anchor to the actual issuance proof that proves the hidden commitment opening. Independently audit the entire chain-to-mint path.

**Decision:** CHp4.14 rejects several event/transaction/Transfer substitutions and adds pinned token-code checks, but provides movement evidence rather than custody authorization. Production remains **NO-GO**.
