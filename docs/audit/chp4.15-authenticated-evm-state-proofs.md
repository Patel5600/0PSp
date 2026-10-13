# CHp4.15 — Authenticated EVM Account and Storage State Proofs

**Status:** implementation candidate; exact-PR CI and independent review required.  
**Namespace V2 / V3:** unchanged.  
**Deposit path:** CHp4.11 event profile, CHp4.12 transaction/receipt MPT inclusion, CHp4.13 Helios Mainnet finalized-header ancestry, CHp4.14 movement-signal consistency, and CHp4.15 EIP-1186 account/storage proof verification.  
**Production:** **NO-GO**. This increment proves account/storage values as authenticated **block-boundary state**. It does not establish that a particular transaction caused a state change, that funds were retained, or that mint authorization is safe.

## 1. Purpose

CHp4.14 correctly stopped short of claiming custody from event logs. The next useful primitive is the ability to verify account and storage claims against the execution state root committed by an authenticated header. EIP-1186 supplies account and storage trie proof nodes; the verifier must not trust the accompanying JSON fields unless the proofs bind them to the state root.

## 2. Implemented verifier

- `src/adapters/evm_state_proof.py` exposes `verify_eip1186_account_proof`.
  - Derives the state root, block number and block hash from raw execution-header RLP.
  - Verifies the account trie path at `Keccak256(address)`.
  - Reconstructs the canonical account leaf from nonce, balance, storage root and code hash, then verifies the exact encoded account value.
  - Verifies each requested storage slot at `Keccak256(slot[32])` against the proven account storage root.
  - Supports non-zero storage inclusion, zero-storage exclusion paths, and the canonical empty-storage-trie root.
  - Checks response address, fixed-width roots/hashes, canonical QUANTITY/DATA encodings, exact requested slot set, duplicate slots, and optional runtime-code bytes against the account's proven code hash.
  - Includes a helper for Solidity address-keyed mapping slots, explicitly conditional on a reviewed storage layout.
- `src/adapters/evm_trie.py`
  - Adds `verify_mpt_exclusion` for empty branch children, divergent extension/leaf paths, and the empty trie root.
  - Rejects malformed/non-canonical RLP, wrong parent references, and unused trailing proof nodes.
- `src/adapters/evm_helios.py`
  - Adds a strict allowlisted `eth_getProof` call shape.
  - `HeliosAuthenticatedHeaderJournal.verify_account_state` first authenticates the exact header through the durable checkpoint-to-finality journal, requests proof data at that exact block number, fetches code at the same block, and verifies both against the header's state root/account code hash.

## 3. Security contract

The EIP-1186 response's JSON convenience fields are not treated as authoritative. The account proof must prove the canonical RLP account value under the authenticated header's state root. Each requested storage proof must prove the reported value or cryptographically establish its absence. Code bytes, when fetched, must hash to the code hash in the proven account leaf.

The state-proof API intentionally requires a raw header that was obtained through `HeliosAuthenticatedHeaderJournal.authenticate_header`. Calling the lower-level verifier directly with an arbitrary header only proves a claim relative to the supplied state root; it does not authenticate consensus or finality.

## 4. What this still does not prove

A state root commits to the state **after a block**, not a transaction-by-transaction state diff. A balance or storage value at block N does not, by itself, prove that a particular deposit transaction caused the change. Multiple transactions in the same block can alter the same account or storage slot. A proof of an ERC-20 balance mapping additionally requires the exact storage layout and mapping slot from reviewed, pinned source/build artifacts.

Even a proven post-state balance is not a generic custody guarantee. A contract can forward/refund native value; a token can have deceptive semantics; a proxy can change implementation while its proxy runtime bytecode stays constant. Those require a contract-specific, independently reviewed custody predicate and explicit upgrade/admin policy. The repository does not have a supplied production 0PSP contract/manifest to approve such a predicate.

Therefore:
- CHp4.15 does **not** create `DepositAuthorization`.
- No event, transfer log, account proof or storage proof may independently authorize minting.
- The existing reference ledger is still an in-memory model, not a durable replay-protected production ledger.
- The actual issuance proof still must bind the authenticated deposit's namespace, amount, beneficiary, canonical deposit ID and finalized anchor to the hidden commitment opening.

## 5. Test evidence

Added synthetic tests cover EIP-1186 account inclusion, non-zero storage inclusion, zero storage under an empty trie, zero storage proven absent from a non-empty trie, tampered response fields, code-hash mismatch, malformed/duplicate/unrequested storage slots, mapping-slot encoding, MPT exclusion paths, and integration through the Helios journal at an exact block number.

These are deterministic local fixtures. They do not substitute for live Mainnet testing, differential testing against a mature Ethereum implementation, source/build verification of a real contract, an independent cryptographic review, or an end-to-end mint test.

## 6. Next required gates

1. Differential-test Keccak/RLP/MPT/EIP-1186 handling against pinned, mature Ethereum tooling and published vectors.
2. Run a live Mainnet smoke test using the exact approved Helios binary, fresh out-of-band checkpoint, compatible execution RPC, and a real finalized account/storage proof.
3. Supply and review the exact deployed protocol and token source/build artifacts, runtime code, proxy implementation/admin slots and upgrade policy.
4. Define the custody predicate for the selected deployment. State proofs are supporting evidence, not a substitute for transaction-level causation or code semantics.
5. Only after those gates, implement a policy-specific trusted `DepositAuthorization` adapter and a durable atomic mint ledger with replay/reorg recovery.
6. Instantiate and independently audit the issuance proof relation and bind its public statement to that authorization.

**Decision:** CHp4.15 adds authenticated block-state proof primitives. It closes neither the transaction-specific custody gap nor the deposit-to-mint release gate. Complete protocol remains **NO-GO**.
