# CHp4.12 — EVM Transaction and Receipt Trie Inclusion Verifier

**Status:** implementation candidate; CI and independent review required.  
**Namespace V2 / V3:** unchanged.  
**Deposit evidence:** CHp4.11's observation type remains observation-only. CHp4.12 adds a separate verifier for raw transaction and receipt inclusion.  
**Production:** **NO-GO**. The finalized-header journal is still based on RPC quorum and is not authenticated chain consensus; no trusted DepositAuthorization conversion or durable mint ledger is implemented.

## 1. Security goal

A deposit-shaped JSON-RPC log is not sufficient. This change adds three cryptographic checks:

1. Parse the raw execution-header RLP using a strict supported field schema, derive the block hash as Keccak256(raw_header_rlp), and extract transactionsRoot and receiptsRoot from the header fields themselves.
2. Require that exact block number and block hash to be present in the durable finalized-header journal.
3. Verify the raw transaction and raw receipt as separate Merkle-Patricia trie values under the respective roots, using the same canonical trie key RLP(transaction_index). Require the raw transaction hash to match Keccak256(raw_transaction), and derive the event from the proven raw receipt bytes, not from RPC logs JSON.

The verifier returns ProvenEvmDepositInclusion, which is deliberately named and labelled as trie inclusion against a quorum-observed finalized header. It does **not** return DepositAuthorization.

## 2. Implemented primitives

- src/adapters/evm_trie.py
  - Pure-Python Ethereum Keccak-256 with legacy Keccak padding, distinct from standardized SHA3-256.
  - Strict canonical RLP decoder: rejects non-minimal string prefixes, malformed length encodings, truncation, trailing bytes and excessive nesting.
  - Canonical RLP integer encoding for transaction-trie keys.
  - Hex-prefix compact-path decoding.
  - Merkle-Patricia inclusion verification for branch, extension and leaf nodes, including hashed and embedded child references, with unused proof nodes rejected.
- src/adapters/evm_deposit_proof.py
  - Validates the raw execution header's supported 15-to-21-field schema and binds its trie roots to the header hash.
  - Checks raw transaction hash and transaction trie inclusion.
  - Checks receipt trie inclusion at the same transaction index.
  - Parses legacy and known typed transaction/receipt envelopes (types 1–4); rejects unknown envelope types and transaction/receipt type mismatch.
  - Accepts only successful post-Byzantium status receipts for this v1 policy, decodes the selected log from the proven receipt, and enforces the pinned emitter, topic, asset, beneficiary and amount policy.
  - Uses transaction_hash || BE32(receipt_log_ordinal) as deposit identity, with BE64(block_number) || block_hash as finalized anchor.

## 3. Verification contract

The caller must provide:

- the exact raw execution-header RLP;
- raw transaction bytes and transaction-trie proof nodes;
- raw receipt bytes and receipt-trie proof nodes;
- the claimed transaction index and receipt-local log ordinal;
- the expected beneficiary.

The verifier computes the block hash and roots from the supplied raw header. It does not accept caller-supplied roots as independent arguments. Both trie proofs use RLP(transaction_index); a proof at a different index is rejected. The raw receipt is parsed only after its exact bytes have been proven against the header's receipt root.

The transaction-envelope parser validates canonical RLP structure and supported field counts. The trie proof plus a genuinely authenticated header is what would establish that the transaction was part of a valid chain block; this verifier is not a complete consensus or transaction-validity verifier on its own.

## 4. What remains unauthenticated

The current SqliteEvmFinalityJournal records a chain and ancestry corroborated by RPC quorum, with an out-of-band checkpoint. Its membership check is useful to detect conflicting observed views, but does not verify sync-committee signatures, a consensus light-client proof, or another chain-authentication mechanism. Therefore the root used by the new verifier is bound to the raw header hash and the journal's observed finalized ancestry, but **the chain consensus behind that header is not cryptographically authenticated**.

Other remaining gaps:

- A raw transaction/receipt proof can be checked mathematically against arbitrary roots; only authenticated consensus makes those roots authoritative.
- The event profile and pinned runtime code hash do not by themselves prove token custody, fee-on-transfer behavior, proxy implementation semantics or contract solvency.
- The v1 parser supports successful post-Byzantium receipts only. Pre-Byzantium state-root receipts are rejected, not guessed.
- The pure-Python Keccak/MPT code is a reference implementation. It needs independent differential testing against a mature implementation and external known vectors before production use.
- The caller must obtain proof nodes and raw bytes from a transport that preserves exact byte encodings. CHp4.12 does not add a trusted RPC method for obtaining MPT proofs.
- No conversion from ProvenEvmDepositInclusion to DepositAuthorization exists. Such a conversion must be added only behind authenticated header verification, audited contract/asset semantics, a canonical authorization record and independent review.
- The durable issuance ledger must atomically consume the canonical deposit ID with issuance, and the actual issuance proof must bind the same namespace, value and beneficiary to the hidden commitment opening.

## 5. Tests and evidence

The added tests cover Ethereum Keccak known vectors, canonical RLP edge cases, compact paths, MPT leaf/branch inclusion with embedded and hashed child references, wrong roots/keys/values, unused proof nodes, raw header binding, transaction/receipt proof substitution, mismatched typed envelopes, failed receipts, wrong beneficiary and amount overflow.

CI must run against the exact PR head. Passing tests establish only the tested local implementation behavior; they do not authenticate a chain, establish asset custody, prove issuer privacy or instantiate the issuance relation.

## 6. Release gate

Before deposit evidence may authorize minting:

1. Differential-test Keccak, RLP and MPT against a mature, pinned Ethereum implementation and published test vectors.
2. Obtain an authenticated execution header through a selected chain's reviewed consensus/light-client strategy or an explicitly approved trust model.
3. Verify raw transaction and receipt proofs against that authenticated header at the same index.
4. Review the actual deployed contract, proxy/governance path and native/token custody semantics.
5. Add a trusted authorization adapter with no RPC-only bypass and an atomic durable replay-protected mint transaction.
6. Bind the resulting authorization into the real issuance proof and independently review the full path.

**Decision: CHp4.12 advances deposit inclusion verification, but the deposit-to-mint path remains NO-GO.**
