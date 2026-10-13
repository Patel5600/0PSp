# CHp4.16 — Differential Conformance Checks for Ethereum Proof Primitives

**Status:** test-only conformance increment; exact-PR CI and independent review required.  
**Runtime dependencies:** unchanged. The reference libraries are development/test dependencies only.  
**Production:** **NO-GO**. Differential agreement raises confidence in encoding/proof handling; it does not certify the full implementation, Helios, a real deployment, custody semantics, or the 0PSP protocol.

## 1. Purpose

CHp4.15 added EIP-1186 account/storage proof verification and MPT exclusion proofs. Those are consensus-adjacent byte parsers, so self-consistency tests alone are weak evidence: a buggy encoder and verifier can agree with each other. CHp4.16 adds a test-only independent reference path.

## 2. Independent test libraries

The development extra adds:

- `eth-hash[pycryptodome]` for an independently implemented Ethereum Keccak-256 reference;
- `rlp` for canonical RLP encode/decode comparison;
- `trie` for independent Hexary Merkle-Patricia trie construction and proof generation.

These are not added to runtime dependencies or production import paths.

## 3. Differential checks

The new test module:

- compares local Keccak-256 to the reference implementation across empty, short, rate-boundary, and longer inputs;
- compares local RLP encoding and decoding with the independent RLP library over boundary and nested values;
- checks the canonical empty-trie root;
- builds tries using the independent HexaryTrie implementation, obtains encoded inclusion proofs, and verifies them with the local MPT verifier;
- obtains proofs of absent keys from the reference trie and verifies local exclusion handling;
- covers multi-key tries and both short/embedded and hashed-child proof shapes;
- mutates a proven value and root to ensure substitution is rejected.

## 4. Security limits

These tests are differential evidence, not a formal proof. They do not test a live Mainnet endpoint, prove that the pinned Helios binary is safe, establish transaction-level state causation, approve any token or proxy, or prove that a contract retained funds. The EIP-1186 parser is tested with local fixtures; a production deployment still requires a real finalized account/storage proof smoke test and independent review.

The generic MPT reference test also does not prove every Ethereum fork's complete header encoding, typed transaction schema, receipt schema, or every edge case in EIP-1186. Those require separate vectors and review.

## 5. Release decision

Namespace V2/V3 byte contracts remain unchanged. The independent libraries are test-only. The custody-policy gap, trusted DepositAuthorization conversion, durable atomic mint ledger, actual issuance proof, and end-to-end security review remain open.

**Decision:** CHp4.16 adds independent differential conformance checks for Keccak/RLP/MPT. Complete protocol remains **NO-GO**.
