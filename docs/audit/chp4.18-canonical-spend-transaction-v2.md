# CHp4.18 — Canonical V2 Spend Transaction and Digest

**Status:** merged to `main` at `72e843ee06a721a93dcc09fd9fe7b9efc45d6021`; exact-main Functional checks and Repository integrity watch passed on 2026-10-13. Internal review scope: host/API canonical encoding only.  
**Compatibility:** existing Namespace V2/V3, CommitV2 and NullifierV2 byte contracts are unchanged.  
**Production:** **NO-GO** until the canonical host encoding is constrained by the actual proof backend and the authorization/value-conservation relation is instantiated.

## 1. Finding closed

RFC-02 previously named TxDigestV2 but left the canonical transaction-field schema unspecified. Both ledgers accepted a caller-supplied transaction byte string and a separate digest, then passed both to an injected spend-verifier callback. That left a host/API-level mismatch surface: the duplicated statement fields could disagree with the serialized fields unless every callback independently checked them.

CHp4.18 defines the missing public wire contract and checks it before the callback is invoked. This is an engineering acceptance rule, not a replacement for the ZK relation.

## 2. Exact canonical encoding

The exact domain strings are ASCII:

- TX_FIELDS_DOMAIN = 0PSP-TX-FIELDS-v2-SHAKE256
- TX_DIGEST_DOMAIN = 0PSP-TX-DIGEST-v2-SHAKE256

All integers are unsigned little-endian.

~~~text
TxFieldsV2 =
  TX_FIELDS_DOMAIN || 0x02 ||
  LE16(len(params_id)) || params_id ||
  namespace_id[48] ||
  commitment_root[48] ||
  public_nullifier[48] ||
  ledger_state_head[48] ||
  LE16(len(authorization_policy_id)) || authorization_policy_id ||
  LE64(fee) ||
  LE32(output_count) ||
  output_commitments[output_count][48]
~~~

Bounds are part of the format: params_id and authorization_policy_id are each 1..65535 bytes; fee is uint64; output count is 1..1024; each output commitment is 48 bytes; duplicates within one transaction are rejected; the decoder rejects unknown prefix/version, truncation, trailing bytes, inconsistent lengths and non-canonical round trips. Output note values remain hidden; the proof must tie each output commitment to its opening and prove value conservation. They are not serialized as plaintext.

The 48-byte digest is:

~~~text
TxDigestV2(fields) =
  SHAKE256-384(
    TX_DIGEST_DOMAIN || 0x02 ||
    LE32(len(fields)) || fields
  )
~~~

A known-answer regression uses params_id = "params-v2-test-2026", namespace derived from (ledger, deployment, asset), root 01 repeated 48 times, nullifier 02 repeated 48 times, state head 03 repeated 48 times, policy "policy-self-spend-v1", fee 123, and two output commitments (44 repeated 48 bytes, 55 repeated 48 bytes). Expected fields length: 370 bytes. Expected digest:

5bdbb402db099432d745fa39d652e06b83792ba0b7a2828bef2028fa0aa5012caade55ae7ce811012f44f2772e9e9e87

## 3. Enforcement

- src/protocol/transaction_v2.py contains the codec, exact decoder, digest recomputation and statement-consistency verifier.
- ReferenceLedger.accept_spend rejects non-canonical fields or any mismatch between decoded fields and SpendStatement before calling the injected verifier.
- SQLiteLedger.accept_spend does the same before calling the injected verifier and before entering the state transition commit path.
- Both paths require the separate transaction_digest to match the recomputed digest and require params ID, Namespace V3, current commitment root, nullifier, ledger-state head, authorization policy and output commitments to match the canonical bytes.
- tests/unit/test_transaction_v2.py tests the KAT, round trip, each field's digest separation, malformed/truncated/trailing encodings, bad bounds, repeated outputs, and statement-field/digest substitution.
- Existing reference/persistent ledger tests now construct valid statements through the canonical encoder rather than synthetic unrelated strings.

## 4. Exact limitation

The host codec closes only a public API consistency gap. A malicious prover can still submit a proof for a different relation if the proof backend does not constrain:

1. exact TxFieldsV2 encoding and TxDigestV2;
2. the same namespace, nullifier, commitment root, ledger head, policy and outputs used by all other predicates;
3. a single hidden commitment opening for CommitV2 and NullifierV2;
4. range-safe input value equals output values plus fee;
5. authorization under the accepted policy;
6. commitment membership and eligible/unspent state.

No actual ZK backend currently enforces those predicates, and the public-key codec/authorization mode are still not frozen. For that reason, the overall protocol and deposit-to-mint path remain **Production: NO-GO**.

## 5. Internal acceptance criteria

Before merging this change, CI must pass on the exact head:
- all existing Python and property tests;
- new tests/unit/test_transaction_v2.py;
- repository documentation/invariant integrity checks;
- no change to frozen Namespace V2/V3, CommitV2 or NullifierV2 KATs.

After merge, this gate can be marked **GO for the canonical host/API codec**, but **NO-GO for cryptographic transaction binding in production** until the actual proof backend uses and constrains these exact bytes.
