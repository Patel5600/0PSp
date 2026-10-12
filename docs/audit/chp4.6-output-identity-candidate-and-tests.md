# CHp4.6 — Output identity candidate implementation and regression evidence

**Status:** reference candidate implemented; protocol fix is **not accepted or proven**.  
**Production:** **NO-GO**.  
**Change class:** reference helper, selected known-answer vectors, adversarial tests and maintainer documentation only.  
**V2 primitives/KATs:** unchanged.

## Decision

The coin issue is **not fully solved at protocol level**. This change implements a concrete hidden-witness output-identity candidate and tests it against the repository's actual V2 Python reference primitives. It closes a practical gap in the design work by specifying candidate field widths and hardcoded regression vectors. It does not close the ZK proof or production-ledger release gates.

## Candidate derivation

For one canonical primary input selected under the future transaction schema, the helper computes the existing V2 nullifier from the exact parent tuple and constructs two domain-separated SHAKE256 preimages. Each binds the candidate derivation version and parameter ID, 48-byte namespace, actual 48-byte parent V2 nullifier, parent 32-byte coin ID and 36-byte nullifier secret, scheme-canonical encoded spend-key witness (LE32 length-prefixed), 32-byte transaction entropy, and canonical uint16 big-endian output index.

The output coin ID is 32 bytes; output r_nf is 36 bytes. The current V2 commitment and nullifier equations are unchanged. The output's V2 nullifier is computed by the repository's existing compute_nullifier_v2 helper.

The scheme-specific spend-key encoding is not frozen. The helper cannot establish that the key witness matches the input public key, that transaction entropy was sampled honestly, or that a ZK verifier constrains the derivation.

## Security boundary

Distinct output indices yield distinct encoded derivation inputs, not mathematically guaranteed distinct hash outputs. The security goal is that valid accepted outputs do not unintentionally share a nullifier except with a stated negligible probability under a reviewed construction. The 32-byte coin ID alone has a generic 128-bit birthday collision target; do not transfer a 192-bit nullifier birthday bound to the shorter coin ID. The joint tuple requires its own formal analysis under the adversarial model.

The privacy claim is an open obligation, not a privacy proof. No claim of global uniqueness, zero leakage, ZK soundness, or recipient safety is made. Finite KATs validate byte-level regression only.

## Tests added

The test file uses actual repository functions commit_coin_v2 and compute_nullifier_v2 and hardcodes selected vectors for parent nullifier, derived 32-byte coin ID, 36-byte r_nf, output nullifier and V2 commitment. It includes a second output index, reference predicate substitution rejection, the original same-tuple failure mode, selected witness/context substitutions, and canonical output-index/field-length checks.

The tests are not a ZK circuit. They cannot prove the actual proof system will reject a malicious witness.

## Mandatory next work before calling this solved

A selected proof backend must constrain one shared relation that binds input membership/opening, the exact parent nullifier, authorization witness consistency with the input public key, canonical primary-input selection, output indexing, both derivations, each output commitment opening, recipient key/value, transaction binding and value conservation. An actual verifier must reject a malicious output-tuple substitution in negative proof tests.

Transaction schema, note encryption/delivery, entropy policy, privacy/leakage game, proof assumptions, durable atomic nullifier ledger, reorg/recovery behavior, and independent cryptographic audit remain mandatory blockers.

**Conclusion:** an executable reference candidate and selected regression tests are now added, but the issue remains unsolved at protocol/production level until the proof relation enforces this candidate and independent review confirms the security argument. Production remains **NO-GO**.
