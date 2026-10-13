# OpenVM V3 nullifier feasibility spike

**Status: experimental, non-production.** This isolated guest checks one predicate slice: canonical BundleV3 parsing, the commitment opening for the recipient-held 48-byte nullifier key, the CommitV3 opening, and the candidate HMAC-SHA3-384 NullifierV3 relation. Its fixed vectors are copied from the Python reference tests.

The guest emits a 32-byte SHAKE256 digest over the declared public statement (params_id, namespace, commitment, nullifier). A future host prover/verifier harness must bind that output to the exact expected statement. This small guest does not authenticate who supplied the statement.

## Not included

- Merkle membership or a trusted/finalized state root.
- V3 issuance or transfer anchor/index derivation.
- Complete transaction-digest binding or output/value-conservation constraints.
- Spend authorization, recipient-address authentication, or note encryption/recovery.
- Durable atomic ledger transition or replay/uniqueness enforcement.
- End-to-end proof generation/verification, measured proving profile, composed 128-bit PQ bound, or independent cryptographic audit.

CI is intended to run host conformance/adversarial tests and compile the OpenVM guest. **A successful build is not a proof.** OpenVM v2's cited profile remains below the project's 128-bit PQ target, and witness hiding has not been independently established for this relation. Do not use this spike to authorize spends or freeze the V3 HMAC byte contract.
