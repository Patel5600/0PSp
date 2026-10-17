# Production-1 threat model

## Scope and profile

This model covers the local synthetic test-value Production-1 profile: a client constructs a 1-in/1-out witness, submits it over TLS to a single-tenant OpenVM 2.0.2 worker, verifies the returned proof locally, and submits to an SQLite ledger that re-verifies and commits the spend atomically. The guest and checker, app VK, circuit ID, executable commitment, and platform checker hashes are bound by the source-controlled Production-1 pin manifest.

The profile uses namespace-scoped depth-63 Merkle membership, CommitV3 opening, same-witness HMAC-SHA3-384 NullifierV3, range-safe value conservation, NK-possession authorization, transaction statement binding, and anchor/slot-bound output identity. Only one input and one output are accepted. The profile does not authenticate public-chain finality or authorize public-chain deposits.

## Assets and trust boundaries

Assets include note secrets (`nk`, commitment and nullifier randomness), note values and identity, witness bytes, proof integrity, public statement/root binding, nullifier uniqueness, output uniqueness, and local ledger consistency.

The client-to-worker boundary uses TLS and bearer authentication. Witness payloads remain in RAM, are not logged or written to disk, and mutable buffers are cleared after use. Proving takes place in a child process. Phase A trusts the single-tenant operator and worker with plaintext witness access. This is a trust assumption, not witness hiding from the worker. The host process, allocator copies, swap, hibernation, and crash dumps are not proven to erase every secret copy.

The worker-to-client boundary returns only proof, public inputs, prove time, and resource metrics. The client verifies against the pinned checker before submission. The SQLite ledger independently verifies within `BEGIN IMMEDIATE`, checks the retained anchor and duplicate state, inserts nullifier/output, and commits atomically. Local SQLite does not provide distributed consensus, external rollback protection, or reorg recovery.

## Adversaries and effects

| Adversary | Capabilities | What the profile protects | What breaks / residual risk |
|---|---|---|---|
| Honest-but-curious operator | Runs the worker correctly but examines RAM, process inputs, crash dumps or logs | TLS protects witness in transit; access logs omit bodies; worker does not intentionally persist witness | Operator can observe plaintext witness and link input/output to the client. Phase A does not provide witness confidentiality from the operator. |
| Malicious operator / compromised worker | Changes prover behavior, returns malformed/forged proof, replays data, records witness, denies service | Client and ledger verify proof against pinned OpenVM artifacts and exact public statement; ledger enforces nullifier/output uniqueness and atomic state transition | Operator can steal witness secrets, censor/deny proving, correlate requests, or serve modified code before pin verification. Verification should reject invalid proof/artifact substitution, but this does not prevent secret exfiltration during malicious proving. |
| Malicious client | Submits malformed witness, wrong anchor, reused nullifier/output, oversized payload, or conflicting spends | Strict parsing, fixed circuit, bounded requests, proof verification, anchor-ring preflight, uniqueness constraints, transaction rollback | Authenticated abuse can consume prover resources; per-peer rate limiting is not a substitute for infrastructure-level admission controls. |
| Local database operator / rollback | Edits or restores SQLite file, forks independent ledgers | Constraints and integrity checks detect many inconsistent local states; atomic commits prevent partial transitions | Privileged rollback or two independent ledgers can reaccept a spend. No external monotonic anchor/consensus exists. |
| Build or artifact attacker | Replaces guest, VK, checker, or pin manifest | Manifest digest, app executable commitment, VK hash, and platform checker hash are checked | A malicious source release/host environment or compromised pin update can authorize malicious artifacts; independently reproducible signed releases are not established. |

## Security boundaries

- The OpenVM verifier validates this pinned relation; the current parameter analysis is below 128 bits. No composed >=128-bit post-quantum claim is made.
- The proof system is not claimed to hide the witness from the proving worker/operator. No trace-masking or end-to-end witness-hiding claim is made.
- NK knowledge is the selected authorization predicate. Threshold/MPC signing, Monero ring signatures, RingCT, and LORTs are not implemented.
- The E2E faucet is local synthetic test value. Mainnet live value remains disabled and NO-GO. External audit is deferred and not performed.
- Phase B attested TEE is optional future work and is not implemented. MPC and secrecy from inside a TEE are out of scope.

## Evidence

`make production-check` is the release gate. It runs Rust and Python tests, builds the guest/checker, executes the authenticated TLS worker flow, verifies client-side and ledger-side, accepts one spend, and rejects a repeated spend. Detailed vectors, artifact hashes, measured proof costs, and remaining limitations are in `tests/vectors/production1-spend-v3/`, `proof/openvm/v3-nullifier-spike/production1-pins.json`, `BENCH.md`, and `docs/LIMITATIONS.md`.
