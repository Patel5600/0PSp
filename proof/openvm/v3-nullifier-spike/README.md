# OpenVM spend_v3 — Production-1 testnet profile

**Status:** Production-1 is scoped to local synthetic test value. Mainnet live value remains **NO-GO**. The active guest and host profile are frozen to one input and one output.

The guest constrains canonical TxFieldsV3, namespace-scoped depth-63/u64 Merkle membership, CommitV3 opening, same-witness HMAC-SHA3-384 NullifierV3, NK-possession authorization, 64-bit value conservation, output commitment opening, and output identity derived from the anchor context and slot zero. Exact public/private inputs and equations are in [`docs/security/ACCEPTED_SPEND_RELATION_V3.md`](../../../docs/security/ACCEPTED_SPEND_RELATION_V3.md).

The source-controlled Production-1 manifest pins the OpenVM app executable commitment, app verifying key digest, checker digests for supported x86_64 builds, backend version, profile, and circuit ID. The client verifies the proof locally; the SQLite testnet ledger independently verifies it again inside the atomic spend transaction. The `mainnet_live` profile always rejects.

## Clean-machine Production-1 check

Use Linux x86_64 with Rust 1.91.1, `rust-src`, `riscv64-unknown-elf-gcc` 15.3.0, OpenSSL, Python 3.11+, and `make`. The cross-compiler version is pinned because it affects the guest executable commitment. From the repository root:

```sh
rustup toolchain install 1.91.1 --profile minimal --component rust-src
sudo apt-get update
sudo apt-get install --yes build-essential gcc-riscv64-unknown-elf openssl make python3-pip
test "$(riscv64-unknown-elf-gcc -dumpfullversion)" = "15.3.0"
python3 -m pip install -e '.[dev]'
```

Install the checksum-pinned cargo-openvm v2.0.2 release binary using the checksum and asset URL in [the OpenVM workflow](../../../.github/workflows/openvm-v3-nullifier-spike.yml), then run:

```sh
make production-check
```

The check builds the exact guest and Rust verifier, runs unit and adversarial tests, starts an authenticated TLS proof worker, mints a deterministic local test note, sends its witness to the worker, verifies the returned proof in the client, commits through the Production-1 SQLite profile, and confirms that a second spend of the same nullifier is rejected. It prints proof bytes, `prove_ms`, `verify_ms`, and prover peak RSS. The proving run is server-side and may take several minutes.

The test faucet/bootstrap is local and synthetic; it proves no public-chain issuance or external finality. Phase A sends plaintext witness to the trusted single-tenant worker operator. The profile does not claim end-to-end witness hiding or a composed 128-bit security bound. See [`docs/LIMITATIONS.md`](../../../docs/LIMITATIONS.md) and [`BENCH.md`](../../../BENCH.md).
