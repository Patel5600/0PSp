# spend_v3 measurements

## Soundness parameter analysis

Reproduce the parameter analysis with:

```sh
cargo +1.91.1 test --manifest-path proof/openvm/v3-nullifier-spike/proof-output-checker/Cargo.toml --locked --bin openvm-v3-sdk-runner security_profile_tests -- --nocapture
```

The test uses the pinned OpenVM 2.0.2 / stark-backend v2.0.1 `SoundnessCalculator`, the proposed parameter constructors in `openvm-v3-sdk-runner.rs`, and explicit bounds for constraints, AIR count, log height, columns, and interactions. The test process reports:

| Component | Calculated soundness | Limiting term | Target |
|---|---:|---|---:|
| App | 102.63 bits | WHIR mu-batching (102.63) | 128 bits |
| Leaf | 102.63 bits | WHIR mu-batching (102.63) | 128 bits |
| Internal | 100.98 bits | WHIR OOD round-by-round bound (100.98) | 128 bits |

The test prints every component from `SoundnessCalculator`, including the minima above. These are reproducible parameter-analysis outputs, not proof measurements and not a security certification. None reaches the target. Increasing only LogUp grinding cannot fix the current bottleneck because the minimum is in WHIR.

## Prover and proof costs

Measured on Kali Linux rolling under WSL2, Linux 6.6.87.2-microsoft-standard-WSL2, AMD Ryzen 5 7530U (6 cores / 12 threads), using OpenVM CLI 2.0.2, rustc 1.91.1, and `riscv64-unknown-elf-gcc` 15.3.0. The runner emitted these stage measurements:

| Operation | Time | Proof bytes |
|---|---:|---:|
| App key generation | 0.273 s | - |
| Narrow application fixture prove | 395.484 s | 645,097 |
| Narrow application fixture verify | 2.601 s | - |
| Complete `spend-valid` fixture prove | 415.161 s | 660,320 |
| Complete `spend-valid` fixture verify | 2.547 s | - |

The runner reported peak resident memory of 3,376,436 KiB across keygen, proving, and verification. The complete spend proof SHA-256 is `002475b9df4d392a8aa4bf2b906dd9b86152689524f3beb4d133649f38efe29c042893ad324eb20caf4b6dc5f49924ceb0c8a64f2d530a1a719fd24bfce11ae7`. The pinned app VK SHA-256 is `0da298daf04036ef93407a00495a74a4bce0cee7fe6fdb4055364b1a2176d699`; the app executable commitment is `002475b9df4d392a8aa4bf2b906dd9b86152689524f3beb4d133649f38efe29c`. The complete spend proof was accepted by the standalone checker and by the SQLite integration, which rejected replay atomically. These are single-run measurements from a local WSL host, not a stable benchmark distribution or a deployment capacity guarantee.

## Controlled Merkle-depth experiment (exploratory, not a release profile)

Measured 2026-10-17 from base release source `a32cdb6b6377f13329943426bed5d229f0165f1c` on Kali Linux under WSL2 (Linux 6.6.87.2-microsoft-standard-WSL2), AMD Ryzen 5 7530U (6 cores / 12 threads), 7.4 GiB guest-visible RAM. Each row is one run; no repeated-run distribution is available. Both used OpenVM 2.0.2 and the same `openvm-v3-sdk-runner prove-stdin` harness. Elapsed time includes runner startup, app key generation, proving, and the runner's self-verification. Peak RSS is sampled from `/proc/<pid>/status` `VmHWM`. It excludes TLS worker, client verification, and ledger apply; these measurements are not the pinned production verifier path.

| Guest depth | Benchmark `params_id` | Witness bytes | Proof bytes | Elapsed | Peak RSS |
|---:|---|---:|---:|---:|---:|
| 63 | `v3-candidate-params` (existing control fixture) | 3,987 | 660,320 | 655.056 s | 3,011,652 KiB |
| 32 | `production1-testnet-depth32-bench-v1` (isolated temporary variant) | 2,499 | 659,199 | 666.437 s | 2,987,356 KiB |

In this single pair the depth-32 run was 1.74% slower, while its serialized proof was 1,121 bytes (0.17%) smaller and peak RSS was 0.81% lower. The timing difference is within plausible run-to-run noise and shows no measured proving-time gain; it does not support the proposed 30-40% saving or a 3-5 minute target. The 31-level path reduction saves 31 SHAKE256-384 node hashes (and 62 Keccak-f permutations for these current preimage lengths), but those operations are only part of the whole OpenVM relation/prover cost.

The depth-32 variant was built and proved from a temporary copy only. It used exactly 32 membership siblings, a separate params ID, and a recomputed 32-level root; it was not pinned, not accepted by the host/ledger profile, and is not a release artifact. Lower depth keeps the node hash function unchanged but caps an epoch/tree at 2^32 leaves instead of 2^63 and requires a new root namespace/state and verifier profile. **Decision: retain the pinned depth-63 profile for now; do not adopt depth 32 on these measurements.** Before selecting any new depth, repeat randomized paired runs and integrate the candidate's params ID, host checks, guest vectors, verifier key, and tree lifecycle as one new profile.

## Worker-to-ledger end-to-end run

The clean Linux `make production-check` run completed on the same AMD Ryzen 5 7530U host under WSL2 (Linux 6.6.87.2). It used the checked-in Production-1 app VK and pins and reported:

| Operation | Measurement |
|---|---:|
| Worker prove time | 682,444.917 ms |
| Client local verify time | 224.389 ms |
| Proof size | 660,320 bytes |
| Prover peak RSS | 3,011,764 KiB |
| End-to-end result | Proof accepted; replay rejected |

The complete TLS worker → client local verification → SQLite acceptance → duplicate-spend rejection path was measured on a Dell 15 DC15255, AMD Ryzen 5 7530U (6 cores / 12 threads), 16 GiB RAM, Windows 11 Home Single Language build 26200. It used the same pinned OpenVM 2.0.2 guest, VK, checker, and Production-1 profile:

| Operation | Measurement |
|---|---:|
| Worker prove time | 569,423 ms |
| Client local verify time | 364 ms |
| Proof size | 660,320 bytes |
| Prover peak RSS | 3,630,504 KiB |
| End-to-end result | Proof accepted; replay rejected |

This is one local run, not a throughput or capacity promise. The worker remains single-tenant with concurrency one. Proving is intentionally server-side; these measured costs are not mobile-viable.

This measurement uses the committed Production-1 artifact pins (`proof/openvm/v3-nullifier-spike/production1-pins.json`) and is generated by the OpenVM 2.0.2 runner and Rust 1.91.1 toolchain on the named local WSL host. The client/mobile path is not a proving target; this machine's measured 6.9-minute spend prove and 3.2 GiB peak make the server-side prover mandatory for this profile. The proof still does not establish the 128-bit target; the measured OpenVM parameter analysis above is below 128 bits.
