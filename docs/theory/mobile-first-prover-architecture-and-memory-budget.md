# 0PSP Mobile-First Prover Architecture and Memory Budget Specification

**Specification Version:** 1.0.0  
**Target Hardware:** Consumer Mobile Devices (Android ARM64, iOS Apple Silicon)  
**Maximum Client Memory Budget:** $\le 128\text{ MB}$ RAM  
**Maximum Client Proving Latency:** $\le 5.0\text{ seconds}$  
**Reference Model:** [`scripts/estimate_mobile_prover_budget.py`](../../scripts/estimate_mobile_prover_budget.py)  
**Security Invariant:** Formal Statistical & Computational Witness Hiding under Blind Delegation

> [!IMPORTANT]
> **Methodological Distinction: Empirical Measurements vs. Analytical Projections**
> - **Empirically Measured (x86_64 CI Server):** The OpenVM v2.0.2 peak memory figure ($2,732\text{ MB}$ peak RSS) was empirically captured during automated GitHub CI runs on an Ubuntu x86_64 runner.
> - **Analytical Projections & Target Budgets:** ARM64 latencies, Native AIR estimates, and Tier 1 mobile footprint ($22.5\text{ MB}$) are analytical models derived from constraint row calculations, hardware instruction models, and BabyBear field evaluation domains. They represent strict engineering budgets and architectural targets, not physical device benchmarks of a production mobile client.

---

## 1. The Mobile Reality: Why NASA-Scale RAM Fails

A privacy primitive that requires a supercomputer or a 64 GB workstation is dead on arrival for consumer adoption. 0PSP prioritizes **real-world smartphone users**, where devices operate under strict operating system memory and thermal constraints:

1. **Android Low Memory Killer (LMK):**
   - On budget Android devices (3 GB – 4 GB total RAM), the OS kernel forcefully terminates any process whose resident set size (RSS) spikes above **$384\text{ MB}$** with `SIGKILL`.
2. **iOS Jetsam Process Limits:**
   - Foreground iOS applications receive memory pressure warnings around **$256\text{ MB}$** and face hard termination above **$350\text{ MB} - 500\text{ MB}$**. App extensions are restricted to $\le 50\text{ MB}$.
3. **Thermal & Battery Throttling:**
   - Sustained multi-minute CPU execution at 100% utilization triggers severe mobile core downclocking (thermal throttling), causing a 2-minute desktop proof to stretch to **8 to 15 minutes on a phone**, draining significant battery.

### Summary of Audited Prover Architectures on Mobile

| Architecture | Peak RAM | ARM64 Time | Android Status | iOS Status | Feasibility on Mobile |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Dense R1CS (SmallWood)** | $\ge 2.082\text{ TiB}$ | $\infty$ | **FATAL OOM** | **FATAL OOM** | ⛔ **REJECTED (CHp4.22)** |
| **Monolithic zkVM (OpenVM v2.0.2)** | $2,732\text{ MB}$ *(Measured CI)* | $185\text{ s}$ *(Projected)* | **FATAL OOM** | **FATAL OOM** | ⛔ **OOM Crash on Phone** |
| **Native Keccak AIR (Plonky3/Binius)** | $180\text{ MB}$ *(Model)* | $9.5\text{ s}$ *(Model)* | **BORDERLINE** | **BORDERLINE** | ⚠️ **High Pressure** |
| **2-Tier Blinded Split-Prover (Tier 1)** | **$22.5\text{ MB}$** *(Target)* | **$0.38\text{ s}$** *(Target)* | **✅ FEASIBLE** | **✅ FEASIBLE** | **TARGET ARCHITECTURE** |

---

## 2. Root Cause: The 82% Merkle Tree Wall

In 0PSP spend verification, computing the hash preimages in pure C11 ([`native/`](../../native)) takes **less than 0.2 milliseconds** on an ARM64 Cortex-A78 core. The cryptographic math itself is blindingly fast.

The memory blowout occurs entirely inside the **Zero-Knowledge Prover**, specifically due to the depth-63 Merkle tree:

$$\text{Total SHAKE Calls} = 68 \quad \implies \quad 63 \text{ calls belong to Merkle tree traversal } (92.6\%)$$
$$\text{Total Keccak-f Permutations} = 153 \quad \implies \quad 126 \text{ permutations belong to Merkle tree } (82.35\%)$$

Traversing 63 levels of an append-only tree in general-purpose zkVM instructions forces the prover to evaluate over **16 million trace rows ($2^{24}$)**, expanding intermediate polynomial evaluation domains into **$2.73\text{ GB}$ of RAM**.

---

## 3. The Solution: 2-Tier Blinded Split-Prover Architecture

To enable instant, zero-crash mobile spend generation, 0PSP defines the **2-Tier Blinded Split-Prover Architecture**:

```
+-----------------------------------------------------------------------------------------+
|                                MOBILE DEVICE (Tier 1 Client)                             |
|  - Private Witness: (nk, coin_id, r_nf, salt, value v)                                   |
|  - Peak RAM Target: <= 22.5 MB  |  Target Latency: <= 0.38 s                             |
|                                                                                         |
|  1. Verify CommitV3 opening: C_in = SHAKE256(params, bundle, v, coin_id, r_nf, salt)    |
|  2. Verify NullifierV3:     N_V3 = HMAC-SHA3-384_nk(ns, C_in, params, coin_id, r_nf)    |
|  3. Verify Value Balance:   v_in = v_out + fee                                          |
|  4. Generate Proof:         pi_local (Tier 1 ZK Proof over only 5 SHAKE calls)          |
+-----------------------------------------------------------------------------------------+
                                         │
                                         ▼ [Public Request: (C_in, N_V3, pi_local, outputs)]
                        (No secret keys, amounts, or salts sent)
                                         │
+-----------------------------------------------------------------------------------------+
|                           UNTRUSTED RELAYER / SERVER (Tier 2)                           |
|  - Public Inputs: C_in, N_V3, pi_local, outputs, Merkle root                             |
|  - Hardware: Server / Desktop / High-Spec Node                                          |
|                                                                                         |
|  1. Verify pi_local (Recursive STARK / SNARK verification)                              |
|  2. Prove Merkle Path: C_in in Tree(root) across tree_depth levels                       |
|  3. Output Composed Proof: pi_spend                                                     |
+-----------------------------------------------------------------------------------------+
```

### 3.1 Tier 1: Mobile Edge Prover (Strict Local Isolation)
- **Scope:** The mobile device proves *only* the predicates that directly consume private witness values:
  1. Note commitment opening: $C_{\text{in}} = \text{CommitV3}(params, bundle, v, ns, coin\_id, r_{\text{nf}}, salt)$.
  2. Nullifier derivation: $N_{\text{V3}} = \text{NullifierV3}(nk, C_{\text{in}}, \dots)$.
  3. Output commitment openings and range-bound value balance: $v_{\text{in}} = \sum v_{\text{out}} + \text{fee}$.
- **Workload:** Only **5 SHAKE calls** (compared to 68 in the full relation).
- **Resource Footprint Target:**
  - Trace Rows: $32,768$ ($2^{15}$ rows).
  - Peak RAM: **$22.5\text{ MB}$** for 1 output ($40.5\text{ MB}$ for 5 outputs, scaling with $18.0 + 4.5m\text{ MB}$).
  - Proving Time: **$\approx 380\text{ ms}$** on mobile ARM64 NEON.

### 3.2 Tier 2: Delegated Relayer Prover & Witness Hiding Conditions

> [!CAUTION]
> **Cryptographic Security Hypothesis & Required Soundness Conditions (Gated on ZK Trace Blinding)**
>
> Let the public handoff tuple sent by the mobile client to the untrusted relayer be:
> $$\text{Req}_{\text{Tier1}} = \left( C_{\text{in}}, N_{\text{V3}}, \pi_{\text{local}}, \{C_{\text{out}}^{(j)}\}, \text{fee} \right)$$
>
> Under this hypothesis, an untrusted relayer observing $\text{Req}_{\text{Tier1}}$ learns zero non-trivial information regarding the private witness $w = (v, nk, coin\_id, r_{\text{nf}}, salt)$ **if and only if** the following three cryptographic conditions hold:
> 1. **Commitment Hiding:** $C_{\text{in}}$ is statistically hiding in the QROM ($\text{Adv}^{\text{hide}} \le 2^{-160}$, formally proven in [`commitment-hiding-and-binding-proof.md`](commitment-hiding-and-binding-proof.md)).
> 2. **Nullifier Pseudorandomness:** $N_{\text{V3}}$ is computed via HMAC-SHA3-384 under key $nk$, acting as a cryptographically secure PRF over distinct canonical preimages.
> 3. **Prover Zero-Knowledge (ZK Blinding Rows):** The local argument $\pi_{\text{local}}$ is generated by a prover with verified randomized blinding rows enabled in its execution trace and quotient polynomial.
>
> **Mandatory Implementation Gate (P0 Issue #36):** In the absence of circuit-level randomized ZK blinding rows, polynomial evaluation queries allow an adversarial relayer to extract linear combinations of witness bits. Composed zero-knowledge witness privacy remains an unproven hypothesis until P0 Issue #36 is implemented and verified.

---

## 4. Alternative Path: Monolithic Binary Tower AIR (Binius / Stwo)

For sovereign users who refuse any delegation and insist on running 100% monolithic proofs on-device:

- **Binius Binary Field Towers ($\mathbb{F}_2$):**
  Keccak-f[1600] operations ($\chi$ nonlinear layer, $\theta$ linear parity) operate on bits.
  In a characteristic-two binary tower field, bitwise XOR is addition ($+$) and bitwise AND is multiplication ($\times$).
  - Trace columns shrink from 1,200 general CPU columns down to **64 dedicated state columns**.
  - Monolithic RAM drops from $2,732\text{ MB}$ down to **$180\text{ MB}$**.
  - Feasible on modern mid-range smartphones (6 GB – 8 GB RAM), though still higher than the 2-Tier Split-Prover.

---

## 5. Mobile Consensus Profile: Depth-32 Tree Scaling

While the consensus layer maintains a depth-63 Merkle tree ($2^{63}$ capacity), mobile clients can optionally operate on a **Depth-32 Subtree Index**:

$$2^{32} = 4,294,967,296 \text{ coins (4.29 Billion Coins)}$$

- Accommodates global consumer scale.
- Eliminates 31 levels of hash operations from the client-side tree verification path (reducing permutations from 153 to 91, a $40.5\%$ reduction).
- In Native AIR architectures, active execution trace buffers shrink proportionally, reducing RAM and proving latency. Note that for STARK provers whose quotient polynomial degree requires padding to the next power of two, both depth 63 ($16.78\text{M}$ active rows in zkVM) and depth 32 ($9.98\text{M}$ active rows) quantize to a $2^{24}$ domain; thus base LDE domain memory remains invariant while active trace buffers and proving execution times scale down linearly.
- Evaluated dynamically in [`scripts/estimate_mobile_prover_budget.py`](../../scripts/estimate_mobile_prover_budget.py).

---

## 6. Implementation Status and Roadmap Checklist

The mobile-first architecture is an active engineering track with the following milestone boundaries:

- [x] **Analytical Memory & Resource Model:** Parameterized scaling script implemented and verified ([`scripts/estimate_mobile_prover_budget.py`](../../scripts/estimate_mobile_prover_budget.py)).
- [x] **Native Cryptographic Engine:** Zero-dependency C11 constant-time engine ([`native/`](../../native)) tested and compatible with Android NDK and iOS Clang.
- [x] **Tier 1 Mobile Edge Cryptographic Engine:** Zero-heap C11 implementation ([`native/tier1_mobile.c`](../../native/tier1_mobile.c), [`native/include/psp_tier1_mobile.h`](../../native/include/psp_tier1_mobile.h)) enforcing value conservation, NK-possession authorization, deterministic output identity, canonical TxFieldsV3 encoding, and spend package generation.
- [x] **Mobile Language & Platform Bindings:** Android JNI interface ([`native/psp_jni.c`](../../native/psp_jni.c)), iOS/C-FFI umbrella header ([`native/include/psp_mobile.h`](../../native/include/psp_mobile.h)), and Python ctypes adapter ([`src/adapters/native_mobile_adapter.py`](../../src/adapters/native_mobile_adapter.py)) with 100% differential test coverage.
- [x] **Subtree Merkle Verification (Depth-32 & Depth-63):** Constant-time on-device path verification for mobile consensus profiles ([`native/merkle_tree_v3.c`](../../native/merkle_tree_v3.c)).
- [ ] **Tier 1 Guest Spend Circuit (Open Engineering Milestone):** Implement isolated 5-hash private witness circuit in OpenVM / Plonky3 with verified ZK trace blinding.
- [ ] **Blind Delegation RPC Protocol (Open Engineering Milestone):** Define fail-closed client-relayer JSON-RPC interface with mutual authentication and relay censorship resistance.
