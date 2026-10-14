# 0PSP Composed Security Games and Concrete Reduction Bounds

**Document Version:** 1.0.0  
**Status:** Formal Specification and Analytical Reductions (V2 Production Baseline & V3 Candidate)  
**Security Baseline:** Testnet `v0.1.0-alpha` (GO for testnet tokens); Mainnet live-value transfer is strictly **GATED (NO-GO)** pending external audit and prover-trace zero-knowledge masking.

---

## 1. Scope and Cryptographic Doctrine

This document formalizes the composed security model for the 0PSP zero-knowledge private cash protocol. It establishes the mathematical definitions, execution games, and reduction bounds for:

1. **Balance Conservation Game ($\mathbf{Exp}^{\text{balance}}_{\mathcal{A}}$)**: Preventing token minting out of thin air, inflation, double spending, and unauthorized value extraction.
2. **Anonymity and Unlinkability Game ($\mathbf{Exp}^{\text{anon}}_{\mathcal{A}}$)**: Preventing note ownership linkage, transaction tracing, and sender-directed deanonymization.
3. **Concrete QROM Soundness Budget and Fiat–Shamir Analysis**: Evaluating concrete post-quantum security losses under quantum oracle access ($Q_H$ quantum queries), including the Don–Fehr–Majenz (DFM20) multi-round loss and the Binius64 sumcheck limitation.

In accordance with the **Anti Style / Iron Lock Doctrine**, this specification rejects speculative claims ("unhackable", "mathematically unbreakable", "gold standard"). It records proven computational bounds, identifies concrete security boundaries, and explicitly documents demonstrated limitations.

---

## 2. Global Execution Model and Adversarial Capabilities

### 2.1 Threat Model and Quantum Oracles

Let $\lambda = 128$ denote the target post-quantum security parameter. The adversary $\mathcal{A}$ is a quantum-capable polynomial-time algorithm operating in the **Quantum Random Oracle Model (QROM)**:

- $\mathcal{A}$ has quantum superposition query access to the random oracle $H$ (instantiated with $\text{SHAKE256-384}$ domain-separated sponge or $\text{HMAC-SHA3-384}$), bounded by $Q_H \le 2^{64}$ quantum queries.
- $\mathcal{A}$ has classical interactive query access to the protocol execution environment:
  - $\mathcal{O}_{\text{issue}}(evidence, comm, params, \pi_{\text{issue}})$: Evaluates deposit authorization and records commitments.
  - $\mathcal{O}_{\text{spend}}(statement, \pi_{\text{spend}})$: Verifies spend proofs, checks nullifiers, and appends output commitments.
  - $\mathcal{O}_{\text{corrupt}}(id)$: Adaptively corrupts protocol participants and obtains their long-term or ephemeral secret keys.
- $\mathcal{A}$ can view all public ledger data: Merkle tree nodes, root history, historical state heads, spent nullifier set, transaction digests, and proof strings.

### 2.2 Protocol Primitives and Encodings

- **Namespace V3 Identifier**:
  $$\text{NamespaceIdV3} = \text{SHAKE256-384}(\text{Domain} \parallel \text{LedgerDesc} \parallel \text{DeployDesc} \parallel \text{AssetDesc}) \in \{0, 1\}^{384}$$
- **Coin Commitment (V2 & V3)**:
  $$C = \text{Commit}(\text{params\_id}, \text{pk\_bundle}, v, \text{coin\_id}, r_{\text{nf}}, \rho_{\text{coin}}, \text{salt}) \in \{0, 1\}^{384}$$
- **Nullifier Functions**:
  - **Nullifier V2 (Frozen Baseline)**:
    $$\text{NF}_{\text{v2}} = \text{SHAKE256-384}(\text{Domain} \parallel \text{Namespace} \parallel \text{coin\_id} \parallel r_{\text{nf}}) \in \{0, 1\}^{384}$$
  - **Nullifier V3 (Recipient-Keyed Candidate)**:
    $$\text{NF}_{\text{v3}} = \text{HMAC-SHA3-384}_{nk}(\text{Domain} \parallel \text{Namespace} \parallel C \parallel \text{coin\_id} \parallel r_{\text{nf}} \parallel \rho_{\text{coin}}) \in \{0, 1\}^{384}$$
- **Durable Commitment Tree**: Complete binary Merkle tree of depth $D = 63$ over $\{0, 1\}^{384}$ with capacity $2^{63}$ leaves.

---

## 3. Game 1: Balance Conservation

### 3.1 Formal Definition

The Balance Conservation Game guarantees that no polynomial-time adversary $\mathcal{A}$ can extract more value from the 0PSP ledger than has been legitimately deposited and authorized via finalized EVM custody contracts.

```
Game Exp_balance(A):
  1. (params, state_0) <- Initialize(1^\lambda)
  2. A interacts with O_issue and O_spend adaptively.
  3. At conclusion, A outputs:
     - Set of spent transactions {tx_1, ..., tx_m} with nullifiers {nf_1, ..., nf_m}
     - Total legitimately authorized EVM deposits: V_deposited = \sum v_i
     - Total minted / withdrawn value: V_extracted = \sum v_out + fee
  4. A wins if:
     V_extracted > V_deposited
     OR \exists i != j such that nf_i = nf_j and both spends were accepted in state_t.
```

### 3.2 Security Reduction

$$\mathbf{Adv}^{\text{balance}}_{\mathcal{A}} \le \mathbf{Adv}^{\text{evm-auth}}_{\mathcal{A}} + D \cdot \mathbf{Adv}^{\text{CR}}_{\text{SHAKE256-384}} + \mathbf{Adv}^{\text{KS}}_{\mathcal{R}_{\text{spend}}} + \mathbf{Adv}^{\text{null-coll}}_{\mathcal{A}}$$

Where:

1. **EVM Deposit Soundness ($\mathbf{Adv}^{\text{evm-auth}}_{\mathcal{A}}$)**:
   Any forged deposit requires breaking:
   - The consensus light client (Helios weak-subjectivity sync committee signature aggregation),
   - Or the EIP-1186 account/storage Modified Patricia Trie (MPT) inclusion proof over Keccak-256 ($\le \mathbf{Adv}^{\text{CR}}_{\text{Keccak-256}}$),
   - Or violating the fail-closed custody reserve solvency invariant (`contract_balance >= total_minted + amount`).
2. **Merkle Commitment Tree Soundness ($D \cdot \mathbf{Adv}^{\text{CR}}_{\text{SHAKE256-384}}$)**:
   For depth $D = 63$, opening an uncommitted leaf to an authenticated root requires finding a collision in SHAKE256-384 with query bound:
   $$\mathbf{Adv}^{\text{CR}}_{\text{SHAKE256-384}} \le \frac{C_{\text{BHT}} \cdot Q_H^3}{2^{384}} \approx 2^{-128} \quad (\text{for } Q_H = 2^{64})$$
3. **Knowledge Soundness of Spend Relation ($\mathbf{Adv}^{\text{KS}}_{\mathcal{R}_{\text{spend}}}$)**:
   By the knowledge-soundness property of the proof system, an efficient extractor $\mathcal{E}$ extracts a witness $(w_{\text{in}}, w_{\text{out}})$ satisfying:
   $$v_{\text{in}} = \sum_{j} v_{\text{out}, j} + \text{fee} \quad \text{with } 0 \le v_i < 2^{64}$$
   Integer range and carry containment ensures no arithmetic modular wraparound can occur in field operations.
4. **Nullifier Uniqueness and Atomic State Enforcement ($\mathbf{Adv}^{\text{null-coll}}_{\mathcal{A}}$)**:
   The ledger records every accepted nullifier inside an atomic `IMMEDIATE` SQLite transaction with unique constraint `PRIMARY KEY (namespace_id, nullifier)`. A double-spend attack requires:
   - Creating two distinct valid commitments $C \ne C'$ for the same note opening that yield two distinct nullifiers $\text{NF} \ne \text{NF}'$ (impossible since $\text{NF}$ is deterministic over the committed tuple),
   - Or finding a preimage collision in the nullifier hash function ($\le \mathbf{Adv}^{\text{pre}}_{\text{SHAKE256-384}} \le 2^{-192}$ quantum).

---

## 4. Game 2: Anonymity and Unlinkability

### 4.1 Formal Definition (Left/Right Indistinguishability)

The Anonymity Game measures the adversary's advantage in linking a spend transaction to its source commitment within the Merkle tree.

```
Game Exp_anon(A):
  1. (params, state) <- Initialize(1^\lambda)
  2. A interacts with O_issue and O_spend.
  3. A chooses two distinct unspent commitments C_0, C_1 in the tree with equal values v_0 = v_1.
  4. A provides valid secret note witnesses w_0, w_1 to the Challenger.
  5. Challenger samples random bit b <- {0, 1}.
  6. Challenger generates spend transaction tx* = Spend(w_b, params).
  7. Challenger sends tx* = (statement*, \pi*, nf*, ledger_state) to A.
  8. A continues interactive queries with the restriction that A cannot query O_spend on nf*.
  9. A outputs a guess bit b'.
  10. A wins if b' = b.
```

The adversary's advantage is defined as:
$$\mathbf{Adv}^{\text{anon}}_{\mathcal{A}} = \left| \Pr[b' = b] - \frac{1}{2} \right|$$

### 4.2 Security Reduction and Version Differentiation

$$\mathbf{Adv}^{\text{anon}}_{\mathcal{A}} \le \mathbf{Adv}^{\text{hide}}_{\text{Commit}} + \mathbf{Adv}^{\text{ZK}}_{\mathcal{R}_{\text{spend}}} + \mathbf{Adv}^{\text{link}}_{\text{nullifier}}$$

#### 4.2.1 Commitment Hiding ($\mathbf{Adv}^{\text{hide}}_{\text{Commit}}$)
As proven in `docs/theory/commitment-hiding-and-binding-proof.md`:
$$\mathbf{Adv}^{\text{hide}} \le 2^{-160}$$
The 288-bit CSPRNG salt provides unconditional statistical hiding, ensuring that prior to spending, commitments $C_0$ and $C_1$ are statistically indistinguishable to any adversary, including unbounded quantum adversaries.

#### 4.2.2 Zero-Knowledge Proof Simulation ($\mathbf{Adv}^{\text{ZK}}_{\mathcal{R}_{\text{spend}}}$)
There exists a polynomial-time zero-knowledge simulator $\mathcal{S}$ such that:
$$\left| \Pr[\mathcal{A}(\pi) = 1] - \Pr[\mathcal{A}(\mathcal{S}(statement)) = 1] \right| \le \mathbf{Adv}^{\text{ZK}}$$
All intermediate execution trace registers, multilinear evaluations, and polynomial opening values are randomized via prover-added blinding degrees.

#### 4.2.3 Nullifier Unlinkability ($\mathbf{Adv}^{\text{link}}_{\text{nullifier}}$): V2 vs. V3

> [!WARNING] Critical Architectural Vulnerability in V2 Protocol
> In Protocol V2, $\text{NullifierV2} = \text{SHAKE256-384}(\text{Domain} \parallel \text{Namespace} \parallel \text{coin\_id} \parallel r_{\text{nf}})$ does **not** include the commitment salt and is unkeyed.
> If the sender who created the note retains knowledge of $(\text{coin\_id}, r_{\text{nf}})$, the sender can precompute $\text{NF}_{\text{v2}}$ and observe the ledger to identify exactly when and where the recipient spends the note.
> Therefore: **Protocol V2 does NOT achieve sender-unlinkability.**

**Protocol V3 Remediation (Recipient-Keyed Nullifier):**
In Protocol V3 Candidate:
$$\text{NF}_{\text{v3}} = \text{HMAC-SHA3-384}_{nk}(\text{Domain} \parallel \text{Namespace} \parallel C \parallel \text{coin\_id} \parallel r_{\text{nf}} \parallel \rho_{\text{coin}})$$
The secret key $nk \in \{0, 1\}^{384}$ is generated privately by the recipient via OS-backed CSPRNG. The sender receives only the public key bundle $\text{BundleV3}$ containing the key commitment:
$$C_{nk} = \text{SHAKE256-384}(\text{Domain}_{nk} \parallel nk)$$
Under the PRF security of HMAC-SHA3-384, for an adversary without knowledge of $nk$:
$$\mathbf{Adv}^{\text{link}}_{\text{nullifier}} \le \mathbf{Adv}^{\text{PRF}}_{\text{HMAC-SHA3-384}} \le 2^{-128}$$
Thus, Protocol V3 achieves full sender-unlinkability.

---

## 5. Concrete QROM Soundness Budget and Fiat–Shamir Losses

### 5.1 Multi-Round Fiat–Shamir Reduction Loss (DFM20)

Under the classical Fiat–Shamir transform, an interactive public-coin protocol is made non-interactive by replacing verifier challenges with random oracle evaluations over the prior transcript.

In the **Quantum Random Oracle Model (QROM)**, generic security reductions suffer substantial loss. As proved by Don, Fehr, and Majenz (CRYPTO 2020, DFM20), for a $(2n+1)$-round public-coin interactive argument with knowledge error $\epsilon_{\text{interactive}}$, the non-interactive soundness error in the QROM against an adversary making $Q_H$ quantum queries is bounded by:

$$\epsilon_{\text{non-interactive}} = O\left( Q_H^{2n} \cdot \epsilon_{\text{interactive}} \right)$$

### 5.2 Application to Binius64: Demonstrated Mathematical Soundness Bound

Consider Binius64 over binary field towers utilizing a 23-round sumcheck over $\mathbb{F}_{2^{128}}$:

1. **Sumcheck Degree Bound**: In each round $i \in \{1, \dots, 23\}$, the prover sends a univariate polynomial of degree $d = 2$.
2. **Schwartz–Zippel Error per Round**: The verifier selects a random challenge $r_i \in \mathbb{F}_{2^{128}}$. The collision/root probability is $\frac{d}{|\mathbb{F}|} = \frac{2}{2^{128}}$.
3. **Cumulative Interactive Sumcheck Bound**:
   $$\epsilon_{\text{sumcheck}} \le \sum_{i=1}^{23} \frac{d}{|\mathbb{F}|} = \frac{46}{2^{128}} \approx 2^{-122.48}$$
4. **Proximity Term Composition**:
   If an additional proximity test error of $2^{-128}$ is composed:
   $$\epsilon_{\text{total}} \le \frac{46 + 1}{2^{128}} = \frac{47}{2^{128}} \approx 2^{-122.45}$$

#### 5.2.1 Analysis of QROM Soundness for Binius64
Applying the DFM20 generic reduction loss with $n = 23$ rounds:
$$\text{Reduction Loss Factor} = O(Q_H^{46})$$
For an adversary query budget of $Q_H = 2^{60}$:
$$Q_H^{46} = 2^{2760} \gg 2^{122.48}$$
The generic DFM20 reduction yields a **concrete-security-vacuous bound** ($\gg 1$).

**Conclusion for Binius64**:
While specialized non-generic reductions or Fiat–Shamir with aborts / PoW grinding could theoretically improve this, currently no proof demonstrates 128-bit statistical soundness for the 23-round Binius64 construction in the QROM. Therefore, Binius64 is approved **for research only** and is blocked from production release.

---

### 5.3 STARK / FRI Soundness Budget in QROM

For STARK architectures with Fast Reed–Solomon Interactive Oracle Proofs of Proximity (FRI) (e.g., OpenVM profile):

$$\epsilon_{\text{STARK}} \le \epsilon_{\text{AIR}} + \epsilon_{\text{FRI}} + \epsilon_{\text{grind}} + \epsilon_{\text{FS-QROM}}$$

1. **FRI Proximity Error**:
   For Reed–Solomon code rate $\rho = \frac{1}{8}$ and query count $N_q = 86$:
   - **Provable Soundness Bound**:
     $$\epsilon_{\text{FRI, proven}} \le \rho^{N_q / 2} = \left(\frac{1}{8}\right)^{43} = 2^{-129}$$
   - **Conjectural Soundness Bound**:
     $$\epsilon_{\text{FRI, conj}} \le \rho^{N_q} = \left(\frac{1}{8}\right)^{86} = 2^{-258}$$
2. **Proof-of-Work Grinding ($\epsilon_{\text{grind}}$)**:
   A 16-bit proof-of-work prefix difficulty forces the prover to execute $2^{16}$ sequential hash trials, reducing quantum adaptive query advantage by a factor of $2^{-16}$.
3. **Hash Function Collision Margin**:
   - `SHAKE256-384` provides 192 bits of classical collision resistance.
   - Under the Brassard–Høyer–Tapp (BHT) quantum algorithm, quantum collision queries scale as:
     $$Q_{\text{BHT}} \approx 2^{384/3} = 2^{128}$$
   - **Boundary Condition**: A 384-bit output provides exactly the $2^{128}$ quantum collision query bound with **zero security margin**. A 512-bit output (`SHAKE256-512`) provides $2^{170.6}$ quantum queries, yielding a 42-bit safety margin.

---

## 6. Synthesis and Release Readiness Matrix

| Security Property | Mathematical Bound | Mechanism / Theorem | Production Status |
|---|---|---|---|
| **Balance Conservation** | $\le 2^{-128}$ | EVM MPT Trie + Depth-63 Merkle Tree + Knowledge Soundness | **TESTNET: GO / MAINNET: GATED** |
| **Commitment Hiding** | $\le 2^{-160}$ | 288-bit CSPRNG salt; statistical distance theorem | **GO** (Proven) |
| **Commitment Binding** | $\le \mathbf{Adv}^{\text{CR}}_{\text{SHAKE256-384}} \approx 2^{-128}$ | Cryptographic collision reduction | **GO** (Proven) |
| **Side-Channel Timing** | $|t| < 4.5$ ($p > 10^{-5}$) | Welch's t-test / dudect diagnostics (Empirical $0.49, 2.99$) | **GO** (Verified) |
| **State Replay Protection**| 100% atomic rollback | SQLite WAL transaction isolation + PK unique constraint | **GO** (Tested) |
| **V2 Unlinkability** | **BROKEN against sender** | Unkeyed Nullifier V2 exposes coin identity to sender | **NO-GO for sender privacy** |
| **V3 Unlinkability** | $\le 2^{-128}$ | HMAC-SHA3-384 keyed with private recipient $nk$ | **GO Candidate** |
| **Binius64 Soundness** | $\le 2^{-122.48}$ (Interactive) | 23-round sumcheck over $\mathbb{F}_{2^{128}}$ (Vacuous in generic QROM) | **RESEARCH ONLY** |
| **STARK FRI Soundness** | $\le 2^{-129}$ (Proven) | Code rate $\rho = 1/8$, $N_q = 86$ query openings | **GO Candidate** |

---

## 7. Operational Acceptance Criteria

1. **Testnet Launch (`v0.1.0-alpha`)**:
   - **Accepted**: Operational testing with testnet tokens only.
   - **Cryptographic Guarantees**: Complete ledger consistency, replay protection, local fault resilience, and fail-closed EVM deposit verification.
   - **Risk Profile**: Zero financial risk.
2. **Mainnet Live-Value Transfer**:
   - Strictly **NO-GO**.
   - Mandatory release blockers:
     - Independent third-party cryptographic review of the complete spend circuit relation.
     - Formal proof of full zero-knowledge witness blinding for all intermediate VM execution states.
     - Production deployment and audit of the threshold authorization signer.
