# 0PSP Commitment Scheme: Formal Hiding, Binding, and Codec Specification

**Status:** Normative mathematical specification and reduction for Commitment V2 and Commitment V3.  
**Security Target:** 128-bit Post-Quantum Security ($\lambda = 128$).  
**Hash Primitive:** SHAKE256-384 (XOF length = 48 bytes = 384 bits).

---

## 1. Specification & Canonical Codecs

### 1.1 Commitment V2 Scheme
For a 48-byte namespace $N$, 32-byte scoped coin ID $c$, 36-byte nullifier secret $r_{nf}$, 36-byte commitment randomness $\rho_C$, unsigned 64-bit value $v$, parameter identifier $\text{params}$, and canonical public key $pk$:
$$\text{Preimage}_{V2} = \text{DOM}_{V2} \parallel 0\text{x}02 \parallel |params|_2 \parallel params \parallel |pk|_4 \parallel pk \parallel |v|_8 \parallel |N|_2 \parallel N \parallel |c|_2 \parallel c \parallel |r_{nf}|_2 \parallel r_{nf} \parallel |\rho_C|_2 \parallel \rho_C$$
$$C_{V2} = \text{SHAKE256-384}(\text{Preimage}_{V2})$$
where $\text{DOM}_{V2} = \texttt{"0PSP-COIN-COMMIT-v2-SHAKE256"}$.

### 1.2 Commitment V3 Scheme
In Commitment V3, the raw public key is replaced by the canonical `NotePublicKeyBundleV3`, which binds the spender's authorization public key to a hidden nullifier-deriving key commitment:
$$\text{Preimage}_{V3} = \text{DOM}_{V3} \parallel 0\text{x}03 \parallel |params|_2 \parallel params \parallel |\text{BundleV3}|_4 \parallel \text{BundleV3} \parallel |v|_8 \parallel |N|_2 \parallel N \parallel |c|_2 \parallel c \parallel |r_{nf}|_2 \parallel r_{nf} \parallel |\rho_C|_2 \parallel \rho_C$$
$$C_{V3} = \text{SHAKE256-384}(\text{Preimage}_{V3})$$
where $\text{DOM}_{V3} = \texttt{"0PSP-COIN-COMMIT-v3-SHAKE256"}$.

### 1.3 Canonical BundleV3 Codec
The public key bundle $\text{BundleV3}$ is encoded deterministically without ambiguity or trailing bytes:
$$\text{BundleV3} = \text{DOM}_{bundle} \parallel 0\text{x}03 \parallel |\text{auth\_scheme\_id}|_2 \parallel \text{auth\_scheme\_id} \parallel |\text{auth\_pk}|_4 \parallel \text{auth\_pk} \parallel |\text{nk\_comm}|_2 \parallel \text{nk\_comm}$$
- $\text{DOM}_{bundle} = \texttt{"0PSP-NOTE-PK-BUNDLE-v3"}$
- $\text{auth\_scheme\_id}$: UTF-8 identifier (1..65,535 bytes) defining the authorization policy.
- $\text{auth\_pk}$: Canonical public key bytes (1..$2^{32}-1$ bytes).
- $\text{nk\_comm}$: 48-byte commitment to the recipient's private nullifier key: $\text{nk\_comm} = \text{SHAKE256-384}(\texttt{"0PSP-NULLIFIER-KEY-COMMIT-v3-SHAKE256"} \parallel 0\text{x}03 \parallel nk)$.

---

## 2. Formal Security Theorems

### Theorem 1: Computational Binding
Let $\mathcal{A}$ be a probabilistic polynomial-time (PPT) classical or quantum adversary. The binding advantage $\mathbf{Adv}^{bind}_{\mathcal{A}}$ is the probability that $\mathcal{A}$ outputs two distinct openings for the same commitment $C$:
$$\mathbf{Adv}^{bind}_{\mathcal{A}} = \Pr\left[ C(m_0, \rho_0) = C(m_1, \rho_1) \land (m_0, \rho_0) \neq (m_1, \rho_1) \right]$$

**Reduction:**
Suppose $\mathcal{A}$ wins the binding game. Then $\mathcal{A}$ outputs two distinct preimages $X_0 \neq X_1$ such that $\text{SHAKE256-384}(X_0) = \text{SHAKE256-384}(X_1)$. Thus, any adversary that breaks the binding of Commitment V2 or V3 immediately breaks the collision resistance of SHAKE256-384:
$$\mathbf{Adv}^{bind}_{\mathcal{A}} \le \mathbf{Adv}^{CR}_{\text{SHAKE256-384}}$$

**Concrete Security Bound:**
For an output digest length $n = 384$ bits:
- **Classical Collision Resistance:** Under the birthday bound, collision search requires $O(2^{n/2}) = 2^{192}$ evaluations.
- **Quantum Collision Resistance (BHT Algorithm):** Under Brassard-Høyer-Tapp (BHT) optimal quantum collision search, the query complexity is:
  $$Q_{BHT} = \Theta(2^{n/3}) = 2^{384/3} = 2^{128} \text{ queries}.$$
This satisfies the post-quantum 128-bit security target $\lambda \ge 128$ with no security shortfall.

---

### Theorem 2: Statistical Hiding
Let $\mathcal{A}$ be an adversary with unbounded computational power that submits two challenge tuples $m_0, m_1$ where $m_i = (N, \text{Bundle}_i, v_i, c_i, r_{nf,i})$. The challenger picks $b \leftarrow \{0, 1\}$ and samples $\rho_C \leftarrow \{0, 1\}^{288}$ uniformly from the OS-backed CSPRNG. The challenger returns $C^* = C(m_b, \rho_C)$. $\mathcal{A}$ outputs a guess $b'$.

**Hiding Advantage:**
In the Random Oracle Model (ROM / QROM), because $\rho_C$ is chosen uniformly and independently from $\{0, 1\}^{288}$:
$$\mathbf{Adv}^{hide}_{\mathcal{A}} = \left| \Pr[b' = b] - \frac{1}{2} \right| \le \frac{Q_{hash}}{2^{|\rho_C|}} = \frac{Q_{hash}}{2^{288}}$$
where $Q_{hash}$ is the total number of hash queries made by the adversary.

Even for an adversary making $Q_{hash} = 2^{128}$ quantum random-oracle queries:
$$\mathbf{Adv}^{hide}_{\mathcal{A}} \le \frac{2^{128}}{2^{288}} = 2^{-160} \approx 0.$$

Therefore, Commitment V2 and Commitment V3 are **statistically hiding** against both classical and quantum adversaries.

---

## 3. Implementation Invariants & Verification

1. **Length-Prefixed Codec Non-Ambiguity:** Every variable-length field ($params$, $public\_key$, $N$, $c$, $r_{nf}$, $\rho_C$) includes an explicit little-endian length prefix. Because the field ordering is fixed and prefix-free, two distinct tuples cannot produce identical byte concatenations (Trivial Injection Lemma).
2. **Deterministic Error Handling:** The native and Python implementations reject:
   - Values $v \ge 2^{64}$.
   - Non-canonical bundle encodings or trailing garbage bytes.
   - Commitment randomness with length $\neq 36$ bytes.
3. **Re-Opening Verification:**
   Re-opening verification computes $C_{expected} = \text{commit}(...)$ and compares $C$ with $C_{expected}$ using constant-time equality (`hmac.compare_digest` in Python, constant-time assembly in native).
