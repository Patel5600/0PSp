# CHp4.21 — Static SHAKE arithmetization cost baseline

**Gate status:** **GO for this deterministic estimator only** after exact-branch CI; **NO-GO for actual proof feasibility and production use**.  
**Protocol formats:** frozen V2 byte contracts are unchanged.  
**External cryptographic audit:** **NOT PERFORMED**.  
**Purpose:** put a reproducible lower-level planning model ahead of any claim that SHAKE-based 0PSP predicates fit an available ZK backend.

## 1. Decision boundary

The repository freezes SHAKE256-384 for CommitV2, NullifierV2, TxDigestV2, and the depth-63 commitment tree. A candidate backend must constrain these exact computations. Replacing them with an algebraic hash would change the protocol construction and is not authorized by this checkpoint.

CHp4.21 adds `scripts/estimate_keccak_zk_cost.py` and boundary/regression tests. It is a static arithmetic model, not a Keccak gadget, proof generator, benchmark, formal circuit, or backend-selection decision. It does not change any cryptographic production gate from NO-GO.

## 2. Model

SHAKE256 has an absorb rate of 136 bytes. For an input message of length `m`, the number of absorb/permutation blocks is:

```text
blocks(m) = floor(m / 136) + 1
```

The extra block is required when the message length is an exact multiple of the rate. The requested output is 48 bytes, below the rate, so a single output digest does not require an additional squeeze permutation.

For a straightforward bit-sliced circuit over an odd-characteristic field, Boolean XOR can be represented as `a + b - 2ab` and AND as `ab`. The model counts:
- Keccak-f[1600] theta: 3,200 XOR operations per round;
- chi: 1,600 AND and 1,600 XOR operations per round;
- 24 rounds, yielding `24 × (3,200 + 1,600 + 1,600) = 153,600` multiplication-equivalents per permutation.

Absorbing later message bytes into a nonzero sponge state has extra XOR-equivalents. The script reports `8 × max(0, m - 136)` per hash as a conservative upper bound, treating all bytes after the first rate block as dynamic even when some encoding bytes are fixed constants.

These are operation equivalents for this specific naive bit-sliced mapping. They are **not** a lower bound for every possible circuit, exact SmallWood/PACS constraints, actual prover time, proof bytes, or a security estimate. Lookup gates, packed representations, custom arithmetization, optimizations and different field representations can change cost, but each proposed optimization must preserve the frozen byte-level semantics and have its own soundness argument.

## 3. Reproducible scenario

Run:

```bash
python scripts/estimate_keccak_zk_cost.py \
  --outputs 1 \
  --params-id-bytes 19 \
  --policy-id-bytes 20 \
  --input-public-key-bytes 1024 \
  --output-public-key-bytes 1024
```

The scenario is explicitly illustrative. **The public-key codec and its size are not frozen**, so 1,024 bytes is a parameter, not a claim about the eventual Ringtail encoding.

| Computation | Preimage bytes | SHAKE256 permutations |
|---|---:|---:|
| Input CommitV2 | 1,246 | 10 |
| Merkle leaf hash | 137 | 2 |
| Merkle node hash | 181 each × 63 levels | 126 |
| NullifierV2 | 149 | 2 |
| TxDigestV2 for one output | 353 | 3 |
| One output CommitV2 | 1,246 | 10 |
| **Total** | — | **153** |

For this scenario, the model reports **23,500,800 Keccak-f multiplication-equivalents**, plus an **upper bound of 42,288 absorb-XOR equivalents**, for a combined modeled count of **23,543,088**. The model deliberately excludes bit/range decomposition, the output-identity construction, Ringtail verification, value-conservation gadgets, public-input conversion, and the proof system's own commitment/opening/transcript costs. So the total is incomplete by design, not a disguised full circuit estimate.

## 4. What this evidence establishes

- The byte lengths and SHAKE rate-boundary arithmetic in the estimator match the frozen reference encodings covered by tests.
- The chosen direct bit-sliced mapping has a large static cost even for one input and one output; depth-63 SHAKE Merkle membership dominates the hash count in the illustrative case.
- This gives the next feasibility experiment a falsifiable baseline and explicit parameters instead of invented proof-size or runtime numbers.

## 5. What this evidence does not establish

- It does not prove that SmallWood or any other backend can run the full relation within target hardware limits.
- It does not prove the actual circuit or test any malicious prover.
- It does not implement zero knowledge, knowledge soundness, hash constraints, Ringtail authorization, output identity, value conservation, or minting authorization.
- It does not establish constant-time behavior, side-channel resistance, post-quantum security of the composed protocol, or external review.

The C and Python SmallWood upstream projects both mark their implementations as unaudited prototypes not intended for production. A paper describing a zero-knowledge argument is not a production proof backend, and a generic constraint API is not an instantiated 0PSP relation.

## 6. Next gate

**Actual backend feasibility remains NO-GO.** Pin an exact backend revision and parameter set, implement the real frozen predicates beginning with SHAKE and a depth-63 membership relation, run positive and adversarial witnesses, and record actual constraints, proof size, prover/verifier time, peak memory and leakage checks on the target device. If the full relation is infeasible, propose a versioned protocol change with a separate security argument. Do not silently replace the V2 hashes or mark production GO from static arithmetic.

External audit remains **NOT PERFORMED**. Complete 0PSP production remains **NO-GO**.
