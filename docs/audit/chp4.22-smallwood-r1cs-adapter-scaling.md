# CHp4.22 — SmallWood Python R1CS adapter scaling audit

**Gate:** **NO-GO for the pinned Python R1CS-to-PACS adapter on a SHAKE-sized relation.**  
**Scope limit:** this does not reject the SmallWood construction/theorem or the upstream C API; it rejects using this particular dense adapter unchanged.  
**Protocol impact:** no V2 encoding changes; no production cryptographic gate is closed.  
**External cryptographic audit:** **NOT PERFORMED**.

## 1. Pinned evidence

The reviewed upstream revision is `CryptoExperts/smallwood-python@28c269c8a19838030d0cfc48ebb8a61a110302c3`, a prototype whose own README says it is unaudited and not intended for production:

- [Pinned PACSFromR1CS implementation](https://github.com/CryptoExperts/smallwood-python/blob/28c269c8a19838030d0cfc48ebb8a61a110302c3/smallwood/pacs/constraints/pacs_r1cs.py)
- [Pinned upstream README and prototype warning](https://github.com/CryptoExperts/smallwood-python/blob/28c269c8a19838030d0cfc48ebb8a61a110302c3/README.md)

In `PACSFromR1CS.get_theta_`, the implementation loops over every R1CS equation and its A, B and C linear terms. For each term it allocates a dense matrix with `ceil(number_of_variables / batch_columns) + 2` rows and `batch_columns` entries per row, then retains those matrices in `theta_`. It adds a two-row matrix for each primary input.

This gives the retained dense-list-slot count:

```text
witness_rows = ceil(variables / batch_columns)
equation_slots = 3 * constraints * (witness_rows + 2) * batch_columns
primary_input_slots = 2 * primary_inputs * batch_columns
total_slots = equation_slots + primary_input_slots
```

This is a direct accounting of the allocation shape visible in the pinned source, not a benchmark run.

## 2. Reproducible scaling calculation

The local estimator mirrors that formula and tests the arithmetic:

```bash
python scripts/estimate_smallwood_r1cs_adapter.py \
  --constraints 307200 \
  --variables 310000 \
  --batch-columns 256
```

For the two-permutation scale of a 149-byte NullifierV2 SHAKE input, the representative parameters produce:

| Quantity | Result |
|---|---:|
| R1CS equations | 307,200 |
| Variables | 310,000 |
| Batch columns | 256 |
| Witness rows | 1,211 |
| Dense retained list slots | 286,182,604,800 |
| Pointer-only storage floor at 8 bytes/reference | 2,289,460,838,400 bytes |
| Pointer-only storage floor | about 2.082 TiB |

Even a single 153,600-operation Keccak-f permutation with 155,200 representative variables yields 71,840,563,200 list slots, or 574,724,505,600 bytes (about 535.254 GiB) at the pointer-only floor.

The 8-byte/reference calculation is intentionally favorable to the implementation. It excludes Python list headers, Sage field-element objects, R1CS equations, witness values, the rest of the proof, garbage-collector overhead, and runtime allocations. It is not a measurement of resident memory, but none of those omissions can make the represented list slots fit into a normal laptop's RAM.

The operation counts are from the CHp4.21 bit-sliced arithmetic model. They are not asserted to be the exact constraint count of every optimized Keccak representation. The scaling finding is specifically about the matrix allocation in this adapter for the representative relation sizes.

## 3. Engineering consequence

**Do not connect this adapter to the full 0PSP spend relation.** It has quadratic dense intermediate storage in the relation size:

```text
O(constraints × variables)
```

Tuning the batch-column count only changes padding/constant factors; it does not remove that quadratic materialization.

This does **not** prove SmallWood itself is unusable. Its C API exposes custom constraint callbacks, and a carefully implemented sparse/custom PACS representation could avoid this specific allocation pattern. That path remains unimplemented here, requires exact V2 constraints, real prover/verifier benchmarks, adversarial mutation tests and an independent internal review. SmallWood's upstream implementation remains a prototype, not a production dependency.

## 4. Binary decision and exit condition

- **Pinned SmallWood Python `PACSFromR1CS` adapter:** **NO-GO** for the SHAKE/Keccak relation.
- **SmallWood mathematical construction as a potential backend:** **NO-GO** until a concrete implementation proves the exact 0PSP relation and meets measured resource/privacy/security limits.
- **Overall 0PSP production:** **NO-GO**.
- **External audit:** **NOT PERFORMED**.

Exit condition: replace the dense adapter with a reviewed sparse/custom constraint implementation or select another backend, then demonstrate an actual proof of the exact shared-witness relation. Include CommitV2 opening, depth-63 membership, same-witness NullifierV2, TxDigestV2 binding, output identities/openings, checked value conservation, and the approved authorization predicate. Measure peak RSS, proof size, prover/verifier latency, and malformed-proof rejection on a pinned configuration. No estimate or literature theorem alone changes the production gate.
