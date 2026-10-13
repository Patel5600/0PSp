# CHp4.23 — Binary-field Keccak arithmetization and Aurora candidate screen

**Gate:** deterministic circuit-shape model **GO**; real backend feasibility **NO-GO pending experiment**; complete 0PSP production **NO-GO**.  
**Protocol compatibility:** frozen V2 encodings unchanged.  
**External cryptographic audit:** **NOT PERFORMED**.

## 1. Why the CHp4.21 estimate is not the only encoding

CHp4.21 deliberately modeled SHAKE256-384 in an odd-characteristic field. That direct encoding charges nonlinear operations for XOR and is a useful baseline, but it is not necessarily the least expensive field representation for a bitwise algorithm.

Keccak operates on bits. Over a characteristic-two extension field GF(2^m), addition implements XOR for values in the GF(2) subfield. The round's theta, rho, pi and iota transforms are linear over this subfield. Each chi output can be expressed using one rank-1 row:

```text
out = a XOR ((NOT b) AND c)
(1 + b) * c = out + a
```

All additions in that relation are in characteristic two. For a,b,c in {0,1}, it is exactly the chi truth table. One multiplication relation per output bit suffices, and that same row binds the output bit. If every externally supplied source bit is constrained by b*(b+1)=0, then intermediate values stay in the GF(2) subfield: addition and multiplication of zero/one values remain zero/one. This invariant must be explicit in a real R1CS builder. Merely selecting GF(2^m) does not magically make arbitrary field elements bits.

There are 1,600 chi output bits per round and 24 Keccak-f[1600] rounds, yielding 38,400 chi rows per permutation. Under CHp4.21's illustrative one-input/one-output scenario of 153 permutations, the core chi relation is therefore 5,875,200 rank-1 rows, rather than 23,500,800 odd-characteristic multiplication-equivalents. The equality is a source-derived circuit-shape count, not measured circuit size.

The script counts one additional booleanity row for every bit of every encoded SHAKE preimage as an intentionally conservative bound. This includes redundant bit checks for constants or digest bytes already constrained by an earlier hash, so a real circuit should reuse proven bitness rather than retain duplicates. In this scenario, the upper bound for the modeled SHAKE subrelation is 5,991,472 rows. This excludes public-key serialization constraints, public-input binding not already included, value/range arithmetic, output identity, Ringtail authorization, state policy, ledger logic, and proof-backend overhead.

## 2. Reproducibility

```bash
python scripts/estimate_binary_field_keccak.py \
  --outputs 1 \
  --params-id-bytes 19 \
  --policy-id-bytes 20 \
  --input-public-key-bytes 1024 \
  --output-public-key-bytes 1024
```

Expected key numbers:

| Metric | Illustrative result |
|---|---:|
| SHAKE invocations | 68 |
| Keccak-f permutations | 153 |
| Chi rows per permutation | 38,400 |
| Keccak chi rows | 5,875,200 |
| Conservative preimage bitness rows | 116,272 |
| Modeled SHAKE-subrelation upper bound | 5,991,472 |

The tests exhaustively check the chi relation's truth table and test the exact scenario arithmetic. They do **not** instantiate GF(2^m), generate an R1CS, create a proof, or establish soundness/privacy of an integrated backend.

## 3. Candidate screen

### Aurora / libiop: next feasibility candidate only

The upstream [libiop project](https://github.com/scipr-lab/libiop/tree/a2ed2ec2f3e85f29b6035951553b02cb737c817a) documents Aurora, R1CS support over binary extension fields, and the BCS transformation's QROM security rationale. The [Aurora paper](https://eprint.iacr.org/2018/828) describes a transparent zero-knowledge R1CS argument with O(N log N) prover arithmetic and a polylogarithmic argument. That makes it worth testing for the characteristic-two circuit shape above.

However, the pinned upstream code's latest commit is dated 2021-05-13 and its own README explicitly labels the code an academic proof-of-concept that has not received careful code review and is not production-ready. Existing tests also show use of BLAKE2b and heuristic soundness settings; those defaults cannot be accepted by assumption. A 128-bit post-quantum profile requires a documented field, hash, QROM soundness calculation, and zero-knowledge setting. The proof's own transcript hash must be pinned and sized adequately; the protocol's SHAKE encodings alone do not secure the proof system.

**Decision:** Aurora/libiop is selected for a controlled feasibility spike, not as the production backend. Pin source and dependencies, verify the supported binary field and exact ZK mode, create a one-SHAKE proof with adversarial mutations, and measure real peak memory, proof bytes and prover/verifier time before scaling to the full relation. Re-review the actual masking/degree-bound logic against the known STARK zero-knowledge pitfalls, including [IACR ePrint 2024/1037](https://eprint.iacr.org/2024/1037).

### Rejected or deferred alternatives

- **RISC Zero zkVM:** **NO-GO for a privacy-critical release on current evidence.** Its [own advisory GHSA-5xgj-pmjj-gw49](https://github.com/risc0/risc0/security/advisories/GHSA-5xgj-pmjj-gw49) currently lists all versions as affected and no patched versions for the provable zero-knowledge property. The advisory says no practical attack was known at publication; this is not a claim of an exploit, but a formal privacy guarantee gap that cannot be waived for 0PSP.
- **Miden VM:** **NO-GO for production dependency.** Its [official README](https://github.com/0xMiden/miden-vm) labels the implementation alpha, unaudited and not ready for production.
- **SmallWood Python R1CS adapter:** **NO-GO as-is** by CHp4.22 because the generic dense constraint-table expansion becomes infeasible for the relation. This does not reject the SmallWood proof construction or a separate custom C/PACS implementation.
- **SmallWood C/PACS:** research candidate only. The published SmallWood paper proves its argument properties in the random-oracle model, but the exact implementation, full SHAKE relation, QROM concrete security, target-resource profile, and full-system integration still require separate evidence. Its proof-size benchmarks target comparatively small instances, not a demonstrated 5.9-million-row 0PSP relation.

## 4. Required next gate

1. Pin Aurora/libiop and all transitive sources by immutable commit/version.
2. Prove a tiny byte-oriented SHAKE256-384 preimage relation in the selected characteristic-two field. Public digest and program/image identity must be bound as verifier inputs, not trusted host assertions.
3. Test correct witness acceptance plus invalid preimage, altered digest, non-Boolean input field values, mutated padding/domain bytes, malformed serialization, and altered public inputs.
4. Review Aurora's actual masking and degree-bound argument against updated STARK ZK analyses. Verify the implementation actually enables its ZK mode.
5. Calculate concrete security for a defined quantum-adversary model, extension field, transcript hash, FRI/RS parameters, and query count. No default BLAKE2b or heuristic setting passes without explicit analysis.
6. Benchmark a complete NullifierV2 hash, then a depth-63 membership relation, then the full shared-witness spend. Record peak RSS, latency, proof size and verifier cost on the target device. A smaller synthetic constraint test is not evidence for full-scale feasibility.

Until these conditions are met, the binary-field estimate is a scoped **GO for arithmetic reasoning only**; proof-system selection, authorization, custody, end-to-end private spend and complete production remain **NO-GO**. External audit remains **NOT PERFORMED**.
