# 0PSP Upstream Source Manifest

**Checked:** 2026-10-11 (UTC).  
**Purpose:** reproducibility and research provenance, not an endorsement of upstream security or a 0PSP security proof.

The Git commit IDs below identify the repository heads inspected during this review. The paper/artifact version is listed separately where relevant. Re-check these references before depending on APIs or making publication claims; an upstream branch is mutable, while a commit hash is immutable.

| Component / claim | Source snapshot checked | What it supports | What it does not support |
|---|---|---|---|
| LoTRS implementation | [commit \`f3c917a3b18b64f12779b8f61db06a19e74ba64b\`](https://github.com/lotrs-sig/lotrs/commit/f3c917a3b18b64f12779b8f61db06a19e74ba64b); [ePrint 2026/974](https://eprint.iacr.org/2026/974) | Parameters and implementation of a structured threshold ring-signature design | A drop-in 0PSP spend proof or a proven 128-bit PQ baseline |
| LoTRS v2 reference artifact | [Zenodo v2, DOI 10.5281/zenodo.22807126](https://zenodo.org/records/22807126) | Artifact states \(n=256\), \(q=2^{43}-67\), \(\hat q=2^{35}-451\), analytic size about 52.6574 KiB and measured Rice-encoded signature 53.53 KiB. It explicitly says its displayed attack costs do not substantiate 128-bit post-quantum security. | A security-matched benchmark for 0PSP or proof that the listed estimator costs are unconditional hardness lower bounds |
| Ringtail threshold signatures | [repository commit \`1e181c356492e9360765cf27d58497018172ba3c\`](https://github.com/daryakaviani/ringtail/commit/1e181c356492e9360765cf27d58497018172ba3c); [ePrint 2024/1113](https://eprint.iacr.org/2024/1113) | Research construction/prototype for LWE-based threshold signatures | A full anonymous private-spend protocol; a pinned 0PSP adapter does not yet exist |
| Generic post-quantum linkable ring signature / signature-of-knowledge scaffold | [repository commit \`83d58abfbc282ce93866d295b14029e3cfb76e55\`](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature/commit/83d58abfbc282ce93866d295b14029e3cfb76e55); [ESORICS 2024 implementation](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature) | Research scaffold for expressing linkable ring signatures as signature-of-knowledge over NP statements | Production readiness: upstream labels it experimental/unaudited and describes its added ZK enhancement informally |
| Obscura-PQ comparator | [repository commit \`dc707c4b3162a8741aa960540dc9b91584d59e44\`](https://github.com/n-azimi/Obscura-PQ/commit/dc707c4b3162a8741aa960540dc9b91584d59e44); [arXiv:2608.22645](https://arxiv.org/abs/2608.22645) | Author-reported lattice linkable-ring privacy protocol, deterministic serial number and Algorand testnet implementation | The exact 0PSP threshold-wallet composition or a proof that 0PSP is novel |
| SHAKE-256 | [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) | Definition of SHAKE128/SHAKE256 extendable-output functions and related hash primitives | Protocol unlinkability, commitment hiding/binding, or a QROM reduction merely from choosing a 384-bit output |
| ML-DSA | [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Standard ML-DSA parameter namespace and signature definition | LoTRS or Ringtail parameter equivalence |

## Source-review conclusions

1. LoTRS is a structured threshold-ring research comparator; its published artifact explicitly warns that the displayed reference estimator outputs do not substantiate 128-bit PQ security.
2. Ringtail supplies a threshold-signature component, not the full coin membership, nullifier, hidden-member and ledger relation required by 0PSP.
3. The generic PQ SoK/LRS implementation is useful research code, but the upstream warning that its ZK enhancement is informal means 0PSP cannot inherit an end-to-end ZK claim from it.
4. Obscura-PQ is direct prior art for post-quantum linkable spending. Novelty must be based on a precise capability comparison, not a feature checklist.
5. FIPS 202 defines SHAKE; selecting a SHAKE output size alone does not establish any protocol-level security theorem.

## Current 0PSP integration status

No cited upstream repository is yet integrated as a dependency of the current implementation. No immutable Ringtail adapter revision, single-relation ZK proof backend, or composed security theorem has been selected. This manifest is a reproducibility aid; it does not clear those implementation/security gates.

## Links

- [LoTRS artifact](https://zenodo.org/records/22807126)
- [Ringtail paper](https://eprint.iacr.org/2024/1113)
- [Generic PQ SoK/LRS repository](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature)
- [Obscura-PQ preprint](https://arxiv.org/abs/2608.22645)
- [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
