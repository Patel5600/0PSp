# 0PSP — Post-Quantum Private Spend Primitive

> **Research codename: 0PSP** (zero-knowledge Post-quantum Spend Primitive)  
> Mathematics first. Blockchain never, unless the math survives.

---

## What this is

A cryptographic research project targeting a novel composition of five properties under a single primitive:

| Property | Description |
|---|---|
| **PQ-Security** | Authorization resists quantum-capable adversaries (Module-LWE / Module-SIS hardness) |
| **Spender Anonymity** | Verifier learns authorization without learning *which* eligible owner authorized |
| **Key Rerandomization** | Public keys transform safely across transactions without exposing the root key |
| **Double-Spend Prevention** | Deterministic nullifier reveals reuse without linking distinct transactions |
| **Threshold Compatibility** | `t`-of-`n` key holders jointly authorize without reconstructing the full secret |

The research hypothesis is that existing post-quantum spend and threshold-signature constructions do not provide the exact combination of properties required by 0PSP under our specified model. This claim remains unverified pending a systematic literature and construction comparison.

---

## Research phases

```
Phase 1  →  Mathematical core attack (Falsification phase)
Phase 2  →  Formal security proofs
Phase 3  →  Reference implementation
Phase 4  →  Independent cryptanalysis
Phase 5  →  Protocol / chain decision
```

**Current phase: 1**

---

## First target: Share-Compatible Rerandomization Lemma (SCRL)

Investigating whether a valid lattice threshold signing secret can be transformed or rerandomized consistently with derived public keys while preserving threshold unforgeability, simulation anonymity, and nullifier correctness.

This is a **research hypothesis under active falsification**, not an established theorem.

---

## Repository layout

```
0psp/
├── docs/
│   ├── theory/          # Primitive definition, SCRL falsification, Design A vs B
│   ├── security/        # Security games, reductions, attack catalogue
│   └── related-work/    # Literature survey, LoTRS / Raccoon / Ringtail analysis
├── src/                 # Phase 3 reference implementation (deferred until math survives)
├── tests/               # Formal test suites (property & unit)
└── scripts/             # Parameter estimators & benchmark harnesses
```

---

## Related work we track

| Scheme | Relevance | What 0PSP must establish against it |
|---|---|---|
| **ML-DSA / Dilithium** (FIPS 204) | Standardized PQ signature baseline | No spend anonymity, no nullifier, no threshold structure |
| **Threshold Raccoon** (ePrint 2024/184) | Practical lattice threshold sigs (additive masks) | Analyze how Raccoon avoids Lagrange norm explosion without Shamir |
| **Ringtail** (ePrint 2024/1113) | 2-round LWE threshold, scales to 1024 parties | Non-interactive DKG; no spend anonymity, no nullifier |
| **LoTRS** (ACM CCS 2026 / ePrint 2026/974) | Post-quantum structured threshold ring signatures | Explicit lattice TRS (multisig + 1-out-of-N proof, 35-36 KB @ 50-of-100); investigate whether spend-specific rerandomization is needed or if LoTRS + nullifier suffices |
| **Monero / CLSAG** | Ring signature + key image nullifier | Classical (discrete log) only |
| **Zcash Sapling / Orchard** | State-of-the-art spend privacy | Non-PQ (Groth16/Halo2); no threshold wallet compatibility |

---

## Non-goals (Phase 1–3)

- No token
- No chain
- No consensus mechanism
- No whitepaper claiming novelty before proof

---

## How to run (Phase 3 — not yet)

```bash
pip install -e ".[dev]"
pytest tests/
python scripts/estimate_params.py --security 128
```

---

## License

Research only. No production use until cryptanalysis clears Phase 4.
