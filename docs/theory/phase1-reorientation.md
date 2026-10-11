# Phase 1 Reorientation: Falsification Before Construction

**Date:** 2026-10-11  
**Trigger:** Critical review of initial SCRL formulation  
**Decision:** Phase 1 is now a **falsification phase**. No implementation work until the mathematical core survives a structured attack.

---

## What Changed and Why

The initial Phase 1 approach committed two errors:

**Error 1 — Premature construction.**  
We wrote a rerandomizer before establishing that rerandomizable Shamir shares are compatible with the required lattice-signature properties. An NTT that passes its own tests is not evidence that the mathematical structure works.

**Error 2 — Conflated lemma.**  
The SCRL statement bundled four independent hard problems into a single claim. When one fails, you cannot identify which assumption broke.

---

## The Correct Order

```
STEP 1  Representation and correctness
        Define the ring, secret distribution, share format, 
        reconstruction algorithm, and signature protocol.
        Verify that valid shares produce valid signatures BEFORE 
        adding rerandomization.

STEP 2  Rerandomization feasibility
        Define the pk transformation φ and the share transformation ψ.
        Prove their algebraic relationship holds exactly, or 
        exhibit a counterexample under the stated constraints.

STEP 3  Related-key security
        Model an adversary with multiple derived public keys 
        and up to t-1 corrupted participants. State what is 
        public and what can be corrupted.

STEP 4  Privacy composition
        Show how the derived key enters the membership proof,  
        how the nullifier is bound, and why neither reveals 
        the owner or links distinct legitimate spends.
```

Each step must be completed before the next begins. Steps 2-4 are blocked on Step 1.

---

## Immediate Deliverables for Phase 1

1. `system-model.md` — participants, keys, adversary model, spend lifecycle
2. `scrl-falsification.md` — SCRL split into testable sub-claims with attack strategies
3. `design-ab-comparison.md` — rerandomized vs. non-rerandomized constructions
4. `attack-catalogue.md` — structured attack inventory with go/no-go criteria
5. Updated `related-work/survey.md` — correct LoTRS description

---

## What Constitutes a Go/No-Go Decision

**Go:** A proof that rerandomized shares of a lattice secret remain in a distribution compatible with threshold signing, under a stated assumption no stronger than Module-LWE + Module-SIS.

**No-Go:** A proof (or convincing argument) that:
- Consistent rerandomization requires correlated noise that leaks secret polynomial structure, OR
- The norm of rerandomized shares necessarily exceeds any practical signing bound, OR  
- An adversary with poly(λ) rerandomization transcripts can distinguish the key from a fresh key.

**Fallback if No-Go:** Design B (non-rerandomized keys, anonymous proof of authorization, correctly bound nullifier). Evaluate whether Design B achieves the same five properties under a simpler construction.
