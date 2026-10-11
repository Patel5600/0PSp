# Inter-Layer Binding Protocol — Interface Under Falsification

**Status:** Candidate interface. It is not an implemented or proven construction, and the candidate commitment has not been shown to be both hiding and binding.

## 1. Purpose

Two individually valid proofs can use different witnesses. The intended interface makes Layer 1 and Layer 2 bind to one per-spend public value \(B\).

Let

\[
x=\operatorname{Encode}(\mathsf{version},coin\_id,r_{\mathrm{nf}})
\]

and publish

\[
B=\operatorname{Com}_{\mathrm{bridge}}(x;\tau_B).
\]

Layer 1 must prove the selected coin commitment and authorization are linked to an opening of this \(B\). Layer 2 must prove that the same \(B\) opens to \(x\) and that the public nullifier is SHAKE256-384 of the canonical nullifier input. The exact same byte encoding, domain/version constants and commitment parameters must be used in both layers.

## 2. Conditional composition rule

If both proof systems have suitable knowledge-soundness/extractability, both extracted witnesses open the identical \(B\), and the commitment is binding for the stated domains, the extracted nullifier inputs agree except with the commitment's binding failure probability. Deterministic nullifier generation then ties the published nullifier to that input.

This rule does not provide a commitment construction or prove the assumptions. In particular, the current linear expression \(A_1m_x+A_2\tau_B\bmod q\) lacks a demonstrated hiding reduction.

## 3. Layer-specific obligations

### Layer 1

The extension to LoTRS must prove selection of the same column/coin, an opening of the coin commitment, the bridge-opening relation, and a valid threshold wallet authorization. LoTRS's structured threshold grid is not automatically a generic \(t\)-of-\(n\) wallet. The two LoTRS moduli \(q\) and \(\hat q\) must remain distinct.

### Layer 2

The chosen AIR must prove canonical input encoding, bridge opening, SHAKE-256-384, and all range/carry constraints. Since a 43-bit modulus is embedded into a smaller field such as BabyBear, the relation needs a complete limb/carry integer-equality argument. A congruence over BabyBear alone does not prove equality modulo LoTRS's \(q\).

The actual backend must provide zero knowledge for the complete protocol, not merely expose a hiding PCS component. Plonky3 documents that its BinaryPcs example is not zero knowledge.

## 4. Required security model

The theorem needs explicit assumptions for coin commitment binding/hiding, bridge commitment binding/hiding, Layer 1 knowledge soundness and anonymity, Layer 2 knowledge soundness and zero knowledge, threshold authorization security, QROM/nullifier unlinkability, minting uniqueness and ledger duplicate rejection.

Do not infer a statistical min-entropy lower bound from computational hiding. A QROM reduction must define the challenge input, the adversary's classical and quantum queries, the entropy premise conditioned on its view, and a correct advantage bound.

## 5. Go/no-go conditions

Proceed to implementation only when a concrete commitment and parameterization are specified; both layers prove exactly the same canonical opening; custody threshold semantics are implemented; the full STARK AIR and ZK mode compile; and the composed security argument and parameter analysis match the concrete backend.

If no commitment is efficiently provable in both layers with acceptable hiding, binding and proof cost, redesign or abandon the two-layer composition instead of treating the interface as a solved cryptographic primitive.


## CHP3 status change: retired from active architecture

This bridge protocol is retained as historical research. It is not the active V0 path because its candidate commitment did not have an established hiding/binding theorem and the paired proof systems were not instantiated. The active target uses one proof relation to bind coin selection, commitment opening, threshold-signature validity and nullifier correctness. See [Constructionable V0](constructionable-v0.md). The historical bridge is not considered secure or implemented.
