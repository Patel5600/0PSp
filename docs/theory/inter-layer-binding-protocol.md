# 0PSP Phase 1 — Inter-Layer Binding Protocol

**Version:** Draft 0.1  
**Status:** Candidate interface for mathematical falsification; not an implemented or proven construction.  
**Decision:** Investigate a per-spend bridge commitment shared by an extended lattice selection proof and a zero-knowledge STARK. Keep Route 1 conditional on feasibility of the extended lattice relation.

## 1. Purpose and central issue

The hybrid must establish that the following facts concern one and the same hidden coin:

1. the coin is a member of the public anonymity set;
2. the coin commitment opens to the wallet authorization key and coin-specific data;
3. a valid wallet threshold has authorized this exact transaction;
4. the public nullifier is the prescribed hash of the data fixed at mint time; and
5. neither proof reveals which coin was selected.

Two independently valid proofs do **not** establish that they use the same witness. The proposed interface binds them through a common, per-transaction commitment `B` to the hidden nullifier input. The commitment must be binding, hiding, post-quantum defensible, and efficiently provable in both proof systems.

This document specifies the required interface. It does not claim that the current LoTRS implementation already supports the additional relation.

## 2. Notation and encodings

Let the public anonymity set be `R_C = {C_1, ..., C_N}`. The selected index `j` and commitment `C_j` are hidden by the spend proof; all candidate commitments are public as members of `R_C`.

For one coin, define the canonical hidden nullifier input:

`x = EncodeNF(version, coin_id, r_nf)`

where `coin_id` has a fixed, specified length/encoding and `r_nf` is a uniformly generated 256-bit value fixed at mint time. Use an unambiguous, canonical, length-delimited encoding. `r_nf` must be bound into the coin commitment, must not be exposed in the public transcript, and must not be re-sampled at spend time.

The nullifier is:

`nu = SHAKE256(domain_null || x, 48 bytes)`

The domain label, version, field order, endianness, length prefixes, and output length must be fixed by the protocol specification. Use distinct domain separators for the nullifier, transaction digest, bridge commitment, and proof transcripts.

### 2.1 Coin commitment

At mint time, the ledger accepts a coin commitment of the form:

`C = Com_coin(pk, value, coin_id, r_nf; rho_coin)`

The actual `Com_coin` construction must be specified. Its binding and hiding properties, message encoding, and relation to the wallet public key must be proved. Minting must guarantee that `coin_id` identifies one asset and that `r_nf` is fixed for that asset. Asset-conservation and duplicate-mint protection are outside this bridge interface but are prerequisites for the full spend theorem.

### 2.2 Bridge commitment

For every spend attempt, sample fresh independent commitment randomness `tau_B` and compute:

`B = Com_bridge(x; tau_B)`

`B` is a public, per-transaction bridge value shared by the two proofs. **Fresh `tau_B` must be used for each transaction; do not reuse `B` across spends.** This avoids creating an unnecessary stable coin identifier. A repeat spend remains linkable through the duplicate nullifier `nu`, as required for double-spend detection.

`Com_bridge` is an interface, not yet a selected primitive. It must satisfy:

- computational binding against the stated quantum adversary;
- hiding for `x` under fresh `tau_B`;
- canonical encoding and explicit parameters;
- a proof relation that the lattice layer can express without revealing `x`;
- a proof relation that the STARK can check efficiently; and
- sound cross-layer semantics: two accepted proofs for the same public `B` cannot use different `x` values except with the commitment's binding-failure probability.

A possible direction to investigate is a lattice commitment linear over the same ring/module used by the extended lattice proof, with `x` encoded as fixed-size, range-constrained chunks. This is **not** a selected or validated construction. The bit/range encoding and the bridge commitment's hiding/binding reductions remain open.

## 3. Public transaction statement

Use one canonical public statement shared by both proof verifiers:

`S = (protocol_id, version, chain_id, state_root, R_C_or_root, B, nu, tx_context, M)`

`tx_context` contains the canonical transaction data, including outputs and fees. Define:

`M = H_tx(domain_tx || Encode(protocol_id, version, chain_id, state_root, tx_context, nu, B))`

The chain verifies that `M` is correctly recomputed from the actual transaction. The threshold authorization signs this exact context (or the protocol's authenticated equivalent), which includes `nu` and `B` and excludes any exposed selected commitment `C_j`.

If the implementation uses a public set root instead of transmitting all of `R_C`, the root construction, canonical ordering, and membership/table-digest binding must be defined. All Fiat–Shamir transcripts must bind the full canonical statement `S`, the protocol/version identifier, and the relevant proof-system parameters. Never let a prover substitute a different ring, `B`, `nu`, chain, or transaction while reusing a proof transcript.

## 4. Layer 1: extended lattice selection and authorization proof

Define `Pi_L` as an **extended, to-be-designed lattice selection proof**. It is not assumed to be available from unmodified LoTRS.

The desired relation is:

`R_L(S; w_L) = 1`

for witness

`w_L = (j, pk_j, value, coin_id, r_nf, rho_coin, tau_B, authorization_witness)`

and must jointly establish:

1. `j` selects a valid member `C_j` of `R_C`;
2. `C_j = Com_coin(pk_j, value, coin_id, r_nf; rho_coin)`;
3. `B = Com_bridge(EncodeNF(version, coin_id, r_nf); tau_B)`;
4. the wallet associated with `pk_j` meets its stated custody policy and authorizes `M`; and
5. any required ledger eligibility predicates are satisfied.

The same hidden `j`, `pk_j`, `coin_id`, and `r_nf` must be used in all applicable predicates. It is insufficient to prove selection and authorization in separate statements without a sound link between them.

### 4.1 Threshold semantics are a separate obligation

The wallet custody policy `(t,n)` is not the anonymity-set size `N`. Specify the exact `t`-of-`n` authorization relation and corruptions allowed. LoTRS's published structured threshold pattern uses a hidden column with one signer per row; this is not automatically a generic `t`-of-`n` wallet protocol. The proposed `Pi_L` must therefore either:

- extend the LoTRS selection protocol with a proved relation that also binds the selected coin commitment and the intended wallet threshold policy; or
- use a different threshold-anonymous authorization construction with an explicit security theorem.

A conventional threshold signature exposed alongside a list of candidate public keys may be linkable by checking it against each key. If a conventional signature is used, its verification under the hidden selected key must itself be hidden in a sound zero-knowledge relation. Do not count a public signature as anonymous merely because it is placed next to another proof.

### 4.2 Algebraic feasibility gate

`Pi_L` must show that the coin opening and bridge commitment relation fit the actual lattice proof's supported relation language, norm bounds, response distributions, and soundness analysis. Do not assume the existing one-out-of-many proof can prove arbitrary bit-level operations. This layer should prove only the commitment/equality and authorization relations assigned to it; the SHAKE computation belongs to Layer 2.

## 5. Layer 2: zero-knowledge STARK for nullifier correctness

Define `Pi_H` as a **zero-knowledge-enabled** STARK (not merely any STARK configuration) with public inputs `(B, nu, protocol_id, version)` and witness `(coin_id, r_nf, tau_B)`.

Its computation relation is:

1. `x = EncodeNF(version, coin_id, r_nf)` using the same canonical encoding as Layer 1;
2. `B = Com_bridge(x; tau_B)` using byte-for-byte identical commitment parameters and encoding; and
3. `nu = SHAKE256(domain_null || x, 48 bytes)`.

The STARK must hide the execution trace/witness under its explicitly selected zero-knowledge configuration. Its transcript and verifier statement must also bind to the transaction statement `S` so the proof cannot be transplanted to another chain, ring, nullifier, bridge commitment, or transaction.

The current one-permutation estimate is valid only if the exact encoded hash input plus SHAKE padding fits in the 136-byte SHAKE256 rate block and the requested 48-byte output is squeezed from that block. Verify this from the actual encoding. The `38,400` figure is the count of generic `chi`-step AND operations in a bit-level representation of one Keccak-f[1600] permutation (`1,600 × 24`); it is **not** a universal count of all STARK constraints. The bridge-commitment check, bit/range checks, trace layout, lookup arguments, commitment scheme, FRI parameters, and zero-knowledge masking add costs.

## 6. Proving and verification protocol

### Spend generation

1. The wallet/prover selects an eligible coin `C_j` and obtains threshold authorization for the fully specified transaction context `M`, including `nu` and `B`. The authorization protocol must bind approval to the actual transaction outputs, fees, chain/state context, nullifier, and bridge commitment.
2. Using the coin's fixed `(coin_id, r_nf)`, compute `nu = SHAKE256(domain_null || EncodeNF(version, coin_id, r_nf), 48 bytes)`.
3. Sample fresh `tau_B`; compute `B = Com_bridge(EncodeNF(version, coin_id, r_nf); tau_B)`.
4. Construct `M` from canonical transaction data including `nu` and `B`.
5. Generate `Pi_L` for `R_L(S; w_L)`, proving the hidden coin opening, selected key/coin binding, bridge-commitment opening, and threshold authorization.
6. Generate `Pi_H` for the STARK relation, proving the same bridge commitment opens to the same nullifier input and that the published `nu` is correct.
7. Serialize the transaction and both proofs with protocol/version identifiers. Publicly reveal `B`, `nu`, `M`, and the public anonymity set or its specified root, but never reveal `j`, `C_j` as a selected index/value, `coin_id`, `r_nf`, or either commitment opening.

### Verification

The ledger:

1. validates canonical transaction encoding and recomputes `M`;
2. validates the anonymity-set/table commitment and eligibility state;
3. verifies `Pi_L` against exactly `S`;
4. verifies `Pi_H` against the same `B`, `nu`, and protocol/version;
5. verifies any separate public transaction conservation rules; and
6. rejects if `nu` already appears in the spent-nullifier set. It then atomically records `nu` as spent and applies the state transition.

Both proofs must use identical serialized `B`, `nu`, protocol/version, and transaction context. A change in any public input invalidates the relevant proof transcript.

## 7. Security obligations and conditional arguments

The following are proof obligations, not established theorems.

### 7.1 Cross-layer witness binding

Assume `Pi_L` and `Pi_H` satisfy the required soundness/extractability notions and `Com_bridge` is binding. From an accepted `Pi_L`, extract `x_L` such that `B = Com_bridge(x_L; tau_L)` and the selected coin commitment opens to the corresponding coin data. From an accepted `Pi_H`, extract `x_H` such that `B = Com_bridge(x_H; tau_H)` and `nu = SHAKE256(domain_null || x_H, 48 bytes)`. Binding implies `x_L = x_H`, except with the bridge-commitment binding advantage. Therefore the nullifier relation is bound to the same hidden coin used by the lattice selection/authorization relation.

This argument only applies if the extracted relations actually exist and the commitment scheme's binding theorem covers the encodings and adversarial model. Merely using the same variable names in two documents proves nothing.

### 7.2 Double-spend resistance

For a fixed valid coin, minting binds its `coin_id` and `r_nf` into its commitment. If the commitment has a unique message opening, a sound extracted spend witness for that same coin yields the same `coin_id` and `r_nf`. The deterministic nullifier function therefore yields the same `nu`. Since the ledger rejects a previously spent `nu`, two accepted spends of the same coin with different nullifiers imply a failure of a stated premise: proof soundness/extractability, coin-commitment binding, canonical encoding, asset uniqueness/conservation, or correct hash evaluation.

Collision resistance serves a different purpose: preventing distinct coins from causing accidental nullifier collisions and false rejections. It is not itself the mechanism that rejects a second spend.

### 7.3 Unlinkability

A target theorem must account for all of the following: zero knowledge of `Pi_L`, zero knowledge of `Pi_H`, hiding of `Com_bridge`, anonymity of the extended selection/authorization proof, the nullifier hash assumption, and public leakage from amounts, transaction timing, state, ring composition, and signer policy. Use fresh `tau_B` per spend so `B` is not a stable tag. Repeated attempts to spend the same coin intentionally reveal the same `nu`.

If the proof is in the QROM, do not set the O2H `find` probability to `2^-256` independently of the adversary's quantum query budget. Define the challenge-input min-entropy conditioned on the adversary's view and bound its actual `find` probability. For a uniformly hidden 256-bit secret with no side-channel leakage, generic quantum search suggests a scale of `O(q_H^2 / 2^256)` for finding the secret input with `q_H` queries; combined with an O2H-style `O(q_H sqrt(p_find))` term, this gives a rough `O(q_H^2 / 2^128)` scale. This is only a planning bound: the exact theorem, query model, challenge distribution, and all other hybrids must be stated. If the secret has less conditional entropy, the bound worsens.

Treat SHAKE256 as an instantiation heuristic for the QROM analysis, not as a function proven identical to a random oracle. The final theorem must separately state idealized-model assumptions and the concrete instantiation caveat.

### 7.4 Proof composition

State and prove a composition theorem for the joint proof `(Pi_L, Pi_H)` under the shared public statement. It must account for the bridge-commitment binding error, each proof's soundness error, the threshold authorization error, the hiding of `B`, and zero knowledge of both proof systems. Use explicit error terms rather than claiming that two individually secure components are automatically secure when connected.

## 8. Performance accounting

The combined proof size is:

`size_total = size(Pi_L_extended) + size(Pi_H_ZK) + size(B) + size(nu) + serialization/transaction overhead`

The published LoTRS artifact's 53.53 KiB signature is a reference measurement for its specified configuration, not the size of `Pi_L_extended` and not a 128-bit-security baseline. Its v2 reference estimator explicitly says its displayed attack-cost outputs do not substantiate 128-bit post-quantum security. Parameters must be recalibrated before making a 128-bit system claim. See the official artifact record: https://zenodo.org/records/22807126.

The earlier `35–48 KiB` estimate for the hash STARK and `90–100 KiB` total are **unverified hypotheses**. They exclude, unless separately measured, the bridge-commitment opening, canonical bit/range constraints, the added Layer 1 relations, zero-knowledge masking, transcript/public-input overhead, and any larger parameters required by the target security level. Plonky3 exposes Keccak-f proof examples and documents a configuration-dependent security cap for its binary trace commitment; its default/example parameters must not be assumed to provide 128-bit post-quantum security. Measure the exact circuit, prover/verifier time, peak memory, serialized proof size, and quantified classical/quantum soundness before updating the estimate.

## 9. Phase 1 go/no-go tests

### GO to a minimal prototype only if

- a concrete `Com_bridge` with stated post-quantum hiding/binding assumptions is selected;
- the extended lattice proof can express both `C_j` and `B` opening relations with sound norm/distribution bounds;
- the actual threshold custody relation is compatible with the anonymity layer;
- a zero-knowledge STARK proves both the bridge opening and SHAKE relation under an explicit security configuration;
- both proof statements share the exact same canonical `B` and transaction context; and
- a composition proof or a clearly bounded proof plan states soundness, unlinkability, and double-spend conditions.

### NO-GO / redesign if

- no bridge commitment can be efficiently and securely opened in both layers;
- adding bit/range/equality constraints invalidates the lattice proof's soundness or makes it impractical;
- the selected wallet threshold structure cannot be hidden by the proposed LoTRS extension;
- the STARK's actual security parameters cannot meet the system's quantum-security target; or
- measured combined proof size/runtime exceeds the project's predeclared practicality limits.

## 10. Required experiment before revising cost claims

Build a standalone benchmark for **one exact** `EncodeNF` and `Com_bridge` design. Use a zero-knowledge configuration and publish a manifest containing:

- exact input bytes and SHAKE padding/block count;
- bridge commitment algorithm, ring/field, parameters, and range encodings;
- STARK implementation commit, AIR/trace width, trace length, query settings, grinding, masking mode, and soundness analysis;
- serialized proof bytes, proving time, verification time, and peak memory;
- repeated runs and hardware/toolchain details; and
- separate results for hash-only and hash-plus-bridge-opening proofs.

Do not infer proof size from the AND-gate count. The 38,400 figure is an operation count for one permutation's `chi` layer, not a STARK proof-size formula.

## 11. External calibration sources

- LoTRS Zenodo v2 artifact and estimator output: https://zenodo.org/records/22807126
- LoTRS repository: https://github.com/lotrs-sig/lotrs
- Plonky3 repository and Keccak/STARK configuration notes: https://github.com/Plonky3/Plonky3
- NIST FIPS 202 (SHA-3 and SHAKE): https://csrc.nist.gov/pubs/fips/202/final
- O2H/QROM discussion: https://eprint.iacr.org/2017/1005.pdf

## Current conclusion

The bridge-commitment interface is the cleanest way to state what the two layers must agree on, but it is not yet a demonstrated construction. The next research gate is to instantiate and analyze `Com_bridge`, then write the extended lattice relation and the STARK relation using one canonical encoding. Until those relations are shown to be efficiently expressible and jointly sound, Route 1 and the 90–100 KiB estimate remain conditional hypotheses.
