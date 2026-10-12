# CHp4.4 — Review of the proposed deterministic output coin-ID derivation

**Status:** adversarial design review; proposal not approved.  
**Reviewed:** 2026-10-12  
**Release:** **NO-GO**.  
**Change class:** documentation-only review. No V2 primitive, KAT, production API, output semantics, authorization policy or ledger behavior changes.

## Executive verdict

The submitted proposal correctly identifies a real risk: two distinct commitments can use the same hidden `(namespace_id, coin_id, r_nf)` while differing in commitment randomness, producing the same V2 nullifier. It also correctly notes that deposit replay protection does not govern ordinary transfer outputs.

However, the proposed "definitive solution" **must not be merged into the protocol as written**. Its output-ID derivation makes `coin_id` publicly computable, contradicting the current issuer-private requirement; its uniqueness argument is computational, not mathematical; it leaves the hash suite and canonical encodings unspecified; and the sample test suite does not exercise the repository's frozen V2 primitives. Several formulas in the submitted sample are incompatible with the actual V2 byte contract.

This review records the useful threat finding without accepting the suggested construction. It is not an impossibility result against every deterministic derivation. A derivation may be feasible after a deliberate privacy-model change and a complete protocol analysis, but it is not a drop-in privacy-preserving fix.

## 1. The attack observation is valid

Under the frozen V2 components:

```text
C = CommitV2(params_id, pk, v, ns, coin_id, r_nf, rho_C)
nf = NullifierV2(ns, coin_id, r_nf)
```

Two openings that share `(ns, coin_id, r_nf)` and differ only in `rho_C` can produce different commitment candidates but the same nullifier. The ledger's spent-nullifier set can reject a second accepted spend; that alone does not make both notes spendable. If a sender creates these as outputs for other recipients, it is not safe to claim the sender necessarily harms only themself.

A transfer's value-conservation relation and its external-deposit replay set solve different problems. A transfer output does not normally need a new external deposit for every output, so `ConsumedDepositSet` by itself cannot prevent this output-identity griefing case.

## 2. The proposed circuit rule conflicts with the current privacy target

The proposal suggests:

```text
coin_id_out[j] = CRH_coin(
  "0PSp-CoinID-Transfer" || public_nf_in_0 || output_index[j]
)
coin_id_mint = CRH_coin(
  "0PSp-CoinID-Mint" || public_deposit_id || 0
)
```

The cited inputs are public. Any observer can run the same deterministic function and calculate the resulting `coin_id`; the wallet's hidden witness is not needed. The mint-derived ID is public for the same reason. That contradicts the current stated privacy target that the issuer should not learn `coin_id`, and changes the leakage function. It also publicly ties each output identity to a source nullifier and index. Even if secret `r_nf` prevents an observer from immediately calculating a future nullifier, that does not make the public `coin_id` private or preserve the existing privacy model.

This is not a proof that all use of deterministic identities is insecure. It means the proposed scheme cannot simultaneously claim public derivability and that `coin_id` remains hidden. Any adoption requires a deliberate, approved threat-model/leakage change and a new unlinkability analysis.

## 3. The uniqueness claim overstates what a hash proves

A cryptographic hash is not mathematically injective. With unique canonical inputs and a suitable collision-resistant hash, collisions may be computationally negligible under stated assumptions; they are not logically impossible.

To even formulate that computational claim, the proposal must pin:
- the exact `CRH_coin` algorithm and output size;
- unambiguous domain-separated encoding, including fixed lengths/byte order for the nullifier and output index;
- the namespace/parameter/version binding and treatment of cross-chain deployment scopes;
- canonical transaction input ordering and output indexing;
- how every accepted transaction binds the exact derived ID into each output commitment in the same proof relation;
- the precise assumption that the parent input nullifier is unique among accepted transactions, plus hash-collision and reorganization considerations.

The submitted text calls output indices distinct and then jumps to globally unique IDs. Distinct input strings only imply distinct hash outputs under an additional collision-resistance assumption, not by arithmetic necessity. A 256-bit digest is not an injective mapping from arbitrary inputs.

## 4. The submitted equations are not the repository's frozen V2 formulas

The current normative bytes are in [RFC-02](../theory/spend-relation-spec.md) and implemented by the Python/native V2 reference components.

**Actual Commitment V2:**

```text
SHAKE256-384(
  "0PSP-COIN-COMMIT-v2-SHAKE256" || 0x02 ||
  LE16(len(params_id)) || params_id ||
  LE32(len(pk)) || pk || LE64(v) ||
  LE16(48) || ns[48] ||
  LE16(32) || coin_id[32] ||
  LE16(36) || r_nf[36] ||
  LE16(36) || rho_C[36]
)
```

**Actual Nullifier V2:**

```text
SHAKE256-384(
  "0PSP-NULLIFIER-v2-SHAKE256" || 0x02 ||
  LE16(48) || ns[48] ||
  LE16(32) || coin_id[32] ||
  LE16(36) || r_nf[36]
)
```

The supplied example instead uses different domains, omits version and length prefixes, omits the commitment's parameter/namespace binding and changes the nullifier input to `sk_user XOR r_nf`. It is not a test of the repository's V2 contract. Implementing those sample equations would silently change protocol semantics despite the instruction to keep KATs frozen.

The sample helper named `keccak256` calls Python `hashlib.sha256`. SHA-256 is not Keccak-256. Therefore that function cannot be used as a Keccak-256 event identifier implementation or reference vector.

The sample references `docs/security/v2-protocol-security-arguments.md` (plural), whereas the canonical file in this repository is `docs/security/v2-protocol-security-argument.md` (singular). The target path must not be copied blindly.

## 5. Orchard is relevant prior art, not proof of this construction

The Orchard design documentation treats Faerie Resistance, note privacy and spend unlinkability as distinct security properties and derives nullifiers from note fields under a specific circuit and cryptographic design. It does not establish the submitted SHAKE/hash rule `H(public_nf, index)` as a universally valid solution for 0PSp.

References:
- [The Orchard Book: Nullifiers](https://zcash.github.io/orchard/design/nullifiers.html) — describes the actual Orchard nullifier structure and its separate security goals.
- [The Orchard Book: Commitments](https://zcash.github.io/orchard/design/commitments.html) — describes binding/hiding requirements and the concrete constructions used there.

Using a design concept from another protocol requires matching its assumptions and proving the adaptation. A citation is not a security reduction.

## 6. Canonical deposit and finality details remain chain-specific

An authenticated deposit locator needs canonical encoding of the source chain/network, bridge/deployment/asset scope as appropriate, transaction identifier, and event/output index. The value must come from authenticated source evidence, not a caller-supplied `v_claimed`. Do not use a stand-in based on `hashlib.sha256` while naming it Keccak.

The suggested fixed “two Casper epochs” rule is Ethereum-specific context, not a universal bridge finality policy. A real adapter must consume authenticated finality/checkpoint evidence, state what reorgs it can tolerate, and define halt/recovery semantics for deeper failures. A fixed wait duration alone is not a general finality proof. The current repository has no chain adapter or bridge contract.

## 7. What can be accepted now

Accept the **threat finding**, not the proposed fix.

1. Retain a formal requirement that a malicious sender must not be able to create two valid recipient outputs which share a nullifier unless the protocol explicitly accepts the resulting unspendability risk.
2. Keep output witness creation and the same-witness commitment/nullifier relation as blockers until a canonical output schema and proof backend are selected.
3. Keep V2 hashes, byte layouts and KATs frozen.
4. Preserve the current issuer-private requirement. Do not introduce public deposit- or nullifier-derived `coin_id` values without an explicit privacy decision.
5. Add tests only when they have a pinned algorithm/encoding and test the actual defined relation. The submitted Python suite should **not** be copied into `tests/`: it implements toy concatenation formulas, labels SHA-256 as Keccak, uses noncanonical example bytes, and its assertions mostly show that repeated calls on identical inputs return identical values. Those checks do not prove collision resistance, uniqueness, ZK soundness or Faerie Resistance.

## 8. Required work before revisiting deterministic IDs

A revised proposal must supply:
- a written leakage function and issuer/observer/trustee corruption model;
- exact `CRH_coin` specification, encoding, version, parameter binding and KATs;
- a formal output relation constraining every output's ID and commitment from a shared witness;
- a proof argument for the stated monetary-soundness and Faerie Resistance goals, explicitly assuming computational collision resistance rather than injectivity;
- an analysis of public input nullifiers, output transaction metadata and resulting linkability;
- canonical source-chain receipt/consensus/finality and deep-reorg recovery policy;
- adversarial tests using actual repository reference primitives and, once selected, the instantiated proof backend;
- independent review with concrete security parameters.

Until these gates close, global hidden-ID uniqueness remains under review, the output-identity/spendability issue remains unresolved, and production stays **NO-GO**.

## Decision

**Do not add the proposed circuit constraint to RFC-02 yet.** The current proposal is a useful threat report but not a definitive cryptographic solution. Record it as rejected-for-now pending a privacy-compatible, fully specified alternative. No production code, V2 formats, KATs or `main` change is authorized by this review.
