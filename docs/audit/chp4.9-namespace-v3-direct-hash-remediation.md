# CHp4.9 — Namespace V3 Direct-Hash Remediation

**Status:** implementation candidate on branch \`namespace-v3-direct-hash\`; production approval is not implied.  
**V2 compatibility:** the original Namespace V2 core formula and known-answer test remain frozen.  
**Current EVM namespace mapping:** direct-hash Namespace V3, not the intermediate-hash mapping in CHp4.8.  
**Reference ledger:** now requires the typed NamespaceIdV3 value for its configured context and public statements.  
**Production status:** **NO-GO** until the proof relation, authenticated chain/deposit adapter, durable ledger, finality/reorg policy and independent review are complete.

## 1. Problem statement

The first EVM adapter in CHp4.8 derived three 32-byte identifiers by independently hashing larger identity descriptors to 256 bits, then passed those three digests to the frozen Namespace V2 core. Although the final namespace digest is 384 bits, a collision in any one of those 256-bit intermediate functions could be used while keeping the other descriptor inputs fixed. The full namespace would then collide too. Under an idealized generic quantum collision-search model, an unconstrained 256-bit intermediate has BHT-style collision-query scale about \(2^{256/3} = 2^{85.3}\), below a nominal 128-bit post-quantum collision target.

This was not a flaw in SHAKE256-384's digest length, and it was not a SHAKE collision already demonstrated against a real chain. It was an avoidable composition choice: the identity adapter compressed each field independently before the final namespace hash.

**Decision:** preserve Namespace V2 exactly for compatibility, but make the EVM adapter hash the full canonical identity tuple with one final SHAKE256-384 invocation. No shorter intermediate digest participates in the namespace identity.

## 2. Namespace V2 is frozen

The existing V2 core remains:

~~~text
NAMESPACE_V2(L, D, A) =
  SHAKE256-384(
    "0PSP-NAMESPACE-v2-SHAKE256" || 0x02 ||
    LE16(32) || L[32] ||
    LE16(32) || D[32] ||
    LE16(32) || A[32]
  )
~~~

This accepts three already-canonical 32-byte component IDs. It does not by itself require those IDs to be hashes. A V2 adapter must not silently feed it independently compressed 256-bit digests when the surrounding threat model expects a 128-bit quantum collision-search margin.

The V2 equation and its native/Python known-answer vectors are unchanged by this remediation.

## 3. Canonical Namespace V3 equation

Each descriptor must be a bytes value of length 1 through 4096. Component order is fixed: ledger, deployment, asset. All field boundaries use a 32-bit little-endian length immediately followed by exactly that many bytes.

~~~text
NAMESPACE_V3(L, D, A) =
  SHAKE256-384(
    "0PSP-NAMESPACE-v3-SHAKE256" || 0x03 ||
    LE32(len(L)) || L ||
    LE32(len(D)) || D ||
    LE32(len(A)) || A
  )
~~~

No descriptor is pre-hashed. The 48-byte result is represented by a distinct NamespaceIdV3 type, rather than reusing the NamespaceId V2 Python type. Serialization to the public 48-byte string is explicit via its data field.

The length prefixes make the encoding unambiguous: for valid descriptors, parsing the three lengths and then consuming the declared byte counts uniquely recovers the three component byte strings. The domain and version separate this construction from Namespace V2 and from other SHAKE-based domains.

## 4. Exact EVM identity descriptors

The EVM adapter first verifies its manifest against the selected JSON-RPC view, then directly encodes the full identities below. All integer encodings are unsigned and big-endian within the descriptors.

~~~text
L =
  "0PSP-EVM-LEDGER-IDENTITY-v1" || 0x01 ||
  BE256(chain_id) || genesis_hash[32]

D =
  "0PSP-EVM-DEPLOYMENT-IDENTITY-v1" || 0x01 ||
  protocol_address[20] || BE64(deployment_epoch)

A_native =
  "0PSP-EVM-ASSET-IDENTITY-v1" || 0x01 ||
  0x00 || BE64(asset_epoch)

A_token =
  "0PSP-EVM-ASSET-IDENTITY-v1" || 0x01 ||
  0x01 || token_address[20] || BE64(asset_epoch)

namespace_id = NAMESPACE_V3(L, D, A_native_or_token)
~~~

- The ledger descriptor binds the configured positive EVM chain ID and genesis block hash.
- The deployment descriptor binds the protocol contract address and explicit deployment epoch.
- Asset tag 0 identifies the native asset. Asset tag 1 identifies a token contract by its 20-byte address. No display symbol or ticker contributes to identity.
- deployment_epoch must be increased under a reviewed policy when protocol semantics change behind a proxy whose address/runtime code remains stable.
- asset_epoch must be increased under a reviewed policy when the economic or identity semantics of the asset change behind the same asset address. Updating a manifest alone does not automatically rotate the namespace.

The checkpoint and code fingerprints are manifest validation fields, not identity inputs. Using different valid checkpoints therefore does not split one logical chain into multiple namespaces. Conversely, a fork that shares chain ID and genesis can share the same namespace identity: namespace derivation is not a consensus or reorg-resolution mechanism.

## 5. Runtime-code fingerprint contract

The code fingerprint has itself been versioned and widened to 48 bytes. Its exact preimage is:

~~~text
CodeFP_v2(code) =
  SHAKE256-384(
    "0PSP-EVM-RUNTIME-CODE-FINGERPRINT-v2-SHAKE256" ||
    0x02 ||
    BE32(len(code)) || code
  )
~~~

The adapter checks the protocol runtime code and token runtime code, if any, against independently pinned 48-byte expected fingerprints. Empty code and code beyond the local safety bound are rejected. This fingerprint is used only as a manifest validation value; it is not fed into namespace identity as a shorter digest.

The expected fingerprint must come from an independently reviewed deployment artifact. Computing the expected fingerprint from the same untrusted RPC response that supplies the observed code offers no protection. Runtime-code comparison alone does not verify proxy implementation slots, storage configuration, ownership, contract logic, consensus truth or finality.

## 6. Security argument and mathematical limits

### Encoding uniqueness

For permitted inputs, the tuple-to-preimage encoding is injective. Domain/version are fixed, descriptor order is fixed, each descriptor length is encoded unambiguously in LE32, and the encoder appends exactly the declared bytes. EVM descriptors also include explicit domain labels and the native/token asset-type byte.

This proves that different canonical descriptor tuples yield different preimages. It does not prove that SHAKE256-384 is injective.

### Collision existence versus collision search

The set of permitted three-descriptor inputs is much larger than \(2^{384}\). By the pigeonhole principle, the 384-bit output function must map some distinct tuples to the same namespace ID. Mathematical injectivity is impossible and is not a goal.

The relevant computational claim is narrower: when SHAKE256-384 is modeled as an ideal quantum-accessible random oracle, generic quantum collision algorithms of the Brassard–Høyer–Tapp family have query scale on the order of \(2^{n/3}\) for an n-bit output. At n = 384, that scale is approximately \(2^{128}\). The new construction removes the adapter's 256-bit intermediate identity digests, so a 256-bit intermediate collision is no longer sufficient to collide the final namespace.

This is a generic-model security estimate, not a formal cryptographic reduction for the complete 0PSP system, not a proof of SHAKE256 security against all future quantum algorithms, and not a claim that a \(2^{128}\)-query computation is physically impossible forever. It also does not establish a practical work factor for the restricted set of deployed EVM identities without considering the attacker's ability to choose chain parameters, deployment addresses, and asset contracts.

A 48-byte runtime-code fingerprint is checked against a pinned expected digest, a fixed-target comparison problem rather than the namespace identity collision search. It does not replace manifest provenance or chain authentication.

### Chain and ledger assumptions

- The manifest is trusted and pinned independently of the RPC provider.
- JSON-RPC checks detect mismatches with the configured manifest; they do not prove the provider's consensus view. Deployments requiring stronger assurance need a light client or a specified multi-provider verification policy.
- A fixed checkpoint is verification-only. Reorg/finality and cross-fork state behavior remain the responsibility of a separate authenticated chain adapter and the durable state transition.
- A proxy code hash may remain unchanged across implementation upgrades. Governance must bump deployment_epoch or asset_epoch when semantics affecting the namespace change.
- The actual spend/issuance proof must bind the exact 48-byte NamespaceIdV3 value into the commitment/nullifier relation and accepted parameter set. The current reference ledger does not create or verify that proof.

## 7. End-to-end API boundary

The EVM adapter returns NamespaceIdV3 plus the exact raw descriptors used. The reference ledger accepts NamespaceIdV3 as its configured expected namespace, and requires DepositAuthorization and SpendStatement to carry that same typed ID. It rejects mismatches before invoking the injected proof-verifier callbacks. This prevents an accidental Namespace V2/V3 type mix at the Python API boundary.

The cryptographic commitments and nullifiers already accept a fixed 48-byte namespace field, so the serialized V3 namespace value fits that field width. However, the complete proof circuit and consensus parameters must explicitly select and bind Namespace V3 before any production use. A type check in the reference model is not a cryptographic proof constraint.

## 8. Evidence added

- New Python NamespaceIdV3 type and direct-hash preimage encoder.
- EVM adapter now hashes raw descriptors directly with one SHAKE256-384 call.
- Runtime-code fingerprints are versioned and widened to 48 bytes; checkpoint and code fingerprints remain validation-only.
- Native C API for direct Namespace V3 derivation, integrated into the shared library, native test target and ASan/UBSan target.
- Python known-answer vector for the exact canonical preimage and output.
- Native known-answer vector for the same EVM descriptor tuple.
- Adversarial coverage for descriptor changes, ordering/length separation, invalid widths/lengths, RPC substitutions, typed namespace enforcement, and deployment/asset epoch changes.
- Reference ledger now requires typed NamespaceIdV3 for configuration, issuance authorization and spend statements.

The finite vectors establish Python/native implementation agreement for the tested cases. They do not prove collision freedom, RPC consensus, value conservation, issuance soundness, zero knowledge or production ledger safety.

## 9. References

- [Brassard, Høyer, and Tapp, Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002) — reference for the generic quantum collision query scale.
- [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) — SHA-3 and SHAKE definitions.
- [Ethereum JSON-RPC API](https://ethereum.org/developers/docs/apis/json-rpc/) — chain ID, block queries, code queries, and canonical QUANTITY/DATA conventions.

**Production remains NO-GO.**
