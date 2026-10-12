# CHp4.8 — Namespace V2: canonical EVM mapping and mint-scope binding

**Status:** implementation candidate on branch `namespace-v2-evm-canonical-binding`; not production certification.  
**Namespace V2 primitive:** unchanged.  
**Adapter:** EVM JSON-RPC manifest adapter with explicit pinned network, deployment and asset identity.  
**Ledger integration:** reference model now requires one fixed 48-byte expected namespace.  
**Production:** **NO-GO**; the reference ledger remains in-memory and all proof verifiers remain injected dependencies.

## 1. Scope and compatibility

The core Namespace V2 primitive remains the existing function in `src/primitives/namespace.py`. It accepts exactly three canonical 32-byte component IDs and returns a 48-byte namespace ID. The existing Namespace V2 KAT must not change.

The new adapter does not guess chain identifiers from names like "mainnet", token symbols, environment labels or RPC URLs. It resolves one EVM deployment from a trusted manifest and verifies the node's responses against pinned values before it returns a namespace.

This is a chain-identity adapter, **not** the deposit/issuance adapter. It does not verify a deposit event, prove a value transfer, establish consensus finality, or implement reorg recovery.

## 2. Frozen Namespace V2 equation

Let all fields be bytes, and let `LE16(x)` mean a two-byte unsigned little-endian encoding.

```text
NAMESPACE_V2(L, D, A) =
  SHAKE256-384(
    "0PSP-NAMESPACE-v2-SHAKE256" || 0x02 ||
    LE16(32) || L[32] ||
    LE16(32) || D[32] ||
    LE16(32) || A[32]
  )
```

The output is 48 bytes. This equation, domains, version, field order, lengths and endianness are unchanged by CHp4.8.

## 3. EVM canonical manifest

The adapter's configuration pins:

- EVM `chain_id` as a positive unsigned 256-bit integer.
- Exact 32-byte genesis block hash.
- A pinned checkpoint block number (uint64) and exact 32-byte hash. It validates the RPC view but does not enter the namespace-ID preimage. Changing the checkpoint requires reviewed manifest maintenance, not a namespace migration.
- The 20-byte nonzero protocol contract address.
- The expected 32-byte fingerprint of that contract's runtime bytecode, obtained independently from reviewed deployment artifacts.
- Either the native asset marker, or the 20-byte ERC-20-like asset contract address and its independently pinned runtime-code fingerprint.
- A deployment epoch/version (uint64) to deliberately create a new namespace when protocol semantics change behind an upgradeable proxy whose proxy bytecode remains the same.

Raw addresses are represented as exactly 20 bytes, not display/checksum strings. JSON-RPC chain IDs and block heights use canonical QUANTITY encodings; block hashes and bytecode use canonical even-length DATA hex. Symbols and tickers are never identity inputs.

Production configuration should use HTTPS JSON-RPC and a supported `finalized` code block tag. `safe` or `latest` are available only when explicitly selected; development HTTP requires explicit opt-in. A trusted manifest must be generated and reviewed separately: never calculate the expected code fingerprint from the same untrusted RPC response you are trying to verify.

## 4. Exact EVM component derivation

The adapter encoding itself has version `0x01`, independently of the frozen Namespace V2 version `0x02`.

First derive the runtime-code fingerprint for a contract's canonical runtime bytecode `code`:

```text
CodeFP(code) =
  SHAKE256-256(
    "0PSP-EVM-RUNTIME-CODE-FINGERPRINT-v1-SHAKE256" ||
    0x01 || BE32(len(code)) || code
  )
```

The adapter rejects empty code and compares the result against the pinned expected fingerprint.

Let `BE256(chain_id)` be the 32-byte big-endian chain ID and `E` the 8-byte big-endian deployment epoch. Checkpoint height/hash and runtime-code fingerprints are validated separately and are not inputs to these identity preimages. Then:

```text
L = SHAKE256-256(
  "0PSP-EVM-LEDGER-COMPONENT-v1-SHAKE256" || 0x01 ||
  BE256(chain_id) || genesis_hash[32]
)

D = SHAKE256-256(
  "0PSP-EVM-DEPLOYMENT-COMPONENT-v1-SHAKE256" || 0x01 ||
  L[32] || protocol_address[20] || E
)

A_native = SHAKE256-256(
  "0PSP-EVM-ASSET-COMPONENT-v1-SHAKE256" || 0x01 ||
  L[32] || 0x00
)

A_token = SHAKE256-256(
  "0PSP-EVM-ASSET-COMPONENT-v1-SHAKE256" || 0x01 ||
  L[32] || 0x01 || token_address[20]
)

namespace_id = NAMESPACE_V2(L, D, A_native_or_token)
```

Each inner component digest is exactly 32 bytes, satisfying the unchanged Namespace V2 API. All field boundaries are fixed-width. The outer Namespace V2 encoding length-prefixes each component with LE16(32).

### Canonical RPC checks

The resolver makes these read-only calls:

1. `eth_chainId`: parsed as a canonical QUANTITY and compared with the pinned chain ID.
2. `eth_getBlockByNumber("0x0", false)`: block height and genesis hash must match the manifest.
3. `eth_getBlockByNumber(checkpoint_height, false)`: exact height and checkpoint hash must match (unless the configured checkpoint is genesis itself).
4. `eth_getCode(protocol_address, code_block_tag)`: code must be non-empty and its fingerprint must match.
5. For token assets only, `eth_getCode(token_address, code_block_tag)`: code must be non-empty and its fingerprint must match.

Malformed replies, noncanonical quantities, wrong IDs/heights/hashes, RPC errors, unavailable/empty code, or fingerprint mismatches fail closed. Exceptions do not include the endpoint URL because providers commonly put credentials in the URL.

## 5. Mint-ledger namespace binding

`ReferenceLedger` now requires `expected_namespace_id` (exactly 48 bytes) at construction.

- The issuance adapter must return a `DepositAuthorization` whose namespace exactly equals that configured ID. A mismatch is rejected before the issuance-proof callback.
- A spend statement with a different namespace is rejected before the spend-proof callback.
- The namespace is exposed read-only as `expected_namespace_id`.
- Existing duplicate-deposit, duplicate-commitment and duplicate-nullifier transition rules remain in force.

Reference usage:

```python
binding = EvmNamespaceAdapter(config, JsonRpcClient(rpc_url)).resolve()
ledger = ReferenceLedger(
    expected_namespace_id=binding.namespace_id.data,
    authorize_deposit=verified_deposit_adapter,
    verify_issuance_proof=issuance_verifier,
    verify_spend_proof=spend_verifier,
)
```

The configured namespace must come from a reviewed/pinned manifest, not a request parameter. One reference-ledger instance intentionally represents one chain/deployment/asset scope; instantiate separate instances for separate namespace scopes.

**This is still a reference model.** It is in-memory, single-process and uses injected callbacks. It is not durable state, a consensus ledger, a chain light client, or a live cryptographic proof verifier.

## 6. Security argument and limits

### Properties tested by this increment

- Deterministic mapping: the same chain ID, genesis hash, protocol address, deployment epoch and asset identity produce the same three component IDs and namespace ID, independent of which valid pinned checkpoint is used.
- Domain/type separation: native asset and token asset use different asset-type bytes and fields. Chain ID/genesis hash, protocol address/epoch and token contract identity feed the component IDs; checkpoint and code fingerprints are validation-only manifest pins.
- Fail-closed identity checks: a response disagreeing with the pinned chain/checkpoint/code manifest cannot yield a namespace.
- Ledger context binding: an issuance or spend using a namespace other than the ledger's configured 48-byte namespace is rejected before invoking the proof-verifier callback.
- Backward compatibility: the existing core Namespace V2 formula and KAT are unchanged.

These are deterministic encoding and state-model arguments backed by finite tests, not a mathematical proof that SHAKE256 is injective, not a consensus proof, and not a ZK proof.

### Trust and protocol assumptions

- The manifest (chain ID, genesis/checkpoint, contract addresses, code fingerprints and deployment epoch) was obtained and reviewed independently. Checkpoint and code fingerprints validate what the node serves; they intentionally do not define the namespace, so operators need not choose the same inspection checkpoint to agree on the logical chain.
- The JSON-RPC endpoint is trusted for truthful chain data, or is compared with a light client / independent providers. JSON-RPC responses alone do not prove consensus.
- A pinned checkpoint is used to reject a node reporting an unexpected history at that height. Since it is validation-only, operators may use different reviewed checkpoints on the same logical chain without splitting the namespace. Chains that fork after a shared checkpoint still require a separate finality/reorg policy; namespace identity does not prove consensus or resolve forks.
- Upgradeable proxy semantics are not automatically discovered. Governance must pin and increment `deployment_epoch` when the protocol's identity semantics change, and the deployment mechanism must authenticate that governance decision.
- The selected chain's meaning of a native asset is agreed by the manifest. Wrapped assets must be represented as token-contract assets.
- Runtime-code fingerprint checks are validation gates, not identity inputs. They are only as trustworthy as the expected fingerprint and chain view. They do not by themselves verify proxy implementation slots, storage configuration, token behavior, or contract correctness. For a semantics-changing protocol upgrade that preserves the proxy address/code, governance must explicitly increment deployment_epoch.

### Collision/security parameters

The adapter uses 32-byte intermediate component hashes because Namespace V2 fixes each component at 32 bytes. Those outputs are not mathematically injective. In an idealized generic quantum-oracle model, a 256-bit hash has a birthday-style collision-search scale around \(2^{85}\) queries; targeted second-preimage work is a different problem and should not be conflated with generic collision search. The outer 48-byte namespace digest does not restore information lost in a colliding 32-byte component. The deployment threat model must assess whether this bound is acceptable for all component-collision scenarios. Do not claim a blanket 128-bit quantum collision-resistance level for the entire adapter solely because the final namespace is 48 bytes. A future version that needs a stronger generic collision bound would require a separately versioned wider-component namespace design; changing the frozen V2 formula silently is forbidden.

## 7. Test evidence

The implementation adds:
- A hardcoded end-to-end EVM ERC-20 namespace vector over synthetic but byte-exact pinned inputs.
- Determinism and native-vs-token separation tests.
- Manifest-shape validation for chain IDs, hashes, addresses, checkpoint rules, code fingerprints, deployment epoch and code block tag.
- RPC-client HTTPS/default policy, explicit HTTP opt-in, response-ID/result validation, response-size bounds and sanitized transport errors.
- Adversarial chain ID, genesis/checkpoint substitution, noncanonical QUANTITY, wrong block height, missing code and protocol/token runtime-code substitution tests.
- Reference-ledger tests proving namespace mismatch rejects issuance/spend before the proof callback and does not mutate state.

The fake JSON-RPC tests validate the adapter's local decision logic. They do not authenticate a real RPC provider, run a real chain, prove the chain's consensus, or establish finality/reorg safety. The adapter must be smoke-tested against the intended production chain and deployment manifest before that chain is supported.

## 8. Release gate

This increment closes the missing **EVM identity mapping contract** and **single-namespace binding in the reference ledger**. It does not close the production ledger, authenticated deposit/event verification, persistent replay constraints, proof backend, recipient/threshold authorization, proxy-upgrade verification, independent cryptographic audit, or end-to-end privacy gates.

**Production remains NO-GO.**
