"""Canonical EVM identity adapter using direct-hash Namespace V3.

The adapter retains the full canonical ledger, deployment and asset identity
descriptors and passes them to one SHAKE256-384 invocation. It does not hash
each descriptor to 256 bits first. Namespace V2 remains frozen as a separate
compatibility primitive.

Security boundary: JSON-RPC is an observation interface, not a light client.
The adapter checks RPC responses against a trusted, out-of-band chain/checkpoint
and runtime-code manifest. It does not prove a node's consensus view or verify
deposit events/finality; those belong to the separate chain/deposit adapter.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import urllib.request
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from src.primitives.namespace_v3 import (
    NAMESPACE_V3_COMPONENT_MAX_BYTES,
    NamespaceIdV3,
    derive_namespace_id_v3,
)

EVM_IDENTITY_ENCODING_VERSION = b"\x01"
EVM_CODE_FINGERPRINT_VERSION = b"\x02"
EVM_ADDRESS_BYTES = 20
EVM_HASH_BYTES = 32
EVM_CODE_FINGERPRINT_BYTES = 48
EVM_CHAIN_ID_MAX = (1 << 256) - 1
EVM_BLOCK_NUMBER_MAX = (1 << 64) - 1
MAX_RUNTIME_CODE_BYTES = 1_000_000
# Runtime code is returned as hex, which expands each byte to two characters.
MAX_RPC_RESPONSE_BYTES = (2 * MAX_RUNTIME_CODE_BYTES) + 100_000

DOMAIN_EVM_LEDGER_IDENTITY = b"0PSP-EVM-LEDGER-IDENTITY-v1"
DOMAIN_EVM_DEPLOYMENT_IDENTITY = b"0PSP-EVM-DEPLOYMENT-IDENTITY-v1"
DOMAIN_EVM_ASSET_IDENTITY = b"0PSP-EVM-ASSET-IDENTITY-v1"
DOMAIN_EVM_CODE_FINGERPRINT = b"0PSP-EVM-RUNTIME-CODE-FINGERPRINT-v2-SHAKE256"


class EvmNamespaceError(RuntimeError):
    """Base class for fail-closed EVM namespace adapter failures."""


class EvmRpcError(EvmNamespaceError):
    """The configured EVM JSON-RPC endpoint failed or returned invalid JSON-RPC."""


class EvmIdentityMismatch(EvmNamespaceError):
    """The observed chain or deployment does not match the pinned manifest."""


class JsonRpcTransport(Protocol):
    """Minimal injectable transport contract used by the namespace resolver."""

    def call(self, method: str, params: list[object]) -> object:
        """Call one JSON-RPC method and return its result value."""


def _require_fixed_bytes(value: bytes, length: int, name: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")


def _require_nonzero_address(value: bytes, name: str) -> None:
    _require_fixed_bytes(value, EVM_ADDRESS_BYTES, name)
    if value == bytes(EVM_ADDRESS_BYTES):
        raise ValueError(f"{name} must not be the zero address")


def runtime_code_fingerprint(runtime_code: bytes) -> bytes:
    """Return the 48-byte manifest fingerprint of canonical EVM runtime bytecode.

    The fingerprint is a 384-bit SHAKE256 output over a domain/version and
    length-prefixed bytecode. Callers should compute the expected value from
    independently obtained, reviewed deployment artifacts and pin it in
    deployment configuration; deriving the expectation from the same RPC
    response would provide no protection.
    """
    if not isinstance(runtime_code, bytes) or not runtime_code:
        raise ValueError("runtime_code must be non-empty bytes")
    if len(runtime_code) > MAX_RUNTIME_CODE_BYTES:
        raise ValueError("runtime_code exceeds the adapter safety bound")
    preimage = (
        DOMAIN_EVM_CODE_FINGERPRINT
        + EVM_CODE_FINGERPRINT_VERSION
        + len(runtime_code).to_bytes(4, "big")
        + runtime_code
    )
    return hashlib.shake_256(preimage).digest(EVM_CODE_FINGERPRINT_BYTES)


@dataclass(frozen=True, slots=True)
class EvmNamespaceConfig:
    """Trusted manifest for one protocol deployment and one asset on an EVM chain.

    The checkpoint and runtime-code fingerprints validate the selected RPC
    view against this manifest; they are NOT namespace inputs. This keeps
    operators with different valid checkpoints from deriving different IDs.
    If protocol semantics change behind an upgradeable proxy, increment
    deployment_epoch. If the asset's identity semantics change behind an
    upgradeable token proxy, increment asset_epoch. Both increments require
    a reviewed protocol/deployment policy decision.
    """

    chain_id: int
    genesis_hash: bytes
    checkpoint_block_number: int
    checkpoint_hash: bytes
    protocol_address: bytes
    expected_protocol_code_fingerprint: bytes
    asset_address: bytes | None = None
    expected_asset_code_fingerprint: bytes | None = None
    deployment_epoch: int = 0
    asset_epoch: int = 0
    code_block_tag: str = "finalized"

    def __post_init__(self) -> None:
        if (
            isinstance(self.chain_id, bool)
            or not isinstance(self.chain_id, int)
            or not 1 <= self.chain_id <= EVM_CHAIN_ID_MAX
        ):
            raise ValueError("chain_id must be an integer in [1, 2^256-1]")
        _require_fixed_bytes(self.genesis_hash, EVM_HASH_BYTES, "genesis_hash")
        if (
            isinstance(self.checkpoint_block_number, bool)
            or not isinstance(self.checkpoint_block_number, int)
            or not 0 <= self.checkpoint_block_number <= EVM_BLOCK_NUMBER_MAX
        ):
            raise ValueError("checkpoint_block_number must be an integer in [0, 2^64-1]")
        _require_fixed_bytes(self.checkpoint_hash, EVM_HASH_BYTES, "checkpoint_hash")
        if self.checkpoint_block_number == 0 and self.checkpoint_hash != self.genesis_hash:
            raise ValueError("checkpoint hash at block 0 must equal genesis_hash")
        _require_nonzero_address(self.protocol_address, "protocol_address")
        _require_fixed_bytes(
            self.expected_protocol_code_fingerprint,
            EVM_CODE_FINGERPRINT_BYTES,
            "expected_protocol_code_fingerprint",
        )
        if self.asset_address is None:
            if self.expected_asset_code_fingerprint is not None:
                raise ValueError("native asset must not set expected_asset_code_fingerprint")
        else:
            _require_nonzero_address(self.asset_address, "asset_address")
            _require_fixed_bytes(
                self.expected_asset_code_fingerprint,
                EVM_CODE_FINGERPRINT_BYTES,
                "expected_asset_code_fingerprint",
            )
        if (
            isinstance(self.deployment_epoch, bool)
            or not isinstance(self.deployment_epoch, int)
            or not 0 <= self.deployment_epoch <= EVM_BLOCK_NUMBER_MAX
        ):
            raise ValueError("deployment_epoch must be an integer in [0, 2^64-1]")
        if (
            isinstance(self.asset_epoch, bool)
            or not isinstance(self.asset_epoch, int)
            or not 0 <= self.asset_epoch <= EVM_BLOCK_NUMBER_MAX
        ):
            raise ValueError("asset_epoch must be an integer in [0, 2^64-1]")
        if self.code_block_tag not in ("finalized", "safe", "latest"):
            raise ValueError("code_block_tag must be finalized, safe, or latest")


@dataclass(frozen=True, slots=True)
class EvmNamespaceBinding:
    """Resolved, auditable V3 identity descriptors for one EVM deployment."""

    namespace_id: NamespaceIdV3
    chain_id: int
    genesis_hash: bytes
    checkpoint_block_number: int
    checkpoint_hash: bytes
    protocol_address: bytes
    protocol_code_fingerprint: bytes
    asset_address: bytes | None
    asset_code_fingerprint: bytes | None
    deployment_epoch: int
    asset_epoch: int
    ledger_identity: bytes
    deployment_identity: bytes
    asset_identity: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.namespace_id, NamespaceIdV3):
            raise TypeError("namespace_id must be a NamespaceIdV3")
        for name, value in (
            ("ledger_identity", self.ledger_identity),
            ("deployment_identity", self.deployment_identity),
            ("asset_identity", self.asset_identity),
        ):
            if not isinstance(value, bytes) or not 1 <= len(value) <= NAMESPACE_V3_COMPONENT_MAX_BYTES:
                raise ValueError(f"{name} must contain 1..{NAMESPACE_V3_COMPONENT_MAX_BYTES} bytes")
        _require_fixed_bytes(self.protocol_code_fingerprint, EVM_CODE_FINGERPRINT_BYTES,
                             "protocol_code_fingerprint")
        if self.asset_code_fingerprint is not None:
            _require_fixed_bytes(self.asset_code_fingerprint, EVM_CODE_FINGERPRINT_BYTES,
                                 "asset_code_fingerprint")


class JsonRpcClient:
    """Small standard-library JSON-RPC client with fail-closed response checks.

    HTTPS is mandatory unless the caller explicitly opts into HTTP for a
    controlled local development node. The endpoint is deliberately omitted
    from exception messages because hosted RPC URLs often contain API tokens.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        timeout_seconds: float = 5.0,
        allow_insecure_http: bool = False,
    ) -> None:
        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("endpoint must be a non-empty URL")
        parsed = urlsplit(endpoint)
        try:
            parsed.port
        except ValueError:
            raise ValueError("endpoint has an invalid port") from None
        if (
            parsed.scheme not in ("https", "http")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("endpoint must be a valid HTTP(S) URL without userinfo or fragment")
        if parsed.scheme == "http" and allow_insecure_http is not True:
            raise ValueError("HTTP RPC is disabled; explicitly allow it only for controlled development")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")
        self._endpoint = endpoint
        self._timeout_seconds = float(timeout_seconds)

    def call(self, method: str, params: list[object]) -> object:
        if not isinstance(method, str) or not method or not isinstance(params, list):
            raise TypeError("method must be a non-empty string and params must be a list")
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                raw = response.read(MAX_RPC_RESPONSE_BYTES + 1)
        except Exception:
            # Never propagate a transport exception that could include a URL/API key.
            raise EvmRpcError(f"JSON-RPC transport failed for {method}") from None
        if len(raw) > MAX_RPC_RESPONSE_BYTES:
            raise EvmRpcError(f"JSON-RPC response too large for {method}")
        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise EvmRpcError(f"JSON-RPC returned invalid or ambiguous JSON for {method}") from None
        if (
            not isinstance(payload, dict)
            or payload.get("jsonrpc") != "2.0"
            or type(payload.get("id")) is not int
            or payload.get("id") != 1
        ):
            raise EvmRpcError(f"JSON-RPC envelope mismatch for {method}")
        if "error" in payload:
            error = payload["error"]
            code = error.get("code") if isinstance(error, dict) else None
            raise EvmRpcError(f"JSON-RPC method {method} failed (code={code!r})")
        if "result" not in payload:
            raise EvmRpcError(f"JSON-RPC response omitted result for {method}")
        return payload["result"]


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object members instead of silently accepting last-wins JSON."""
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError("duplicate JSON object member")
        decoded[key] = value
    return decoded


def _parse_quantity(value: object, name: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value) is None:
        raise EvmRpcError(f"{name} is not a canonical JSON-RPC QUANTITY")
    return int(value[2:], 16)


def _parse_data(value: object, name: str, *, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is None:
        raise EvmRpcError(f"{name} is not canonical even-length JSON-RPC DATA")
    result = bytes.fromhex(value[2:])
    if expected_length is not None and len(result) != expected_length:
        raise EvmRpcError(f"{name} must be exactly {expected_length} bytes")
    return result


def _hex_data(value: bytes) -> str:
    return "0x" + value.hex()


def _hex_quantity(value: int) -> str:
    return hex(value)


def _canonical_evm_identities(
    config: EvmNamespaceConfig,
    genesis_hash: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Encode identity descriptors directly; do not hash any descriptor first."""
    ledger_identity = (
        DOMAIN_EVM_LEDGER_IDENTITY
        + EVM_IDENTITY_ENCODING_VERSION
        + config.chain_id.to_bytes(32, "big")
        + genesis_hash
    )
    deployment_identity = (
        DOMAIN_EVM_DEPLOYMENT_IDENTITY
        + EVM_IDENTITY_ENCODING_VERSION
        + config.protocol_address
        + config.deployment_epoch.to_bytes(8, "big")
    )
    if config.asset_address is None:
        asset_type = b"\x00"
        asset_address = b""
    else:
        asset_type = b"\x01"
        asset_address = config.asset_address
    asset_identity = (
        DOMAIN_EVM_ASSET_IDENTITY
        + EVM_IDENTITY_ENCODING_VERSION
        + asset_type
        + asset_address
        + config.asset_epoch.to_bytes(8, "big")
    )
    for name, value in (
        ("ledger_identity", ledger_identity),
        ("deployment_identity", deployment_identity),
        ("asset_identity", asset_identity),
    ):
        if not 1 <= len(value) <= NAMESPACE_V3_COMPONENT_MAX_BYTES:
            raise EvmNamespaceError(f"{name} exceeds the Namespace V3 input bound")
    return ledger_identity, deployment_identity, asset_identity


class EvmNamespaceAdapter:
    """Resolve one EVM deployment into a typed, direct-hash Namespace V3 ID."""

    def __init__(self, config: EvmNamespaceConfig, rpc: JsonRpcTransport) -> None:
        if not isinstance(config, EvmNamespaceConfig):
            raise TypeError("config must be an EvmNamespaceConfig")
        if not callable(getattr(rpc, "call", None)):
            raise TypeError("rpc must provide call(method, params)")
        self._config = config
        self._rpc = rpc

    def _call(self, method: str, params: list[object]) -> object:
        try:
            return self._rpc.call(method, params)
        except EvmNamespaceError:
            raise
        except Exception:
            raise EvmRpcError(f"JSON-RPC call failed for {method}") from None

    def _block_hash(self, number: int) -> bytes:
        block = self._call("eth_getBlockByNumber", [_hex_quantity(number), False])
        if not isinstance(block, dict):
            raise EvmRpcError(f"node returned no block object for height {number}")
        actual_number = _parse_quantity(block.get("number"), f"block {number}.number")
        if actual_number != number:
            raise EvmIdentityMismatch(f"node returned the wrong block height for {number}")
        return _parse_data(block.get("hash"), f"block {number}.hash", expected_length=EVM_HASH_BYTES)

    def _contract_code(self, address: bytes, name: str) -> bytes:
        result = self._call("eth_getCode", [_hex_data(address), self._config.code_block_tag])
        code = _parse_data(result, f"{name} runtime code")
        if not code:
            raise EvmIdentityMismatch(f"{name} has no runtime code at the configured block tag")
        if len(code) > MAX_RUNTIME_CODE_BYTES:
            raise EvmRpcError(f"{name} runtime code exceeds the adapter safety bound")
        return code

    def resolve(self) -> EvmNamespaceBinding:
        """Verify the configured chain/deployment and compute Namespace V3.

        Raises an adapter error rather than returning a namespace if any identity
        check fails. The caller should persist the returned binding and use the
        exact namespace_id bytes for its single-namespace ledger instance.
        """
        config = self._config
        actual_chain_id = _parse_quantity(self._call("eth_chainId", []), "eth_chainId")
        if actual_chain_id != config.chain_id:
            raise EvmIdentityMismatch("RPC chain ID does not match the pinned manifest")

        genesis_hash = self._block_hash(0)
        if not hmac.compare_digest(genesis_hash, config.genesis_hash):
            raise EvmIdentityMismatch("RPC genesis hash does not match the pinned manifest")

        checkpoint_hash = (
            genesis_hash
            if config.checkpoint_block_number == 0
            else self._block_hash(config.checkpoint_block_number)
        )
        if not hmac.compare_digest(checkpoint_hash, config.checkpoint_hash):
            raise EvmIdentityMismatch("RPC checkpoint hash does not match the pinned manifest")

        protocol_code = self._contract_code(config.protocol_address, "protocol deployment")
        protocol_fingerprint = runtime_code_fingerprint(protocol_code)
        if not hmac.compare_digest(
            protocol_fingerprint, config.expected_protocol_code_fingerprint
        ):
            raise EvmIdentityMismatch("protocol runtime code does not match the pinned fingerprint")

        asset_fingerprint: bytes | None = None
        if config.asset_address is not None:
            asset_code = self._contract_code(config.asset_address, "asset contract")
            asset_fingerprint = runtime_code_fingerprint(asset_code)
            if not hmac.compare_digest(
                asset_fingerprint, config.expected_asset_code_fingerprint  # type: ignore[arg-type]
            ):
                raise EvmIdentityMismatch("asset runtime code does not match the pinned fingerprint")

        # Checkpoint and code fingerprints authenticate this RPC view, but
        # identity is encoded from the full chain/deployment/asset descriptors.
        # No 256-bit intermediate hash participates in namespace derivation.
        ledger_identity, deployment_identity, asset_identity = _canonical_evm_identities(
            config,
            genesis_hash,
        )
        namespace_id = derive_namespace_id_v3(
            ledger_identity,
            deployment_identity,
            asset_identity,
        )
        return EvmNamespaceBinding(
            namespace_id=namespace_id,
            chain_id=config.chain_id,
            genesis_hash=genesis_hash,
            checkpoint_block_number=config.checkpoint_block_number,
            checkpoint_hash=checkpoint_hash,
            protocol_address=config.protocol_address,
            protocol_code_fingerprint=protocol_fingerprint,
            asset_address=config.asset_address,
            asset_code_fingerprint=asset_fingerprint,
            deployment_epoch=config.deployment_epoch,
            asset_epoch=config.asset_epoch,
            ledger_identity=ledger_identity,
            deployment_identity=deployment_identity,
            asset_identity=asset_identity,
        )
