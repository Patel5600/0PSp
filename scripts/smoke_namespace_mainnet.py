#!/usr/bin/env python3
"""Run a real Ethereum Mainnet namespace + authenticated-finality smoke test.

This is an operator-run acceptance check, not a testnet fixture and not a
production approval. It requires independently sourced deployment pins. The
report deliberately leaves proof binding and independent review NO-GO.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from src.adapters.evm_helios import (
    ETHEREUM_MAINNET_CHAIN_ID,
    ETHEREUM_MAINNET_GENESIS_HASH,
    HeliosAuthenticatedHeaderJournal,
    HeliosMainnetConfig,
    HeliosMainnetLightClient,
)
from src.adapters.evm_namespace import EvmNamespaceAdapter, EvmNamespaceConfig
from src.primitives.namespace_v3 import NamespaceIdV3


_HEX_RE = re.compile(r"[0-9a-fA-F]+\Z")
_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_U64_MAX = (1 << 64) - 1


class SmokeConfigurationError(ValueError):
    """Required live smoke-test configuration is absent or non-canonical."""


@dataclass(frozen=True, slots=True)
class MainnetSmokeConfiguration:
    helios: HeliosMainnetConfig
    namespace: EvmNamespaceConfig
    finality_database: Path
    max_headers_per_sync: int


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not isinstance(value, str) or not value or value.strip() != value:
        raise SmokeConfigurationError(f"{name} is required and must not contain surrounding whitespace")
    return value


def _hex_bytes(env: Mapping[str, str], name: str, size: int) -> bytes:
    value = _required(env, name)
    digits = value[2:] if value.startswith("0x") else value
    if len(digits) != size * 2 or _HEX_RE.fullmatch(digits) is None:
        raise SmokeConfigurationError(f"{name} must encode exactly {size} bytes as hexadecimal")
    return bytes.fromhex(digits)


def _uint(
    env: Mapping[str, str],
    name: str,
    *,
    default: int | None = None,
    maximum: int = _U64_MAX,
    minimum: int = 0,
) -> int:
    value = env.get(name)
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
        raise SmokeConfigurationError(f"{name} must be a canonical unsigned decimal integer")
    parsed = int(value, 10)
    if not minimum <= parsed <= maximum:
        raise SmokeConfigurationError(f"{name} is outside its permitted integer range")
    return parsed


def load_configuration(env: Mapping[str, str] | None = None) -> MainnetSmokeConfiguration:
    """Parse explicit, out-of-band trust pins; never infer a deployment from RPC."""
    values = os.environ if env is None else env

    helios = HeliosMainnetConfig(
        binary_path=_required(values, "PSP_HELIOS_BINARY"),
        binary_sha256=_hex_bytes(values, "PSP_HELIOS_BINARY_SHA256", 32),
        execution_rpc_url=_required(values, "PSP_HELIOS_EXECUTION_RPC_URL"),
        consensus_rpc_url=_required(values, "PSP_HELIOS_CONSENSUS_RPC_URL"),
        weak_subjectivity_checkpoint=_hex_bytes(
            values, "PSP_HELIOS_WEAK_SUBJECTIVITY_CHECKPOINT", 32
        ),
        rpc_port=_uint(values, "PSP_HELIOS_RPC_PORT", default=18545, minimum=1024, maximum=65535),
    )

    asset_address_value = values.get("PSP_ASSET_ADDRESS")
    asset_fingerprint_value = values.get("PSP_ASSET_RUNTIME_FINGERPRINT")
    if (asset_address_value is None) != (asset_fingerprint_value is None):
        raise SmokeConfigurationError(
            "PSP_ASSET_ADDRESS and PSP_ASSET_RUNTIME_FINGERPRINT must be set together"
        )
    asset_address = (
        None if asset_address_value is None
        else _hex_bytes(values, "PSP_ASSET_ADDRESS", 20)
    )
    asset_fingerprint = (
        None if asset_fingerprint_value is None
        else _hex_bytes(values, "PSP_ASSET_RUNTIME_FINGERPRINT", 48)
    )

    checkpoint_number = _uint(values, "PSP_MAINNET_EXECUTION_CHECKPOINT_NUMBER")
    checkpoint_hash = _hex_bytes(values, "PSP_MAINNET_EXECUTION_CHECKPOINT_HASH", 32)
    namespace = EvmNamespaceConfig(
        chain_id=ETHEREUM_MAINNET_CHAIN_ID,
        genesis_hash=ETHEREUM_MAINNET_GENESIS_HASH,
        checkpoint_block_number=checkpoint_number,
        checkpoint_hash=checkpoint_hash,
        protocol_address=_hex_bytes(values, "PSP_PROTOCOL_ADDRESS", 20),
        expected_protocol_code_fingerprint=_hex_bytes(
            values, "PSP_PROTOCOL_RUNTIME_FINGERPRINT", 48
        ),
        asset_address=asset_address,
        expected_asset_code_fingerprint=asset_fingerprint,
        deployment_epoch=_uint(values, "PSP_DEPLOYMENT_EPOCH", default=0),
        asset_epoch=_uint(values, "PSP_ASSET_EPOCH", default=0),
        code_block_tag="finalized",
    )

    database_value = _required(values, "PSP_FINALITY_JOURNAL_PATH")
    database_path = Path(database_value).expanduser()
    if str(database_path) == ":memory:" or not database_path.is_absolute():
        raise SmokeConfigurationError(
            "PSP_FINALITY_JOURNAL_PATH must be an absolute file-backed SQLite path"
        )
    max_headers = _uint(
        values, "PSP_MAX_HEADERS_PER_SYNC", default=4096, minimum=1, maximum=100_000
    )

    # Explicit checks guard against accidental profile drift if constants change.
    if namespace.chain_id != 1 or namespace.genesis_hash != ETHEREUM_MAINNET_GENESIS_HASH:
        raise SmokeConfigurationError("this smoke runner only accepts the pinned Ethereum Mainnet profile")
    return MainnetSmokeConfiguration(helios, namespace, database_path, max_headers)


def run_live_smoke(config: MainnetSmokeConfiguration) -> dict[str, object]:
    """Start pinned Helios, derive V3 from real Mainnet observations and persist finality."""
    if not isinstance(config, MainnetSmokeConfiguration):
        raise TypeError("config must be a MainnetSmokeConfiguration")

    client = HeliosMainnetLightClient(config.helios)
    try:
        client.start()
        binding = EvmNamespaceAdapter(config.namespace, client).resolve()
        if not isinstance(binding.namespace_id, NamespaceIdV3):
            raise RuntimeError("namespace adapter did not return typed NamespaceIdV3")

        journal = HeliosAuthenticatedHeaderJournal(
            config.finality_database,
            namespace_config=config.namespace,
            namespace_id=binding.namespace_id,
            light_client=client,
            max_headers_per_sync=config.max_headers_per_sync,
        )
        finalized = journal.advance_to_finalized()
        if not journal.contains_finalized_header(finalized.number, finalized.block_hash):
            raise RuntimeError("the reported finalized head is absent from its durable authenticated journal")
        if finalized.number < config.namespace.checkpoint_block_number:
            raise RuntimeError("finalized head is below the configured execution checkpoint")

        return {
            "smoke_result": "PASS",
            "chain_id": ETHEREUM_MAINNET_CHAIN_ID,
            "genesis_hash": ETHEREUM_MAINNET_GENESIS_HASH.hex(),
            "namespace_version": 3,
            "namespace_id": binding.namespace_id.data.hex(),
            "namespace_mapping": "PASS_DIRECT_HASH_OF_CANONICAL_RAW_DESCRIPTORS",
            "runtime_code_fingerprint_check": "PASS",
            "consensus_profile": "PINNED_HELIOS_0.12.0_ETHEREUM_MAINNET",
            "execution_checkpoint_number": config.namespace.checkpoint_block_number,
            "execution_checkpoint_hash": config.namespace.checkpoint_hash.hex(),
            "finalized_number": finalized.number,
            "finalized_hash": finalized.block_hash.hex(),
            "durable_authenticated_ancestry": "PASS",
            "proof_binding": "NO-GO_NOT_INSTANTIATED_BY_THIS_SMOKE",
            "independent_security_review": "NOT_PERFORMED",
            "external_cryptographic_audit": "NOT_PERFORMED",
            "composite_production_gate": "NO-GO",
        }
    finally:
        client.stop()


def main() -> int:
    try:
        report = run_live_smoke(load_configuration())
    except Exception as exc:
        # Do not dump environment variables, RPC request bodies, or full URLs.
        print(json.dumps({
            "smoke_result": "FAIL",
            "failure_type": type(exc).__name__,
            "failure": str(exc),
            "composite_production_gate": "NO-GO",
            "independent_security_review": "NOT_PERFORMED",
            "external_cryptographic_audit": "NOT_PERFORMED",
        }, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
