"""Versioned direct-hash namespace identifiers with no intermediate digest.

Namespace V2 remains frozen in namespace.py. Namespace V3 hashes the three
canonical, domain-separated identity descriptors directly into one 48-byte
SHAKE256 digest. It deliberately does not first compress individual descriptors
to 32-byte component hashes.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

NAMESPACE_V3_ID_BYTES: Final = 48
NAMESPACE_V3_VERSION: Final = b"\x03"
NAMESPACE_V3_COMPONENT_MAX_BYTES: Final = 4096
NAMESPACE_V3_LENGTH_BYTES: Final = 4
DOMAIN_NAMESPACE_V3: Final = b"0PSP-NAMESPACE-v3-SHAKE256"


@dataclass(frozen=True, slots=True)
class NamespaceIdV3:
    """Typed 48-byte Namespace V3 identifier.

    This is a distinct Python type from NamespaceId (V2) so callers cannot
    accidentally mix the two by relying on dataclass equality or type hints.
    Protocol/serialization boundaries must explicitly use the data property.
    """

    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) != NAMESPACE_V3_ID_BYTES:
            raise ValueError(f"namespace_id_v3 must be exactly {NAMESPACE_V3_ID_BYTES} bytes")

    def __bytes__(self) -> bytes:
        return self.data

    def __repr__(self) -> str:
        return f"NamespaceIdV3({self.data.hex()[:16]}…)"


def _validate_component(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if not 1 <= len(value) <= NAMESPACE_V3_COMPONENT_MAX_BYTES:
        raise ValueError(
            f"{name} length must be in [1, {NAMESPACE_V3_COMPONENT_MAX_BYTES}] bytes"
        )


def namespace_v3_preimage(
    ledger_identity: bytes,
    deployment_identity: bytes,
    asset_identity: bytes,
) -> bytes:
    """Build the exact canonical V3 preimage for independent vectors/audits.

    Component order is fixed. Each descriptor length is a 32-bit little-endian
    unsigned integer immediately followed by exactly that many bytes. All
    descriptor contents are retained; no intermediate component hash is used.
    """
    components = (
        ("ledger_identity", ledger_identity),
        ("deployment_identity", deployment_identity),
        ("asset_identity", asset_identity),
    )
    encoded = bytearray(DOMAIN_NAMESPACE_V3 + NAMESPACE_V3_VERSION)
    for name, value in components:
        _validate_component(value, name)
        encoded.extend(len(value).to_bytes(NAMESPACE_V3_LENGTH_BYTES, "little"))
        encoded.extend(value)
    return bytes(encoded)


def derive_namespace_id_v3(
    ledger_identity: bytes,
    deployment_identity: bytes,
    asset_identity: bytes,
) -> NamespaceIdV3:
    """Derive a 48-byte namespace ID from canonical identity descriptors.

    Security claim: with SHAKE256 modeled as an ideal quantum-accessible random
    oracle, the 384-bit final digest has a generic BHT-style collision-query
    scale of about 2**128. This is a computational bound, not injectivity:
    because the descriptor domain is much larger than 384 bits, collisions
    exist mathematically. Callers must canonicalize descriptors before calling.
    """
    preimage = namespace_v3_preimage(
        ledger_identity,
        deployment_identity,
        asset_identity,
    )
    return NamespaceIdV3(hashlib.shake_256(preimage).digest(NAMESPACE_V3_ID_BYTES))
