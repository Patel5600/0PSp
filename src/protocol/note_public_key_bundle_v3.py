"""Canonical V3 note public-key bundle for identity/nullifier binding.

The bundle is supplied as the public_key byte field to the frozen CommitV2
primitive. This module does not change CommitV2's formula.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.primitives.nullifier_v3 import NullifierKeyCommitmentV3

NOTE_PUBLIC_KEY_BUNDLE_V3_VERSION = b"\x03"
DOMAIN_NOTE_PUBLIC_KEY_BUNDLE_V3 = b"0PSP-NOTE-PK-BUNDLE-v3"


@dataclass(frozen=True, slots=True)
class NotePublicKeyBundleV3:
    """Canonical bundle binding the authorization key to a hidden NF-key commitment."""

    auth_scheme_id: bytes
    auth_public_key: bytes
    nullifier_key_commitment: NullifierKeyCommitmentV3

    def __post_init__(self) -> None:
        if not isinstance(self.auth_scheme_id, bytes) or not 1 <= len(self.auth_scheme_id) < (1 << 16):
            raise ValueError("auth_scheme_id must be 1..65535 bytes")
        if not isinstance(self.auth_public_key, bytes) or not 1 <= len(self.auth_public_key) < (1 << 32):
            raise ValueError("auth_public_key must be 1..2^32-1 bytes")
        if not isinstance(self.nullifier_key_commitment, NullifierKeyCommitmentV3):
            raise TypeError("nullifier_key_commitment must be a NullifierKeyCommitmentV3")

    def encode(self) -> bytes:
        """Encode all fields canonically; no alternate/trailing encodings are valid."""
        commitment = self.nullifier_key_commitment.value
        return b"".join((
            DOMAIN_NOTE_PUBLIC_KEY_BUNDLE_V3,
            NOTE_PUBLIC_KEY_BUNDLE_V3_VERSION,
            len(self.auth_scheme_id).to_bytes(2, "little"),
            self.auth_scheme_id,
            len(self.auth_public_key).to_bytes(4, "little"),
            self.auth_public_key,
            len(commitment).to_bytes(2, "little"),
            commitment,
        ))


def decode_note_public_key_bundle_v3(encoded: bytes) -> NotePublicKeyBundleV3:
    """Decode one canonical bundle and reject malformed, truncated, or trailing data."""
    if not isinstance(encoded, bytes):
        raise TypeError("encoded bundle must be bytes")
    prefix = DOMAIN_NOTE_PUBLIC_KEY_BUNDLE_V3 + NOTE_PUBLIC_KEY_BUNDLE_V3_VERSION
    if not encoded.startswith(prefix):
        raise ValueError("invalid V3 note-public-key bundle domain/version")
    offset = len(prefix)

    def take_length(width: int, field: str) -> int:
        nonlocal offset
        if len(encoded) - offset < width:
            raise ValueError(f"truncated {field} length")
        length = int.from_bytes(encoded[offset:offset + width], "little")
        offset += width
        return length

    def take(length: int, field: str) -> bytes:
        nonlocal offset
        if length <= 0 or len(encoded) - offset < length:
            raise ValueError(f"invalid or truncated {field}")
        value = encoded[offset:offset + length]
        offset += length
        return value

    scheme_id = take(take_length(2, "auth_scheme_id"), "auth_scheme_id")
    auth_pk = take(take_length(4, "auth_public_key"), "auth_public_key")
    commitment_len = take_length(2, "nullifier_key_commitment")
    if commitment_len != 48:
        raise ValueError("nullifier_key_commitment must be exactly 48 bytes")
    commitment = take(commitment_len, "nullifier_key_commitment")
    if offset != len(encoded):
        raise ValueError("trailing bytes in V3 note-public-key bundle")
    bundle = NotePublicKeyBundleV3(
        auth_scheme_id=scheme_id,
        auth_public_key=auth_pk,
        nullifier_key_commitment=NullifierKeyCommitmentV3(commitment),
    )
    if bundle.encode() != encoded:
        raise ValueError("non-canonical V3 note-public-key bundle")
    return bundle
