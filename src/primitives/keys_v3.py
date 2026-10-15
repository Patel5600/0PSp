"""0PSP 2-Tier Key Hierarchy and Spend Authorization Primitives (V3).

Implements a 3-tier key separation architecture:
  1. Master Spend Secret (sk_spend in {0,1}^384): held strictly in Tier-1 secure hardware.
  2. Nullifier Deriving Key (nk in {0,1}^384): derived via SHAKE256-384, enables incoming scanning without spend rights.
  3. Spend Authorizing Key (ak in {0,1}^384): derived via SHAKE256-384, delegates proving rights without exposing sk_spend.
  4. Owner Commitment / Shielded Address (pk_owner in {0,1}^384): commits (ak, nk) into the coin commitment.
  5. Transaction-Bound Spend Authorization Token (tau_auth): one-time HMAC-SHA3-384 spend witness.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Final


SK_SPEND_BYTES: Final = 48
NK_BYTES: Final = 48
AK_BYTES: Final = 48
PK_OWNER_BYTES: Final = 48
AUTH_TOKEN_BYTES: Final = 48

DOM_AK_V3: Final = b"0PSP_AK_DERIVE_V3"
DOM_NK_V3: Final = b"0PSP_NK_DERIVE_V3"
DOM_OWNER_V3: Final = b"0PSP_OWNER_V3"
DOM_SPEND_AUTH_V3: Final = b"0PSP_SPEND_AUTH_V3"


@dataclass(frozen=True, slots=True)
class V3KeyHierarchy:
    """Immutable 3-tier key hierarchy for a 0PSP shielded address."""
    sk_spend: bytes   # Master spend key (Tier-1 private)
    ak: bytes         # Spend authorization key
    nk: bytes         # Nullifier deriving key (scanning key)
    pk_owner: bytes   # Owner public commitment / address component

    def __post_init__(self) -> None:
        if len(self.sk_spend) != SK_SPEND_BYTES:
            raise ValueError(f"sk_spend must be {SK_SPEND_BYTES} bytes, got {len(self.sk_spend)}")
        if len(self.ak) != AK_BYTES:
            raise ValueError(f"ak must be {AK_BYTES} bytes, got {len(self.ak)}")
        if len(self.nk) != NK_BYTES:
            raise ValueError(f"nk must be {NK_BYTES} bytes, got {len(self.nk)}")
        if len(self.pk_owner) != PK_OWNER_BYTES:
            raise ValueError(f"pk_owner must be {PK_OWNER_BYTES} bytes, got {len(self.pk_owner)}")

    def __repr__(self) -> str:
        return f"V3KeyHierarchy(sk_spend=<redacted>, ak={self.ak.hex()[:12]}..., nk={self.nk.hex()[:12]}..., pk_owner={self.pk_owner.hex()[:12]}...)"


def derive_keys_v3(sk_spend: bytes) -> V3KeyHierarchy:
    """Derive ak, nk, and pk_owner from master spend secret sk_spend.

    Derivations:
      ak = SHAKE256-384("0PSP_AK_DERIVE_V3" || sk_spend)
      nk = SHAKE256-384("0PSP_NK_DERIVE_V3" || sk_spend)
      pk_owner = SHAKE256-384("0PSP_OWNER_V3" || ak || nk)
    """
    if not isinstance(sk_spend, bytes) or len(sk_spend) != SK_SPEND_BYTES:
        raise ValueError(f"sk_spend must be exactly {SK_SPEND_BYTES} bytes")

    shake_ak = hashlib.shake_256(DOM_AK_V3 + sk_spend)
    ak = shake_ak.digest(AK_BYTES)

    shake_nk = hashlib.shake_256(DOM_NK_V3 + sk_spend)
    nk = shake_nk.digest(NK_BYTES)

    shake_owner = hashlib.shake_256(DOM_OWNER_V3 + ak + nk)
    pk_owner = shake_owner.digest(PK_OWNER_BYTES)

    return V3KeyHierarchy(
        sk_spend=sk_spend,
        ak=ak,
        nk=nk,
        pk_owner=pk_owner,
    )


def generate_master_spend_key_v3() -> bytes:
    """Generate a fresh 384-bit master spend key from OS CSPRNG."""
    return secrets.token_bytes(SK_SPEND_BYTES)


def compute_spend_auth_token_v3(
    sk_spend: bytes,
    tx_digest: bytes,
    commitment: bytes,
) -> bytes:
    """Compute one-time transaction-bound spend authorization token.

    tau_auth = HMAC-SHA3-384(sk_spend, "0PSP_SPEND_AUTH_V3" || tx_digest || commitment)
    """
    if not isinstance(sk_spend, bytes) or len(sk_spend) != SK_SPEND_BYTES:
        raise ValueError(f"sk_spend must be {SK_SPEND_BYTES} bytes")
    if not isinstance(tx_digest, bytes) or len(tx_digest) not in (48, 64):
        raise ValueError(f"tx_digest must be 48 or 64 bytes, got {len(tx_digest)}")
    if not isinstance(commitment, bytes) or len(commitment) != 48:
        raise ValueError(f"commitment must be 48 bytes, got {len(commitment)}")

    data = DOM_SPEND_AUTH_V3 + tx_digest + commitment
    return hmac.new(sk_spend, data, hashlib.sha3_384).digest()


def verify_spend_auth_token_v3(
    sk_spend: bytes,
    tx_digest: bytes,
    commitment: bytes,
    auth_token: bytes,
) -> bool:
    """Verify spend authorization token in constant time."""
    if not isinstance(auth_token, bytes) or len(auth_token) != AUTH_TOKEN_BYTES:
        return False
    expected = compute_spend_auth_token_v3(sk_spend, tx_digest, commitment)
    return hmac.compare_digest(expected, auth_token)
