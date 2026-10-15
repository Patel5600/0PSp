"""High-performance Python ctypes adapter for 0PSP Native C11 Mobile Engine.

Binds directly to libpsp_native.so / libpsp_native.dll to provide constant-time,
zero-heap Tier 1 edge spend package generation and Merkle subtree verification
for consumer devices and mobile clients.
"""
from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PSP_CRYPTO_OK = 0

PSP_TIER1_COIN_ID_BYTES = 32
PSP_TIER1_RNF_BYTES = 36
PSP_TIER1_SALT_BYTES = 36
PSP_TIER1_KEY_BYTES = 48
PSP_TIER1_COMMITMENT_BYTES = 48
PSP_TIER1_NULLIFIER_BYTES = 48
PSP_TIER1_NAMESPACE_BYTES = 48
PSP_TIER1_ENTROPY_BYTES = 32
PSP_TIER1_DIGEST_BYTES = 64
PSP_TIER1_MAX_TX_FIELDS_BYTES = 4096


class _CTier1SpendPackage(ctypes.Structure):
    _fields_ = [
        ("input_commitment", ctypes.c_uint8 * PSP_TIER1_COMMITMENT_BYTES),
        ("input_nullifier", ctypes.c_uint8 * PSP_TIER1_NULLIFIER_BYTES),
        ("output_commitment", ctypes.c_uint8 * PSP_TIER1_COMMITMENT_BYTES),
        ("output_coin_id", ctypes.c_uint8 * PSP_TIER1_COIN_ID_BYTES),
        ("output_r_nf", ctypes.c_uint8 * PSP_TIER1_RNF_BYTES),
        ("output_rho_coin", ctypes.c_uint8 * PSP_TIER1_SALT_BYTES),
        ("tx_digest", ctypes.c_uint8 * PSP_TIER1_DIGEST_BYTES),
        ("encoded_tx_len", ctypes.c_size_t),
        ("encoded_tx", ctypes.c_uint8 * PSP_TIER1_MAX_TX_FIELDS_BYTES),
    ]


@dataclass(frozen=True, slots=True)
class NativeGeneratedNote:
    nk: bytes
    coin_id: bytes
    r_nf: bytes
    rho_coin: bytes
    bundle: bytes
    commitment: bytes


@dataclass(frozen=True, slots=True)
class NativeTier1SpendPackage:
    input_commitment: bytes
    input_nullifier: bytes
    output_commitment: bytes
    output_coin_id: bytes
    output_r_nf: bytes
    output_rho_coin: bytes
    tx_digest: bytes
    encoded_tx: bytes


def find_native_library() -> Path:
    """Locate the compiled libpsp_native shared library across platforms."""
    base_dir = Path(__file__).resolve().parent.parent.parent / "native" / "build"
    candidates = [
        base_dir / "libpsp_native.so",
        base_dir / "libpsp_native.dll",
        base_dir / "libpsp_native.dylib",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"libpsp_native shared library not found in {base_dir}. "
        "Run 'make' in the native/ directory first."
    )


class NativeMobileEngine:
    """Thread-safe interface to the C11 native 0PSP mobile engine."""

    def __init__(self, library_path: Optional[str | Path] = None) -> None:
        path = Path(library_path) if library_path else find_native_library()
        self._lib = ctypes.CDLL(str(path))
        self._setup_bindings()

    def _setup_bindings(self) -> None:
        u8_p = ctypes.POINTER(ctypes.c_uint8)
        size_t = ctypes.c_size_t
        u16 = ctypes.c_uint16
        u64 = ctypes.c_uint64

        # psp_output_identity_v3
        self._lib.psp_output_identity_v3.argtypes = [
            u8_p, size_t, u8_p, u8_p, u8_p, u8_p, u8_p,
            u8_p, size_t, u8_p, size_t, u8_p, u16, u8_p, u8_p,
        ]
        self._lib.psp_output_identity_v3.restype = ctypes.c_int

        # psp_note_generate_v3
        self._lib.psp_note_generate_v3.argtypes = [
            u8_p, size_t, u8_p, u64, u8_p, size_t, u8_p, size_t,
            u8_p, u8_p, u8_p, u8_p, u8_p, ctypes.POINTER(size_t), size_t, u8_p,
        ]
        self._lib.psp_note_generate_v3.restype = ctypes.c_int

        # psp_tier1_create_spend_package
        self._lib.psp_tier1_create_spend_package.argtypes = [
            u8_p, size_t, u8_p, u8_p, size_t, u64, u8_p, u8_p, u8_p, u8_p,
            u8_p, size_t, u64, u64, u8_p, u8_p, u8_p, u8_p,
            ctypes.POINTER(_CTier1SpendPackage),
        ]
        self._lib.psp_tier1_create_spend_package.restype = ctypes.c_int

        # psp_tier1_verify_spend_package
        self._lib.psp_tier1_verify_spend_package.argtypes = [
            ctypes.POINTER(_CTier1SpendPackage), u8_p, u8_p,
        ]
        self._lib.psp_tier1_verify_spend_package.restype = ctypes.c_int

        # psp_merkle_verify_path
        self._lib.psp_merkle_verify_path.argtypes = [
            u8_p, u64, u8_p, u8_p, size_t, u8_p,
        ]
        self._lib.psp_merkle_verify_path.restype = ctypes.c_int

        # psp_derive_keys_v3: (sk_spend[48], ak_out[48], nk_out[48], pk_owner_out[48])
        self._lib.psp_derive_keys_v3.argtypes = [
            u8_p, u8_p, u8_p, u8_p,
        ]
        self._lib.psp_derive_keys_v3.restype = ctypes.c_int

        # psp_compute_spend_auth_token_v3: (sk_spend[48], tx_digest[64], commitment[48], auth_token_out[48])
        self._lib.psp_compute_spend_auth_token_v3.argtypes = [
            u8_p, u8_p, u8_p, u8_p,
        ]
        self._lib.psp_compute_spend_auth_token_v3.restype = ctypes.c_int

        # psp_verify_spend_auth_token_v3: (sk_spend[48], tx_digest[64], commitment[48], auth_token[48])
        self._lib.psp_verify_spend_auth_token_v3.argtypes = [
            u8_p, u8_p, u8_p, u8_p,
        ]
        self._lib.psp_verify_spend_auth_token_v3.restype = ctypes.c_int

    def derive_output_identity_v3(
        self,
        *,
        params_id: bytes,
        namespace_id: bytes,
        parent_nullifier: bytes,
        parent_commitment: bytes,
        parent_coin_id: bytes,
        parent_r_nf: bytes,
        parent_bundle: bytes,
        recipient_bundle: bytes,
        transaction_entropy: bytes,
        output_index: int = 0,
    ) -> tuple[bytes, bytes]:
        """Derive (coin_id, r_nf) using native C11 constant-time engine."""
        coin_id_buf = (ctypes.c_uint8 * PSP_TIER1_COIN_ID_BYTES)()
        r_nf_buf = (ctypes.c_uint8 * PSP_TIER1_RNF_BYTES)()

        st = self._lib.psp_output_identity_v3(
            (ctypes.c_uint8 * len(params_id)).from_buffer_copy(params_id),
            len(params_id),
            (ctypes.c_uint8 * len(namespace_id)).from_buffer_copy(namespace_id),
            (ctypes.c_uint8 * len(parent_nullifier)).from_buffer_copy(parent_nullifier),
            (ctypes.c_uint8 * len(parent_commitment)).from_buffer_copy(parent_commitment),
            (ctypes.c_uint8 * len(parent_coin_id)).from_buffer_copy(parent_coin_id),
            (ctypes.c_uint8 * len(parent_r_nf)).from_buffer_copy(parent_r_nf),
            (ctypes.c_uint8 * len(parent_bundle)).from_buffer_copy(parent_bundle),
            len(parent_bundle),
            (ctypes.c_uint8 * len(recipient_bundle)).from_buffer_copy(recipient_bundle),
            len(recipient_bundle),
            (ctypes.c_uint8 * len(transaction_entropy)).from_buffer_copy(transaction_entropy),
            output_index,
            coin_id_buf,
            r_nf_buf,
        )
        if st != PSP_CRYPTO_OK:
            raise ValueError(f"native psp_output_identity_v3 failed with error {st}")
        return bytes(coin_id_buf), bytes(r_nf_buf)

    def generate_note_v3(
        self,
        *,
        params_id: bytes,
        namespace_id: bytes,
        value: int,
        auth_scheme_id: bytes,
        auth_public_key: bytes,
    ) -> NativeGeneratedNote:
        """Generate a fresh note locally using OS CSPRNG in native C11."""
        nk = (ctypes.c_uint8 * PSP_TIER1_KEY_BYTES)()
        coin_id = (ctypes.c_uint8 * PSP_TIER1_COIN_ID_BYTES)()
        r_nf = (ctypes.c_uint8 * PSP_TIER1_RNF_BYTES)()
        rho_coin = (ctypes.c_uint8 * PSP_TIER1_SALT_BYTES)()
        bundle = (ctypes.c_uint8 * 512)()
        bundle_len = ctypes.c_size_t(0)
        commitment = (ctypes.c_uint8 * PSP_TIER1_COMMITMENT_BYTES)()

        st = self._lib.psp_note_generate_v3(
            (ctypes.c_uint8 * len(params_id)).from_buffer_copy(params_id),
            len(params_id),
            (ctypes.c_uint8 * len(namespace_id)).from_buffer_copy(namespace_id),
            value,
            (ctypes.c_uint8 * len(auth_scheme_id)).from_buffer_copy(auth_scheme_id),
            len(auth_scheme_id),
            (ctypes.c_uint8 * len(auth_public_key)).from_buffer_copy(auth_public_key),
            len(auth_public_key),
            nk,
            coin_id,
            r_nf,
            rho_coin,
            bundle,
            ctypes.byref(bundle_len),
            len(bundle),
            commitment,
        )
        if st != PSP_CRYPTO_OK:
            raise RuntimeError(f"native psp_note_generate_v3 failed with error {st}")

        return NativeGeneratedNote(
            nk=bytes(nk),
            coin_id=bytes(coin_id),
            r_nf=bytes(r_nf),
            rho_coin=bytes(rho_coin),
            bundle=bytes(bundle)[:bundle_len.value],
            commitment=bytes(commitment),
        )

    def create_tier1_spend_package(
        self,
        *,
        params_id: bytes,
        namespace_id: bytes,
        input_bundle: bytes,
        input_value: int,
        input_coin_id: bytes,
        input_r_nf: bytes,
        input_rho_coin: bytes,
        input_nk: bytes,
        recipient_bundle: bytes,
        output_value: int,
        fee: int,
        output_entropy: bytes,
        commitment_root: bytes,
        state_head: bytes,
        state_context_digest: bytes,
    ) -> NativeTier1SpendPackage:
        """Execute Tier 1 mobile spend package creation in native constant-time C11."""
        pkg = _CTier1SpendPackage()

        st = self._lib.psp_tier1_create_spend_package(
            (ctypes.c_uint8 * len(params_id)).from_buffer_copy(params_id),
            len(params_id),
            (ctypes.c_uint8 * len(namespace_id)).from_buffer_copy(namespace_id),
            (ctypes.c_uint8 * len(input_bundle)).from_buffer_copy(input_bundle),
            len(input_bundle),
            input_value,
            (ctypes.c_uint8 * len(input_coin_id)).from_buffer_copy(input_coin_id),
            (ctypes.c_uint8 * len(input_r_nf)).from_buffer_copy(input_r_nf),
            (ctypes.c_uint8 * len(input_rho_coin)).from_buffer_copy(input_rho_coin),
            (ctypes.c_uint8 * len(input_nk)).from_buffer_copy(input_nk),
            (ctypes.c_uint8 * len(recipient_bundle)).from_buffer_copy(recipient_bundle),
            len(recipient_bundle),
            output_value,
            fee,
            (ctypes.c_uint8 * len(output_entropy)).from_buffer_copy(output_entropy),
            (ctypes.c_uint8 * len(commitment_root)).from_buffer_copy(commitment_root),
            (ctypes.c_uint8 * len(state_head)).from_buffer_copy(state_head),
            (ctypes.c_uint8 * len(state_context_digest)).from_buffer_copy(state_context_digest),
            ctypes.byref(pkg),
        )
        if st != PSP_CRYPTO_OK:
            raise ValueError(f"native psp_tier1_create_spend_package failed with code {st}")

        return NativeTier1SpendPackage(
            input_commitment=bytes(pkg.input_commitment),
            input_nullifier=bytes(pkg.input_nullifier),
            output_commitment=bytes(pkg.output_commitment),
            output_coin_id=bytes(pkg.output_coin_id),
            output_r_nf=bytes(pkg.output_r_nf),
            output_rho_coin=bytes(pkg.output_rho_coin),
            tx_digest=bytes(pkg.tx_digest),
            encoded_tx=bytes(pkg.encoded_tx)[:pkg.encoded_tx_len],
        )

    def verify_merkle_path(
        self,
        *,
        namespace_id: bytes,
        leaf_index: int,
        commitment: bytes,
        siblings: list[bytes],
        expected_root: bytes,
    ) -> bool:
        """Verify Merkle inclusion path on-device in constant time."""
        depth = len(siblings)
        siblings_flat = b"".join(siblings)
        st = self._lib.psp_merkle_verify_path(
            (ctypes.c_uint8 * len(namespace_id)).from_buffer_copy(namespace_id),
            leaf_index,
            (ctypes.c_uint8 * len(commitment)).from_buffer_copy(commitment),
            (ctypes.c_uint8 * len(siblings_flat)).from_buffer_copy(siblings_flat),
            depth,
            (ctypes.c_uint8 * len(expected_root)).from_buffer_copy(expected_root),
        )
        return st == PSP_CRYPTO_OK

    def derive_keys_v3(self, sk_spend: bytes) -> tuple[bytes, bytes, bytes]:
        """Derive (ak, nk, pk_owner) from sk_spend using native C11 constant-time engine."""
        if len(sk_spend) != 48:
            raise ValueError(f"sk_spend must be 48 bytes, got {len(sk_spend)}")
        ak_buf = (ctypes.c_uint8 * 48)()
        nk_buf = (ctypes.c_uint8 * 48)()
        pk_owner_buf = (ctypes.c_uint8 * 48)()
        st = self._lib.psp_derive_keys_v3(
            (ctypes.c_uint8 * 48).from_buffer_copy(sk_spend),
            ak_buf,
            nk_buf,
            pk_owner_buf,
        )
        if st != PSP_CRYPTO_OK:
            raise ValueError(f"psp_derive_keys_v3 failed with code {st}")
        return bytes(ak_buf), bytes(nk_buf), bytes(pk_owner_buf)

    def compute_spend_auth_token_v3(
        self,
        *,
        sk_spend: bytes,
        tx_digest: bytes,
        commitment: bytes,
    ) -> bytes:
        """Compute 48-byte spend authorization token tau_auth."""
        if len(sk_spend) != 48:
            raise ValueError(f"sk_spend must be 48 bytes, got {len(sk_spend)}")
        if len(tx_digest) != 64:
            raise ValueError(f"tx_digest must be 64 bytes, got {len(tx_digest)}")
        if len(commitment) != 48:
            raise ValueError(f"commitment must be 48 bytes, got {len(commitment)}")
        token_buf = (ctypes.c_uint8 * 48)()
        st = self._lib.psp_compute_spend_auth_token_v3(
            (ctypes.c_uint8 * 48).from_buffer_copy(sk_spend),
            (ctypes.c_uint8 * 64).from_buffer_copy(tx_digest),
            (ctypes.c_uint8 * 48).from_buffer_copy(commitment),
            token_buf,
        )
        if st != PSP_CRYPTO_OK:
            raise ValueError(f"psp_compute_spend_auth_token_v3 failed with code {st}")
        return bytes(token_buf)

    def verify_spend_auth_token_v3(
        self,
        *,
        sk_spend: bytes,
        tx_digest: bytes,
        commitment: bytes,
        token: bytes,
    ) -> bool:
        """Verify spend authorization token tau_auth in constant time."""
        if len(sk_spend) != 48 or len(tx_digest) != 64 or len(commitment) != 48 or len(token) != 48:
            return False
        st = self._lib.psp_verify_spend_auth_token_v3(
            (ctypes.c_uint8 * 48).from_buffer_copy(sk_spend),
            (ctypes.c_uint8 * 64).from_buffer_copy(tx_digest),
            (ctypes.c_uint8 * 48).from_buffer_copy(commitment),
            (ctypes.c_uint8 * 48).from_buffer_copy(token),
        )
        return st == 1
