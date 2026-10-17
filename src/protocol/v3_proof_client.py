"""Client-side OpenVM proof request and local verification path."""
from __future__ import annotations

import http.client
import base64
import json
import ssl
import time
import uuid
from urllib.parse import urlsplit

from src.protocol.openvm_v3_candidate_verifier import (
    OpenVMV3CandidateProofVerifier,
    v3_spend_public_digest_candidate,
)
from src.protocol.transaction_v3_candidate import TxFieldsV3Candidate
from src.protocol.v3_proof_worker import (
    MAX_PROOF_BYTES,
    PRODUCTION1_CIRCUIT_ID,
)


class V3ProofClientError(ValueError):
    """The worker response or local proof verification failed."""


def _request_and_verify_spend_proof(
    *,
    worker_url: str,
    api_key: bytes,
    ca_certificate: str,
    witness: bytes | bytearray,
    statement: TxFieldsV3Candidate,
    verifier: OpenVMV3CandidateProofVerifier,
    timeout_seconds: float = 1200,
) -> tuple[bytes, bytes, float, float, int]:
    """Prove remotely, then bind and verify the public statement locally.

    The witness remains in the caller's process and is sent only through a
    certificate-validated HTTPS connection. Phase A still trusts the worker
    operator with plaintext while the OpenVM guest executes.
    """
    if not isinstance(witness, bytearray) or not 1 <= len(witness) <= 2_000_000:
        raise V3ProofClientError("witness length is outside configured bounds")
    if not isinstance(api_key, bytes) or len(api_key) < 32:
        raise V3ProofClientError("worker API key must contain at least 32 bytes")
    if not api_key.isascii() or any(byte < 0x21 or byte > 0x7E for byte in api_key):
        raise V3ProofClientError("worker API key must use visible ASCII bytes")
    parsed = urlsplit(worker_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in ("", "/")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise V3ProofClientError("worker URL must be an HTTPS origin")
    port = parsed.port or 443
    context = ssl.create_default_context(cafile=ca_certificate)
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        port,
        context=context,
        timeout=timeout_seconds,
    )
    try:
        connection.request(
            "POST",
            "/v1/prove",
            body=json.dumps({
                "circuit_id": PRODUCTION1_CIRCUIT_ID,
                "public_inputs": v3_spend_public_digest_candidate(statement).hex(),
                "witness_blob": base64.b64encode(witness).decode("ascii"),
                "client_req_id": str(uuid.uuid4()),
            }, separators=(",", ":")).encode("ascii"),
            headers={
                "Authorization": "Bearer " + api_key.decode("ascii"),
                "Content-Type": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            response.read(1024)
            raise V3ProofClientError(f"proof worker rejected request with HTTP {response.status}")
        content_length = response.getheader("Content-Length")
        if content_length is None or not content_length.isascii() or not content_length.isdecimal():
            raise V3ProofClientError("proof worker omitted a valid response length")
        response_length = int(content_length)
        if response_length > MAX_PROOF_BYTES * 2:
            raise V3ProofClientError("proof worker response exceeds configured bounds")
        envelope = response.read(response_length + 1)
        if len(envelope) != response_length:
            raise V3ProofClientError("proof worker response was truncated or oversized")
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise V3ProofClientError("proof worker connection failed") from exc
    finally:
        connection.close()

    try:
        result = json.loads(envelope)
        if not isinstance(result, dict) or set(result) != {
            "proof", "public_inputs", "prove_ms", "peak_rss_kib"
        }:
            raise ValueError("invalid response fields")
        public_inputs = bytes.fromhex(result["public_inputs"])
        proof = base64.b64decode(result["proof"], validate=True)
        if not 1 <= len(proof) <= MAX_PROOF_BYTES:
            raise ValueError("invalid proof length")
        if (isinstance(result["prove_ms"], bool)
                or not isinstance(result["prove_ms"], (int, float))
                or result["prove_ms"] < 0):
            raise ValueError("invalid prove time")
        if (isinstance(result["peak_rss_kib"], bool)
                or not isinstance(result["peak_rss_kib"], int)
                or result["peak_rss_kib"] <= 0):
            raise ValueError("invalid peak RSS")
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise V3ProofClientError("proof worker returned a malformed proof envelope") from exc
    expected_public_inputs = v3_spend_public_digest_candidate(statement)
    if public_inputs != expected_public_inputs:
        raise V3ProofClientError("proof public inputs do not bind the requested spend statement")
    try:
        verify_started = time.perf_counter()
        verified = verifier(statement, proof)
        verify_ms = (time.perf_counter() - verify_started) * 1000
    except Exception as exc:
        raise V3ProofClientError("local OpenVM proof verification failed") from exc
    if verified is not True:
        raise V3ProofClientError("local OpenVM proof verification rejected the proof")
    return public_inputs, proof, float(result["prove_ms"]), verify_ms, result["peak_rss_kib"]


def request_and_verify_spend_proof(
    *,
    worker_url: str,
    api_key: bytes,
    ca_certificate: str,
    witness: bytearray,
    statement: TxFieldsV3Candidate,
    verifier: OpenVMV3CandidateProofVerifier,
    timeout_seconds: float = 1200,
) -> tuple[bytes, bytes, float, float, int]:
    """Request a proof and wipe the caller-owned mutable witness on every exit."""
    if not isinstance(witness, bytearray):
        raise V3ProofClientError("witness must be a mutable bytearray so it can be wiped")
    try:
        return _request_and_verify_spend_proof(
            worker_url=worker_url,
            api_key=api_key,
            ca_certificate=ca_certificate,
            witness=witness,
            statement=statement,
            verifier=verifier,
            timeout_seconds=timeout_seconds,
        )
    finally:
        witness[:] = b"\x00" * len(witness)
