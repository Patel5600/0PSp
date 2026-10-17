from __future__ import annotations

import base64
import json
from unittest.mock import patch

import pytest

from src.primitives.namespace_v3 import NamespaceIdV3
from src.primitives.note_types_v3 import CoinCommitmentV3
from src.primitives.nullifier_v3 import NullifierV3
from src.protocol.openvm_v3_candidate_verifier import v3_spend_public_digest_candidate
from src.protocol.transaction_v3_candidate import V3_NK_POSSESSION_POLICY_CANDIDATE, TxFieldsV3Candidate
from src.protocol.v3_proof_client import V3ProofClientError, request_and_verify_spend_proof

API_KEY = b"client-test-api-key-material-32-bytes!!"
PROOF = b"serialized proof"


def statement() -> TxFieldsV3Candidate:
    return TxFieldsV3Candidate(
        params_id=b"test-params",
        namespace_id=NamespaceIdV3(b"\x11" * 48),
        commitment_root=b"\x22" * 48,
        input_nullifier=NullifierV3(b"\x33" * 48),
        ledger_state_head=b"\x44" * 48,
        state_context_digest=b"\x55" * 64,
        authorization_policy_id=V3_NK_POSSESSION_POLICY_CANDIDATE,
        fee=0,
        output_entropy=b"\x66" * 32,
        output_commitments=(CoinCommitmentV3(b"\x77" * 48),),
    )


class FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def getheader(self, name: str) -> str | None:
        return str(len(self._body)) if name == "Content-Length" else None

    def read(self, length: int = -1) -> bytes:
        return self._body if length < 0 else self._body[:length]


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request_args = None
        self.closed = False

    def request(self, *args, **kwargs) -> None:
        if isinstance(kwargs.get("body"), bytearray):
            kwargs["body"] = bytes(kwargs["body"])
        self.request_args = (args, kwargs)

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def call_client(response_bytes: bytes, *, verifier_result: bool = True):
    current = statement()
    envelope = (
        json.dumps({
            "proof": base64.b64encode(PROOF).decode("ascii"),
            "public_inputs": v3_spend_public_digest_candidate(current).hex(),
            "prove_ms": 123.5,
            "peak_rss_kib": 4096,
        }, separators=(",", ":")).encode("ascii")
    )
    connection = FakeConnection(FakeResponse(response_bytes if response_bytes else envelope))
    verifier_calls = []
    witness = bytearray(b"client-memory-witness")

    with (
        patch("src.protocol.v3_proof_client.ssl.create_default_context", return_value=object()),
        patch("src.protocol.v3_proof_client.http.client.HTTPSConnection", return_value=connection),
    ):
        result = request_and_verify_spend_proof(
            worker_url="https://localhost:8443",
            api_key=API_KEY,
            ca_certificate="local-ca.pem",
            witness=witness,
            statement=current,
            verifier=lambda tx, proof: verifier_calls.append((tx, proof)) or verifier_result,
        )
    return result, connection, verifier_calls, current, envelope, witness


def test_client_sends_witness_over_https_and_locally_verifies_public_input() -> None:
    result, connection, verifier_calls, current, envelope, witness = call_client(b"")
    assert result[:3] == (v3_spend_public_digest_candidate(current), PROOF, 123.5)
    assert result[3] >= 0 and result[4] == 4096
    assert verifier_calls == [(current, PROOF)]
    args, kwargs = connection.request_args
    assert args[:2] == ("POST", "/v1/prove")
    request_body = json.loads(kwargs["body"])
    assert request_body["witness_blob"] == base64.b64encode(b"client-memory-witness").decode("ascii")
    assert request_body["circuit_id"] == "openvm-spend-v3-p1-depth63-1in1out-v1"
    assert request_body["public_inputs"] == v3_spend_public_digest_candidate(current).hex()
    assert witness == bytearray(len(b"client-memory-witness"))
    assert kwargs["headers"]["Content-Type"] == "application/json"
    assert connection.closed


def test_client_rejects_non_https_worker_url() -> None:
    with pytest.raises(V3ProofClientError, match="HTTPS origin"):
        request_and_verify_spend_proof(
            worker_url="http://localhost:8443",
            api_key=API_KEY,
            ca_certificate="local-ca.pem",
            witness=bytearray(b"witness"),
            statement=statement(),
            verifier=lambda *_args: True,
        )


def test_client_requires_mutable_witness_and_wipes_on_early_failure() -> None:
    with pytest.raises(V3ProofClientError, match="mutable bytearray"):
        request_and_verify_spend_proof(
            worker_url="https://localhost:8443",
            api_key=API_KEY,
            ca_certificate="local-ca.pem",
            witness=b"immutable witness",
            statement=statement(),
            verifier=lambda *_args: True,
        )

    witness = bytearray(b"secret")
    with pytest.raises(V3ProofClientError, match="API key"):
        request_and_verify_spend_proof(
            worker_url="https://localhost:8443",
            api_key=b"short",
            ca_certificate="local-ca.pem",
            witness=witness,
            statement=statement(),
            verifier=lambda *_args: True,
        )
    assert witness == bytearray(len(b"secret"))


def test_client_rejects_proof_when_local_verifier_fails() -> None:
    with pytest.raises(V3ProofClientError, match="rejected"):
        call_client(b"", verifier_result=False)
