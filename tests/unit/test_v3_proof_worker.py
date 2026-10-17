from __future__ import annotations

import http.client
import base64
import json
import sys
import threading

import pytest

from src.protocol.v3_proof_worker import (
    MAX_PROOF_BYTES,
    PROOF_PRIVACY_STATUS,
    PROOF_RESPONSE_MAGIC,
    ProofHTTPServer,
    ProofRequestHandler,
    ProverResult,
    TokenBucket,
    WorkerRequestError,
    _run_prover,
    parse_proof_response,
    PRODUCTION1_CIRCUIT_ID,
)

API_KEY = b"worker-test-api-key-material-32-bytes!!"
PUBLIC_INPUTS = bytes(range(64))
PROOF = b"proof-artifact"
RESPONSE = PROOF_RESPONSE_MAGIC + PUBLIC_INPUTS + len(PROOF).to_bytes(4, "big") + PROOF


@pytest.fixture
def worker_server():
    received: list[bytearray] = []

    def prover(witness: bytearray) -> ProverResult:
        received.append(witness)
        return ProverResult(RESPONSE, 2048)

    server = ProofHTTPServer(
        ("127.0.0.1", 0),
        ProofRequestHandler,
        api_key=API_KEY,
        prover=prover,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def send(server: ProofHTTPServer, *, token: bytes, body: bytes) -> http.client.HTTPResponse:
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.request(
        "POST",
        "/v1/prove",
        body=body,
        headers={
            "Authorization": "Bearer " + token.decode("utf-8"),
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    # Consume and close so each request has an independent connection lifecycle.
    response.body = response.read()
    connection.close()
    return response


def test_worker_requires_auth_and_wipes_request_witness(worker_server) -> None:
    server, received = worker_server

    # Unauthorized requests are rejected before reading the body, so use no
    # body here; keeping unread attacker-controlled bytes out of the worker is
    # intentional (and avoids a client-side TCP reset on Windows).
    unauthorized = send(server, token=b"incorrect-token", body=b"")
    assert unauthorized.status == 401
    assert received == []

    accepted = send(server, token=API_KEY, body=request_body(b"secret witness"))
    assert accepted.status == 200
    result = json.loads(accepted.body)
    assert result["proof"] == base64.b64encode(PROOF).decode("ascii")
    assert result["public_inputs"] == PUBLIC_INPUTS.hex()
    assert result["proof_privacy"] == PROOF_PRIVACY_STATUS
    assert isinstance(result["prove_ms"], float)
    assert result["peak_rss_kib"] == 2048
    assert len(received) == 1
    assert received[0] == bytearray(len(b"secret witness"))


def test_worker_rate_limits_the_single_operator_endpoint(worker_server) -> None:
    server, received = worker_server
    assert send(server, token=API_KEY, body=request_body(b"first witness")).status == 200
    assert send(server, token=API_KEY, body=request_body(b"second witness")).status == 429
    assert len(received) == 1


def request_body(witness: bytes) -> bytes:
    return json.dumps({
        "circuit_id": PRODUCTION1_CIRCUIT_ID,
        "public_inputs": PUBLIC_INPUTS.hex(),
        "witness_blob": base64.b64encode(witness).decode("ascii"),
        "client_req_id": "test-request-1",
    }).encode("ascii")


def test_token_bucket_uses_monotonic_interval() -> None:
    limiter = TokenBucket(interval_seconds=2.0)
    assert limiter.allow("loopback", now=10.0)
    assert not limiter.allow("loopback", now=11.9)
    assert limiter.allow("loopback", now=12.0)


def test_proof_envelope_rejects_wrong_lengths() -> None:
    public_inputs, proof = parse_proof_response(RESPONSE)
    assert public_inputs == PUBLIC_INPUTS
    assert proof == PROOF
    with pytest.raises(WorkerRequestError):
        parse_proof_response(PROOF_RESPONSE_MAGIC + PUBLIC_INPUTS + (MAX_PROOF_BYTES + 1).to_bytes(4, "big") + b"x")


def test_one_shot_prover_receives_witness_on_stdin_without_a_witness_file(tmp_path) -> None:
    child = tmp_path / "fake_openvm_runner.py"
    child.write_text(
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        f"sys.stdout.buffer.write(bytes.fromhex('{RESPONSE.hex()}'))\n",
        encoding="ascii",
    )
    body = bytearray(b"in-memory witness bytes")
    response = _run_prover([sys.executable, str(child)], body)
    assert parse_proof_response(response.envelope) == (PUBLIC_INPUTS, PROOF)
    assert response.peak_rss_kib > 0
