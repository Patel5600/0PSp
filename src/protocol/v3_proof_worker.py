"""Single-tenant TLS proof worker for the OpenVM V3 candidate relation.

Phase A accepts plaintext witness bytes inside one operator-controlled process.
It is deliberately not described as witness-hiding: TLS protects transport, while
the operator and the prover process can observe witness data.
"""
from __future__ import annotations

import hmac
import base64
import ctypes
import json
import os
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable

PROOF_RESPONSE_MAGIC = b"0PSP-OPENVM-APP-PROOF-v1"
PRODUCTION1_CIRCUIT_ID = "openvm-spend-v3-p1-depth63-1in1out-v1"
MAX_WITNESS_BYTES = 2_000_000
MAX_PROOF_BYTES = 2_000_000
MAX_RESPONSE_BYTES = len(PROOF_RESPONSE_MAGIC) + 64 + 4 + MAX_PROOF_BYTES
PROVE_TIMEOUT_SECONDS = 1200
REQUEST_INTERVAL_SECONDS = 1.0


class WorkerRequestError(ValueError):
    """Malformed, unauthorized, or rate-limited proof request."""


class ProverResult(tuple):
    """Internal immutable tuple: (binary envelope, peak RSS KiB)."""

    __slots__ = ()

    def __new__(cls, envelope: bytes, peak_rss_kib: int):
        return tuple.__new__(cls, (envelope, peak_rss_kib))

    @property
    def envelope(self) -> bytes:
        return self[0]

    @property
    def peak_rss_kib(self) -> int:
        return self[1]


def parse_proof_response(response: bytes) -> tuple[bytes, bytes]:
    """Decode a runner result and enforce its bounded public-input/proof envelope."""
    header = len(PROOF_RESPONSE_MAGIC) + 64 + 4
    if not isinstance(response, bytes) or len(response) < header:
        raise WorkerRequestError("prover returned a truncated proof envelope")
    if not response.startswith(PROOF_RESPONSE_MAGIC):
        raise WorkerRequestError("prover returned an unknown proof envelope")
    public_inputs = response[len(PROOF_RESPONSE_MAGIC):len(PROOF_RESPONSE_MAGIC) + 64]
    proof_len = int.from_bytes(response[len(PROOF_RESPONSE_MAGIC) + 64:header], "big")
    proof = response[header:]
    if not 1 <= proof_len <= MAX_PROOF_BYTES or proof_len != len(proof):
        raise WorkerRequestError("prover returned a malformed proof length")
    return public_inputs, proof


class TokenBucket:
    """Small in-memory per-peer limiter for the single-threaded worker."""

    def __init__(self, *, interval_seconds: float = REQUEST_INTERVAL_SECONDS) -> None:
        self._interval = interval_seconds
        self._last_request: dict[str, float] = {}

    def allow(self, peer: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        previous = self._last_request.get(peer)
        if previous is not None and current - previous < self._interval:
            return False
        if previous is None and len(self._last_request) >= 4096:
            expiry = current - self._interval
            self._last_request = {
                key: value for key, value in self._last_request.items() if value >= expiry
            }
            if len(self._last_request) >= 4096:
                return False
        self._last_request[peer] = current
        return True


def _prover_command() -> list[str]:
    runner = os.environ.get("OPENVM_RUNNER", "").strip()
    config = os.environ.get("OPENVM_CONFIG", "").strip()
    elf = os.environ.get("OPENVM_ELF", "").strip()
    if not runner or not config or not elf:
        raise RuntimeError("OPENVM_RUNNER, OPENVM_CONFIG, and OPENVM_ELF are required")
    return [runner, "prove-stdin", config, elf]


def _run_prover(command: list[str], witness: bytearray) -> ProverResult:
    process: subprocess.Popen[bytes] | None = None
    peak = [0]
    monitor_stop = threading.Event()

    def monitor() -> None:
        while not monitor_stop.is_set():
            if process is not None and process.poll() is not None:
                break
            if process is not None and process.pid is not None:
                if os.name == "nt":
                    try:
                        from ctypes import wintypes

                        class _Counters(ctypes.Structure):
                            _fields_ = [
                                ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                            ]

                        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                        psapi = ctypes.WinDLL("psapi", use_last_error=True)
                        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                        kernel32.OpenProcess.restype = wintypes.HANDLE
                        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                        psapi.GetProcessMemoryInfo.argtypes = [
                            wintypes.HANDLE, ctypes.POINTER(_Counters), wintypes.DWORD
                        ]
                        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
                        handle = kernel32.OpenProcess(0x0400 | 0x0010, False, process.pid)
                        if handle:
                            counters = _Counters()
                            counters.cb = ctypes.sizeof(counters)
                            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                                peak[0] = max(peak[0], int(counters.PeakWorkingSetSize // 1024))
                            kernel32.CloseHandle(handle)
                    except (OSError, AttributeError, ValueError):
                        pass
                else:
                    try:
                        with open(f"/proc/{process.pid}/status", "r", encoding="ascii") as status:
                            for line in status:
                                if line.startswith("VmHWM:"):
                                    peak[0] = max(peak[0], int(line.split()[1]))
                                    break
                    except (OSError, ValueError):
                        pass
            monitor_stop.wait(0.05)

    monitor_thread: threading.Thread | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        stdout, _ = process.communicate(input=witness, timeout=PROVE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise WorkerRequestError("proof generation timed out") from exc
    except OSError as exc:
        raise WorkerRequestError("proof generation failed") from exc
    finally:
        monitor_stop.set()
        if monitor_thread is not None:
            monitor_thread.join(timeout=1)
    if process.returncode != 0:
        raise WorkerRequestError("proof generation failed")
    if len(stdout) > MAX_RESPONSE_BYTES:
        raise WorkerRequestError("proof response exceeded the configured limit")
    parse_proof_response(stdout)
    if peak[0] <= 0:
        raise WorkerRequestError("prover peak RSS measurement is unavailable on this platform")
    return ProverResult(stdout, peak[0])


class ProofHTTPServer(HTTPServer):
    """Single-request-at-a-time server; requests share one in-memory rate limiter."""

    def __init__(self, address, handler, *, api_key: bytes, prover: Callable[[bytearray], ProverResult]):
        if (
            not isinstance(api_key, bytes)
            or len(api_key) < 32
            or not api_key.isascii()
            or any(byte < 0x21 or byte > 0x7E for byte in api_key)
        ):
            raise ValueError("worker API key must contain at least 32 visible ASCII bytes")
        self.api_key = api_key
        self.prover = prover
        self.rate_limiter = TokenBucket()
        super().__init__(address, handler)


class ProofRequestHandler(BaseHTTPRequestHandler):
    server: ProofHTTPServer

    def log_message(self, _format: str, *_args: object) -> None:
        # Default HTTP logging includes request metadata. Keep the worker silent so
        # credentials, transaction data, and witness-derived values cannot leak.
        return

    def _respond(self, status: int, body: bytes = b"") -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if body:
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/v1/prove":
            self._respond(404)
            return
        authorization = self.headers.get("Authorization", "")
        supplied = authorization.removeprefix("Bearer ").encode("utf-8")
        authorization_headers = self.headers.get_all("Authorization", [])
        if len(authorization_headers) != 1 or not authorization.startswith("Bearer ") or not hmac.compare_digest(
            supplied, self.server.api_key
        ):
            self._respond(401)
            return
        peer = self.client_address[0]
        if not self.server.rate_limiter.allow(peer):
            self._respond(429)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._respond(400)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            self._respond(400)
            return
        if self.headers.get("Content-Type") != "application/json":
            self._respond(415)
            return
        length = int(lengths[0])
        # Base64 expands witness bytes by 4/3; bound the encoded request too.
        if not 1 <= length <= (MAX_WITNESS_BYTES * 4 // 3 + 4096):
            self._respond(413 if length > MAX_WITNESS_BYTES * 4 // 3 + 4096 else 400)
            return
        body = bytearray(length)
        try:
            offset = 0
            view = memoryview(body)
            while offset < length:
                received = self.rfile.readinto(view[offset:])
                if not received:
                    self._respond(400)
                    return
                offset += received
            view.release()
            request = json.loads(body)
            if not isinstance(request, dict) or set(request) != {
                "circuit_id", "public_inputs", "witness_blob", "client_req_id"
            }:
                self._respond(400)
                return
            if request["circuit_id"] != PRODUCTION1_CIRCUIT_ID:
                self._respond(422)
                return
            req_id = request["client_req_id"]
            public_inputs_claim = request["public_inputs"]
            encoded_witness = request["witness_blob"]
            if (not isinstance(req_id, str) or not 1 <= len(req_id) <= 128
                    or not isinstance(public_inputs_claim, str)
                    or len(public_inputs_claim) != 128
                    or not isinstance(encoded_witness, str)):
                self._respond(400)
                return
            witness = bytearray(base64.b64decode(encoded_witness, validate=True))
            if not 1 <= len(witness) <= MAX_WITNESS_BYTES:
                self._respond(413)
                return
            started = time.perf_counter()
            prover_result = self.server.prover(witness)
            if not isinstance(prover_result, ProverResult):
                self._respond(500)
                return
            response = prover_result.envelope
            prove_ms = round((time.perf_counter() - started) * 1000, 3)
            public_inputs, proof = parse_proof_response(response)
            if not hmac.compare_digest(public_inputs.hex(), public_inputs_claim.lower()):
                self._respond(422)
                return
            result = json.dumps({
                "proof": base64.b64encode(proof).decode("ascii"),
                "public_inputs": public_inputs.hex(),
                "prove_ms": prove_ms,
                "peak_rss_kib": prover_result.peak_rss_kib,
            }, separators=(",", ":")).encode("ascii")
            self._respond(200, result)
        except WorkerRequestError:
            self._respond(422)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self._respond(400)
        except Exception:
            self._respond(500)
        finally:
            body[:] = b"\x00" * len(body)
            if "view" in locals():
                try:
                    view.release()
                except ValueError:
                    pass
            if "witness" in locals():
                witness[:] = b"\x00" * len(witness)


def _tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def main() -> int:
    if os.environ.get("PROFILE") != "production1_testnet":
        raise SystemExit("proof worker PROFILE must be production1_testnet; mainnet_live is disabled")
    host = os.environ.get("WORKER_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("WORKER_PORT", "8443"))
    api_key = os.environ.get("WORKER_API_KEY", "").encode("utf-8")
    cert_path = os.environ.get("WORKER_TLS_CERT", "")
    key_path = os.environ.get("WORKER_TLS_KEY", "")
    if not cert_path or not key_path:
        raise SystemExit("WORKER_TLS_CERT and WORKER_TLS_KEY are required")
    command = _prover_command()
    server = ProofHTTPServer(
        (host, port),
        ProofRequestHandler,
        api_key=api_key,
        prover=lambda witness: _run_prover(command, witness),
    )
    server.socket = _tls_context(cert_path, key_path).wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
