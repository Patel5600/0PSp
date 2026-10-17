#!/usr/bin/env python3
"""Run mint-fixture → OpenVM worker prove → client verify → ledger/replay test."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.protocol.v3_proof_worker import ProofHTTPServer, ProofRequestHandler, _run_prover, _tls_context


def _executable(stem: str) -> Path:
    release = ROOT / "proof/openvm/v3-nullifier-spike/proof-output-checker/target/release"
    path = release / (stem + (".exe" if os.name == "nt" else ""))
    if not path.is_file():
        raise SystemExit(f"required release artifact is missing: {path}")
    return path


def _make_test_certificate(cert: Path, key: Path) -> None:
    openssl = shutil.which("openssl")
    if openssl:
        command = [openssl]
        output_cert, output_key = str(cert), str(key)
    elif os.name == "nt" and shutil.which("wsl.exe"):
        wsl = shutil.which("wsl.exe")
        def wslpath(path: Path) -> str:
            result = subprocess.run([wsl, "-e", "wslpath", "-a", str(path)], check=True,
                                    text=True, capture_output=True)
            return result.stdout.strip()
        command = [wsl, "-e", "openssl"]
        output_cert, output_key = wslpath(cert), wslpath(key)
    else:
        raise SystemExit("openssl is required to make the loopback-only TLS test certificate")
    subprocess.run(
        command + ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                   "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                   "-keyout", output_key, "-out", output_cert],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def main() -> int:
    proof_root = ROOT / "proof/openvm/v3-nullifier-spike"
    runner = _executable("openvm-v3-sdk-runner")
    checker = _executable("psp-openvm-v3-proof-output-checker")
    elf = proof_root / "target/riscv32im-risc0-zkvm-elf/release/psp-openvm-v3-nullifier-spike"
    if not elf.is_file():
        raise SystemExit(f"OpenVM guest ELF is missing: {elf}; run cargo +1.91.1 openvm build")
    app_vk = proof_root / "openvm/production1-app.vk"
    pins = proof_root / "production1-pins.json"
    if not app_vk.is_file() or not pins.is_file():
        raise SystemExit("Production-1 pinned app VK/pin manifest is missing from this release")

    api_key = "production1-local-test-key-change-per-run"
    with tempfile.TemporaryDirectory(prefix="0psp-production1-") as directory:
        temp = Path(directory)
        cert, key = temp / "tls.crt", temp / "tls.key"
        _make_test_certificate(cert, key)
        command = [str(runner), "prove-stdin", str(proof_root / "openvm.toml"), str(elf)]
        server = ProofHTTPServer(
            ("127.0.0.1", 0), ProofRequestHandler,
            api_key=api_key.encode("ascii"), prover=lambda witness: _run_prover(command, witness),
        )
        server.socket = _tls_context(str(cert), str(key)).wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        old_key = os.environ.get("WORKER_API_KEY")
        old_profile = os.environ.get("PROFILE")
        os.environ["WORKER_API_KEY"] = api_key
        os.environ["PROFILE"] = "production1_testnet"
        old_argv = sys.argv
        import importlib.util
        script = proof_root / "scripts/openvm_local_spend.py"
        spec = importlib.util.spec_from_file_location("openvm_local_spend", script)
        assert spec is not None and spec.loader is not None
        openvm_local_spend = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(openvm_local_spend)
        try:
            sys.argv = [
                "openvm_local_spend.py", "--worker-url", f"https://127.0.0.1:{server.server_port}",
                "--ca-certificate", str(cert), "--checker", str(checker), "--app-vk", str(app_vk),
                "--pins", str(pins), "--ledger", str(temp / "ledger.sqlite3"),
                "--allow-synthetic-bootstrap",
            ]
            return openvm_local_spend.main()
        finally:
            sys.argv = old_argv
            if old_key is None:
                os.environ.pop("WORKER_API_KEY", None)
            else:
                os.environ["WORKER_API_KEY"] = old_key
            if old_profile is None:
                os.environ.pop("PROFILE", None)
            else:
                os.environ["PROFILE"] = old_profile
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
