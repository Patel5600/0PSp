"""Ethereum-mainnet light-client process and authenticated finalized ancestry.

This module implements one concrete consensus profile first: Ethereum Mainnet
via a digest-pinned Helios 0.12.0 binary. The upstream client is not claimed to
be independently audited. Its executable digest and fresh beacon checkpoint
are explicit operator-supplied trust anchors.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import urlsplit

from src.adapters.evm_deposit_evidence import EvmDepositEvidencePolicy
from src.adapters.evm_deposit_proof import (
    EvmDepositInclusionError,
    EvmDepositInclusionVerifier,
    ProvenEvmDepositInclusion,
    _parse_header,
)
from src.adapters.evm_namespace import EvmNamespaceConfig, JsonRpcClient, runtime_code_fingerprint
from src.adapters.evm_trie import EthereumEncodingError, rlp_decode, rlp_encode_bytes, rlp_encode_list
from src.primitives.namespace_v3 import NamespaceIdV3

ETHEREUM_MAINNET_CHAIN_ID = 1
ETHEREUM_MAINNET_GENESIS_HASH = bytes.fromhex(
    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
)
SUPPORTED_HELIOS_VERSION = "0.12.0"
_U64_MAX = (1 << 64) - 1
_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")
_DATA_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")


class HeliosConsensusError(RuntimeError):
    """The pinned light-client process or its verified-finality view is invalid."""


class HeliosFinalityCatchupRequired(HeliosConsensusError):
    """The finalized ancestry gap exceeds the configured per-sync bound."""


class HeliosRpc(Protocol):
    def call(self, method: str, params: list[object]) -> object:
        """Read from the loopback JSON-RPC exposed by the supervised Helios process."""


def _canonical_quantity(value: object, field: str, *, maximum: int = (1 << 256) - 1) -> int:
    if not isinstance(value, str) or _QUANTITY_RE.fullmatch(value) is None:
        raise HeliosConsensusError(f"{field} is not a canonical JSON-RPC QUANTITY")
    result = int(value[2:], 16)
    if result > maximum:
        raise HeliosConsensusError(f"{field} exceeds its configured integer bound")
    return result


def _canonical_data(value: object, field: str, *, length: int | None = None) -> bytes:
    if not isinstance(value, str) or _DATA_RE.fullmatch(value) is None:
        raise HeliosConsensusError(f"{field} is not canonical JSON-RPC DATA")
    result = bytes.fromhex(value[2:])
    if length is not None and len(result) != length:
        raise HeliosConsensusError(f"{field} must be exactly {length} bytes")
    return result


def _json_uint_bytes(value: object, field: str, *, maximum: int = (1 << 256) - 1) -> bytes:
    number = _canonical_quantity(value, field, maximum=maximum)
    return b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big")


def _toml_string(value: str) -> str:
    # JSON basic strings use compatible escapes for the URLs accepted here.
    return json.dumps(value, ensure_ascii=True)


def execution_header_rlp_from_json(header: object) -> bytes:
    """Reconstruct canonical execution-header RLP from an execution API block object.

    The hash and trie roots are validated by the caller. Unsupported/inconsistent
    fork-field combinations are rejected instead of silently using incomplete roots.
    """
    if not isinstance(header, dict):
        raise HeliosConsensusError("execution header must be a JSON-RPC object")
    fields: list[bytes] = []
    for name, length in (
        ("parentHash", 32), ("sha3Uncles", 32), ("miner", 20),
        ("stateRoot", 32), ("transactionsRoot", 32), ("receiptsRoot", 32),
        ("logsBloom", 256),
    ):
        fields.append(_canonical_data(header.get(name), f"header.{name}", length=length))
    fields.append(_json_uint_bytes(header.get("difficulty"), "header.difficulty"))
    fields.append(_json_uint_bytes(header.get("number"), "header.number", maximum=_U64_MAX))
    fields.append(_json_uint_bytes(header.get("gasLimit"), "header.gasLimit", maximum=_U64_MAX))
    fields.append(_json_uint_bytes(header.get("gasUsed"), "header.gasUsed", maximum=_U64_MAX))
    fields.append(_json_uint_bytes(header.get("timestamp"), "header.timestamp", maximum=_U64_MAX))
    extra_data = _canonical_data(header.get("extraData"), "header.extraData")
    if len(extra_data) > 32:
        raise HeliosConsensusError("header.extraData exceeds 32 bytes")
    fields.append(extra_data)
    fields.append(_canonical_data(header.get("mixHash"), "header.mixHash", length=32))
    fields.append(_canonical_data(header.get("nonce"), "header.nonce", length=8))

    base_fee_present = header.get("baseFeePerGas") is not None and "baseFeePerGas" in header
    withdrawals_present = header.get("withdrawalsRoot") is not None and "withdrawalsRoot" in header
    blob_keys = ("blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot")
    blob_present = tuple(key in header and header[key] is not None for key in blob_keys)
    requests_present = "requestsHash" in header and header["requestsHash"] is not None

    if any(blob_present) and not all(blob_present):
        raise HeliosConsensusError("Cancun header must include all three blob-era header fields")
    if requests_present and not all(blob_present):
        raise HeliosConsensusError("requestsHash requires the complete Cancun header field set")
    if withdrawals_present and not base_fee_present:
        raise HeliosConsensusError("withdrawalsRoot requires baseFeePerGas")
    if all(blob_present) and not withdrawals_present:
        raise HeliosConsensusError("blob-era fields require withdrawalsRoot")
    profile = (base_fee_present, withdrawals_present, all(blob_present), requests_present)
    if profile not in (
        (False, False, False, False), (True, False, False, False),
        (True, True, False, False), (True, True, True, False),
        (True, True, True, True),
    ):
        raise HeliosConsensusError("execution header has an unsupported fork-field combination")

    if base_fee_present:
        fields.append(_json_uint_bytes(header["baseFeePerGas"], "header.baseFeePerGas"))
    if withdrawals_present:
        fields.append(_canonical_data(header["withdrawalsRoot"], "header.withdrawalsRoot", length=32))
    if all(blob_present):
        fields.append(_json_uint_bytes(header["blobGasUsed"], "header.blobGasUsed", maximum=_U64_MAX))
        fields.append(_json_uint_bytes(header["excessBlobGas"], "header.excessBlobGas", maximum=_U64_MAX))
        fields.append(_canonical_data(header["parentBeaconBlockRoot"], "header.parentBeaconBlockRoot", length=32))
    if requests_present:
        fields.append(_canonical_data(header["requestsHash"], "header.requestsHash", length=32))

    if len(fields) not in (15, 16, 17, 20, 21):
        raise HeliosConsensusError(f"unsupported execution header field count {len(fields)}")
    encoded = rlp_encode_list([rlp_encode_bytes(field) for field in fields])
    try:
        number, calculated_hash, _transactions_root, _receipts_root = _parse_header(encoded)
    except (EvmDepositInclusionError, EthereumEncodingError, ValueError, TypeError) as exc:
        raise HeliosConsensusError(f"reconstructed execution header is invalid: {exc}") from None
    claimed_number = _canonical_quantity(header.get("number"), "header.number", maximum=_U64_MAX)
    claimed_hash = _canonical_data(header.get("hash"), "header.hash", length=32)
    if number != claimed_number:
        raise HeliosConsensusError("reconstructed header number does not match its JSON-RPC field")
    if calculated_hash != claimed_hash:
        raise HeliosConsensusError("reconstructed header hash does not match its JSON-RPC field")
    return encoded


@dataclass(frozen=True, slots=True)
class HeliosMainnetConfig:
    """Pinned launch configuration for the supervised Ethereum Mainnet light client.

    The beacon checkpoint must be obtained out-of-band and be less than two weeks
    old. Never copy it from the execution RPC being verified. The executable hash
    must be pinned independently to an approved distribution.
    """

    binary_path: str | Path
    binary_sha256: bytes
    execution_rpc_url: str
    consensus_rpc_url: str
    weak_subjectivity_checkpoint: bytes
    rpc_port: int = 18545
    startup_timeout_seconds: float = 120.0
    request_timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        if not isinstance(self.binary_path, (str, Path)) or not str(self.binary_path).strip():
            raise ValueError("binary_path must be a non-empty filesystem path")
        if not isinstance(self.binary_sha256, bytes) or len(self.binary_sha256) != 32:
            raise ValueError("binary_sha256 must be a 32-byte out-of-band binary hash pin")
        for name, value in (("execution_rpc_url", self.execution_rpc_url), ("consensus_rpc_url", self.consensus_rpc_url)):
            parsed = urlsplit(value) if isinstance(value, str) else None
            if (
                parsed is None or parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment
            ):
                raise ValueError(f"{name} must be an HTTPS URL without userinfo or fragment")
            try:
                parsed.port
            except ValueError:
                raise ValueError(f"{name} has an invalid port") from None
        if not isinstance(self.weak_subjectivity_checkpoint, bytes) or len(self.weak_subjectivity_checkpoint) != 32:
            raise ValueError("weak_subjectivity_checkpoint must be exactly 32 beacon-root bytes")
        if isinstance(self.rpc_port, bool) or not isinstance(self.rpc_port, int) or not 1024 <= self.rpc_port <= 65535:
            raise ValueError("rpc_port must be in [1024, 65535]")
        for name, value in (
            ("startup_timeout_seconds", self.startup_timeout_seconds),
            ("request_timeout_seconds", self.request_timeout_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0.1 <= value <= 600:
                raise ValueError(f"{name} must be finite and in [0.1, 600]")


class HeliosMainnetLightClient:
    """Run a binary-pinned Helios 0.12.0 Mainnet client on loopback RPC only.

    Secret-bearing RPC URLs are placed in a mode-0600 TOML file under a private
    temporary HOME, rather than process arguments. The local server binds only
    to 127.0.0.1. A same-user hostile process is outside this trust boundary.
    """

    def __init__(
        self,
        config: HeliosMainnetConfig,
        *,
        process_factory: Callable[..., object] = subprocess.Popen,
        rpc_factory: Callable[..., HeliosRpc] = JsonRpcClient,
        version_probe: Callable[..., object] = subprocess.run,
    ) -> None:
        if not isinstance(config, HeliosMainnetConfig):
            raise TypeError("config must be a HeliosMainnetConfig")
        self.config = config
        self._process_factory = process_factory
        self._rpc_factory = rpc_factory
        self._version_probe = version_probe
        self._process = None
        self._temp_home: tempfile.TemporaryDirectory[str] | None = None
        self._rpc: HeliosRpc | None = None
        self._started = False

    @property
    def started(self) -> bool:
        return self._started and self._process is not None and self._process.poll() is None

    @property
    def rpc(self) -> HeliosRpc:
        if not self.started or self._rpc is None:
            raise HeliosConsensusError("Helios Mainnet light client is not running")
        return self._rpc

    def _check_executable(self) -> Path:
        path = Path(self.config.binary_path).expanduser().resolve()
        if not path.is_file():
            raise HeliosConsensusError("configured Helios executable is absent")
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            raise HeliosConsensusError("configured Helios executable cannot be read") from None
        if digest.digest() != self.config.binary_sha256:
            raise HeliosConsensusError("Helios executable SHA-256 does not match the configured trust pin")
        try:
            probe = self._version_probe(
                [str(path), "--version"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=5, check=False,
            )
        except Exception:
            raise HeliosConsensusError("could not inspect the pinned Helios executable version") from None
        output = (getattr(probe, "stdout", None) or "").strip()
        if getattr(probe, "returncode", 1) != 0 or SUPPORTED_HELIOS_VERSION not in output:
            raise HeliosConsensusError(f"Helios executable must report version {SUPPORTED_HELIOS_VERSION}")
        return path

    def start(self) -> "HeliosMainnetLightClient":
        if self.started:
            return self
        binary = self._check_executable()
        self._temp_home = tempfile.TemporaryDirectory(prefix="0psp-helios-")
        home = Path(self._temp_home.name)
        config_dir = home / ".helios"
        config_dir.mkdir(mode=0o700)
        config_path = config_dir / "helios.toml"
        config_text = (
            "[mainnet]\n"
            f"execution_rpc = {_toml_string(self.config.execution_rpc_url)}\n"
            f"consensus_rpc = {_toml_string(self.config.consensus_rpc_url)}\n"
            f'checkpoint = "0x{self.config.weak_subjectivity_checkpoint.hex()}"\n'
        )
        descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(config_text)
            stream.flush()
            os.fsync(stream.fileno())

        environment = os.environ.copy()
        environment["HOME"] = str(home)
        command = [
            str(binary), "ethereum", "--network", "mainnet", "--strict-checkpoint-age",
            "--rpc-bind-ip", "127.0.0.1", "--rpc-port", str(self.config.rpc_port),
        ]
        try:
            kwargs = {
                "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL, "env": environment, "close_fds": True,
            }
            if os.name == "posix":
                kwargs["start_new_session"] = True
            self._process = self._process_factory(command, **kwargs)
            self._rpc = self._rpc_factory(
                f"http://127.0.0.1:{self.config.rpc_port}",
                timeout_seconds=self.config.request_timeout_seconds,
                allow_insecure_http=True,
            )
            deadline = time.monotonic() + self.config.startup_timeout_seconds
            last_error = None
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    raise HeliosConsensusError("Helios exited before exposing its verified RPC")
                try:
                    chain_id = _canonical_quantity(self._rpc.call("eth_chainId", []), "Helios eth_chainId")
                    if chain_id != ETHEREUM_MAINNET_CHAIN_ID:
                        raise HeliosConsensusError("Helios local RPC is not Ethereum Mainnet")
                    genesis_json = self._rpc.call("eth_getBlockByNumber", ["0x0", False])
                    genesis_rlp = execution_header_rlp_from_json(genesis_json)
                    genesis_number, genesis_hash, _, _ = _parse_header(genesis_rlp)
                    if genesis_number != 0 or genesis_hash != ETHEREUM_MAINNET_GENESIS_HASH:
                        raise HeliosConsensusError("Helios local RPC returned the wrong Mainnet genesis header")
                    finalized_json = self._rpc.call("eth_getBlockByNumber", ["finalized", False])
                    execution_header_rlp_from_json(finalized_json)
                    self._started = True
                    return self
                except HeliosConsensusError as exc:
                    last_error = exc
                    if "not Ethereum Mainnet" in str(exc) or "wrong Mainnet genesis" in str(exc):
                        raise
                except Exception:
                    last_error = None
                time.sleep(0.2)
            raise HeliosConsensusError("Helios did not expose a valid Mainnet finalized header before startup deadline") from last_error
        except Exception:
            self.stop()
            raise

    def call(self, method: str, params: list[object]) -> object:
        """Expose only chain identity and header reads from the supervised local client."""
        if method not in {"eth_chainId", "eth_getBlockByNumber", "eth_getCode"}:
            raise HeliosConsensusError(f"Helios trust adapter does not permit RPC method {method!r}")
        if not isinstance(params, list):
            raise TypeError("params must be a list")
        if method == "eth_chainId" and params:
            raise HeliosConsensusError("eth_chainId parameters must be empty")
        if method == "eth_getBlockByNumber" and (
            len(params) != 2 or type(params[1]) is not bool or not isinstance(params[0], str)
        ):
            raise HeliosConsensusError("eth_getBlockByNumber parameters are malformed")
        if method == "eth_getCode":
            if (
                len(params) != 2
                or not isinstance(params[0], str)
                or re.fullmatch(r"0x[0-9a-fA-F]{40}", params[0]) is None
                or not isinstance(params[1], str)
                or not (
                    params[1] in {"latest", "safe", "finalized"}
                    or _QUANTITY_RE.fullmatch(params[1]) is not None
                )
            ):
                raise HeliosConsensusError("eth_getCode parameters are malformed")
        return self.rpc.call(method, params)

    def stop(self) -> None:
        self._started = False
        process, self._process = self._process, None
        self._rpc = None
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            except Exception:
                pass
        if self._temp_home is not None:
            self._temp_home.cleanup()
            self._temp_home = None

    def __enter__(self) -> "HeliosMainnetLightClient":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


@dataclass(frozen=True, slots=True)
class AuthenticatedExecutionHeader:
    number: int
    block_hash: bytes
    parent_hash: bytes | None
    transactions_root: bytes
    receipts_root: bytes
    raw_header_rlp: bytes
    observed_finalized_number: int
    observed_finalized_hash: bytes
    light_client_binary_sha256: bytes

    @property
    def assurance_level(self) -> str:
        return "HELIOS_LIGHT_CLIENT_FINALIZED_ANCESTRY_AND_HEADER_RLP_VERIFIED"


class HeliosAuthenticatedHeaderJournal:
    """Persist headers linked from an out-of-band execution checkpoint to Helios finality.

    This authenticates only blocks at or after EvmNamespaceConfig's checkpoint.
    A current weak-subjectivity beacon checkpoint is also enforced by Helios.
    Every persisted child is parent-linked, and each sync terminates at the exact
    block returned by the light client's finalized tag.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        namespace_config: EvmNamespaceConfig,
        namespace_id: NamespaceIdV3,
        light_client: HeliosMainnetLightClient,
        max_headers_per_sync: int = 4096,
    ) -> None:
        if not isinstance(namespace_config, EvmNamespaceConfig):
            raise TypeError("namespace_config must be an EvmNamespaceConfig")
        if not isinstance(namespace_id, NamespaceIdV3):
            raise TypeError("namespace_id must be NamespaceIdV3")
        if namespace_config.chain_id != ETHEREUM_MAINNET_CHAIN_ID:
            raise ValueError("Helios profile supports Ethereum Mainnet chain ID 1 only")
        if namespace_config.genesis_hash != ETHEREUM_MAINNET_GENESIS_HASH:
            raise ValueError("namespace config does not pin the Ethereum Mainnet genesis hash")
        if not isinstance(light_client, HeliosMainnetLightClient):
            raise TypeError("light_client must be a supervised HeliosMainnetLightClient")
        if not isinstance(database_path, (str, Path)) or not str(database_path).strip() or str(database_path) == ":memory:":
            raise ValueError("a non-empty file-backed SQLite path is required")
        if (
            isinstance(max_headers_per_sync, bool) or not isinstance(max_headers_per_sync, int)
            or not 1 <= max_headers_per_sync <= 100_000
        ):
            raise ValueError("max_headers_per_sync must be in [1, 100000]")
        self._path = str(database_path)
        self.config = namespace_config
        self.namespace_id = namespace_id
        self.light_client = light_client
        self.max_headers_per_sync = max_headers_per_sync
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _ensure_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS helios_namespace_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    chain_id TEXT NOT NULL,
                    genesis_hash BLOB NOT NULL CHECK (length(genesis_hash) = 32),
                    checkpoint_number INTEGER NOT NULL CHECK (checkpoint_number >= 0),
                    checkpoint_hash BLOB NOT NULL CHECK (length(checkpoint_hash) = 32),
                    namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 48),
                    binary_sha256 BLOB NOT NULL CHECK (length(binary_sha256) = 32),
                    beacon_checkpoint BLOB NOT NULL CHECK (length(beacon_checkpoint) = 32)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS helios_authenticated_headers (
                    height INTEGER PRIMARY KEY CHECK (height >= 0),
                    block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
                    parent_hash BLOB,
                    raw_header_rlp BLOB NOT NULL,
                    transactions_root BLOB NOT NULL CHECK (length(transactions_root) = 32),
                    receipts_root BLOB NOT NULL CHECK (length(receipts_root) = 32),
                    CHECK (parent_hash IS NULL OR length(parent_hash) = 32)
                )"""
            )

    def _expected_meta(self) -> tuple[object, ...]:
        return (
            str(self.config.chain_id),
            self.config.genesis_hash,
            self.config.checkpoint_block_number,
            self.config.checkpoint_hash,
            self.namespace_id.data,
            self.light_client.config.binary_sha256,
            self.light_client.config.weak_subjectivity_checkpoint,
        )

    @staticmethod
    def _decode_header(raw_header_rlp: bytes) -> tuple[int, bytes, bytes | None, bytes, bytes]:
        try:
            number, block_hash, transactions_root, receipts_root = _parse_header(raw_header_rlp)
            decoded = rlp_decode(raw_header_rlp)
            if not isinstance(decoded, list) or len(decoded) not in (15, 16, 17, 20, 21):
                raise EthereumEncodingError("header field count is unsupported")
            parent_hash = decoded[0]
            if not isinstance(parent_hash, bytes) or len(parent_hash) != 32:
                raise EthereumEncodingError("header parentHash must be 32 bytes")
            return number, block_hash, parent_hash if number else None, transactions_root, receipts_root
        except (EvmDepositInclusionError, EthereumEncodingError, ValueError, TypeError) as exc:
            raise HeliosConsensusError(f"invalid execution header: {exc}") from None

    def _verified_rpc_header(self, tag: str) -> tuple[dict[str, object], bytes, tuple[int, bytes, bytes | None, bytes, bytes]]:
        try:
            value = self.light_client.call("eth_getBlockByNumber", [tag, False])
            raw = execution_header_rlp_from_json(value)
            decoded = self._decode_header(raw)
        except Exception as exc:
            if isinstance(exc, HeliosConsensusError):
                raise
            raise HeliosConsensusError("could not obtain a canonical header from the supervised Helios client") from None
        return value, raw, decoded

    def advance_to_finalized(self) -> AuthenticatedExecutionHeader:
        """Advance durable ancestry from the pinned execution checkpoint to finality."""
        if not self.light_client.started:
            raise HeliosConsensusError("start the digest-pinned Helios client before syncing headers")
        chain_id = _canonical_quantity(self.light_client.call("eth_chainId", []), "Helios eth_chainId")
        if chain_id != self.config.chain_id:
            raise HeliosConsensusError("Helios consensus source chain ID differs from namespace manifest")
        _genesis_json, _genesis_rlp, genesis = self._verified_rpc_header("0x0")
        if genesis[0] != 0 or genesis[1] != self.config.genesis_hash:
            raise HeliosConsensusError("Helios consensus source genesis hash differs from namespace manifest")
        _finalized_json, finalized_rlp, finalized = self._verified_rpc_header("finalized")
        finalized_number, finalized_hash = finalized[0], finalized[1]

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            meta = conn.execute(
                "SELECT chain_id, genesis_hash, checkpoint_number, checkpoint_hash, namespace_id, "
                "binary_sha256, beacon_checkpoint FROM helios_namespace_meta WHERE singleton = 1"
            ).fetchone()
            expected = self._expected_meta()
            if meta is None:
                _checkpoint_json, checkpoint_rlp, checkpoint = self._verified_rpc_header(
                    hex(self.config.checkpoint_block_number)
                )
                if checkpoint[0] != self.config.checkpoint_block_number or checkpoint[1] != self.config.checkpoint_hash:
                    raise HeliosConsensusError("Helios header at the out-of-band execution checkpoint differs from pinned manifest")
                if finalized_number < checkpoint[0]:
                    raise HeliosConsensusError("Helios finalized head is below the pinned execution checkpoint")
                start_number, prior_hash = checkpoint[0], checkpoint[1]
                conn.execute(
                    "INSERT INTO helios_namespace_meta "
                    "(singleton, chain_id, genesis_hash, checkpoint_number, checkpoint_hash, namespace_id, binary_sha256, beacon_checkpoint) "
                    "VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                    expected,
                )
                self._insert_raw_header(conn, checkpoint_rlp, checkpoint)
            else:
                if tuple(meta) != expected:
                    raise HeliosConsensusError("Helios finality database belongs to another chain, checkpoint, namespace, or binary pin")
                row = conn.execute(
                    "SELECT height, block_hash FROM helios_authenticated_headers ORDER BY height DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    raise HeliosConsensusError("Helios finality metadata exists without an authenticated header")
                start_number, prior_hash = row[0], bytes(row[1])
                _live_json, _live_rlp, live = self._verified_rpc_header(hex(start_number))
                if live[1] != prior_hash:
                    raise HeliosConsensusError("Helios header conflicts with durable authenticated history; operator recovery required")
            if finalized_number < start_number:
                raise HeliosConsensusError("Helios finalized height regressed below durable header state")
            if finalized_number == start_number:
                if finalized_hash != prior_hash:
                    raise HeliosConsensusError("Helios finalized hash conflicts with durable header tip")
            else:
                distance = finalized_number - start_number
                if distance > self.max_headers_per_sync:
                    raise HeliosFinalityCatchupRequired(
                        f"finalized catch-up requires {distance} headers; limit is {self.max_headers_per_sync}"
                    )
                current = None
                for height in range(start_number + 1, finalized_number + 1):
                    _json_header, raw_header, parsed = self._verified_rpc_header(hex(height))
                    number, block_hash, parent_hash, _tx_root, _receipt_root = parsed
                    if number != height:
                        raise HeliosConsensusError("Helios returned a header for the wrong block height")
                    if parent_hash != prior_hash:
                        raise HeliosConsensusError(f"parentHash mismatch at block {height}; refusing broken finality ancestry")
                    self._insert_raw_header(conn, raw_header, parsed)
                    prior_hash = block_hash
                    current = parsed
                if current is None or current[0] != finalized_number or current[1] != finalized_hash:
                    raise HeliosConsensusError("numbered header chain does not terminate at Helios's finalized header")
            conn.execute("COMMIT")
            return AuthenticatedExecutionHeader(
                number=finalized_number,
                block_hash=finalized_hash,
                parent_hash=finalized[2],
                transactions_root=finalized[3],
                receipts_root=finalized[4],
                raw_header_rlp=finalized_rlp,
                observed_finalized_number=finalized_number,
                observed_finalized_hash=finalized_hash,
                light_client_binary_sha256=self.light_client.config.binary_sha256,
            )
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _insert_raw_header(
        self,
        conn: sqlite3.Connection,
        raw_header_rlp: bytes,
        header: tuple[int, bytes, bytes | None, bytes, bytes],
    ) -> None:
        number, block_hash, parent_hash, transactions_root, receipts_root = header
        row = conn.execute(
            "SELECT block_hash, raw_header_rlp FROM helios_authenticated_headers WHERE height = ?",
            (number,),
        ).fetchone()
        if row is not None:
            if bytes(row[0]) != block_hash or bytes(row[1]) != raw_header_rlp:
                raise HeliosConsensusError("authenticated header conflicts with existing history; refusing silent rollback")
            return
        conn.execute(
            "INSERT INTO helios_authenticated_headers "
            "(height, block_hash, parent_hash, raw_header_rlp, transactions_root, receipts_root) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (number, block_hash, parent_hash, raw_header_rlp, transactions_root, receipts_root),
        )

    def authenticate_header(self, raw_header_rlp: bytes) -> AuthenticatedExecutionHeader:
        """Require a specific raw header to exist in the durable checkpoint-to-finality chain."""
        target = self._decode_header(raw_header_rlp)
        finalized = self.advance_to_finalized()
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT raw_header_rlp, block_hash, parent_hash, transactions_root, receipts_root "
                "FROM helios_authenticated_headers WHERE height = ?",
                (target[0],),
            ).fetchone()
        if row is None:
            raise HeliosConsensusError("deposit header is outside the authenticated execution checkpoint/finality window")
        if bytes(row[0]) != raw_header_rlp or bytes(row[1]) != target[1]:
            raise HeliosConsensusError("supplied deposit header differs from authenticated history at that height")
        return AuthenticatedExecutionHeader(
            number=target[0], block_hash=target[1], parent_hash=target[2],
            transactions_root=target[3], receipts_root=target[4], raw_header_rlp=raw_header_rlp,
            observed_finalized_number=finalized.number, observed_finalized_hash=finalized.block_hash,
            light_client_binary_sha256=self.light_client.config.binary_sha256,
        )

    def contains_finalized_header(self, block_number: int, block_hash: bytes) -> bool:
        if (
            isinstance(block_number, bool) or not isinstance(block_number, int)
            or not 0 <= block_number <= _U64_MAX or not isinstance(block_hash, bytes)
            or len(block_hash) != 32
        ):
            return False
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT block_hash FROM helios_authenticated_headers WHERE height = ?",
                (block_number,),
            ).fetchone()
        return row is not None and bytes(row[0]) == block_hash


@dataclass(frozen=True, slots=True)
class HeliosAuthenticatedEvmDeposit:
    inclusion: ProvenEvmDepositInclusion
    authenticated_header: AuthenticatedExecutionHeader

    def __post_init__(self) -> None:
        if self.inclusion.block_number != self.authenticated_header.number or self.inclusion.block_hash != self.authenticated_header.block_hash:
            raise ValueError("deposit inclusion and authenticated header differ")

    @property
    def assurance_level(self) -> str:
        return "HELIOS_FINALIZED_HEADER_ANCESTRY_AND_TRANSACTION_RECEIPT_TRIES_VERIFIED"


class HeliosAuthenticatedDepositVerifier:
    """Combine a pinned Mainnet light client with transaction/receipt trie inclusion checks.

    The result is authenticated inclusion evidence only. It does not establish
    asset custody semantics and never produces DepositAuthorization.
    """

    def __init__(
        self,
        policy: EvmDepositEvidencePolicy,
        namespace_config: EvmNamespaceConfig,
        journal: HeliosAuthenticatedHeaderJournal,
    ) -> None:
        if not isinstance(policy, EvmDepositEvidencePolicy):
            raise TypeError("policy must be an EvmDepositEvidencePolicy")
        if not isinstance(namespace_config, EvmNamespaceConfig):
            raise TypeError("namespace_config must be an EvmNamespaceConfig")
        if namespace_config != journal.config:
            raise ValueError("namespace config does not match the authenticated-header journal's pinned manifest")
        if policy.namespace_id != journal.namespace_id or policy.chain_id != namespace_config.chain_id:
            raise ValueError("deposit policy, namespace journal and chain configuration disagree")
        if (
            policy.deposit_contract_address != namespace_config.protocol_address
            or policy.asset_address != namespace_config.asset_address
            or policy.expected_runtime_code_fingerprint != namespace_config.expected_protocol_code_fingerprint
        ):
            raise ValueError("deposit event/code policy must match the namespace's pinned protocol and asset")
        self._policy = policy
        self._journal = journal
        self._inclusion_verifier = EvmDepositInclusionVerifier(policy, journal)

    def verify(
        self,
        *,
        raw_header_rlp: bytes,
        raw_transaction: bytes,
        transaction_proof: tuple[bytes, ...] | list[bytes],
        raw_receipt: bytes,
        receipt_proof: tuple[bytes, ...] | list[bytes],
        transaction_index: int,
        receipt_log_ordinal: int,
        expected_beneficiary: bytes,
    ) -> HeliosAuthenticatedEvmDeposit:
        authenticated_header = self._journal.authenticate_header(raw_header_rlp)
        inclusion = self._inclusion_verifier.verify(
            raw_header_rlp=raw_header_rlp,
            raw_transaction=raw_transaction,
            transaction_proof=transaction_proof,
            raw_receipt=raw_receipt,
            receipt_proof=receipt_proof,
            transaction_index=transaction_index,
            receipt_log_ordinal=receipt_log_ordinal,
            expected_beneficiary=expected_beneficiary,
        )
        try:
            code_result = self._journal.light_client.call(
                "eth_getCode",
                [
                    "0x" + self._policy.deposit_contract_address.hex(),
                    hex(inclusion.block_number),
                ],
            )
            if not isinstance(code_result, str) or _DATA_RE.fullmatch(code_result) is None:
                raise HeliosConsensusError("Helios returned malformed contract code at the deposit block")
            runtime_code = bytes.fromhex(code_result[2:])
            observed_fingerprint = runtime_code_fingerprint(runtime_code)
        except HeliosConsensusError:
            raise
        except Exception:
            raise HeliosConsensusError("could not authenticate protocol runtime code at the deposit block") from None
        if observed_fingerprint != self._policy.expected_runtime_code_fingerprint:
            raise HeliosConsensusError("protocol runtime code at the deposit block differs from the pinned manifest")
        return HeliosAuthenticatedEvmDeposit(inclusion, authenticated_header)
