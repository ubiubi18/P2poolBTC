#!/usr/bin/env python3
"""Mine a bounded number of easy PoHW blocks through a loopback Stratum adapter."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import time
from typing import BinaryIO, Callable, NamedTuple


MAX_JSON_LINE_BYTES = 1024 * 1024
MAX_COINBASE_BYTES = 1024 * 1024
MAX_MERKLE_BRANCHES = 512
MAX_HASHES_LIMIT = 10_000_000
MAX_ERROR_SUMMARY_CHARS = 240
MAX_TX_INPUTS = 100_000
MAX_TX_OUTPUTS = 100_000
MAX_WITNESS_ITEMS = 100_000
EXPECTED_NO_SOLUTION_ERRORS = frozenset(
    {
        "hash limit reached without a block-valid share",
        "mining timeout reached",
    }
)


class SmokeMineError(ValueError):
    pass


class StratumJob(NamedTuple):
    job_id: str
    prevhash: str
    coinbase1: str
    coinbase2: str
    merkle_branches: tuple[str, ...]
    version: str
    nbits: str
    ntime: str


def _stratum_error_summary(error: object) -> str:
    if not isinstance(error, list) or len(error) < 2:
        return "malformed Stratum error"
    code = error[0] if isinstance(error[0], int) and not isinstance(error[0], bool) else "unknown"
    message = error[1] if isinstance(error[1], str) else "malformed error message"
    message = "".join(char if 32 <= ord(char) <= 126 else "?" for char in message)
    message = re.sub(r"(?i)\b0x[0-9a-f]{40,}\b", "<address>", message)
    message = re.sub(r"(?i)\b[0-9a-f]{64,128}\b", "<hex>", message)
    message = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", "<ip>", message)
    message = re.sub(r"(?i)\b(password|secret|token|cookie|key)=\S+", r"\1=<redacted>", message)
    message = re.sub(r"(?<![A-Za-z0-9._-])/(?:[^\s:]+/?)+", "<path>", message)
    if len(message) > MAX_ERROR_SUMMARY_CHARS:
        message = message[: MAX_ERROR_SUMMARY_CHARS - 3] + "..."
    return f"Stratum error code={code}: {message}"


def _decode_hex(label: str, value: object, expected_bytes: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise SmokeMineError(f"{label} must be a hex string")
    if len(value) % 2:
        raise SmokeMineError(f"{label} must contain complete bytes")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise SmokeMineError(f"{label} contains invalid hex") from exc
    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise SmokeMineError(f"{label} must be exactly {expected_bytes} bytes")
    return decoded


def parse_notify(params: object) -> StratumJob:
    if not isinstance(params, list) or len(params) != 9:
        raise SmokeMineError("mining.notify must contain exactly 9 parameters")
    job_id, prevhash, coinbase1, coinbase2, branches, version, nbits, ntime, clean = params
    if not isinstance(job_id, str) or not job_id or len(job_id) > 256:
        raise SmokeMineError("job id must be a non-empty bounded string")
    _decode_hex("previous block hash", prevhash, 32)
    first = _decode_hex("coinbase1", coinbase1)
    second = _decode_hex("coinbase2", coinbase2)
    if len(first) + len(second) > MAX_COINBASE_BYTES:
        raise SmokeMineError("coinbase template exceeds the size limit")
    if not isinstance(branches, list) or len(branches) > MAX_MERKLE_BRANCHES:
        raise SmokeMineError("merkle branch list exceeds the size limit")
    for branch in branches:
        _decode_hex("merkle branch", branch, 32)
    _decode_hex("version", version, 4)
    _decode_hex("nbits", nbits, 4)
    _decode_hex("ntime", ntime, 4)
    if not isinstance(clean, bool):
        raise SmokeMineError("clean-jobs flag must be boolean")
    return StratumJob(
        job_id=job_id,
        prevhash=prevhash.lower(),
        coinbase1=coinbase1.lower(),
        coinbase2=coinbase2.lower(),
        merkle_branches=tuple(branch.lower() for branch in branches),
        version=version.lower(),
        nbits=nbits.lower(),
        ntime=ntime.lower(),
    )


def compact_target_from_header_bits(nbits: str) -> int:
    raw = _decode_hex("nbits", nbits, 4)
    compact = int.from_bytes(raw, "little")
    exponent = compact >> 24
    mantissa = compact & 0x007FFFFF
    if compact & 0x00800000 or mantissa == 0:
        raise SmokeMineError("nbits encodes a negative or zero target")
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if not 0 < target < 1 << 256:
        raise SmokeMineError("nbits target is outside the uint256 range")
    return target


def sha256d(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def _read_compact_size(payload: bytes, offset: int, label: str) -> tuple[int, int]:
    if offset >= len(payload):
        raise SmokeMineError(f"{label} compact size is truncated")
    first = payload[offset]
    if first < 0xFD:
        return first, offset + 1
    widths = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    width = widths[first]
    end = offset + 1 + width
    if end > len(payload):
        raise SmokeMineError(f"{label} compact size is truncated")
    value = int.from_bytes(payload[offset + 1 : end], "little")
    minimum = {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[first]
    if value < minimum:
        raise SmokeMineError(f"{label} compact size is non-canonical")
    return value, end


def _advance(payload: bytes, offset: int, length: int, label: str) -> int:
    if length < 0 or offset > len(payload) or length > len(payload) - offset:
        raise SmokeMineError(f"{label} is truncated")
    return offset + length


def transaction_without_witness(payload: bytes) -> bytes:
    if len(payload) < 10:
        raise SmokeMineError("coinbase transaction is truncated")
    cursor = 4
    has_witness = payload[cursor] == 0
    if has_witness:
        if cursor + 1 >= len(payload) or payload[cursor + 1] != 1:
            raise SmokeMineError("coinbase transaction has an unsupported witness flag")
        cursor += 2
    body_start = cursor

    input_count, cursor = _read_compact_size(payload, cursor, "input count")
    if not 1 <= input_count <= MAX_TX_INPUTS:
        raise SmokeMineError("coinbase transaction input count is outside the limit")
    for _ in range(input_count):
        cursor = _advance(payload, cursor, 36, "transaction input outpoint")
        script_size, cursor = _read_compact_size(payload, cursor, "input script")
        cursor = _advance(payload, cursor, script_size, "input script")
        cursor = _advance(payload, cursor, 4, "transaction input sequence")

    output_count, cursor = _read_compact_size(payload, cursor, "output count")
    if output_count > MAX_TX_OUTPUTS:
        raise SmokeMineError("coinbase transaction output count exceeds the limit")
    for _ in range(output_count):
        cursor = _advance(payload, cursor, 8, "transaction output value")
        script_size, cursor = _read_compact_size(payload, cursor, "output script")
        cursor = _advance(payload, cursor, script_size, "output script")
    outputs_end = cursor

    if has_witness:
        for _ in range(input_count):
            item_count, cursor = _read_compact_size(payload, cursor, "witness item count")
            if item_count > MAX_WITNESS_ITEMS:
                raise SmokeMineError("coinbase witness item count exceeds the limit")
            for _ in range(item_count):
                item_size, cursor = _read_compact_size(payload, cursor, "witness item")
                cursor = _advance(payload, cursor, item_size, "witness item")

    locktime_start = cursor
    cursor = _advance(payload, cursor, 4, "transaction locktime")
    if cursor != len(payload):
        raise SmokeMineError("coinbase transaction contains trailing bytes")
    if not has_witness:
        return payload
    return payload[:4] + payload[body_start:outputs_end] + payload[locktime_start:cursor]


def build_header(job: StratumJob, extranonce1: str, extranonce2: str, nonce: int) -> bytes:
    extra1 = _decode_hex("extranonce1", extranonce1)
    extra2 = _decode_hex("extranonce2", extranonce2)
    coinbase = (
        _decode_hex("coinbase1", job.coinbase1)
        + extra1
        + extra2
        + _decode_hex("coinbase2", job.coinbase2)
    )
    if len(coinbase) > MAX_COINBASE_BYTES:
        raise SmokeMineError("completed coinbase exceeds the size limit")
    merkle = sha256d(transaction_without_witness(coinbase))
    for branch in job.merkle_branches:
        merkle = sha256d(merkle + _decode_hex("merkle branch", branch, 32))
    header = b"".join(
        (
            _decode_hex("version", job.version, 4),
            _decode_hex("previous block hash", job.prevhash, 32),
            merkle,
            _decode_hex("ntime", job.ntime, 4),
            _decode_hex("nbits", job.nbits, 4),
            nonce.to_bytes(4, "little"),
        )
    )
    if len(header) != 80:
        raise SmokeMineError("constructed header is not 80 bytes")
    return header


def find_nonce(
    job: StratumJob,
    extranonce1: str,
    extranonce2: str,
    max_hashes: int,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[int, int]:
    if not 1 <= max_hashes <= MAX_HASHES_LIMIT:
        raise SmokeMineError(f"max hashes must be between 1 and {MAX_HASHES_LIMIT}")
    target = compact_target_from_header_bits(job.nbits)
    for nonce in range(max_hashes):
        if nonce % 4096 == 0 and clock() > deadline:
            raise SmokeMineError("mining timeout reached")
        digest = sha256d(build_header(job, extranonce1, extranonce2, nonce))
        if int.from_bytes(digest, "little") <= target:
            return nonce, nonce + 1
    raise SmokeMineError("hash limit reached without a block-valid share")


def _send(stream: BinaryIO, message: dict[str, object]) -> None:
    encoded = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if len(encoded) > MAX_JSON_LINE_BYTES:
        raise SmokeMineError("outbound Stratum message exceeds the size limit")
    stream.write(encoded)
    stream.flush()


def _read(stream: BinaryIO) -> dict[str, object]:
    raw = stream.readline(MAX_JSON_LINE_BYTES + 1)
    if not raw:
        raise SmokeMineError("Stratum connection closed")
    if len(raw) > MAX_JSON_LINE_BYTES or not raw.endswith(b"\n"):
        raise SmokeMineError("inbound Stratum message exceeds the size limit")
    try:
        message = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SmokeMineError("Stratum returned invalid JSON") from exc
    if not isinstance(message, dict):
        raise SmokeMineError("Stratum message must be an object")
    return message


def _wait_for_response(
    stream: BinaryIO,
    request_id: int,
    latest_job: list[StratumJob | None],
) -> dict[str, object]:
    while True:
        message = _read(stream)
        if message.get("method") == "mining.notify":
            latest_job[0] = parse_notify(message.get("params"))
            continue
        if message.get("id") == request_id:
            error = message.get("error")
            if error is not None:
                raise SmokeMineError(_stratum_error_summary(error))
            return message


def mine_one(host: str, port: int, worker: str, max_hashes: int, timeout: float) -> int:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise SmokeMineError("Stratum host must be a numeric loopback address") from exc
    if not address.is_loopback:
        raise SmokeMineError("smoke miner refuses non-loopback Stratum endpoints")
    if not 1 <= port <= 65535:
        raise SmokeMineError("Stratum port is outside the valid range")
    if not worker or len(worker) > 128 or any(ord(char) < 33 or ord(char) > 126 for char in worker):
        raise SmokeMineError("worker name must be 1-128 printable non-space ASCII bytes")
    if not 0 < timeout <= 300:
        raise SmokeMineError("timeout must be between 0 and 300 seconds")

    deadline = time.monotonic() + timeout
    with socket.create_connection((str(address), port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        with connection.makefile("rwb", buffering=0) as stream:
            jobs: list[StratumJob | None] = [None]
            _send(stream, {"id": 1, "method": "mining.subscribe", "params": []})
            subscribed = _wait_for_response(stream, 1, jobs)
            result = subscribed.get("result")
            if not isinstance(result, list) or len(result) != 3:
                raise SmokeMineError("mining.subscribe returned an invalid result")
            extranonce1 = result[1]
            extranonce2_size = result[2]
            _decode_hex("extranonce1", extranonce1)
            if isinstance(extranonce2_size, bool) or not isinstance(extranonce2_size, int):
                raise SmokeMineError("extranonce2 size must be an integer")
            if not 1 <= extranonce2_size <= 32:
                raise SmokeMineError("extranonce2 size is outside the supported range")

            _send(stream, {"id": 2, "method": "mining.authorize", "params": [worker, ""]})
            authorized = _wait_for_response(stream, 2, jobs)
            if authorized.get("result") is not True:
                raise SmokeMineError("Stratum authorization failed")
            while jobs[0] is None:
                message = _read(stream)
                if message.get("method") == "mining.notify":
                    jobs[0] = parse_notify(message.get("params"))
            job = jobs[0]
            assert job is not None
            extranonce2 = "00" * extranonce2_size
            nonce, hashes = find_nonce(job, extranonce1, extranonce2, max_hashes, deadline)
            _send(
                stream,
                {
                    "id": 3,
                    "method": "mining.submit",
                    "params": [worker, job.job_id, extranonce2, job.ntime, nonce.to_bytes(4, "little").hex()],
                },
            )
            submitted = _wait_for_response(stream, 3, jobs)
            if submitted.get("result") is not True:
                raise SmokeMineError("block-valid share was not accepted")
            return hashes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mine one bounded no-value Experiment 1 block through loopback Stratum."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3333)
    parser.add_argument("--worker", default="experiment-1-smoke")
    parser.add_argument("--max-hashes", type=int, default=1_000_000)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument(
        "--allow-no-solution",
        action="store_true",
        help="return success when the bounded hash or time limit is reached",
    )
    args = parser.parse_args()
    try:
        hashes = mine_one(args.host, args.port, args.worker, args.max_hashes, args.timeout_seconds)
        print(f"Stratum accepted one block-valid Experiment 1 share after {hashes} hashes")
        return 0
    except SmokeMineError as exc:
        if args.allow_no_solution and str(exc) in EXPECTED_NO_SOLUTION_ERRORS:
            print("Bounded Experiment 1 mining attempt completed without an accepted block")
            return 0
        print(f"smoke mine failed: {exc}", file=__import__("sys").stderr)
        return 1
    except OSError as exc:
        print(f"smoke mine failed: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
