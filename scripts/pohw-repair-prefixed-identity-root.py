#!/usr/bin/env python3
"""Quarantine legacy PoHW commitments with a prefixed identity root.

The early Experiment 1 bootstrap wrote one otherwise well-formed commitment
with a ``0x``-prefixed identity proof root. Commitments require canonical,
unprefixed 32-byte hex. The malformed message was never valid, so this tool
removes only that message and its signed gossip envelope while preserving and
backing up every valid record byte-for-byte.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import time
from pathlib import Path


HEX_32 = re.compile(r"^[0-9a-fA-F]{64}$")
PREFIXED_HEX_32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
MAX_LOG_BYTES = 256 * 1024 * 1024
LOGS = ("sharechain.ndjson", "gossip-envelopes.ndjson")
LOCK_NAME = "sharechain.append.lock"


class RepairError(ValueError):
    pass


def read_regular(path: Path, label: str, *, required: bool = True) -> tuple[bytes, os.stat_result] | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        if required:
            raise RepairError(f"missing {label}")
        return None
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise RepairError(f"{label} must be a regular non-symlink file")
    if before.st_size > MAX_LOG_BYTES:
        raise RepairError(f"{label} exceeds the size limit")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise RepairError(f"{label} changed while reading")
    if len(raw) != opened.st_size:
        raise RepairError(f"short read from {label}")
    return raw, opened


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def malformed_prefixed_commitment(message: object) -> bool:
    if not isinstance(message, dict) or message.get("type") != "PohwCommitment":
        return False
    payload = message.get("payload")
    if not isinstance(payload, dict) or payload.get("version") != "POHW1":
        return False
    root = payload.get("identity_proof_root")
    if not isinstance(root, str) or PREFIXED_HEX_32.fullmatch(root) is None:
        return False
    for key in (
        "idena_score_root",
        "sharechain_tip",
        "payout_schedule_root",
        "frost_vault_key_xonly",
    ):
        value = payload.get(key)
        if not isinstance(value, str) or HEX_32.fullmatch(value) is None:
            return False
    state_root = payload.get("sharechain_state_root")
    if state_root is not None and (
        not isinstance(state_root, str) or HEX_32.fullmatch(state_root) is None
    ):
        return False
    return True


def parse_lines(raw: bytes, label: str) -> list[tuple[bytes, object]]:
    records: list[tuple[bytes, object]] = []
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.strip():
            records.append((line, None))
            continue
        if not line.endswith(b"\n"):
            raise RepairError(f"{label} has an unterminated line {number}")
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RepairError(f"{label} has invalid JSON at line {number}") from error
        records.append((line, value))
    return records


def write_new_file(path: Path, raw: bytes, metadata: os.stat_result) -> Path:
    temporary = path.with_name(f".{path.name}.repair-{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        stat.S_IMODE(metadata.st_mode),
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def backup_file(path: Path, raw: bytes, metadata: os.stat_result) -> Path:
    backup = path.with_name(path.name + ".pre-prefixed-identity-root-repair")
    if backup.exists() or backup.is_symlink():
        raise RepairError(f"backup already exists for {path.name}")
    temporary = write_new_file(backup, raw, metadata)
    os.replace(temporary, backup)
    return backup


def acquire_lock(datadir: Path) -> tuple[Path, str]:
    path = datadir / LOCK_NAME
    token = f"{os.getpid()} {int(time.time())}"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(token)
        stream.flush()
        os.fsync(stream.fileno())
    return path, token


def release_lock(path: Path, token: str) -> None:
    try:
        if path.read_text(encoding="ascii").strip() == token:
            path.unlink()
    except OSError:
        pass


def repair(datadir: Path, apply: bool) -> tuple[int, int]:
    metadata = datadir.lstat()
    if datadir.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise RepairError("datadir must be a non-symlink directory")
    datadir = datadir.resolve(strict=True)
    lock_path, lock_token = acquire_lock(datadir)
    try:
        parsed: dict[str, list[tuple[bytes, object]]] = {}
        source: dict[str, tuple[bytes, os.stat_result]] = {}
        for name in LOGS:
            raw, info = read_regular(datadir / name, name)  # type: ignore[misc]
            source[name] = (raw, info)
            parsed[name] = parse_lines(raw, name)

        payout = read_regular(
            datadir / "confirmed-payouts.ndjson", "confirmed payout log", required=False
        )
        if payout is not None and payout[0].strip():
            raise RepairError("refusing repair after a confirmed payout exists")

        invalid_messages = {
            canonical(value)
            for _, value in parsed["sharechain.ndjson"]
            if malformed_prefixed_commitment(value)
        }
        invalid_envelopes: set[str] = set()
        for _, value in parsed["gossip-envelopes.ndjson"]:
            if not isinstance(value, dict):
                continue
            envelope = value.get("envelope")
            message = envelope.get("message") if isinstance(envelope, dict) else None
            if malformed_prefixed_commitment(message):
                invalid_envelopes.add(canonical(message))
        if invalid_messages != invalid_envelopes:
            raise RepairError("sharechain and signed-envelope commitment sets differ")
        if not invalid_messages:
            return 0, 0

        removed: list[dict[str, object]] = []
        rewritten: dict[str, bytes] = {}
        for name, records in parsed.items():
            kept: list[bytes] = []
            for number, (raw_line, value) in enumerate(records, 1):
                message = value
                if name == "gossip-envelopes.ndjson" and isinstance(value, dict):
                    envelope = value.get("envelope")
                    message = envelope.get("message") if isinstance(envelope, dict) else None
                if malformed_prefixed_commitment(message):
                    removed.append({"log": name, "line": number, "record": value})
                else:
                    kept.append(raw_line)
            rewritten[name] = b"".join(kept)

        if not apply:
            return len(invalid_messages), len(removed)

        quarantine = datadir / "quarantine-prefixed-identity-root.json"
        if quarantine.exists() or quarantine.is_symlink():
            raise RepairError("quarantine file already exists")
        quarantine_raw = (
            json.dumps(
                {"schemaVersion": 1, "reason": "noncanonical-0x-identity-proof-root", "records": removed},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
        descriptor = os.open(
            quarantine,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(quarantine_raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(quarantine, metadata.st_uid, metadata.st_gid)

        staged: dict[str, Path] = {}
        for name, raw in rewritten.items():
            original_raw, info = source[name]
            backup_file(datadir / name, original_raw, info)
            staged[name] = write_new_file(datadir / name, raw, info)
        for name in LOGS:
            os.replace(staged[name], datadir / name)

        index = datadir / "sharechain-index.json"
        index_data = read_regular(index, "sharechain index", required=False)
        if index_data is not None:
            backup_file(index, index_data[0], index_data[1])
            index.unlink()
        directory = os.open(datadir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return len(invalid_messages), len(removed)
    finally:
        release_lock(lock_path, lock_token)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--datadir", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    commitments, records = repair(args.datadir, args.apply)
    mode = "applied" if args.apply else "audit"
    print(f"mode={mode}")
    print(f"invalid_commitments={commitments}")
    print(f"quarantined_records={records if args.apply else 0}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
