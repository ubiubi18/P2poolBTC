#!/usr/bin/env python3
"""Forward Idena session recorder for PoHW replay.

This recorder stores only verifiable local-node observations: block headers,
session/consensus flags, transaction hashes, and optional transaction JSON. It
does not classify rewards. Exact reward events must be produced by a separate
replay engine that consumes this cache and validates computed roots.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from idena_rpc_client_minimal import IdenaRPCClientMinimal, IdenaRPCError
except ModuleNotFoundError:
    try:
        from .idena_rpc_client_minimal import IdenaRPCClientMinimal, IdenaRPCError
    except (ImportError, ModuleNotFoundError):
        IdenaRPCClientMinimal = None  # type: ignore[assignment]

        class IdenaRPCError(Exception):
            pass


DATA_DIR = Path("data/idena-session-recorder")
DB_PATH = DATA_DIR / "session_recorder.sqlite3"
POLL_INTERVAL_SECONDS = 10
MAX_BLOCKS_PER_PASS = 250
MAX_TRANSACTION_FETCHES_PER_BLOCK = 2_000
MAX_TEXT_FIELD_BYTES = 4_096
ADDRESS_RE = re.compile(r"^0x[a-f0-9]{40}$")
HASH_RE = re.compile(r"^0x[a-f0-9]{64}$")
SESSION_PROGRESS_FLAGS = {
    "FlipLotteryStarted",
    "ShortSessionStarted",
    "LongSessionStarted",
    "AfterLongSessionStarted",
}
SESSION_CLOSE_FLAG = "ValidationFinished"
REPLAY_RELEVANT_FLAGS = SESSION_PROGRESS_FLAGS | {
    SESSION_CLOSE_FLAG,
    "IdentityUpdate",
    "OfflinePropose",
    "OfflineCommit",
    "Snapshot",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def normalize_address(value: Any) -> str:
    return str(value or "").strip().lower()


def normalize_hash(value: Any) -> str:
    return str(value or "").strip().lower()


def validate_optional_address(value: Any, field: str) -> str:
    address = normalize_address(value)
    if not address:
        return ""
    if not ADDRESS_RE.fullmatch(address):
        raise ValueError(f"{field} must be a 20-byte hex Idena address")
    return address


def validate_hash(value: Any, field: str) -> str:
    digest = normalize_hash(value)
    if not HASH_RE.fullmatch(digest):
        raise ValueError(f"{field} must be a 32-byte hex hash")
    return digest


def validate_optional_hash(value: Any, field: str) -> str:
    digest = normalize_hash(value)
    if not digest:
        return ""
    if not HASH_RE.fullmatch(digest):
        raise ValueError(f"{field} must be a 32-byte hex hash")
    return digest


def safe_text(value: Any, field: str, *, max_bytes: int = MAX_TEXT_FIELD_BYTES) -> str:
    text = str(value or "")
    if len(text.encode("utf-8")) > max_bytes or any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{field} must be printable and no longer than {max_bytes} bytes")
    return text


def safe_payload_text(value: Any, field: str, *, max_bytes: int = MAX_TEXT_FIELD_BYTES) -> str:
    text = str(value or "")
    text_bytes = text.encode("utf-8")
    if len(text_bytes) <= max_bytes and all(ord(ch) >= 32 for ch in text):
        return text

    encoded = json.dumps(text, ensure_ascii=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) <= max_bytes:
        return f"json:{encoded}"

    digest = hashlib.sha256(text_bytes).hexdigest()
    preview = text_bytes[:256].hex()
    return f"sha256:{digest};bytes:{len(text_bytes)};head_hex:{preview}"


def parse_int(value: Any, field: str, *, minimum: int = 0) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError
        parsed = int(str(value), 10)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if parsed < minimum:
        raise ValueError(f"{field} must be >= {minimum}")
    return parsed


def idena_sync_ready(sync_state: Dict[str, Any]) -> bool:
    if bool(sync_state.get("wrongTime")):
        return False
    if not bool(sync_state.get("syncing")):
        return True
    current_block = parse_int(sync_state.get("currentBlock") or 0, "sync.currentBlock", minimum=0)
    highest_block = parse_int(sync_state.get("highestBlock") or 0, "sync.highestBlock", minimum=0)
    return highest_block > 0 and current_block >= highest_block


def validate_rpc_url(raw_url: str, *, allow_remote_rpc: bool = False) -> str:
    if not raw_url or len(raw_url) > 2048 or any(ord(ch) < 32 for ch in raw_url):
        raise ValueError("Idena RPC URL is empty, too long, or contains control characters")
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Idena RPC URL scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("Idena RPC URL must include a host")
    if parsed.username or parsed.password:
        raise ValueError("Idena RPC URL must not include userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("Idena RPC URL must not include query or fragment data")
    host = parsed.hostname
    if host.lower() == "localhost":
        return raw_url
    try:
        if ipaddress.ip_address(host).is_loopback:
            return raw_url
    except ValueError:
        pass
    if allow_remote_rpc:
        return raw_url
    raise ValueError("Idena RPC URL must be loopback unless remote RPC is explicitly allowed")


def normalize_flags(block: Dict[str, Any]) -> List[str]:
    raw_flags = block.get("flags") or []
    if not isinstance(raw_flags, list):
        raise ValueError("block flags must be an array")
    flags = sorted({str(flag).strip() for flag in raw_flags if str(flag).strip()})
    for flag in flags:
        if len(flag) > 64 or any(ord(ch) < 32 for ch in flag):
            raise ValueError(f"invalid block flag: {flag!r}")
    return flags


def normalize_transaction_hashes(block: Dict[str, Any]) -> List[str]:
    raw_transactions = block.get("transactions") or []
    if not isinstance(raw_transactions, list):
        raise ValueError("block transactions must be an array")
    return [validate_hash(tx_hash, "transaction hash") for tx_hash in raw_transactions]


def normalize_block(block: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(block, dict):
        raise ValueError("block must be a JSON object")
    height = parse_int(block.get("height"), "block.height", minimum=1)
    timestamp = parse_int(block.get("timestamp"), "block.timestamp", minimum=0)
    block_hash = validate_hash(block.get("hash"), "block.hash")
    parent_hash = validate_optional_hash(block.get("parentHash") or block.get("parent_hash"), "block.parentHash")
    root = validate_hash(block.get("root"), "block.root")
    identity_root = validate_hash(block.get("identityRoot") or block.get("identity_root"), "block.identityRoot")
    return {
        "height": height,
        "hash": block_hash,
        "parent_hash": parent_hash,
        "timestamp": timestamp,
        "root": root,
        "identity_root": identity_root,
        "coinbase": validate_optional_address(block.get("coinbase"), "block.coinbase"),
        "is_empty": bool(block.get("isEmpty") or block.get("is_empty")),
        "ipfs_cid": safe_text(block.get("ipfsCid"), "block.ipfsCid"),
        "offline_address": validate_optional_address(
            block.get("offlineAddress") or block.get("offline_address"),
            "block.offlineAddress",
        ),
        "flags": normalize_flags(block),
        "transaction_hashes": normalize_transaction_hashes(block),
        "raw": block,
    }


def normalize_transaction(tx_hash: str, tx: Any) -> Dict[str, Any]:
    if not isinstance(tx, dict):
        raise ValueError(f"transaction {tx_hash} must be a JSON object")
    return {
        "hash": validate_hash(tx.get("hash") or tx_hash, "transaction.hash"),
        "type": safe_text(tx.get("type"), "transaction.type", max_bytes=128),
        "from": validate_optional_address(tx.get("from"), "transaction.from"),
        "to": validate_optional_address(tx.get("to"), "transaction.to"),
        "amount": safe_text(tx.get("amount") or "0", "transaction.amount", max_bytes=128),
        "tips": safe_text(tx.get("tips") or "0", "transaction.tips", max_bytes=128),
        "max_fee": safe_text(tx.get("maxFee") or "0", "transaction.maxFee", max_bytes=128),
        "used_fee": safe_text(tx.get("usedFee") or "0", "transaction.usedFee", max_bytes=128),
        "epoch": parse_int(tx.get("epoch") or 0, "transaction.epoch", minimum=0),
        "nonce": parse_int(tx.get("nonce") or 0, "transaction.nonce", minimum=0),
        "payload": safe_payload_text(tx.get("payload"), "transaction.payload"),
        "raw": tx,
    }


class SessionLedger:
    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        self.path = prepare_sqlite_database_path(
            path,
            "session recorder database",
            read_only=read_only,
        )
        if read_only:
            self.conn = sqlite3.connect(sqlite_readonly_uri(self.path), uri=True)
        else:
            self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        if not read_only:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.ensure_schema()

    def close(self) -> None:
        self.conn.close()

    def ensure_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocks (
              height INTEGER PRIMARY KEY,
              hash TEXT NOT NULL,
              parent_hash TEXT NOT NULL,
              timestamp INTEGER NOT NULL,
              root TEXT NOT NULL,
              identity_root TEXT NOT NULL,
              coinbase TEXT NOT NULL,
              is_empty INTEGER NOT NULL,
              ipfs_cid TEXT NOT NULL,
              offline_address TEXT NOT NULL,
              flags_json TEXT NOT NULL,
              transaction_hashes_json TEXT NOT NULL,
              raw_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_session_blocks_hash ON blocks(hash);
            CREATE TABLE IF NOT EXISTS block_transactions (
              block_height INTEGER NOT NULL,
              tx_hash TEXT NOT NULL,
              tx_index INTEGER NOT NULL,
              tx_type TEXT NOT NULL,
              from_address TEXT NOT NULL,
              to_address TEXT NOT NULL,
              amount TEXT NOT NULL,
              tips TEXT NOT NULL,
              max_fee TEXT NOT NULL,
              used_fee TEXT NOT NULL,
              epoch INTEGER NOT NULL,
              nonce INTEGER NOT NULL,
              payload TEXT NOT NULL,
              raw_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY(block_height, tx_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_session_block_transactions_hash
              ON block_transactions(tx_hash);
            CREATE TABLE IF NOT EXISTS sessions (
              start_height INTEGER PRIMARY KEY,
              start_hash TEXT NOT NULL,
              start_timestamp INTEGER NOT NULL,
              end_height INTEGER,
              end_hash TEXT,
              end_timestamp INTEGER,
              status TEXT NOT NULL,
              flags_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
            CREATE TABLE IF NOT EXISTS session_events (
              id TEXT PRIMARY KEY,
              block_height INTEGER NOT NULL,
              block_hash TEXT NOT NULL,
              timestamp INTEGER NOT NULL,
              flag TEXT NOT NULL,
              session_start_height INTEGER,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_session_events_height ON session_events(block_height);
            CREATE INDEX IF NOT EXISTS idx_session_events_flag ON session_events(flag, block_height);
            """
        )
        self.conn.commit()

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    def open_session(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM sessions WHERE status = 'open' ORDER BY start_height DESC LIMIT 1"
        ).fetchone()

    def start_session(self, block: Dict[str, Any], *, status: str = "open") -> int:
        now = utc_now()
        flags = sorted(set(block["flags"]))
        self.conn.execute(
            """
            INSERT INTO sessions(
              start_height, start_hash, start_timestamp, end_height, end_hash,
              end_timestamp, status, flags_json, created_at, updated_at
            ) VALUES (?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?)
            ON CONFLICT(start_height) DO UPDATE SET
              start_hash = excluded.start_hash,
              start_timestamp = excluded.start_timestamp,
              status = excluded.status,
              flags_json = excluded.flags_json,
              updated_at = excluded.updated_at
            """,
            (
                block["height"],
                block["hash"],
                block["timestamp"],
                status,
                json.dumps(flags, sort_keys=True),
                now,
                now,
            ),
        )
        return int(block["height"])

    def close_session(self, start_height: int, block: Dict[str, Any]) -> None:
        row = self.conn.execute(
            "SELECT flags_json FROM sessions WHERE start_height = ?", (start_height,)
        ).fetchone()
        session_flags = set(json.loads(row["flags_json"] or "[]")) if row else set()
        session_flags.update(block["flags"])
        self.conn.execute(
            """
            UPDATE sessions
            SET end_height = ?, end_hash = ?, end_timestamp = ?, status = 'closed',
                flags_json = ?, updated_at = ?
            WHERE start_height = ?
            """,
            (
                block["height"],
                block["hash"],
                block["timestamp"],
                json.dumps(sorted(session_flags), sort_keys=True),
                utc_now(),
                start_height,
            ),
        )

    def abandon_open_session(self, block: Dict[str, Any]) -> None:
        open_row = self.open_session()
        if not open_row:
            return
        self.conn.execute(
            """
            UPDATE sessions
            SET end_height = ?, end_hash = ?, end_timestamp = ?, status = 'abandoned',
                updated_at = ?
            WHERE start_height = ?
            """,
            (
                max(0, int(block["height"]) - 1),
                "",
                block["timestamp"],
                utc_now(),
                int(open_row["start_height"]),
            ),
        )

    def record_block(self, raw_block: Dict[str, Any], transactions: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
        block = normalize_block(raw_block)
        existing = self.conn.execute(
            "SELECT hash FROM blocks WHERE height = ?",
            (block["height"],),
        ).fetchone()
        if existing is not None and str(existing["hash"]) != block["hash"]:
            raise ValueError(
                f"recorded block hash mismatch at height {block['height']}: "
                f"{existing['hash']} != {block['hash']}; manual recorder rewind required"
            )
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO blocks(
              height, hash, parent_hash, timestamp, root, identity_root, coinbase,
              is_empty, ipfs_cid, offline_address, flags_json, transaction_hashes_json,
              raw_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(height) DO UPDATE SET
              hash = excluded.hash,
              parent_hash = excluded.parent_hash,
              timestamp = excluded.timestamp,
              root = excluded.root,
              identity_root = excluded.identity_root,
              coinbase = excluded.coinbase,
              is_empty = excluded.is_empty,
              ipfs_cid = excluded.ipfs_cid,
              offline_address = excluded.offline_address,
              flags_json = excluded.flags_json,
              transaction_hashes_json = excluded.transaction_hashes_json,
              raw_json = excluded.raw_json
            """,
            (
                block["height"],
                block["hash"],
                block["parent_hash"],
                block["timestamp"],
                block["root"],
                block["identity_root"],
                block["coinbase"],
                1 if block["is_empty"] else 0,
                block["ipfs_cid"],
                block["offline_address"],
                json.dumps(block["flags"], sort_keys=True),
                json.dumps(block["transaction_hashes"], sort_keys=True),
                json.dumps(block["raw"], sort_keys=True),
                now,
            ),
        )
        if transactions is not None:
            self.record_transactions(block["height"], block["transaction_hashes"], transactions)
        self.record_session_flags(block)
        current_height = int(self.get_meta("last_scanned_height", "0") or 0)
        if block["height"] >= current_height:
            self.set_meta("last_scanned_height", block["height"])
            self.set_meta("last_scanned_hash", block["hash"])
        self.conn.commit()
        return block

    def record_transactions(
        self,
        block_height: int,
        transaction_hashes: Sequence[str],
        transactions: Sequence[Any],
    ) -> None:
        if len(transactions) != len(transaction_hashes):
            raise ValueError("transactions length must match block transaction hash count")
        now = utc_now()
        for index, (tx_hash, raw_tx) in enumerate(zip(transaction_hashes, transactions)):
            tx = normalize_transaction(tx_hash, raw_tx)
            if tx["hash"] and tx["hash"] != tx_hash:
                raise ValueError(f"transaction hash mismatch at block {block_height}: {tx['hash']} != {tx_hash}")
            self.conn.execute(
                """
                INSERT INTO block_transactions(
                  block_height, tx_hash, tx_index, tx_type, from_address, to_address,
                  amount, tips, max_fee, used_fee, epoch, nonce, payload, raw_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(block_height, tx_hash) DO UPDATE SET
                  tx_index = excluded.tx_index,
                  tx_type = excluded.tx_type,
                  from_address = excluded.from_address,
                  to_address = excluded.to_address,
                  amount = excluded.amount,
                  tips = excluded.tips,
                  max_fee = excluded.max_fee,
                  used_fee = excluded.used_fee,
                  epoch = excluded.epoch,
                  nonce = excluded.nonce,
                  payload = excluded.payload,
                  raw_json = excluded.raw_json
                """,
                (
                    block_height,
                    tx_hash,
                    index,
                    tx["type"],
                    tx["from"],
                    tx["to"],
                    tx["amount"],
                    tx["tips"],
                    tx["max_fee"],
                    tx["used_fee"],
                    tx["epoch"],
                    tx["nonce"],
                    tx["payload"],
                    json.dumps(tx["raw"], sort_keys=True),
                    now,
                ),
            )

    def record_session_flags(self, block: Dict[str, Any]) -> None:
        flags = set(block["flags"])
        relevant = sorted(flags & REPLAY_RELEVANT_FLAGS)
        if not relevant:
            return

        open_row = self.open_session()
        session_start_height: Optional[int] = int(open_row["start_height"]) if open_row else None
        if "FlipLotteryStarted" in flags and open_row and int(open_row["start_height"]) != block["height"]:
            self.abandon_open_session(block)
            open_row = None
            session_start_height = None
        if flags & SESSION_PROGRESS_FLAGS and open_row is None:
            session_start_height = self.start_session(block)
        elif open_row:
            current_flags = set(json.loads(open_row["flags_json"] or "[]"))
            current_flags.update(relevant)
            self.conn.execute(
                "UPDATE sessions SET flags_json = ?, updated_at = ? WHERE start_height = ?",
                (
                    json.dumps(sorted(current_flags), sort_keys=True),
                    utc_now(),
                    int(open_row["start_height"]),
                ),
            )

        if SESSION_CLOSE_FLAG in flags:
            if session_start_height is None:
                session_start_height = self.start_session(block, status="open")
            self.close_session(session_start_height, block)

        for flag in relevant:
            event_id = f"{block['height']}:{flag}"
            self.conn.execute(
                """
                INSERT OR IGNORE INTO session_events(
                  id, block_height, block_hash, timestamp, flag, session_start_height, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    block["height"],
                    block["hash"],
                    block["timestamp"],
                    flag,
                    session_start_height,
                    utc_now(),
                ),
            )

    def status(self) -> Dict[str, Any]:
        def scalar(sql: str) -> int:
            row = self.conn.execute(sql).fetchone()
            return int(row[0] or 0)

        open_session = self.open_session()
        recent_flags = self.conn.execute(
            """
            SELECT block_height, flag
            FROM session_events
            ORDER BY block_height DESC, flag
            LIMIT 20
            """
        ).fetchall()
        return {
            "db": str(self.path),
            "lastScannedHeight": int(self.get_meta("last_scanned_height", "0") or 0),
            "lastScannedHash": self.get_meta("last_scanned_hash", ""),
            "blocks": scalar("SELECT COUNT(*) FROM blocks"),
            "transactions": scalar("SELECT COUNT(*) FROM block_transactions"),
            "sessions": scalar("SELECT COUNT(*) FROM sessions"),
            "openSessionStartHeight": int(open_session["start_height"]) if open_session else None,
            "recentFlags": [dict(row) for row in recent_flags],
        }


def sqlite_readonly_uri(path: Path) -> str:
    return f"file:{urllib.parse.quote(str(Path(path)), safe='/')}?mode=ro"


def prepare_sqlite_database_path(path: Path, label: str, *, read_only: bool) -> Path:
    path = Path(path)
    parent = path.parent if path.parent != Path("") else Path(".")
    if read_only:
        reject_unsafe_symlink_ancestors(parent, f"{label} parent")
        validate_existing_sqlite_file(path, label, required=True)
    else:
        prepare_private_directory(parent, f"{label} parent")
        validate_existing_sqlite_file(path, label, required=False)
    return path


def prepare_private_directory(path: Path, label: str) -> None:
    path = Path(path)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        parent = path.parent if path.parent != Path("") else Path(".")
        if parent != path:
            prepare_private_directory(parent, label)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            prepare_private_directory(path, label)
        return
    except OSError as exc:
        raise ValueError(f"{label} is not inspectable: {path}: {exc}") from exc
    if os.path.islink(path):
        raise ValueError(f"{label} must not be a symlink: {path}")
    if not os.path.isdir(path):
        raise ValueError(f"{label} path must be a directory: {path}")
    if os.name == "posix" and metadata.st_mode & 0o022:
        raise ValueError(f"{label} is group/world writable: {path}")
    reject_unsafe_symlink_ancestors(path, label)


def validate_existing_sqlite_file(path: Path, label: str, *, required: bool) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        if required:
            raise ValueError(f"{label} file is missing: {path}")
        return
    except OSError as exc:
        raise ValueError(f"{label} file is not inspectable: {path}: {exc}") from exc
    if os.path.islink(path):
        raise ValueError(f"{label} file must not be a symlink: {path}")
    if not os.path.isfile(path):
        raise ValueError(f"{label} path must be a regular file: {path}")


def reject_unsafe_symlink_ancestors(path: Path, label: str) -> None:
    current = os.path.abspath(Path(path))
    while current and current != os.path.dirname(current):
        if os.path.islink(current):
            try:
                link_stat = os.lstat(current)
                parent_stat = os.lstat(os.path.dirname(current) or os.sep)
            except OSError as exc:
                raise ValueError(f"{label} symlink ancestor is not inspectable: {current}") from exc
            if link_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
                raise ValueError(f"{label} contains unsafe symlink ancestor: {current}")
        current = os.path.dirname(current)


def empty_status(path: Path) -> Dict[str, Any]:
    return {
        "db": str(path),
        "lastScannedHeight": 0,
        "lastScannedHash": "",
        "blocks": 0,
        "transactions": 0,
        "sessions": 0,
        "openSessionStartHeight": None,
        "recentFlags": [],
    }


class SessionRecorder:
    def __init__(
        self,
        *,
        ledger: SessionLedger,
        client: IdenaRPCClientMinimal,
        poll_interval: int,
        max_blocks_per_pass: int,
        fetch_transactions: bool,
    ) -> None:
        self.ledger = ledger
        self.client = client
        self.poll_interval = poll_interval
        self.max_blocks_per_pass = max_blocks_per_pass
        self.fetch_transactions = fetch_transactions

    def rpc(self, method: str, params: Optional[List[Any]] = None) -> Any:
        return self.client.call(method, params or [])

    def syncing(self) -> Dict[str, Any]:
        result = self.rpc("bcn_syncing", [])
        if not isinstance(result, dict):
            raise IdenaRPCError(f"unexpected bcn_syncing result: {type(result)}")
        return result

    def last_block(self) -> Dict[str, Any]:
        result = self.rpc("bcn_lastBlock", [])
        if not isinstance(result, dict):
            raise IdenaRPCError(f"unexpected bcn_lastBlock result: {type(result)}")
        return result

    def block_at(self, height: int) -> Dict[str, Any]:
        result = self.rpc("bcn_blockAt", [height])
        if not isinstance(result, dict):
            raise IdenaRPCError(f"unexpected bcn_blockAt result for {height}: {type(result)}")
        return result

    def transaction(self, tx_hash: str) -> Any:
        return self.rpc("bcn_transaction", [tx_hash])

    def scan_once(self, *, start_height: Optional[int] = None) -> Dict[str, Any]:
        sync_state = self.syncing()
        if not idena_sync_ready(sync_state):
            return {
                "status": "skipped",
                "reason": "idena node is syncing or reports wrong time",
                "syncing": bool(sync_state.get("syncing")),
                "wrongTime": bool(sync_state.get("wrongTime")),
                "currentBlock": int(sync_state.get("currentBlock") or 0),
                "highestBlock": int(sync_state.get("highestBlock") or 0),
            }
        head = normalize_block(self.last_block())
        cursor = int(self.ledger.get_meta("last_scanned_height", "0") or 0)
        if start_height is None:
            start = cursor + 1 if cursor else head["height"]
        else:
            start = start_height
        if start > head["height"]:
            return {
                "status": "caught_up",
                "headHeight": head["height"],
                "lastScannedHeight": cursor,
                "scannedBlocks": 0,
            }
        end = min(head["height"], start + self.max_blocks_per_pass - 1)
        return self.scan_range(start, end)

    def scan_range(self, start_height: int, end_height: int) -> Dict[str, Any]:
        if end_height < start_height:
            raise ValueError("end height must be >= start height")
        scanned = 0
        txs_fetched = 0
        flags_seen: List[Tuple[int, List[str]]] = []
        for height in range(start_height, end_height + 1):
            raw_block = self.block_at(height)
            block = normalize_block(raw_block)
            transactions: Optional[List[Any]] = None
            if self.fetch_transactions:
                if len(block["transaction_hashes"]) > MAX_TRANSACTION_FETCHES_PER_BLOCK:
                    raise ValueError(
                        f"block {height} has too many transactions to fetch safely: "
                        f"{len(block['transaction_hashes'])}"
                    )
                transactions = [self.transaction(tx_hash) for tx_hash in block["transaction_hashes"]]
                txs_fetched += len(transactions)
            self.ledger.record_block(raw_block, transactions)
            scanned += 1
            if block["flags"]:
                flags_seen.append((height, block["flags"]))
        return {
            "status": "scanned",
            "fromHeight": start_height,
            "toHeight": end_height,
            "scannedBlocks": scanned,
            "transactionsFetched": txs_fetched,
            "flagsSeen": [{"height": height, "flags": flags} for height, flags in flags_seen],
        }

    def run(self, *, start_height: Optional[int] = None) -> None:
        first_start = start_height
        while True:
            try:
                result = self.scan_once(start_height=first_start)
                first_start = None
                print(f"[INFO] {utc_now()} {json.dumps(result, sort_keys=True)}", flush=True)
            except (IdenaRPCError, OSError, ValueError, sqlite3.Error) as exc:
                print(f"[ERROR] {utc_now()} {exc}", file=sys.stderr, flush=True)
            time.sleep(self.poll_interval)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--rpc-url", default=os.getenv("IDENA_RPC_URL", "http://127.0.0.1:9009"))
    parser.add_argument("--api-key-file", default=os.getenv("IDENA_API_KEY_FILE", ""))
    parser.add_argument("--allow-remote-rpc", action="store_true")
    parser.add_argument("--poll-interval", type=int, default=POLL_INTERVAL_SECONDS)
    parser.add_argument("--max-blocks-per-pass", type=int, default=MAX_BLOCKS_PER_PASS)
    parser.add_argument("--no-transactions", action="store_true")
    parser.add_argument("--start-height", type=int)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run")
    sub.add_parser("once")
    sub.add_parser("status")
    scan_range = sub.add_parser("scan-range")
    scan_range.add_argument("from_height", type=int)
    scan_range.add_argument("to_height", type=int)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.max_blocks_per_pass <= 0 or args.max_blocks_per_pass > 10_000:
        print("error: --max-blocks-per-pass must be 1-10000", file=sys.stderr)
        return 2
    read_only = args.command == "status"
    if read_only and not args.db.exists():
        print_json(empty_status(args.db))
        return 0
    ledger = SessionLedger(args.db, read_only=read_only)
    try:
        if args.command == "status":
            print_json(ledger.status())
            return 0
        try:
            rpc_url = validate_rpc_url(args.rpc_url, allow_remote_rpc=args.allow_remote_rpc)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if IdenaRPCClientMinimal is None:
            raise RuntimeError("idena_rpc_client_minimal.py is required for RPC commands")
        client = IdenaRPCClientMinimal(
            url=rpc_url,
            api_key_file=args.api_key_file or None,
            timeout=20,
        )
        recorder = SessionRecorder(
            ledger=ledger,
            client=client,
            poll_interval=args.poll_interval,
            max_blocks_per_pass=args.max_blocks_per_pass,
            fetch_transactions=not args.no_transactions,
        )
        if args.command == "once":
            print_json(recorder.scan_once(start_height=args.start_height))
            return 0
        if args.command == "scan-range":
            print_json(recorder.scan_range(args.from_height, args.to_height))
            return 0
        if args.command == "run":
            recorder.run(start_height=args.start_height)
            return 0
    except (RuntimeError, IdenaRPCError, OSError, ValueError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        ledger.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
