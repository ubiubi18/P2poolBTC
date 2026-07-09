#!/usr/bin/env python3
"""Event-sourced Idena reward ledger.

This indexer is intentionally separate from provisional_rolling_indexer.py.
It stores observed balance/stake changes as ledger events, tracks invitee
locked-stake liabilities for ten epochs, and exposes a small query CLI.

The stock idena-go RPC does not expose the internal StatsCollector reward
events. Events produced from balance/stake deltas are therefore marked with a
confidence field so callers can distinguish exact observations from inferred
classifications.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ipaddress
import os
import re
import sqlite3
import subprocess
import sys
import time
import http.client
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    from idena_rpc_client_minimal import (
        IdenaRPCClientMinimal,
        IdenaRPCError,
        read_limited_rpc_response_body,
    )
except ModuleNotFoundError:
    try:
        from .idena_rpc_client_minimal import (
            IdenaRPCClientMinimal,
            IdenaRPCError,
            read_limited_rpc_response_body,
        )
    except (ImportError, ModuleNotFoundError):
        IdenaRPCClientMinimal = None  # type: ignore[assignment]
        read_limited_rpc_response_body = None  # type: ignore[assignment]

        class IdenaRPCError(Exception):
            pass


DATA_DIR = Path("data/rewards")
DB_PATH = DATA_DIR / "reward_ledger.sqlite3"
ROLLING_DATA_DIR = Path("data")
DEFAULT_OFFICIAL_INDEXER_SQL_FILE = (
    Path(__file__).resolve().parents[1] / "scripts" / "pohw-export-idena-indexer-rewards.sql"
)
DEFAULT_OFFICIAL_API_BASE_URL = "https://api.idena.io/api"
POLL_INTERVAL_SECONDS = 5
LIVE_SETTLE_SECONDS = 2.0
NON_ATOMIC_BACKOFF_SECONDS = 15.0
DNA_BASE = Decimal("1000000000000000000")
MAX_DATABASE_URL_BYTES = 4096
MAX_OFFICIAL_INDEXER_SQL_BYTES = 256 * 1024
MAX_OFFICIAL_INDEXER_EXPORT_BYTES = 512 * 1024 * 1024
MAX_OFFICIAL_API_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_ROLLING_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_ROLLING_DELTA_BYTES = 256 * 1024 * 1024
DEFAULT_PSQL_TIMEOUT_SECONDS = 300
DEFAULT_OFFICIAL_API_TIMEOUT_SECONDS = 30
DEFAULT_OFFICIAL_API_PAGE_LIMIT = 100
DEFAULT_OFFICIAL_API_RETRIES = 4
TRACKED_STATES = {"Candidate", "Newbie", "Verified", "Human", "Suspended", "Zombie"}
LIABILITY_WINDOW_EPOCHS = 10
STATS_COLLECTOR_SOURCE = "idena_stats_collector"
OFFICIAL_API_SOURCE = "idena_public_api"
REPLAY_KINDS = {
    "Validation",
    "Proposer",
    "FinalCommittee",
    "Invitation",
    "Invitee",
    "ContractOracle",
    "Other",
}
EXACT_LEDGER_KIND_BY_REPLAY_KIND = {
    "Validation": "stats_validation_reward",
    "Proposer": "stats_proposer_reward",
    "FinalCommittee": "stats_final_committee_reward",
    "Invitation": "stats_invitation_reward",
    "Invitee": "stats_invitee_reward",
    "ContractOracle": "stats_contract_oracle_reward",
    "Other": "stats_other_reward",
}
REPLAY_KIND_BY_LEDGER_KIND = {
    "session_reward": "Validation",
    "mining_proposer_reward": "Proposer",
    "staking_or_committee_reward": "FinalCommittee",
    "invitation_locked_reward": "Invitation",
    "invitation_unlock": "Invitation",
    "invitation_reversal_or_burn": "Invitation",
    **{ledger_kind: replay_kind for replay_kind, ledger_kind in EXACT_LEDGER_KIND_BY_REPLAY_KIND.items()},
}
ELIGIBLE_REPLAY_KIND_BY_LEDGER_KIND = {
    "session_reward": "Validation",
    "mining_proposer_reward": "Proposer",
    "staking_or_committee_reward": "FinalCommittee",
    "stats_validation_reward": "Validation",
    "stats_proposer_reward": "Proposer",
    "stats_final_committee_reward": "FinalCommittee",
}
IDENA_ADDRESS_RE = re.compile(r"^0x[a-f0-9]{40}$")
HASH_RE = re.compile(r"^0x[a-f0-9]{64}$")
BARE_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
OFFICIAL_VALIDATION_REWARD_KIND_BY_TYPE = {
    0: "Validation",  # Validation
    1: "Validation",  # Flips
    2: "Invitation",
    3: "Other",  # FoundationPayouts
    4: "Other",  # ZeroWalletFund
    5: "Invitation",
    6: "Invitation",
    7: "Invitation",  # SavedInvite
    8: "Invitation",  # SavedInviteWin
    9: "Validation",  # Reports
    10: "Validation",  # Staking
    11: "Validation",  # Candidate
    12: "Validation",  # ExtraFlips
    13: "Invitee",
    14: "Invitee",
    15: "Invitee",
}
OFFICIAL_VALIDATION_REWARD_TYPE_BY_NAME = {
    "validation": 0,
    "flips": 1,
    "invitations": 2,
    "foundationpayouts": 3,
    "zerowalletfund": 4,
    "invitations2": 5,
    "invitations3": 6,
    "savedinvite": 7,
    "savedinvitewin": 8,
    "reports": 9,
    "staking": 10,
    "candidate": 11,
    "extraflips": 12,
    "invitee": 13,
    "invitee2": 14,
    "invitee3": 15,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_address(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def normalize_hash(value: Any, label: str, *, required: bool = True) -> str:
    raw = "" if value is None else str(value).strip().lower()
    if not raw:
        if required:
            raise ValueError(f"{label} must be a 32-byte hex hash")
        return ""
    if raw.startswith("\\x"):
        raw = "0x" + raw[2:]
    elif BARE_HASH_RE.fullmatch(raw):
        raw = "0x" + raw
    if not HASH_RE.fullmatch(raw):
        raise ValueError(f"{label} must be a 32-byte hex hash")
    return raw


def decimal_to_atoms(value: Any) -> int:
    if value is None or value == "":
        return 0
    try:
        dec = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid decimal amount: {value!r}") from exc
    return int(dec * DNA_BASE)


def atoms_to_decimal_string(value: int) -> str:
    sign = "-" if value < 0 else ""
    value = abs(value)
    whole = value // 10**18
    frac = value % 10**18
    if frac == 0:
        return f"{sign}{whole}"
    return f"{sign}{whole}.{str(frac).rjust(18, '0').rstrip('0')}"


def parse_block_timestamp(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OSError):
        return utc_now()


def stable_event_id(parts: Sequence[Any]) -> str:
    payload = json.dumps([str(part) for part in parts], separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Position:
    address: str
    epoch: int
    state: str
    age: int
    balance_atoms: int
    stake_atoms: int
    replenished_stake_atoms: int
    locked_stake_atoms: int
    delegatee: str
    inviter_address: str
    inviter_tx_hash: str
    invite_epoch_height: Optional[int]
    updated_height: int
    updated_at: str
    raw: Dict[str, Any]


@dataclass(frozen=True)
class Delta:
    balance_atoms: int = 0
    stake_atoms: int = 0
    replenished_stake_atoms: int = 0
    locked_stake_atoms: int = 0

    @property
    def reward_atoms(self) -> int:
        return self.balance_atoms + self.stake_atoms


class RewardLedger:
    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        self.path = prepare_sqlite_database_path(
            path,
            "reward ledger database",
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
            CREATE TABLE IF NOT EXISTS positions (
              address TEXT PRIMARY KEY,
              epoch INTEGER NOT NULL,
              state TEXT NOT NULL,
              age INTEGER NOT NULL,
              balance_atoms TEXT NOT NULL,
              stake_atoms TEXT NOT NULL,
              replenished_stake_atoms TEXT NOT NULL,
              locked_stake_atoms TEXT NOT NULL,
              delegatee TEXT NOT NULL,
              inviter_address TEXT NOT NULL,
              inviter_tx_hash TEXT NOT NULL,
              invite_epoch_height INTEGER,
              updated_height INTEGER NOT NULL,
              updated_at TEXT NOT NULL,
              raw_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reward_events (
              id TEXT PRIMARY KEY,
              address TEXT NOT NULL,
              epoch INTEGER NOT NULL,
              height INTEGER NOT NULL,
              block_hash TEXT NOT NULL,
              timestamp TEXT NOT NULL,
              kind TEXT NOT NULL,
              direction TEXT NOT NULL,
              amount_atoms TEXT NOT NULL,
              balance_atoms_delta TEXT NOT NULL,
              stake_atoms_delta TEXT NOT NULL,
              replenished_stake_atoms_delta TEXT NOT NULL,
              locked_stake_atoms_delta TEXT NOT NULL,
              source TEXT NOT NULL,
              confidence TEXT NOT NULL,
              liability_status TEXT NOT NULL,
              counterparty_address TEXT NOT NULL,
              tx_hash TEXT NOT NULL,
              notes TEXT NOT NULL,
              raw_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reward_events_address_epoch
              ON reward_events(address, epoch, height);
            CREATE INDEX IF NOT EXISTS idx_reward_events_epoch_kind
              ON reward_events(epoch, kind, height);
            CREATE INDEX IF NOT EXISTS idx_reward_events_replay_export
              ON reward_events(kind, confidence, epoch, height);
            CREATE TABLE IF NOT EXISTS invitation_liabilities (
              id TEXT PRIMARY KEY,
              invitee_address TEXT NOT NULL,
              inviter_address TEXT NOT NULL,
              tx_hash TEXT NOT NULL,
              first_seen_epoch INTEGER NOT NULL,
              invite_epoch_height INTEGER,
              original_locked_atoms TEXT NOT NULL,
              current_locked_atoms TEXT NOT NULL,
              status TEXT NOT NULL,
              last_seen_epoch INTEGER NOT NULL,
              last_height INTEGER NOT NULL,
              raw_json TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_invitation_liabilities_invitee
              ON invitation_liabilities(invitee_address);
            CREATE INDEX IF NOT EXISTS idx_invitation_liabilities_status
              ON invitation_liabilities(status);
            CREATE TABLE IF NOT EXISTS block_cache (
              height INTEGER PRIMARY KEY,
              hash TEXT NOT NULL,
              coinbase TEXT NOT NULL,
              timestamp TEXT NOT NULL,
              flags_json TEXT NOT NULL,
              raw_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS coverage_gaps (
              id TEXT PRIMARY KEY,
              from_height INTEGER NOT NULL,
              to_height INTEGER NOT NULL,
              reason TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_meta(self, key: str, value: Any, *, commit: bool = True) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        if commit:
            self.conn.commit()

    def load_position(self, address: str) -> Optional[Position]:
        row = self.conn.execute(
            "SELECT * FROM positions WHERE address = ?", (normalize_address(address),)
        ).fetchone()
        if not row:
            return None
        return row_to_position(row)

    def upsert_position(self, pos: Position) -> None:
        self.conn.execute(
            """
            INSERT INTO positions(
              address, epoch, state, age, balance_atoms, stake_atoms,
              replenished_stake_atoms, locked_stake_atoms, delegatee,
              inviter_address, inviter_tx_hash, invite_epoch_height,
              updated_height, updated_at, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
              epoch = excluded.epoch,
              state = excluded.state,
              age = excluded.age,
              balance_atoms = excluded.balance_atoms,
              stake_atoms = excluded.stake_atoms,
              replenished_stake_atoms = excluded.replenished_stake_atoms,
              locked_stake_atoms = excluded.locked_stake_atoms,
              delegatee = excluded.delegatee,
              inviter_address = excluded.inviter_address,
              inviter_tx_hash = excluded.inviter_tx_hash,
              invite_epoch_height = excluded.invite_epoch_height,
              updated_height = excluded.updated_height,
              updated_at = excluded.updated_at,
              raw_json = excluded.raw_json
            """,
            (
                pos.address,
                pos.epoch,
                pos.state,
                pos.age,
                str(pos.balance_atoms),
                str(pos.stake_atoms),
                str(pos.replenished_stake_atoms),
                str(pos.locked_stake_atoms),
                pos.delegatee,
                pos.inviter_address,
                pos.inviter_tx_hash,
                pos.invite_epoch_height,
                pos.updated_height,
                pos.updated_at,
                json.dumps(pos.raw, sort_keys=True),
            ),
        )

    def insert_event(self, event: Dict[str, Any]) -> bool:
        columns = [
            "id",
            "address",
            "epoch",
            "height",
            "block_hash",
            "timestamp",
            "kind",
            "direction",
            "amount_atoms",
            "balance_atoms_delta",
            "stake_atoms_delta",
            "replenished_stake_atoms_delta",
            "locked_stake_atoms_delta",
            "source",
            "confidence",
            "liability_status",
            "counterparty_address",
            "tx_hash",
            "notes",
            "raw_json",
            "created_at",
        ]
        atom_columns = {
            "amount_atoms",
            "balance_atoms_delta",
            "stake_atoms_delta",
            "replenished_stake_atoms_delta",
            "locked_stake_atoms_delta",
        }
        values = [str(event[column]) if column in atom_columns else event[column] for column in columns]
        cur = self.conn.execute(
            f"INSERT OR IGNORE INTO reward_events({','.join(columns)}) "
            f"VALUES({','.join(['?'] * len(columns))})",
            values,
        )
        return cur.rowcount > 0

    def import_statscollector_replay_events(
        self,
        raw_events: Any,
        *,
        default_epoch: Optional[int] = None,
        source: str = STATS_COLLECTOR_SOURCE,
        replace_source: bool = False,
    ) -> int:
        source = validate_source_label(source)
        events = extract_exact_event_list(raw_events)
        if replace_source and not events:
            raise ValueError("refusing to replace exact reward source with an empty event export")
        imported = 0
        self.conn.execute("SAVEPOINT statscollector_replay_import")
        try:
            if replace_source:
                self.conn.execute(
                    "DELETE FROM reward_events WHERE source = ? AND confidence = 'exact'",
                    (source,),
                )
            for raw_event in events:
                event = statscollector_replay_event_to_ledger_event(
                    raw_event,
                    default_epoch=default_epoch,
                    source=source,
                )
                if self.insert_event(event):
                    imported += 1
            if events:
                self.set_meta("exact_reward_source", source, commit=False)
                self.set_meta("exact_reward_events", len(events), commit=False)
                max_height = self.conn.execute(
                    """
                    SELECT COALESCE(MAX(height), 0)
                    FROM reward_events
                    WHERE source = ? AND confidence = 'exact'
                    """,
                    (source,),
                ).fetchone()[0]
                if max_height:
                    self.set_meta("last_exact_reward_height", max_height, commit=False)
            self.conn.execute("RELEASE SAVEPOINT statscollector_replay_import")
        except Exception:
            try:
                self.conn.execute("ROLLBACK TO SAVEPOINT statscollector_replay_import")
                self.conn.execute("RELEASE SAVEPOINT statscollector_replay_import")
            except sqlite3.Error:
                self.conn.rollback()
            raise
        self.conn.commit()
        return imported

    def upsert_liability(
        self,
        *,
        invitee_address: str,
        inviter_address: str,
        tx_hash: str,
        epoch: int,
        invite_epoch_height: Optional[int],
        locked_atoms: int,
        status: str,
        height: int,
        raw: Dict[str, Any],
    ) -> None:
        liability_id = stable_event_id(["liability", invitee_address, tx_hash or invitee_address])
        existing = self.conn.execute(
            "SELECT original_locked_atoms FROM invitation_liabilities WHERE id = ?",
            (liability_id,),
        ).fetchone()
        original_locked_atoms = (
            int(existing["original_locked_atoms"]) if existing else max(0, locked_atoms)
        )
        self.conn.execute(
            """
            INSERT INTO invitation_liabilities(
              id, invitee_address, inviter_address, tx_hash, first_seen_epoch,
              invite_epoch_height, original_locked_atoms, current_locked_atoms,
              status, last_seen_epoch, last_height, raw_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              inviter_address = excluded.inviter_address,
              current_locked_atoms = excluded.current_locked_atoms,
              status = excluded.status,
              last_seen_epoch = excluded.last_seen_epoch,
              last_height = excluded.last_height,
              raw_json = excluded.raw_json,
              updated_at = excluded.updated_at
            """,
            (
                liability_id,
                invitee_address,
                inviter_address,
                tx_hash,
                epoch,
                invite_epoch_height,
                str(original_locked_atoms),
                str(max(0, locked_atoms)),
                status,
                epoch,
                height,
                json.dumps(raw, sort_keys=True),
                utc_now(),
            ),
        )

    def record_gap(self, from_height: int, to_height: int, reason: str) -> None:
        if to_height < from_height:
            return
        rows = self.conn.execute(
            """
            SELECT id, from_height, to_height
            FROM coverage_gaps
            WHERE reason = ?
              AND from_height <= ?
              AND to_height >= ?
            """,
            (reason, to_height + 1, from_height - 1),
        ).fetchall()
        if rows:
            from_height = min([from_height] + [int(row["from_height"]) for row in rows])
            to_height = max([to_height] + [int(row["to_height"]) for row in rows])
            self.conn.executemany(
                "DELETE FROM coverage_gaps WHERE id = ?",
                [(row["id"],) for row in rows],
            )
        gap_id = stable_event_id(["gap", from_height, to_height, reason])
        self.conn.execute(
            "INSERT OR IGNORE INTO coverage_gaps(id, from_height, to_height, reason, created_at) "
            "VALUES(?, ?, ?, ?, ?)",
            (gap_id, from_height, to_height, reason, utc_now()),
        )
        self.conn.commit()

    def cache_block(self, block: Dict[str, Any]) -> Dict[str, Any]:
        height = int(block.get("height") or 0)
        item = {
            "height": height,
            "hash": str(block.get("hash") or ""),
            "coinbase": normalize_address(block.get("coinbase")),
            "timestamp": parse_block_timestamp(block.get("timestamp")),
            "flags": block.get("flags") or [],
            "raw": block,
        }
        self.conn.execute(
            """
            INSERT INTO block_cache(height, hash, coinbase, timestamp, flags_json, raw_json)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(height) DO UPDATE SET
              hash = excluded.hash,
              coinbase = excluded.coinbase,
              timestamp = excluded.timestamp,
              flags_json = excluded.flags_json,
              raw_json = excluded.raw_json
            """,
            (
                item["height"],
                item["hash"],
                item["coinbase"],
                item["timestamp"],
                json.dumps(item["flags"]),
                json.dumps(block, sort_keys=True),
            ),
        )
        return item

    def get_cached_block(self, height: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM block_cache WHERE height = ?", (height,)).fetchone()
        if not row:
            return None
        return {
            "height": int(row["height"]),
            "hash": row["hash"],
            "coinbase": row["coinbase"],
            "timestamp": row["timestamp"],
            "flags": json.loads(row["flags_json"] or "[]"),
            "raw": json.loads(row["raw_json"] or "{}"),
        }

    def query_address(self, address: str, epoch: Optional[int]) -> Dict[str, Any]:
        address = normalize_address(address)
        params: List[Any] = [address]
        where = "address = ?"
        if epoch is not None:
            where += " AND epoch = ?"
            params.append(epoch)
        rows = self.conn.execute(
            f"""
            SELECT kind, amount_atoms, balance_atoms_delta, stake_atoms_delta,
                   locked_stake_atoms_delta
            FROM reward_events
            WHERE {where}
            """,
            params,
        ).fetchall()
        totals_by_kind: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {
                "event_count": 0,
                "amount_atoms": 0,
                "balance_atoms_delta": 0,
                "stake_atoms_delta": 0,
                "locked_stake_atoms_delta": 0,
            }
        )
        for row in rows:
            total = totals_by_kind[str(row["kind"])]
            total["event_count"] += 1
            for key in (
                "amount_atoms",
                "balance_atoms_delta",
                "stake_atoms_delta",
                "locked_stake_atoms_delta",
            ):
                total[key] += int(row[key] or 0)
        events = self.conn.execute(
            f"""
            SELECT height, timestamp, kind, direction, amount_atoms,
                   balance_atoms_delta, stake_atoms_delta, locked_stake_atoms_delta,
                   confidence, source, notes
            FROM reward_events
            WHERE {where}
            ORDER BY height DESC
            LIMIT 25
            """,
            params,
        ).fetchall()
        position = self.load_position(address)
        liabilities = self.conn.execute(
            """
            SELECT * FROM invitation_liabilities
            WHERE invitee_address = ? OR inviter_address = ?
            ORDER BY last_height DESC
            """,
            (address, address),
        ).fetchall()
        return {
            "address": address,
            "epoch": epoch,
            "position": position_to_json(position) if position else None,
            "totals": format_totals(totals_by_kind),
            "recentEvents": [format_event_row(row) for row in events],
            "invitationLiabilities": [format_liability_row(row) for row in liabilities],
        }

    def status(self) -> Dict[str, Any]:
        def scalar(sql: str) -> int:
            row = self.conn.execute(sql).fetchone()
            return int(row[0] or 0)

        gaps = self.conn.execute(
            "SELECT from_height, to_height, reason, created_at FROM coverage_gaps ORDER BY to_height DESC LIMIT 10"
        ).fetchall()
        return {
            "db": str(self.path),
            "lastHeight": int(self.get_meta("last_height", "0") or 0),
            "epoch": self.get_meta("epoch"),
            "events": scalar("SELECT COUNT(*) FROM reward_events"),
            "positions": scalar("SELECT COUNT(*) FROM positions"),
            "openInvitationLiabilities": scalar(
                "SELECT COUNT(*) FROM invitation_liabilities WHERE status = 'open'"
            ),
            "coverageGaps": [dict(row) for row in gaps],
        }

    def export_replay_events(
        self,
        *,
        epoch: Optional[int] = None,
        max_height: Optional[int] = None,
        allow_inferred: bool = False,
        require_exact: bool = False,
    ) -> List[Dict[str, Any]]:
        if require_exact and allow_inferred:
            raise ValueError("reward replay export cannot combine require_exact with allow_inferred")
        where = ["direction = 'credit'", "amount_atoms NOT LIKE '-%'", "amount_atoms <> '0'"]
        params: List[Any] = []
        if epoch is not None:
            where.append("epoch = ?")
            params.append(epoch)
        if max_height is not None:
            where.append("height <= ?")
            params.append(max_height)
        where_sql = " AND ".join(where)
        eligible_kinds = sorted(ELIGIBLE_REPLAY_KIND_BY_LEDGER_KIND)
        placeholders = ",".join("?" for _ in eligible_kinds)
        exact_count_row = self.conn.execute(
            f"""
            SELECT COUNT(*)
            FROM reward_events
            WHERE {where_sql}
              AND kind IN ({placeholders})
              AND confidence = 'exact'
            """,
            [*params, *eligible_kinds],
        ).fetchone()
        exact_count = int(exact_count_row[0] or 0)
        if require_exact and exact_count == 0:
            raise ValueError(
                "reward replay export has no exact eligible reward events; "
                "run sync-official-indexer first or use --allow-inferred only for development"
            )
        if not allow_inferred:
            if exact_count == 0:
                inferred_row = self.conn.execute(
                    f"""
                    SELECT address, height, kind, confidence, source
                    FROM reward_events
                    WHERE {where_sql}
                      AND kind IN ({placeholders})
                      AND confidence <> 'exact'
                    LIMIT 1
                    """,
                    [*params, *eligible_kinds],
                ).fetchone()
                if inferred_row is not None:
                    raise ValueError(
                        "reward replay export contains only non-exact eligible reward "
                        f"data at height {inferred_row['height']} for {inferred_row['address']} "
                        f"(kind={inferred_row['kind']}, confidence={inferred_row['confidence']}, "
                        f"source={inferred_row['source']}); run sync-official-indexer first or "
                        "use --allow-inferred only for non-consensus development snapshots"
                    )
            where.append("confidence = 'exact'")
            where_sql = " AND ".join(where)
        rows = self.conn.execute(
            f"""
            SELECT address, epoch, height, block_hash, kind, amount_atoms, confidence, source
            FROM reward_events
            WHERE {where_sql}
              AND kind IN ({",".join("?" for _ in eligible_kinds)})
            ORDER BY epoch, height, address, id
            """,
            [*params, *eligible_kinds],
        ).fetchall()
        events: List[Dict[str, Any]] = []
        for row in rows:
            ledger_kind = str(row["kind"])
            replay_kind = ELIGIBLE_REPLAY_KIND_BY_LEDGER_KIND[ledger_kind]
            events.append(
                {
                    "idena_address": normalize_address(row["address"]),
                    "kind": replay_kind,
                    "amount_atoms": int(row["amount_atoms"]),
                    "source_height": int(row["height"]),
                    "source_hash": str(row["block_hash"] or ""),
                }
            )
        return events


def extract_exact_event_list(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        events = raw
    elif isinstance(raw, dict) and isinstance(raw.get("events"), list):
        events = raw["events"]
    else:
        raise ValueError("StatsCollector replay import must be a JSON array or an object with an events array")
    result: List[Dict[str, Any]] = []
    for index, item in enumerate(events):
        if not isinstance(item, dict):
            raise ValueError(f"StatsCollector replay event at index {index} must be an object")
        result.append(item)
    return result


def first_present(item: Dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return None


def parse_int_field(value: Any, field_name: str, *, minimum: int = 0) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError
        parsed = int(str(value), 10)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}")
    return parsed


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


def validate_source_label(source: str) -> str:
    source = str(source).strip()
    if not source or len(source) > 128 or any(ord(ch) < 32 for ch in source):
        raise ValueError("source must be 1-128 printable characters")
    return source


def validate_executable_label(value: str, label: str) -> str:
    value = str(value).strip()
    if not value or len(value) > 512 or any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{label} must be 1-512 printable characters")
    return value


def validate_database_url(raw: str) -> str:
    raw = str(raw).strip()
    if not raw or len(raw.encode("utf-8")) > MAX_DATABASE_URL_BYTES:
        raise ValueError(f"Postgres database URL must be 1-{MAX_DATABASE_URL_BYTES} bytes")
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError("Postgres database URL must not contain control characters")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ValueError("Postgres database URL scheme must be postgres or postgresql")
    if not parsed.hostname:
        raise ValueError("Postgres database URL must include a host")
    return raw


def _validate_not_symlink_regular_file(path: Path, label: str, max_bytes: int) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} file is not readable: {path}: {exc}") from exc
    if os.path.islink(path):
        raise ValueError(f"{label} file must not be a symlink: {path}")
    if not os.path.isfile(path):
        raise ValueError(f"{label} path must be a regular file: {path}")
    if metadata.st_size > max_bytes:
        raise ValueError(f"{label} file is too large: {path} ({metadata.st_size} bytes)")
    return metadata


def read_protected_text_file(path: Path, label: str, max_bytes: int) -> str:
    path = Path(path)
    parent = path.parent if path.parent != Path("") else Path(".")
    try:
        parent_stat = os.lstat(parent)
    except OSError as exc:
        raise ValueError(f"{label} parent directory is not readable: {parent}: {exc}") from exc
    if os.path.islink(parent):
        raise ValueError(f"{label} parent directory must not be a symlink: {parent}")
    if not os.path.isdir(parent):
        raise ValueError(f"{label} parent path must be a directory: {parent}")
    if os.name == "posix" and parent_stat.st_mode & 0o022:
        raise ValueError(f"{label} parent directory is group/world writable: {parent}")
    reject_unsafe_symlink_ancestors(parent, f"{label} parent")
    metadata = _validate_not_symlink_regular_file(path, label, max_bytes)
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise ValueError(f"{label} file is too permissive: {path}; run chmod 600 {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"{label} file is empty: {path}")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{label} file must not contain control characters")
    return text


def validate_readable_text_file(path: Path, label: str, max_bytes: int) -> Path:
    path = Path(path)
    parent = path.parent if path.parent != Path("") else Path(".")
    reject_unsafe_symlink_ancestors(parent, f"{label} parent")
    _validate_not_symlink_regular_file(path, label, max_bytes)
    return path


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


def read_limited_json_file(path: Path, label: str, max_bytes: int) -> Any:
    path = validate_readable_text_file(path, label, max_bytes)
    return json.loads(path.read_text(encoding="utf-8"))


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


def load_official_indexer_database_url(
    *,
    database_url_file: Optional[Path],
    database_url_env: str,
) -> str:
    if database_url_file is not None:
        return validate_database_url(
            read_protected_text_file(
                database_url_file,
                "official idena-indexer database URL",
                MAX_DATABASE_URL_BYTES,
            )
        )
    env_name = str(database_url_env or "").strip()
    if not env_name or any(ord(ch) < 32 for ch in env_name):
        raise ValueError("database URL environment variable name is invalid")
    raw = os.getenv(env_name)
    if raw:
        return validate_database_url(raw)
    raise ValueError(
        f"official idena-indexer database URL is required; set --database-url-file or ${env_name}"
    )


def run_official_indexer_reward_export(
    *,
    database_url: str,
    sql_file: Path,
    psql_bin: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> Any:
    if timeout_seconds <= 0:
        raise ValueError("psql timeout must be greater than zero")
    if max_output_bytes <= 0:
        raise ValueError("max output bytes must be greater than zero")
    sql_file = validate_readable_text_file(
        sql_file,
        "official idena-indexer reward SQL",
        MAX_OFFICIAL_INDEXER_SQL_BYTES,
    )
    psql_bin = validate_executable_label(psql_bin, "psql binary")
    env = os.environ.copy()
    env["PGDATABASE"] = validate_database_url(database_url)
    env.setdefault("PGCONNECT_TIMEOUT", "10")
    try:
        completed = subprocess.run(
            [
                psql_bin,
                "-X",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                str(sql_file),
            ],
            check=False,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"failed to run psql exact reward export: {exc}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"psql exact reward export failed with exit {completed.returncode}: {stderr}"
        )
    if len(completed.stdout) > max_output_bytes:
        raise RuntimeError(
            f"psql exact reward export produced {len(completed.stdout)} bytes; maximum is {max_output_bytes}"
        )
    raw = completed.stdout.decode("utf-8").strip()
    if not raw:
        raise RuntimeError("psql exact reward export produced no JSON")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"psql exact reward export did not produce valid JSON: {exc}") from exc


def sync_official_indexer_rewards(
    *,
    ledger: RewardLedger,
    database_url: str,
    sql_file: Path,
    psql_bin: str = "psql",
    timeout_seconds: int = DEFAULT_PSQL_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_OFFICIAL_INDEXER_EXPORT_BYTES,
    source: str = STATS_COLLECTOR_SOURCE,
) -> Dict[str, Any]:
    source = validate_source_label(source)
    raw_events = run_official_indexer_reward_export(
        database_url=database_url,
        sql_file=sql_file,
        psql_bin=psql_bin,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    exported_count = len(extract_exact_event_list(raw_events))
    if exported_count == 0:
        raise RuntimeError(
            "official idena-indexer reward export returned no events; refusing to replace exact ledger"
        )
    imported_count = ledger.import_statscollector_replay_events(
        raw_events,
        source=source,
        replace_source=True,
    )
    row = ledger.conn.execute(
        """
        SELECT COUNT(*), COALESCE(MAX(height), 0)
        FROM reward_events
        WHERE source = ? AND confidence = 'exact'
        """,
        (source,),
    ).fetchone()
    ledger.set_meta("last_exact_sync_at", utc_now(), commit=False)
    ledger.set_meta("last_exact_sync_source", source, commit=False)
    ledger.conn.commit()
    return {
        "source": source,
        "sqlFile": str(sql_file),
        "exportedEvents": exported_count,
        "importedEvents": imported_count,
        "exactEventsInLedger": int(row[0] or 0),
        "lastExactRewardHeight": int(row[1] or 0),
    }


def validate_official_api_base_url(raw_url: str) -> str:
    raw_url = str(raw_url or "").strip().rstrip("/")
    if not raw_url or len(raw_url) > 2048 or any(ord(ch) < 32 for ch in raw_url):
        raise ValueError("official Idena API base URL is empty, too long, or contains control characters")
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("official Idena API base URL scheme must be http or https")
    if parsed.username or parsed.password:
        raise ValueError("official Idena API base URL must not include userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("official Idena API base URL must not include query or fragment data")
    if not parsed.hostname:
        raise ValueError("official Idena API base URL must include a host")
    if parsed.scheme == "http":
        host = parsed.hostname
        is_loopback = host.lower() == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError("official Idena API base URL must use https unless the host is loopback")
    return raw_url


def official_api_url(base_url: str, path: str, params: Optional[Dict[str, Any]] = None) -> str:
    base_url = validate_official_api_base_url(base_url)
    query = urllib.parse.urlencode(
        {key: value for key, value in (params or {}).items() if value not in (None, "")}
    )
    url = f"{base_url}/{path.lstrip('/')}"
    return f"{url}?{query}" if query else url


def read_bounded_http_json_response(resp: Any, label: str, max_bytes: int) -> Any:
    body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise RuntimeError(f"{label} response exceeded {max_bytes} bytes")
    raw = body.decode("utf-8").strip()
    if not raw:
        raise RuntimeError(f"{label} response was empty")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} response was not valid JSON: {exc}") from exc


def official_api_get_json(
    *,
    base_url: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout_seconds: int = DEFAULT_OFFICIAL_API_TIMEOUT_SECONDS,
    retries: int = DEFAULT_OFFICIAL_API_RETRIES,
    max_response_bytes: int = MAX_OFFICIAL_API_RESPONSE_BYTES,
    retry_delay_seconds: float = 1.0,
) -> Any:
    if timeout_seconds <= 0:
        raise ValueError("official Idena API timeout must be greater than zero")
    if retries < 0:
        raise ValueError("official Idena API retries must be >= 0")
    if max_response_bytes <= 0:
        raise ValueError("official Idena API max response bytes must be greater than zero")
    url = official_api_url(base_url, path, params)
    last_error: Optional[BaseException] = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "pohw-idena-reward-indexer/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                status = int(resp.getcode() or 0)
                if status != 200:
                    raise RuntimeError(f"official Idena API returned HTTP {status} for {path}")
                return read_bounded_http_json_response(
                    resp,
                    f"official Idena API {path}",
                    max_response_bytes,
                )
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt >= retries:
                body = exc.read(4096).decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"official Idena API returned HTTP {exc.code} for {path}: {body}"
                ) from exc
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            delay = retry_delay_seconds * (2**attempt)
            if retry_after:
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    pass
            time.sleep(delay)
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.HTTPException,
            RuntimeError,
        ) as exc:
            last_error = exc
            if attempt >= retries:
                raise RuntimeError(f"official Idena API request failed for {path}: {exc}") from exc
            time.sleep(retry_delay_seconds * (2**attempt))
    raise RuntimeError(f"official Idena API request failed for {path}: {last_error}")


def official_api_result(response: Any, label: str) -> Any:
    if not isinstance(response, dict):
        raise RuntimeError(f"{label} response must be a JSON object")
    if response.get("error"):
        raise RuntimeError(f"{label} returned error: {response['error']}")
    return response.get("result")


def iter_official_api_pages(
    *,
    base_url: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    page_limit: int = DEFAULT_OFFICIAL_API_PAGE_LIMIT,
    timeout_seconds: int = DEFAULT_OFFICIAL_API_TIMEOUT_SECONDS,
    retries: int = DEFAULT_OFFICIAL_API_RETRIES,
    request_delay_seconds: float = 0.0,
    max_pages: int = 10000,
) -> Sequence[List[Dict[str, Any]]]:
    if page_limit <= 0:
        raise ValueError("official Idena API page limit must be greater than zero")
    if max_pages <= 0:
        raise ValueError("official Idena API max pages must be greater than zero")
    base_params = dict(params or {})
    base_params["limit"] = page_limit
    pages: List[List[Dict[str, Any]]] = []
    continuation_token = base_params.get("continuationToken")
    for _ in range(max_pages):
        request_params = dict(base_params)
        if continuation_token:
            request_params["continuationToken"] = continuation_token
        response = official_api_get_json(
            base_url=base_url,
            path=path,
            params=request_params,
            timeout_seconds=timeout_seconds,
            retries=retries,
        )
        if not isinstance(response, dict):
            raise RuntimeError(f"official Idena API {path} page response must be an object")
        result = official_api_result(response, f"official Idena API {path}")
        if result is None:
            result = []
        if not isinstance(result, list):
            raise RuntimeError(f"official Idena API {path} result must be an array")
        page: List[Dict[str, Any]] = []
        for index, item in enumerate(result):
            if not isinstance(item, dict):
                raise RuntimeError(f"official Idena API {path} item {index} must be an object")
            page.append(item)
        pages.append(page)
        continuation_token = response.get("continuationToken")
        if not continuation_token:
            return pages
        if request_delay_seconds > 0:
            time.sleep(request_delay_seconds)
    raise RuntimeError(f"official Idena API {path} exceeded {max_pages} pages")


def get_official_api_last_epoch(
    *,
    base_url: str,
    timeout_seconds: int,
    retries: int,
) -> int:
    response = official_api_get_json(
        base_url=base_url,
        path="Epoch/Last",
        timeout_seconds=timeout_seconds,
        retries=retries,
    )
    result = official_api_result(response, "official Idena API Epoch/Last")
    if not isinstance(result, dict):
        raise RuntimeError("official Idena API Epoch/Last result must be an object")
    return parse_int_field(result.get("epoch"), "last epoch", minimum=1)


def get_official_api_epoch_source_block(
    *,
    base_url: str,
    epoch: int,
    timeout_seconds: int,
    retries: int,
) -> Dict[str, Any]:
    response = official_api_get_json(
        base_url=base_url,
        path=f"Epoch/{epoch}/Blocks",
        params={"limit": 1},
        timeout_seconds=timeout_seconds,
        retries=retries,
    )
    result = official_api_result(response, f"official Idena API Epoch/{epoch}/Blocks")
    if not isinstance(result, list) or not result:
        raise RuntimeError(f"official Idena API returned no blocks for epoch {epoch}")
    block = result[0]
    if not isinstance(block, dict):
        raise RuntimeError(f"official Idena API block for epoch {epoch} must be an object")
    return {
        "height": parse_int_field(block.get("height"), "epoch source block height", minimum=1),
        "hash": normalize_hash(block.get("hash"), "epoch source block hash"),
        "timestamp": block.get("timestamp") or utc_now(),
    }


def decimal_fields_have_positive_amount(item: Dict[str, Any]) -> bool:
    return decimal_to_atoms(item.get("balance", 0)) + decimal_to_atoms(item.get("stake", 0)) > 0


def collect_official_api_validation_rewards(
    *,
    base_url: str,
    epoch: int,
    source_block: Dict[str, Any],
    page_limit: int,
    timeout_seconds: int,
    retries: int,
    request_delay_seconds: float,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    events: List[Dict[str, Any]] = []
    addresses: List[str] = []
    seen_addresses = set()
    pages = iter_official_api_pages(
        base_url=base_url,
        path=f"Epoch/{epoch}/IdentityRewards",
        page_limit=page_limit,
        timeout_seconds=timeout_seconds,
        retries=retries,
        request_delay_seconds=request_delay_seconds,
    )
    for page in pages:
        for identity_rewards in page:
            address = normalize_address(identity_rewards.get("address"))
            if not IDENA_ADDRESS_RE.fullmatch(address):
                raise ValueError(f"invalid Idena address in official API rewards: {address!r}")
            if address not in seen_addresses:
                seen_addresses.add(address)
                addresses.append(address)
            raw_rewards = identity_rewards.get("rewards") or []
            if not isinstance(raw_rewards, list):
                raise RuntimeError("official Idena API identity rewards field must be an array")
            for reward in raw_rewards:
                if not isinstance(reward, dict):
                    raise RuntimeError("official Idena API reward item must be an object")
                if not decimal_fields_have_positive_amount(reward):
                    continue
                event = {
                    "idena_address": address,
                    "epoch": epoch,
                    "source_height": source_block["height"],
                    "source_hash": source_block["hash"],
                    "timestamp": source_block["timestamp"],
                    "reward_type": reward.get("type"),
                    "balance": reward.get("balance", "0"),
                    "stake": reward.get("stake", "0"),
                    "source_table": "official_api_epoch_identity_rewards",
                }
                events.append(event)
    return events, addresses


def collect_official_api_epoch_identity_addresses(
    *,
    base_url: str,
    epoch: int,
    page_limit: int,
    timeout_seconds: int,
    retries: int,
    request_delay_seconds: float,
) -> List[str]:
    addresses: List[str] = []
    seen = set()
    pages = iter_official_api_pages(
        base_url=base_url,
        path=f"Epoch/{epoch}/Identities",
        page_limit=page_limit,
        timeout_seconds=timeout_seconds,
        retries=retries,
        request_delay_seconds=request_delay_seconds,
    )
    for page in pages:
        for identity in page:
            address = normalize_address(identity.get("address"))
            if not IDENA_ADDRESS_RE.fullmatch(address):
                raise ValueError(f"invalid Idena address in official API identities: {address!r}")
            if address not in seen:
                seen.add(address)
                addresses.append(address)
    return addresses


def collect_official_api_mining_rewards_for_address(
    *,
    base_url: str,
    address: str,
    epoch: int,
    source_block: Dict[str, Any],
    page_limit: int,
    timeout_seconds: int,
    retries: int,
    request_delay_seconds: float,
) -> List[Dict[str, Any]]:
    address = normalize_address(address)
    pages = iter_official_api_pages(
        base_url=base_url,
        path=f"Address/{address}/MiningRewardSummaries",
        page_limit=page_limit,
        timeout_seconds=timeout_seconds,
        retries=retries,
        request_delay_seconds=request_delay_seconds,
        max_pages=1000,
    )
    events: List[Dict[str, Any]] = []
    for page in pages:
        older_than_target = False
        for summary in page:
            item_epoch = parse_int_field(summary.get("epoch"), "mining summary epoch", minimum=1)
            if item_epoch < epoch:
                older_than_target = True
                continue
            if item_epoch != epoch:
                continue
            amount = summary.get("amount", "0")
            if decimal_to_atoms(amount) <= 0:
                continue
            events.append(
                {
                    "idena_address": address,
                    "epoch": epoch,
                    "source_height": source_block["height"],
                    "source_hash": source_block["hash"],
                    "timestamp": source_block["timestamp"],
                    "kind": "FinalCommittee",
                    "amount": amount,
                    "source_table": "official_api_mining_reward_summaries",
                    "penalty": summary.get("penalty", "0"),
                }
            )
        if older_than_target:
            break
    return events


def sync_official_api_rewards(
    *,
    ledger: RewardLedger,
    api_base_url: str = DEFAULT_OFFICIAL_API_BASE_URL,
    epochs: Optional[Sequence[int]] = None,
    completed_epochs: int = 1,
    include_mining_summaries: bool = True,
    page_limit: int = DEFAULT_OFFICIAL_API_PAGE_LIMIT,
    mining_page_limit: int = 20,
    timeout_seconds: int = DEFAULT_OFFICIAL_API_TIMEOUT_SECONDS,
    retries: int = DEFAULT_OFFICIAL_API_RETRIES,
    request_delay_seconds: float = 0.0,
    source: str = OFFICIAL_API_SOURCE,
) -> Dict[str, Any]:
    api_base_url = validate_official_api_base_url(api_base_url)
    source = validate_source_label(source)
    if epochs:
        selected_epochs = sorted({parse_int_field(epoch, "epoch", minimum=1) for epoch in epochs})
    else:
        if completed_epochs <= 0:
            raise ValueError("completed_epochs must be greater than zero when no explicit epochs are provided")
        last_epoch = get_official_api_last_epoch(
            base_url=api_base_url,
            timeout_seconds=timeout_seconds,
            retries=retries,
        )
        first_epoch = max(1, last_epoch - completed_epochs)
        selected_epochs = list(range(first_epoch, last_epoch))
    if not selected_epochs:
        raise ValueError("no completed official API epochs selected")

    epoch_results: List[Dict[str, Any]] = []
    total_exported = 0
    total_imported = 0
    for epoch in selected_epochs:
        source_block = get_official_api_epoch_source_block(
            base_url=api_base_url,
            epoch=epoch,
            timeout_seconds=timeout_seconds,
            retries=retries,
        )
        validation_events, reward_addresses = collect_official_api_validation_rewards(
            base_url=api_base_url,
            epoch=epoch,
            source_block=source_block,
            page_limit=page_limit,
            timeout_seconds=timeout_seconds,
            retries=retries,
            request_delay_seconds=request_delay_seconds,
        )
        events = list(validation_events)
        mining_events: List[Dict[str, Any]] = []
        if include_mining_summaries:
            identity_addresses = collect_official_api_epoch_identity_addresses(
                base_url=api_base_url,
                epoch=epoch,
                page_limit=page_limit,
                timeout_seconds=timeout_seconds,
                retries=retries,
                request_delay_seconds=request_delay_seconds,
            )
            addresses = sorted(set(reward_addresses) | set(identity_addresses))
            for address in addresses:
                mining_events.extend(
                    collect_official_api_mining_rewards_for_address(
                        base_url=api_base_url,
                        address=address,
                        epoch=epoch,
                        source_block=source_block,
                        page_limit=mining_page_limit,
                        timeout_seconds=timeout_seconds,
                        retries=retries,
                        request_delay_seconds=request_delay_seconds,
                    )
                )
                if request_delay_seconds > 0:
                    time.sleep(request_delay_seconds)
            events.extend(mining_events)
        if not events:
            raise RuntimeError(f"official Idena API exported no reward events for epoch {epoch}")
        epoch_source = f"{source}:epoch:{epoch}"
        imported = ledger.import_statscollector_replay_events(
            events,
            source=epoch_source,
            replace_source=True,
        )
        total_exported += len(events)
        total_imported += imported
        epoch_results.append(
            {
                "epoch": epoch,
                "source": epoch_source,
                "sourceHeight": source_block["height"],
                "sourceHash": source_block["hash"],
                "validationEvents": len(validation_events),
                "miningEvents": len(mining_events),
                "exportedEvents": len(events),
                "importedEvents": imported,
            }
        )

    row = ledger.conn.execute(
        """
        SELECT COUNT(*), COALESCE(MAX(height), 0)
        FROM reward_events
        WHERE source LIKE ? AND confidence = 'exact'
        """,
        (f"{source}:epoch:%",),
    ).fetchone()
    ledger.set_meta("last_official_api_sync_at", utc_now(), commit=False)
    ledger.set_meta("last_official_api_base_url", api_base_url, commit=False)
    ledger.set_meta("last_official_api_epochs", ",".join(str(epoch) for epoch in selected_epochs), commit=False)
    ledger.conn.commit()
    return {
        "source": source,
        "apiBaseUrl": api_base_url,
        "epochs": epoch_results,
        "exportedEvents": total_exported,
        "importedEvents": total_imported,
        "exactEventsInLedger": int(row[0] or 0),
        "lastExactRewardHeight": int(row[1] or 0),
    }


def parse_bool_field(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "t", "yes", "y"}:
            return True
        if lowered in {"0", "false", "f", "no", "n"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise ValueError(f"{field_name} must be boolean")


def parse_atoms_from_decimal(value: Any, field_name: str) -> int:
    atoms = decimal_to_atoms(value)
    if atoms < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return atoms


def parse_atoms_from_integer(value: Any, field_name: str) -> int:
    return parse_int_field(value, field_name, minimum=0)


def parse_exact_atoms(item: Dict[str, Any]) -> Tuple[int, int, int]:
    balance_raw = first_present(item, ("balance_atoms", "balance_delta_atoms", "balanceAtoms"))
    stake_raw = first_present(item, ("stake_atoms", "stake_delta_atoms", "stakeAtoms"))
    if balance_raw is None and "balance" in item:
        balance_atoms = parse_atoms_from_decimal(item["balance"], "balance")
    elif balance_raw is not None:
        balance_atoms = parse_atoms_from_integer(balance_raw, "balance_atoms")
    else:
        balance_atoms = 0

    if stake_raw is None and "stake" in item:
        stake_atoms = parse_atoms_from_decimal(item["stake"], "stake")
    elif stake_raw is not None:
        stake_atoms = parse_atoms_from_integer(stake_raw, "stake_atoms")
    else:
        stake_atoms = 0

    amount_raw = first_present(item, ("amount_atoms", "amountAtoms"))
    if amount_raw is None and "amount" in item:
        amount_atoms = parse_atoms_from_decimal(item["amount"], "amount")
    elif amount_raw is not None:
        amount_atoms = parse_atoms_from_integer(amount_raw, "amount_atoms")
    else:
        amount_atoms = balance_atoms + stake_atoms

    if balance_atoms or stake_atoms:
        expected = balance_atoms + stake_atoms
        if amount_atoms != expected:
            raise ValueError(
                f"amount_atoms must equal balance_atoms + stake_atoms for exact rewards ({amount_atoms} != {expected})"
            )
    else:
        balance_atoms = amount_atoms

    if amount_atoms <= 0:
        raise ValueError("amount_atoms must be positive")
    return amount_atoms, balance_atoms, stake_atoms


def normalize_exact_replay_kind(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    raw = str(value).strip()
    normalized = raw[:1].upper() + raw[1:]
    aliases = {
        "Finalcommittee": "FinalCommittee",
        "Final_committee": "FinalCommittee",
        "Committee": "FinalCommittee",
        "Mining": "FinalCommittee",
        "Miner": "FinalCommittee",
        "Miningproposer": "Proposer",
        "Mining_proposer": "Proposer",
        "Stats_validation_reward": "Validation",
        "Stats_proposer_reward": "Proposer",
        "Stats_final_committee_reward": "FinalCommittee",
        "Stats_invitation_reward": "Invitation",
        "Stats_invitee_reward": "Invitee",
        "Stats_contract_oracle_reward": "ContractOracle",
        "Stats_other_reward": "Other",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized in REPLAY_KINDS:
        return normalized
    return None


def official_reward_type_to_kind(value: Any) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        key = stripped.replace(" ", "").replace("_", "").replace("-", "").lower()
        if key in OFFICIAL_VALIDATION_REWARD_TYPE_BY_NAME:
            value = OFFICIAL_VALIDATION_REWARD_TYPE_BY_NAME[key]
        else:
            value = stripped
    reward_type = parse_int_field(value, "reward_type", minimum=0)
    if reward_type not in OFFICIAL_VALIDATION_REWARD_KIND_BY_TYPE:
        raise ValueError(f"unsupported official reward_type: {reward_type}")
    return OFFICIAL_VALIDATION_REWARD_KIND_BY_TYPE[reward_type]


def derive_exact_replay_kind(item: Dict[str, Any]) -> str:
    explicit = normalize_exact_replay_kind(
        first_present(item, ("kind", "replay_kind", "reward_kind", "pohw_kind"))
    )
    if explicit is not None:
        return explicit

    source_table = str(first_present(item, ("source_table", "table")) or "").strip().lower()
    if source_table == "mining_rewards" or "proposer" in item:
        return "Proposer" if parse_bool_field(item.get("proposer", False), "proposer") else "FinalCommittee"

    reward_type = first_present(item, ("reward_type", "official_reward_type", "type", "type_name"))
    if reward_type is not None:
        return official_reward_type_to_kind(reward_type)

    raise ValueError("exact reward event must include kind, reward_type, or mining_rewards proposer flag")


def statscollector_replay_event_to_ledger_event(
    item: Dict[str, Any],
    *,
    default_epoch: Optional[int],
    source: str,
) -> Dict[str, Any]:
    address = normalize_address(first_present(item, ("idena_address", "address", "identity_address")))
    if not IDENA_ADDRESS_RE.fullmatch(address):
        raise ValueError(f"invalid Idena address for exact reward import: {address!r}")

    epoch_value = first_present(item, ("epoch", "source_epoch"))
    if epoch_value is None:
        if default_epoch is None:
            raise ValueError("epoch is required for exact reward import")
        epoch = default_epoch
    else:
        epoch = parse_int_field(epoch_value, "epoch", minimum=0)

    height = parse_int_field(
        first_present(item, ("source_height", "height", "block_height", "blockHeight")),
        "source_height",
        minimum=1,
    )
    block_hash = normalize_hash(
        first_present(item, ("source_hash", "block_hash", "hash", "blockHash")),
        "source_hash",
    )

    replay_kind = derive_exact_replay_kind(item)
    ledger_kind = EXACT_LEDGER_KIND_BY_REPLAY_KIND[replay_kind]
    amount_atoms, balance_atoms, stake_atoms = parse_exact_atoms(item)
    timestamp_raw = first_present(item, ("timestamp", "block_timestamp", "blockTimestamp"))
    timestamp = parse_block_timestamp(timestamp_raw) if timestamp_raw is not None else utc_now()
    tx_hash = normalize_hash(
        first_present(item, ("tx_hash", "txHash")),
        "tx_hash",
        required=False,
    )
    counterparty = normalize_address(first_present(item, ("counterparty_address", "counterpartyAddress")))
    if counterparty and not IDENA_ADDRESS_RE.fullmatch(counterparty):
        raise ValueError(f"invalid counterparty address for exact reward import: {counterparty!r}")
    event_id = stable_event_id(
        [
            source,
            epoch,
            height,
            block_hash,
            address,
            ledger_kind,
            amount_atoms,
            balance_atoms,
            stake_atoms,
            tx_hash,
        ]
    )
    return {
        "id": event_id,
        "address": address,
        "epoch": epoch,
        "height": height,
        "block_hash": block_hash,
        "timestamp": timestamp,
        "kind": ledger_kind,
        "direction": "credit",
        "amount_atoms": amount_atoms,
        "balance_atoms_delta": balance_atoms,
        "stake_atoms_delta": stake_atoms,
        "replenished_stake_atoms_delta": 0,
        "locked_stake_atoms_delta": 0,
        "source": source,
        "confidence": "exact",
        "liability_status": "",
        "counterparty_address": counterparty,
        "tx_hash": tx_hash,
        "notes": "exact reward event imported from official idena-indexer StatsCollector output",
        "raw_json": json.dumps(item, sort_keys=True),
        "created_at": utc_now(),
    }


def row_to_position(row: sqlite3.Row) -> Position:
    return Position(
        address=row["address"],
        epoch=int(row["epoch"]),
        state=row["state"],
        age=int(row["age"]),
        balance_atoms=int(row["balance_atoms"]),
        stake_atoms=int(row["stake_atoms"]),
        replenished_stake_atoms=int(row["replenished_stake_atoms"]),
        locked_stake_atoms=int(row["locked_stake_atoms"]),
        delegatee=row["delegatee"],
        inviter_address=row["inviter_address"],
        inviter_tx_hash=row["inviter_tx_hash"],
        invite_epoch_height=row["invite_epoch_height"],
        updated_height=int(row["updated_height"]),
        updated_at=row["updated_at"],
        raw=json.loads(row["raw_json"] or "{}"),
    )


def format_totals(totals_by_kind: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for kind in sorted(totals_by_kind):
        total = totals_by_kind[kind]
        result.append(
            {
                "kind": kind,
                "eventCount": total["event_count"],
                "amountAtoms": str(total["amount_atoms"]),
                "amount": atoms_to_decimal_string(total["amount_atoms"]),
                "balanceDeltaAtoms": str(total["balance_atoms_delta"]),
                "balanceDelta": atoms_to_decimal_string(total["balance_atoms_delta"]),
                "stakeDeltaAtoms": str(total["stake_atoms_delta"]),
                "stakeDelta": atoms_to_decimal_string(total["stake_atoms_delta"]),
                "lockedStakeDeltaAtoms": str(total["locked_stake_atoms_delta"]),
                "lockedStakeDelta": atoms_to_decimal_string(total["locked_stake_atoms_delta"]),
            }
        )
    return result


def format_event_row(row: sqlite3.Row) -> Dict[str, Any]:
    amount_atoms = int(row["amount_atoms"] or 0)
    balance_atoms = int(row["balance_atoms_delta"] or 0)
    stake_atoms = int(row["stake_atoms_delta"] or 0)
    locked_atoms = int(row["locked_stake_atoms_delta"] or 0)
    return {
        "height": int(row["height"]),
        "timestamp": row["timestamp"],
        "kind": row["kind"],
        "direction": row["direction"],
        "amountAtoms": str(amount_atoms),
        "amount": atoms_to_decimal_string(amount_atoms),
        "balanceDeltaAtoms": str(balance_atoms),
        "balanceDelta": atoms_to_decimal_string(balance_atoms),
        "stakeDeltaAtoms": str(stake_atoms),
        "stakeDelta": atoms_to_decimal_string(stake_atoms),
        "lockedStakeDeltaAtoms": str(locked_atoms),
        "lockedStakeDelta": atoms_to_decimal_string(locked_atoms),
        "confidence": row["confidence"],
        "source": row["source"],
        "notes": row["notes"],
    }


def format_liability_row(row: sqlite3.Row) -> Dict[str, Any]:
    original_atoms = int(row["original_locked_atoms"] or 0)
    current_atoms = int(row["current_locked_atoms"] or 0)
    return {
        "inviteeAddress": row["invitee_address"],
        "inviterAddress": row["inviter_address"],
        "txHash": row["tx_hash"],
        "firstSeenEpoch": int(row["first_seen_epoch"]),
        "inviteEpochHeight": row["invite_epoch_height"],
        "originalLockedAtoms": str(original_atoms),
        "originalLocked": atoms_to_decimal_string(original_atoms),
        "currentLockedAtoms": str(current_atoms),
        "currentLocked": atoms_to_decimal_string(current_atoms),
        "status": row["status"],
        "lastSeenEpoch": int(row["last_seen_epoch"]),
        "lastHeight": int(row["last_height"]),
        "updatedAt": row["updated_at"],
    }


def position_to_json(pos: Position) -> Dict[str, Any]:
    return {
        "address": pos.address,
        "epoch": pos.epoch,
        "state": pos.state,
        "age": pos.age,
        "balance": atoms_to_decimal_string(pos.balance_atoms),
        "stake": atoms_to_decimal_string(pos.stake_atoms),
        "replenishedStake": atoms_to_decimal_string(pos.replenished_stake_atoms),
        "lockedStake": atoms_to_decimal_string(pos.locked_stake_atoms),
        "delegatee": pos.delegatee or None,
        "inviterAddress": pos.inviter_address or None,
        "inviterTxHash": pos.inviter_tx_hash or None,
        "inviteEpochHeight": pos.invite_epoch_height,
        "updatedHeight": pos.updated_height,
        "updatedAt": pos.updated_at,
    }


def position_from_identity(
    *,
    identity: Dict[str, Any],
    balance: Optional[Dict[str, Any]],
    epoch: int,
    height: int,
    timestamp: str,
) -> Position:
    address = normalize_address(identity.get("address"))
    inviter = identity.get("inviter") if isinstance(identity.get("inviter"), dict) else {}
    if balance is None:
        balance = {}
    return Position(
        address=address,
        epoch=epoch,
        state=str(identity.get("state") or "Undefined"),
        age=int(identity.get("age") or 0),
        balance_atoms=decimal_to_atoms(balance.get("balance", 0)),
        stake_atoms=decimal_to_atoms(balance.get("stake", identity.get("stake", 0))),
        replenished_stake_atoms=decimal_to_atoms(
            balance.get("replenishedStake", identity.get("replenishedStake", 0))
        ),
        locked_stake_atoms=decimal_to_atoms(
            balance.get("lockedStake", identity.get("lockedStake", 0))
        ),
        delegatee=normalize_address(identity.get("delegatee")),
        inviter_address=normalize_address(inviter.get("address")),
        inviter_tx_hash=str(inviter.get("txHash") or "").lower(),
        invite_epoch_height=inviter.get("epochHeight"),
        updated_height=height,
        updated_at=timestamp,
        raw={"identity": identity, "balance": balance},
    )


def delta_between(old: Position, new: Position) -> Delta:
    return Delta(
        balance_atoms=new.balance_atoms - old.balance_atoms,
        stake_atoms=new.stake_atoms - old.stake_atoms,
        replenished_stake_atoms=new.replenished_stake_atoms - old.replenished_stake_atoms,
        locked_stake_atoms=new.locked_stake_atoms - old.locked_stake_atoms,
    )


def classify_delta(
    *,
    address: str,
    delta: Delta,
    old_state: str,
    new_state: str,
    block: Dict[str, Any],
    source: str,
) -> Tuple[str, str, str, str]:
    flags = set(block.get("flags") or [])
    coinbase = normalize_address(block.get("coinbase"))
    amount = delta.reward_atoms
    direction = "neutral"
    if amount > 0 or delta.locked_stake_atoms > 0:
        direction = "credit"
    elif amount < 0 or delta.locked_stake_atoms < 0:
        direction = "debit"

    if delta.locked_stake_atoms > 0:
        return "invitation_locked_reward", direction, "inferred", "locked stake increased"
    if delta.locked_stake_atoms < 0:
        if new_state in {"Killed", "Undefined"} or delta.stake_atoms < 0:
            return "invitation_reversal_or_burn", direction, "inferred", "locked stake decreased"
        return "invitation_unlock", direction, "inferred", "locked stake decreased without stake burn"
    if amount > 0 and "ValidationFinished" in flags:
        return "session_reward", direction, "inferred", "validation-finished block balance/stake increase"
    if amount > 0 and address == coinbase:
        return "mining_proposer_reward", direction, "inferred", "block coinbase balance/stake increase"
    if amount > 0:
        return "staking_or_committee_reward", direction, "inferred", "non-coinbase balance/stake increase"
    if amount < 0:
        return "balance_or_stake_reversal", direction, "observed", "balance/stake decreased"
    if old_state != new_state:
        return "identity_state_change", "neutral", "observed", f"state changed {old_state}->{new_state}"
    return "identity_attribute_change", "neutral", "observed", "non-monetary identity change"


def event_from_delta(
    *,
    address: str,
    epoch: int,
    block: Dict[str, Any],
    delta: Delta,
    old_state: str,
    new_state: str,
    source: str,
    raw: Dict[str, Any],
    counterparty_address: str = "",
    tx_hash: str = "",
) -> Dict[str, Any]:
    kind, direction, confidence, notes = classify_delta(
        address=address,
        delta=delta,
        old_state=old_state,
        new_state=new_state,
        block=block,
        source=source,
    )
    liability_status = ""
    if kind == "invitation_locked_reward":
        liability_status = "open"
    elif kind in {"invitation_reversal_or_burn", "invitation_unlock"}:
        liability_status = "changed"
    event_id = stable_event_id(
        [
            source,
            epoch,
            block.get("height"),
            address,
            kind,
            delta.balance_atoms,
            delta.stake_atoms,
            delta.replenished_stake_atoms,
            delta.locked_stake_atoms,
            tx_hash,
        ]
    )
    return {
        "id": event_id,
        "address": address,
        "epoch": epoch,
        "height": int(block.get("height") or 0),
        "block_hash": str(block.get("hash") or ""),
        "timestamp": str(block.get("timestamp") or utc_now()),
        "kind": kind,
        "direction": direction,
        "amount_atoms": delta.reward_atoms,
        "balance_atoms_delta": delta.balance_atoms,
        "stake_atoms_delta": delta.stake_atoms,
        "replenished_stake_atoms_delta": delta.replenished_stake_atoms,
        "locked_stake_atoms_delta": delta.locked_stake_atoms,
        "source": source,
        "confidence": confidence,
        "liability_status": liability_status,
        "counterparty_address": counterparty_address,
        "tx_hash": tx_hash,
        "notes": notes,
        "raw_json": json.dumps(raw, sort_keys=True),
        "created_at": utc_now(),
    }


def mark_non_reward_event(event: Dict[str, Any], *, kind: str, confidence: str, notes: str) -> Dict[str, Any]:
    event = dict(event)
    event["kind"] = kind
    event["confidence"] = confidence
    event["notes"] = notes
    event["liability_status"] = ""
    event["id"] = stable_event_id(
        [
            event["source"],
            event["epoch"],
            event["height"],
            event["address"],
            event["kind"],
            event["tx_hash"],
        ]
    )
    return event


def collapse_rolling_changes(rows: Sequence[Dict[str, Any]], current: Optional[Position]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for row in rows:
        changes = row.get("changes") if isinstance(row.get("changes"), dict) else {}
        for key, value in changes.items():
            if not isinstance(value, list) or len(value) != 2:
                continue
            if key not in merged:
                merged[key] = [value[0], value[1]]
            else:
                merged[key][1] = value[1]

    if current is not None:
        current_values = {
            "balance": atoms_to_decimal_string(current.balance_atoms),
            "stake": atoms_to_decimal_string(current.stake_atoms),
            "replenishedStake": atoms_to_decimal_string(current.replenished_stake_atoms),
            "lockedStake": atoms_to_decimal_string(current.locked_stake_atoms),
            "state": current.state,
            "age": current.age,
            "delegatee": current.delegatee,
        }
        for key, old_value in current_values.items():
            if key in merged:
                merged[key][0] = old_value
    return merged


class RewardIndexer:
    def __init__(
        self,
        *,
        ledger: RewardLedger,
        client: Optional[IdenaRPCClientMinimal],
        rolling_data_dir: Path,
        poll_interval: int,
        live_settle_seconds: float = LIVE_SETTLE_SECONDS,
        non_atomic_backoff_seconds: float = NON_ATOMIC_BACKOFF_SECONDS,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if poll_interval < 1:
            raise ValueError("poll_interval must be at least 1 second")
        if live_settle_seconds < 0:
            raise ValueError("live_settle_seconds must be non-negative")
        if non_atomic_backoff_seconds < 0:
            raise ValueError("non_atomic_backoff_seconds must be non-negative")
        self.ledger = ledger
        self.client = client
        self.rolling_data_dir = rolling_data_dir
        self.poll_interval = poll_interval
        self.live_settle_seconds = live_settle_seconds
        self.non_atomic_backoff_seconds = non_atomic_backoff_seconds
        self.sleeper = sleeper

    def rpc(self) -> IdenaRPCClientMinimal:
        if self.client is None:
            raise RuntimeError("RPC client is required for this command")
        return self.client

    def get_epoch(self) -> Dict[str, Any]:
        epoch = self.rpc().get_epoch()
        self.ledger.set_meta("epoch", epoch.get("epoch"))
        self.ledger.set_meta("epoch_start_block", epoch.get("startBlock"))
        return epoch

    def get_block(self, height: int) -> Dict[str, Any]:
        cached = self.ledger.get_cached_block(height)
        if cached:
            return cached
        block = self.rpc().get_block_at_height(height)
        if not isinstance(block, dict):
            raise IdenaRPCError(f"unexpected bcn_blockAt result for {height}: {type(block)}")
        item = self.ledger.cache_block(block)
        self.ledger.conn.commit()
        return item

    def get_last_block(self) -> Dict[str, Any]:
        block = self.rpc().get_last_block()
        item = self.ledger.cache_block(block)
        self.ledger.conn.commit()
        return item

    def batch_call(self, calls: Sequence[Tuple[str, List[Any]]], chunk_size: int = 75) -> List[Any]:
        if not calls:
            return []
        client = self.rpc()
        results: List[Any] = [None] * len(calls)
        for offset in range(0, len(calls), chunk_size):
            chunk = calls[offset : offset + chunk_size]
            payload = [
                {
                    "jsonrpc": "2.0",
                    "id": offset + index,
                    "key": client.api_key,
                    "method": method,
                    "params": params,
                }
                for index, (method, params) in enumerate(chunk)
            ]
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                client.url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    status = resp.getcode()
                    if read_limited_rpc_response_body is None:
                        raise IdenaRPCError(
                            "idena_rpc_client_minimal.py is required for RPC commands"
                        )
                    body = read_limited_rpc_response_body(resp, "Idena RPC batch")
            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                http.client.HTTPException,
            ) as exc:
                raise IdenaRPCError(f"HTTP error talking to Idena RPC batch: {exc}") from exc
            if status != 200:
                raise IdenaRPCError(f"Non 200 HTTP status from Idena RPC batch: {status} - {body}")
            parsed = json.loads(body)
            if not isinstance(parsed, list):
                raise IdenaRPCError(f"Unexpected Idena batch response: {parsed}")
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                response_id = item.get("id")
                if not isinstance(response_id, int) or response_id < 0 or response_id >= len(results):
                    continue
                if item.get("error") is None:
                    results[response_id] = item.get("result")
        return results

    def batch_get_balances(self, addresses: Sequence[str]) -> Dict[str, Dict[str, Any]]:
        normalized = [normalize_address(address) for address in addresses if normalize_address(address)]
        calls = [("dna_getBalance", [address]) for address in normalized]
        responses = self.batch_call(calls)
        balances: Dict[str, Dict[str, Any]] = {}
        for address, response in zip(normalized, responses):
            if isinstance(response, dict):
                balances[address] = response
        return balances

    def import_rolling_epoch(self, epoch: int, with_block_lookup: bool = True) -> int:
        marker = f"rolling_imported_epoch_{epoch}"
        if self.ledger.get_meta(marker) == "1":
            return 0

        snapshot_path = self.rolling_data_dir / "snapshots" / f"epoch_{epoch}_snapshot.json"
        delta_path = self.rolling_data_dir / "deltas" / f"epoch_{epoch}_deltas.jsonl"
        imported = 0

        if snapshot_path.exists():
            snapshot_path = validate_readable_text_file(
                snapshot_path,
                "rolling snapshot",
                MAX_ROLLING_SNAPSHOT_BYTES,
            )
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            start_block = int(snapshot.get("startBlock") or 0)
            created_at = str(snapshot.get("createdAtUtc") or utc_now())
            for address, data in (snapshot.get("identities") or {}).items():
                if not isinstance(data, dict):
                    continue
                address = normalize_address(address)
                pos = Position(
                    address=address,
                    epoch=epoch,
                    state=str(data.get("state") or "Undefined"),
                    age=int(data.get("age") or 0),
                    balance_atoms=decimal_to_atoms(data.get("balance", 0)),
                    stake_atoms=decimal_to_atoms(data.get("stake", 0)),
                    replenished_stake_atoms=0,
                    locked_stake_atoms=0,
                    delegatee=normalize_address(data.get("delegatee")),
                    inviter_address="",
                    inviter_tx_hash="",
                    invite_epoch_height=None,
                    updated_height=start_block,
                    updated_at=created_at,
                    raw={"rollingSnapshot": data},
                )
                if not self.ledger.load_position(address):
                    self.ledger.upsert_position(pos)

        if delta_path.exists():
            delta_path = validate_readable_text_file(
                delta_path,
                "rolling delta",
                MAX_ROLLING_DELTA_BYTES,
            )
            grouped: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}
            with delta_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    raw_delta = json.loads(line)
                    height = int(raw_delta.get("height") or 0)
                    address = normalize_address(raw_delta.get("address"))
                    if not height or not address:
                        continue
                    grouped.setdefault((height, address), []).append(raw_delta)

            block_cache: Dict[int, Dict[str, Any]] = {}
            for height, address in sorted(grouped):
                rows = grouped[(height, address)]
                if with_block_lookup:
                    block = block_cache.get(height)
                    if block is None:
                        try:
                            block = self.get_block(height)
                        except IdenaRPCError:
                            block = {
                                "height": height,
                                "hash": "",
                                "coinbase": "",
                                "timestamp": rows[-1].get("timestamp") or utc_now(),
                                "flags": [],
                            }
                        block_cache[height] = block
                else:
                    block = {
                        "height": height,
                        "hash": "",
                        "coinbase": "",
                        "timestamp": rows[-1].get("timestamp") or utc_now(),
                        "flags": [],
                    }

                current = self.ledger.load_position(address)
                changes = collapse_rolling_changes(rows, current)
                delta = Delta(
                    balance_atoms=change_to_delta_atoms(changes.get("balance")),
                    stake_atoms=change_to_delta_atoms(changes.get("stake")),
                    replenished_stake_atoms=change_to_delta_atoms(changes.get("replenishedStake")),
                    locked_stake_atoms=change_to_delta_atoms(changes.get("lockedStake")),
                )
                old_state, new_state = state_change(changes.get("state"))
                if delta != Delta() or old_state != new_state:
                    event = event_from_delta(
                        address=address,
                        epoch=epoch,
                        block=block,
                        delta=delta,
                        old_state=old_state,
                        new_state=new_state,
                        source="rolling_delta_import",
                        raw={
                            "collapsed": True,
                            "rowCount": len(rows),
                            "firstRow": rows[0],
                            "lastRow": rows[-1],
                        },
                    )
                    if self.ledger.insert_event(event):
                        imported += 1
                self.apply_delta_to_position(address, epoch, height, str(block["timestamp"]), changes)

        self.ledger.set_meta(marker, "1")
        if imported:
            max_height = self.ledger.conn.execute(
                "SELECT COALESCE(MAX(height), 0) FROM reward_events WHERE source = 'rolling_delta_import'"
            ).fetchone()[0]
            self.ledger.set_meta("last_height", max_height)
        self.ledger.conn.commit()
        return imported

    def apply_delta_to_position(
        self,
        address: str,
        epoch: int,
        height: int,
        timestamp: str,
        changes: Dict[str, Any],
    ) -> None:
        pos = self.ledger.load_position(address)
        if pos is None:
            pos = Position(
                address=address,
                epoch=epoch,
                state="Undefined",
                age=0,
                balance_atoms=0,
                stake_atoms=0,
                replenished_stake_atoms=0,
                locked_stake_atoms=0,
                delegatee="",
                inviter_address="",
                inviter_tx_hash="",
                invite_epoch_height=None,
                updated_height=height,
                updated_at=timestamp,
                raw={},
            )
        state_old, state_new = state_change(changes.get("state"))
        pos = Position(
            address=address,
            epoch=epoch,
            state=state_new or pos.state,
            age=change_to_new_int(changes.get("age"), pos.age),
            balance_atoms=change_to_new_atoms(changes.get("balance"), pos.balance_atoms),
            stake_atoms=change_to_new_atoms(changes.get("stake"), pos.stake_atoms),
            replenished_stake_atoms=change_to_new_atoms(
                changes.get("replenishedStake"), pos.replenished_stake_atoms
            ),
            locked_stake_atoms=change_to_new_atoms(changes.get("lockedStake"), pos.locked_stake_atoms),
            delegatee=change_to_new_str(changes.get("delegatee"), pos.delegatee),
            inviter_address=pos.inviter_address,
            inviter_tx_hash=pos.inviter_tx_hash,
            invite_epoch_height=pos.invite_epoch_height,
            updated_height=height,
            updated_at=timestamp,
            raw=pos.raw,
        )
        self.ledger.upsert_position(pos)

    def seed_current_positions(self, epoch: int, height: int, timestamp: str) -> int:
        identities = self.rpc().call("dna_identities", [])
        if not isinstance(identities, list):
            raise IdenaRPCError(f"unexpected dna_identities result: {type(identities)}")
        pending: List[Dict[str, Any]] = []
        for identity in identities:
            if not isinstance(identity, dict):
                continue
            state = str(identity.get("state") or "Undefined")
            locked = decimal_to_atoms(identity.get("lockedStake", 0))
            if state not in TRACKED_STATES and locked <= 0:
                continue
            address = normalize_address(identity.get("address"))
            if not address:
                continue
            pending.append(identity)

        balances = self.batch_get_balances([normalize_address(item.get("address")) for item in pending])
        seeded = 0
        for identity in pending:
            address = normalize_address(identity.get("address"))
            balance = balances.get(address)
            pos = position_from_identity(
                identity=identity,
                balance=balance,
                epoch=epoch,
                height=height,
                timestamp=timestamp,
            )
            old = self.ledger.load_position(address)
            if old:
                delta = delta_between(old, pos)
                if delta != Delta() or old.state != pos.state:
                    block = self.ledger.get_cached_block(height) or {
                        "height": height,
                        "hash": "",
                        "coinbase": "",
                        "timestamp": timestamp,
                        "flags": [],
                    }
                    event = event_from_delta(
                        address=address,
                        epoch=epoch,
                        block=block,
                        delta=delta,
                        old_state=old.state,
                        new_state=pos.state,
                        source="current_position_resync",
                        raw=pos.raw,
                        counterparty_address=pos.inviter_address,
                        tx_hash=pos.inviter_tx_hash,
                    )
                    event = mark_non_reward_event(
                        event,
                        kind="coverage_gap_net_change",
                        confidence="gap_net",
                        notes="net position change across an indexed coverage gap; not attributable to a single block reward",
                    )
                    self.ledger.insert_event(event)
            self.ledger.upsert_position(pos)
            self.update_invitation_liability(pos)
            seeded += 1
        self.ledger.conn.commit()
        return seeded

    def update_invitation_liability(self, pos: Position) -> None:
        if pos.locked_stake_atoms <= 0 and not pos.inviter_tx_hash:
            return
        status = "open"
        if pos.locked_stake_atoms <= 0:
            status = "closed"
        elif pos.age >= LIABILITY_WINDOW_EPOCHS:
            status = "matured"
        self.ledger.upsert_liability(
            invitee_address=pos.address,
            inviter_address=pos.inviter_address,
            tx_hash=pos.inviter_tx_hash,
            epoch=pos.epoch,
            invite_epoch_height=pos.invite_epoch_height,
            locked_atoms=pos.locked_stake_atoms,
            status=status,
            height=pos.updated_height,
            raw=pos.raw,
        )

    def watched_addresses(self) -> List[str]:
        rows = self.ledger.conn.execute(
            """
            SELECT address FROM positions
            WHERE state IN ('Candidate', 'Newbie', 'Verified', 'Human', 'Suspended', 'Zombie')
               OR locked_stake_atoms > 0
            ORDER BY address
            """
        ).fetchall()
        return [str(row["address"]) for row in rows]

    def wait_for_live_block_stability(
        self,
        block: Dict[str, Any],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[int]]:
        height = int(block["height"])
        if self.live_settle_seconds <= 0:
            return block, height
        self.sleeper(self.live_settle_seconds)
        fresh_block = self.get_last_block()
        fresh_height = int(fresh_block["height"])
        block_hash = str(block.get("hash") or "")
        fresh_hash = str(fresh_block.get("hash") or "")
        if fresh_height != height or (block_hash and fresh_hash and fresh_hash != block_hash):
            print(
                f"[INFO] deferring live scan: head moved from {height} to {fresh_height} "
                "during settle wait",
                file=sys.stderr,
            )
            return None, fresh_height
        return fresh_block, fresh_height

    def process_block_live(self, epoch: int, block: Dict[str, Any]) -> Optional[int]:
        height = int(block["height"])
        changed = 0
        addresses = set(self.watched_addresses())
        if block.get("coinbase"):
            addresses.add(normalize_address(block.get("coinbase")))

        identities_by_address: Dict[str, Dict[str, Any]] = {}
        try:
            identities = self.rpc().call("dna_identities", [])
            if isinstance(identities, list):
                for identity in identities:
                    if isinstance(identity, dict):
                        identity_address = normalize_address(identity.get("address"))
                        if identity_address:
                            identities_by_address[identity_address] = identity
        except IdenaRPCError as exc:
            print(f"[WARN] failed to bulk-read identities at {height}: {exc}", file=sys.stderr)

        sorted_addresses = sorted(addr for addr in addresses if addr)
        balances = self.batch_get_balances(sorted_addresses)
        fresh_block = self.get_last_block()
        if int(fresh_block["height"]) != height:
            print(
                f"[INFO] discarding non-atomic scan: started at height {height}, ended at {fresh_block['height']}",
                file=sys.stderr,
            )
            return None
        for address in sorted_addresses:
            try:
                identity = identities_by_address.get(address)
                if identity is None:
                    identity = self.rpc().get_identity(address)
                balance = balances.get(address)
                if balance is None:
                    balance = self.rpc().call("dna_getBalance", [address])
            except IdenaRPCError as exc:
                print(f"[WARN] failed to read {address} at {height}: {exc}", file=sys.stderr)
                continue
            if not isinstance(identity, dict) or not isinstance(balance, dict):
                continue
            identity = dict(identity)
            identity.setdefault("address", address)
            pos = position_from_identity(
                identity=identity,
                balance=balance,
                epoch=epoch,
                height=height,
                timestamp=str(block["timestamp"]),
            )
            old = self.ledger.load_position(address)
            if old is None:
                self.ledger.upsert_position(pos)
                self.update_invitation_liability(pos)
                changed += 1
                continue
            delta = delta_between(old, pos)
            if delta != Delta() or old.state != pos.state or old.delegatee != pos.delegatee:
                event = event_from_delta(
                    address=address,
                    epoch=epoch,
                    block=block,
                    delta=delta,
                    old_state=old.state,
                    new_state=pos.state,
                    source="live_rpc_delta",
                    raw=pos.raw,
                    counterparty_address=pos.inviter_address,
                    tx_hash=pos.inviter_tx_hash,
                )
                if old.updated_height == height:
                    event = mark_non_reward_event(
                        event,
                        kind="same_height_net_correction",
                        confidence="rpc_race",
                        notes="state changed without an observed block-height change; excluded from reward classification",
                    )
                self.ledger.insert_event(event)
                changed += 1
            self.ledger.upsert_position(pos)
            self.update_invitation_liability(pos)
        self.ledger.set_meta("last_height", height)
        self.ledger.conn.commit()
        return changed

    def deferred_live_result(
        self,
        *,
        epoch: int,
        height: int,
        imported: int,
        seeded: int,
        current_height: Optional[int] = None,
    ) -> Dict[str, Any]:
        result = {
            "epoch": epoch,
            "height": height,
            "importedRollingEvents": imported,
            "seededPositions": seeded,
            "liveChanges": 0,
            "deferredLiveBlock": True,
        }
        if current_height is not None:
            result["currentHeight"] = current_height
        return result

    def once(self) -> Dict[str, Any]:
        epoch_info = self.get_epoch()
        epoch = int(epoch_info.get("epoch"))
        last_block = self.get_last_block()
        height = int(last_block["height"])

        imported = self.import_rolling_epoch(epoch, with_block_lookup=True)
        seeded = 0
        if self.ledger.get_meta(f"seeded_epoch_{epoch}") != "1":
            seeded = self.seed_current_positions(epoch, height, str(last_block["timestamp"]))
            self.ledger.set_meta(f"seeded_epoch_{epoch}", "1")

        cursor = int(self.ledger.get_meta("last_height", "0") or 0)
        if cursor >= height:
            return {
                "epoch": epoch,
                "height": height,
                "importedRollingEvents": imported,
                "seededPositions": seeded,
                "liveChanges": 0,
                "skippedLiveBlock": True,
            }
        if cursor and height > cursor + 1:
            self.ledger.record_gap(
                cursor + 1,
                height - 1,
                "historical balance RPC unavailable; live delta indexer resumed at current tip",
            )

        stable_block, current_height = self.wait_for_live_block_stability(last_block)
        if stable_block is None:
            return self.deferred_live_result(
                epoch=epoch,
                height=height,
                imported=imported,
                seeded=seeded,
                current_height=current_height,
            )
        changed = self.process_block_live(epoch, stable_block)
        if changed is None:
            return self.deferred_live_result(
                epoch=epoch,
                height=height,
                imported=imported,
                seeded=seeded,
            )
        return {
            "epoch": epoch,
            "height": height,
            "importedRollingEvents": imported,
            "seededPositions": seeded,
            "liveChanges": changed,
        }

    def sleep_interval_for_result(self, result: Dict[str, Any]) -> float:
        if result.get("deferredLiveBlock"):
            return max(float(self.poll_interval), self.non_atomic_backoff_seconds)
        return float(self.poll_interval)

    def run(self) -> None:
        while True:
            sleep_seconds = float(self.poll_interval)
            try:
                result = self.once()
                sleep_seconds = self.sleep_interval_for_result(result)
                if not result.get("skippedLiveBlock"):
                    print(f"[INFO] {utc_now()} {json.dumps(result, sort_keys=True)}", flush=True)
            except (IdenaRPCError, OSError, ValueError, sqlite3.Error) as exc:
                print(f"[ERROR] {utc_now()} {exc}", file=sys.stderr, flush=True)
            self.sleeper(sleep_seconds)


def change_to_delta_atoms(change: Any) -> int:
    if not isinstance(change, list) or len(change) != 2:
        return 0
    return decimal_to_atoms(change[1]) - decimal_to_atoms(change[0])


def change_to_new_atoms(change: Any, default: int) -> int:
    if not isinstance(change, list) or len(change) != 2:
        return default
    return decimal_to_atoms(change[1])


def change_to_new_int(change: Any, default: int) -> int:
    if not isinstance(change, list) or len(change) != 2:
        return default
    try:
        return int(change[1])
    except (TypeError, ValueError):
        return default


def change_to_new_str(change: Any, default: str) -> str:
    if not isinstance(change, list) or len(change) != 2:
        return default
    return normalize_address(change[1])


def state_change(change: Any) -> Tuple[str, str]:
    if not isinstance(change, list) or len(change) != 2:
        return "", ""
    return str(change[0] or ""), str(change[1] or "")


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--rolling-data-dir", type=Path, default=ROLLING_DATA_DIR)
    parser.add_argument("--rpc-url", default=os.getenv("IDENA_RPC_URL", "http://127.0.0.1:9009"))
    parser.add_argument("--api-key-file", default=os.getenv("IDENA_API_KEY_FILE", ""))
    parser.add_argument("--allow-remote-rpc", action="store_true")
    parser.add_argument("--poll-interval", type=int, default=POLL_INTERVAL_SECONDS)
    parser.add_argument("--live-settle-seconds", type=float, default=LIVE_SETTLE_SECONDS)
    parser.add_argument(
        "--non-atomic-backoff-seconds",
        type=float,
        default=NON_ATOMIC_BACKOFF_SECONDS,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("run")
    sub.add_parser("once")
    sub.add_parser("status")

    export = sub.add_parser("export-replay")
    export.add_argument("--epoch", type=int)
    export.add_argument("--max-height", type=int)
    export.add_argument("--allow-inferred", action="store_true")
    export.add_argument(
        "--require-exact",
        action="store_true",
        help="Fail if no exact eligible reward events are available for the selected range",
    )

    import_parser = sub.add_parser("import-rolling")
    import_parser.add_argument("--epoch", type=int, required=True)
    import_parser.add_argument("--no-block-lookup", action="store_true")

    exact_import = sub.add_parser(
        "import-statscollector-replay",
        aliases=["import-exact-replay"],
        help="Import exact reward events produced from official idena-indexer StatsCollector data",
    )
    exact_import.add_argument("events_file", type=Path)
    exact_import.add_argument("--epoch", type=int)
    exact_import.add_argument("--source", default=STATS_COLLECTOR_SOURCE)

    exact_sync = sub.add_parser(
        "sync-official-indexer",
        help="Export official idena-indexer StatsCollector rewards from Postgres and import exact replay events",
    )
    exact_sync.add_argument("--database-url-file", type=Path)
    exact_sync.add_argument("--database-url-env", default="IDENA_INDEXER_DATABASE_URL")
    exact_sync.add_argument("--sql-file", type=Path, default=DEFAULT_OFFICIAL_INDEXER_SQL_FILE)
    exact_sync.add_argument("--psql-bin", default="psql")
    exact_sync.add_argument("--timeout-seconds", type=int, default=DEFAULT_PSQL_TIMEOUT_SECONDS)
    exact_sync.add_argument("--max-output-bytes", type=int, default=MAX_OFFICIAL_INDEXER_EXPORT_BYTES)
    exact_sync.add_argument("--source", default=STATS_COLLECTOR_SOURCE)

    api_sync = sub.add_parser(
        "sync-official-api",
        help="Import exact completed-epoch rewards from the official public Idena API",
    )
    api_sync.add_argument("--api-base-url", default=DEFAULT_OFFICIAL_API_BASE_URL)
    api_sync.add_argument(
        "--epoch",
        type=int,
        action="append",
        help="Completed epoch to import; repeat for multiple epochs. Defaults to previous completed epoch.",
    )
    api_sync.add_argument("--completed-epochs", type=int, default=1)
    api_sync.add_argument("--page-limit", type=int, default=DEFAULT_OFFICIAL_API_PAGE_LIMIT)
    api_sync.add_argument("--mining-page-limit", type=int, default=20)
    api_sync.add_argument("--timeout-seconds", type=int, default=DEFAULT_OFFICIAL_API_TIMEOUT_SECONDS)
    api_sync.add_argument("--retries", type=int, default=DEFAULT_OFFICIAL_API_RETRIES)
    api_sync.add_argument("--request-delay-seconds", type=float, default=0.0)
    api_sync.add_argument("--source", default=OFFICIAL_API_SOURCE)
    api_sync.add_argument(
        "--skip-mining-summaries",
        action="store_true",
        help="Import validation/staking/session rewards only; mining summaries are included by default.",
    )

    query = sub.add_parser("query")
    query.add_argument("address")
    query.add_argument("--epoch", type=int)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    ledger = RewardLedger(
        args.db,
        read_only=args.command in {"status", "query", "export-replay"},
    )
    client: Optional[IdenaRPCClientMinimal] = None
    if args.command in {"run", "once", "import-rolling"}:
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
    indexer = RewardIndexer(
        ledger=ledger,
        client=client,
        rolling_data_dir=args.rolling_data_dir,
        poll_interval=args.poll_interval,
        live_settle_seconds=args.live_settle_seconds,
        non_atomic_backoff_seconds=args.non_atomic_backoff_seconds,
    )
    try:
        if args.command == "run":
            indexer.run()
            return 0
        if args.command == "once":
            print_json(indexer.once())
            return 0
        if args.command == "status":
            print_json(ledger.status())
            return 0
        if args.command == "export-replay":
            try:
                events = ledger.export_replay_events(
                    epoch=args.epoch,
                    max_height=args.max_height,
                    allow_inferred=args.allow_inferred,
                    require_exact=args.require_exact,
                )
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print_json(events)
            return 0
        if args.command == "import-rolling":
            count = indexer.import_rolling_epoch(args.epoch, with_block_lookup=not args.no_block_lookup)
            print_json({"epoch": args.epoch, "importedEvents": count})
            return 0
        if args.command in {"import-statscollector-replay", "import-exact-replay"}:
            try:
                raw_events = read_limited_json_file(
                    args.events_file,
                    "StatsCollector replay events",
                    MAX_OFFICIAL_INDEXER_EXPORT_BYTES,
                )
                count = ledger.import_statscollector_replay_events(
                    raw_events,
                    default_epoch=args.epoch,
                    source=args.source,
                )
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print_json(
                {
                    "source": args.source,
                    "inputFile": str(args.events_file),
                    "importedEvents": count,
                }
            )
            return 0
        if args.command == "sync-official-indexer":
            try:
                database_url = load_official_indexer_database_url(
                    database_url_file=args.database_url_file,
                    database_url_env=args.database_url_env,
                )
                result = sync_official_indexer_rewards(
                    ledger=ledger,
                    database_url=database_url,
                    sql_file=args.sql_file,
                    psql_bin=args.psql_bin,
                    timeout_seconds=args.timeout_seconds,
                    max_output_bytes=args.max_output_bytes,
                    source=args.source,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print_json(result)
            return 0
        if args.command == "sync-official-api":
            try:
                result = sync_official_api_rewards(
                    ledger=ledger,
                    api_base_url=args.api_base_url,
                    epochs=args.epoch,
                    completed_epochs=args.completed_epochs,
                    include_mining_summaries=not args.skip_mining_summaries,
                    page_limit=args.page_limit,
                    mining_page_limit=args.mining_page_limit,
                    timeout_seconds=args.timeout_seconds,
                    retries=args.retries,
                    request_delay_seconds=args.request_delay_seconds,
                    source=args.source,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print_json(result)
            return 0
        if args.command == "query":
            result = ledger.query_address(args.address, args.epoch)
            print_json(result)
            return 0
    finally:
        ledger.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
