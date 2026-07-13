#!/usr/bin/env python3
"""Compare PoHW Experiment 0 report bundles from multiple nodes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat as stat_module
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


MAX_REPORT_FILE_BYTES = 5 * 1024 * 1024
MAX_REPORT_FILES = 200
REGISTRATION_PROOF_FILE = "miner-registration-envelope.json"
REGISTRATION_PROOF_MAX_AGE_SECONDS = "0"
REGISTRATION_PROOF_VERIFY_TIMEOUT_SECONDS = 120
FORK_ACTIVATION_HASH_TAG = b"POHW1_FORK_ACTIVATION"
FORK_ACTIVATION_SCHEMA_VERSION = 2
FORK_DIFFICULTY_ALGORITHM = "bootstrap_then_bitcoin_2016_v1"
BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL = 2016
U64_MAX = (1 << 64) - 1

SECRET_NAME_RE = re.compile(
    r"(^|[./_-])("
    r"\.env|api[_-]?key|auth[_-]?token|dashboard[_-]?token|"
    r"rpc[_-]?cookie|private[_-]?key|seed[_-]?phrase|mnemonic|wallet"
    r")([./_-]|$)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\b[xyzt]prv[1-9A-HJ-NP-Za-km-z]{20,}\b"),
    re.compile(r"\b__cookie__:[0-9a-fA-F]{16,}\b"),
    re.compile(
        r"\b("
        r"IDENA_API_KEY|DASHBOARD_API_TOKEN|BITCOIN_RPC_COOKIE|"
        r"PRIVATE_KEY|MNEMONIC|SEED_PHRASE"
        r")\s*[:=]\s*['\"]?[^'\"\s]{8,}",
        re.IGNORECASE,
    ),
]
HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")


def compact_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    if exponent > 32 or mantissa > 0x7FFFFF:
        return 0
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def compact_from_target(target: int) -> int:
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


@dataclass
class Issue:
    level: str
    message: str


@dataclass
class Report:
    source: str
    root: Path | None = None
    label: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    status: dict[str, Any] | None = None
    preflight: dict[str, Any] | None = None
    fork_activation: dict[str, Any] | None = None
    latest_snapshot_summary: dict[str, Any] | None = None
    registration_proof: dict[str, Any] | None = None
    registration_proof_error: str | None = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def node_id(self) -> str:
        miner_id = self.metadata.get("miner_id", "").strip()
        return miner_id or self.label or Path(self.source).name

    @property
    def participant_id(self) -> str | None:
        registration = (self.registration_proof or {}).get("miner_registration")
        if not isinstance(registration, dict):
            return None
        required = {
            "btc_payout_script_hex": registration.get("btc_payout_script_hex"),
            "claim_owner_pubkey_hex": registration.get("claim_owner_pubkey_hex"),
            "idena_address": registration.get("idena_address"),
            "miner_id": registration.get("miner_id"),
            "mining_pubkey_hex": registration.get("mining_pubkey_hex"),
        }
        if not all(isinstance(value, str) and value for value in required.values()):
            return None
        payload = json.dumps(required, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @property
    def registration_miner_id(self) -> str | None:
        registration = (self.registration_proof or {}).get("miner_registration")
        if isinstance(registration, dict) and isinstance(registration.get("miner_id"), str):
            return registration["miner_id"].strip().lower()
        return None

    @property
    def git_commit(self) -> str:
        return self.metadata.get("git_commit", "").strip()

    @property
    def git_dirty(self) -> bool:
        return self.metadata.get("git_dirty", "").strip().lower() == "true"

    @property
    def replay(self) -> dict[str, Any]:
        local = (self.preflight or {}).get("local") or {}
        replay = local.get("replay")
        return replay if isinstance(replay, dict) else {}

    @property
    def readiness(self) -> dict[str, Any]:
        readiness = (self.preflight or {}).get("readiness")
        return readiness if isinstance(readiness, dict) else {}

    @property
    def peer_probe(self) -> list[Any]:
        peers = (self.preflight or {}).get("peer_inventory_probe")
        if not isinstance(peers, list):
            return []
        return [peer for peer in peers if isinstance(peer, dict)]

    @property
    def malformed_peer_probe_count(self) -> int:
        peers = (self.preflight or {}).get("peer_inventory_probe")
        if not isinstance(peers, list):
            return 0
        return sum(1 for peer in peers if not isinstance(peer, dict))

    @property
    def sharechain_message_count(self) -> int:
        local = (self.preflight or {}).get("local") or {}
        return int_or_zero(local.get("sharechain_message_count"))

    @property
    def gossip_envelope_count(self) -> int:
        local = (self.preflight or {}).get("local") or {}
        return int_or_zero(local.get("gossip_envelope_count"))

    @property
    def replay_fingerprint(self) -> str | None:
        replay = self.replay
        if not replay and self.sharechain_message_count == 0:
            return None
        payload = json.dumps(replay, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @property
    def latest_snapshot(self) -> dict[str, Any] | None:
        snapshot_dir = (self.preflight or {}).get("snapshot_directory") or {}
        latest = snapshot_dir.get("latest") if isinstance(snapshot_dir, dict) else None
        if isinstance(latest, dict):
            return latest
        summary = self.latest_snapshot_summary or {}
        latest = summary.get("latest") if isinstance(summary, dict) else None
        if isinstance(latest, dict):
            return latest
        if summary.get("snapshot_day") and summary.get("identity_root"):
            return summary
        return None

    @property
    def snapshot_key(self) -> str | None:
        snapshot = self.latest_snapshot
        if not snapshot:
            return None
        payload = {
            "snapshot_day": snapshot.get("snapshot_day"),
            "idena_height": snapshot.get("idena_height"),
            "idena_block_hash": snapshot.get("idena_block_hash"),
            "identity_root": snapshot.get("identity_root"),
            "score_root": snapshot.get("score_root"),
            "formula_version": snapshot.get("formula_version"),
            "leaf_count": snapshot.get("leaf_count"),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @property
    def activation_key(self) -> str | None:
        if not isinstance(self.fork_activation, dict):
            return None
        payload = {
            "activation_id": self.fork_activation.get("activation_id"),
            "schema_version": self.fork_activation.get("schema_version"),
            "config": self.fork_activation.get("config"),
            "fork_point": self.fork_activation.get("fork_point"),
            "launch_block": self.fork_activation.get("launch_block"),
            "replay_protection_required": self.fork_activation.get(
                "replay_protection_required"
            ),
        }
        if not payload["activation_id"]:
            return None
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @property
    def report_fingerprint(self) -> str:
        payload = {
            "metadata": self.metadata,
            "status": self.status,
            "preflight": self.preflight,
            "fork_activation": self.fork_activation,
            "latest_snapshot_summary": self.latest_snapshot_summary,
            "registration_proof": self.registration_proof,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare public PoHW Experiment 0 report directories or .tar.gz bundles."
    )
    parser.add_argument("reports", nargs="+", help="Report directory or report .tar.gz")
    parser.add_argument(
        "--min-nodes",
        type=int,
        default=1,
        help="Minimum registered unique participants required; use 0 for unregistered debug comparisons.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat replay mismatches and unreachable peers as errors instead of warnings.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the text report.",
    )
    parser.add_argument(
        "--p2pool-node-bin",
        help="Path to p2pool-node; defaults to POHW_P2POOL_NODE_BIN, then cargo run from this repo.",
    )
    return parser.parse_args()


def p2pool_node_command(explicit: str | None) -> list[str]:
    if explicit:
        return [explicit]
    env_bin = os.environ.get("POHW_P2POOL_NODE_BIN")
    if env_bin:
        return [env_bin]
    repo_root = Path(__file__).resolve().parents[1]
    if (repo_root / "Cargo.toml").exists():
        return [
            "cargo",
            "run",
            "--manifest-path",
            str(repo_root / "Cargo.toml"),
            "-q",
            "-p",
            "p2pool-node",
            "--",
        ]
    for candidate in (
        repo_root / "target" / "release" / "p2pool-node",
        repo_root / "target" / "debug" / "p2pool-node",
    ):
        if candidate.exists() and os.access(candidate, os.X_OK):
            return [str(candidate)]
    return ["p2pool-node"]


def load_json(path: Path, report: Report) -> dict[str, Any] | None:
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        report.issues.append(Issue("error", f"missing {path.name}"))
        return None
    except OSError as exc:
        report.issues.append(Issue("error", f"cannot stat {path.name}: {exc}"))
        return None
    if stat_module.S_ISLNK(file_stat.st_mode):
        report.issues.append(Issue("error", f"{path.name} must not be a symlink"))
        return None
    if not stat_module.S_ISREG(file_stat.st_mode):
        report.issues.append(Issue("error", f"{path.name} must be a regular file"))
        return None
    if file_stat.st_size > MAX_REPORT_FILE_BYTES:
        report.issues.append(Issue("error", f"{path.name} is too large"))
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report parsing should continue.
        report.issues.append(Issue("error", f"invalid {path.name}: {exc}"))
        return None
    if not isinstance(data, dict):
        report.issues.append(Issue("error", f"{path.name} is not a JSON object"))
        return None
    return data


def load_optional_json(path: Path, report: Report) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    return load_json(path, report)


def validate_fork_activation_manifest(
    data: dict[str, Any] | None,
    report: Report,
) -> dict[str, Any] | None:
    if data is None:
        return None
    issue_start = len(report.issues)

    def error(message: str) -> None:
        report.issues.append(Issue("error", f"invalid fork-activation.json: {message}"))

    def require_dict(parent: dict[str, Any], key: str) -> dict[str, Any] | None:
        value = parent.get(key)
        if not isinstance(value, dict):
            error(f"{key} must be an object")
            return None
        return value

    def require_str(parent: dict[str, Any], key: str) -> str | None:
        value = parent.get(key)
        if not isinstance(value, str) or not value:
            error(f"{key} must be a non-empty string")
            return None
        return value

    def require_bool(parent: dict[str, Any], key: str) -> bool | None:
        value = parent.get(key)
        if not isinstance(value, bool):
            error(f"{key} must be a boolean")
            return None
        return value

    def require_u64(parent: dict[str, Any], key: str, *, positive: bool = False) -> int | None:
        value = parent.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            error(f"{key} must be an integer")
            return None
        if value < 0 or (positive and value == 0):
            comparator = "positive" if positive else "non-negative"
            error(f"{key} must be {comparator}")
            return None
        if value > U64_MAX:
            error(f"{key} must fit in an unsigned 64-bit integer")
            return None
        return value

    def require_hash(parent: dict[str, Any], key: str) -> str | None:
        value = require_str(parent, key)
        if value is None:
            return None
        if not HEX_32_RE.fullmatch(value):
            error(f"{key} must be 64 lowercase hex characters")
            return None
        return value

    def parse_timestamp(value: str | None, key: str) -> datetime | None:
        if value is None:
            return None
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            error(f"{key} must be an RFC3339 timestamp")
            return None
        if timestamp.tzinfo is None:
            error(f"{key} must include a timezone")
            return None
        return timestamp.astimezone(timezone.utc)

    schema_version = require_u64(data, "schema_version", positive=True)
    if schema_version is not None and schema_version != FORK_ACTIVATION_SCHEMA_VERSION:
        error(f"schema_version must be {FORK_ACTIVATION_SCHEMA_VERSION}")
    activation_id = require_hash(data, "activation_id")
    config = require_dict(data, "config")
    fork_point = require_dict(data, "fork_point")
    launch_block = require_dict(data, "launch_block")
    replay_protection_required = require_bool(data, "replay_protection_required")

    config_launch_timestamp = None
    inherited_utxo_spending_enabled = None
    if config is not None:
        chain_name = require_str(config, "chain_name")
        if chain_name is not None and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", chain_name):
            error("config.chain_name contains unsupported characters")
        config_launch_timestamp = parse_timestamp(
            require_str(config, "launch_timestamp_utc"),
            "config.launch_timestamp_utc",
        )
        inherited_utxo_spending_enabled = require_bool(
            config,
            "inherited_utxo_spending_enabled",
        )
        pow_limit_bits = require_u64(config, "post_fork_pow_limit_bits", positive=True)
        if pow_limit_bits is not None:
            if pow_limit_bits > 0xFFFFFFFF:
                error("config.post_fork_pow_limit_bits must fit in 32 bits")
            else:
                pow_limit = compact_target(pow_limit_bits)
                if pow_limit == 0:
                    error("config.post_fork_pow_limit_bits decodes to a zero target")
                elif compact_from_target(pow_limit) != pow_limit_bits:
                    error("config.post_fork_pow_limit_bits must be canonical")
        target_spacing = require_u64(config, "target_spacing_seconds", positive=True)
        if target_spacing is not None:
            if target_spacing < 4:
                error("config.target_spacing_seconds must be at least 4")
            elif target_spacing > U64_MAX // (BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL * 4):
                error("config.target_spacing_seconds overflows the bounded Bitcoin retarget period")
        difficulty_algorithm = require_str(config, "difficulty_algorithm")
        if (
            difficulty_algorithm is not None
            and difficulty_algorithm != FORK_DIFFICULTY_ALGORITHM
        ):
            error(
                "config.difficulty_algorithm must be "
                f"{FORK_DIFFICULTY_ALGORITHM}"
            )
        require_u64(config, "bootstrap_handoff_hashrate_hps", positive=True)
        if (
            inherited_utxo_spending_enabled is not None
            and replay_protection_required is not None
            and replay_protection_required == inherited_utxo_spending_enabled
        ):
            error("replay_protection_required must be the inverse of inherited_utxo_spending_enabled")

    inherited_tip_height = None
    first_fork_height = None
    fork_launch_timestamp = None
    if fork_point is not None:
        inherited_tip_height = require_u64(fork_point, "inherited_tip_height")
        require_hash(fork_point, "inherited_tip_hash")
        first_fork_height = require_u64(fork_point, "first_fork_height")
        fork_launch_timestamp = parse_timestamp(
            require_str(fork_point, "launch_timestamp_utc"),
            "fork_point.launch_timestamp_utc",
        )
        if (
            config_launch_timestamp is not None
            and fork_launch_timestamp is not None
            and config_launch_timestamp != fork_launch_timestamp
        ):
            error("config.launch_timestamp_utc must match fork_point.launch_timestamp_utc")
        if (
            inherited_tip_height is not None
            and first_fork_height is not None
            and first_fork_height != inherited_tip_height + 1
        ):
            error("fork_point.first_fork_height must equal inherited_tip_height + 1")

    launch_height = None
    launch_block_timestamp = None
    if launch_block is not None:
        launch_height = require_u64(launch_block, "height")
        require_hash(launch_block, "block_hash")
        launch_block_timestamp = parse_timestamp(
            require_str(launch_block, "timestamp"),
            "launch_block.timestamp",
        )
        if (
            first_fork_height is not None
            and launch_height is not None
            and launch_height != first_fork_height
        ):
            error("launch_block.height must equal fork_point.first_fork_height")
        if (
            config_launch_timestamp is not None
            and launch_block_timestamp is not None
            and launch_block_timestamp < config_launch_timestamp
        ):
            error("launch_block.timestamp must not be before config.launch_timestamp_utc")

    if len(report.issues) == issue_start and activation_id is not None:
        expected_activation_id = compute_fork_activation_id(data)
        if activation_id != expected_activation_id:
            error("activation_id does not match manifest content")

    return None if len(report.issues) > issue_start else data


def compute_fork_activation_id(data: dict[str, Any]) -> str:
    config = data["config"]
    fork_point = data["fork_point"]
    launch_block = data["launch_block"]
    payload = {
        "schema_version": data["schema_version"],
        "config": {
            "chain_name": config["chain_name"],
            "launch_timestamp_utc": config["launch_timestamp_utc"],
            "inherited_utxo_spending_enabled": config[
                "inherited_utxo_spending_enabled"
            ],
            "post_fork_pow_limit_bits": config["post_fork_pow_limit_bits"],
            "target_spacing_seconds": config["target_spacing_seconds"],
            "difficulty_algorithm": config["difficulty_algorithm"],
            "bootstrap_handoff_hashrate_hps": config[
                "bootstrap_handoff_hashrate_hps"
            ],
        },
        "fork_point": {
            "inherited_tip_height": fork_point["inherited_tip_height"],
            "inherited_tip_hash": fork_point["inherited_tip_hash"],
            "first_fork_height": fork_point["first_fork_height"],
            "launch_timestamp_utc": fork_point["launch_timestamp_utc"],
        },
        "launch_block": {
            "height": launch_block["height"],
            "block_hash": launch_block["block_hash"],
            "timestamp": launch_block["timestamp"],
        },
        "replay_protection_required": data["replay_protection_required"],
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(FORK_ACTIVATION_HASH_TAG + b"\0" + encoded).hexdigest()


def load_metadata(path: Path, report: Report) -> dict[str, str]:
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        report.issues.append(Issue("error", "missing metadata.txt"))
        return {}
    except OSError as exc:
        report.issues.append(Issue("error", f"cannot stat metadata.txt: {exc}"))
        return {}
    if stat_module.S_ISLNK(file_stat.st_mode):
        report.issues.append(Issue("error", "metadata.txt must not be a symlink"))
        return {}
    if not stat_module.S_ISREG(file_stat.st_mode):
        report.issues.append(Issue("error", "metadata.txt must be a regular file"))
        return {}
    if file_stat.st_size > MAX_REPORT_FILE_BYTES:
        report.issues.append(Issue("error", "metadata.txt is too large"))
        return {}
    metadata: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def load_registration_proof(
    root: Path,
    report: Report,
    p2pool_cmd: list[str],
) -> dict[str, Any] | None:
    proof_path = root / REGISTRATION_PROOF_FILE
    if not proof_path.exists() and not proof_path.is_symlink():
        preflight_registration = (report.preflight or {}).get("miner_registration")
        if (
            isinstance(preflight_registration, dict)
            and preflight_registration.get("registered") is True
        ):
            report.registration_proof_error = "registered summary has no signed proof file"
        return None
    try:
        file_stat = proof_path.lstat()
    except OSError as exc:
        report.registration_proof_error = f"cannot stat {REGISTRATION_PROOF_FILE}: {exc}"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    if stat_module.S_ISLNK(file_stat.st_mode):
        report.registration_proof_error = f"{REGISTRATION_PROOF_FILE} must not be a symlink"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    if not stat_module.S_ISREG(file_stat.st_mode):
        report.registration_proof_error = f"{REGISTRATION_PROOF_FILE} must be a regular file"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    if file_stat.st_size > MAX_REPORT_FILE_BYTES:
        report.registration_proof_error = f"{REGISTRATION_PROOF_FILE} is too large"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None

    cmd = [
        *p2pool_cmd,
        "verify-miner-registration-envelope",
        "--envelope-file",
        str(proof_path),
        "--max-future-skew-seconds",
        "300",
        "--max-age-seconds",
        REGISTRATION_PROOF_MAX_AGE_SECONDS,
    ]
    try:
        result = subprocess.run(
            cmd,
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
            text=True,
            timeout=REGISTRATION_PROOF_VERIFY_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 - comparison should explain verifier failures.
        report.registration_proof_error = f"registration proof verifier failed: {exc}"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        report.registration_proof_error = f"invalid registration proof: {stderr}"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    try:
        proof = json.loads(result.stdout)
    except Exception as exc:  # noqa: BLE001 - user-facing validation.
        report.registration_proof_error = f"registration proof verifier returned invalid JSON: {exc}"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    if not isinstance(proof, dict) or proof.get("valid") is not True:
        report.registration_proof_error = "registration proof verifier did not return valid=true"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    registration = proof.get("miner_registration")
    if not isinstance(registration, dict):
        report.registration_proof_error = "registration proof has no miner_registration object"
        report.issues.append(Issue("error", report.registration_proof_error))
        return None
    return proof


def validate_archive_members(archive: tarfile.TarFile) -> list[Issue]:
    issues: list[Issue] = []
    members = archive.getmembers()
    if len(members) > MAX_REPORT_FILES:
        issues.append(Issue("error", f"archive contains too many files: {len(members)}"))
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            issues.append(Issue("error", f"unsafe archive path: {member.name}"))
            continue
        if not (member.isfile() or member.isdir()):
            issues.append(Issue("error", f"archive contains unsupported entry: {member.name}"))
            continue
        if member.isfile() and member.size > MAX_REPORT_FILE_BYTES:
            issues.append(Issue("error", f"archive file too large: {member.name}"))
    return issues


def validate_directory_members(root: Path) -> list[Issue]:
    issues: list[Issue] = []
    file_count = 0
    member_count = 0
    try:
        paths = root.rglob("*")
    except OSError as exc:
        return [Issue("error", f"cannot scan report directory: {exc}")]
    for path in paths:
        try:
            stat_result = path.lstat()
        except OSError as exc:
            issues.append(Issue("error", f"cannot stat report member: {path}: {exc}"))
            continue
        rel = path.relative_to(root).as_posix()
        member_count += 1
        if member_count > MAX_REPORT_FILES:
            issues.append(Issue("error", f"report directory contains too many entries: {member_count}"))
            break
        if path.is_symlink():
            issues.append(Issue("error", f"report directory contains symlink: {rel}"))
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            issues.append(Issue("error", f"report directory contains unsupported entry: {rel}"))
            continue
        file_count += 1
        if file_count > MAX_REPORT_FILES:
            issues.append(Issue("error", f"report directory contains too many files: {file_count}"))
            break
        if stat_result.st_size > MAX_REPORT_FILE_BYTES:
            issues.append(Issue("error", f"report file too large: {rel}"))
    return issues


def extract_archive(path: Path, temp_root: Path) -> tuple[Path | None, list[Issue]]:
    issues: list[Issue] = []
    destination = temp_root / path.stem.replace(".", "_")
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(path, "r:*") as archive:
            issues.extend(validate_archive_members(archive))
            if any(issue.level == "error" for issue in issues):
                return None, issues
            archive.extractall(destination)
    except Exception as exc:  # noqa: BLE001 - user-facing archive validation.
        return None, [Issue("error", f"cannot read archive: {exc}")]
    issues.extend(validate_directory_members(destination))
    if any(issue.level == "error" for issue in issues):
        return None, issues
    return find_report_root(destination), issues


def find_report_root(path: Path) -> Path:
    if (path / "metadata.txt").exists() and (path / "multinode-preflight.json").exists():
        return path
    candidates = sorted(
        candidate
        for candidate in path.rglob("*")
        if candidate.is_dir()
        and (candidate / "metadata.txt").exists()
        and (candidate / "multinode-preflight.json").exists()
    )
    return candidates[0] if candidates else path


def scan_for_secrets(root: Path, report: Report) -> None:
    for file_path in sorted(path for path in root.rglob("*") if path.is_file()):
        rel = file_path.relative_to(root).as_posix()
        if SECRET_NAME_RE.search(rel):
            report.issues.append(Issue("error", f"secret-looking filename in report: {rel}"))
            continue
        try:
            if file_path.stat().st_size > MAX_REPORT_FILE_BYTES:
                report.issues.append(Issue("error", f"report file too large: {rel}"))
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            report.issues.append(Issue("error", f"cannot inspect {rel}: {exc}"))
            continue
        for pattern in SECRET_VALUE_PATTERNS:
            if pattern.search(text):
                report.issues.append(Issue("error", f"secret-looking content in report: {rel}"))
                break


def load_report(source: str, temp_root: Path, p2pool_cmd: list[str]) -> Report:
    path = Path(source)
    report = Report(source=source, label=path.name)
    if not path.exists():
        report.issues.append(Issue("error", "report path does not exist"))
        return report
    if path.is_symlink():
        report.issues.append(Issue("error", "report path must not be a symlink"))
        return report
    if path.is_dir():
        directory_issues = validate_directory_members(path)
        report.issues.extend(directory_issues)
        if any(issue.level == "error" for issue in directory_issues):
            return report
        report.root = find_report_root(path)
    elif tarfile.is_tarfile(path):
        root, issues = extract_archive(path, temp_root)
        report.root = root
        report.issues.extend(issues)
    else:
        report.issues.append(Issue("error", "report must be a directory or tar archive"))
        return report

    if report.root is None:
        report.issues.append(Issue("error", "could not locate report root"))
        return report
    report.metadata = load_metadata(report.root / "metadata.txt", report)
    report.status = load_json(report.root / "status.json", report)
    report.preflight = load_json(report.root / "multinode-preflight.json", report)
    report.fork_activation = validate_fork_activation_manifest(
        load_optional_json(report.root / "fork-activation.json", report),
        report,
    )
    report.latest_snapshot_summary = load_json(
        report.root / "latest-snapshot-summary.json", report
    )
    report.registration_proof = load_registration_proof(report.root, report, p2pool_cmd)
    scan_for_secrets(report.root, report)
    return report


def issue(level: str, message: str, issues: list[Issue]) -> None:
    issues.append(Issue(level, message))


def group_by(reports: list[Report], value: str) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for report in reports:
        groups.setdefault(value_of(report, value), []).append(report.node_id)
    return groups


def value_of(report: Report, value: str) -> str:
    if value == "git_commit":
        return report.git_commit or "(missing)"
    if value == "replay_fingerprint":
        return report.replay_fingerprint or "(empty)"
    if value == "snapshot_key":
        return report.snapshot_key or "(none)"
    if value == "activation_key":
        return report.activation_key or "(none)"
    raise ValueError(value)


def compare_reports(
    reports: list[Report],
    min_nodes: int,
    strict: bool,
) -> list[Issue]:
    issues: list[Issue] = []
    unique_participants = {
        participant for report in reports if (participant := report.participant_id) is not None
    }
    if len(unique_participants) < min_nodes:
        issue(
            "error",
            f"expected at least {min_nodes} registered unique participants, got {len(unique_participants)}",
            issues,
        )

    source_groups: dict[str, list[str]] = {}
    node_groups: dict[str, list[str]] = {}
    fingerprint_groups: dict[str, list[str]] = {}
    for report in reports:
        source_groups.setdefault(str(Path(report.source).resolve()), []).append(report.node_id)
        node_groups.setdefault(report.node_id, []).append(report.source)
        fingerprint_groups.setdefault(report.report_fingerprint, []).append(report.node_id)
    for source, nodes in sorted(source_groups.items()):
        if len(nodes) > 1:
            issue("error", f"same report path was supplied multiple times: {source}", issues)
    for node, sources in sorted(node_groups.items()):
        if len(sources) > 1:
            issue("error", f"duplicate node id in reports: {node}", issues)
    for fingerprint, nodes in sorted(fingerprint_groups.items()):
        if len(nodes) > 1:
            issue(
                "error",
                f"duplicate report content {fingerprint[:12]} submitted by: {', '.join(nodes)}",
                issues,
            )

    for report in reports:
        issues.extend(
            Issue(item.level, f"{report.node_id}: {item.message}") for item in report.issues
        )
        if report.git_dirty:
            issue("warn", f"{report.node_id}: git tree was dirty when report was made", issues)
        metadata_miner_id = report.metadata.get("miner_id", "").strip().lower()
        if (
            metadata_miner_id
            and report.registration_miner_id
            and metadata_miner_id != report.registration_miner_id
        ):
            issue(
                "error",
                f"{report.node_id}: metadata miner_id does not match signed registration proof",
                issues,
            )
        if report.participant_id is None:
            detail = (
                f" ({report.registration_proof_error})"
                if report.registration_proof_error
                else ""
            )
            issue(
                "warn",
                f"{report.node_id}: no verified registered miner proof{detail}; report does not count toward --min-nodes",
                issues,
            )
        if report.malformed_peer_probe_count:
            issue(
                "error",
                f"{report.node_id}: peer_inventory_probe contains {report.malformed_peer_probe_count} non-object entries",
                issues,
            )
        pending = [
            key for key, value in sorted(report.readiness.items()) if value is not True
        ]
        if pending:
            issue("warn", f"{report.node_id}: pending readiness items: {', '.join(pending)}", issues)
        reachable = sum(1 for peer in report.peer_probe if peer.get("reachable"))
        if report.peer_probe and reachable == 0:
            level = "error" if strict else "warn"
            issue(level, f"{report.node_id}: no configured peer was reachable", issues)

    commit_groups = group_by(reports, "git_commit")
    if len(commit_groups) > 1:
        formatted = "; ".join(
            f"{commit}: {', '.join(nodes)}" for commit, nodes in sorted(commit_groups.items())
        )
        issue("error", f"reports were produced from different git commits: {formatted}", issues)

    activation_reports = [report for report in reports if report.activation_key is not None]
    if activation_reports and len(activation_reports) != len(reports):
        missing = ", ".join(
            report.node_id for report in reports if report.activation_key is None
        )
        issue("warn", f"missing fork activation manifest in reports: {missing}", issues)
    activation_groups = (
        group_by(activation_reports, "activation_key") if activation_reports else {}
    )
    if len(activation_groups) > 1:
        formatted = "; ".join(
            f"{hashlib.sha256(key.encode('utf-8')).hexdigest()[:12]}: {', '.join(nodes)}"
            for key, nodes in sorted(activation_groups.items())
        )
        issue("error", f"fork activation manifests differ: {formatted}", issues)

    snapshot_groups = group_by(
        [report for report in reports if report.snapshot_key is not None],
        "snapshot_key",
    )
    if len(snapshot_groups) > 1:
        day_groups: dict[str, set[str]] = {}
        for report in reports:
            snapshot = report.latest_snapshot
            if snapshot:
                day = str(snapshot.get("snapshot_day") or "(missing-day)")
                day_groups.setdefault(day, set()).add(report.snapshot_key or "")
        for day, keys in sorted(day_groups.items()):
            if len(keys) > 1:
                issue("error", f"snapshot roots differ for snapshot day {day}", issues)

    replay_reports = [report for report in reports if report.sharechain_message_count > 0]
    replay_groups = group_by(replay_reports, "replay_fingerprint") if replay_reports else {}
    if len(replay_groups) > 1:
        formatted = "; ".join(
            f"{fingerprint[:12]}: {', '.join(nodes)}"
            for fingerprint, nodes in sorted(replay_groups.items())
        )
        level = "error" if strict else "warn"
        issue(level, f"sharechain replay summaries differ: {formatted}", issues)
    return issues


def report_row(report: Report) -> dict[str, Any]:
    snapshot = report.latest_snapshot or {}
    activation = report.fork_activation or {}
    pending = [key for key, value in sorted(report.readiness.items()) if value is not True]
    reachable = sum(1 for peer in report.peer_probe if peer.get("reachable"))
    return {
        "node": report.node_id,
        "participant_id": report.participant_id,
        "git_commit": report.git_commit,
        "git_dirty": report.git_dirty,
        "activation_id": activation.get("activation_id"),
        "sharechain_messages": report.sharechain_message_count,
        "gossip_envelopes": report.gossip_envelope_count,
        "last_message_hash": report.replay.get("last_message_hash"),
        "best_share_tip": report.replay.get("best_share_tip"),
        "snapshot_day": snapshot.get("snapshot_day"),
        "snapshot_identity_root": snapshot.get("identity_root"),
        "snapshot_score_root": snapshot.get("score_root"),
        "peer_probe_reachable": reachable,
        "peer_probe_total": len(report.peer_probe),
        "registration_proof_error": report.registration_proof_error,
        "pending_readiness": pending,
        "issues": [issue.__dict__ for issue in report.issues],
    }


def emit_json(reports: list[Report], issues: list[Issue]) -> None:
    payload = {
        "reports": [report_row(report) for report in reports],
        "issues": [issue.__dict__ for issue in issues],
        "ok": not any(issue.level == "error" for issue in issues),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def short_hash(value: Any) -> str:
    if not value:
        return "-"
    text = str(value)
    return text[:12]


def emit_text(reports: list[Report], issues: list[Issue]) -> None:
    print("PoHW Experiment 0 report comparison")
    print(f"Reports: {len(reports)}")
    print()
    print(
        "Node | Participant | Commit | Dirty | Activation | Share msgs | Gossip env | Replay tip | Snapshot | Peers | Pending"
    )
    print("--- | --- | --- | --- | --- | ---: | ---: | --- | --- | ---: | ---")
    for report in reports:
        snapshot = report.latest_snapshot or {}
        pending = [key for key, value in sorted(report.readiness.items()) if value is not True]
        reachable = sum(1 for peer in report.peer_probe if peer.get("reachable"))
        peer_total = len(report.peer_probe)
        snapshot_label = "-"
        if snapshot:
            snapshot_label = (
                f"{snapshot.get('snapshot_day', '?')} "
                f"{short_hash(snapshot.get('identity_root'))}/"
                f"{short_hash(snapshot.get('score_root'))}"
            )
        print(
            " | ".join(
                [
                    report.node_id,
                    short_hash(report.participant_id),
                    short_hash(report.git_commit),
                    "yes" if report.git_dirty else "no",
                    short_hash((report.fork_activation or {}).get("activation_id")),
                    str(report.sharechain_message_count),
                    str(report.gossip_envelope_count),
                    short_hash(report.replay.get("last_message_hash")),
                    snapshot_label,
                    f"{reachable}/{peer_total}",
                    ", ".join(pending) if pending else "-",
                ]
            )
        )
    print()
    if issues:
        print("Issues:")
        for item in issues:
            print(f"- {item.level.upper()}: {item.message}")
    else:
        print("Issues: none")
    print()
    result = "FAIL" if any(item.level == "error" for item in issues) else "PASS"
    if result == "PASS" and any(item.level == "warn" for item in issues):
        result = "PASS WITH WARNINGS"
    print(f"Result: {result}")


def main() -> int:
    args = parse_args()
    p2pool_cmd = p2pool_node_command(args.p2pool_node_bin)
    with tempfile.TemporaryDirectory(prefix="pohw-report-compare-") as temp:
        reports = [load_report(source, Path(temp), p2pool_cmd) for source in args.reports]
        issues = compare_reports(reports, args.min_nodes, args.strict)
        if args.json:
            emit_json(reports, issues)
        else:
            emit_text(reports, issues)
        return 1 if any(item.level == "error" for item in issues) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(1)
