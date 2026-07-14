#!/usr/bin/env python3
"""One-way Experiment 0 fork-to-Bitcoin-mainnet handoff controller."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
PARTICIPANT_THRESHOLD = 20
HANDOFF_ACK = "I_UNDERSTAND_REAL_BITCOIN"
MAX_JSON_BYTES = 4 * 1024 * 1024


class HandoffError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def env_bool(env: dict[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise HandoffError(f"{name} must be true or false")


def require_env_value(env: dict[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise HandoffError(f"{name} is required")
    return value


def env_int(
    env: dict[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = env.get(name, str(default))
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise HandoffError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise HandoffError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Config:
    enabled: bool
    acknowledged: bool
    confirmations_required: int
    settle_seconds: int
    command_timeout_seconds: int
    workdir: Path
    p2pool_bin: Path
    datadir: Path
    snapshot_dir: Path
    max_snapshot_age_days: int
    min_snapshot_voters: int
    max_share_age_seconds: int
    min_confirmation_interval_seconds: int
    state_dir: Path
    fork_datadir: Path
    fork_marker: Path
    payout_candidate_dir: Path
    pohw_commitment: Path
    rpc_url: str
    rpc_cookie_file: Path | None
    rpc_allow_remote: bool
    extranonce2_size: int
    systemctl_bin: Path
    mining_service: str
    fork_service: str
    process_cmdline_file: Path | None

    @classmethod
    def from_env(
        cls,
        env: dict[str, str],
        process_cmdline_file: Path | None = None,
    ) -> "Config":
        workdir = Path(env.get("POHW_WORKDIR", "/opt/p2pool"))
        state_dir = Path(
            env.get(
                "POHW_MAINNET_HANDOFF_STATE_DIR",
                "/var/lib/pohw-p2pool/mainnet-handoff",
            )
        )
        cookie_raw = env.get("POHW_BITCOIN_RPC_COOKIE_FILE", "").strip()
        return cls(
            enabled=env_bool(env, "POHW_MAINNET_HANDOFF_ENABLED"),
            acknowledged=env.get("POHW_MAINNET_HANDOFF_ACK") == HANDOFF_ACK,
            confirmations_required=env_int(
                env, "POHW_MAINNET_HANDOFF_CONFIRMATIONS", 3, 1, 60
            ),
            settle_seconds=env_int(
                env, "POHW_MAINNET_HANDOFF_SETTLE_SECONDS", 15, 0, 120
            ),
            command_timeout_seconds=env_int(
                env, "POHW_MAINNET_HANDOFF_COMMAND_TIMEOUT_SECONDS", 60, 5, 600
            ),
            workdir=workdir,
            p2pool_bin=Path(
                env.get("POHW_P2POOL_NODE_BIN", str(workdir / "target/release/p2pool-node"))
            ),
            datadir=Path(env.get("POHW_DATADIR", "/var/lib/pohw-p2pool")),
            snapshot_dir=Path(
                env.get("POHW_SNAPSHOT_DIR", "/var/lib/pohw-p2pool/snapshots")
            ),
            max_snapshot_age_days=env_int(
                env, "POHW_MAINNET_HANDOFF_MAX_SNAPSHOT_AGE_DAYS", 2, 0, 30
            ),
            min_snapshot_voters=env_int(
                env, "POHW_MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS", 3, 1, 1000
            ),
            max_share_age_seconds=env_int(
                env, "POHW_MAINNET_HANDOFF_MAX_SHARE_AGE_SECONDS", 3600, 60, 86400
            ),
            min_confirmation_interval_seconds=env_int(
                env, "POHW_MAINNET_HANDOFF_MIN_CONFIRMATION_INTERVAL_SECONDS", 600, 0, 86400
            ),
            state_dir=state_dir,
            fork_datadir=Path(
                env.get("POHW_FORK_CHAIN_DATADIR", "/var/lib/pohw-p2pool/fork-chain")
            ),
            fork_marker=Path(
                env.get(
                    "POHW_MAINNET_HANDOFF_FORK_MARKER",
                    "/etc/pohw/enable-experiment-0-fork",
                )
            ),
            payout_candidate_dir=Path(
                env.get(
                    "POHW_PAYOUT_CANDIDATE_DIR",
                    str(
                        Path(env.get("POHW_DATADIR", "/var/lib/pohw-p2pool"))
                        / "payout-candidates"
                    ),
                )
            ),
            pohw_commitment=Path(
                env.get(
                    "POHW_STRATUM_POHW_COMMITMENT_FILE",
                    "/var/lib/pohw-p2pool/pohw-commitment.json",
                )
            ),
            rpc_url=env.get("POHW_BITCOIN_RPC_URL", "http://127.0.0.1:8332"),
            rpc_cookie_file=Path(cookie_raw) if cookie_raw else None,
            rpc_allow_remote=env_bool(env, "POHW_BITCOIN_RPC_ALLOW_REMOTE"),
            extranonce2_size=env_int(env, "POHW_STRATUM_EXTRANONCE2_SIZE", 4, 1, 32),
            systemctl_bin=Path(env.get("POHW_SYSTEMCTL_BIN", "/usr/bin/systemctl")),
            mining_service=env.get(
                "POHW_MAINNET_HANDOFF_MINING_SERVICE", "pohw-mining-adapter.service"
            ),
            fork_service=env.get(
                "POHW_MAINNET_HANDOFF_FORK_SERVICE", "pohw-fork-chain-node.service"
            ),
            process_cmdline_file=process_cmdline_file,
        )

    @property
    def controller_state_file(self) -> Path:
        return self.state_dir / "controller-state.json"

    @property
    def status_file(self) -> Path:
        return self.state_dir / "status.json"

    @property
    def receipt_file(self) -> Path:
        return self.state_dir / "handoff-receipt.json"

    @property
    def activation_marker(self) -> Path:
        return self.state_dir / "mainnet-activated.json"

    @property
    def mining_mode_file(self) -> Path:
        return self.state_dir / "mining-mode.env"

    @property
    def preflight_job_file(self) -> Path:
        return self.state_dir / "preflight-mainnet-job.json"


@dataclass(frozen=True)
class ParticipantEvidence:
    registered_miners: int
    unique_registered_identities: int
    active_contributor_identities: int
    active_identities: int
    snapshot_voter_identities: int
    snapshot_day: str
    last_message_hash: str | None


def ensure_state_dir(path: Path) -> None:
    if not path.is_absolute():
        raise HandoffError("handoff state directory must be absolute")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise HandoffError("handoff state path must be a real directory")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise HandoffError("handoff state directory must not be group/world writable")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, content: str) -> None:
    if path.is_symlink():
        raise HandoffError(f"refusing symlinked handoff file: {path.name}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        payload = content.encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise HandoffError(f"failed to write handoff file: {path.name}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    fsync_directory(path.parent)


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write(path, json.dumps(value, sort_keys=True, indent=2) + "\n")


def read_json(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HandoffError(f"handoff file must be regular: {path.name}")
    if metadata.st_size > MAX_JSON_BYTES:
        raise HandoffError(f"handoff file is too large: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HandoffError(f"cannot read handoff file: {path.name}") from exc
    if not isinstance(value, dict):
        raise HandoffError(f"handoff file must contain an object: {path.name}")
    return value


def require_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise HandoffError(f"{label} is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HandoffError(f"{label} must be a regular file")
    return metadata


def require_private_regular_file(path: Path, label: str) -> None:
    metadata = require_regular_file(path, label)
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise HandoffError(f"{label} must not be accessible by group or others")


def run_command(
    args: list[str], config: Config, env: dict[str, str], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            cwd=config.workdir,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=config.command_timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HandoffError("required command could not be executed") from exc
    if check and result.returncode != 0:
        raise HandoffError("required command failed")
    return result


def child_env(env: dict[str, str]) -> dict[str, str]:
    result = dict(env)
    mappings = {
        "POHW_BITCOIN_RPC_USER": "BITCOIN_RPC_USER",
        "POHW_BITCOIN_RPC_PASSWORD": "BITCOIN_RPC_PASSWORD",
        "POHW_BITCOIN_RPC_COOKIE_FILE": "BITCOIN_RPC_COOKIE_FILE",
    }
    for source, destination in mappings.items():
        if source in env:
            result[destination] = env[source]
    return result


def rpc_args(config: Config) -> list[str]:
    args = ["--rpc-url", config.rpc_url]
    if config.rpc_cookie_file is not None:
        args.extend(["--rpc-cookie-file", str(config.rpc_cookie_file)])
    if config.rpc_allow_remote:
        args.append("--allow-remote-rpc")
    return args


def participant_evidence(config: Config, env: dict[str, str]) -> ParticipantEvidence:
    result = run_command(
        [
            str(config.p2pool_bin),
            "mainnet-handoff-evidence",
            "--datadir",
            str(config.datadir),
            "--snapshot-dir",
            str(config.snapshot_dir),
            "--max-snapshot-age-days",
            str(config.max_snapshot_age_days),
            "--min-snapshot-voters",
            str(config.min_snapshot_voters),
            "--max-share-age-seconds",
            str(config.max_share_age_seconds),
        ],
        config,
        child_env(env),
    )
    try:
        payload = json.loads(result.stdout)
        registered = payload["registered_miner_count"]
        unique = payload["unique_registered_idena_count"]
        active_contributors = payload["active_idena_participant_count"]
        active = payload["eligible_active_idena_participant_count"]
        snapshot_voters = payload["snapshot_voter_idena_count"]
        snapshot_day = payload["snapshot_day"]
        last_message_hash = payload.get("last_message_hash")
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HandoffError("p2pool status lacks participant handoff evidence") from exc
    if not all(
        isinstance(value, int) and value >= 0
        for value in (registered, unique, active_contributors, active, snapshot_voters)
    ):
        raise HandoffError("p2pool participant counters are invalid")
    if active > active_contributors or active_contributors > unique or unique > registered:
        raise HandoffError("p2pool participant counters are inconsistent")
    if snapshot_voters < config.min_snapshot_voters:
        raise HandoffError("p2pool snapshot voter quorum is insufficient")
    if not isinstance(snapshot_day, str) or not snapshot_day:
        raise HandoffError("p2pool snapshot day is invalid")
    if not isinstance(last_message_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", last_message_hash):
        raise HandoffError("p2pool replay hash is invalid")
    return ParticipantEvidence(
        registered,
        unique,
        active_contributors,
        active,
        snapshot_voters,
        snapshot_day,
        last_message_hash,
    )


def mainnet_preflight(config: Config, env: dict[str, str]) -> dict[str, Any]:
    require_regular_file(config.pohw_commitment, "PoHW commitment")
    if config.rpc_cookie_file is not None:
        require_regular_file(config.rpc_cookie_file, "Bitcoin RPC cookie")

    readiness = run_command(
        [str(config.p2pool_bin), "bitcoin-mining-readiness", *rpc_args(config)],
        config,
        child_env(env),
    )
    try:
        readiness_payload = json.loads(readiness.stdout)
    except json.JSONDecodeError as exc:
        raise HandoffError("Bitcoin readiness command returned invalid JSON") from exc
    if readiness_payload.get("ready") is not True or readiness_payload.get("chain") != "main":
        raise HandoffError("Bitcoin mainnet is not mining-ready")

    run_command(
        [
            str(config.p2pool_bin),
            "build-dynamic-pohw-stratum-job-rpc",
            "--datadir",
            str(config.datadir),
            "--snapshot-dir",
            str(config.snapshot_dir),
            "--miner-id",
            require_env_value(env, "POHW_MINER_ID"),
            "--job-out",
            str(config.preflight_job_file),
            "--replace",
            "--pohw-commitment-file",
            str(config.pohw_commitment),
            "--extranonce2-size",
            str(config.extranonce2_size),
            *rpc_args(config),
        ],
        config,
        child_env(env),
    )
    require_regular_file(config.preflight_job_file, "mainnet preflight job")
    return {
        "chain": "main",
        "blocks": readiness_payload.get("blocks"),
        "headers": readiness_payload.get("headers"),
        "initialBlockDownload": readiness_payload.get("initialBlockDownload"),
        "templateHeight": readiness_payload.get("templateHeight"),
    }


def systemctl(
    config: Config,
    env: dict[str, str],
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_command([str(config.systemctl_bin), *args], config, env, check=check)


def service_is_active(config: Config, env: dict[str, str], service: str) -> bool:
    return systemctl(config, env, "is-active", "--quiet", service, check=False).returncode == 0


def expected_mainnet_mode() -> str:
    return """# Generated by pohw-mainnet-handoff.py. Do not edit.
POHW_MAINNET_HANDOFF_ACTIVE=true
POHW_STRATUM_FORK_CHAIN_RPC_ADDR=
POHW_FORK_ACTIVATION_MANIFEST=
POHW_STRATUM_BUILD_JOB_FROM_RPC=false
POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=false
POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE=true
POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true
POHW_STRATUM_ALLOW_MAINNET_SUBMIT=true
"""


def write_mainnet_mode(config: Config) -> None:
    atomic_write(config.mining_mode_file, expected_mainnet_mode())


def remove_regular_file(path: Path, label: str, *, missing_ok: bool = True) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise HandoffError(f"{label} is missing")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HandoffError(f"{label} must be a regular file")
    path.unlink()
    fsync_directory(path.parent)
    return True


def recreate_fork_marker(config: Config) -> None:
    config.fork_marker.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if config.fork_marker.exists():
        require_private_regular_file(config.fork_marker, "fork approval marker")
        return
    atomic_write(config.fork_marker, "approved\n")


def service_main_pid(config: Config, env: dict[str, str]) -> int:
    result = systemctl(
        config,
        env,
        "show",
        "--property=MainPID",
        "--value",
        config.mining_service,
    )
    try:
        pid = int(result.stdout.strip(), 10)
    except ValueError as exc:
        raise HandoffError("mining adapter MainPID is invalid") from exc
    if pid <= 0:
        raise HandoffError("mining adapter has no live MainPID")
    return pid


def verify_mainnet_process(config: Config, env: dict[str, str]) -> None:
    if config.process_cmdline_file is None:
        cmdline_path = Path("/proc") / str(service_main_pid(config, env)) / "cmdline"
    else:
        cmdline_path = config.process_cmdline_file
    try:
        raw = cmdline_path.read_bytes()
    except OSError as exc:
        raise HandoffError("cannot inspect mining adapter command line") from exc
    if len(raw) > 1024 * 1024:
        raise HandoffError("mining adapter command line is too large")
    separator = b"\0" if b"\0" in raw else b"\n"
    args = [part.decode("utf-8", errors="replace") for part in raw.split(separator) if part]
    arg_set = set(args)
    required = {
        "run-mining-adapter",
        "--refresh-job-from-rpc",
        "--derive-pohw-payouts-from-state",
        "--auto-submit-blocks",
        "--allow-mainnet-submit",
    }
    forbidden = {
        "--fork-chain-rpc-addr",
        "--fork-chain-activation-manifest",
        "--allow-example-mining-job",
        "--payout-schedule-file",
        "--job-file",
    }
    if not required.issubset(arg_set) or forbidden.intersection(arg_set):
        raise HandoffError("mining adapter did not start in verified mainnet mode")

    expected_options = {
        "--datadir": str(config.datadir),
        "--miner-id": require_env_value(env, "POHW_MINER_ID"),
        "--snapshot-dir": str(config.snapshot_dir),
        "--payout-candidate-dir": str(config.payout_candidate_dir),
        "--pohw-commitment-file": str(config.pohw_commitment),
        "--rpc-url": config.rpc_url,
    }
    if config.rpc_cookie_file is not None:
        expected_options["--rpc-cookie-file"] = str(config.rpc_cookie_file)
    elif "--rpc-cookie-file" in arg_set:
        raise HandoffError("mining adapter did not start in verified mainnet mode")
    for option, expected in expected_options.items():
        values = [
            args[index + 1]
            for index, value in enumerate(args[:-1])
            if value == option
        ]
        if values != [expected]:
            raise HandoffError("mining adapter did not start in verified mainnet mode")
    if ("--allow-remote-rpc" in arg_set) != config.rpc_allow_remote:
        raise HandoffError("mining adapter did not start in verified mainnet mode")


def wait_for_verified_mainnet_process(config: Config, env: dict[str, str]) -> None:
    deadline = time.monotonic() + config.settle_seconds
    while True:
        if service_is_active(config, env, config.mining_service):
            try:
                verify_mainnet_process(config, env)
                return
            except HandoffError:
                pass
        if time.monotonic() >= deadline:
            raise HandoffError("mainnet mining adapter failed verified startup")
        time.sleep(1)


def safe_delete_fork_datadir(path: Path) -> bool:
    if not path.is_absolute():
        raise HandoffError("fork datadir must be absolute")
    forbidden = {
        Path("/"),
        Path("/var"),
        Path("/var/lib"),
        Path("/var/lib/pohw-p2pool"),
        Path("/mnt"),
        Path("/mnt/ssd"),
    }
    if path in forbidden or len(path.parts) < 4:
        raise HandoffError("refusing unsafe fork datadir deletion target")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise HandoffError("fork datadir deletion target must be a real directory")
    if path.resolve(strict=True) != path:
        raise HandoffError("fork datadir deletion target must use its canonical path")
    require_regular_file(path / "fork-chain.lock", "fork-chain datadir lock")
    shutil.rmtree(path)
    fsync_directory(path.parent)
    return True


def sanitized_status(
    phase: str,
    evidence: ParticipantEvidence | None,
    confirmations: int,
    detail: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": utc_now(),
        "phase": phase,
        "participantThreshold": PARTICIPANT_THRESHOLD,
        "activeIdenaParticipants": evidence.active_identities if evidence else None,
        "activeShareContributorIdentities": (
            evidence.active_contributor_identities if evidence else None
        ),
        "uniqueRegisteredIdenaIdentities": (
            evidence.unique_registered_identities if evidence else None
        ),
        "registeredMiners": evidence.registered_miners if evidence else None,
        "snapshotVoterIdentities": evidence.snapshot_voter_identities if evidence else None,
        "snapshotDay": evidence.snapshot_day if evidence else None,
        "confirmationCount": confirmations,
        "detail": detail,
    }


def write_status(
    config: Config,
    phase: str,
    evidence: ParticipantEvidence | None,
    confirmations: int,
    detail: str,
) -> None:
    write_json(
        config.status_file,
        sanitized_status(phase, evidence, confirmations, detail),
    )


def monitor_confirmations(config: Config, evidence: ParticipantEvidence) -> int:
    previous: dict[str, Any] = {}
    if config.controller_state_file.exists():
        previous = read_json(config.controller_state_file)
        if previous.get("schemaVersion") != SCHEMA_VERSION:
            raise HandoffError("unsupported handoff controller state schema")
    confirmations = 0
    confirmed_hash: str | None = None
    last_confirmation_at: str | None = None
    if evidence.active_identities >= PARTICIPANT_THRESHOLD:
        old = previous.get("confirmationCount", 0)
        previous_hash = previous.get(
            "lastConfirmedMessageHash", previous.get("lastMessageHash")
        )
        previous_confirmed_at = previous.get("lastConfirmationAt")
        if previous_confirmed_at is None and isinstance(old, int) and old > 0:
            previous_confirmed_at = previous.get("updatedAt")
        elapsed = config.min_confirmation_interval_seconds
        if isinstance(previous_confirmed_at, str):
            try:
                previous_time = datetime.fromisoformat(
                    previous_confirmed_at.replace("Z", "+00:00")
                )
                elapsed = max(0, int((datetime.now(timezone.utc) - previous_time).total_seconds()))
            except ValueError:
                elapsed = -1
        is_new_evidence = previous_hash is None or previous_hash != evidence.last_message_hash
        interval_elapsed = previous_hash is None or elapsed >= config.min_confirmation_interval_seconds
        if isinstance(old, int) and old >= 0 and is_new_evidence and interval_elapsed:
            confirmations = min(old + 1, config.confirmations_required)
            confirmed_hash = evidence.last_message_hash
            last_confirmation_at = utc_now()
        elif isinstance(old, int) and old >= 0:
            confirmations = min(old, config.confirmations_required)
            confirmed_hash = previous_hash if isinstance(previous_hash, str) else None
            last_confirmation_at = (
                previous_confirmed_at
                if isinstance(previous_confirmed_at, str)
                else None
            )
    state = {
        "schemaVersion": SCHEMA_VERSION,
        "updatedAt": utc_now(),
        "confirmationCount": confirmations,
        "activeIdenaParticipants": evidence.active_identities,
        "lastObservedMessageHash": evidence.last_message_hash,
        "lastConfirmedMessageHash": confirmed_hash,
        "lastConfirmationAt": last_confirmation_at,
    }
    write_json(config.controller_state_file, state)
    return confirmations


def read_activation_marker(config: Config) -> dict[str, Any]:
    activated = read_json(config.activation_marker)
    active_identities = activated.get("activeIdenaParticipants")
    if (
        activated.get("schemaVersion") != SCHEMA_VERSION
        or activated.get("participantThreshold") != PARTICIPANT_THRESHOLD
        or activated.get("mode") != "bitcoin-mainnet"
        or type(active_identities) is not int
        or active_identities < PARTICIPANT_THRESHOLD
        or not isinstance(activated.get("activatedAt"), str)
    ):
        raise HandoffError("mainnet activation marker is invalid")
    return activated


def cleanup_after_activation(
    config: Config,
    env: dict[str, str],
    evidence: ParticipantEvidence | None,
) -> None:
    activated = read_activation_marker(config)
    write_mainnet_mode(config)
    systemctl(config, env, "stop", config.fork_service)
    remove_regular_file(config.fork_marker, "fork approval marker", missing_ok=True)
    systemctl(config, env, "disable", config.fork_service, check=False)
    if service_is_active(config, env, config.mining_service):
        try:
            verify_mainnet_process(config, env)
        except HandoffError:
            systemctl(config, env, "stop", config.mining_service, check=False)
            systemctl(config, env, "start", config.mining_service)
    else:
        systemctl(config, env, "start", config.mining_service)
    wait_for_verified_mainnet_process(config, env)
    fork_data_deleted = safe_delete_fork_datadir(config.fork_datadir)
    remove_regular_file(config.preflight_job_file, "mainnet preflight job", missing_ok=True)
    receipt = {
        "schemaVersion": SCHEMA_VERSION,
        "completedAt": utc_now(),
        "activatedAt": activated.get("activatedAt"),
        "participantThreshold": PARTICIPANT_THRESHOLD,
        "activeIdenaParticipants": activated.get("activeIdenaParticipants"),
        "forkDataDeleted": fork_data_deleted or not config.fork_datadir.exists(),
        "forkServiceDisabled": True,
        "miningMode": "bitcoin-mainnet",
        "sharechainPreserved": True,
        "idenaAccountingPreserved": True,
    }
    write_json(config.receipt_file, receipt)
    write_status(config, "complete", evidence, config.confirmations_required, "mainnet active; fork data deleted")


def rollback_before_activation(config: Config, env: dict[str, str]) -> None:
    systemctl(config, env, "stop", config.mining_service, check=False)
    remove_regular_file(config.mining_mode_file, "mainnet mining mode", missing_ok=True)
    recreate_fork_marker(config)
    systemctl(config, env, "start", config.fork_service, check=False)
    systemctl(config, env, "start", config.mining_service, check=False)


def activate_mainnet(
    config: Config,
    env: dict[str, str],
    evidence: ParticipantEvidence,
) -> None:
    require_private_regular_file(config.fork_marker, "fork approval marker")
    mainnet_preflight(config, env)
    write_status(
        config,
        "transitioning",
        evidence,
        config.confirmations_required,
        "mainnet preflight passed; services switching",
    )
    try:
        systemctl(config, env, "stop", config.mining_service)
        systemctl(config, env, "stop", config.fork_service)
        write_json(
            config.activation_marker,
            {
                "schemaVersion": SCHEMA_VERSION,
                "activatedAt": utc_now(),
                "participantThreshold": PARTICIPANT_THRESHOLD,
                "activeIdenaParticipants": evidence.active_identities,
                "lastMessageHash": evidence.last_message_hash,
                "mode": "bitcoin-mainnet",
            },
        )
    except Exception:
        if not config.activation_marker.exists():
            rollback_before_activation(config, env)
        raise
    cleanup_after_activation(config, env, evidence)


def controller(config: Config, env: dict[str, str], dry_run: bool) -> None:
    ensure_state_dir(config.state_dir)
    lock_path = config.state_dir / "controller.lock"
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return

        if config.activation_marker.exists() or config.activation_marker.is_symlink():
            cleanup_after_activation(config, env, None)
            return
        if config.receipt_file.exists():
            raise HandoffError("handoff receipt exists without activation marker")

        if not config.enabled:
            write_status(
                config,
                "disabled",
                None,
                0,
                "automatic mainnet handoff is disabled",
            )
            return
        if not config.acknowledged:
            write_status(
                config,
                "disarmed",
                None,
                0,
                "real-Bitcoin acknowledgement is missing",
            )
            return

        evidence = participant_evidence(config, env)
        confirmations = monitor_confirmations(config, evidence)
        if evidence.active_identities < PARTICIPANT_THRESHOLD:
            write_status(config, "monitoring", evidence, confirmations, "waiting for 20 active Idena identities")
            return
        if confirmations < config.confirmations_required:
            write_status(config, "confirming", evidence, confirmations, "participant threshold is being confirmed")
            return
        if dry_run:
            mainnet_preflight(config, env)
            remove_regular_file(config.preflight_job_file, "mainnet preflight job", missing_ok=True)
            write_status(config, "dry_run_ready", evidence, confirmations, "handoff preflight passed; no state changed")
            return
        activate_mainnet(config, env, evidence)
    finally:
        os.close(lock_fd)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor and perform the one-way 20-participant Bitcoin mainnet handoff."
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="run readiness checks without switching services"
    )
    parser.add_argument(
        "--process-cmdline-file",
        type=Path,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env = dict(os.environ)
    config: Config | None = None
    try:
        config = Config.from_env(env, args.process_cmdline_file)
        controller(config, env, args.dry_run)
    except HandoffError as exc:
        if config is not None:
            try:
                ensure_state_dir(config.state_dir)
                phase = (
                    "mainnet_active_cleanup_pending"
                    if config.activation_marker.exists()
                    else "error"
                )
                write_status(config, phase, None, 0, str(exc))
            except Exception:
                pass
        print(f"PoHW mainnet handoff: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
