#!/usr/bin/env python3
"""Report sanitized local progress for the source-first Experiment 0 join flow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


CONFIG_SCHEMA = "pohw-agent-config/v2"
JOIN_SCHEMA = "pohw-source-join/v1"
STATUS_SCHEMA = "pohw-community-status/v1"
EXPERIMENT_ID = "pohw-experiment-0"
ACTIVATION_ID = "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e"
MAX_JSON_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 15


class StatusError(RuntimeError):
    pass


class NodeUnavailable(StatusError):
    pass


def is_link_like(metadata: os.stat_result) -> bool:
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_point)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StatusError("JSON input contains a duplicate key")
        value[key] = item
    return value


def read_regular_bytes(path: Path, label: str, *, private: bool = False) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise StatusError(f"{label} is unavailable") from error
    if is_link_like(before) or not stat.S_ISREG(before.st_mode):
        raise StatusError(f"{label} must be a regular non-symlink file")
    if before.st_size > MAX_JSON_BYTES:
        raise StatusError(f"{label} exceeds the safety limit")
    if private and os.name == "posix" and before.st_mode & 0o077:
        raise StatusError(f"{label} must not be accessible by group or other users")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StatusError(f"open {label} safely") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise StatusError(f"{label} changed while it was being opened")
        chunks: list[bytes] = []
        retained = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_JSON_BYTES + 1 - retained))
            if not chunk:
                break
            chunks.append(chunk)
            retained += len(chunk)
            if retained > MAX_JSON_BYTES:
                raise StatusError(f"{label} exceeds the safety limit")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StatusError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise StatusError(f"{label} must contain a JSON object")
    return value


def read_json(path: Path, label: str, *, private: bool = False) -> dict[str, Any]:
    return parse_json_bytes(read_regular_bytes(path, label, private=private), label)


def require_string(value: dict[str, Any], field: str, label: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise StatusError(f"{label} has an invalid {field}")
    return result


def require_object(value: dict[str, Any], field: str, label: str) -> dict[str, Any]:
    result = value.get(field)
    if not isinstance(result, dict):
        raise StatusError(f"{label} has an invalid {field}")
    return result


def require_count(value: dict[str, Any], field: str, label: str) -> int:
    result = value.get(field)
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise StatusError(f"{label} has an invalid {field}")
    return result


def sha256_regular_file(path: Path, label: str) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise StatusError(f"{label} is unavailable") from error
    if is_link_like(before) or not stat.S_ISREG(before.st_mode):
        raise StatusError(f"{label} must be a regular non-symlink file")
    if before.st_size > MAX_BINARY_BYTES:
        raise StatusError(f"{label} exceeds the safety limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StatusError(f"open {label} safely") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise StatusError(f"{label} changed while it was being opened")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def run_node_json(binary: Path, arguments: list[str], label: str) -> dict[str, Any]:
    environment = {
        name: os.environ[name]
        for name in ("PATH", "SYSTEMROOT", "WINDIR")
        if name in os.environ
    }
    try:
        result = subprocess.run(
            [str(binary), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise NodeUnavailable(f"{label} is unavailable") from error
    if len(result.stdout) > MAX_JSON_BYTES or len(result.stderr) > MAX_JSON_BYTES:
        raise StatusError(f"{label} output exceeds the safety limit")
    if result.returncode != 0:
        raise NodeUnavailable(f"{label} is unavailable")
    return parse_json_bytes(result.stdout, label)


def registration_status(root: Path, binary: Path) -> dict[str, Any]:
    directory = root / "node" / "agent-registration"
    public_path = directory / "registration-public.json"
    message_path = directory / "miner-registration-message.json"
    envelope_path = directory / "miner-registration-envelope.json"
    present = [path.exists() for path in (public_path, message_path, envelope_path)]
    if not any(present):
        return {"verified": False, "gossip_delivered": 0, "gossip_attempted": 0}
    if not all(present):
        raise StatusError("the local registration is incomplete")

    public = read_json(public_path, "registration receipt", private=True)
    verified = run_node_json(
        binary,
        [
            "verify-miner-registration-envelope",
            "--envelope-file",
            str(envelope_path),
            "--message-file",
            str(message_path),
            "--datadir",
            str(root / "node"),
            "--durable",
        ],
        "registration verification",
    )
    fields = require_object(verified, "miner_registration", "registration verification")
    if verified.get("valid") is not True or public.get("status") != "registration_ready":
        raise StatusError("the local registration does not match its signed envelope")
    for name in (
        "miner_id",
        "idena_address",
        "btc_payout_script_hex",
        "claim_owner_pubkey_hex",
        "mining_pubkey_hex",
    ):
        if require_string(public, name, "registration receipt") != require_string(
            fields, name, "registration verification"
        ):
            raise StatusError("the local registration does not match its signed envelope")
    for name in ("message_hash", "envelope_hash", "registration_binding_hash"):
        if require_string(public, name, "registration receipt") != require_string(
            verified, name, "registration verification"
        ):
            raise StatusError("the local registration does not match its signed envelope")

    deliveries = public.get("gossip_delivery", [])
    if not isinstance(deliveries, list) or any(not isinstance(item, dict) for item in deliveries):
        raise StatusError("registration receipt has invalid delivery metadata")
    if any(not isinstance(item.get("delivered"), bool) for item in deliveries):
        raise StatusError("registration receipt has invalid delivery metadata")
    delivered = sum(item.get("delivered") is True for item in deliveries)
    return {
        "verified": True,
        "gossip_delivered": delivered,
        "gossip_attempted": len(deliveries),
    }


def build_status(datadir: Path) -> dict[str, Any]:
    requested_datadir = datadir.expanduser().absolute()
    try:
        requested_metadata = requested_datadir.lstat()
    except OSError as error:
        raise StatusError("the agent datadir is unavailable") from error
    if is_link_like(requested_metadata) or not stat.S_ISDIR(requested_metadata.st_mode):
        raise StatusError("the agent datadir must be a regular directory")
    try:
        datadir = requested_datadir.resolve(strict=True)
    except OSError as error:
        raise StatusError("the agent datadir is unavailable") from error

    config = read_json(datadir / "agent-config.json", "agent configuration", private=True)
    if config.get("schema_version") != CONFIG_SCHEMA:
        raise StatusError("agent configuration has an unsupported schema")
    configured_datadir = Path(require_string(config, "datadir", "agent configuration"))
    try:
        configured_datadir = configured_datadir.resolve(strict=True)
    except OSError as error:
        raise StatusError("configured agent datadir is unavailable") from error
    if configured_datadir != datadir:
        raise StatusError("agent configuration is bound to a different datadir")

    manifest_path = datadir / "build-receipt" / "source-join-manifest.json"
    manifest_bytes = read_regular_bytes(manifest_path, "source-join manifest", private=True)
    expected_manifest_sha = require_string(
        config, "join_manifest_sha256", "agent configuration"
    )
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha:
        raise StatusError("source-join manifest digest mismatch")
    manifest = parse_json_bytes(manifest_bytes, "source-join manifest")
    if manifest.get("schema_version") != JOIN_SCHEMA:
        raise StatusError("source-join manifest has an unsupported schema")
    if manifest.get("experiment_id") != EXPERIMENT_ID:
        raise StatusError("source-join manifest is not Experiment 0")
    if manifest.get("network_mode") != "join-existing":
        raise StatusError("community status accepts only the existing Experiment 0 network")
    if manifest.get("trust_model") != "local-source-build":
        raise StatusError("source-join manifest has an unsupported trust model")

    source = require_object(manifest, "source", "source-join manifest")
    artifact = require_object(source, "local_artifact", "source-join source")
    binary = Path(require_string(config, "p2pool_node_path", "agent configuration"))
    expected_binary_sha = require_string(config, "p2pool_node_sha256", "agent configuration")
    if expected_binary_sha != require_string(artifact, "sha256", "source artifact"):
        raise StatusError("source artifact and agent binary digests disagree")
    if sha256_regular_file(binary, "source-built p2pool-node") != expected_binary_sha:
        raise StatusError("source-built p2pool-node digest mismatch")
    if require_string(config, "source_tree_cid", "agent configuration") != require_string(
        source, "source_tree_cid", "source-join source"
    ):
        raise StatusError("source CID mismatch")
    if require_string(config, "git_commit", "agent configuration") != require_string(
        source, "git_commit", "source-join source"
    ):
        raise StatusError("Git commit metadata mismatch")

    activation = require_object(manifest, "activation", "source-join manifest")
    activation_id = require_string(activation, "activation_id", "source-join activation")
    if activation_id != ACTIVATION_ID:
        raise StatusError("source-join manifest has the wrong Experiment 0 activation ID")
    activation_path = Path(
        require_string(config, "activation_manifest_path", "agent configuration")
    )
    expected_activation_sha = require_string(
        activation, "manifest_sha256", "source-join activation"
    )
    activation_bytes = read_regular_bytes(
        activation_path, "activation manifest", private=True
    )
    if hashlib.sha256(activation_bytes).hexdigest() != expected_activation_sha:
        raise StatusError("activation manifest digest mismatch")
    activation_document = parse_json_bytes(activation_bytes, "activation manifest")
    if activation_document.get("activation_id") != activation_id:
        raise StatusError("activation manifest ID mismatch")

    launch = require_object(manifest, "launch", "source-join manifest")
    phase = require_string(launch, "phase", "source-join launch policy")
    if phase not in {"registration", "fork-sync", "mining"}:
        raise StatusError("source-join manifest has an unsupported launch phase")
    if launch.get("no_value") is not True or launch.get("mainnet_handoff_armed") is not False:
        raise StatusError("community join must stay no-value with mainnet handoff disabled")

    registration = registration_status(datadir, binary)
    local = run_node_json(
        binary,
        ["status", "--datadir", str(datadir / "node")],
        "local sharechain status",
    )
    replay = require_object(local, "replay", "local sharechain status")
    sharechain = {
        "applied_messages": require_count(replay, "applied_message_count", "sharechain replay"),
        "registered_miners": require_count(
            replay, "registered_miner_count", "sharechain replay"
        ),
        "active_shares": require_count(replay, "active_share_count", "sharechain replay"),
        "inactive_shares": require_count(replay, "inactive_share_count", "sharechain replay"),
        "share_miners": require_count(replay, "share_miner_count", "sharechain replay"),
        "snapshot_vote_roots": require_count(
            replay, "snapshot_vote_root_count", "sharechain replay"
        ),
    }

    fork: dict[str, Any] = {"state": "not_requested"}
    if phase in {"fork-sync", "mining"}:
        try:
            fork_status = run_node_json(
                binary,
                [
                    "fork-chain-status",
                    "--activation-manifest",
                    str(activation_path),
                    "--rpc-addr",
                    "127.0.0.1:40408",
                ],
                "local fork-chain status",
            )
        except NodeUnavailable:
            fork = {"state": "not_running"}
        else:
            if fork_status.get("activation_id") != activation_id:
                raise StatusError("local fork node reports a different activation ID")
            fork = {
                "state": "running",
                "tip_height": require_count(fork_status, "tip_height", "fork-chain status"),
                "active_fork_blocks": require_count(
                    fork_status, "active_fork_block_count", "fork-chain status"
                ),
                "stored_fork_blocks": require_count(
                    fork_status, "stored_block_count", "fork-chain status"
                ),
                "difficulty_phase": require_string(
                    fork_status, "difficulty_phase", "fork-chain status"
                ),
            }

    if sha256_regular_file(binary, "source-built p2pool-node") != expected_binary_sha:
        raise StatusError("source-built p2pool-node changed during status verification")

    phase_ready = registration["verified"] and sharechain["registered_miners"] > 0
    if phase in {"fork-sync", "mining"}:
        phase_ready = phase_ready and fork.get("state") == "running"

    return {
        "schema_version": STATUS_SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "phase": phase,
        "phase_ready": phase_ready,
        "source": {
            "verified": True,
            "git_commit": require_string(config, "git_commit", "agent configuration"),
            "source_tree_cid": require_string(
                config, "source_tree_cid", "agent configuration"
            ),
        },
        "activation": {"verified": True, "activation_id": activation_id},
        "registration": registration,
        "sharechain": sharechain,
        "fork": fork,
        "bitcoin_core": {
            "queried": False,
            "expected_chain": "main",
            "contains_experiment_fork": False,
        },
    }


def print_human(status: dict[str, Any]) -> None:
    registration = status["registration"]
    sharechain = status["sharechain"]
    fork = status["fork"]
    print("Experiment 0 local status")
    print(
        "Source receipt + local binary: VERIFIED "
        f"({status['source']['source_tree_cid']})"
    )
    print(f"Activation: VERIFIED ({status['activation']['activation_id']})")
    print(
        "Idena registration: "
        + ("VERIFIED" if registration["verified"] else "NOT COMPLETE")
    )
    print(
        "Initial registration delivery: "
        f"{registration['gossip_delivered']}/{registration['gossip_attempted']} peer attempts"
    )
    print(
        "Sharechain: "
        f"{sharechain['applied_messages']} messages, "
        f"{sharechain['registered_miners']} registered miners, "
        f"{sharechain['active_shares']} active shares"
    )
    if fork["state"] == "running":
        print(
            "Fork chain: RUNNING, "
            f"height {fork['tip_height']}, "
            f"{fork['active_fork_blocks']} active fork blocks, "
            f"phase {fork['difficulty_phase']}"
        )
    elif fork["state"] == "not_running":
        print("Fork chain: NOT RUNNING OR NOT REACHABLE")
    else:
        print("Fork chain: NOT REQUESTED IN REGISTRATION PHASE")
    print(
        f"Local {status['phase']} checks: "
        + ("READY" if status["phase_ready"] else "INCOMPLETE")
    )
    print("Bitcoin Core: not queried; it must remain on mainnet and will not show fork coins")
    print("Independent proof: compare the fork height and your public miner ID in the explorer")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify and report sanitized local Experiment 0 progress"
    )
    parser.add_argument(
        "--datadir",
        type=Path,
        default=Path.home() / ".pohw-agent" / EXPERIMENT_ID,
        help="source-first agent datadir (default: ~/.pohw-agent/pohw-experiment-0)",
    )
    parser.add_argument("--json", action="store_true", help="emit sanitized JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        status = build_status(args.datadir)
    except StatusError as error:
        print(f"Experiment 0 status failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        print_human(status)
    return 0 if status["phase_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
