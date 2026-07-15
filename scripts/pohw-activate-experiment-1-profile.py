#!/usr/bin/env python3
"""Atomically switch an existing P2Pool environment to Experiment 1 Core RPC."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any


MAX_ENV_BYTES = 1024 * 1024
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_MANIFEST = REPO_ROOT / "compatibility" / "experiment-1-full-consensus.json"
ACTIVATION_RE = re.compile(r"^[0-9a-f]{64}$")
SUBDIRECTORY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
KEY_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
REQUIRED_EXISTING = {
    "POHW_MINER_ID",
    "POHW_IDENA_SNAPSHOT_ID",
    "POHW_IDENA_SNAPSHOT_PROOF_ROOT",
    "POHW_MINING_SECRET_KEY_FILE",
    "POHW_NODE_SECRET_KEY_FILE",
    "POHW_SNAPSHOT_DIR",
    "POHW_STRATUM_POHW_COMMITMENT_FILE",
    "POHW_IDENA_ANCHOR_POLICY",
    "IDENA_API_KEY_FILE",
    "POHW_MINER_REGISTRY_EXPERIMENT_ID",
    "POHW_MINER_REGISTRY_ANCHOR_FILE",
}
REMOVE_KEYS = {
    "POHW_STRATUM_FORK_CHAIN_RPC_ADDR",
    "POHW_FORK_ACTIVATION_MANIFEST",
    "POHW_STRATUM_DIFFICULTY",
    "POHW_STRATUM_SHARE_TARGET",
}
MANAGED_COMMENTS = (
    "# Managed by pohw-activate-experiment-1-profile.py.",
    "# Experiment 0 fork RPC is intentionally unset; mainnet submission stays disabled.",
)


class ProfileError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def load_experiment_profile(manifest_path: Path) -> tuple[str, str, dict[str, str]]:
    payload, _ = _read_regular_bytes(manifest_path, "Experiment 1 manifest")
    try:
        manifest = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError("Experiment 1 manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise ProfileError("Experiment 1 manifest root must be an object")
    activation_id = manifest.get("activation_id")
    if not isinstance(activation_id, str) or not ACTIVATION_RE.fullmatch(
        activation_id
    ):
        raise ProfileError("Experiment 1 manifest has an invalid activation ID")
    if manifest.get("experiment_id") != "pohw-experiment-1-full-consensus":
        raise ProfileError("manifest is not the Experiment 1 full-consensus profile")
    revision = manifest.get("profile_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ProfileError("Experiment 1 manifest has an invalid profile revision")
    network = manifest.get("network")
    if not isinstance(network, dict):
        raise ProfileError("Experiment 1 manifest is missing network settings")
    data_subdirectory = network.get("data_subdirectory")
    if not isinstance(data_subdirectory, str) or not SUBDIRECTORY_RE.fullmatch(
        data_subdirectory
    ):
        raise ProfileError("Experiment 1 manifest has an unsafe data subdirectory")
    datadir = f"/srv/sharechain/{data_subdirectory}-{activation_id[:8]}"
    managed_values = {
        "POHW_P2POOL_NODE_BIN": "/usr/local/libexec/p2pool-experiment-1/p2pool-node",
        "POHW_DATADIR": datadir,
        "POHW_GOSSIP_NETWORK_ID": activation_id,
        "POHW_REQUIRE_IDENA_ANCHOR_POLICY": "true",
        "POHW_ADMIT_PEER_WORK_TEMPLATES": "true",
        "POHW_BITCOIN_RPC_URL": "http://127.0.0.1:40414",
        "POHW_BITCOIN_EXPECTED_CHAIN": "pohw",
        "POHW_BITCOIN_RPC_COOKIE_FILE": "/run/bitcoin-pohw-rpc/.cookie",
        "POHW_BITCOIN_RPC_ALLOW_REMOTE": "false",
        "POHW_STRATUM_BUILD_JOB_FROM_RPC": "false",
        "POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC": "false",
        "POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE": "true",
        "POHW_STRATUM_DYNAMIC_MIN_SNAPSHOT_VOTERS": "1",
        "POHW_STRATUM_AUTO_SUBMIT_BLOCKS": "true",
        "POHW_STRATUM_ALLOW_MAINNET_SUBMIT": "false",
        "POHW_STRATUM_BLOCK_CANDIDATE_DIR": f"{datadir}/block-candidates",
        "POHW_PAYOUT_CANDIDATE_DIR": f"{datadir}/payout-candidates",
        "POHW_MAINNET_HANDOFF_ACTIVE": "false",
        "POHW_MAINNET_HANDOFF_ENABLED": "false",
    }
    return activation_id, datadir, managed_values


def _read_environment(path: Path) -> tuple[list[str], os.stat_result]:
    try:
        payload, metadata = _read_regular_bytes(path, "environment file")
        return payload.decode("utf-8").splitlines(), metadata
    except UnicodeError as exc:
        raise ProfileError(f"cannot read environment file: {exc}") from exc


def render_profile(
    lines: list[str], managed_values: dict[str, str] | None = None
) -> tuple[str, list[str]]:
    if managed_values is None:
        _, _, managed_values = load_experiment_profile(DEFAULT_MANIFEST)
    managed_keys = REMOVE_KEYS | managed_values.keys()
    seen: dict[str, str] = {}
    retained: list[str] = []
    for line in lines:
        if line in MANAGED_COMMENTS:
            continue
        match = KEY_RE.match(line)
        if not match:
            retained.append(line)
            continue
        key, value = match.groups()
        if key in seen:
            raise ProfileError(f"duplicate environment key: {key}")
        seen[key] = value
        if key not in managed_keys:
            retained.append(line)

    missing = sorted(key for key in REQUIRED_EXISTING if not seen.get(key, "").strip())
    if missing:
        raise ProfileError("required existing settings are missing: " + ", ".join(missing))

    while retained and not retained[-1].strip():
        retained.pop()
    retained.extend(["", *MANAGED_COMMENTS])
    retained.extend(f"{key}={managed_values[key]}" for key in sorted(managed_values))
    rendered = "\n".join(retained) + "\n"

    changed = sorted(
        key
        for key in managed_keys
        if (key in REMOVE_KEYS and key in seen)
        or (key in managed_values and seen.get(key) != managed_values[key])
    )
    return rendered, changed


def write_profile(path: Path, rendered: str, metadata: os.stat_result) -> None:
    _write_atomic(path, rendered.encode("utf-8"), metadata, ".pohw-experiment-1-")


def _write_atomic(
    path: Path, payload: bytes, metadata: os.stat_result, prefix: str
) -> None:
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    temp_path: str | None = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=prefix, dir=path.parent)
        try:
            os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
            if hasattr(os, "fchown"):
                os.fchown(fd, metadata.st_uid, metadata.st_gid)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
            temp_path = None
            os.fsync(parent_fd)
        finally:
            if temp_path is not None:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    pass
    finally:
        os.close(parent_fd)


def _read_regular_bytes(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProfileError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProfileError(f"{label} must be a regular non-symlink file")
    if metadata.st_size > MAX_ENV_BYTES:
        raise ProfileError(f"{label} exceeds 1 MiB")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                payload.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ProfileError(f"cannot read {label}: {exc}") from exc
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(metadata) != identity(opened) or identity(opened) != identity(after):
        raise ProfileError(f"{label} changed while reading")
    if len(payload) != metadata.st_size:
        raise ProfileError(f"{label} size changed while reading")
    return bytes(payload), metadata


def _validate_backup_path(path: Path, backup_path: Path) -> None:
    try:
        parent = path.parent.resolve(strict=True)
        backup_parent = backup_path.parent.resolve(strict=True)
    except OSError as exc:
        raise ProfileError(f"cannot resolve environment backup directory: {exc}") from exc
    if parent != backup_parent or path.absolute() == backup_path.absolute():
        raise ProfileError("backup file must be a different file in the environment directory")
    if backup_path.exists() or backup_path.is_symlink():
        try:
            metadata = backup_path.lstat()
        except OSError as exc:
            raise ProfileError(f"cannot inspect environment backup: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ProfileError("environment backup must be a regular non-symlink file")


def activate_profile(
    path: Path,
    backup_path: Path,
    rendered: str,
    metadata: os.stat_result,
) -> bool:
    _validate_backup_path(path, backup_path)
    original, current_metadata = _read_regular_bytes(path, "environment file")
    if current_metadata.st_dev != metadata.st_dev or current_metadata.st_ino != metadata.st_ino:
        raise ProfileError("environment file changed before activation")
    candidate = rendered.encode("utf-8")
    if original == candidate:
        return False
    _write_atomic(backup_path, original, metadata, ".pohw-experiment-1-backup-")
    try:
        write_profile(path, rendered, metadata)
    except Exception as exc:
        try:
            _write_atomic(path, original, metadata, ".pohw-experiment-1-restore-")
        except Exception as rollback_exc:
            raise ProfileError(
                f"profile activation failed and automatic rollback failed: {rollback_exc}"
            ) from exc
        raise ProfileError("profile activation failed; original environment restored") from exc
    return True


def rollback_profile(path: Path, backup_path: Path) -> None:
    _validate_backup_path(path, backup_path)
    _read_regular_bytes(path, "environment file")
    payload, backup_metadata = _read_regular_bytes(backup_path, "environment backup")
    _write_atomic(path, payload, backup_metadata, ".pohw-experiment-1-rollback-")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, default=Path("/etc/pohw/p2pool.env"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="exact Experiment 1 manifest that defines the activation ID",
    )
    parser.add_argument(
        "--backup-file",
        type=Path,
        help="same-directory backup path (default: ENV.experiment-1.previous)",
    )
    parser.add_argument("--check", action="store_true", help="verify without changing the file")
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="atomically restore the pre-activation backup",
    )
    args = parser.parse_args()
    if args.check and args.rollback:
        parser.error("--check and --rollback are mutually exclusive")
    backup_file = args.backup_file or args.env_file.with_name(
        args.env_file.name + ".experiment-1.previous"
    )

    try:
        if args.rollback:
            rollback_profile(args.env_file, backup_file)
            print("Experiment 1 profile rolled back")
            return 0
        activation_id, datadir, managed_values = load_experiment_profile(
            args.manifest
        )
        lines, metadata = _read_environment(args.env_file)
        rendered, changed = render_profile(lines, managed_values)
        if args.check:
            if changed or rendered != "\n".join(lines) + "\n":
                raise ProfileError("environment file is not on the Experiment 1 profile")
        else:
            activated = activate_profile(
                args.env_file, backup_file, rendered, metadata
            )
        print("Experiment 1 profile verified" if args.check else "Experiment 1 profile activated")
        if not args.check:
            print(
                "backup: " + str(backup_file)
                if activated
                else "profile already active; existing backup preserved"
            )
        if changed:
            print("changed keys: " + ", ".join(changed))
        print(f"manifest activation: {activation_id}; datadir: {datadir}")
        return 0
    except ProfileError as exc:
        print(f"profile error: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
