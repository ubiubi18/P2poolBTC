#!/usr/bin/env python3
"""Start local Idena indexing workers only after the node reaches its head."""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from pohw_idena_rpc.idena_rpc_client_minimal import IdenaRPCClientMinimal


STATE_DIR = Path(os.getenv("POHW_IDENA_WORKERS_STATE_DIR", "/var/lib/pohw/idena-workers"))
STATUS_FILE = STATE_DIR / "status.json"
RPC_URL = os.getenv("IDENA_RPC_URL", "http://127.0.0.1:9009")
API_KEY_FILE = os.getenv("IDENA_API_KEY_FILE", "/var/lib/idena/api.key")
RPC_TIMEOUT = int(os.getenv("POHW_IDENA_WORKERS_RPC_TIMEOUT", "10"))
IDENA_SERVICE = "idena.service"
WORKER_SERVICES = (
    "idena-reward-indexer.service",
    "idena-session-recorder.service",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def validate_loopback_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Idena worker watcher RPC must use loopback HTTP")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Idena worker watcher RPC URL contains unsupported components")
    return value


def sync_heights(payload: object) -> tuple[int, int]:
    if not isinstance(payload, dict):
        return 0, 0
    try:
        current = int(payload.get("currentBlock") or 0)
        highest = int(payload.get("highestBlock") or 0)
    except (TypeError, ValueError):
        return 0, 0
    return current, highest


def sync_is_ready(payload: object) -> bool:
    current, highest = sync_heights(payload)
    if not isinstance(payload, dict):
        return False
    return current > 0 and highest > 0 and current >= highest and not bool(payload.get("wrongTime"))


def service_is_active(name: str) -> bool:
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", name],
        check=False,
        timeout=15,
    )
    return result.returncode == 0


def secure_state_dir(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("Idena worker watcher state directory is symlinked")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("Idena worker watcher state directory is not root-protected")
    path.chmod(0o700)


def write_status(payload: dict[str, Any]) -> None:
    secure_state_dir(STATE_DIR)
    if STATUS_FILE.is_symlink():
        raise RuntimeError("Idena worker watcher status file is symlinked")
    fd, temp_name = tempfile.mkstemp(prefix=".status.", suffix=".tmp", dir=STATE_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, STATUS_FILE)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def record(status: str, **details: Any) -> None:
    write_status({"generatedAt": utc_now(), "status": status, **details})


def main() -> int:
    if os.geteuid() != 0:
        print("Idena worker watcher must run as root", file=sys.stderr)
        return 1
    if not 1 <= RPC_TIMEOUT <= 60:
        print("POHW_IDENA_WORKERS_RPC_TIMEOUT must be between 1 and 60", file=sys.stderr)
        return 1
    if not service_is_active(IDENA_SERVICE):
        record("idena_inactive")
        return 0

    inactive_workers = [name for name in WORKER_SERVICES if not service_is_active(name)]
    if not inactive_workers:
        record("workers_active", workers=list(WORKER_SERVICES))
        return 0

    try:
        client = IdenaRPCClientMinimal(
            url=validate_loopback_url(RPC_URL),
            api_key_file=API_KEY_FILE,
            timeout=RPC_TIMEOUT,
        )
        sync = client.call("bcn_syncing")
    except Exception as exc:
        record("rpc_unavailable", error=type(exc).__name__)
        print("Idena worker watcher could not query local sync status", file=sys.stderr)
        return 1

    if not sync_is_ready(sync):
        current, highest = sync_heights(sync)
        record("waiting_for_sync", currentBlock=current, highestBlock=highest)
        return 0

    try:
        subprocess.run(
            ["/usr/bin/systemctl", "start", *inactive_workers],
            check=True,
            timeout=90,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        record("worker_start_failed", workers=inactive_workers)
        print("Idena worker watcher failed to start local workers", file=sys.stderr)
        return 1

    failed_workers = [name for name in WORKER_SERVICES if not service_is_active(name)]
    if failed_workers:
        record("worker_start_failed", workers=failed_workers)
        print("Idena worker watcher found inactive workers after start", file=sys.stderr)
        return 1

    record("workers_started", workers=inactive_workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
