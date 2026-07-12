#!/usr/bin/env python3
"""Serialize and bound the write-only Idena return rsync endpoint."""

from __future__ import annotations

import fcntl
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path


INBOX = Path("/var/lib/idena-return-inbox")
LOCK_FILE = Path("/run/lock/idena-return-transfer.lock")
RRSYNC = "/usr/bin/rrsync"
MIN_FREE_BYTES = 10 * 1024**3
MAX_TRANSFER_SECONDS = 6 * 60 * 60
POLL_SECONDS = 1.0
TERMINATE_GRACE_SECONDS = 10


class GuardError(RuntimeError):
    pass


def ensure_plain_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise GuardError(f"{label} is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise GuardError(f"{label} is not a plain directory")
    if path.resolve() != path:
        raise GuardError(f"{label} is not canonical")


def open_transfer_lock() -> int:
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(LOCK_FILE, flags)
    except OSError as exc:
        raise GuardError("transfer lock is unavailable") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise GuardError("transfer lock is not a regular file")
    if (
        metadata.st_uid != 0
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != 0o660
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise GuardError("transfer lock ownership or mode is unsafe")
    return descriptor


def available_bytes() -> int:
    return shutil.disk_usage(INBOX).free


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_transfer() -> int:
    original_command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not original_command.startswith("rsync --server ") or "\n" in original_command:
        raise GuardError("invalid rsync server command")

    lock_descriptor = open_transfer_lock()
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        if available_bytes() < MIN_FREE_BYTES:
            raise GuardError("destination free-space reserve is already exhausted")

        process = subprocess.Popen([RRSYNC, "-wo", str(INBOX)], start_new_session=True)
        terminating_signal: int | None = None

        def handle_signal(signum: int, _frame: object) -> None:
            nonlocal terminating_signal
            terminating_signal = signum
            stop_process_group(process)

        previous_handlers = {
            signum: signal.signal(signum, handle_signal)
            for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
        }
        try:
            deadline = time.monotonic() + MAX_TRANSFER_SECONDS
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    stop_process_group(process)
                    raise GuardError("transfer exceeded its time limit")
                if available_bytes() < MIN_FREE_BYTES:
                    stop_process_group(process)
                    raise GuardError("transfer stopped to preserve the free-space reserve")
                try:
                    process.wait(timeout=POLL_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
            if terminating_signal is not None:
                return 128 + terminating_signal
            return process.returncode
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
    finally:
        os.close(lock_descriptor)


def main() -> int:
    try:
        ensure_plain_directory(INBOX, "return inbox")
        if len(sys.argv) != 2:
            raise GuardError("exactly one operation is required")
        if sys.argv[1] == "capacity":
            print(available_bytes())
            return 0
        if sys.argv[1] == "transfer":
            return run_transfer()
        raise GuardError("unsupported operation")
    except (GuardError, OSError, subprocess.SubprocessError) as exc:
        print(f"Idena return guard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
