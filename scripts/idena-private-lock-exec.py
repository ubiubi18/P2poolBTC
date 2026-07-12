#!/usr/bin/env python3
"""Safely acquire a private root process lock, then exec the requested program."""

from __future__ import annotations

import fcntl
import os
import re
import stat
import sys
from pathlib import Path


LOCK_NAME = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")
LOCK_FD = 9
LOCK_ENV = "IDENA_PRIVATE_LOCK_HELD"


def fail(message: str) -> int:
    print(f"Idena private lock: {message}", file=sys.stderr)
    return 1


def main() -> int:
    if os.geteuid() != 0:
        return fail("must run as root")
    if len(sys.argv) < 3:
        return fail("usage: idena-private-lock-exec LOCK PROGRAM [ARG ...]")

    lock_path = Path(sys.argv[1])
    program = Path(sys.argv[2])
    if lock_path.parent != Path("/run/lock") or not LOCK_NAME.fullmatch(lock_path.name):
        return fail("lock must be a simple filename directly inside /run/lock")
    if program.is_symlink() or not program.is_file() or not os.access(program, os.X_OK):
        return fail("program must be an executable, non-symlink regular file")
    if program.resolve() != program:
        return fail("program path must be canonical")

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        return fail(f"cannot safely open lock: {exc.strerror}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return fail("lock is not a regular file")
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
            return fail("lock must be owned by root with mode 0600")
        if metadata.st_nlink != 1:
            return fail("lock must have exactly one hard link")
        try:
            current = lock_path.lstat()
        except FileNotFoundError:
            return fail("lock path disappeared while opening")
        if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            return fail("lock path changed while opening")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("another process already holds the private Idena lock")
            return 0

        if descriptor != LOCK_FD:
            os.dup2(descriptor, LOCK_FD, inheritable=True)
            os.close(descriptor)
            descriptor = LOCK_FD
        else:
            os.set_inheritable(descriptor, True)
        environment = dict(os.environ)
        environment[LOCK_ENV] = str(lock_path)
        os.execve(program, [str(program), *sys.argv[3:]], environment)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
