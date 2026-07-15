#!/usr/bin/env python3
"""Fail closed unless every local governance build tool matches its exact lock."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_LOCK_BYTES = 1024 * 1024
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class ToolchainGateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ToolchainGateError(message)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "toolchain lock contains a duplicate object key")
        result[key] = value
    return result


def load_locks(path: Path) -> dict[str, str]:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), "build plan must be a regular non-symlink file")
    require(metadata.st_size <= MAX_LOCK_BYTES, "build plan exceeds the size limit")
    payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs)
    locks = payload.get("toolchains")
    require(isinstance(locks, dict), "build plan has no toolchains object")
    expected = {"go", "rust", "node", "npm", "pnpm", "assemblyscript"}
    require(set(locks) == expected, "build plan toolchain set is incomplete or unknown")
    for name, value in locks.items():
        require(isinstance(value, str) and VERSION.fullmatch(value) is not None, f"invalid {name} lock")
    return locks


def run_version(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise ToolchainGateError(f"toolchain command failed: {' '.join(command)}: {detail.strip()}") from exc
    return result.stdout.strip()


def parse_versions(outputs: dict[str, str]) -> dict[str, str]:
    patterns = {
        "rust": re.compile(r"^rustc ([0-9]+\.[0-9]+\.[0-9]+) .+$"),
        "go": re.compile(r"^go version go([0-9]+\.[0-9]+\.[0-9]+) .+$"),
        "node": re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)$"),
        "npm": re.compile(r"^([0-9]+\.[0-9]+\.[0-9]+)$"),
        "pnpm": re.compile(r"^([0-9]+\.[0-9]+\.[0-9]+)$"),
        "assemblyscript": re.compile(r"^Version ([0-9]+\.[0-9]+\.[0-9]+)$"),
    }
    versions: dict[str, str] = {}
    for name, pattern in patterns.items():
        match = pattern.fullmatch(outputs.get(name, ""))
        require(match is not None, f"cannot parse {name} version output")
        versions[name] = match.group(1)
    return versions


def collect_versions(root: Path, locks: dict[str, str]) -> dict[str, str]:
    go_env = os.environ.copy()
    go_env["GOTOOLCHAIN"] = f"go{locks['go']}"
    outputs = {
        "rust": run_version(["rustc", "--version"], root),
        "go": run_version(["go", "version"], root, go_env),
        "node": run_version(["node", "--version"], root),
        "npm": run_version(["npm", "--version"], root),
        "pnpm": run_version(["corepack", "pnpm", "--version"], root),
        "assemblyscript": run_version(
            [
                "corepack",
                "pnpm",
                "--dir",
                "contracts/idena-code-governance",
                "exec",
                "asc",
                "--version",
            ],
            root,
        ),
    }
    return parse_versions(outputs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--build-plan", type=Path, default=Path("compatibility/governance-build-plan-v1.json"))
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    plan = args.build_plan if args.build_plan.is_absolute() else root / args.build_plan
    locks = load_locks(plan)
    actual = collect_versions(root, locks)
    mismatches = {
        name: {"expected": locks[name], "actual": actual.get(name)}
        for name in sorted(locks)
        if actual.get(name) != locks[name]
    }
    require(not mismatches, "toolchain mismatch: " + json.dumps(mismatches, sort_keys=True))
    print(json.dumps({"schemaVersion": 1, "ready": True, "toolchains": actual}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ToolchainGateError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"governance toolchain gate failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
