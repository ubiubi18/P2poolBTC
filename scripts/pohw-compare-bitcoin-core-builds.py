#!/usr/bin/env python3
"""Compare Experiment 2 Bitcoin Core build evidence without claiming identity proof."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "pohw-experiment-2-build-comparison/v2"
EVIDENCE_SCHEMA = "pohw-bitcoin-core-build-evidence/v5"
LOCK_SCHEMA = "pohw-bitcoin-core-patch-series-lock/v1"
MAX_JSON_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TARGET_TRIPLET_RE = re.compile(r"^[A-Za-z0-9_.+]+-[A-Za-z0-9_.+]+-[A-Za-z0-9_.+-]+$")
ARTIFACT_SET_TAG = b"P2POOLBTC_EXPERIMENT_2_CORE_ARTIFACT_SET_V1\0"
ROOT_KEYS = {
    "schema_version",
    "activation_id",
    "manifest_sha256",
    "upstream_commit",
    "patch_sha256",
    "target",
    "source_snapshot",
    "build",
    "tests",
    "toolchain",
    "artifacts",
}
ARTIFACT_PATHS = {
    "bitcoin-cli": "pohw-release/bin/bitcoin-cli",
    "bitcoind": "pohw-release/bin/bitcoind",
    "test_bitcoin": "pohw-release/libexec/test_bitcoin",
}
BUILD_KEYS = {
    "generator",
    "cmake_flags",
    "cmake_cache",
    "cmake_cxx_configuration_sha256",
    "depends",
    "environment",
    "commands",
    "run_record_sha256",
    "snapshot_metadata_sha256",
}
COMMAND_KEYS = {"label", "argv", "env", "exit_code", "log_path", "output_sha256"}


class ComparisonError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ComparisonError(message)


def platform_family_for_triplet(host: str) -> str:
    require(
        TARGET_TRIPLET_RE.fullmatch(host) is not None,
        "build evidence target host must be a canonical triplet",
    )
    lowered = host.lower()
    families = (
        ("linux", "linux"),
        ("darwin", "macos"),
        ("mingw", "windows"),
        ("windows", "windows"),
        ("freebsd", "freebsd"),
        ("openbsd", "openbsd"),
    )
    matches = {family for marker, family in families if marker in lowered}
    require(
        len(matches) == 1,
        f"build evidence target has an unsupported platform family: {host}",
    )
    return matches.pop()


def duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular_file(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ComparisonError(f"cannot open JSON input {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"JSON input is not a regular file: {path}")
        require(before.st_size <= MAX_JSON_BYTES, f"JSON input is too large: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            require(bool(chunk), f"JSON input was truncated while reading: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(not os.read(descriptor, 1), f"JSON input grew while reading: {path}")
        after = os.fstat(descriptor)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            f"JSON input changed while reading: {path}",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_file(path)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate_safe_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ComparisonError(f"invalid UTF-8 JSON input {path}: {exc}") from exc
    require(isinstance(value, dict), f"JSON root must be an object: {path}")
    return value, raw


def load_evidence_module(root: Path):
    path = root / "scripts" / "pohw-bitcoin-core-build-evidence.py"
    spec = importlib.util.spec_from_file_location("pohw_bitcoin_core_build_evidence", path)
    require(spec is not None and spec.loader is not None, "cannot load build evidence verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_lock(root: Path, lock_path: Path) -> tuple[dict[str, Any], bytes]:
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "pohw-experiment-2-consensus-identity.py"),
            "--repo-root",
            str(root),
            "--lock",
            str(lock_path),
        ],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    require(result.returncode == 0, f"Experiment 2 lock verification failed: {result.stderr.strip()}")
    lock, raw = read_json(lock_path)
    require(lock.get("schema_version") == LOCK_SCHEMA, "unexpected Experiment 2 lock schema")
    return lock, raw


def artifact_set(evidence: dict[str, Any]) -> tuple[str, tuple[tuple[str, str, int], ...]]:
    artifacts = evidence.get("artifacts")
    require(
        isinstance(artifacts, dict) and set(artifacts) == set(ARTIFACT_PATHS),
        "build evidence does not contain the exact required artifact set",
    )
    normalized: list[tuple[str, str, int]] = []
    for name in sorted(artifacts):
        artifact = artifacts[name]
        require(
            isinstance(artifact, dict) and set(artifact) == {"path", "sha256", "size_bytes"},
            f"invalid build artifact entry: {name}",
        )
        require(artifact.get("path") == ARTIFACT_PATHS[name], f"artifact path mismatch: {name}")
        digest = artifact.get("sha256")
        size = artifact.get("size_bytes")
        require(isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None, f"invalid artifact digest: {name}")
        require(isinstance(size, int) and not isinstance(size, bool) and size >= 0, f"invalid artifact size: {name}")
        normalized.append((name, digest, size))
    digest = hashlib.sha256(ARTIFACT_SET_TAG)
    for name, artifact_sha256, size in normalized:
        encoded_name = name.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(bytes.fromhex(artifact_sha256))
        digest.update(size.to_bytes(8, "big"))
    return digest.hexdigest(), tuple(normalized)


def snapshot_digest(evidence: dict[str, Any]) -> str:
    try:
        digest = evidence["source_snapshot"]["snapshot"]["sha256"]
    except (KeyError, TypeError) as exc:
        raise ComparisonError("build evidence lacks a source snapshot digest") from exc
    require(isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None, "invalid source snapshot digest")
    return digest


def validate_evidence(
    evidence: dict[str, Any],
    lock: dict[str, Any],
    lock_sha256: str,
    profile: dict[str, Any],
) -> tuple[str, tuple[tuple[str, str, int], ...], str, str, str]:
    require(set(evidence) == ROOT_KEYS, "build evidence root fields differ")
    require(evidence.get("schema_version") == EVIDENCE_SCHEMA, "unsupported build evidence schema")
    require(evidence.get("activation_id") == profile["activation_id"], "build evidence activation ID mismatch")
    require(evidence.get("upstream_commit") == profile["upstream_commit"], "build evidence upstream commit mismatch")
    require(evidence.get("patch_sha256") == profile["patch_sha256"], "build evidence patch-series mismatch")
    require(evidence.get("manifest_sha256") == lock_sha256, "build evidence lock digest mismatch")
    tests = evidence.get("tests")
    require(isinstance(tests, dict) and set(tests) == {"status", "required_steps"}, "build test evidence fields differ")
    require(isinstance(tests, dict) and tests.get("status") == "passed", "build evidence does not report passing tests")
    require(tests.get("required_steps") == list(profile["test_steps"]), "build evidence omits or reorders required tests")
    build = evidence.get("build")
    require(isinstance(build, dict) and set(build) == BUILD_KEYS, "build evidence fields differ")
    require(build.get("generator") == "Ninja", "build evidence generator mismatch")
    require(build.get("cmake_flags") == list(profile["cmake_flags"]), "build evidence CMake flags mismatch")
    for field in (
        "cmake_cxx_configuration_sha256",
        "run_record_sha256",
        "snapshot_metadata_sha256",
    ):
        value = build.get(field)
        require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"invalid build digest: {field}")
    require(isinstance(build.get("cmake_cache"), dict), "build evidence has no CMake cache")
    require(isinstance(build.get("depends"), dict), "build evidence has no depends record")
    require(isinstance(build.get("environment"), dict), "build evidence has no environment record")
    commands = build.get("commands")
    require(isinstance(commands, list), "build evidence has no command record")
    labels = []
    for command in commands:
        require(isinstance(command, dict) and set(command) == COMMAND_KEYS, "build command fields differ")
        label = command.get("label")
        labels.append(label)
        require(
            isinstance(label, str)
            and isinstance(command.get("argv"), list)
            and bool(command["argv"])
            and all(isinstance(item, str) for item in command["argv"])
            and isinstance(command.get("env"), dict)
            and command.get("exit_code") == 0
            and command.get("log_path") == f"pohw-build-logs/{label}.log"
            and isinstance(command.get("output_sha256"), str)
            and SHA256_RE.fullmatch(command["output_sha256"]) is not None,
            f"invalid build command record: {label}",
        )
    require(labels == list(profile["required_steps"]), "build evidence command sequence is incomplete")
    require(isinstance(evidence.get("toolchain"), dict) and evidence["toolchain"], "build evidence has no toolchain record")
    target = evidence.get("target")
    require(
        isinstance(target, dict) and set(target) == {"triple", "platform_family"},
        "build evidence target fields differ",
    )
    target_triple = target.get("triple")
    platform_family = target.get("platform_family")
    require(isinstance(target_triple, str), "build evidence target triple is invalid")
    expected_family = platform_family_for_triplet(target_triple)
    require(platform_family == expected_family, "build evidence target platform family mismatch")
    require(
        build["depends"].get("host") == target_triple,
        "build evidence target does not match the sealed depends toolchain",
    )
    return (*artifact_set(evidence), snapshot_digest(evidence), target_triple, platform_family)


def compare(root: Path, lock_path: Path, evidence_paths: list[Path], minimum: int) -> dict[str, Any]:
    lock, lock_raw = verify_lock(root, lock_path)
    policy = lock["independent_builds"]
    locked_minimum = policy["minimum_matching_builds"]
    minimum_per_target = policy["minimum_matching_builds_per_target"]
    minimum_platform_families = policy["minimum_platform_families"]
    require(
        minimum >= locked_minimum,
        f"consensus-critical comparison requires at least {locked_minimum} builds",
    )
    require(len(evidence_paths) >= minimum, f"at least {minimum} build evidence files are required")
    lock_sha256 = hashlib.sha256(lock_raw).hexdigest()
    profile = load_evidence_module(root).manifest_profile(lock)
    evidence_digests: list[str] = []
    expected_snapshot: str | None = None
    target_groups: dict[
        str,
        tuple[str, str, tuple[tuple[str, str, int], ...], list[str]],
    ] = {}
    for path in evidence_paths:
        evidence, raw = read_json(path)
        evidence_sha256 = hashlib.sha256(raw).hexdigest()
        require(evidence_sha256 not in evidence_digests, "duplicate build evidence payload")
        evidence_digests.append(evidence_sha256)
        artifact_digest, artifacts, source_snapshot, target_triple, platform_family = validate_evidence(
            evidence, lock, lock_sha256, profile
        )
        if expected_snapshot is None:
            expected_snapshot = source_snapshot
        else:
            require(source_snapshot == expected_snapshot, "builders used different source snapshots")
        existing = target_groups.get(target_triple)
        if existing is None:
            target_groups[target_triple] = (
                platform_family,
                artifact_digest,
                artifacts,
                [evidence_sha256],
            )
        else:
            expected_family, expected_digest, expected_artifacts, group_evidence = existing
            require(
                platform_family == expected_family,
                "target platform family changed between builders",
            )
            require(
                artifact_digest == expected_digest and artifacts == expected_artifacts,
                f"builder artifact sets do not match for target {target_triple}",
            )
            group_evidence.append(evidence_sha256)
    require(bool(target_groups), "no target build groups were produced")
    for target_triple, (_, _, _, group_evidence) in target_groups.items():
        require(
            len(group_evidence) >= minimum_per_target,
            f"target {target_triple} has fewer than {minimum_per_target} matching builds",
        )
    platform_families = sorted({group[0] for group in target_groups.values()})
    require(
        len(platform_families) >= minimum_platform_families,
        f"comparison requires at least {minimum_platform_families} platform families",
    )
    target_reports = [
        {
            "target_triple": target_triple,
            "platform_family": platform_family,
            "artifact_set_sha256": artifact_digest,
            "matching_build_count": len(group_evidence),
            "evidence_sha256": sorted(group_evidence),
        }
        for target_triple, (platform_family, artifact_digest, _, group_evidence) in sorted(
            target_groups.items()
        )
    ]
    return {
        "schema_version": SCHEMA,
        "status": "matching-build-evidence-unattributed",
        "experiment_id": lock["release_id"],
        "activation_id": profile["activation_id"],
        "lock_sha256": lock_sha256,
        "source_snapshot_sha256": expected_snapshot,
        "matching_build_count": len(evidence_paths),
        "minimum_matching_builds": minimum,
        "minimum_matching_builds_per_target": minimum_per_target,
        "minimum_platform_families": minimum_platform_families,
        "platform_families": platform_families,
        "target_groups": target_reports,
        "evidence_sha256": sorted(evidence_digests),
        "operator_independence_verified": False,
        "release_authorized": False,
        "next_gate": "authenticate each target-group build with a distinct eligible Idena owner; critical DAO execution remains disabled until artifact-group governance is deployed",
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("ascii")
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    try:
        os.link(temporary, path)
    except FileExistsError as exc:
        raise ComparisonError("comparison output must be new") from exc
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--evidence", type=Path, action="append", required=True)
    parser.add_argument("--minimum-builds", type=int, default=4)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    lock = args.lock or root / "compatibility" / "experiment-2-bitcoin-core-patch-lock.json"
    if not lock.is_absolute():
        lock = root / lock
    try:
        report = compare(root, lock, args.evidence, args.minimum_builds)
        if args.output:
            write_report(args.output, report)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (ComparisonError, OSError, subprocess.SubprocessError) as exc:
        print(f"Experiment 2 build comparison failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
