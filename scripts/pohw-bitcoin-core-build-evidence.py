#!/usr/bin/env python3
"""Create and verify fail-closed provenance for the PoHW Bitcoin Core build."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import posixpath
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "pohw-bitcoin-core-build-evidence/v4"
RUN_SCHEMA = "pohw-bitcoin-core-build-run/v4"
SNAPSHOT_SCHEMA = "pohw-bitcoin-core-source-snapshot/v1"
SNAPSHOT_HASH_SCHEMA = b"pohw-bitcoin-core-source-snapshot-sha256/v1\0"
DEPENDS_SCHEMA = "pohw-bitcoin-core-depends-prefix/v1"
DEPENDS_SOURCE_SCHEMA = "pohw-bitcoin-core-depends-source/v1"
REQUIRED_ARTIFACTS = ("bitcoind", "bitcoin-cli", "test_bitcoin")
RELEASE_ARTIFACT_PATHS = {
    "bitcoind": "pohw-release/bin/bitcoind",
    "bitcoin-cli": "pohw-release/bin/bitcoin-cli",
    "test_bitcoin": "pohw-release/libexec/test_bitcoin",
}
REQUIRED_STEPS = (
    "depends_fetch",
    "depends_build",
    "configure",
    "build",
    "pow_sanity",
    "block_file_magic",
    "bootstrap_marker",
    "template_difficulty",
    "replay_marker",
    "replay_domain",
    "replay_checkpoint",
    "replay_version",
    "script_cache_domain",
    "block_file_reader",
    "replay_functional",
    "ctest",
    "install",
)
TEST_STEPS = (
    "pow_sanity",
    "block_file_magic",
    "bootstrap_marker",
    "template_difficulty",
    "replay_marker",
    "replay_domain",
    "replay_checkpoint",
    "replay_version",
    "script_cache_domain",
    "block_file_reader",
    "replay_functional",
    "ctest",
)
CANONICAL_FLAGS = (
    "-DBUILD_GUI=OFF",
    "-DBUILD_TESTS=ON",
    "-DBUILD_BENCH=OFF",
    "-DBUILD_FUZZ_BINARY=OFF",
    "-DENABLE_IPC=OFF",
)
TEST_FILTERS = {
    "pow_sanity": "pow_tests/ChainParams_POHW_sanity",
    "block_file_magic": "pow_tests/POHW_inherited_block_file_magic_is_disk_only",
    "bootstrap_marker": "pow_tests/POHW_bootstrap_and_handoff_marker",
    "template_difficulty": "pow_tests/POHW_update_time_refreshes_template_difficulty",
    "replay_marker": (
        "transaction_tests/"
        "pohw_inherited_spend_requires_fork_only_replay_marker"
    ),
    "replay_domain": (
        "transaction_tests/pohw_replay_sighash_domain_resists_marker_stripping"
    ),
    "replay_checkpoint": (
        "transaction_tests/"
        "pohw_active_chain_replay_checkpoint_is_fail_closed"
    ),
    "replay_version": (
        "transaction_tests/pohw_replay_protected_version_is_network_scoped"
    ),
    "script_cache_domain": "txvalidationcache_tests",
    "block_file_reader": "streams_tests/streams_buffered_file_find_any_byte",
}
EXPERIMENT_2_LOCK_SCHEMA = "pohw-bitcoin-core-patch-series-lock/v1"
EXPERIMENT_2_TEST_FILTERS = {
    "consensus_identity": "pohw_identity_auth_tests",
}
EXPERIMENT_1_FUNCTIONAL_TESTS = (
    ("replay_functional", "feature_pohw_replay.py"),
)
EXPERIMENT_2_FUNCTIONAL_TESTS = (
    ("replay_functional", "feature_pohw_replay.py"),
    ("consensus_identity_functional", "feature_pohw_identity_auth.py"),
)
HEX_TREE_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
BUILD_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
HOST_TRIPLET_RE = re.compile(r"^[A-Za-z0-9_.+]+-[A-Za-z0-9_.+]+-[A-Za-z0-9_.+-]+$")
BASE_ENVIRONMENT_KEYS = {"HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "TZ", "USER"}
DEPENDS_VARIABLES = (
    "NO_QT=1",
    "NO_QR=1",
    "NO_ZMQ=1",
    "NO_IPC=1",
    "NO_USDT=1",
)


class EvidenceError(ValueError):
    pass


def manifest_profile(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != EXPERIMENT_2_LOCK_SCHEMA:
        return {
            "id": "experiment-1",
            "activation_id": manifest.get("activation_id"),
            "upstream_commit": manifest.get("upstream", {}).get("commit"),
            "patch_sha256": manifest.get("build", {}).get("patch_sha256"),
            "cmake_flags": CANONICAL_FLAGS,
            "required_steps": REQUIRED_STEPS,
            "test_steps": TEST_STEPS,
            "test_filters": TEST_FILTERS,
            "functional_tests": EXPERIMENT_1_FUNCTIONAL_TESTS,
        }

    if manifest.get("status") != "experimental-candidate-inactive" or manifest.get("launch_enabled") is not False:
        raise EvidenceError("Experiment 2 build lock must remain inactive")
    upstream = manifest.get("upstream")
    network = manifest.get("network")
    if not isinstance(upstream, dict) or not isinstance(network, dict):
        raise EvidenceError("Experiment 2 build lock is missing upstream or network data")
    activation_id = network.get("candidate_activation_id")
    upstream_commit = upstream.get("commit")
    patch_sha256 = manifest.get("patch_series_sha256")
    if not isinstance(activation_id, str) or HEX_SHA256_RE.fullmatch(activation_id) is None:
        raise EvidenceError("Experiment 2 activation ID is invalid")
    if not isinstance(upstream_commit, str) or re.fullmatch(r"[0-9a-f]{40}", upstream_commit) is None:
        raise EvidenceError("Experiment 2 upstream commit is invalid")
    if not isinstance(patch_sha256, str) or HEX_SHA256_RE.fullmatch(patch_sha256) is None:
        raise EvidenceError("Experiment 2 patch-series digest is invalid")
    cmake_flags = (*CANONICAL_FLAGS, f"-DPOHW2_ACTIVATION_ID={activation_id}")
    test_filters = {**TEST_FILTERS, **EXPERIMENT_2_TEST_FILTERS}
    required_steps = (
        *REQUIRED_STEPS[: REQUIRED_STEPS.index("replay_functional")],
        "consensus_identity",
        "replay_functional",
        "consensus_identity_functional",
        *REQUIRED_STEPS[REQUIRED_STEPS.index("replay_functional") + 1 :],
    )
    test_steps = (
        *TEST_STEPS[: TEST_STEPS.index("replay_functional")],
        "consensus_identity",
        "replay_functional",
        "consensus_identity_functional",
        *TEST_STEPS[TEST_STEPS.index("replay_functional") + 1 :],
    )
    return {
        "id": "experiment-2",
        "activation_id": activation_id,
        "upstream_commit": upstream_commit,
        "patch_sha256": patch_sha256,
        "cmake_flags": cmake_flags,
        "required_steps": required_steps,
        "test_steps": test_steps,
        "test_filters": test_filters,
        "functional_tests": EXPERIMENT_2_FUNCTIONAL_TESTS,
    }


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink():
            raise EvidenceError(f"JSON path must not be a symlink: {path}")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"JSON root must be an object: {path}")
    return value


def encoded_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise EvidenceError(f"output path must not be a symlink: {path}")
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(encoded_json(value))
        temp_path = Path(handle.name)
    temp_path.chmod(mode)
    temp_path.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        if path.is_symlink():
            raise EvidenceError(f"file must not be a symlink: {path}")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceError(f"cannot hash file {path}: {exc}") from exc
    return digest.hexdigest()


def _frame(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def snapshot_details(snapshot_dir: Path, require_immutable: bool = True) -> dict[str, Any]:
    if snapshot_dir.is_symlink():
        raise EvidenceError(f"snapshot directory must not be a symlink: {snapshot_dir}")
    root = snapshot_dir.resolve(strict=True)
    root_stat = root.stat()
    if not stat.S_ISDIR(root_stat.st_mode):
        raise EvidenceError(f"snapshot path is not a directory: {root}")
    if require_immutable and root_stat.st_mode & 0o222:
        raise EvidenceError("source snapshot root is writable")

    records: list[tuple[bytes, bytes, int, bytes]] = []
    total_bytes = 0

    def visit(directory: Path, prefix: str) -> None:
        nonlocal total_bytes
        try:
            entries = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            raise EvidenceError(f"cannot enumerate source snapshot {directory}: {exc}") from exc
        for entry in entries:
            try:
                name = entry.name.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise EvidenceError("snapshot path is not valid UTF-8") from exc
            if name in (b".", b"..") or b"\x00" in name or b"/" in name:
                raise EvidenceError("snapshot contains an unsafe path component")
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if relative == ".git" or relative.startswith(".git/"):
                raise EvidenceError("source snapshot must not contain .git metadata")
            relative_bytes = relative.encode("utf-8", errors="strict")
            path = Path(entry.path)
            try:
                item_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise EvidenceError(f"cannot stat snapshot entry {path}: {exc}") from exc
            if require_immutable and not stat.S_ISLNK(item_stat.st_mode):
                if item_stat.st_mode & 0o222:
                    raise EvidenceError(f"source snapshot entry is writable: {relative}")
            if stat.S_ISDIR(item_stat.st_mode):
                records.append((relative_bytes, b"d", 0o755, b""))
                visit(path, relative)
            elif stat.S_ISREG(item_stat.st_mode):
                if item_stat.st_nlink != 1:
                    raise EvidenceError(f"snapshot regular file has external hard links: {relative}")
                try:
                    payload = path.read_bytes()
                except OSError as exc:
                    raise EvidenceError(f"cannot read snapshot file {path}: {exc}") from exc
                mode = 0o755 if item_stat.st_mode & 0o111 else 0o644
                records.append((relative_bytes, b"f", mode, payload))
                total_bytes += len(payload)
            elif stat.S_ISLNK(item_stat.st_mode):
                try:
                    target = os.readlink(path)
                    target_bytes = target.encode("utf-8", errors="strict")
                except (OSError, UnicodeEncodeError) as exc:
                    raise EvidenceError(f"cannot read snapshot symlink {relative}: {exc}") from exc
                if posixpath.isabs(target):
                    raise EvidenceError(f"snapshot symlink is absolute: {relative}")
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
                if resolved == ".." or resolved.startswith("../"):
                    raise EvidenceError(f"snapshot symlink escapes the tree: {relative}")
                records.append((relative_bytes, b"l", 0o777, target_bytes))
                total_bytes += len(target_bytes)
            else:
                raise EvidenceError(f"snapshot contains a special file: {relative}")

    visit(root, "")
    records.sort(key=lambda item: item[0])
    digest = hashlib.sha256(SNAPSHOT_HASH_SCHEMA)
    for relative, kind, mode, payload in records:
        _frame(digest, relative)
        _frame(digest, kind)
        _frame(digest, f"{mode:o}".encode("ascii"))
        _frame(digest, payload)
    return {
        "hash_format": SNAPSHOT_HASH_SCHEMA.rstrip(b"\0").decode("ascii"),
        "sha256": digest.hexdigest(),
        "entry_count": len(records),
        "payload_bytes": total_bytes,
        "immutable": require_immutable,
    }


def seal_tree(root: Path) -> Path:
    if root.is_symlink():
        raise EvidenceError(f"tree root must not be a symlink: {root}")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise EvidenceError(f"tree root must be a directory: {resolved}")
    snapshot_details(resolved, require_immutable=False)

    def seal(directory: Path) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise EvidenceError(f"cannot enumerate tree {directory}: {exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            try:
                item_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise EvidenceError(f"cannot stat tree entry {path}: {exc}") from exc
            if stat.S_ISLNK(item_stat.st_mode):
                continue
            if stat.S_ISDIR(item_stat.st_mode):
                seal(path)
                path.chmod(0o555)
            elif stat.S_ISREG(item_stat.st_mode):
                path.chmod(0o555 if item_stat.st_mode & 0o111 else 0o444)
            else:
                raise EvidenceError(f"tree contains a special file: {path}")

    seal(resolved)
    resolved.chmod(0o555)
    snapshot_details(resolved)
    return resolved


def copy_verified_tree(source: Path, destination: Path) -> dict[str, Any]:
    source = source.resolve(strict=True)
    source_details = snapshot_details(source)
    if destination.exists() or destination.is_symlink():
        raise EvidenceError("depends source destination must be new")
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise EvidenceError("depends source parent must be a real directory")
    try:
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
    except OSError as exc:
        raise EvidenceError(f"cannot copy depends source: {exc}") from exc
    destination.chmod(0o755)
    for path in destination.rglob("*"):
        if path.is_symlink():
            continue
        mode = path.lstat().st_mode
        path.chmod(0o755 if path.is_dir() or mode & 0o111 else 0o644)
    copied = snapshot_details(destination, require_immutable=False)
    for key in ("hash_format", "sha256", "entry_count", "payload_bytes"):
        if copied[key] != source_details[key]:
            raise EvidenceError("copied depends source differs from the immutable snapshot")
    return source_details


def validate_depends_source_metadata(
    metadata_path: Path,
    snapshot_dir: Path,
    build_dir: Path,
) -> dict[str, Any]:
    expected_metadata = build_dir / "pohw-depends-source.json"
    if metadata_path.resolve(strict=False) != expected_metadata:
        raise EvidenceError("depends source metadata must use the canonical build path")
    metadata = read_json(metadata_path)
    if set(metadata) != {"schema_version", "source", "destination", "tree"}:
        raise EvidenceError("depends source metadata has missing or unexpected fields")
    if metadata.get("schema_version") != DEPENDS_SOURCE_SCHEMA:
        raise EvidenceError("unsupported depends source metadata schema")
    if metadata.get("source") != "depends":
        raise EvidenceError("depends source metadata has a noncanonical source")
    if metadata.get("destination") != "pohw-depends/source":
        raise EvidenceError("depends source metadata has a noncanonical destination")
    actual = snapshot_details(snapshot_dir / "depends")
    if metadata.get("tree") != actual:
        raise EvidenceError("depends source metadata is stale for the immutable snapshot")
    return metadata


def validate_depends_metadata(metadata_path: Path, build_dir: Path) -> dict[str, Any]:
    expected_metadata = build_dir / "pohw-depends-prefix.json"
    if metadata_path.resolve(strict=False) != expected_metadata:
        raise EvidenceError("depends metadata must use the canonical build path")
    metadata = read_json(metadata_path)
    if set(metadata) != {"schema_version", "host", "prefix", "tree"}:
        raise EvidenceError("depends metadata has missing or unexpected fields")
    if metadata.get("schema_version") != DEPENDS_SCHEMA:
        raise EvidenceError("unsupported depends metadata schema")
    host = metadata.get("host")
    if not isinstance(host, str) or HOST_TRIPLET_RE.fullmatch(host) is None:
        raise EvidenceError("depends metadata has an invalid host triplet")
    expected_prefix = f"pohw-depends/source/{host}"
    if metadata.get("prefix") != expected_prefix:
        raise EvidenceError("depends metadata has a noncanonical prefix")
    prefix = (build_dir / expected_prefix).resolve(strict=True)
    actual = snapshot_details(prefix)
    if metadata.get("tree") != actual:
        raise EvidenceError("depends metadata does not match the immutable prefix")
    toolchain = prefix / "toolchain.cmake"
    if not toolchain.is_file() or toolchain.is_symlink():
        raise EvidenceError("depends prefix has no regular toolchain.cmake")
    return metadata


def command_output(executable: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            (str(executable), *args),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"cannot inspect tool {executable}: {exc}") from exc
    lines = result.stdout.splitlines()
    if not lines:
        raise EvidenceError(f"tool produced no version output: {executable}")
    return lines[0].strip()


def executable_identity(raw: str, *version_args: str) -> dict[str, Any]:
    candidate = Path(raw)
    if not candidate.is_absolute():
        located = shutil.which(raw)
        if located is None:
            raise EvidenceError(f"tool is not available: {raw}")
        candidate = Path(located)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"cannot resolve tool {candidate}: {exc}") from exc
    if not resolved.is_file():
        raise EvidenceError(f"tool is not a regular file: {resolved}")
    return {
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "size_bytes": resolved.stat().st_size,
        "version": command_output(resolved, *version_args),
    }


def cmake_cache(build_dir: Path) -> dict[str, str]:
    cache = build_dir / "CMakeCache.txt"
    try:
        if cache.is_symlink():
            raise EvidenceError(f"CMake cache must not be a symlink: {cache}")
        lines = cache.read_text(encoding="utf-8", errors="strict").splitlines()
    except OSError as exc:
        raise EvidenceError(f"cannot read CMake cache {cache}: {exc}") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        key_and_type, value = line.split("=", 1)
        key = key_and_type.split(":", 1)[0]
        if key in entries:
            raise EvidenceError(f"duplicate CMake cache entry: {key}")
        entries[key] = value
    return entries


def cmake_cxx_configuration(build_dir: Path) -> tuple[Path, str]:
    candidates = sorted(
        (build_dir / "CMakeFiles").glob("*/CMakeCXXCompiler.cmake")
    )
    if len(candidates) != 1:
        raise EvidenceError("CMake must produce exactly one C++ compiler configuration")
    configuration = candidates[0]
    if not configuration.is_file() or configuration.is_symlink():
        raise EvidenceError("CMake C++ compiler configuration must be a regular file")
    try:
        content = configuration.read_text(encoding="utf-8", errors="strict")
    except OSError as exc:
        raise EvidenceError(f"cannot read CMake C++ compiler configuration: {exc}") from exc
    matches = re.findall(r'^set\(CMAKE_CXX_COMPILER "([^"]+)"\)$', content, re.MULTILINE)
    if len(matches) != 1 or not Path(matches[0]).is_absolute():
        raise EvidenceError("CMake C++ compiler configuration is ambiguous")
    return configuration, matches[0]


def validate_snapshot_metadata(
    metadata_path: Path,
    snapshot_dir: Path,
    manifest: dict[str, Any],
    manifest_path: Path,
) -> dict[str, Any]:
    profile = manifest_profile(manifest)
    metadata = read_json(metadata_path)
    if set(metadata) != {
        "schema_version",
        "upstream_commit",
        "patch_sha256",
        "manifest_sha256",
        "patched_tree_oid",
        "snapshot",
    }:
        raise EvidenceError("source snapshot metadata has missing or unexpected fields")
    if metadata.get("schema_version") != SNAPSHOT_SCHEMA:
        raise EvidenceError("unsupported source snapshot metadata schema")
    tree_oid = metadata.get("patched_tree_oid")
    if not isinstance(tree_oid, str) or not HEX_TREE_RE.fullmatch(tree_oid):
        raise EvidenceError("source snapshot metadata has an invalid patched tree id")
    if metadata.get("upstream_commit") != profile["upstream_commit"]:
        raise EvidenceError("source snapshot metadata has a stale upstream commit")
    if metadata.get("patch_sha256") != profile["patch_sha256"]:
        raise EvidenceError("source snapshot metadata has a stale patch digest")
    if metadata.get("manifest_sha256") != sha256_file(manifest_path):
        raise EvidenceError("source snapshot metadata has a stale manifest digest")
    actual = snapshot_details(snapshot_dir)
    if metadata.get("snapshot") != actual:
        raise EvidenceError("source snapshot metadata does not match the immutable tree")
    return metadata


def normalize_step(step: dict[str, Any], build_dir: Path) -> dict[str, Any]:
    if set(step) != {"label", "argv", "env", "exit_code", "log_path", "output_sha256"}:
        raise EvidenceError("build run step has missing or unexpected fields")
    label = step.get("label")
    argv = step.get("argv")
    env = step.get("env")
    if not isinstance(label, str) or not LABEL_RE.fullmatch(label):
        raise EvidenceError("build run step has an invalid label")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise EvidenceError(f"build run step {label} has invalid argv")
    if not isinstance(env, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in env.items()
    ):
        raise EvidenceError(f"build run step {label} has invalid environment data")
    if step.get("exit_code") != 0:
        raise EvidenceError(f"required build step did not pass: {label}")
    log_path = step.get("log_path")
    if log_path != f"pohw-build-logs/{label}.log":
        raise EvidenceError(f"build run step {label} has a noncanonical log path")
    log = build_dir / log_path
    if not log.is_file() or log.is_symlink():
        raise EvidenceError(f"missing regular build log for step {label}")
    output_digest = step.get("output_sha256")
    if not isinstance(output_digest, str) or output_digest != sha256_file(log):
        raise EvidenceError(f"build log digest mismatch for step {label}")
    return step


def build_environment() -> dict[str, str]:
    path = os.environ.get("PATH", "")
    username = pwd.getpwuid(os.getuid()).pw_name
    return {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": username,
        "PATH": path,
        "TZ": "UTC",
        "USER": username,
    }


def validate_build_environment(environment: Any) -> dict[str, str]:
    if not isinstance(environment, dict) or set(environment) != BASE_ENVIRONMENT_KEYS:
        raise EvidenceError("build run environment has missing or unexpected fields")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in environment.items()):
        raise EvidenceError("build run environment must contain only strings")
    if environment["HOME"] != "/nonexistent":
        raise EvidenceError("build HOME must be /nonexistent")
    if environment["LANG"] != "C" or environment["LC_ALL"] != "C":
        raise EvidenceError("build locale must be C")
    if environment["TZ"] != "UTC":
        raise EvidenceError("build timezone must be UTC")
    if (
        environment["USER"] != environment["LOGNAME"]
        or BUILD_USER_RE.fullmatch(environment["USER"]) is None
    ):
        raise EvidenceError("build user identity is invalid")
    path_entries = environment["PATH"].split(":")
    if not path_entries or any(not item or not Path(item).is_absolute() for item in path_entries):
        raise EvidenceError("build PATH must contain only nonempty absolute directories")
    return environment


def validate_commands(
    steps: list[dict[str, Any]],
    snapshot_dir: Path,
    build_dir: Path,
    cache: dict[str, str],
    depends: dict[str, Any],
    profile: dict[str, Any],
) -> None:
    by_label = {step["label"]: step for step in steps}
    depends_root = build_dir / "pohw-depends"
    depends_source = depends_root / "source"
    depends_prefix = depends_source / depends["host"]
    make = str(Path(by_label["depends_fetch"]["argv"][0]).resolve(strict=True))
    depends_argv = [
        make,
        "-C",
        str(depends_source),
        f"HOST={depends['host']}",
        *DEPENDS_VARIABLES,
    ]
    fetch = by_label["depends_fetch"]
    if fetch["argv"] != [*depends_argv, "download-one"] or fetch["env"]:
        raise EvidenceError("depends fetch command does not match the canonical invocation")
    depends_build = by_label["depends_build"]
    if depends_build["argv"] != [*depends_argv, "install"] or depends_build["env"]:
        raise EvidenceError("depends build command does not match the canonical invocation")

    cmake = str(Path(by_label["configure"]["argv"][0]).resolve(strict=True))
    configure = by_label["configure"]["argv"]
    toolchain = depends_prefix / "toolchain.cmake"
    expected_configure = [
        cmake,
        "-S",
        str(snapshot_dir),
        "-B",
        str(build_dir),
        "-G",
        "Ninja",
        "--toolchain",
        str(toolchain),
        *profile["cmake_flags"],
    ]
    prefix_map_flags = (
        f"-ffile-prefix-map={snapshot_dir}=/pohw/source "
        f"-ffile-prefix-map={build_dir}=/pohw/build"
    )
    configure_environment = {
        "CFLAGS": prefix_map_flags,
        "CXXFLAGS": prefix_map_flags,
    }
    if "-apple-darwin" in depends["host"]:
        configure_environment["LDFLAGS"] = "-Wl,-no_uuid"
    if (
        configure != expected_configure
        or by_label["configure"]["env"] != configure_environment
    ):
        raise EvidenceError("configure command does not match the canonical invocation")
    build = by_label["build"]["argv"]
    if build[:3] != [cmake, "--build", str(build_dir)]:
        raise EvidenceError("build command does not match the canonical invocation")
    if len(build) not in (3, 5) or (len(build) == 5 and (build[3] != "-j" or not build[4].isdigit() or int(build[4]) < 1)):
        raise EvidenceError("build command has an invalid parallelism argument")
    if by_label["build"]["env"]:
        raise EvidenceError("build command has an unexpected environment override")

    test_binary = str((build_dir / "bin" / "test_bitcoin").resolve(strict=True))
    tmpdirs: set[str] = set()
    for label, test_filter in profile["test_filters"].items():
        step = by_label[label]
        if step["argv"] != [test_binary, f"--run_test={test_filter}"]:
            raise EvidenceError(f"test command does not match the required filter: {label}")
        if set(step["env"]) != {"TMPDIR"}:
            raise EvidenceError(f"test command has an invalid environment: {label}")
        tmpdir = Path(step["env"]["TMPDIR"]).resolve(strict=False)
        try:
            tmpdir.relative_to(build_dir)
        except ValueError as exc:
            raise EvidenceError("test temporary directory escapes the build directory") from exc
        tmpdirs.add(str(tmpdir))
    functional_runner = snapshot_dir / "test" / "functional" / "test_runner.py"
    resolved_functional_runner = functional_runner.resolve(strict=True)
    expected_source_runner = (
        snapshot_dir / "test" / "functional" / "test_runner.py"
    ).resolve(strict=True)
    if resolved_functional_runner != expected_source_runner:
        raise EvidenceError(
            "functional-test runner is not bound to the immutable source snapshot"
        )
    functional_config = build_dir / "test" / "config.ini"
    if functional_config.is_symlink() or not functional_config.is_file():
        raise EvidenceError("functional-test configuration is not a regular file")
    config = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        with functional_config.open("r", encoding="utf-8") as handle:
            config.read_file(handle)
        configured_source = Path(config["environment"]["SRCDIR"]).resolve()
        configured_build = Path(config["environment"]["BUILDDIR"]).resolve()
        executable_suffix = config["environment"]["EXEEXT"]
        bitcoind_enabled = config["components"].getboolean("ENABLE_BITCOIND")
    except (OSError, KeyError, ValueError, configparser.Error) as exc:
        raise EvidenceError(f"functional-test configuration is invalid: {exc}") from exc
    if configured_source != snapshot_dir or configured_build != build_dir:
        raise EvidenceError(
            "functional-test configuration is not bound to the verified source and build directories"
        )
    if executable_suffix != "":
        raise EvidenceError(
            "functional-test configuration redirects the attested executable suffix"
        )
    if not bitcoind_enabled:
        raise EvidenceError("functional-test configuration disables bitcoind")
    functional_tests_dir = snapshot_dir / "test" / "functional"
    for label, filename in profile["functional_tests"]:
        functional_step = by_label[label]
        python = Path(functional_step["argv"][0]).resolve(strict=True)
        if not python.is_file() or not os.access(python, os.X_OK):
            raise EvidenceError("functional-test Python interpreter is not executable")
        functional_tmpdir = Path(functional_step["env"].get("TMPDIR", "")).resolve(
            strict=False
        )
        functional_test = functional_tests_dir / filename
        if functional_test.is_symlink() or not functional_test.is_file():
            raise EvidenceError(f"{label} test is not a regular snapshot file")
        expected_functional = [
            str(python),
            str(functional_runner),
            filename,
            "--jobs=1",
            f"--tmpdirprefix={functional_tmpdir}",
            f"--configfile={functional_config}",
            f"--testsdir={functional_tests_dir}",
        ]
        if functional_step["argv"] != expected_functional:
            raise EvidenceError(f"{label} command is not canonical")
        if set(functional_step["env"]) != {"TMPDIR"}:
            raise EvidenceError(f"{label} environment is not canonical")
        try:
            functional_tmpdir.relative_to(build_dir)
        except ValueError as exc:
            raise EvidenceError(
                "functional-test temporary directory escapes the build directory"
            ) from exc
        tmpdirs.add(str(functional_tmpdir))
    ctest_step = by_label["ctest"]
    ctest = str(Path(ctest_step["argv"][0]).resolve(strict=True))
    if ctest_step["argv"] != [ctest, "--test-dir", str(build_dir), "--output-on-failure"]:
        raise EvidenceError("CTest command does not match the canonical invocation")
    if set(ctest_step["env"]) != {"TMPDIR"}:
        raise EvidenceError("CTest command has an invalid environment")
    tmpdirs.add(str(Path(ctest_step["env"]["TMPDIR"]).resolve(strict=False)))
    if len(tmpdirs) != 1:
        raise EvidenceError("test commands did not use one isolated temporary directory")

    install = by_label["install"]
    expected_install = [
        cmake,
        "--install",
        str(build_dir),
        "--prefix",
        str(build_dir / "pohw-release"),
        "--strip",
    ]
    if install["argv"] != expected_install or install["env"]:
        raise EvidenceError("install command does not match the canonical invocation")

    if Path(cache.get("CMAKE_HOME_DIRECTORY", "")).resolve(strict=False) != snapshot_dir:
        raise EvidenceError("CMake build directory is not bound to the immutable snapshot")
    if Path(cache.get("CMAKE_TOOLCHAIN_FILE", "")).resolve(strict=False) != toolchain:
        raise EvidenceError("CMake build directory is not bound to the sealed depends toolchain")
    for language in ("C", "CXX"):
        compiler_flags = cache.get(f"CMAKE_{language}_FLAGS", "")
        for required_flag in prefix_map_flags.split():
            if required_flag not in compiler_flags.split():
                raise EvidenceError(
                    f"CMake {language} flags do not contain the canonical path map"
                )
    linker_flags = cache.get("CMAKE_EXE_LINKER_FLAGS", "")
    if "-apple-darwin" in depends["host"] and "-Wl,-no_uuid" not in linker_flags:
        raise EvidenceError("Darwin linker flags do not disable nondeterministic UUIDs")


def validate_run_record(
    run_record_path: Path,
    snapshot_dir: Path,
    build_dir: Path,
    snapshot: dict[str, Any],
    cache: dict[str, str],
    depends: dict[str, Any],
    profile: dict[str, Any],
) -> dict[str, Any]:
    record = read_json(run_record_path)
    if set(record) != {
        "schema_version",
        "source_snapshot_sha256",
        "environment",
        "steps",
    }:
        raise EvidenceError("build run record has missing or unexpected fields")
    if record.get("schema_version") != RUN_SCHEMA:
        raise EvidenceError("unsupported build run record schema")
    if record.get("source_snapshot_sha256") != snapshot["snapshot"]["sha256"]:
        raise EvidenceError("build run record is stale for this source snapshot")
    validate_build_environment(record.get("environment"))
    raw_steps = record.get("steps")
    if not isinstance(raw_steps, list):
        raise EvidenceError("build run record steps must be an array")
    steps = [normalize_step(step, build_dir) for step in raw_steps if isinstance(step, dict)]
    if len(steps) != len(raw_steps):
        raise EvidenceError("build run record contains a non-object step")
    labels = tuple(step["label"] for step in steps)
    if labels != profile["required_steps"]:
        raise EvidenceError("build run record is incomplete, reordered, or duplicated")
    validate_commands(steps, snapshot_dir, build_dir, cache, depends, profile)
    return record


def expected_evidence(
    manifest_path: Path,
    snapshot_dir: Path,
    snapshot_metadata_path: Path,
    build_dir: Path,
    run_record_path: Path,
) -> dict[str, Any]:
    manifest = read_json(manifest_path)
    profile = manifest_profile(manifest)
    snapshot_dir = snapshot_dir.resolve(strict=True)
    build_dir = build_dir.resolve(strict=True)
    expected_metadata = build_dir / "pohw-source-snapshot.json"
    expected_record = build_dir / "pohw-build-run.json"
    if snapshot_metadata_path.resolve(strict=False) != expected_metadata:
        raise EvidenceError("source snapshot metadata must use the canonical build path")
    if run_record_path.resolve(strict=False) != expected_record:
        raise EvidenceError("build run record must use the canonical build path")
    cache = cmake_cache(build_dir)
    required_cache = {
        "CMAKE_GENERATOR": "Ninja",
        "BUILD_GUI": "OFF",
        "BUILD_TESTS": "ON",
        "BUILD_BENCH": "OFF",
        "BUILD_FUZZ_BINARY": "OFF",
        "ENABLE_IPC": "OFF",
    }
    if profile["id"] == "experiment-2":
        required_cache["POHW2_ACTIVATION_ID"] = profile["activation_id"]
    for key, expected in required_cache.items():
        actual = cache.get(key)
        if actual != expected:
            raise EvidenceError(f"CMake cache {key} must be {expected}, got {actual!r}")
    manifest_flags = list(profile["cmake_flags"])
    if profile["id"] == "experiment-1" and manifest.get("build", {}).get(
        "cmake_flags"
    ) != manifest_flags:
        raise EvidenceError("manifest CMake flags are not the canonical build flags")
    snapshot = validate_snapshot_metadata(
        snapshot_metadata_path, snapshot_dir, manifest, manifest_path
    )
    depends_source = validate_depends_source_metadata(
        build_dir / "pohw-depends-source.json", snapshot_dir, build_dir
    )
    depends = validate_depends_metadata(
        build_dir / "pohw-depends-prefix.json", build_dir
    )
    run_record = validate_run_record(
        run_record_path,
        snapshot_dir,
        build_dir,
        snapshot,
        cache,
        depends,
        profile,
    )

    artifacts: dict[str, Any] = {}
    for name in REQUIRED_ARTIFACTS:
        relative_path = RELEASE_ARTIFACT_PATHS[name]
        path = build_dir / relative_path
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"missing regular build artifact: {path}")
        artifacts[name] = {
            "path": relative_path,
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }

    steps = run_record["steps"]
    commands_by_label = {step["label"]: step for step in steps}
    cmake_path = commands_by_label["configure"]["argv"][0]
    ctest_path = commands_by_label["ctest"]["argv"][0]
    make_program = cache.get("CMAKE_MAKE_PROGRAM")
    if not make_program:
        raise EvidenceError("CMake cache does not bind Ninja")
    cxx_configuration, cxx_compiler = cmake_cxx_configuration(build_dir)
    git_path = shutil.which("git")
    if git_path is None:
        raise EvidenceError("git is not available for provenance verification")
    toolchain = {
        "make": executable_identity(
            commands_by_label["depends_fetch"]["argv"][0], "--version"
        ),
        "cmake": executable_identity(cmake_path, "--version"),
        "ctest": executable_identity(ctest_path, "--version"),
        "ninja": executable_identity(make_program, "--version"),
        "cxx": executable_identity(cxx_compiler, "--version"),
        "git": executable_identity(git_path, "--version"),
        "python": executable_identity(
            commands_by_label["replay_functional"]["argv"][0], "--version"
        ),
    }
    return {
        "schema_version": SCHEMA,
        "activation_id": profile["activation_id"],
        "manifest_sha256": sha256_file(manifest_path),
        "upstream_commit": profile["upstream_commit"],
        "patch_sha256": profile["patch_sha256"],
        "source_snapshot": snapshot,
        "build": {
            "generator": "Ninja",
            "cmake_flags": manifest_flags,
            "cmake_cache": required_cache,
            "cmake_cxx_configuration_sha256": sha256_file(cxx_configuration),
            "depends": {
                "source": depends_source,
                "source_metadata_sha256": sha256_file(
                    build_dir / "pohw-depends-source.json"
                ),
                **depends,
                "metadata_sha256": sha256_file(
                    build_dir / "pohw-depends-prefix.json"
                ),
                "toolchain_sha256": sha256_file(
                    build_dir / depends["prefix"] / "toolchain.cmake"
                ),
            },
            "environment": run_record["environment"],
            "commands": steps,
            "run_record_sha256": sha256_file(run_record_path),
            "snapshot_metadata_sha256": sha256_file(snapshot_metadata_path),
        },
        "tests": {
            "status": "passed",
            "required_steps": list(profile["test_steps"]),
        },
        "toolchain": toolchain,
        "artifacts": artifacts,
    }


def run_step(args: argparse.Namespace) -> int:
    build_dir = args.build_dir.resolve(strict=True)
    snapshot_dir = args.snapshot_dir.resolve(strict=True)
    if not LABEL_RE.fullmatch(args.label):
        raise EvidenceError("run step label is invalid")
    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv.pop(0)
    if not argv:
        raise EvidenceError("run step command is empty")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise EvidenceError("run step executable must be an absolute path")
    argv[0] = str(executable.resolve(strict=True))
    overrides: dict[str, str] = {}
    for item in args.env:
        if "=" not in item:
            raise EvidenceError(f"invalid environment override: {item}")
        key, value = item.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in overrides:
            raise EvidenceError(f"invalid or duplicate environment key: {key}")
        overrides[key] = value

    record_path = args.run_record.resolve(strict=False)
    if record_path != build_dir / "pohw-build-run.json":
        raise EvidenceError("build run record must use the canonical build path")
    if record_path.exists():
        record = read_json(record_path)
        if record.get("schema_version") != RUN_SCHEMA:
            raise EvidenceError("unsupported build run record schema")
    else:
        record = {
            "schema_version": RUN_SCHEMA,
            "source_snapshot_sha256": snapshot_details(snapshot_dir)["sha256"],
            "environment": build_environment(),
            "steps": [],
        }
    base_environment = validate_build_environment(record.get("environment"))
    overlap = sorted(BASE_ENVIRONMENT_KEYS.intersection(overrides))
    if overlap:
        raise EvidenceError(
            "build step may not override the baseline environment: " + ", ".join(overlap)
        )
    if not isinstance(record.get("steps"), list):
        raise EvidenceError("build run record steps must be an array")
    if any(step.get("label") == args.label for step in record["steps"] if isinstance(step, dict)):
        raise EvidenceError(f"build step was already recorded: {args.label}")

    log_dir = build_dir / "pohw-build-logs"
    if log_dir.is_symlink():
        raise EvidenceError("build log directory must not be a symlink")
    log_dir.mkdir(mode=0o700, exist_ok=True)
    if not log_dir.is_dir():
        raise EvidenceError("build log path is not a directory")
    log_path = log_dir / f"{args.label}.log"
    if log_path.exists() or log_path.is_symlink():
        raise EvidenceError(f"build log already exists: {log_path}")
    environment = base_environment.copy()
    environment.update(overrides)
    digest = hashlib.sha256()
    try:
        with log_path.open("xb") as log:
            process = subprocess.Popen(
                argv,
                cwd=build_dir,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            assert process.stdout is not None
            for chunk in iter(lambda: process.stdout.read(64 * 1024), b""):
                log.write(chunk)
                log.flush()
                digest.update(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            exit_code = process.wait()
    except OSError as exc:
        raise EvidenceError(f"cannot execute build step {args.label}: {exc}") from exc
    record["steps"].append(
        {
            "label": args.label,
            "argv": argv,
            "env": overrides,
            "exit_code": exit_code,
            "log_path": f"pohw-build-logs/{args.label}.log",
            "output_sha256": digest.hexdigest(),
        }
    )
    write_json(record_path, record)
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    metadata = subparsers.add_parser("snapshot-metadata")
    metadata.add_argument("--snapshot-dir", required=True, type=Path)
    metadata.add_argument("--metadata", required=True, type=Path)
    metadata.add_argument("--tree-oid", required=True)
    metadata.add_argument("--upstream-commit", required=True)
    metadata.add_argument("--patch-sha256", required=True)
    metadata.add_argument("--manifest-sha256", required=True)

    prepare = subparsers.add_parser("depends-prepare")
    prepare.add_argument("--source", required=True, type=Path)
    prepare.add_argument("--destination", required=True, type=Path)
    prepare.add_argument("--metadata", required=True, type=Path)

    depends = subparsers.add_parser("depends-metadata")
    depends.add_argument("--prefix", required=True, type=Path)
    depends.add_argument("--metadata", required=True, type=Path)
    depends.add_argument("--host", required=True)

    runner = subparsers.add_parser("run-step")
    runner.add_argument("--snapshot-dir", required=True, type=Path)
    runner.add_argument("--build-dir", required=True, type=Path)
    runner.add_argument("--run-record", required=True, type=Path)
    runner.add_argument("--label", required=True)
    runner.add_argument("--env", action="append", default=[])
    runner.add_argument("argv", nargs=argparse.REMAINDER)

    for command in ("write", "verify"):
        evidence = subparsers.add_parser(command)
        evidence.add_argument("--manifest", required=True, type=Path)
        evidence.add_argument("--snapshot-dir", required=True, type=Path)
        evidence.add_argument("--snapshot-metadata", required=True, type=Path)
        evidence.add_argument("--build-dir", required=True, type=Path)
        evidence.add_argument("--run-record", required=True, type=Path)
        evidence.add_argument("--evidence", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "snapshot-metadata":
            if not HEX_TREE_RE.fullmatch(args.tree_oid):
                raise EvidenceError("patched tree id must be a lowercase hexadecimal object id")
            if not re.fullmatch(r"[0-9a-f]{40}", args.upstream_commit):
                raise EvidenceError("upstream commit must be lowercase 40-character hex")
            if not HEX_SHA256_RE.fullmatch(args.patch_sha256):
                raise EvidenceError("patch digest must be lowercase SHA-256")
            if not HEX_SHA256_RE.fullmatch(args.manifest_sha256):
                raise EvidenceError("manifest digest must be lowercase SHA-256")
            value = {
                "schema_version": SNAPSHOT_SCHEMA,
                "upstream_commit": args.upstream_commit,
                "patch_sha256": args.patch_sha256,
                "manifest_sha256": args.manifest_sha256,
                "patched_tree_oid": args.tree_oid,
                "snapshot": snapshot_details(args.snapshot_dir),
            }
            write_json(args.metadata, value)
            print(args.metadata)
            return 0
        if args.command == "depends-prepare":
            source = args.source.resolve(strict=True)
            destination = args.destination.resolve(strict=False)
            if source.name != "depends":
                raise EvidenceError("depends source must be the snapshot depends tree")
            if destination.name != "source" or destination.parent.name != "pohw-depends":
                raise EvidenceError("depends source destination must use the canonical build path")
            build_dir = destination.parent.parent
            expected_metadata = build_dir / "pohw-depends-source.json"
            if args.metadata.resolve(strict=False) != expected_metadata:
                raise EvidenceError("depends source metadata must use the canonical build path")
            if args.metadata.exists() or args.metadata.is_symlink():
                raise EvidenceError("depends source metadata output must be new")
            tree = copy_verified_tree(source, destination)
            value = {
                "schema_version": DEPENDS_SOURCE_SCHEMA,
                "source": "depends",
                "destination": "pohw-depends/source",
                "tree": tree,
            }
            write_json(args.metadata, value)
            print(args.metadata)
            return 0
        if args.command == "depends-metadata":
            if HOST_TRIPLET_RE.fullmatch(args.host) is None:
                raise EvidenceError("depends host must be a canonical triplet")
            prefix = args.prefix.resolve(strict=True)
            if (
                prefix.name != args.host
                or prefix.parent.name != "source"
                or prefix.parent.parent.name != "pohw-depends"
            ):
                raise EvidenceError("depends prefix must use the canonical build path")
            build_dir = prefix.parents[2]
            expected_metadata = build_dir / "pohw-depends-prefix.json"
            if args.metadata.resolve(strict=False) != expected_metadata:
                raise EvidenceError("depends metadata must use the canonical build path")
            if args.metadata.exists() or args.metadata.is_symlink():
                raise EvidenceError("depends metadata output must be new")
            seal_tree(prefix)
            value = {
                "schema_version": DEPENDS_SCHEMA,
                "host": args.host,
                "prefix": f"pohw-depends/source/{args.host}",
                "tree": snapshot_details(prefix),
            }
            write_json(args.metadata, value)
            print(args.metadata)
            return 0
        if args.command == "run-step":
            return run_step(args)

        evidence_path = args.evidence or args.build_dir / "pohw-build-evidence.json"
        expected = expected_evidence(
            args.manifest,
            args.snapshot_dir,
            args.snapshot_metadata,
            args.build_dir,
            args.run_record,
        )
        if args.command == "write":
            write_json(evidence_path, expected)
            print(evidence_path)
        else:
            actual = read_json(evidence_path)
            if actual != expected:
                raise EvidenceError(
                    "build evidence does not match source snapshot, commands, tests, "
                    "toolchain, or artifacts"
                )
            print("PoHW Bitcoin Core build evidence verified")
    except EvidenceError as exc:
        print(f"evidence error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
