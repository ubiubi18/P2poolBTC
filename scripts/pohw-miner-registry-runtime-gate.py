#!/usr/bin/env python3
"""Exercise the exact miner-registry WASM in idena-go's production runtime."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TEST_BYTES = 1024 * 1024
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TARGET = "vm/wasm/pohw_miner_registry_contract_integration_test.go"
TEST_NAME = "TestPohwMinerRegistryProductionRuntimeIdentityGate"
RAW_CODEC = 0x55
SHA2_256 = 0x12


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def encode_varint(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def raw_cid(digest_hex: str) -> str:
    raw = (
        encode_varint(1)
        + encode_varint(RAW_CODEC)
        + encode_varint(SHA2_256)
        + encode_varint(32)
        + bytes.fromhex(digest_hex)
    )
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "JSON document contains a duplicate object key")
        result[key] = value
    return result


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GateError(f"cannot inspect {label}: {path}") from exc
    require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular non-symlink file")
    require(metadata.st_size <= maximum, f"{label} exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GateError(f"cannot safely open {label}: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino),
            f"{label} changed before opening",
        )
        chunks: list[bytes] = []
        length = 0
        while length <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        payload = b"".join(chunks)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    require(len(payload) <= maximum, f"{label} exceeds the size limit")
    require(len(payload) == finished.st_size, f"{label} changed while reading")
    require(
        (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
        f"{label} changed while reading",
    )
    return payload


def run_output(command: list[str], cwd: Path, environment: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise GateError(f"command failed: {' '.join(command)}: {detail.strip()}") from exc
    return result.stdout.strip()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            read_regular(path, 4 * 1024 * 1024, "JSON document"),
            object_pairs_hook=reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("compatibility lock is not valid JSON") from exc
    require(isinstance(payload, dict), "compatibility lock must be an object")
    return payload


def resolve_repo_path(root: Path, value: Any, label: str) -> Path:
    require(isinstance(value, str) and value, f"invalid {label} path")
    relative = PurePosixPath(value)
    require(not relative.is_absolute(), f"{label} path must be relative")
    require(all(part not in ("", ".", "..") for part in relative.parts), f"unsafe {label} path")
    candidate = (root / Path(*relative.parts)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise GateError(f"{label} path escapes the repository") from exc
    return candidate


def verify_candidate(
    root: Path,
    candidate_path: Path,
    contract: Path,
    lock: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    candidate_bytes = read_regular(candidate_path, 4 * 1024 * 1024, "registry candidate")
    try:
        candidate = json.loads(candidate_bytes, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("registry candidate is not valid JSON") from exc
    require(isinstance(candidate, dict), "registry candidate must be an object")
    require(candidate.get("schema_version") == "pohw-miner-registry-candidate/v1", "unsupported registry candidate schema")
    require(candidate.get("status") == "reviewed-local-candidate-not-deployed", "registry candidate status is unsafe")
    require(candidate.get("experiment_id") == "p2poolbtc-experiment-1", "registry candidate experiment mismatch")
    require(candidate.get("contract_schema_version") == 3, "registry contract schema mismatch")
    require(candidate.get("contract_version") == "0.3.0", "registry contract version mismatch")
    require(
        candidate.get("eligible_identity_states") == ["Newbie", "Verified", "Human"],
        "registry candidate eligibility set mismatch",
    )
    require(candidate.get("deployment") is None, "local registry candidate must not claim a deployment")

    sources = candidate.get("source_files")
    require(isinstance(sources, list) and sources, "registry candidate has no source files")
    source_paths = [item.get("path") for item in sources if isinstance(item, dict)]
    require(len(source_paths) == len(sources), "registry candidate source entry is malformed")
    require(source_paths == sorted(source_paths), "registry candidate source paths must be sorted")
    require(len(set(source_paths)) == len(source_paths), "registry candidate source path is duplicated")
    for item in sources:
        path = resolve_repo_path(root, item.get("path"), "source file")
        payload = read_regular(path, MAX_ARTIFACT_BYTES, "source file")
        expected = item.get("sha256")
        require(isinstance(expected, str) and len(expected) == 64, "invalid source SHA-256")
        require(hashlib.sha256(payload).hexdigest() == expected, f"source digest mismatch: {item['path']}")

    package_path = root / "contracts/idena-pohw-miner-registry/package.json"
    try:
        package = json.loads(read_regular(package_path, 1024 * 1024, "contract package"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("contract package is not valid JSON") from exc
    require(package.get("version") == candidate.get("contract_version"), "package and contract versions differ")
    require(package.get("packageManager") == "pnpm@11.11.0", "contract package manager is not pinned")

    artifact = candidate.get("artifact")
    require(isinstance(artifact, dict), "registry candidate has no artifact")
    artifact_path = resolve_repo_path(root, artifact.get("path"), "contract artifact")
    require(artifact_path == contract, "--contract does not match the registry candidate artifact")
    artifact_payload = read_regular(artifact_path, MAX_ARTIFACT_BYTES, "contract artifact")
    artifact_digest = hashlib.sha256(artifact_payload).hexdigest()
    require(len(artifact_payload) == artifact.get("size"), "registry artifact size mismatch")
    require(artifact_digest == artifact.get("sha256"), "registry artifact SHA-256 mismatch")
    require(raw_cid(artifact_digest) == artifact.get("cid"), "registry artifact CID mismatch")

    runtime_test = candidate.get("runtime_test")
    require(isinstance(runtime_test, dict), "registry candidate has no runtime test")
    require(runtime_test.get("target_path") == TARGET, "registry runtime-test target mismatch")
    require(runtime_test.get("test_name") == TEST_NAME, "registry runtime-test name mismatch")
    runtime_path = resolve_repo_path(root, runtime_test.get("path"), "runtime test")
    runtime_payload = read_regular(runtime_path, MAX_TEST_BYTES, "runtime test")
    runtime_digest = hashlib.sha256(runtime_payload).hexdigest()
    require(len(runtime_payload) == runtime_test.get("size"), "registry runtime-test size mismatch")
    require(runtime_digest == runtime_test.get("sha256"), "registry runtime-test SHA-256 mismatch")
    require(raw_cid(runtime_digest) == runtime_test.get("cid"), "registry runtime-test CID mismatch")

    binding = candidate.get("runtime_binding")
    require(isinstance(binding, dict), "registry candidate has no runtime binding")
    locked_idena_go = locked_component(lock, "idena-go").get("commit")
    locked_binding = locked_component(lock, "idena-wasm-binding").get("commit")
    require(binding.get("idena_go_commit") == locked_idena_go, "registry idena-go commit mismatch")
    require(binding.get("idena_wasm_binding_commit") == locked_binding, "registry runtime binding commit mismatch")
    require(binding.get("go") == lock.get("toolchains", {}).get("go"), "registry Go toolchain mismatch")
    require(binding.get("node") == "24.18.0", "registry Node.js toolchain mismatch")
    require(binding.get("pnpm") == "11.11.0", "registry pnpm toolchain mismatch")
    require(binding.get("assemblyscript") == "0.27.37", "registry AssemblyScript toolchain mismatch")

    release_gates = candidate.get("release_gates")
    require(isinstance(release_gates, dict), "registry candidate has no release gates")
    require(release_gates.get("independent_matching_builders_required") >= 2, "registry builder threshold is unsafe")
    require(release_gates.get("independent_matching_builders_observed") == 1, "local candidate must report one builder")
    require(release_gates.get("external_security_review_complete") is False, "local candidate must not claim external review")
    require(release_gates.get("deployment_receipt_verified") is False, "local candidate must not claim deployment verification")
    return candidate, hashlib.sha256(candidate_bytes).hexdigest()


def locked_component(lock: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        item
        for item in lock.get("components", [])
        if isinstance(item, dict) and item.get("name") == name
    ]
    require(len(matches) == 1, f"compatibility lock must contain exactly one {name} component")
    return matches[0]


def verify_runtime_binding(idena_go: Path, expected_commit: str) -> str:
    raw = run_output(
        ["go", "list", "-mod=readonly", "-m", "-json", "github.com/idena-network/idena-wasm-binding"],
        idena_go,
    )
    try:
        module = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GateError("go list returned invalid module JSON") from exc
    resolved = module.get("Replace") or module
    version = resolved.get("Version") if isinstance(resolved, dict) else None
    require(isinstance(version, str), "resolved idena-wasm-binding has no exact module version")
    require(
        version.endswith("-" + expected_commit[:12]),
        "resolved idena-wasm-binding does not match compatibility/stack-lock.json",
    )
    return version


def verify_exact_clean_checkout(worktree: Path, expected_commit: str) -> str:
    require(COMMIT_RE.fullmatch(expected_commit) is not None, "invalid expected idena-go commit")
    inside = run_output(["git", "rev-parse", "--is-inside-work-tree"], worktree)
    require(inside == "true", "--idena-go is not a Git worktree")
    actual_commit = run_output(["git", "rev-parse", "HEAD"], worktree)
    require(actual_commit == expected_commit, "idena-go checkout does not match the compatibility lock")
    status = run_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], worktree
    )
    require(not status, "idena-go checkout is dirty")
    return actual_commit


def clean_environment(temporary: Path, module_cache: str, go_toolchain: str) -> dict[str, str]:
    allowed = (
        "PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SDKROOT",
        "DEVELOPER_DIR",
        "MACOSX_DEPLOYMENT_TARGET",
        "CGO_ENABLED",
        "CC",
        "CXX",
        "AR",
        "PKG_CONFIG_PATH",
    )
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    home = temporary / "home"
    cache = temporary / "go-build-cache"
    home.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    environment.update(
        {
            "HOME": str(home),
            "GOCACHE": str(cache),
            "GOMODCACHE": module_cache,
            "GOPROXY": "off",
            "GOSUMDB": "sum.golang.org",
            "GOTOOLCHAIN": "go" + go_toolchain,
        }
    )
    return environment


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idena-go", required=True, type=Path)
    parser.add_argument(
        "--contract",
        type=Path,
        default=root / "contracts/idena-pohw-miner-registry/build/idena-pohw-miner-registry.wasm",
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=root / "compatibility/stack-lock.json",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        default=root / "compatibility/experiment-1-miner-registry-candidate.json",
    )
    args = parser.parse_args()

    idena_go = args.idena_go.expanduser().resolve()
    contract = args.contract.expanduser().resolve()
    lock = load_lock(args.lock.expanduser().resolve())
    require((idena_go / "go.mod").is_file(), "--idena-go is not an idena-go worktree")
    candidate, candidate_sha256 = verify_candidate(
        root,
        args.candidate.expanduser().resolve(),
        contract,
        lock,
    )
    idena_go_commit = candidate["runtime_binding"]["idena_go_commit"]
    verify_exact_clean_checkout(idena_go, idena_go_commit)
    test_source = resolve_repo_path(root, candidate["runtime_test"]["path"], "runtime test")
    test_payload = read_regular(test_source, MAX_TEST_BYTES, "runtime integration test")
    contract_payload = read_regular(contract, MAX_ARTIFACT_BYTES, "miner-registry WASM")
    contract_sha256 = hashlib.sha256(contract_payload).hexdigest()
    test_sha256 = hashlib.sha256(test_payload).hexdigest()

    binding_commit = locked_component(lock, "idena-wasm-binding").get("commit")
    require(
        isinstance(binding_commit, str) and COMMIT_RE.fullmatch(binding_commit) is not None,
        "compatibility lock has an invalid idena-wasm-binding commit",
    )
    binding_version = verify_runtime_binding(idena_go, binding_commit)
    expected_go = str(lock.get("toolchains", {}).get("go", ""))
    require(expected_go, "compatibility lock has no Go toolchain")
    actual_go = run_output(["go", "env", "GOVERSION"], idena_go)
    require(actual_go == "go" + expected_go, f"Go toolchain mismatch: expected go{expected_go}, found {actual_go}")
    module_cache = run_output(["go", "env", "GOMODCACHE"], idena_go)
    require(module_cache, "Go module cache is empty")

    target = (idena_go / TARGET).resolve()
    require(not target.exists(), f"runtime overlay would shadow an existing file: {target}")
    with tempfile.TemporaryDirectory(prefix="pohw-registry-runtime-") as raw_temporary:
        temporary = Path(raw_temporary)
        staged = temporary / "miner_registry_contract_integration_test.go"
        staged.write_bytes(test_payload)
        staged.chmod(0o400)
        overlay = temporary / "overlay.json"
        overlay.write_text(
            json.dumps({"Replace": {str(target): str(staged)}}, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        overlay.chmod(0o600)
        environment = clean_environment(temporary, module_cache, expected_go)
        environment["IDENA_POHW_MINER_REGISTRY_WASM"] = str(contract)
        environment["IDENA_POHW_MINER_REGISTRY_WASM_SHA256"] = contract_sha256
        command = [
            "go",
            "test",
            "-mod=readonly",
            "-overlay=" + str(overlay),
            "./vm/wasm",
            "-run",
            "^" + TEST_NAME + "$",
            "-count=1",
            "-v",
        ]
        output = run_output(command, idena_go, environment)
        require("--- PASS: " + TEST_NAME in output, "production runtime test did not report a pass")

    print(
        json.dumps(
            {
                "bindingVersion": binding_version,
                "candidateSha256": candidate_sha256,
                "contractSha256": contract_sha256,
                "goVersion": actual_go,
                "idenaGoCommit": idena_go_commit,
                "runtimeTestSha256": test_sha256,
                "status": "passed",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
