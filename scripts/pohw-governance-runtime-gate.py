#!/usr/bin/env python3
"""Run the governance contract against idena-go's production WASM runtime.

The default mode validates the exact contract artifact and resolved native WASM
binding before running the production VM integration test. Release evidence
must additionally use --require-locked-sources, which rejects dirty or
revision-mismatched source repositories and uncommitted prototype locks.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RAW_CODEC = 0x55
SHA2_256_CODE = 0x12
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_CONTRACT_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_TEST_BYTES = 1024 * 1024
RUNTIME_TEST_TARGET = "vm/wasm/pohw_governance_contract_runtime_gate_test.go"
RUNTIME_TEST_NAME = "TestGovernanceContractProductionRuntimeDeterminism"


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
        + encode_varint(SHA2_256_CODE)
        + encode_varint(32)
        + bytes.fromhex(digest_hex)
    )
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "governance fork lock contains a duplicate object key")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode), "governance fork lock must be a regular non-symlink file")
        require(metadata.st_size <= MAX_LOCK_BYTES, "governance fork lock exceeds the size limit")
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
        )
    except GateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read valid JSON lock: {path}") from exc
    require(isinstance(payload, dict), "governance fork lock must be an object")
    return payload


def read_regular_file(path: Path, maximum: int, label: str) -> bytes:
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
        require(stat.S_ISREG(opened.st_mode), f"{label} must be a regular file")
        require(
            (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino),
            f"{label} changed before opening",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    require(len(payload) <= maximum, f"{label} exceeds the size limit")
    require(
        (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
        f"{label} changed while reading",
    )
    require(len(payload) == finished.st_size, f"{label} changed while reading")
    return payload


def hash_regular_file(path: Path) -> tuple[str, int]:
    payload = read_regular_file(path, MAX_CONTRACT_BYTES, "artifact")
    digest = hashlib.sha256()
    digest.update(payload)
    return digest.hexdigest(), len(payload)


def verify_artifact_descriptor(
    contract: Path,
    artifact: Any,
    lock_label: str = "governance lock",
) -> tuple[str, int, str]:
    require(isinstance(artifact, dict), f"{lock_label} is missing the governance contract artifact")
    expected_sha256 = artifact.get("sha256")
    expected_size = artifact.get("size")
    expected_cid = artifact.get("cid")
    require(
        isinstance(expected_sha256, str) and SHA256_RE.fullmatch(expected_sha256) is not None,
        "invalid locked contract SHA-256",
    )
    require(isinstance(expected_size, int) and expected_size > 0, "invalid locked contract size")
    require(isinstance(expected_cid, str), "invalid locked contract CID")
    actual_sha256, actual_size = hash_regular_file(contract)
    require(actual_sha256 == expected_sha256, f"contract SHA-256 does not match the {lock_label}")
    require(actual_size == expected_size, f"contract size does not match the {lock_label}")
    require(raw_cid(actual_sha256) == expected_cid, f"contract raw CID does not match the {lock_label}")
    return expected_sha256, expected_size, expected_cid


def verify_contract_artifact(contract: Path, lock: dict[str, Any]) -> tuple[str, int, str]:
    prototype = lock.get("governancePrototype")
    require(isinstance(prototype, dict), "lock is missing governancePrototype")
    return verify_artifact_descriptor(contract, prototype.get("contractArtifact"))


def resolve_locked_relative_file(root: Path, value: Any, label: str) -> Path:
    require(isinstance(value, str) and value, f"invalid locked {label} path")
    relative = PurePosixPath(value)
    require(not relative.is_absolute(), f"locked {label} path must be relative")
    require(
        all(part not in ("", ".", "..") for part in relative.parts),
        f"locked {label} path is unsafe",
    )
    candidate = (root / Path(*relative.parts)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise GateError(f"locked {label} path escapes the repository") from exc
    return candidate


def verify_runtime_test_overlay(root: Path, lock: dict[str, Any]) -> tuple[Path, bytes, str, str]:
    prototype = lock.get("governancePrototype")
    require(isinstance(prototype, dict), "lock is missing governancePrototype")
    overlay = prototype.get("runtimeIntegrationTestOverlay")
    require(isinstance(overlay, dict), "lock is missing the production-runtime test overlay")
    require(
        set(overlay) == {"path", "targetPath", "testName", "size", "cid", "sha256"},
        "production-runtime test overlay has unknown or missing fields",
    )
    target = overlay.get("targetPath")
    test_name = overlay.get("testName")
    expected_size = overlay.get("size")
    expected_sha256 = overlay.get("sha256")
    expected_cid = overlay.get("cid")
    require(target == RUNTIME_TEST_TARGET, "production-runtime test overlay target is invalid")
    require(test_name == RUNTIME_TEST_NAME, "production-runtime test name is invalid")
    require(
        isinstance(expected_size, int) and 0 < expected_size <= MAX_RUNTIME_TEST_BYTES,
        "invalid production-runtime test size",
    )
    require(
        isinstance(expected_sha256, str) and SHA256_RE.fullmatch(expected_sha256) is not None,
        "invalid production-runtime test SHA-256",
    )
    require(isinstance(expected_cid, str), "invalid production-runtime test CID")
    source = resolve_locked_relative_file(root, overlay.get("path"), "production-runtime test")
    payload = read_regular_file(source, MAX_RUNTIME_TEST_BYTES, "production-runtime test")
    actual_size = len(payload)
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    require(actual_size == expected_size, "production-runtime test size does not match the governance lock")
    require(actual_sha256 == expected_sha256, "production-runtime test SHA-256 does not match the governance lock")
    require(raw_cid(actual_sha256) == expected_cid, "production-runtime test CID does not match the governance lock")
    return source, payload, target, test_name


def run_output(command: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise GateError(f"command failed: {' '.join(command)}: {detail.strip()}") from exc
    return result.stdout.strip()


def git_state(repository: Path) -> tuple[str, bool]:
    require((repository / ".git").exists(), f"not a Git worktree: {repository}")
    head = run_output(["git", "rev-parse", "HEAD"], repository)
    dirty = bool(run_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], repository))
    require(COMMIT_RE.fullmatch(head) is not None, f"invalid Git HEAD in {repository}")
    return head, dirty


def parse_component_repositories(values: list[str]) -> dict[str, Path]:
    repositories: dict[str, Path] = {}
    for value in values:
        require("=" in value, "--component-repo must use NAME=PATH")
        name, raw_path = value.split("=", 1)
        require(name and name not in repositories, f"invalid or duplicate component repository: {name}")
        repositories[name] = Path(raw_path).expanduser().resolve()
    return repositories


def verify_locked_sources(
    root: Path,
    lock: dict[str, Any],
    idena_go: Path,
    supplied: dict[str, Path],
) -> None:
    prototype = lock.get("governancePrototype")
    require(isinstance(prototype, dict), "lock is missing governancePrototype")
    require(
        prototype.get("sourceStatus") == "canonical-locked-source",
        "governance source is not a canonical locked source",
    )
    p2pool_commit = prototype.get("baseCommit")
    require(isinstance(p2pool_commit, str) and COMMIT_RE.fullmatch(p2pool_commit) is not None, "invalid P2poolBTC base commit")
    p2pool_head, p2pool_dirty = git_state(root)
    require(p2pool_head == p2pool_commit, "P2poolBTC HEAD does not match the governance lock")
    require(not p2pool_dirty, "P2poolBTC worktree is dirty")

    repositories = dict(supplied)
    repositories["idena-go"] = idena_go
    components = lock.get("components")
    require(isinstance(components, list) and components, "lock has no components")
    expected_names = {component.get("name") for component in components if isinstance(component, dict)}
    require(None not in expected_names, "lock contains an unnamed component")
    missing = sorted(expected_names - repositories.keys())
    require(not missing, "missing --component-repo paths for: " + ", ".join(missing))
    extra = sorted(repositories.keys() - expected_names)
    require(not extra, "unexpected --component-repo names: " + ", ".join(extra))

    for component in components:
        name = component["name"]
        expected_commit = component.get("commit")
        require(isinstance(expected_commit, str) and COMMIT_RE.fullmatch(expected_commit) is not None, f"invalid locked commit for {name}")
        head, dirty = git_state(repositories[name])
        require(head == expected_commit, f"{name} HEAD does not match the governance lock")
        require(not dirty, f"{name} worktree is dirty")


def verify_resolved_runtime_binding(idena_go: Path, expected_commit: str) -> str:
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
    require(version.endswith("-" + expected_commit[:12]), "resolved idena-wasm-binding does not match the governance lock")
    return version


def runtime_test_environment(temporary: Path, module_cache: str, go_toolchain: str) -> dict[str, str]:
    allowed = (
        "PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
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
            "GOPROXY": "https://proxy.golang.org,direct",
            "GOSUMDB": "sum.golang.org",
            "GOTOOLCHAIN": go_toolchain,
        }
    )
    return environment


def run_runtime_test(
    idena_go: Path,
    source: bytes,
    target: str,
    test_name: str,
    contract: Path,
    contract_sha256: str,
    go_toolchain: str,
) -> None:
    target_path = (idena_go / Path(*PurePosixPath(target).parts)).resolve()
    try:
        target_path.relative_to(idena_go.resolve())
    except ValueError as exc:
        raise GateError("production-runtime test target escapes idena-go") from exc
    require(not target_path.exists(), "production-runtime test overlay would shadow pinned idena-go source")
    module_cache = run_output(["go", "env", "GOMODCACHE"], idena_go)
    require(bool(module_cache), "Go module cache path is empty")
    with tempfile.TemporaryDirectory(prefix="pohw-governance-runtime-") as raw_temporary:
        temporary = Path(raw_temporary)
        staged_source = temporary / "governance_contract_integration_test.go"
        staged_source.write_bytes(source)
        staged_source.chmod(0o400)
        overlay_path = temporary / "overlay.json"
        overlay_path.write_text(
            json.dumps(
                {"Replace": {str(target_path): str(staged_source)}},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        overlay_path.chmod(0o600)
        environment = runtime_test_environment(temporary, module_cache, go_toolchain)
        environment["IDENA_GOVERNANCE_WASM"] = str(contract)
        environment["IDENA_GOVERNANCE_WASM_SHA256"] = contract_sha256
        command = [
            "go",
            "test",
            "-mod=readonly",
            "-overlay=" + str(overlay_path),
            "./vm/wasm",
            "-run",
            "^" + test_name + "$",
            "-count=1",
            "-v",
        ]
        try:
            subprocess.run(command, cwd=idena_go, env=environment, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise GateError("production idena-go WASM runtime gate failed") from exc


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idena-go", type=Path, help="Path to the idena-go worktree")
    parser.add_argument(
        "--contract",
        type=Path,
        default=root / "contracts/idena-code-governance/build/idena-code-governance.wasm",
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=root / "compatibility/governance-fork-lock.json",
    )
    parser.add_argument(
        "--component-repo",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Exact component worktree; required for every non-idena-go component in locked mode",
    )
    parser.add_argument(
        "--require-locked-sources",
        action="store_true",
        help="Fail unless P2poolBTC and every component are clean and at exact locked revisions",
    )
    parser.add_argument(
        "--verify-artifact-only",
        action="store_true",
        help="Verify the built contract against the lock without requiring an idena-go checkout",
    )
    args = parser.parse_args()

    contract = args.contract.expanduser().resolve()
    lock_path = args.lock.expanduser().resolve()
    lock = load_json(lock_path)
    expected_sha256, expected_size, expected_cid = verify_contract_artifact(contract, lock)
    _, runtime_test_source, runtime_test_target, runtime_test_name = verify_runtime_test_overlay(root, lock)

    if args.verify_artifact_only:
        require(not args.require_locked_sources, "artifact-only mode cannot require locked source worktrees")
        print(
            json.dumps(
                {
                    "contractCid": expected_cid,
                    "contractSha256": expected_sha256,
                    "contractSize": expected_size,
                    "runtimeTestCid": lock["governancePrototype"]["runtimeIntegrationTestOverlay"]["cid"],
                    "status": "passed",
                },
                sort_keys=True,
            )
        )
        return 0

    require(args.idena_go is not None, "--idena-go is required unless --verify-artifact-only is used")
    idena_go = args.idena_go.expanduser().resolve()
    require((idena_go / "go.mod").is_file(), f"idena-go worktree is invalid: {idena_go}")

    components = {
        component.get("name"): component
        for component in lock.get("components", [])
        if isinstance(component, dict)
    }
    binding = components.get("idena-wasm-binding")
    require(isinstance(binding, dict), "lock is missing idena-wasm-binding")
    binding_commit = binding.get("commit")
    require(isinstance(binding_commit, str) and COMMIT_RE.fullmatch(binding_commit) is not None, "invalid locked binding commit")
    binding_version = verify_resolved_runtime_binding(idena_go, binding_commit)

    if args.require_locked_sources:
        supplied = parse_component_repositories(args.component_repo)
        verify_locked_sources(root, lock, idena_go, supplied)

    go_version = run_output(["go", "env", "GOVERSION"], idena_go)
    expected_go = lock.get("toolchains", {}).get("go")
    require(go_version == "go" + str(expected_go), f"Go toolchain mismatch: expected go{expected_go}, found {go_version}")

    run_runtime_test(
        idena_go,
        runtime_test_source,
        runtime_test_target,
        runtime_test_name,
        contract,
        expected_sha256,
        go_version,
    )

    print(
        json.dumps(
            {
                "contractCid": expected_cid,
                "contractSha256": expected_sha256,
                "contractSize": expected_size,
                "goToolchain": go_version,
                "lockedSourcesRequired": args.require_locked_sources,
                "resolvedWasmBinding": binding_version,
                "runtimeTestCid": lock["governancePrototype"]["runtimeIntegrationTestOverlay"]["cid"],
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
        print(f"governance runtime gate: {exc}", file=sys.stderr)
        raise SystemExit(2)
