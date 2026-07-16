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
import platform
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
DAG_CBOR_CODEC = 0x71
SHA2_256_CODE = 0x12
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_CONTRACT_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_TEST_BYTES = 1024 * 1024
MAX_CANDIDATE_PATCH_BYTES = 2 * 1024 * 1024
MAX_NATIVE_ARCHIVE_BYTES = 128 * 1024 * 1024
RUNTIME_TEST_TARGET = "vm/wasm/pohw_governance_contract_runtime_gate_test.go"
RUNTIME_TEST_NAME = "TestGovernanceContractProductionRuntimeDeterminism"
CANDIDATE_NETWORK_ID = 10002
FEATURE_EPOCH_BLOCK = 1
GO_API_V2_ABI_VERSION = 2
GO_API_V2_SIZE_64 = 280
LEGACY_GO_API_VTABLE_CALLBACKS = 31


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


def dag_cbor_cid(digest_hex: str) -> str:
    raw = (
        encode_varint(1)
        + encode_varint(DAG_CBOR_CODEC)
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


def verify_locked_file(
    root: Path,
    descriptor: dict[str, Any],
    *,
    path_key: str,
    size_key: str,
    sha256_key: str,
    cid_key: str,
    maximum: int,
    label: str,
) -> tuple[Path, bytes]:
    path = resolve_locked_relative_file(root, descriptor.get(path_key), label)
    payload = read_regular_file(path, maximum, label)
    expected_size = descriptor.get(size_key)
    expected_sha256 = descriptor.get(sha256_key)
    expected_cid = descriptor.get(cid_key)
    require(isinstance(expected_size, int) and 0 < expected_size <= maximum, f"invalid {label} size")
    require(
        isinstance(expected_sha256, str) and SHA256_RE.fullmatch(expected_sha256) is not None,
        f"invalid {label} SHA-256",
    )
    require(isinstance(expected_cid, str), f"invalid {label} CID")
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    require(len(payload) == expected_size, f"{label} size does not match the candidate lock")
    require(actual_sha256 == expected_sha256, f"{label} SHA-256 does not match the candidate lock")
    require(raw_cid(actual_sha256) == expected_cid, f"{label} CID does not match the candidate lock")
    return path, payload


def verify_candidate_runtime_test_overlay(
    root: Path, candidate: dict[str, Any]
) -> tuple[bytes, str, str, str]:
    descriptor = candidate.get("runtimeIntegrationTestOverlay")
    expected_keys = {
        "basePath",
        "baseCid",
        "baseSha256",
        "baseSize",
        "patchPath",
        "patchCid",
        "patchSha256",
        "patchSize",
        "targetPath",
        "testName",
        "resultCid",
        "resultSha256",
        "resultSize",
    }
    require(isinstance(descriptor, dict), "fork candidate is missing the runtime test overlay")
    require(set(descriptor) == expected_keys, "fork candidate runtime test overlay has unknown or missing fields")
    target = descriptor.get("targetPath")
    test_name = descriptor.get("testName")
    require(target == RUNTIME_TEST_TARGET, "fork candidate runtime test target is invalid")
    require(test_name == RUNTIME_TEST_NAME, "fork candidate runtime test name is invalid")
    _, base = verify_locked_file(
        root,
        descriptor,
        path_key="basePath",
        size_key="baseSize",
        sha256_key="baseSha256",
        cid_key="baseCid",
        maximum=MAX_RUNTIME_TEST_BYTES,
        label="fork candidate runtime test base",
    )
    patch_path, _ = verify_locked_file(
        root,
        descriptor,
        path_key="patchPath",
        size_key="patchSize",
        sha256_key="patchSha256",
        cid_key="patchCid",
        maximum=MAX_CANDIDATE_PATCH_BYTES,
        label="fork candidate runtime test patch",
    )
    with tempfile.TemporaryDirectory(prefix="pohw-governance-runtime-overlay-") as temporary:
        temporary_root = Path(temporary)
        staged = temporary_root / Path(*PurePosixPath(descriptor["basePath"]).parts)
        staged.parent.mkdir(parents=True)
        staged.write_bytes(base)
        for check_flag in ("--check", None):
            command = ["git", "apply"]
            if check_flag is not None:
                command.append(check_flag)
            command.append(str(patch_path))
            try:
                subprocess.run(
                    command,
                    cwd=temporary_root,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except (OSError, subprocess.CalledProcessError) as exc:
                raise GateError("cannot reconstruct the fork candidate runtime test") from exc
        result = read_regular_file(staged, MAX_RUNTIME_TEST_BYTES, "fork candidate runtime test result")
    result_sha256 = hashlib.sha256(result).hexdigest()
    require(len(result) == descriptor.get("resultSize"), "fork candidate runtime result size mismatch")
    require(result_sha256 == descriptor.get("resultSha256"), "fork candidate runtime result SHA-256 mismatch")
    require(raw_cid(result_sha256) == descriptor.get("resultCid"), "fork candidate runtime result CID mismatch")
    return result, target, test_name, descriptor["resultCid"]


def run_output(
    command: list[str], cwd: Path, environment: dict[str, str] | None = None
) -> str:
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


def run_bytes(command: list[str], cwd: Path) -> bytes:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        raise GateError(f"command failed: {' '.join(command)}: {str(detail).strip()}") from exc
    return result.stdout


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


def candidate_patch_paths(payload: bytes) -> set[str]:
    paths: set[str] = set()
    pattern = re.compile(rb"^diff --git a/([A-Za-z0-9._/+@-]+) b/([A-Za-z0-9._/+@-]+)$")
    for line in payload.splitlines():
        if not line.startswith(b"diff --git "):
            continue
        match = pattern.fullmatch(line)
        require(match is not None, "fork candidate patch contains a non-portable path")
        before = match.group(1).decode("ascii")
        after = match.group(2).decode("ascii")
        require(before == after, "fork candidate patch renames a path")
        require(
            all(part not in ("", ".", "..") for part in PurePosixPath(before).parts),
            "fork candidate patch path is unsafe",
        )
        require(before not in paths, "fork candidate patch repeats a path")
        paths.add(before)
    require(paths, "fork candidate patch contains no file transitions")
    return paths


def git_changed_paths(repository: Path, *, cached: bool) -> set[str]:
    command = ["git", "diff"]
    if cached:
        command.append("--cached")
    command.extend(["--name-only", "-z"])
    if cached:
        command.append("HEAD")
    command.append("--")
    return {
        item.decode("utf-8")
        for item in run_bytes(command, repository).split(b"\0")
        if item
    }


def staged_candidate_patch_bytes(repository: Path, paths: set[str]) -> bytes:
    return run_bytes(
        [
            "git",
            "-c",
            "diff.noprefix=false",
            "-c",
            "diff.mnemonicPrefix=false",
            "diff",
            "--cached",
            "--binary",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--abbrev=7",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--unified=3",
            "--diff-algorithm=myers",
            "--indent-heuristic",
            "HEAD",
            "--",
            *sorted(paths),
        ],
        repository,
    )


def verify_staged_candidate_patch(
    repository: Path,
    patch_path: Path,
    patch_payload: bytes,
    paths: set[str],
    name: str,
    *,
    allowed_unstaged_paths: set[str],
    state_label: str,
) -> None:
    try:
        subprocess.run(
            ["git", "apply", "--reverse", "--check", str(patch_path)],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"{name} does not contain the exact applied fork candidate patch") from exc

    require(
        staged_candidate_patch_bytes(repository, paths) == patch_payload,
        f"{name} applied patch differs from the candidate lock",
    )
    require(
        git_changed_paths(repository, cached=True) == paths,
        f"{name} contains unexpected staged candidate {state_label} changes",
    )
    require(
        git_changed_paths(repository, cached=False) == allowed_unstaged_paths,
        f"{name} contains unexpected candidate {state_label} changes",
    )
    require(
        not run_bytes(["git", "ls-files", "--others", "--exclude-standard", "-z"], repository),
        f"{name} contains untracked candidate {state_label} files",
    )


def host_binding_archive() -> str:
    key = (platform.system().lower(), platform.machine().lower())
    archives = {
        ("linux", "x86_64"): "lib/libidena_wasm_linux_amd64.a",
        ("linux", "amd64"): "lib/libidena_wasm_linux_amd64.a",
        ("linux", "aarch64"): "lib/libidena_wasm_linux_aarch64.a",
        ("linux", "arm64"): "lib/libidena_wasm_linux_aarch64.a",
        ("darwin", "x86_64"): "lib/libidena_wasm_darwin_amd64.a",
        ("darwin", "amd64"): "lib/libidena_wasm_darwin_amd64.a",
        ("darwin", "arm64"): "lib/libidena_wasm_darwin_arm64.a",
        ("darwin", "aarch64"): "lib/libidena_wasm_darwin_arm64.a",
    }
    archive = archives.get(key)
    require(archive is not None, f"unsupported candidate runtime host: {key[0]}/{key[1]}")
    return archive


def validate_candidate_safety_profile(candidate: dict[str, Any]) -> None:
    require(
        candidate.get("status") == "experimental-uncommitted-candidate",
        "fork candidate status is not fail-closed",
    )
    require(candidate.get("authorizedForDeployment") is False, "fork candidate authorizes deployment")
    require(candidate.get("authorizedForRelease") is False, "fork candidate authorizes release")
    require(
        candidate.get("canonicalReferenceChangePermitted") is False,
        "fork candidate authorizes a canonical change",
    )

    profile = candidate.get("forkProfile")
    require(isinstance(profile, dict), "fork candidate profile is missing")
    require(profile.get("networkId") == CANDIDATE_NETWORK_ID, "fork candidate network is invalid")
    require(profile.get("consensusChangesAllowed") is True, "fork candidate disallows its consensus delta")
    require(profile.get("consensusDeltaImplemented") is True, "fork candidate feature plumbing is incomplete")
    require(profile.get("consensusDeltaActive") is False, "fork candidate consensus delta is active")

    activation = candidate.get("activation")
    require(isinstance(activation, dict), "fork candidate activation descriptor is missing")
    require(activation.get("mechanism") == "fixed-reviewed-source-feature-mask", "fork candidate activation mechanism is mutable")
    require(activation.get("sourcePath") == "vm/wasm/vm.go", "fork candidate activation source is invalid")
    require(activation.get("sourceStatus") == "no-authorized-height-or-genesis", "fork candidate activation source is not fail-closed")
    require(activation.get("enabled") is False, "fork candidate activation must remain disabled")
    require(activation.get("activationHeight") is None, "fork candidate invents an activation height")
    require(activation.get("genesisCid") is None, "fork candidate invents an activation genesis")
    require(activation.get("environmentOverridePermitted") is False, "fork candidate permits an environment activation override")
    require(activation.get("mainnetActivationPermitted") is False, "fork candidate permits mainnet activation")
    require(
        activation.get("liveCanonicalReferenceChangesPermitted") is False,
        "fork candidate permits live canonical changes",
    )

    host_abi = candidate.get("hostAbi")
    require(isinstance(host_abi, dict), "fork candidate host ABI descriptor is missing")
    require(host_abi.get("newImport") == "env.epoch_block", "fork candidate import is invalid")
    require(host_abi.get("featureMask") == FEATURE_EPOCH_BLOCK, "fork candidate feature mask is invalid")
    require(host_abi.get("defaultFeatureMask") == 0, "legacy runtime features do not default to zero")
    require(host_abi.get("disabledResolverBehavior") == "import-omitted", "disabled import remains resolvable")
    require(host_abi.get("nestedPropagation") == "calls-and-deploys", "nested feature propagation is not locked")
    require(host_abi.get("abiVersion") == GO_API_V2_ABI_VERSION, "fork candidate ABI version is invalid")
    require(host_abi.get("goApiV2Size64") == GO_API_V2_SIZE_64, "fork candidate ABI size is invalid")
    require(
        host_abi.get("legacyVtableCallbackCount") == LEGACY_GO_API_VTABLE_CALLBACKS,
        "legacy callback layout changed",
    )
    require(host_abi.get("extensionPlacement") == "after-legacy-go-api-prefix", "fork candidate ABI extension is not append-only")
    require(host_abi.get("contractImportCount") == 13, "governance contract import count changed")
    require(host_abi.get("contractExportCount") == 65, "governance contract export count changed")

    artifact = candidate.get("contractArtifact")
    require(isinstance(artifact, dict), "fork candidate contract artifact is missing")
    require(artifact.get("abiImports") == 13, "governance artifact import count changed")
    require(artifact.get("abiExports") == 65, "governance artifact export count changed")


def validate_candidate_source_descriptor(component: dict[str, Any]) -> None:
    name = component.get("name")
    label = f"{name} candidate source"
    require(component.get("candidateCommit") is None, f"{label} unexpectedly claims a commit")
    require(
        component.get("candidateSourceStatus") == "deterministic-patched-source-uncommitted",
        f"{label} status is invalid",
    )
    source_sha256 = component.get("candidateSourceSha256")
    car_sha256 = component.get("candidateSourceCarSha256")
    source_cid = component.get("candidateSourceCid")
    require(
        isinstance(source_sha256, str) and SHA256_RE.fullmatch(source_sha256) is not None,
        f"{label} SHA-256 is invalid",
    )
    require(
        isinstance(car_sha256, str) and SHA256_RE.fullmatch(car_sha256) is not None,
        f"{label} CAR SHA-256 is invalid",
    )
    require(
        isinstance(source_cid, str) and source_cid == dag_cbor_cid(source_sha256),
        f"{label} CID does not match its root digest",
    )
    file_count = component.get("candidateSourceFileCount")
    total_bytes = component.get("candidateSourceTotalBytes")
    require(
        isinstance(file_count, int) and not isinstance(file_count, bool) and 0 < file_count <= 100_000,
        f"{label} file count is invalid",
    )
    require(
        isinstance(total_bytes, int)
        and not isinstance(total_bytes, bool)
        and 0 < total_bytes <= MAX_CONTRACT_BYTES,
        f"{label} byte count is invalid",
    )


def verify_candidate_source_packages(
    root: Path,
    candidate: dict[str, Any],
    idena_go: Path,
    supplied: dict[str, Path],
    governance_cli: Path,
) -> dict[str, str]:
    validate_candidate_safety_profile(candidate)
    try:
        cli_metadata = governance_cli.lstat()
    except OSError as exc:
        raise GateError(f"cannot inspect governance CLI: {governance_cli}") from exc
    require(stat.S_ISREG(cli_metadata.st_mode), "governance CLI must be a regular non-symlink file")
    require(cli_metadata.st_mode & 0o111 != 0, "governance CLI is not executable")

    components = candidate.get("components")
    require(isinstance(components, list), "fork candidate components are missing")
    patched = {
        component.get("name"): component
        for component in components
        if isinstance(component, dict) and "patch" in component
    }
    require(
        set(patched) == {"idena-go", "idena-wasm-binding", "idena-wasm"},
        "fork candidate patch set is incomplete",
    )
    require(
        set(supplied) == {"idena-wasm-binding", "idena-wasm"},
        "candidate source verification requires exact binding and WASM worktrees",
    )
    repositories = dict(supplied)
    repositories["idena-go"] = idena_go
    verified: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="pohw-governance-candidate-sources-") as raw_output:
        output_root = Path(raw_output)
        for name, component in sorted(patched.items()):
            validate_candidate_source_descriptor(component)
            repository = repositories[name]
            expected_commit = component.get("baseCommit")
            require(
                isinstance(expected_commit, str) and COMMIT_RE.fullmatch(expected_commit) is not None,
                f"invalid fork candidate base commit for {name}",
            )
            require(
                run_output(["git", "rev-parse", "HEAD"], repository) == expected_commit,
                f"{name} HEAD does not match the fork candidate base",
            )
            patch = component.get("patch")
            require(isinstance(patch, dict), f"fork candidate patch descriptor is missing for {name}")
            patch_path, patch_payload = verify_locked_file(
                root,
                patch,
                path_key="path",
                size_key="size",
                sha256_key="sha256",
                cid_key="cid",
                maximum=MAX_CANDIDATE_PATCH_BYTES,
                label=f"{name} fork candidate patch",
            )
            paths = candidate_patch_paths(patch_payload)
            verify_staged_candidate_patch(
                repository,
                patch_path,
                patch_payload,
                paths,
                name,
                allowed_unstaged_paths=set(),
                state_label="source",
            )

            exclusions_path = resolve_locked_relative_file(
                root, component.get("artifactExclusionsPath"), f"{name} artifact exclusions"
            )
            exclusions = read_regular_file(
                exclusions_path, MAX_LOCK_BYTES, f"{name} artifact exclusions"
            )
            exclusions_sha256 = component.get("artifactExclusionsSha256")
            require(
                isinstance(exclusions_sha256, str)
                and SHA256_RE.fullmatch(exclusions_sha256) is not None
                and hashlib.sha256(exclusions).hexdigest() == exclusions_sha256,
                f"{name} artifact exclusions do not match the candidate lock",
            )

            output = output_root / name
            try:
                subprocess.run(
                    [
                        str(governance_cli),
                        "package",
                        "--root",
                        str(repository),
                        "--repository",
                        name,
                        "--output-dir",
                        str(output),
                        "--artifact-exclusions",
                        str(exclusions_path),
                    ],
                    cwd=root,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            except (OSError, subprocess.CalledProcessError) as exc:
                detail = getattr(exc, "stderr", b"")
                if isinstance(detail, bytes):
                    detail = detail.decode("utf-8", errors="replace")
                raise GateError(f"cannot package {name} candidate source: {str(detail).strip()}") from exc

            view_path = output / f"{name}.source.json"
            car_path = output / f"{name}.source.car"
            try:
                view = json.loads(
                    read_regular_file(view_path, MAX_CONTRACT_BYTES, f"{name} source view").decode("utf-8"),
                    object_pairs_hook=reject_duplicate_pairs,
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise GateError(f"{name} source view is invalid JSON") from exc
            require(isinstance(view, dict), f"{name} source view must be an object")
            manifest = view.get("manifest")
            files = manifest.get("files") if isinstance(manifest, dict) else None
            require(isinstance(files, list), f"{name} source view has no file inventory")
            require(
                all(isinstance(item, dict) and isinstance(item.get("size"), int) for item in files),
                f"{name} source view contains an invalid file entry",
            )
            car_payload = read_regular_file(car_path, MAX_CONTRACT_BYTES, f"{name} source CAR")
            require(
                view.get("sourceTreeCid") == component.get("candidateSourceCid"),
                f"{name} source CID does not match the candidate lock",
            )
            require(
                view.get("sourceTreeSha256") == component.get("candidateSourceSha256"),
                f"{name} source digest does not match the candidate lock",
            )
            require(
                view.get("carSha256") == component.get("candidateSourceCarSha256")
                and hashlib.sha256(car_payload).hexdigest() == component.get("candidateSourceCarSha256"),
                f"{name} source CAR digest does not match the candidate lock",
            )
            require(
                len(files) == component.get("candidateSourceFileCount"),
                f"{name} source file count does not match the candidate lock",
            )
            require(
                sum(item["size"] for item in files) == component.get("candidateSourceTotalBytes"),
                f"{name} source byte count does not match the candidate lock",
            )
            verified[name] = component["candidateSourceCid"]
    return verified


def verify_candidate_binding_checksum(binding: Path, archive_path: str) -> None:
    archive = binding / archive_path
    archive_payload = read_regular_file(archive, MAX_NATIVE_ARCHIVE_BYTES, "candidate native WASM archive")
    digest = hashlib.sha256(archive_payload).hexdigest()
    baseline = run_bytes(["git", "show", "HEAD:lib/SHA256SUMS"], binding).decode("ascii")
    name = PurePosixPath(archive_path).name
    rows = baseline.splitlines()
    require(sum(row.endswith("  " + name) for row in rows) == 1, "native archive checksum row is missing or duplicated")
    expected = "\n".join(
        f"{digest}  {name}" if row.endswith("  " + name) else row for row in rows
    ) + "\n"
    current = read_regular_file(
        binding / "lib/SHA256SUMS", MAX_RUNTIME_TEST_BYTES, "candidate native archive checksums"
    ).decode("ascii")
    require(current == expected, "candidate native archive checksum manifest has unrelated changes")


def verify_candidate_component_sources(
    root: Path,
    candidate: dict[str, Any],
    idena_go: Path,
    supplied: dict[str, Path],
) -> Path:
    validate_candidate_safety_profile(candidate)
    components = candidate.get("components")
    require(isinstance(components, list), "fork candidate components are missing")
    patched = {
        component.get("name"): component
        for component in components
        if isinstance(component, dict) and "patch" in component
    }
    require(set(patched) == {"idena-go", "idena-wasm-binding", "idena-wasm"}, "fork candidate patch set is incomplete")
    require(set(supplied) == {"idena-wasm-binding", "idena-wasm"}, "candidate runtime requires exact binding and WASM worktrees")
    repositories = dict(supplied)
    repositories["idena-go"] = idena_go
    archive_path = host_binding_archive()

    for name, component in patched.items():
        repository = repositories[name]
        expected_commit = component.get("baseCommit")
        require(
            isinstance(expected_commit, str) and COMMIT_RE.fullmatch(expected_commit) is not None,
            f"invalid fork candidate base commit for {name}",
        )
        head = run_output(["git", "rev-parse", "HEAD"], repository)
        require(head == expected_commit, f"{name} HEAD does not match the fork candidate base")
        descriptor = component.get("patch")
        require(isinstance(descriptor, dict), f"fork candidate patch descriptor is missing for {name}")
        patch_path, patch_payload = verify_locked_file(
            root,
            descriptor,
            path_key="path",
            size_key="size",
            sha256_key="sha256",
            cid_key="cid",
            maximum=MAX_CANDIDATE_PATCH_BYTES,
            label=f"{name} fork candidate patch",
        )
        paths = candidate_patch_paths(patch_payload)
        allowed_unstaged: set[str] = set()
        if name == "idena-go":
            allowed_unstaged.add("go.mod")
        elif name == "idena-wasm-binding":
            allowed_unstaged.update({"lib/SHA256SUMS", archive_path})
        verify_staged_candidate_patch(
            repository,
            patch_path,
            patch_payload,
            paths,
            name,
            allowed_unstaged_paths=allowed_unstaged,
            state_label="runtime",
        )

    binding = repositories["idena-wasm-binding"]
    verify_candidate_binding_checksum(binding, archive_path)
    return binding


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


def verify_resolved_local_runtime_binding(idena_go: Path, expected: Path) -> str:
    environment = dict(os.environ)
    environment["GOWORK"] = "off"
    raw = run_output(
        ["go", "list", "-mod=readonly", "-m", "-json", "github.com/idena-network/idena-wasm-binding"],
        idena_go,
        environment,
    )
    try:
        module = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GateError("go list returned invalid local binding module JSON") from exc
    resolved = module.get("Replace") or module
    directory = resolved.get("Dir") if isinstance(resolved, dict) else None
    require(isinstance(directory, str), "resolved local idena-wasm-binding has no directory")
    require(Path(directory).resolve() == expected.resolve(), "idena-go does not resolve the supplied candidate binding")
    return "local-candidate-binding"


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
    disable_workspace: bool = False,
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
        if disable_workspace:
            environment["GOWORK"] = "off"
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
        "--fork-candidate-lock",
        type=Path,
        help="Inactive fork candidate that supplies the exact contract, runtime-test patch, and component patches",
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
    parser.add_argument(
        "--verify-candidate-sources-only",
        action="store_true",
        help="Repackage exact applied fork-candidate sources and verify their locked CIDs",
    )
    parser.add_argument(
        "--governance-cli",
        type=Path,
        help="Exact pohw-governance binary used by --verify-candidate-sources-only",
    )
    args = parser.parse_args()

    contract = args.contract.expanduser().resolve()
    lock: dict[str, Any] | None = None
    candidate: dict[str, Any] | None = None
    if args.fork_candidate_lock is not None:
        candidate = load_json(args.fork_candidate_lock.expanduser().resolve())
        validate_candidate_safety_profile(candidate)
        expected_sha256, expected_size, expected_cid = verify_artifact_descriptor(
            contract,
            candidate.get("contractArtifact"),
            "Governance Day fork candidate lock",
        )
        (
            runtime_test_source,
            runtime_test_target,
            runtime_test_name,
            runtime_test_cid,
        ) = verify_candidate_runtime_test_overlay(root, candidate)
    else:
        lock = load_json(args.lock.expanduser().resolve())
        expected_sha256, expected_size, expected_cid = verify_contract_artifact(contract, lock)
        _, runtime_test_source, runtime_test_target, runtime_test_name = verify_runtime_test_overlay(root, lock)
        runtime_test_cid = lock["governancePrototype"]["runtimeIntegrationTestOverlay"]["cid"]

    require(
        not (args.verify_artifact_only and args.verify_candidate_sources_only),
        "artifact-only and candidate-source-only modes are mutually exclusive",
    )
    if args.verify_artifact_only:
        require(not args.require_locked_sources, "artifact-only mode cannot require locked source worktrees")
        print(
            json.dumps(
                {
                    "contractCid": expected_cid,
                    "contractSha256": expected_sha256,
                    "contractSize": expected_size,
                    "runtimeTestCid": runtime_test_cid,
                    "status": "passed",
                },
                sort_keys=True,
            )
        )
        return 0

    require(args.idena_go is not None, "--idena-go is required unless --verify-artifact-only is used")
    idena_go = args.idena_go.expanduser().resolve()
    require((idena_go / "go.mod").is_file(), f"idena-go worktree is invalid: {idena_go}")

    supplied = parse_component_repositories(args.component_repo)
    if args.verify_candidate_sources_only:
        require(candidate is not None, "candidate-source verification requires --fork-candidate-lock")
        require(
            not args.require_locked_sources,
            "an uncommitted candidate cannot satisfy the release-grade locked-source gate",
        )
        require(args.governance_cli is not None, "candidate-source verification requires --governance-cli")
        verified_sources = verify_candidate_source_packages(
            root,
            candidate,
            idena_go,
            supplied,
            args.governance_cli.expanduser().resolve(),
        )
        print(
            json.dumps(
                {
                    "candidateSources": verified_sources,
                    "contractCid": expected_cid,
                    "status": "passed",
                },
                sort_keys=True,
            )
        )
        return 0

    if candidate is not None:
        require(
            not args.require_locked_sources,
            "an uncommitted fork candidate cannot satisfy the release-grade locked-source gate",
        )
        candidate_binding = verify_candidate_component_sources(root, candidate, idena_go, supplied)
        binding_version = verify_resolved_local_runtime_binding(idena_go, candidate_binding)
        expected_go = candidate.get("toolchains", {}).get("go")
    else:
        assert lock is not None
        components = {
            component.get("name"): component
            for component in lock.get("components", [])
            if isinstance(component, dict)
        }
        binding = components.get("idena-wasm-binding")
        require(isinstance(binding, dict), "lock is missing idena-wasm-binding")
        binding_commit = binding.get("commit")
        require(
            isinstance(binding_commit, str) and COMMIT_RE.fullmatch(binding_commit) is not None,
            "invalid locked binding commit",
        )
        binding_version = verify_resolved_runtime_binding(idena_go, binding_commit)
        expected_go = lock.get("toolchains", {}).get("go")

    if args.require_locked_sources:
        assert lock is not None
        verify_locked_sources(root, lock, idena_go, supplied)

    go_version = run_output(["go", "env", "GOVERSION"], idena_go)
    require(go_version == "go" + str(expected_go), f"Go toolchain mismatch: expected go{expected_go}, found {go_version}")

    run_runtime_test(
        idena_go,
        runtime_test_source,
        runtime_test_target,
        runtime_test_name,
        contract,
        expected_sha256,
        go_version,
        disable_workspace=candidate is not None,
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
                "runtimeTestCid": runtime_test_cid,
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
