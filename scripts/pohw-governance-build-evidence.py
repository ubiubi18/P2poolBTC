#!/usr/bin/env python3
"""Generate deterministic, content-addressed clean-room build evidence.

This tool deliberately does not execute the candidate repository's build
commands. A separately isolated builder runs the allowlisted commands and
provides redacted logs plus a result record. This process invokes only a
digest-pinned pohw-governance source verifier, then verifies exact dependency
locks and build artifacts before producing a deterministic CycloneDX SBOM and
BuildEvidenceV1 package.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import unicodedata
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_LOCK_BYTES = 64 * 1024 * 1024
MAX_LOG_BYTES = 128 * 1024 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 1024 * 1024
MAX_PORTABLE_ARTIFACT_SIZE = (1 << 53) - 1
RAW_CODEC = 0x55
DAG_CBOR_CODEC = 0x71
SHA2_256_CODE = 0x12
CORE_ARTIFACT_SET_DOMAIN = b"IDENA_GOV_CORE_ARTIFACT_SET_V1\x00"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9._-]+)?$")
FORBIDDEN_FILENAME_RE = re.compile(
    r"(?:^|[._-])(?:secret|secrets|wallet|mnemonic|cookie|credentials?|private[._-]?key)(?:$|[._-])",
    re.IGNORECASE,
)
FORBIDDEN_EXTENSIONS = {
    ".env",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".keystore",
    ".wallet",
    ".cookie",
}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(
        rb"(?:authorization|api[_-]?key|password|passwd|cookie)\s*[:=]\s*(?!<redacted>|\[redacted\])\S+",
        re.IGNORECASE,
    ),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[a-z]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
)


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def cbor_head(major: int, value: int) -> bytes:
    require(0 <= major <= 7 and isinstance(value, int) and value >= 0, "invalid CBOR value")
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + value.to_bytes(8, "big")
    raise EvidenceError("CBOR value exceeds the deterministic limit")


def cbor_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return cbor_head(3, len(encoded)) + encoded


def canonical_dag_cbor_string_map(value: Dict[str, str]) -> bytes:
    require(isinstance(value, dict) and value, "DAG-CBOR string map must not be empty")
    entries = []
    for key, item in value.items():
        require(isinstance(key, str) and isinstance(item, str), "DAG-CBOR toolchain entries must be strings")
        encoded_key = cbor_text(key)
        entries.append((encoded_key, cbor_text(item)))
    entries.sort(key=lambda entry: (len(entry[0]), entry[0]))
    return cbor_head(5, len(entries)) + b"".join(key + item for key, item in entries)


def reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("JSON contains a duplicate object key")
        result[key] = value
    return result


def strict_json_loads(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_pairs)
    except EvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} is not valid UTF-8 JSON") from exc


def load_json(path: Path, label: str) -> Any:
    raw = read_regular_file(path, label, MAX_JSON_BYTES)
    return strict_json_loads(raw, label)


def reject_log_secrets(raw: bytes, label: str) -> None:
    for pattern in SECRET_PATTERNS:
        require(pattern.search(raw) is None, f"{label} contains unredacted credential-like content")


def read_regular_file(path: Path, label: str, maximum: int) -> bytes:
    validate_regular_file(path, label, maximum)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read {label}: {path}") from exc


def validate_regular_file(path: Path, label: str, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"cannot inspect {label}: {path}") from exc
    require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular non-symlink file: {path}")
    require(metadata.st_size <= maximum, f"{label} exceeds the size limit: {path}")
    return metadata


def file_digest(path: Path, maximum: int = MAX_ARTIFACT_BYTES) -> Tuple[str, int]:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), f"artifact must be a regular non-symlink file: {path}")
    require(metadata.st_size <= maximum, f"artifact exceeds the size limit: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    require(size == metadata.st_size, f"artifact changed while hashing: {path}")
    return digest.hexdigest(), size


def file_reference(path: Path, maximum: int = MAX_ARTIFACT_BYTES) -> Dict[str, Any]:
    digest, size = file_digest(path, maximum)
    return {"cid": cid_for_digest(RAW_CODEC, digest), "sha256": digest, "size": size}


def encode_varint(value: int) -> bytes:
    require(value >= 0, "varint cannot be negative")
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def decode_varint(raw: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    for index in range(offset, min(len(raw), offset + 10)):
        byte = raw[index]
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            require(index == offset or byte != 0, "CID contains a noncanonical varint")
            return value, index + 1
        shift += 7
    raise EvidenceError("CID contains an invalid varint")


def cid_for_digest(codec: int, digest_hex: str) -> str:
    require(SHA256_RE.fullmatch(digest_hex) is not None, "invalid SHA-256 digest")
    raw = (
        encode_varint(1)
        + encode_varint(codec)
        + encode_varint(SHA2_256_CODE)
        + encode_varint(32)
        + bytes.fromhex(digest_hex)
    )
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def raw_cid(data: bytes) -> Tuple[str, str]:
    digest = hashlib.sha256(data).hexdigest()
    return cid_for_digest(RAW_CODEC, digest), digest


def validate_cid(value: Any, codec: int, label: str) -> str:
    require(isinstance(value, str) and value.startswith("b") and value == value.lower(), f"{label} is not lowercase CIDv1 base32")
    encoded = value[1:]
    require(re.fullmatch(r"[a-z2-7]+", encoded or "") is not None, f"{label} has invalid base32")
    padding = "=" * ((8 - len(encoded) % 8) % 8)
    try:
        raw = base64.b32decode((encoded.upper() + padding).encode("ascii"), casefold=False)
    except (ValueError, base64.binascii.Error) as exc:
        raise EvidenceError(f"{label} has invalid base32") from exc
    require("b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=") == value, f"{label} is noncanonical")
    version, offset = decode_varint(raw, 0)
    actual_codec, offset = decode_varint(raw, offset)
    hash_code, offset = decode_varint(raw, offset)
    digest_size, offset = decode_varint(raw, offset)
    digest = raw[offset:]
    require(version == 1 and actual_codec == codec, f"{label} uses the wrong CID profile")
    require(hash_code == SHA2_256_CODE and digest_size == 32 and len(digest) == 32, f"{label} is not SHA2-256")
    return digest.hex()


def parse_assignments(values: Sequence[str], label: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for value in values:
        require("=" in value, f"{label} must use NAME=VALUE")
        name, assigned = value.split("=", 1)
        require(NAME_RE.fullmatch(name) is not None and name not in result, f"invalid or duplicate {label} name: {name}")
        require(bool(assigned), f"empty {label} value for {name}")
        result[name] = assigned
    return result


def validate_relative_path(value: Any, label: str) -> str:
    require(isinstance(value, str) and value and "\\" not in value, f"{label} is invalid")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts), f"{label} is unsafe")
    require(str(path) == value and unicodedata.normalize("NFC", value) == value, f"{label} is noncanonical")
    require(not any(ord(character) < 32 for character in value), f"{label} contains a control character")
    return value


def confined_path(root: Path, relative: str, label: str) -> Path:
    validate_relative_path(relative, label)
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"cannot resolve {label}: {relative}") from exc
    require(resolved == resolved_root or resolved_root in resolved.parents, f"{label} escapes repository root")
    current = resolved_root
    for part in resolved.relative_to(resolved_root).parts:
        current = current / part
        require(not current.is_symlink(), f"{label} traverses a symlink: {relative}")
    return resolved


def validate_plan(payload: Any) -> Dict[str, Any]:
    required_top = {
        "schemaVersion",
        "planId",
        "status",
        "forkReleaseId",
        "sourceDateEpoch",
        "toolchains",
        "targets",
    }
    require(isinstance(payload, dict) and set(payload) == required_top, "build plan has missing or unexpected fields")
    require(payload["schemaVersion"] == 1, "unsupported build-plan schema")
    require(isinstance(payload["planId"], str) and NAME_RE.fullmatch(payload["planId"]), "invalid planId")
    require(payload["status"] == "experimental-local-only", "build plan must remain experimental-local-only")
    require(isinstance(payload["forkReleaseId"], str) and 1 <= len(payload["forkReleaseId"]) <= 160, "invalid forkReleaseId")
    require(isinstance(payload["sourceDateEpoch"], int) and payload["sourceDateEpoch"] >= 0, "invalid sourceDateEpoch")
    toolchains = payload["toolchains"]
    require(isinstance(toolchains, dict) and toolchains, "toolchains must be a nonempty object")
    for name, version in toolchains.items():
        require(NAME_RE.fullmatch(name) is not None, f"invalid toolchain name: {name}")
        require(isinstance(version, str) and VERSION_RE.fullmatch(version), f"invalid toolchain version: {name}")

    targets = payload["targets"]
    require(isinstance(targets, list) and targets, "targets must be a nonempty list")
    target_ids = set()
    for index, target in enumerate(targets):
        required_target = {
            "id",
            "sourceRepositories",
            "requiredToolchains",
            "dependencyLocks",
            "commands",
            "dependencyFetchCommandCount",
            "artifacts",
            "reproducibility",
            "limitations",
        }
        require(isinstance(target, dict) and set(target) == required_target, f"target {index} has missing or unexpected fields")
        target_id = target["id"]
        require(isinstance(target_id, str) and NAME_RE.fullmatch(target_id) and target_id not in target_ids, f"invalid or duplicate target id: {target_id}")
        target_ids.add(target_id)
        repositories = target["sourceRepositories"]
        require(isinstance(repositories, list) and repositories and len(repositories) == len(set(repositories)), f"target {target_id} has invalid sourceRepositories")
        require(all(isinstance(name, str) and NAME_RE.fullmatch(name) for name in repositories), f"target {target_id} has invalid source repository")
        required_tools = target["requiredToolchains"]
        require(isinstance(required_tools, list) and required_tools and len(required_tools) == len(set(required_tools)), f"target {target_id} has invalid requiredToolchains")
        require(all(name in toolchains for name in required_tools), f"target {target_id} references an unknown toolchain")
        commands = target["commands"]
        require(isinstance(commands, list) and commands and len(commands) <= 200, f"target {target_id} has invalid commands")
        for command in commands:
            require(isinstance(command, str) and command.strip() == command and 1 <= len(command) <= 2000, f"target {target_id} has an invalid command")
            require("\n" not in command and "\r" not in command and "\x00" not in command, f"target {target_id} command is multiline")
        fetch_count = target["dependencyFetchCommandCount"]
        require(
            isinstance(fetch_count, int)
            and not isinstance(fetch_count, bool)
            and 1 <= fetch_count < len(commands),
            f"target {target_id} must identify a nonempty dependency-fetch prefix",
        )
        validate_lock_entries(target_id, target["dependencyLocks"], repositories)
        validate_artifact_entries(target_id, target["artifacts"], repositories)
        require(target["reproducibility"] in ("deterministic-core", "platform-constrained"), f"target {target_id} has invalid reproducibility")
        require(isinstance(target["limitations"], list) and all(isinstance(item, str) and item for item in target["limitations"]), f"target {target_id} has invalid limitations")
    return payload


def validate_lock_entries(target_id: str, entries: Any, repositories: Sequence[str]) -> None:
    require(isinstance(entries, list) and entries, f"target {target_id} must declare dependency locks")
    seen = set()
    allowed_formats = {"cargo-lock", "go-sum", "npm-package-lock", "pnpm-lock", "digest-only"}
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"repository", "path", "sha256", "format"}, f"target {target_id} has an invalid dependency lock")
        key = (entry["repository"], entry["path"])
        require(entry["repository"] in repositories and key not in seen, f"target {target_id} has duplicate or foreign dependency lock")
        seen.add(key)
        validate_relative_path(entry["path"], "dependency lock path")
        require(isinstance(entry["sha256"], str) and SHA256_RE.fullmatch(entry["sha256"]), f"target {target_id} has invalid lock SHA-256")
        require(entry["format"] in allowed_formats, f"target {target_id} has unsupported lock format")


def validate_artifact_entries(target_id: str, entries: Any, repositories: Sequence[str]) -> None:
    require(isinstance(entries, list) and entries, f"target {target_id} must declare artifacts")
    seen = set()
    for entry in entries:
        required = {
            "name",
            "repository",
            "kind",
            "pathHint",
            "platform",
            "architecture",
            "deterministic",
            "expectedCid",
            "expectedSha256",
            "expectedSize",
        }
        require(isinstance(entry, dict) and set(entry) == required, f"target {target_id} has an invalid artifact declaration")
        name = entry["name"]
        require(isinstance(name, str) and NAME_RE.fullmatch(name) and name not in seen, f"target {target_id} has invalid or duplicate artifact name")
        seen.add(name)
        require(entry["repository"] in repositories, f"target {target_id} artifact has foreign repository")
        require(entry["kind"] in ("file", "directory-tar"), f"target {target_id} artifact kind is invalid")
        validate_relative_path(entry["pathHint"], "artifact pathHint")
        require(
            "**" not in entry["pathHint"]
            and entry["pathHint"].count("*") <= 1
            and "?" not in entry["pathHint"]
            and "[" not in entry["pathHint"],
            f"target {target_id} artifact pathHint has an unsafe glob",
        )
        for field in ("platform", "architecture"):
            require(
                isinstance(entry[field], str)
                and (entry[field] == "builder-platform" or NAME_RE.fullmatch(entry[field])),
                f"target {target_id} artifact {field} is invalid",
            )
        require(isinstance(entry["deterministic"], bool), f"target {target_id} artifact deterministic flag is invalid")
        expected = (entry["expectedCid"], entry["expectedSha256"], entry["expectedSize"])
        require(all(value is None for value in expected) or all(value is not None for value in expected), f"target {target_id} artifact expected values must be all present or all null")
        if expected[0] is not None:
            digest = validate_cid(expected[0], RAW_CODEC, f"target {target_id} artifact CID")
            require(isinstance(expected[1], str) and SHA256_RE.fullmatch(expected[1]) and digest == expected[1], f"target {target_id} artifact CID/SHA mismatch")
            require(
                isinstance(expected[2], int) and 0 <= expected[2] <= MAX_PORTABLE_ARTIFACT_SIZE,
                f"target {target_id} artifact size is invalid",
            )
    require(
        any(entry["deterministic"] for entry in entries),
        f"target {target_id} must declare at least one deterministic core artifact",
    )


def core_artifact_set_digest(artifacts: Sequence[Dict[str, Any]]) -> str:
    core = sorted(
        (artifact for artifact in artifacts if artifact["deterministic"]),
        key=lambda artifact: canonical_key(artifact["name"]),
    )
    require(core, "at least one deterministic core artifact is required")
    require(len(core) <= 0xFFFFFFFF, "too many deterministic core artifacts")
    hasher = hashlib.sha256()
    hasher.update(CORE_ARTIFACT_SET_DOMAIN)
    hasher.update(len(core).to_bytes(4, "big"))
    for artifact in core:
        for field in ("name", "cid"):
            encoded = artifact[field].encode("utf-8")
            require(len(encoded) <= 0xFFFFFFFF, f"core artifact {field} is too large")
            hasher.update(len(encoded).to_bytes(4, "big"))
            hasher.update(encoded)
        hasher.update(bytes.fromhex(artifact["sha256"]))
        size = artifact["size"]
        require(
            isinstance(size, int) and 0 <= size <= MAX_PORTABLE_ARTIFACT_SIZE,
            "core artifact size is invalid",
        )
        hasher.update(size.to_bytes(8, "big"))
    return hasher.hexdigest()


def target_by_id(plan: Dict[str, Any], target_id: str) -> Dict[str, Any]:
    for target in plan["targets"]:
        if target["id"] == target_id:
            return target
    raise EvidenceError(f"unknown build target: {target_id}")


def parse_repository_roots(values: Sequence[str]) -> Dict[str, Path]:
    assignments = parse_assignments(values, "repository root")
    result = {}
    for name, raw_path in assignments.items():
        path = Path(raw_path).expanduser()
        require(path.is_absolute(), f"repository root must be absolute: {name}")
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and not path.is_symlink(), f"repository root must be a non-symlink directory: {name}")
        result[name] = path.resolve(strict=True)
    return result


def parse_regular_file_assignments(
    values: Sequence[str], label: str, maximum: int
) -> Dict[str, Path]:
    assignments = parse_assignments(values, label)
    result: Dict[str, Path] = {}
    for name, raw_path in assignments.items():
        path = Path(raw_path).expanduser()
        require(path.is_absolute(), f"{label} must be absolute: {name}")
        validate_regular_file(path, label, maximum)
        result[name] = path.resolve(strict=True)
    return result


def verify_source_bindings(
    roots: Dict[str, Path],
    source_cids: Dict[str, str],
    source_cars: Dict[str, Path],
    source_verifier: Path,
    source_verifier_sha256: str,
    artifact_exclusions: Dict[str, Path],
) -> Dict[str, Any]:
    require(set(source_cars) == set(roots), "--source-car names must exactly match the selected target")
    require(set(artifact_exclusions).issubset(roots), "--artifact-exclusions references an unknown source repository")
    require(source_verifier.is_absolute(), "source verifier path must be absolute")
    metadata = source_verifier.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and not source_verifier.is_symlink()
        and metadata.st_mode & 0o111,
        "source verifier must be an executable non-symlink regular file",
    )
    verifier_reference = file_reference(source_verifier, 512 * 1024 * 1024)
    require(
        SHA256_RE.fullmatch(source_verifier_sha256 or "") is not None
        and verifier_reference["sha256"] == source_verifier_sha256,
        "source verifier SHA-256 does not match the declared digest",
    )

    source_car_references = {
        name: file_reference(path) for name, path in source_cars.items()
    }
    exclusion_references = {
        name: file_reference(path, MAX_JSON_BYTES)
        for name, path in artifact_exclusions.items()
    }
    verified_sources = []
    for repository in sorted(roots, key=canonical_key):
        command = [
            str(source_verifier),
            "verify",
            "--car",
            str(source_cars[repository]),
            "--root",
            str(roots[repository]),
            "--repository",
            repository,
        ]
        exclusion = artifact_exclusions.get(repository)
        if exclusion is not None:
            command.extend(["--artifact-exclusions", str(exclusion)])
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceError(f"source verification could not run for {repository}") from exc
        require(
            len(completed.stdout) <= MAX_VERIFIER_OUTPUT_BYTES
            and len(completed.stderr) <= MAX_VERIFIER_OUTPUT_BYTES,
            f"source verifier output exceeds the limit for {repository}",
        )
        reject_log_secrets(completed.stdout, f"source verifier stdout for {repository}")
        reject_log_secrets(completed.stderr, f"source verifier stderr for {repository}")
        require(
            completed.returncode == 0,
            f"source tree does not match its canonical CAR: {repository}",
        )
        response = strict_json_loads(completed.stdout, f"source verifier output for {repository}")
        expected_keys = {
            "verified",
            "sourceTreeCid",
            "sourceTreeSha256",
            "repository",
            "files",
            "localTreeMatch",
        }
        require(
            isinstance(response, dict) and set(response) == expected_keys,
            f"source verifier returned an unexpected result for {repository}",
        )
        cid_digest = validate_cid(
            response.get("sourceTreeCid"),
            DAG_CBOR_CODEC,
            f"verified source CID for {repository}",
        )
        require(
            response["verified"] is True
            and response["localTreeMatch"] is True
            and response["repository"] == repository
            and response["sourceTreeCid"] == source_cids[repository]
            and response["sourceTreeSha256"] == cid_digest
            and isinstance(response["files"], int)
            and not isinstance(response["files"], bool)
            and response["files"] >= 0,
            f"source verifier result does not match the declared binding for {repository}",
        )
        verified_sources.append(
            {
                "artifactExclusions": exclusion_references.get(repository),
                "files": response["files"],
                "repository": repository,
                "sourceCar": source_car_references[repository],
                "sourceCid": response["sourceTreeCid"],
                "sourceTreeSha256": response["sourceTreeSha256"],
            }
        )
    require(
        file_reference(source_verifier, 512 * 1024 * 1024) == verifier_reference,
        "source verifier changed while verification was running",
    )
    require(
        all(file_reference(source_cars[name]) == reference for name, reference in source_car_references.items()),
        "a source CAR changed while verification was running",
    )
    require(
        all(file_reference(artifact_exclusions[name], MAX_JSON_BYTES) == reference for name, reference in exclusion_references.items()),
        "an artifact-exclusion policy changed while verification was running",
    )
    return {
        "schemaVersion": 1,
        "sourceVerifier": verifier_reference,
        "sources": verified_sources,
    }


def validate_result_record(
    record: Any,
    target: Dict[str, Any],
    plan: Dict[str, Any],
    source_cids: Dict[str, str],
) -> Dict[str, Any]:
    required = {
        "schemaVersion",
        "target",
        "sourceCids",
        "cleanRoom",
        "readOnlySources",
        "networkDisabledAfterFetch",
        "dependencyFetchSeparated",
        "isolationKind",
        "containerImageDigest",
        "resourceLimits",
        "redactionPolicy",
        "toolchains",
        "platform",
        "architecture",
        "osFamily",
        "commands",
    }
    require(isinstance(record, dict) and set(record) == required, "build-result record has missing or unexpected fields")
    require(record["schemaVersion"] == 1 and record["target"] == target["id"], "build-result target/schema mismatch")
    require(record["sourceCids"] == source_cids, "build-result source CIDs do not match command-line bindings")
    for repository, cid in source_cids.items():
        validate_cid(cid, DAG_CBOR_CODEC, f"source CID for {repository}")
    for flag in ("cleanRoom", "readOnlySources", "networkDisabledAfterFetch", "dependencyFetchSeparated"):
        require(record[flag] is True, f"build-result must assert {flag}=true")
    require(record["isolationKind"] in ("container", "vm", "nix", "equivalent-clean-room"), "invalid isolationKind")
    image_digest = record["containerImageDigest"]
    require(image_digest is None or (isinstance(image_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest)), "invalid containerImageDigest")
    if record["isolationKind"] == "container":
        require(image_digest is not None, "container builds require an immutable image digest")
    limits = record["resourceLimits"]
    require(isinstance(limits, dict) and set(limits) == {"cpuCount", "memoryBytes", "processes"}, "invalid resourceLimits")
    require(all(isinstance(value, int) and value > 0 for value in limits.values()), "resource limits must be positive integers")
    require(record["redactionPolicy"] == "pohw-build-log-redaction-v1", "unsupported redaction policy")
    actual_tools = record["toolchains"]
    expected_tools = {name: plan["toolchains"][name] for name in target["requiredToolchains"]}
    require(actual_tools == expected_tools, "build-result toolchain versions do not match the locked plan")
    for field in ("platform", "architecture", "osFamily"):
        require(isinstance(record[field], str) and NAME_RE.fullmatch(record[field]), f"invalid build-result {field}")
    commands = record["commands"]
    require(isinstance(commands, list) and len(commands) == len(target["commands"]), "build-result command count mismatch")
    for index, (result, expected_command) in enumerate(zip(commands, target["commands"])):
        require(isinstance(result, dict) and set(result) == {"command", "exitCode"}, f"invalid command result {index}")
        require(result["command"] == expected_command, f"command result {index} does not match the allowlisted plan")
        require(isinstance(result["exitCode"], int), f"command result {index} has invalid exit code")
        require(result["exitCode"] == 0, f"command result {index} failed with exit code {result['exitCode']}")
    return record


def verify_logs(
    logs_dir: Path,
    commands: Sequence[Dict[str, Any]],
    fetch_count: int,
    output_dir: Path,
) -> List[Dict[str, Any]]:
    metadata = logs_dir.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not logs_dir.is_symlink(), "logs directory must be a non-symlink directory")
    expected_names = set()
    results = []
    for index, command in enumerate(commands):
        streams = {}
        for stream_name in ("stdout", "stderr"):
            filename = f"{index:03d}.{stream_name}.log"
            expected_names.add(filename)
            source = logs_dir / filename
            raw = read_regular_file(source, f"command {index} {stream_name} log", MAX_LOG_BYTES)
            reject_log_secrets(raw, f"command {index} {stream_name} log")
            cid, digest = raw_cid(raw)
            destination = output_dir / filename
            write_new(destination, raw)
            streams[f"{stream_name}Cid"] = cid
            streams[f"{stream_name}Sha256"] = digest
            streams[f"{stream_name}Size"] = len(raw)
        results.append(
            {
                "command": command["command"],
                "exitCode": command["exitCode"],
                "phase": "fetch" if index < fetch_count else "build",
                **streams,
            }
        )
    actual_names = {entry.name for entry in logs_dir.iterdir()}
    require(actual_names == expected_names, "logs directory contains missing or unexpected entries")
    return results


def package_url(name: str, version: str, package_type: str) -> str:
    encoded_name = urllib.parse.quote(name, safe="@/")
    encoded_version = urllib.parse.quote(version, safe="._-+")
    return f"pkg:{package_type}/{encoded_name}@{encoded_version}"


def integrity_hash(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, str) or "-" not in value:
        return []
    algorithm, encoded = value.split("-", 1)
    algorithms = {"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
    if algorithm not in algorithms:
        return []
    try:
        digest = base64.b64decode(encoded, validate=True).hex()
    except (ValueError, base64.binascii.Error):
        return []
    return [{"alg": algorithms[algorithm], "content": digest}]


def component(
    repository: str,
    lock_path: str,
    package_type: str,
    name: str,
    version: str,
    hashes: Optional[List[Dict[str, str]]] = None,
    properties: Optional[List[Dict[str, str]]] = None,
    instance: str = "",
) -> Dict[str, Any]:
    purl = package_url(name, version, package_type)
    instance_key = urllib.parse.quote(instance, safe="@/._-+")
    value: Dict[str, Any] = {
        "bom-ref": f"{repository}:{lock_path}:{instance_key}:{purl}",
        "name": name,
        "purl": purl,
        "type": "library",
        "version": version,
    }
    if hashes:
        value["hashes"] = hashes
    base_properties = [
        {"name": "pohw:lockPath", "value": lock_path},
        {"name": "pohw:repository", "value": repository},
    ]
    if instance:
        base_properties.append({"name": "pohw:lockEntry", "value": instance})
    if properties:
        base_properties.extend(properties)
    value["properties"] = sorted(base_properties, key=lambda item: canonical_key(item["name"] + "\0" + item["value"]))
    return value


def parse_cargo_lock(raw: bytes, repository: str, lock_path: str) -> List[Dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"Cargo lock is not UTF-8: {repository}:{lock_path}") from exc
    packages: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None
    field_re = re.compile(r'^(name|version|checksum|source) = "([^"\\]*)"$')
    for line in text.splitlines():
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {}
            continue
        if current is None:
            continue
        match = field_re.fullmatch(line)
        if match:
            current[match.group(1)] = match.group(2)
    if current is not None:
        packages.append(current)
    result = []
    for package in packages:
        require("name" in package and "version" in package, f"malformed package in {repository}:{lock_path}")
        hashes = None
        if "checksum" in package:
            require(SHA256_RE.fullmatch(package["checksum"]) is not None, f"invalid Cargo checksum in {repository}:{lock_path}")
            hashes = [{"alg": "SHA-256", "content": package["checksum"]}]
        result.append(
            component(
                repository,
                lock_path,
                "cargo",
                package["name"],
                package["version"],
                hashes,
                instance=package.get("source", "workspace"),
            )
        )
    require(result, f"Cargo lock has no packages: {repository}:{lock_path}")
    return result


def parse_npm_lock(raw: bytes, repository: str, lock_path: str) -> List[Dict[str, Any]]:
    payload = strict_json_loads(raw, f"npm lock {repository}:{lock_path}")
    require(isinstance(payload, dict) and payload.get("lockfileVersion") in (2, 3), f"unsupported npm lock version: {repository}:{lock_path}")
    packages = payload.get("packages")
    require(isinstance(packages, dict), f"npm lock omits packages: {repository}:{lock_path}")
    result = []
    for package_path, details in packages.items():
        require(isinstance(package_path, str) and isinstance(details, dict), f"invalid npm package entry: {repository}:{lock_path}")
        version = details.get("version")
        if not isinstance(version, str) or not version:
            continue
        name = details.get("name")
        if not isinstance(name, str) or not name:
            name = package_path.rsplit("node_modules/", 1)[-1]
        if not name:
            continue
        result.append(
            component(
                repository,
                lock_path,
                "npm",
                name,
                version,
                integrity_hash(details.get("integrity")),
                instance=package_path or "root",
            )
        )
    require(result, f"npm lock has no versioned packages: {repository}:{lock_path}")
    return result


def split_pnpm_package(value: str) -> Tuple[str, str]:
    normalized = value.split("(", 1)[0]
    separator = normalized.rfind("@")
    require(separator > 0 and separator < len(normalized) - 1, f"invalid pnpm package key: {value}")
    return normalized[:separator], normalized[separator + 1 :]


def parse_pnpm_lock(raw: bytes, repository: str, lock_path: str) -> List[Dict[str, Any]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"pnpm lock is not UTF-8: {repository}:{lock_path}") from exc
    require(any(re.fullmatch(r"lockfileVersion: ['\"]?9\.0['\"]?", line) for line in lines), f"unsupported pnpm lock version: {repository}:{lock_path}")
    in_packages = False
    entries: List[Tuple[str, Optional[str]]] = []
    current_index: Optional[int] = None
    key_re = re.compile(r"^  (\S.*):$")
    integrity_re = re.compile(r"^    resolution: \{integrity: ([^}]+)\}$")
    for line in lines:
        if line == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            break
        if not in_packages:
            continue
        match = key_re.fullmatch(line)
        if match:
            key = match.group(1).strip("'\"")
            entries.append((key, None))
            current_index = len(entries) - 1
            continue
        match = integrity_re.fullmatch(line)
        if match and current_index is not None:
            key, _ = entries[current_index]
            entries[current_index] = (key, match.group(1).strip("'\""))
    result = []
    for key, integrity in entries:
        name, version = split_pnpm_package(key)
        result.append(
            component(
                repository,
                lock_path,
                "npm",
                name,
                version,
                integrity_hash(integrity),
                instance=key,
            )
        )
    require(result, f"pnpm lock has no packages: {repository}:{lock_path}")
    return result


def parse_go_sum(raw: bytes, repository: str, lock_path: str) -> List[Dict[str, Any]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"go.sum is not UTF-8: {repository}:{lock_path}") from exc
    values: Dict[Tuple[str, str], str] = {}
    for index, line in enumerate(lines):
        fields = line.split()
        require(len(fields) == 3, f"malformed go.sum line {index + 1}: {repository}:{lock_path}")
        module, version, checksum = fields
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        require(checksum.startswith("h1:") and len(checksum) > 3, f"invalid go.sum checksum: {repository}:{lock_path}")
        values.setdefault((module, version), checksum)
    result = [
        component(
            repository,
            lock_path,
            "golang",
            module,
            version,
            properties=[{"name": "pohw:goSum", "value": checksum}],
            instance=module + "@" + version,
        )
        for (module, version), checksum in values.items()
    ]
    require(result, f"go.sum has no modules: {repository}:{lock_path}")
    return result


def canonical_key(value: str) -> bytes:
    return value.encode("utf-8")


def verify_locks_and_build_sbom(
    plan: Dict[str, Any],
    target: Dict[str, Any],
    roots: Dict[str, Path],
    source_cids: Dict[str, str],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    parsers = {
        "cargo-lock": parse_cargo_lock,
        "go-sum": parse_go_sum,
        "npm-package-lock": parse_npm_lock,
        "pnpm-lock": parse_pnpm_lock,
    }
    lock_evidence = []
    components = []
    for entry in target["dependencyLocks"]:
        repository = entry["repository"]
        require(repository in roots, f"missing repository root for dependency lock: {repository}")
        path = confined_path(roots[repository], entry["path"], "dependency lock")
        raw = read_regular_file(path, "dependency lock", MAX_LOCK_BYTES)
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == entry["sha256"], f"dependency lock digest mismatch: {repository}:{entry['path']}")
        cid = cid_for_digest(RAW_CODEC, digest)
        lock_evidence.append(
            {
                "cid": cid,
                "format": entry["format"],
                "path": entry["path"],
                "repository": repository,
                "sha256": digest,
                "size": len(raw),
            }
        )
        parser = parsers.get(entry["format"])
        if parser is not None:
            components.extend(parser(raw, repository, entry["path"]))
    components.sort(key=lambda item: canonical_key(item["bom-ref"]))
    seen = set()
    for item in components:
        require(item["bom-ref"] not in seen, f"duplicate SBOM component: {item['bom-ref']}")
        seen.add(item["bom-ref"])
    properties = [
        {"name": f"pohw:sourceCid:{name}", "value": source_cids[name]}
        for name in sorted(source_cids, key=canonical_key)
    ]
    properties.extend(
        [
            {"name": "pohw:buildPlanId", "value": plan["planId"]},
            {"name": "pohw:forkReleaseId", "value": plan["forkReleaseId"]},
        ]
    )
    properties.sort(key=lambda item: canonical_key(item["name"] + "\0" + item["value"]))
    sbom = {
        "bomFormat": "CycloneDX",
        "components": components,
        "metadata": {
            "component": {
                "name": target["id"],
                "type": "application",
                "version": plan["planId"],
            },
            "properties": properties,
        },
        "specVersion": "1.5",
        "version": 1,
    }
    return sorted(lock_evidence, key=lambda item: canonical_key(item["repository"] + "\0" + item["path"])), sbom


def validate_artifact_path(path: Path, root: Path, path_hint: str, label: str) -> None:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    require(resolved_root in resolved.parents, f"{label} must be below its repository root")
    relative = resolved.relative_to(resolved_root).as_posix()
    require(fnmatch.fnmatchcase(relative, path_hint), f"{label} does not match pathHint {path_hint}")
    current = resolved_root
    for part in resolved.relative_to(resolved_root).parts:
        current = current / part
        require(not current.is_symlink(), f"{label} traverses a symlink")


def validate_archive_name(name: str) -> None:
    require(unicodedata.normalize("NFC", name) == name, f"artifact tree contains a non-NFC path: {name}")
    require(not any(ord(character) < 32 for character in name), f"artifact tree contains a control character: {name}")
    lowered = name.lower()
    require(not FORBIDDEN_FILENAME_RE.search(lowered), f"artifact tree contains a forbidden credential-like path: {name}")
    require(not any(lowered == extension or lowered.endswith(extension) for extension in FORBIDDEN_EXTENSIONS), f"artifact tree contains a forbidden file type: {name}")


def walk_artifact_tree(root: Path) -> List[Tuple[str, Path, os.stat_result]]:
    entries: List[Tuple[str, Path, os.stat_result]] = []
    total_size = 0

    def visit(directory: Path, prefix: PurePosixPath) -> None:
        nonlocal total_size
        children = sorted(os.scandir(str(directory)), key=lambda item: canonical_key(item.name))
        for child in children:
            validate_archive_name(child.name)
            relative = prefix / child.name
            relative_text = str(relative)
            metadata = child.stat(follow_symlinks=False)
            mode = metadata.st_mode
            require(not stat.S_ISLNK(mode), f"artifact tree contains a symlink: {relative_text}")
            require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), f"artifact tree contains a special file: {relative_text}")
            path = Path(child.path)
            entries.append((relative_text, path, metadata))
            require(len(entries) <= 1_000_000, "directory artifact contains too many entries")
            if stat.S_ISDIR(mode):
                visit(path, relative)
            else:
                total_size += metadata.st_size
                require(total_size <= MAX_ARTIFACT_BYTES, "directory artifact exceeds the size limit")

    visit(root, PurePosixPath())
    return entries


def deterministic_tar(source: Path, destination: Path) -> None:
    entries = walk_artifact_tree(source)
    require(entries, f"directory artifact is empty: {source}")
    descriptor = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as raw_output:
        with tarfile.open(fileobj=raw_output, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for relative, path, metadata in entries:
                info = tarfile.TarInfo(relative + ("/" if stat.S_ISDIR(metadata.st_mode) else ""))
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.mode = 0o755 if stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o111 else 0o644
                if stat.S_ISDIR(metadata.st_mode):
                    info.type = tarfile.DIRTYPE
                    info.size = 0
                    archive.addfile(info)
                else:
                    info.type = tarfile.REGTYPE
                    info.size = metadata.st_size
                    with path.open("rb") as source_file:
                        archive.addfile(info, source_file)


def verify_artifacts(
    target: Dict[str, Any],
    roots: Dict[str, Path],
    assignments: Dict[str, str],
    output_dir: Path,
    platform: str,
    architecture: str,
) -> List[Dict[str, Any]]:
    expected_names = {entry["name"] for entry in target["artifacts"]}
    require(set(assignments) == expected_names, "--artifact names must exactly match the selected target")
    result = []
    for declaration in target["artifacts"]:
        name = declaration["name"]
        repository = declaration["repository"]
        require(repository in roots, f"missing repository root for artifact: {repository}")
        source = Path(assignments[name]).expanduser()
        require(source.is_absolute(), f"artifact path must be absolute: {name}")
        validate_artifact_path(
            source,
            roots[repository],
            declaration["pathHint"],
            f"artifact {name}",
        )
        if declaration["kind"] == "file":
            metadata = source.lstat()
            require(stat.S_ISREG(metadata.st_mode), f"artifact must be a regular file: {name}")
            measured_path = source
            packaged_name = source.name
        else:
            metadata = source.lstat()
            require(stat.S_ISDIR(metadata.st_mode), f"directory-tar artifact must be a directory: {name}")
            packaged_name = f"{name}.tar"
            measured_path = output_dir / packaged_name
            deterministic_tar(source, measured_path)
        digest, size = file_digest(measured_path)
        cid = cid_for_digest(RAW_CODEC, digest)
        if declaration["expectedCid"] is not None:
            require(cid == declaration["expectedCid"], f"artifact CID mismatch: {name}")
            require(digest == declaration["expectedSha256"], f"artifact SHA-256 mismatch: {name}")
            require(size == declaration["expectedSize"], f"artifact size mismatch: {name}")
        result.append(
            {
                "architecture": architecture
                if declaration["architecture"] == "builder-platform"
                else declaration["architecture"],
                "cid": cid,
                "deterministic": declaration["deterministic"],
                "kind": declaration["kind"],
                "name": name,
                "packagedName": packaged_name,
                "platform": platform
                if declaration["platform"] == "builder-platform"
                else declaration["platform"],
                "repository": repository,
                "sha256": digest,
                "size": size,
            }
        )
    return sorted(result, key=lambda item: canonical_key(item["name"]))


def prepare_output_directory(path: Path) -> Path:
    require(path.is_absolute(), "output directory must be absolute")
    require(not path.exists() and not path.is_symlink(), "output directory must not already exist")
    parent = path.parent.resolve(strict=True)
    parent_metadata = parent.lstat()
    require(stat.S_ISDIR(parent_metadata.st_mode) and not parent.is_symlink(), "output parent must be a non-symlink directory")
    path.mkdir(mode=0o700, parents=False)
    return path.resolve(strict=True)


def write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def evidence_reference(raw: bytes) -> Dict[str, Any]:
    return content_reference(raw, RAW_CODEC)


def content_reference(raw: bytes, codec: int) -> Dict[str, Any]:
    digest = hashlib.sha256(raw).hexdigest()
    cid = cid_for_digest(codec, digest)
    return {"cid": cid, "sha256": digest, "size": len(raw)}


def generate_evidence(args: argparse.Namespace) -> Dict[str, Any]:
    plan_path = Path(args.plan).expanduser().resolve(strict=True)
    plan = validate_plan(load_json(plan_path, "build plan"))
    target = target_by_id(plan, args.target)
    roots = parse_repository_roots(args.repository_root)
    required_roots = set(target["sourceRepositories"])
    require(set(roots) == required_roots, "--repository-root names must exactly match the selected target")
    source_cids = parse_assignments(args.source_cid, "source CID")
    require(set(source_cids) == required_roots, "--source-cid names must exactly match the selected target")
    for name, cid in source_cids.items():
        validate_cid(cid, DAG_CBOR_CODEC, f"source CID for {name}")
    source_cars = parse_regular_file_assignments(
        args.source_car, "source CAR", MAX_ARTIFACT_BYTES
    )
    exclusions = parse_regular_file_assignments(
        args.artifact_exclusions, "artifact exclusions", MAX_JSON_BYTES
    )
    source_verifier = Path(args.source_verifier).expanduser()
    source_verification = verify_source_bindings(
        roots,
        source_cids,
        source_cars,
        source_verifier,
        args.source_verifier_sha256,
        exclusions,
    )
    result_input = load_json(Path(args.result_record).expanduser().resolve(strict=True), "build-result record")
    result_record = validate_result_record(result_input, target, plan, source_cids)
    requested_output = Path(args.output_dir).expanduser()
    require(requested_output.is_absolute(), "output directory must be absolute")
    output_parent = requested_output.parent.resolve(strict=True)
    output_candidate = output_parent / requested_output.name
    for repository, root in roots.items():
        require(
            output_candidate != root and root not in output_candidate.parents,
            f"output directory must be outside source repository {repository}",
        )
    output_dir = prepare_output_directory(requested_output)

    command_results = verify_logs(
        Path(args.logs_dir).expanduser().resolve(strict=True),
        result_record["commands"],
        target["dependencyFetchCommandCount"],
        output_dir,
    )
    test_results = {
        "schemaVersion": 1,
        "passed": all(command["exitCode"] == 0 for command in command_results),
        "redactionPolicy": result_record["redactionPolicy"],
        "sourceCids": source_cids,
        "target": target["id"],
        "commands": command_results,
    }
    test_results_raw = canonical_json(test_results)
    write_new(output_dir / "test-results.json", test_results_raw)

    lock_evidence, sbom = verify_locks_and_build_sbom(plan, target, roots, source_cids)
    sbom_raw = canonical_json(sbom)
    write_new(output_dir / "sbom.cdx.json", sbom_raw)

    artifacts = verify_artifacts(
        target,
        roots,
        parse_assignments(args.artifact, "artifact"),
        output_dir,
        result_record["platform"],
        result_record["architecture"],
    )
    final_source_verification = verify_source_bindings(
        roots,
        source_cids,
        source_cars,
        source_verifier,
        args.source_verifier_sha256,
        exclusions,
    )
    require(
        final_source_verification == source_verification,
        "source verification changed while build evidence was assembled",
    )
    source_verification_raw = canonical_json(source_verification)
    write_new(output_dir / "source-verification.json", source_verification_raw)

    plan_raw = canonical_json(plan)
    toolchain_locks_raw = canonical_dag_cbor_string_map(plan["toolchains"])
    toolchain_locks = content_reference(toolchain_locks_raw, DAG_CBOR_CODEC)
    write_new(output_dir / "toolchain-locks.dag-cbor", toolchain_locks_raw)
    environment = {
        "schemaVersion": 1,
        "architecture": result_record["architecture"],
        "cleanRoom": result_record["cleanRoom"],
        "containerImageDigest": result_record["containerImageDigest"],
        "dependencyFetchSeparated": result_record["dependencyFetchSeparated"],
        "dependencyFetchCommandCount": target["dependencyFetchCommandCount"],
        "isolationKind": result_record["isolationKind"],
        "networkDisabledAfterFetch": result_record["networkDisabledAfterFetch"],
        "osFamily": result_record["osFamily"],
        "plan": evidence_reference(plan_raw),
        "platform": result_record["platform"],
        "readOnlySources": result_record["readOnlySources"],
        "resourceLimits": result_record["resourceLimits"],
        "sourceVerification": evidence_reference(source_verification_raw),
        "sourceDateEpoch": plan["sourceDateEpoch"],
        "toolchains": result_record["toolchains"],
    }
    environment_raw = canonical_json(environment)
    write_new(output_dir / "build-environment.json", environment_raw)
    core_digest = core_artifact_set_digest(artifacts)
    evidence = {
        "schemaVersion": 1,
        "artifacts": artifacts,
        "buildEnvironment": evidence_reference(environment_raw),
        "buildPlan": evidence_reference(plan_raw),
        "coreArtifactDigest": core_digest,
        "dependencyLocks": lock_evidence,
        "forkReleaseId": plan["forkReleaseId"],
        "limitations": target["limitations"],
        "planId": plan["planId"],
        "reproducibility": target["reproducibility"],
        "sbom": evidence_reference(sbom_raw),
        "sourceVerification": evidence_reference(source_verification_raw),
        "sourceCids": [
            {"repository": name, "sourceCid": source_cids[name]}
            for name in sorted(source_cids, key=canonical_key)
        ],
        "status": "verified-local-build-evidence",
        "target": target["id"],
        "testResults": evidence_reference(test_results_raw),
        "toolchainLocks": toolchain_locks,
    }
    evidence_raw = canonical_json(evidence)
    write_new(output_dir / "build-evidence.json", evidence_raw)

    digest_lines = []
    for name in sorted(
        ["build-environment.json", "sbom.cdx.json", "source-verification.json", "test-results.json", "toolchain-locks.dag-cbor"]
        + [entry.name for entry in output_dir.iterdir() if entry.name.endswith(".tar")]
        + [entry.name for entry in output_dir.iterdir() if re.fullmatch(r"[0-9]{3}\.(?:stdout|stderr)\.log", entry.name)],
        key=canonical_key,
    ):
        digest, _ = file_digest(output_dir / name)
        digest_lines.append(f"{digest}  {name}\n")
    write_new(output_dir / "SHA256SUMS", "".join(digest_lines).encode("utf-8"))
    return {
        "buildEvidence": evidence_reference(evidence_raw),
        "coreArtifactDigest": core_digest,
        "outputDirectory": str(output_dir),
        "sbom": evidence["sbom"],
        "sourceVerification": evidence["sourceVerification"],
        "target": target["id"],
        "testResults": evidence["testResults"],
        "toolchain": evidence["toolchainLocks"],
    }


def command_line() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-plan", help="validate a deterministic build plan")
    validate.add_argument("--plan", required=True)

    generate = subparsers.add_parser("generate", help="verify and package build evidence")
    generate.add_argument("--plan", required=True)
    generate.add_argument("--target", required=True)
    generate.add_argument("--repository-root", action="append", default=[], metavar="NAME=ABSOLUTE_PATH")
    generate.add_argument("--source-cid", action="append", default=[], metavar="NAME=CID")
    generate.add_argument("--source-car", action="append", default=[], metavar="NAME=ABSOLUTE_PATH")
    generate.add_argument("--source-verifier", required=True)
    generate.add_argument("--source-verifier-sha256", required=True)
    generate.add_argument("--artifact-exclusions", action="append", default=[], metavar="NAME=ABSOLUTE_PATH")
    generate.add_argument("--artifact", action="append", default=[], metavar="NAME=ABSOLUTE_PATH")
    generate.add_argument("--result-record", required=True)
    generate.add_argument("--logs-dir", required=True)
    generate.add_argument("--output-dir", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = command_line().parse_args(argv)
    try:
        if args.command == "validate-plan":
            plan = validate_plan(load_json(Path(args.plan).expanduser().resolve(strict=True), "build plan"))
            print(json.dumps({"planId": plan["planId"], "targets": [target["id"] for target in plan["targets"]], "valid": True}, sort_keys=True))
        else:
            print(json.dumps(generate_evidence(args), sort_keys=True))
        return 0
    except (EvidenceError, OSError) as exc:
        print(f"build evidence error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
