#!/usr/bin/env python3
"""Verify the fail-closed Experiment 1 public-join launch policy."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_JSON_BYTES = 1024 * 1024
MAX_CAR_BYTES = 4 * 1024 * 1024
MAX_READINESS_EVIDENCE_CAR_BYTES = 16 * 1024 * 1024
MAX_CAR_HEADER_BYTES = 4 * 1024
MAX_CBOR_DEPTH = 32
MAX_CBOR_ITEMS = 1024
SCHEMA = "pohw-experiment-launch-policy/v1"
EXPERIMENT_ID = "pohw-experiment-1-full-consensus"
BLOCKED_STATUS = "blocked-release-readiness"
READY_STATUS = "ready-for-public-join"
REGISTRY_DEPLOYMENT_SCHEMA = "pohw-idena-registry-deployment-finality/v1"
READINESS_BOOLEAN_FIELDS = (
    "exact_source_commit_published",
    "canonical_source_cid_published",
    "deterministic_car_digest_published",
    "release_build_evidence_published",
    "external_security_review_passed",
    "registry_deployment_finalized",
    "immutable_v2_anchor_policy_published",
    "independent_second_node_rehearsal_passed",
)
SHA256_HEX_LENGTH = 64
CID_BYTES_PREFIX = bytes((1, 0x71, 0x12, 32))
READINESS_REPORT_FIELDS = frozenset(
    {
        "schemaVersion",
        "evidenceBundleCid",
        "candidateEcosystemCid",
        "scopeEvidenceCid",
        "riskClass",
        "ready",
        "builderThreshold",
        "matchingBuilderCount",
        "builderPlatformThreshold",
        "matchingBuilderPlatformCount",
        "selectedCoreArtifactDigest",
        "availabilityThreshold",
        "completeAvailabilityCount",
        "externalAuditThreshold",
        "passingExternalAuditCount",
        "requiredContentCidCount",
        "failureCodes",
    }
)
READINESS_VERIFICATION_FIELDS = frozenset(
    {
        "schemaVersion",
        "evidenceBundleCid",
        "reportCid",
        "reportSha256",
        "report",
    }
)
IDENA_ANCHOR_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "registry_contract_address",
        "registry_deployment_tx_hash",
        "registry_deployment_payload_sha256",
        "registry_contract_code_hash",
        "registry_contract_wasm_sha256",
        "registry_ecosystem_cid",
        "minimum_registration_burn_atoms",
        "activation_idena_height",
        "finality_confirmations",
        "max_anchor_age_blocks",
        "handoff_version_bit",
    }
)
REGISTRY_DEPLOYMENT_FIELDS = frozenset(
    {
        "schema_version",
        "idena_anchor_policy_sha256",
        "registry_contract_address",
        "registry_deployment_tx_hash",
        "deployment_block_hash",
        "deployment_block_height",
        "finalized_block_hash",
        "finalized_block_height",
        "observed_registry_experiment_id",
        "observed_registry_ecosystem_cid",
        "observed_minimum_registration_burn_atoms",
    }
)


class LaunchPolicyError(ValueError):
    pass


class CborCid:
    __slots__ = ("raw",)

    def __init__(self, raw: bytes):
        self.raw = raw


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LaunchPolicyError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_regular_file(path: Path, label: str, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise LaunchPolicyError(f"{label} must be a regular non-symlink file")
        if metadata.st_size > maximum:
            raise LaunchPolicyError(f"{label} exceeds its size limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise LaunchPolicyError(f"{label} changed before it was opened")
            chunks = bytearray()
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > maximum:
                    raise LaunchPolicyError(f"{label} exceeds its size limit")
            closed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            closed.st_dev,
            closed.st_ino,
            closed.st_size,
            closed.st_mtime_ns,
        ) or len(chunks) != opened.st_size:
            raise LaunchPolicyError(f"{label} changed while it was read")
        return bytes(chunks)
    except LaunchPolicyError:
        raise
    except OSError as exc:
        raise LaunchPolicyError(f"cannot read {label}: {exc}") from exc


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_file(path, label, MAX_JSON_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except LaunchPolicyError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LaunchPolicyError(f"cannot decode {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise LaunchPolicyError(f"{label} root must be an object")
    return value, raw


def resolve_repo_file(repo_root: Path, raw_path: Any, label: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
        raise LaunchPolicyError(f"{label} must be a non-empty repository path")
    relative = Path(raw_path)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise LaunchPolicyError(f"{label} is not a safe repository path")
    root = repo_root.resolve(strict=True)
    candidate = root.joinpath(relative)
    resolved_parent = candidate.parent.resolve(strict=True)
    if resolved_parent != root and root not in resolved_parent.parents:
        raise LaunchPolicyError(f"{label} escapes the repository")
    return candidate


def require_bool(mapping: dict[str, Any], key: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise LaunchPolicyError(f"{key} must be a boolean")
    return value


def require_positive_int(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise LaunchPolicyError(f"{key} must be a positive integer")
    return value


def require_nonnegative_int(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LaunchPolicyError(f"{key} must be a non-negative integer")
    return value


def require_bounded_uint(
    mapping: dict[str, Any], key: str, maximum: int, *, positive: bool = False
) -> int:
    value = mapping.get(key)
    minimum = 1 if positive else 0
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        qualifier = "positive " if positive else ""
        raise LaunchPolicyError(f"{key} must be a {qualifier}bounded unsigned integer")
    return value


def require_exact_keys(mapping: dict[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(mapping)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise LaunchPolicyError(f"{label} fields are invalid: {'; '.join(details)}")


def require_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise LaunchPolicyError(f"{label} must be a non-empty string")
    return value


def require_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise LaunchPolicyError(f"{label} must be a lowercase SHA-256")
    return value


def require_prefixed_hex(value: Any, byte_length: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 2 + byte_length * 2
        or not value.startswith("0x")
        or any(character not in "0123456789abcdef" for character in value[2:])
        or all(character == "0" for character in value[2:])
    ):
        raise LaunchPolicyError(f"{label} must be a nonzero canonical {byte_length}-byte hash")
    return value


def require_positive_decimal(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 39
        or value[0] not in "123456789"
        or any(character not in "0123456789" for character in value)
    ):
        raise LaunchPolicyError(f"{label} must be a positive canonical decimal")
    return value


def require_canonical_dag_cbor_cid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("b") or value != value.lower():
        raise LaunchPolicyError(f"{label} must be a canonical base32 CIDv1")
    encoded = value[1:]
    try:
        padding = "=" * ((8 - len(encoded) % 8) % 8)
        raw = base64.b32decode((encoded + padding).upper(), casefold=False)
    except (binascii.Error, ValueError) as exc:
        raise LaunchPolicyError(f"{label} is not valid base32") from exc
    if len(raw) != 36 or raw[:4] != CID_BYTES_PREFIX:
        raise LaunchPolicyError(f"{label} must use DAG-CBOR and SHA2-256")
    canonical = "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    if canonical != value:
        raise LaunchPolicyError(f"{label} is not canonically encoded")
    return value


def cid_text(raw: bytes, label: str) -> str:
    if len(raw) != 36 or raw[:4] != CID_BYTES_PREFIX:
        raise LaunchPolicyError(f"{label} must use canonical DAG-CBOR CIDv1/SHA2-256")
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def decode_cbor_argument(data: bytes, offset: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, offset
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths.get(additional)
    if width is None or offset + width > len(data):
        raise LaunchPolicyError("DAG-CBOR contains an invalid or truncated length")
    value = int.from_bytes(data[offset : offset + width], "big")
    minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]
    if value < minimum:
        raise LaunchPolicyError("DAG-CBOR contains a non-canonical integer encoding")
    return value, offset + width


def decode_cbor_item(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_CBOR_DEPTH or offset >= len(data):
        raise LaunchPolicyError("DAG-CBOR is truncated or exceeds its depth limit")
    initial = data[offset]
    offset += 1
    major = initial >> 5
    additional = initial & 0x1F

    if major == 7:
        if additional == 20:
            return False, offset
        if additional == 21:
            return True, offset
        if additional == 22:
            return None, offset
        raise LaunchPolicyError("DAG-CBOR contains a forbidden simple or floating value")

    argument, offset = decode_cbor_argument(data, offset, additional)
    if major == 0:
        return argument, offset
    if major == 1:
        return -1 - argument, offset
    if major in (2, 3):
        end = offset + argument
        if end > len(data):
            raise LaunchPolicyError("DAG-CBOR contains a truncated string")
        encoded = data[offset:end]
        if major == 2:
            return encoded, end
        try:
            return encoded.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise LaunchPolicyError("DAG-CBOR contains invalid UTF-8") from exc
    if major == 4:
        if argument > MAX_CBOR_ITEMS:
            raise LaunchPolicyError("DAG-CBOR array exceeds its item limit")
        values = []
        for _ in range(argument):
            value, offset = decode_cbor_item(data, offset, depth + 1)
            values.append(value)
        return values, offset
    if major == 5:
        if argument > MAX_CBOR_ITEMS:
            raise LaunchPolicyError("DAG-CBOR map exceeds its item limit")
        result: dict[str, Any] = {}
        previous_key_encoding: bytes | None = None
        for _ in range(argument):
            key_start = offset
            key, offset = decode_cbor_item(data, offset, depth + 1)
            key_encoding = data[key_start:offset]
            if not isinstance(key, str):
                raise LaunchPolicyError("DAG-CBOR map keys must be strings")
            if previous_key_encoding is not None and previous_key_encoding >= key_encoding:
                raise LaunchPolicyError("DAG-CBOR map keys are not in canonical order")
            if key in result:
                raise LaunchPolicyError(f"duplicate DAG-CBOR map key: {key}")
            value, offset = decode_cbor_item(data, offset, depth + 1)
            result[key] = value
            previous_key_encoding = key_encoding
        return result, offset
    if major == 6:
        if argument != 42:
            raise LaunchPolicyError("DAG-CBOR contains a forbidden tag")
        value, offset = decode_cbor_item(data, offset, depth + 1)
        if not isinstance(value, bytes) or len(value) < 2 or value[0] != 0:
            raise LaunchPolicyError("DAG-CBOR CID tag is invalid")
        return CborCid(value[1:]), offset
    raise LaunchPolicyError("DAG-CBOR contains an unsupported value")


def decode_dag_cbor(data: bytes, label: str) -> Any:
    value, offset = decode_cbor_item(data, 0, 0)
    if offset != len(data):
        raise LaunchPolicyError(f"{label} DAG-CBOR has trailing data")
    return value


def read_uvarint(data: bytes, offset: int, label: str) -> tuple[int, int]:
    result = 0
    for index in range(10):
        if offset >= len(data):
            raise LaunchPolicyError(f"{label} contains a truncated varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise LaunchPolicyError(f"{label} contains an overflowing varint")
        result |= (byte & 0x7F) << (index * 7)
        if byte & 0x80 == 0:
            if index > 0 and result < 1 << (index * 7):
                raise LaunchPolicyError(f"{label} contains a non-minimal varint")
            return result, offset
    raise LaunchPolicyError(f"{label} contains an overflowing varint")


def load_single_block_dag_cbor_car(
    path: Path, label: str, maximum: int
) -> tuple[bytes, str, Any, bytes]:
    raw = read_regular_file(path, label, maximum)
    header_length, offset = read_uvarint(raw, 0, label)
    if header_length < 1 or header_length > MAX_CAR_HEADER_BYTES:
        raise LaunchPolicyError(f"{label} header length is invalid")
    header_end = offset + header_length
    if header_end > len(raw):
        raise LaunchPolicyError(f"{label} header is truncated")
    header = decode_dag_cbor(raw[offset:header_end], "CAR header")
    if not isinstance(header, dict) or frozenset(header) != frozenset({"roots", "version"}):
        raise LaunchPolicyError(f"{label} header is not strict CARv1")
    roots = header.get("roots")
    if header.get("version") != 1 or not isinstance(roots, list) or len(roots) != 1:
        raise LaunchPolicyError(f"{label} must declare exactly one root")
    root = roots[0]
    if not isinstance(root, CborCid):
        raise LaunchPolicyError(f"{label} root is not a CID")
    root_text = cid_text(root.raw, f"{label} root")

    section_length, section_offset = read_uvarint(
        raw, header_end, label
    )
    section_end = section_offset + section_length
    if section_length <= len(root.raw) or section_end > len(raw):
        raise LaunchPolicyError(f"{label} block is invalid")
    if section_end != len(raw):
        raise LaunchPolicyError(
            f"{label} must contain exactly one root block"
        )
    block_cid = raw[section_offset : section_offset + len(root.raw)]
    if block_cid != root.raw:
        raise LaunchPolicyError(f"{label} root block must be first")
    block = raw[section_offset + len(root.raw) : section_end]
    recomputed_root = CID_BYTES_PREFIX + hashlib.sha256(block).digest()
    if recomputed_root != root.raw:
        raise LaunchPolicyError(f"{label} root CID does not match its block")
    value = decode_dag_cbor(block, label)
    return raw, root_text, value, block


def load_readiness_car(path: Path) -> tuple[bytes, str, dict[str, Any], bytes]:
    raw, root_text, report, block = load_single_block_dag_cbor_car(
        path, "deployment-readiness report CAR", MAX_CAR_BYTES
    )
    if not isinstance(report, dict):
        raise LaunchPolicyError("deployment-readiness report root must be an object")
    return raw, root_text, report, block


def validate_readiness_report(report: dict[str, Any], expected_candidate: str) -> None:
    require_exact_keys(report, READINESS_REPORT_FIELDS, "deployment-readiness report")
    if require_bounded_uint(report, "schemaVersion", 65535) != 1:
        raise LaunchPolicyError("deployment-readiness report schemaVersion must be 1")
    require_canonical_dag_cbor_cid(
        report.get("evidenceBundleCid"),
        "deployment-readiness evidence bundle CID",
    )
    candidate = require_canonical_dag_cbor_cid(
        report.get("candidateEcosystemCid"),
        "deployment-readiness report candidate ecosystem CID",
    )
    if candidate != expected_candidate:
        raise LaunchPolicyError(
            "deployment-readiness report is bound to a different candidate ecosystem"
        )
    require_canonical_dag_cbor_cid(
        report.get("scopeEvidenceCid"), "deployment-readiness report scope evidence CID"
    )
    if report.get("riskClass") not in {"normal", "critical", "consensus", "migration"}:
        raise LaunchPolicyError("deployment-readiness report riskClass is invalid")
    if report.get("ready") is not True:
        raise LaunchPolicyError("deployment-readiness report is not ready")

    thresholds = (
        ("builderThreshold", "matchingBuilderCount"),
        ("builderPlatformThreshold", "matchingBuilderPlatformCount"),
        ("availabilityThreshold", "completeAvailabilityCount"),
        ("externalAuditThreshold", "passingExternalAuditCount"),
    )
    for threshold_key, count_key in thresholds:
        threshold = require_bounded_uint(report, threshold_key, (1 << 32) - 1, positive=True)
        count = require_bounded_uint(report, count_key, (1 << 32) - 1)
        if count < threshold:
            raise LaunchPolicyError(
                f"deployment-readiness report {count_key} is below {threshold_key}"
            )
    require_bounded_uint(
        report, "requiredContentCidCount", (1 << 32) - 1, positive=True
    )
    require_sha256(
        report.get("selectedCoreArtifactDigest"),
        "deployment-readiness selected core artifact digest",
    )
    if report.get("failureCodes") != []:
        raise LaunchPolicyError("ready deployment-readiness report has failure codes")


def verify_readiness_evidence(
    readiness: dict[str, Any],
    readiness_car_path: Path | None,
    readiness_evidence_car_path: Path | None,
    governance_cli_path: Path | None,
) -> tuple[bool, str | None]:
    report_fields = (
        readiness.get("deployment_readiness_report_cid"),
        readiness.get("deployment_readiness_report_car_sha256"),
        readiness.get("deployment_readiness_candidate_ecosystem_cid"),
        readiness.get("deployment_readiness_evidence_cid"),
        readiness.get("deployment_readiness_evidence_car_sha256"),
    )
    if all(value is None for value in report_fields):
        return False, None
    if any(value is None for value in report_fields):
        raise LaunchPolicyError("deployment-readiness evidence is incomplete")
    expected_cid = require_canonical_dag_cbor_cid(
        report_fields[0], "deployment-readiness report CID"
    )
    expected_car_sha256 = require_sha256(
        report_fields[1], "deployment-readiness report CAR SHA-256"
    )
    expected_candidate = require_canonical_dag_cbor_cid(
        report_fields[2], "deployment-readiness candidate ecosystem CID"
    )
    if readiness_car_path is None:
        raise LaunchPolicyError("deployment-readiness report CAR path is required")
    if readiness_evidence_car_path is None:
        raise LaunchPolicyError("deployment-readiness evidence CAR path is required")
    if governance_cli_path is None:
        raise LaunchPolicyError("pohw-governance verifier path is required")
    car_bytes, root_cid, report, report_block = load_readiness_car(readiness_car_path)
    if hashlib.sha256(car_bytes).hexdigest() != expected_car_sha256:
        raise LaunchPolicyError("deployment-readiness report CAR SHA-256 does not match")
    if root_cid != expected_cid:
        raise LaunchPolicyError("deployment-readiness report root CID does not match")
    validate_readiness_report(report, expected_candidate)

    expected_evidence_cid = require_canonical_dag_cbor_cid(
        report_fields[3], "deployment-readiness evidence CID"
    )
    expected_evidence_car_sha256 = require_sha256(
        report_fields[4], "deployment-readiness evidence CAR SHA-256"
    )
    evidence_bytes, evidence_cid, _, _ = load_single_block_dag_cbor_car(
        readiness_evidence_car_path,
        "deployment-readiness evidence CAR",
        MAX_READINESS_EVIDENCE_CAR_BYTES,
    )
    if hashlib.sha256(evidence_bytes).hexdigest() != expected_evidence_car_sha256:
        raise LaunchPolicyError("deployment-readiness evidence CAR SHA-256 does not match")
    if evidence_cid != expected_evidence_cid:
        raise LaunchPolicyError("deployment-readiness evidence root CID does not match")
    if report["evidenceBundleCid"] != evidence_cid:
        raise LaunchPolicyError("deployment-readiness report does not bind the evidence CAR")

    try:
        metadata = governance_cli_path.lstat()
    except OSError as exc:
        raise LaunchPolicyError("pohw-governance verifier is unavailable") from exc
    if (
        not governance_cli_path.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o111 == 0
    ):
        raise LaunchPolicyError(
            "pohw-governance verifier must be an absolute executable regular non-symlink file"
        )
    try:
        result = subprocess.run(
            [
                str(governance_cli_path),
                "deployment-readiness-evidence-verify",
                "--car",
                str(readiness_evidence_car_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LaunchPolicyError("pohw-governance readiness verifier could not run") from exc
    if result.returncode != 0:
        raise LaunchPolicyError("pohw-governance rejected the readiness evidence")
    if len(result.stdout.encode("utf-8")) > MAX_JSON_BYTES:
        raise LaunchPolicyError("pohw-governance readiness output exceeds its size limit")
    try:
        verification = json.loads(result.stdout, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LaunchPolicyError("pohw-governance returned invalid readiness JSON") from exc
    if not isinstance(verification, dict):
        raise LaunchPolicyError("pohw-governance readiness output must be an object")
    require_exact_keys(
        verification, READINESS_VERIFICATION_FIELDS, "pohw-governance readiness output"
    )
    if require_bounded_uint(verification, "schemaVersion", 65535) != 1:
        raise LaunchPolicyError("pohw-governance readiness schemaVersion must be 1")
    if (
        verification.get("evidenceBundleCid") != evidence_cid
        or verification.get("reportCid") != root_cid
        or verification.get("reportSha256") != hashlib.sha256(report_block).hexdigest()
        or verification.get("report") != report
    ):
        raise LaunchPolicyError(
            "pohw-governance recomputed readiness does not match the bound report"
        )
    return True, expected_candidate


def validate_idena_anchor_policy(
    anchor: dict[str, Any],
    policy: dict[str, Any],
    candidate: dict[str, Any],
    artifact: dict[str, Any],
    expected_candidate: str,
) -> None:
    require_exact_keys(anchor, IDENA_ANCHOR_POLICY_FIELDS, "Idena anchor policy")
    if require_bounded_uint(anchor, "schema_version", 65535) != 2:
        raise LaunchPolicyError("Idena anchor policy schema_version must be 2")
    if policy.get("idena_anchor_policy_schema") != 2:
        raise LaunchPolicyError("launch policy must require Idena anchor policy schema 2")
    experiment_id = require_string(anchor, "experiment_id", "registry experiment ID")
    if (
        len(experiment_id) > 64
        or experiment_id != experiment_id.lower()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789._:/-"
            for character in experiment_id
        )
        or experiment_id != candidate.get("experiment_id")
    ):
        raise LaunchPolicyError("Idena anchor policy registry experiment ID is invalid")
    require_prefixed_hex(
        anchor.get("registry_contract_address"), 20, "registry contract address"
    )
    require_prefixed_hex(
        anchor.get("registry_deployment_tx_hash"),
        32,
        "registry deployment transaction hash",
    )
    require_sha256(
        anchor.get("registry_deployment_payload_sha256"),
        "registry deployment payload SHA-256",
    )
    require_sha256(anchor.get("registry_contract_code_hash"), "registry contract code hash")
    wasm_sha256 = require_sha256(
        anchor.get("registry_contract_wasm_sha256"), "registry contract WASM SHA-256"
    )
    if wasm_sha256 != artifact.get("sha256"):
        raise LaunchPolicyError("Idena anchor policy does not bind the reviewed registry WASM")
    ecosystem_cid = require_canonical_dag_cbor_cid(
        anchor.get("registry_ecosystem_cid"), "registry ecosystem CID"
    )
    if ecosystem_cid != expected_candidate:
        raise LaunchPolicyError("Idena anchor policy is bound to a different candidate ecosystem")
    require_positive_decimal(
        anchor.get("minimum_registration_burn_atoms"), "minimum registration burn"
    )
    require_bounded_uint(
        anchor, "activation_idena_height", (1 << 53) - 1, positive=True
    )
    finality = require_bounded_uint(anchor, "finality_confirmations", 1000, positive=True)
    max_age = require_bounded_uint(anchor, "max_anchor_age_blocks", 10000, positive=True)
    if max_age < finality:
        raise LaunchPolicyError("Idena anchor policy age window is below its finality depth")
    handoff_bit = require_bounded_uint(anchor, "handoff_version_bit", 28)
    if handoff_bit != policy.get("required_handoff_version_bit"):
        raise LaunchPolicyError("Idena anchor policy handoff bit does not match launch policy")


def verify_registry_deployment(
    deployment: Any,
    anchor_policy_path: Path | None,
    policy: dict[str, Any],
    candidate: dict[str, Any],
    artifact: dict[str, Any],
    expected_candidate: str | None,
) -> bool:
    if deployment is None:
        return False
    if not isinstance(deployment, dict):
        raise LaunchPolicyError("registry deployment evidence must be an object")
    require_exact_keys(deployment, REGISTRY_DEPLOYMENT_FIELDS, "registry deployment evidence")
    if deployment.get("schema_version") != REGISTRY_DEPLOYMENT_SCHEMA:
        raise LaunchPolicyError("unexpected registry deployment evidence schema")
    if expected_candidate is None:
        raise LaunchPolicyError(
            "registry deployment evidence requires readiness candidate evidence"
        )
    if anchor_policy_path is None:
        raise LaunchPolicyError(
            "Idena anchor policy path is required for registry deployment evidence"
        )

    anchor, anchor_bytes = read_json(anchor_policy_path, "Idena anchor policy")
    expected_anchor_sha256 = require_sha256(
        deployment.get("idena_anchor_policy_sha256"), "Idena anchor policy SHA-256"
    )
    if hashlib.sha256(anchor_bytes).hexdigest() != expected_anchor_sha256:
        raise LaunchPolicyError("Idena anchor policy SHA-256 does not match deployment evidence")
    validate_idena_anchor_policy(anchor, policy, candidate, artifact, expected_candidate)

    for key, anchor_key, label in (
        ("registry_contract_address", "registry_contract_address", "registry contract address"),
        (
            "registry_deployment_tx_hash",
            "registry_deployment_tx_hash",
            "registry deployment transaction hash",
        ),
    ):
        expected_length = 20 if key == "registry_contract_address" else 32
        value = require_prefixed_hex(deployment.get(key), expected_length, label)
        if value != anchor.get(anchor_key):
            raise LaunchPolicyError(f"deployment evidence {label} does not match anchor policy")
    require_prefixed_hex(deployment.get("deployment_block_hash"), 32, "deployment block hash")
    require_prefixed_hex(deployment.get("finalized_block_hash"), 32, "finalized block hash")
    deployment_height = require_bounded_uint(
        deployment, "deployment_block_height", (1 << 53) - 1, positive=True
    )
    finalized_height = require_bounded_uint(
        deployment, "finalized_block_height", (1 << 53) - 1, positive=True
    )
    finality = anchor["finality_confirmations"]
    if finalized_height - deployment_height < finality:
        raise LaunchPolicyError("registry deployment block is not finalized by the evidence")
    if deployment_height >= anchor["activation_idena_height"]:
        raise LaunchPolicyError("registry deployment block must precede policy activation")

    observed_experiment = require_string(
        deployment,
        "observed_registry_experiment_id",
        "observed registry experiment ID",
    )
    observed_ecosystem = require_canonical_dag_cbor_cid(
        deployment.get("observed_registry_ecosystem_cid"),
        "observed registry ecosystem CID",
    )
    observed_burn = require_positive_decimal(
        deployment.get("observed_minimum_registration_burn_atoms"),
        "observed minimum registration burn",
    )
    if (
        observed_experiment != anchor["experiment_id"]
        or observed_ecosystem != anchor["registry_ecosystem_cid"]
        or observed_burn != anchor["minimum_registration_burn_atoms"]
    ):
        raise LaunchPolicyError("observed immutable registry parameters do not match anchor policy")
    return True


def validate(
    policy: dict[str, Any],
    policy_path: Path,
    repo_root: Path,
    readiness_car_path: Path | None = None,
    readiness_evidence_car_path: Path | None = None,
    governance_cli_path: Path | None = None,
    idena_anchor_policy_path: Path | None = None,
) -> None:
    if policy.get("schema_version") != SCHEMA:
        raise LaunchPolicyError("unexpected launch-policy schema")
    if policy.get("experiment_id") != EXPERIMENT_ID:
        raise LaunchPolicyError("unexpected experiment ID")

    manifest_path = resolve_repo_file(
        repo_root, policy.get("fork_manifest_path"), "fork manifest path"
    )
    manifest, manifest_bytes = read_json(manifest_path, "fork manifest")
    if manifest.get("experiment_id") != EXPERIMENT_ID:
        raise LaunchPolicyError("launch policy points to a different experiment")
    if policy.get("activation_id") != manifest.get("activation_id"):
        raise LaunchPolicyError("launch policy activation ID does not match the manifest")
    if policy.get("fork_manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
        raise LaunchPolicyError("launch policy does not bind the exact fork manifest")

    candidate_binding = policy.get("registry_source_candidate")
    if not isinstance(candidate_binding, dict):
        raise LaunchPolicyError("registry source candidate is missing")
    candidate_path = resolve_repo_file(
        repo_root, candidate_binding.get("path"), "registry candidate path"
    )
    candidate, candidate_bytes = read_json(candidate_path, "registry candidate")
    if candidate_binding.get("sha256") != hashlib.sha256(candidate_bytes).hexdigest():
        raise LaunchPolicyError("launch policy does not bind the exact registry candidate")
    artifact = candidate.get("artifact")
    if not isinstance(artifact, dict):
        raise LaunchPolicyError("registry candidate artifact is missing")
    for field in ("wasm_sha256", "wasm_cid"):
        artifact_field = "sha256" if field == "wasm_sha256" else "cid"
        if candidate_binding.get(field) != artifact.get(artifact_field):
            raise LaunchPolicyError(f"registry candidate {field} does not match its artifact")
    if not isinstance(candidate_binding.get("deployment_authorized"), bool):
        raise LaunchPolicyError("registry deployment authorization flag must be a boolean")
    if candidate_binding.get("contract_schema_version") != candidate.get(
        "contract_schema_version"
    ) or candidate_binding.get("contract_version") != candidate.get("contract_version"):
        raise LaunchPolicyError("registry candidate contract version binding is invalid")

    runtime_gates = policy.get("required_runtime_gates")
    if not isinstance(runtime_gates, dict):
        raise LaunchPolicyError("required runtime gates are missing")
    for key in (
        "idena_anchor_policy_required",
        "peer_work_template_admission_required",
        "registry_deployment_verification_required",
        "registry_registration_identity_callback_required",
        "checkpoint_vote_identity_callback_required",
        "production_idena_wasm_runtime_gate_required",
    ):
        if require_bool(runtime_gates, key) is not True:
            raise LaunchPolicyError(f"required runtime gate is disabled: {key}")
    if require_bool(runtime_gates, "bound_policy_replacement_allowed") is not False:
        raise LaunchPolicyError("bound policy replacement must remain disabled")

    readiness = policy.get("public_join_readiness")
    if not isinstance(readiness, dict):
        raise LaunchPolicyError("public-join readiness evidence is missing")
    readiness_values = [require_bool(readiness, key) for key in READINESS_BOOLEAN_FIELDS]
    if require_bool(readiness, "external_security_review_required") is not True:
        raise LaunchPolicyError("external security review must remain required")
    required_builders = require_positive_int(
        readiness, "required_independent_registry_build_operators"
    )
    verified_builders = require_nonnegative_int(
        readiness, "verified_independent_registry_build_operators"
    )
    matching_builds = require_nonnegative_int(readiness, "matching_registry_builds_observed")
    if required_builders < 2:
        raise LaunchPolicyError("at least two independent registry build operators are required")
    if verified_builders > matching_builds:
        raise LaunchPolicyError("independent builder count exceeds matching build count")

    readiness_report_bound, readiness_candidate = verify_readiness_evidence(
        readiness,
        readiness_car_path,
        readiness_evidence_car_path,
        governance_cli_path,
    )
    deployment_finalized = verify_registry_deployment(
        policy.get("registry_deployment"),
        idena_anchor_policy_path,
        policy,
        candidate,
        artifact,
        readiness_candidate,
    )
    if require_bool(readiness, "registry_deployment_finalized") != deployment_finalized:
        raise LaunchPolicyError(
            "registry deployment finality flag does not match verified deployment evidence"
        )
    ready = (
        all(readiness_values)
        and verified_builders >= required_builders
        and readiness_report_bound
        and deployment_finalized
        and candidate_binding.get("deployment_authorized") is True
    )
    status = policy.get("status")
    if ready and status != READY_STATUS:
        raise LaunchPolicyError("all public-join gates pass but policy status is not ready")
    if not ready and status != BLOCKED_STATUS:
        raise LaunchPolicyError("public joining must remain blocked while any gate is incomplete")

    if policy_path.resolve(strict=True).parent != repo_root.resolve(strict=True) / "compatibility":
        raise LaunchPolicyError(
            "launch policy must come from the repository compatibility directory"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--readiness-car",
        type=Path,
        help="canonical DeploymentReadinessReportV1 CAR bound by the launch policy",
    )
    parser.add_argument(
        "--readiness-evidence-car",
        type=Path,
        help="canonical authenticated DeploymentReadinessEvidenceV1 CAR",
    )
    parser.add_argument(
        "--governance-cli",
        type=Path,
        help="exact pohw-governance binary used to recompute readiness evidence",
    )
    parser.add_argument(
        "--idena-anchor-policy",
        type=Path,
        help="installed IdenaAnchorPolicyV2 bound by finalized deployment evidence",
    )
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="fail unless the verified policy is ready for public joining",
    )
    args = parser.parse_args()
    try:
        policy, _ = read_json(args.policy, "launch policy")
        validate(
            policy,
            args.policy,
            args.repo_root,
            args.readiness_car,
            args.readiness_evidence_car,
            args.governance_cli,
            args.idena_anchor_policy,
        )
        if args.require_ready and policy.get("status") != READY_STATUS:
            raise LaunchPolicyError("launch requires ready-for-public-join status")
        print(f"launch policy verified: {policy['status']}")
        return 0
    except LaunchPolicyError as exc:
        print(f"launch policy verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
