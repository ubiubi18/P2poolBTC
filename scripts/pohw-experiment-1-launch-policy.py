#!/usr/bin/env python3
"""Verify the fail-closed Experiment 1 public-join launch policy."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import Any


MAX_JSON_BYTES = 1024 * 1024
SCHEMA = "pohw-experiment-launch-policy/v1"
EXPERIMENT_ID = "pohw-experiment-1-full-consensus"
BLOCKED_STATUS = "blocked-release-readiness"
READY_STATUS = "ready-for-public-join"
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


class LaunchPolicyError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LaunchPolicyError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise LaunchPolicyError(f"{label} must be a regular non-symlink file")
        if metadata.st_size > MAX_JSON_BYTES:
            raise LaunchPolicyError(f"{label} exceeds 1 MiB")
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except LaunchPolicyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LaunchPolicyError(f"cannot read {label}: {exc}") from exc
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


def require_canonical_dag_cbor_cid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("b") or value != value.lower():
        raise LaunchPolicyError(f"{label} must be a canonical base32 CIDv1")
    encoded = value[1:]
    try:
        padding = "=" * ((8 - len(encoded) % 8) % 8)
        raw = base64.b32decode((encoded + padding).upper(), casefold=False)
    except (binascii.Error, ValueError) as exc:
        raise LaunchPolicyError(f"{label} is not valid base32") from exc
    if len(raw) != 36 or raw[:4] != bytes((1, 0x71, 0x12, 32)):
        raise LaunchPolicyError(f"{label} must use DAG-CBOR and SHA2-256")
    canonical = "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    if canonical != value:
        raise LaunchPolicyError(f"{label} is not canonically encoded")
    return value


def validate(policy: dict[str, Any], policy_path: Path, repo_root: Path) -> None:
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

    report_fields = (
        readiness.get("deployment_readiness_report_cid"),
        readiness.get("deployment_readiness_report_car_sha256"),
        readiness.get("deployment_readiness_candidate_ecosystem_cid"),
    )
    if all(value is None for value in report_fields):
        readiness_report_bound = False
    elif any(value is None for value in report_fields):
        raise LaunchPolicyError("deployment-readiness evidence is incomplete")
    else:
        require_canonical_dag_cbor_cid(
            report_fields[0], "deployment-readiness report CID"
        )
        if (
            not isinstance(report_fields[1], str)
            or len(report_fields[1]) != SHA256_HEX_LENGTH
            or any(character not in "0123456789abcdef" for character in report_fields[1])
        ):
            raise LaunchPolicyError("deployment-readiness report CAR SHA-256 is invalid")
        require_canonical_dag_cbor_cid(
            report_fields[2], "deployment-readiness candidate ecosystem CID"
        )
        readiness_report_bound = True

    registry_deployment = policy.get("registry_deployment")
    deployment_finalized = (
        isinstance(registry_deployment, dict)
        and registry_deployment.get("finalized") is True
    )
    ready = (
        all(readiness_values)
        and verified_builders >= required_builders
        and readiness_report_bound
        and deployment_finalized
    )
    status = policy.get("status")
    if ready and status != READY_STATUS:
        raise LaunchPolicyError("all public-join gates pass but policy status is not ready")
    if not ready and status != BLOCKED_STATUS:
        raise LaunchPolicyError("public joining must remain blocked while any gate is incomplete")

    if policy_path.resolve(strict=True).parent != repo_root.resolve(strict=True) / "compatibility":
        raise LaunchPolicyError("launch policy must come from the repository compatibility directory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        policy, _ = read_json(args.policy, "launch policy")
        validate(policy, args.policy, args.repo_root)
        print(f"launch policy verified: {policy['status']}")
        return 0
    except LaunchPolicyError as exc:
        print(f"launch policy verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
