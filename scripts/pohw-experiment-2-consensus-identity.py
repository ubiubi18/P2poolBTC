#!/usr/bin/env python3
"""Verify the inactive Experiment 2 consensus-identity candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path, PurePosixPath
from typing import Any


POLICY_TAG = b"P2POOLBTC_IDENA_AUTH_POLICY_V1"
ACTIVATION_TAG = b"P2POOLBTC_IDENA_AUTH_ACTIVATION_V1"
LEAF_TAG = b"P2POOLBTC_IDENA_AUTH_LEAF_V1"
NODE_TAG = b"P2POOLBTC_IDENA_AUTH_NODE_V1"
EXPECTED_UPSTREAM_COMMIT = "9be056a8a72b624dae9623b2f7bded92c2a21c91"
EXPECTED_POLICY_HASH = "4f727128f49d0f4cd1e1fcca85cbfcb5b9b5f0f3877787be8d33f4c0384d5ab3"
EXPECTED_ROOT = "2430c7f7ab395c27c67ed7d4bfc6e55f4db2cbd72ce8dc1876b1c5ebc9411e38"
EXPECTED_ACTIVATION_ID = "194a60f81ecf2719d4c47b129311a181b81172d3e1742b2b3f4c53707d2d499f"
EXPECTED_PREDECESSOR = "86dfc3ff2736717781cdf007727bfc6bc3ec56a87f27a1d09703885adca434d8"
EXPECTED_INPUT_PATHS = {
    "activation_manifest": "compatibility/experiment-2-consensus-identity-candidate.json",
    "authorization_fixture": "compatibility/experiment-2-consensus-identity-authorization.fixture.json",
    "authorization_schema": "schemas/pohw/ConsensusIdentityAuthorizationV1.schema.json",
    "activation_schema": "schemas/pohw/ConsensusIdentityActivationManifestV1.schema.json",
    "policy": "compatibility/experiment-2-consensus-identity-policy.fixture.json",
    "policy_schema": "schemas/pohw/ConsensusIdentityPolicyV1.schema.json",
    "snapshot_input_schema": "schemas/pohw/ConsensusIdentitySnapshotInputV1.schema.json",
    "snapshot_bundle_schema": "schemas/pohw/ConsensusIdentitySnapshotBundleV1.schema.json",
    "snapshot_verification_schema": "schemas/pohw/ConsensusIdentitySnapshotVerificationV1.schema.json",
    "snapshot_comparison_schema": "schemas/pohw/ConsensusIdentitySnapshotComparisonV1.schema.json",
    "build_comparison_schema": "schemas/pohw/Experiment2BuildComparisonV1.schema.json",
    "snapshot_comparison_tool": "scripts/pohw-compare-idena-snapshots.py",
    "build_comparison_tool": "scripts/pohw-compare-bitcoin-core-builds.py",
    "build_evidence_tool": "scripts/pohw-bitcoin-core-build-evidence.py",
    "clean_room_builder": "scripts/pohw-build-bitcoin-core-fork.sh",
    "source_verifier": "scripts/pohw-verify-bitcoin-core-source.sh",
}
HEX = re.compile(r"^[0-9a-f]+$")
IDENTIFIER = re.compile(r"^[a-z0-9._/-]+$")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_LOCKED_FILE_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_SECONDS = 31 * 24 * 60 * 60
PATCH_SERIES_TAG = b"P2POOLBTC_BITCOIN_CORE_PATCH_SERIES_V1"


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise VerificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_regular_file(path: Path, maximum: int) -> bytes:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), f"input must be a regular file: {path}")
            require(before.st_size <= maximum, f"input is too large: {path}")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                require(bool(chunk), f"input was truncated while reading: {path}")
                chunks.append(chunk)
                remaining -= len(chunk)
            require(not os.read(descriptor, 1), f"input grew while reading: {path}")
            after = os.fstat(descriptor)
            require(
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                f"input changed while reading: {path}",
            )
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise VerificationError(f"cannot read input {path}: {exc}") from exc


def read_json(path: Path) -> dict[str, Any]:
    try:
        raw = read_regular_file(path, MAX_JSON_BYTES)
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read JSON {path}: {exc}") from exc
    require(isinstance(value, dict), f"JSON root must be an object: {path}")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(actual == expected, f"{label} keys differ: missing={sorted(expected - actual)} extra={sorted(actual - expected)}")


def tagged_hash(tag: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(tag + b"\0" + payload).digest()


def hex_bytes(value: Any, size: int, label: str, prefixed: bool = False) -> bytes:
    require(isinstance(value, str), f"{label} must be a string")
    if prefixed:
        require(value.startswith("0x"), f"{label} must use lowercase 0x prefix")
        value = value[2:]
    require(len(value) == size * 2 and HEX.fullmatch(value) is not None, f"{label} must be canonical lowercase {size}-byte hex")
    return bytes.fromhex(value)


def bounded_ascii(value: Any, maximum: int, label: str) -> bytes:
    require(isinstance(value, str), f"{label} must be a string")
    raw = value.encode("ascii", errors="strict")
    require(0 < len(raw) <= maximum and IDENTIFIER.fullmatch(value) is not None, f"{label} must be bounded canonical lowercase ASCII")
    return bytes([len(raw)]) + raw


def bool_byte(value: Any, label: str) -> bytes:
    require(type(value) is bool, f"{label} must be a boolean")
    return bytes([int(value)])


def uint(value: Any, bits: int, label: str) -> int:
    require(type(value) is int and 0 <= value < 1 << bits, f"{label} must be an unsigned {bits}-bit integer")
    return value


def policy_hash(policy: dict[str, Any]) -> str:
    exact_keys(
        policy,
        {
            "schema_version", "experiment_id", "bitcoin_network",
            "bitcoin_fork_activation_id", "share_work_activation_id",
            "registry_contract_address", "idena_finalized_height",
            "idena_finalized_timestamp", "idena_finalized_block_hash",
            "idena_next_validation_timestamp", "authorization_root",
            "authorized_identity_count", "bitcoin_activation_height",
            "bitcoin_expiry_height", "bitcoin_expiry_mtp", "max_proof_depth",
            "require_share_work_commitment",
        },
        "policy",
    )
    schema = uint(policy["schema_version"], 16, "policy.schema_version")
    require(schema == 1, "policy.schema_version must be 1")
    payload = bytearray(struct.pack("<H", schema))
    payload += bounded_ascii(policy["experiment_id"], 64, "policy.experiment_id")
    payload += bounded_ascii(policy["bitcoin_network"], 32, "policy.bitcoin_network")
    payload += hex_bytes(policy["bitcoin_fork_activation_id"], 32, "policy.bitcoin_fork_activation_id")
    payload += hex_bytes(policy["share_work_activation_id"], 32, "policy.share_work_activation_id")
    payload += hex_bytes(policy["registry_contract_address"], 20, "policy.registry_contract_address", True)
    finalized_height = uint(policy["idena_finalized_height"], 64, "policy.idena_finalized_height")
    require(finalized_height > 0, "policy.idena_finalized_height must be positive")
    payload += struct.pack("<Q", finalized_height)
    finalized_timestamp = uint(policy["idena_finalized_timestamp"], 64, "policy.idena_finalized_timestamp")
    next_validation_timestamp = uint(policy["idena_next_validation_timestamp"], 64, "policy.idena_next_validation_timestamp")
    require(
        finalized_timestamp > 0
        and finalized_timestamp < next_validation_timestamp
        and next_validation_timestamp - finalized_timestamp <= MAX_SNAPSHOT_SECONDS,
        "policy Idena snapshot time window is invalid",
    )
    payload += struct.pack("<Q", finalized_timestamp)
    payload += hex_bytes(policy["idena_finalized_block_hash"], 32, "policy.idena_finalized_block_hash", True)
    payload += struct.pack("<Q", next_validation_timestamp)
    payload += hex_bytes(policy["authorization_root"], 32, "policy.authorization_root")
    count = uint(policy["authorized_identity_count"], 32, "policy.authorized_identity_count")
    require(count > 0, "policy.authorized_identity_count must be positive")
    require(count <= (1 << 16), "policy.authorized_identity_count exceeds the canonical tree capacity")
    payload += struct.pack("<I", count)
    activation = uint(policy["bitcoin_activation_height"], 64, "policy.bitcoin_activation_height")
    expiry = uint(policy["bitcoin_expiry_height"], 64, "policy.bitcoin_expiry_height")
    require(activation > 0 and expiry >= activation, "policy Bitcoin height window is invalid")
    payload += struct.pack("<QQ", activation, expiry)
    expiry_mtp = uint(policy["bitcoin_expiry_mtp"], 64, "policy.bitcoin_expiry_mtp")
    require(
        finalized_timestamp < expiry_mtp <= next_validation_timestamp,
        "policy Bitcoin MTP expiry is outside the Idena snapshot window",
    )
    payload += struct.pack("<Q", expiry_mtp)
    depth = uint(policy["max_proof_depth"], 8, "policy.max_proof_depth")
    require(depth <= 16, "policy.max_proof_depth exceeds 16")
    require((count - 1).bit_length() <= depth, "policy.max_proof_depth is too small for the authorization set")
    payload += bytes([depth])
    require(policy["require_share_work_commitment"] is True, "policy must require P2SW1")
    payload += bool_byte(policy["require_share_work_commitment"], "policy.require_share_work_commitment")
    return tagged_hash(POLICY_TAG, bytes(payload)).hex()


def leaf_hash(leaf: dict[str, Any]) -> bytes:
    exact_keys(
        leaf,
        {
            "idena_address", "identity_state", "mining_pubkey_xonly",
            "registry_commitment", "registration_sequence",
            "registration_block", "registration_epoch",
        },
        "authorization leaf",
    )
    states = {"Verified": 3, "Newbie": 7, "Human": 8}
    require(leaf["identity_state"] in states, "authorization leaf identity is ineligible")
    payload = bytearray(hex_bytes(leaf["idena_address"], 20, "leaf.idena_address", True))
    payload += bytes([states[leaf["identity_state"]]])
    payload += hex_bytes(leaf["mining_pubkey_xonly"], 32, "leaf.mining_pubkey_xonly")
    payload += hex_bytes(leaf["registry_commitment"], 32, "leaf.registry_commitment")
    sequence = uint(leaf["registration_sequence"], 32, "leaf.registration_sequence")
    block = uint(leaf["registration_block"], 64, "leaf.registration_block")
    epoch = uint(leaf["registration_epoch"], 16, "leaf.registration_epoch")
    require(sequence > 0 and block > 0, "authorization registration sequence and block must be positive")
    payload += struct.pack("<IQH", sequence, block, epoch)
    require(len(payload) == 99, "authorization leaf encoding length changed")
    return tagged_hash(LEAF_TAG, bytes(payload))


def verify_authorization(policy: dict[str, Any], authorization: dict[str, Any]) -> None:
    exact_keys(authorization, {"schema_version", "policy_hash", "leaf", "proof", "block_signature_hex"}, "authorization")
    require(authorization["schema_version"] == 1, "authorization.schema_version must be 1")
    expected_policy = policy_hash(policy)
    require(authorization["policy_hash"] == expected_policy, "authorization policy hash mismatch")
    proof = authorization["proof"]
    require(isinstance(proof, dict), "authorization proof must be an object")
    exact_keys(proof, {"leaf_index", "siblings"}, "authorization proof")
    index = uint(proof["leaf_index"], 32, "proof.leaf_index")
    require(index < policy["authorized_identity_count"], "proof leaf index is outside the authorization set")
    siblings = proof["siblings"]
    required_depth = (policy["authorized_identity_count"] - 1).bit_length()
    require(
        isinstance(siblings, list)
        and len(siblings) == required_depth
        and len(siblings) <= policy["max_proof_depth"],
        "proof depth is invalid",
    )
    current = leaf_hash(authorization["leaf"])
    for position, sibling in enumerate(siblings):
        sibling_hash = hex_bytes(sibling, 32, f"proof.siblings[{position}]")
        pair = current + sibling_hash if index & 1 == 0 else sibling_hash + current
        current = tagged_hash(NODE_TAG, pair)
        index >>= 1
    require(index == 0 and current.hex() == policy["authorization_root"], "authorization Merkle proof mismatch")
    signature = hex_bytes(authorization["block_signature_hex"], 64, "authorization.block_signature_hex")
    require(signature == bytes(64), "inactive authorization fixture must not contain a reusable block signature")


def activation_id(manifest: dict[str, Any]) -> str:
    exact_keys(
        manifest,
        {
            "schema_version", "profile_revision", "status", "launch_enabled",
            "activation_id", "experiment_id", "predecessor_activation_id",
            "consensus_ruleset", "bitcoin_core_upstream_commit",
            "bitcoin_core_patch_series_sha256", "authorization_parent_height",
            "authorization_parent_hash",
            "bitcoin_network", "bitcoin_datadir", "p2p_port", "rpc_port",
            "message_start_hex", "consensus_policy_hash",
            "require_fresh_datadir", "history_reinterpreted",
        },
        "activation manifest",
    )
    payload = bytearray(struct.pack("<H", uint(manifest["profile_revision"], 16, "manifest.profile_revision")))
    payload += bounded_ascii(manifest["schema_version"], 64, "manifest.schema_version")
    payload += bounded_ascii(manifest["status"], 32, "manifest.status")
    payload += bool_byte(manifest["launch_enabled"], "manifest.launch_enabled")
    payload += bounded_ascii(manifest["experiment_id"], 64, "manifest.experiment_id")
    payload += hex_bytes(manifest["predecessor_activation_id"], 32, "manifest.predecessor_activation_id")
    payload += bounded_ascii(manifest["consensus_ruleset"], 64, "manifest.consensus_ruleset")
    payload += hex_bytes(manifest["bitcoin_core_upstream_commit"], 20, "manifest.bitcoin_core_upstream_commit")
    payload += hex_bytes(manifest["bitcoin_core_patch_series_sha256"], 32, "manifest.bitcoin_core_patch_series_sha256")
    parent_height = uint(manifest["authorization_parent_height"], 64, "manifest.authorization_parent_height")
    require(parent_height > 0, "manifest authorization parent height must be positive")
    payload += struct.pack("<Q", parent_height)
    payload += hex_bytes(manifest["authorization_parent_hash"], 32, "manifest.authorization_parent_hash")
    payload += bounded_ascii(manifest["bitcoin_network"], 32, "manifest.bitcoin_network")
    payload += bounded_ascii(manifest["bitcoin_datadir"], 64, "manifest.bitcoin_datadir")
    p2p = uint(manifest["p2p_port"], 16, "manifest.p2p_port")
    rpc = uint(manifest["rpc_port"], 16, "manifest.rpc_port")
    require(p2p > 0 and rpc > 0 and p2p != rpc, "manifest ports must be distinct and nonzero")
    payload += struct.pack("<HH", p2p, rpc)
    payload += hex_bytes(manifest["message_start_hex"], 4, "manifest.message_start_hex")
    payload += hex_bytes(manifest["consensus_policy_hash"], 32, "manifest.consensus_policy_hash")
    payload += bool_byte(manifest["require_fresh_datadir"], "manifest.require_fresh_datadir")
    payload += bool_byte(manifest["history_reinterpreted"], "manifest.history_reinterpreted")
    return tagged_hash(ACTIVATION_TAG, bytes(payload)).hex()


def safe_repo_path(root: Path, relative: Any) -> Path:
    require(isinstance(relative, str), "locked path must be a string")
    pure = PurePosixPath(relative)
    require(not pure.is_absolute() and ".." not in pure.parts and relative == pure.as_posix(), f"unsafe locked path: {relative}")
    target = root.joinpath(*pure.parts)
    require(target.resolve(strict=True) == target, f"locked path must not traverse symlinks: {relative}")
    info = target.lstat()
    require(stat.S_ISREG(info.st_mode), f"locked input must be a regular file: {relative}")
    return target


def file_sha256(path: Path) -> str:
    return hashlib.sha256(read_regular_file(path, MAX_LOCKED_FILE_BYTES)).hexdigest()


def patch_series_sha256(patches: list[dict[str, Any]]) -> str:
    payload = bytearray(PATCH_SERIES_TAG + b"\0")
    for expected_order, entry in enumerate(patches, 1):
        require(isinstance(entry, dict) and entry.get("order") == expected_order, "patch order is invalid")
        path = entry.get("path")
        require(isinstance(path, str), "patch path must be a string")
        payload += struct.pack("<I", expected_order)
        payload += bounded_ascii(path, 255, "patch path")
        payload += hex_bytes(entry.get("sha256"), 32, "patch sha256")
    return hashlib.sha256(payload).hexdigest()


def verify_lock(root: Path, lock: dict[str, Any], policy: dict[str, Any], manifest: dict[str, Any]) -> None:
    require(lock.get("schema_version") == "pohw-bitcoin-core-patch-series-lock/v1", "unexpected patch lock schema")
    require(lock.get("status") == "experimental-candidate-inactive" and lock.get("launch_enabled") is False, "Experiment 2 patch lock must remain inactive")
    require(lock.get("artifact_status") == "source-patch-only-no-release-artifacts", "patch lock must not claim release artifacts")
    upstream = lock.get("upstream")
    require(isinstance(upstream, dict) and upstream.get("commit") == EXPECTED_UPSTREAM_COMMIT, "upstream Bitcoin Core commit mismatch")
    patches = lock.get("patch_series")
    require(isinstance(patches, list) and len(patches) == 2, "patch lock must contain exactly two ordered patches")
    for expected_order, entry in enumerate(patches, 1):
        require(isinstance(entry, dict) and entry.get("order") == expected_order, "patch order is invalid")
        path = safe_repo_path(root, entry.get("path"))
        require(file_sha256(path) == entry.get("sha256"), f"patch SHA-256 mismatch: {entry.get('path')}")
    series_sha256 = patch_series_sha256(patches)
    require(lock.get("patch_series_sha256") == series_sha256, "patch-series SHA-256 mismatch")
    require(
        manifest["bitcoin_core_patch_series_sha256"] == series_sha256,
        "activation manifest does not bind the locked patch series",
    )
    require(
        manifest["bitcoin_core_upstream_commit"] == upstream["commit"],
        "activation manifest does not bind the locked upstream commit",
    )

    inputs = lock.get("profile_inputs")
    require(isinstance(inputs, dict) and set(inputs) == set(EXPECTED_INPUT_PATHS), "profile input lock is incomplete")
    for name, expected_path in EXPECTED_INPUT_PATHS.items():
        entry = inputs[name]
        require(isinstance(entry, dict) and entry.get("path") == expected_path, f"locked {name} path mismatch")
        path = safe_repo_path(root, expected_path)
        require(file_sha256(path) == entry.get("sha256"), f"locked {name} SHA-256 mismatch")

    network = lock.get("network")
    consensus = lock.get("consensus")
    require(isinstance(network, dict) and isinstance(consensus, dict), "lock network and consensus objects are required")
    require(network.get("chain_argument") == "pohw2" and network.get("require_fresh_datadir") is True, "lock must isolate pohw2 in a fresh datadir")
    require(network.get("candidate_activation_id") == manifest["activation_id"], "lock activation ID mismatch")
    require(network.get("authorization_parent_height") == manifest["authorization_parent_height"], "lock authorization parent height mismatch")
    require(network.get("authorization_parent_hash") == manifest["authorization_parent_hash"], "lock authorization parent hash mismatch")
    require(consensus.get("policy_hash") == policy_hash(policy), "lock policy hash mismatch")
    require(consensus.get("authorization_root") == policy["authorization_root"], "lock authorization root mismatch")
    require(consensus.get("expiry_mtp") == policy["bitcoin_expiry_mtp"], "lock MTP expiry mismatch")
    require(consensus.get("fixture_keys_only") is True, "candidate must identify fixture keys")

    snapshot_assurance = lock.get("snapshot_assurance")
    require(isinstance(snapshot_assurance, dict), "snapshot assurance policy is required")
    exact_keys(
        snapshot_assurance,
        {
            "capture_schema", "bundle_schema", "verification_schema",
            "comparison_schema", "minimum_finality_confirmations",
            "maximum_finality_confirmations", "minimum_matching_captures",
            "minimum_authenticated_operators", "require_matching_source_input_hash",
            "require_complete_identity_export", "require_complete_registry_export",
            "identity_rows_assurance", "identity_rows_cryptographically_bound_to_root",
            "require_finalized_state_replay_or_row_proofs_for_active_manifest",
            "active_release_allowed",
            "operator_independence_verified_by_comparator", "comparison_release_authorized",
        },
        "snapshot assurance",
    )
    require(
        snapshot_assurance == {
            "capture_schema": "pohw-consensus-identity-snapshot-input/v1",
            "bundle_schema": "pohw-consensus-identity-snapshot-bundle/v1",
            "verification_schema": "pohw-consensus-identity-snapshot-verification/v1",
            "comparison_schema": "pohw-consensus-identity-snapshot-comparison/v1",
            "minimum_finality_confirmations": 6,
            "maximum_finality_confirmations": 120,
            "minimum_matching_captures": 3,
            "minimum_authenticated_operators": 3,
            "require_matching_source_input_hash": True,
            "require_complete_identity_export": True,
            "require_complete_registry_export": True,
            "identity_rows_assurance": "compatible-rpc-unproven",
            "identity_rows_cryptographically_bound_to_root": False,
            "require_finalized_state_replay_or_row_proofs_for_active_manifest": True,
            "active_release_allowed": False,
            "operator_independence_verified_by_comparator": False,
            "comparison_release_authorized": False,
        },
        "snapshot assurance policy differs from the inactive candidate",
    )

    independent_builds = lock.get("independent_builds")
    require(isinstance(independent_builds, dict), "independent build policy is required")
    exact_keys(
        independent_builds,
        {
            "evidence_schema", "comparison_schema", "minimum_matching_builds",
            "minimum_authenticated_operators", "minimum_platform_families",
            "require_exact_source_snapshot", "require_exact_artifact_set",
            "require_complete_consensus_test_set",
            "operator_independence_verified_by_comparator", "comparison_release_authorized",
        },
        "independent builds",
    )
    require(
        independent_builds == {
            "evidence_schema": "pohw-bitcoin-core-build-evidence/v4",
            "comparison_schema": "pohw-experiment-2-build-comparison/v1",
            "minimum_matching_builds": 3,
            "minimum_authenticated_operators": 3,
            "minimum_platform_families": 2,
            "require_exact_source_snapshot": True,
            "require_exact_artifact_set": True,
            "require_complete_consensus_test_set": True,
            "operator_independence_verified_by_comparator": False,
            "comparison_release_authorized": False,
        },
        "independent build policy differs from the inactive candidate",
    )


def verify(root: Path, lock_path: Path) -> None:
    lock = read_json(lock_path)
    policy = read_json(root / EXPECTED_INPUT_PATHS["policy"])
    authorization = read_json(root / EXPECTED_INPUT_PATHS["authorization_fixture"])
    manifest = read_json(root / EXPECTED_INPUT_PATHS["activation_manifest"])

    computed_policy = policy_hash(policy)
    require(computed_policy == EXPECTED_POLICY_HASH, "policy fixed vector changed")
    require(policy["authorization_root"] == EXPECTED_ROOT, "authorization root fixed vector changed")
    verify_authorization(policy, authorization)
    computed_activation = activation_id(manifest)
    require(computed_activation == manifest["activation_id"] == EXPECTED_ACTIVATION_ID, "activation ID mismatch")
    require(manifest["status"] == "experimental-candidate" and manifest["launch_enabled"] is False, "candidate manifest must remain inactive")
    require(manifest["predecessor_activation_id"] == EXPECTED_PREDECESSOR, "predecessor activation mismatch")
    require(manifest["consensus_policy_hash"] == computed_policy, "manifest policy hash mismatch")
    require(manifest["bitcoin_network"] == "pohw2" and manifest["require_fresh_datadir"] is True and manifest["history_reinterpreted"] is False, "manifest does not isolate successor history")
    verify_lock(root, lock, policy, manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    lock = args.lock or root / "compatibility" / "experiment-2-bitcoin-core-patch-lock.json"
    if not lock.is_absolute():
        lock = root / lock
    try:
        verify(root, lock)
    except (OSError, UnicodeError, VerificationError) as exc:
        print(f"Experiment 2 verification failed: {exc}", file=sys.stderr)
        return 2
    print("inactive Experiment 2 consensus-identity candidate verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
