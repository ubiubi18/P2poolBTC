#!/usr/bin/env python3
"""Run the guarded, source-first Experiment 1 community onboarding check.

This command is intentionally read-only. It never downloads software, registers an
identity, writes node configuration, starts services, or joins a network. A live
probe is available only after the independently verified launch policy is ready.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


PROFILE_SCHEMA = "pohw-community-onboarding-profile/v1"
RECEIPT_SCHEMA = "pohw-community-onboarding-receipt/v1"
EXPERIMENT_ID = "pohw-experiment-1-full-consensus"
BLOCKED_POLICY_STATUS = "blocked-release-readiness"
READY_POLICY_STATUS = "ready-for-public-join"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 300
MAX_CAR_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_CBOR_DEPTH = 32
MAX_CBOR_ITEMS = 16_384
MAX_CAR_HEADER_BYTES = 16 * 1024
SHA256_HEX_LENGTH = 64
COMMIT_HEX_LENGTH = 40
DAG_CBOR_CID_PREFIX = bytes((1, 0x71, 0x12, 32))
RAW_CID_PREFIX = bytes((1, 0x55, 0x12, 32))
SOURCE_REPOSITORY = "P2poolBTC"
REQUIRED_RUNTIME_ARTIFACTS = (
    "pohw-governance",
    "p2pool-node",
    "bitcoin-cli",
    "bitcoind",
)
STAGE_IDS = (
    "system-check",
    "release-verification",
    "identity-registration",
    "network-join",
    "success-proof",
)
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
READINESS_FIELDS = frozenset(
    set(READINESS_BOOLEAN_FIELDS)
    | {
        "required_independent_registry_build_operators",
        "verified_independent_registry_build_operators",
        "matching_registry_builds_observed",
        "external_security_review_required",
        "deployment_readiness_report_cid",
        "deployment_readiness_report_car_sha256",
        "deployment_readiness_candidate_ecosystem_cid",
        "deployment_readiness_evidence_cid",
        "deployment_readiness_evidence_car_sha256",
    }
)
RUNTIME_GATE_FIELDS = frozenset(
    {
        "idena_anchor_policy_required",
        "peer_work_template_admission_required",
        "registry_deployment_verification_required",
        "registry_registration_identity_callback_required",
        "checkpoint_vote_identity_callback_required",
        "production_idena_wasm_runtime_gate_required",
        "historical_replay_requires_finalized_checkpoint",
        "candidate_submission_identity_required",
        "bound_policy_replacement_allowed",
    }
)
IDENTITY_ADMISSION_SCOPE = {
    "p2pool_runtime_enforced": True,
    "bitcoin_block_consensus_enforced": False,
    "successor_consensus_profile_required": True,
}
PRIVACY_FLAGS = {
    "contains_identity_address": False,
    "contains_miner_id": False,
    "contains_peer_address": False,
    "contains_wallet_data": False,
    "contains_rpc_secret": False,
    "contains_local_path": False,
}
ACTION_LABELS = {
    "insufficient-cpu": "Use a host with more CPU cores for this role.",
    "memory-unverified": "Verify the host memory before continuing.",
    "insufficient-memory": "Use a host with more memory for this role.",
    "insufficient-storage": "Choose storage with more free space for this role.",
    "linux-required": "Use a Linux host for a live node role.",
    "systemd-required": "Use the reviewed systemd deployment profile.",
    "ssd-unverified": "Use SSD-backed storage and make it verifiable to the checker.",
    "commands-missing": "Install the missing source-build tools shown in the receipt.",
    "storage-path-unavailable": "Use an existing readable storage root on the writable filesystem the node will actually use.",
    "use-clean-exact-source": "Start again from a clean checkout of the exact candidate revision.",
    "verify-fork-manifest": "Resolve the Experiment 1 manifest verification failure.",
    "verify-launch-policy": "Resolve the launch-policy verification failure.",
    "pass-focused-tests": "Run and pass the focused locked Rust test suite.",
    "review-experiment-and-report-findings": "Review the source and submit the generated redacted issue template if you find a problem.",
    "exact-source-commit-published": "Wait for an exact release commit to be published and independently checked.",
    "canonical-source-cid-published": "Wait for the canonical source CID to be published and independently checked.",
    "candidate-ecosystem-car-required": "Obtain the DAO-authorized candidate ecosystem CAR from independent public IPFS sources.",
    "expected-ecosystem-cid-required": "Obtain the canonical ecosystem CID from the Idena governance contract through an independent source.",
    "source-car-required": "Obtain the exact P2poolBTC source CAR named by the candidate ecosystem manifest.",
    "canonical-source-verification": "Verify that this checkout reproduces the candidate ecosystem source CID.",
    "attested-runtime-artifacts": "Use runtime executables whose digests match the candidate ecosystem manifest.",
    "deterministic-car-digest-published": "Wait for the deterministic CAR digest to be published and independently checked.",
    "release-build-evidence-published": "Wait for reproducible release-build evidence.",
    "external-security-review-passed": "Wait for the required independent security review to pass.",
    "registry-deployment-finalized": "Wait for finalized Idena registry deployment evidence.",
    "registry-chain-verification": "Verify the exact registry deployment through a synchronized loopback Idena RPC before registering an identity.",
    "immutable-v2-anchor-policy-published": "Wait for the immutable V2 Idena anchor policy.",
    "independent-second-node-rehearsal-passed": "Wait for a successful independent second-node rehearsal.",
    "independent-registry-build-operators": "Wait for enough independent matching registry builds.",
    "registry-deployment-authorization": "Wait for the release policy to authorize registry deployment.",
    "complete-local-identity-ownership-registration": "Follow the reviewed identity-ownership registration step; sign only the exact public challenge.",
    "restore-pohw-core-readiness": "Restore the isolated PoHW Bitcoin Core node to a fully synchronized state.",
    "verify-pinned-checkpoint": "Verify the exact pinned replay-domain checkpoint in local Core.",
    "complete-identity-registration": "Complete and locally verify miner identity registration.",
    "install-verified-idena-snapshot": "Install and verify the required Idena accounting snapshot.",
    "wait-for-accepted-bitcoin-template": "Wait until the local node accepts a Bitcoin work template.",
    "wait-for-share-tip": "Wait until the locally verified sharechain has a tip.",
    "wait-for-fresh-miner-share": "Submit and locally verify a recent active share from this registered miner.",
    "restore-fresh-core-tip": "Synchronize local PoHW Core and restore a recent fully verified tip.",
    "connect-bitcoin-peer": "Connect local PoHW Core to at least one fork-network peer.",
    "verify-core-consensus-profile": "Run the exact attested Experiment 1 Core profile on loopback RPC.",
    "verify-local-core-service": "Run the attested bitcoind executable through the reviewed systemd unit.",
    "connect-independent-gossip-peer": "Connect at least one independently verified gossip peer.",
    "submit-accepted-share": "Submit and locally verify at least one accepted share.",
    "keep-redacted-receipt-and-monitor-node": "Keep this redacted receipt and continue monitoring local Core and sharechain progress.",
}
ROLE_FIELDS = frozenset(
    {
        "live_join",
        "minimum_cpu_cores",
        "minimum_memory_gib",
        "minimum_free_storage_gib",
        "requires_linux",
        "requires_systemd",
        "requires_ssd",
        "required_command_groups",
    }
)
EXPECTED_ROLE_REQUIREMENTS = {
    "observer": {
        "live_join": False,
        "minimum_cpu_cores": 2,
        "minimum_memory_gib": 4,
        "minimum_free_storage_gib": 5,
        "requires_linux": False,
        "requires_systemd": False,
        "requires_ssd": False,
        "required_command_groups": [["git"], ["python3"]],
    },
    "pruned-miner": {
        "live_join": True,
        "minimum_cpu_cores": 4,
        "minimum_memory_gib": 16,
        "minimum_free_storage_gib": 100,
        "requires_linux": True,
        "requires_systemd": True,
        "requires_ssd": True,
        "required_command_groups": [
            ["git"],
            ["cargo"],
            ["python3"],
            ["cmake"],
            ["ninja"],
            ["c++", "g++", "clang++"],
            ["systemctl"],
        ],
    },
    "archive-operator": {
        "live_join": True,
        "minimum_cpu_cores": 4,
        "minimum_memory_gib": 16,
        "minimum_free_storage_gib": 900,
        "requires_linux": True,
        "requires_systemd": True,
        "requires_ssd": True,
        "required_command_groups": [
            ["git"],
            ["cargo"],
            ["python3"],
            ["cmake"],
            ["ninja"],
            ["c++", "g++", "clang++"],
            ["systemctl"],
        ],
    },
}
EXPECTED_LIVE_SUCCESS = {
    "checkpoint_height": 958175,
    "checkpoint_hash": "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6",
    "rpc_port": 40414,
    "minimum_bitcoin_peers": 1,
    "minimum_reachable_gossip_peers": 1,
    "minimum_active_shares": 1,
    "minimum_miner_active_shares": 1,
    "maximum_miner_share_age_seconds": 3600,
    "maximum_core_tip_age_seconds": 7200,
    "maximum_future_clock_skew_seconds": 300,
    "minimum_snapshot_voters": 3,
    "require_registered_miner": True,
    "require_verified_snapshot": True,
    "require_accepted_bitcoin_template": True,
}


class OnboardingError(ValueError):
    """A fail-closed onboarding validation error."""


class CborCid:
    __slots__ = ("raw",)

    def __init__(self, raw: bytes):
        self.raw = raw


class StagedExecutable:
    __slots__ = ("command_path", "pass_fds")

    def __init__(self, command_path: str, pass_fds: tuple[int, ...] = ()):
        self.command_path = command_path
        self.pass_fds = pass_fds


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OnboardingError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular_file(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise OnboardingError(f"{label} must be a regular non-symlink file")
        if before.st_size > maximum:
            raise OnboardingError(f"{label} exceeds its size limit")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise OnboardingError(f"{label} changed before it was opened")
            chunks = bytearray()
            while True:
                remaining = maximum + 1 - len(chunks)
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > maximum:
                    raise OnboardingError(f"{label} exceeds its size limit")
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
            raise OnboardingError(f"{label} changed while it was read")
        return bytes(chunks)
    except OnboardingError:
        raise
    except OSError as exc:
        raise OnboardingError(f"cannot read {label}: {exc}") from exc


def _hash_regular_file(path: Path, label: str, maximum: int = MAX_ARTIFACT_BYTES) -> tuple[str, int]:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise OnboardingError(f"{label} must be a regular non-symlink file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise OnboardingError(f"{label} size is outside the accepted range")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        digest = hashlib.sha256()
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise OnboardingError(f"{label} changed before it was opened")
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise OnboardingError(f"{label} exceeds its size limit")
                digest.update(chunk)
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
        ) or total != opened.st_size:
            raise OnboardingError(f"{label} changed while it was read")
        return digest.hexdigest(), total
    except OnboardingError:
        raise
    except OSError as exc:
        raise OnboardingError(f"cannot hash {label}: {exc}") from exc


def _write_all(descriptor: int, value: bytes, label: str) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OnboardingError(f"cannot stage {label}")
        offset += written


def _copy_attested_executable(
    source: Path, target_descriptor: int, label: str, expected: Mapping[str, Any]
) -> None:
    expected_digest = expected.get("sha256")
    expected_size = expected.get("size")
    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in expected_digest)
        or not _is_positive_int(expected_size)
        or expected_size > MAX_ARTIFACT_BYTES
    ):
        raise OnboardingError(f"{label} has an invalid candidate ecosystem binding")
    try:
        before = source.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o111 == 0
        ):
            raise OnboardingError(f"{label} must be an executable regular non-symlink file")
        if before.st_size != expected_size:
            raise OnboardingError(f"{label} does not match the candidate ecosystem artifact")
        source_descriptor = os.open(
            source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        digest = hashlib.sha256()
        try:
            opened = os.fstat(source_descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise OnboardingError(f"{label} changed before it was opened")
            total = 0
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    raise OnboardingError(f"{label} exceeds its size limit")
                digest.update(chunk)
                _write_all(target_descriptor, chunk, label)
            closed = os.fstat(source_descriptor)
        finally:
            os.close(source_descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (closed.st_dev, closed.st_ino, closed.st_size, closed.st_mtime_ns)
            or total != opened.st_size
        ):
            raise OnboardingError(f"{label} changed while it was staged")
        if digest.hexdigest() != expected_digest or total != expected_size:
            raise OnboardingError(f"{label} does not match the candidate ecosystem artifact")
        os.fchmod(target_descriptor, 0o500)
        os.fsync(target_descriptor)
        os.lseek(target_descriptor, 0, os.SEEK_SET)
    except OnboardingError:
        raise
    except OSError as exc:
        raise OnboardingError(f"cannot stage {label}: {exc}") from exc


@contextlib.contextmanager
def _stage_attested_executable(
    source: Path, label: str, expected: Mapping[str, Any]
) -> Iterator[StagedExecutable]:
    if platform.system() == "Linux":
        if not hasattr(os, "memfd_create"):
            raise OnboardingError("Linux kernel cannot create an immutable executable snapshot")
        try:
            import fcntl

            descriptor = os.memfd_create(
                "pohw-attested-executable",
                getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
            )
            try:
                _copy_attested_executable(source, descriptor, label, expected)
                seals = (
                    getattr(fcntl, "F_SEAL_SEAL", 0x0001)
                    | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                    | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                    | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
                )
                fcntl.fcntl(descriptor, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
                yield StagedExecutable(f"/proc/self/fd/{descriptor}", (descriptor,))
            finally:
                os.close(descriptor)
        except OnboardingError:
            raise
        except (ImportError, OSError) as exc:
            raise OnboardingError(f"cannot create an immutable snapshot for {label}: {exc}") from exc
        return

    raise OnboardingError(
        "immutable attested executable snapshots are supported only on Linux"
    )


def _read_json(path: Path, label: str) -> dict[str, Any]:
    raw = _read_regular_file(path, label)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except OnboardingError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OnboardingError(f"cannot decode {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise OnboardingError(f"{label} root must be an object")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual == expected:
        return
    missing = ", ".join(sorted(expected - actual))
    unknown = ", ".join(sorted(actual - expected))
    details = []
    if missing:
        details.append(f"missing {missing}")
    if unknown:
        details.append(f"unknown {unknown}")
    raise OnboardingError(f"{label} fields are invalid: {'; '.join(details)}")


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_positive_int(value: Any) -> bool:
    return _is_nonnegative_int(value) and value > 0


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_profile_cid(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 59
        and value.startswith(prefix)
        and all(character in "abcdefghijklmnopqrstuvwxyz234567" for character in value[1:])
    )


def _is_dag_cbor_cid(value: Any) -> bool:
    return _is_profile_cid(value, "bafyrei")


def _is_raw_cid(value: Any) -> bool:
    return _is_profile_cid(value, "bafkrei")


def _cid_text(raw: bytes, *, codec_prefix: bytes, label: str) -> str:
    if len(raw) != 36 or raw[:4] != codec_prefix:
        raise OnboardingError(f"{label} has an unsupported CID profile")
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def _decode_cbor_argument(data: bytes, offset: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, offset
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths.get(additional)
    if width is None or offset + width > len(data):
        raise OnboardingError("DAG-CBOR contains an invalid or truncated length")
    value = int.from_bytes(data[offset : offset + width], "big")
    minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]
    if value < minimum:
        raise OnboardingError("DAG-CBOR contains a non-canonical integer encoding")
    return value, offset + width


def _decode_cbor_item(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_CBOR_DEPTH or offset >= len(data):
        raise OnboardingError("DAG-CBOR is truncated or exceeds its depth limit")
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
        raise OnboardingError("DAG-CBOR contains a forbidden simple or floating value")
    argument, offset = _decode_cbor_argument(data, offset, additional)
    if major == 0:
        return argument, offset
    if major == 1:
        return -1 - argument, offset
    if major in (2, 3):
        end = offset + argument
        if end > len(data):
            raise OnboardingError("DAG-CBOR contains a truncated string")
        encoded = data[offset:end]
        if major == 2:
            return encoded, end
        try:
            return encoded.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise OnboardingError("DAG-CBOR contains invalid UTF-8") from exc
    if major == 4:
        if argument > MAX_CBOR_ITEMS:
            raise OnboardingError("DAG-CBOR array exceeds its item limit")
        values = []
        for _ in range(argument):
            value, offset = _decode_cbor_item(data, offset, depth + 1)
            values.append(value)
        return values, offset
    if major == 5:
        if argument > MAX_CBOR_ITEMS:
            raise OnboardingError("DAG-CBOR map exceeds its item limit")
        result: dict[str, Any] = {}
        previous_key_encoding: bytes | None = None
        for _ in range(argument):
            key_start = offset
            key, offset = _decode_cbor_item(data, offset, depth + 1)
            key_encoding = data[key_start:offset]
            if not isinstance(key, str):
                raise OnboardingError("DAG-CBOR map keys must be strings")
            if previous_key_encoding is not None and previous_key_encoding >= key_encoding:
                raise OnboardingError("DAG-CBOR map keys are not in canonical order")
            if key in result:
                raise OnboardingError(f"duplicate DAG-CBOR map key: {key}")
            value, offset = _decode_cbor_item(data, offset, depth + 1)
            result[key] = value
            previous_key_encoding = key_encoding
        return result, offset
    if major == 6:
        if argument != 42:
            raise OnboardingError("DAG-CBOR contains a forbidden tag")
        value, offset = _decode_cbor_item(data, offset, depth + 1)
        if not isinstance(value, bytes) or len(value) < 2 or value[0] != 0:
            raise OnboardingError("DAG-CBOR CID tag is invalid")
        return CborCid(value[1:]), offset
    raise OnboardingError("DAG-CBOR contains an unsupported value")


def _read_uvarint(data: bytes, offset: int, label: str) -> tuple[int, int]:
    result = 0
    for index in range(10):
        if offset >= len(data):
            raise OnboardingError(f"{label} contains a truncated varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise OnboardingError(f"{label} contains an overflowing varint")
        result |= (byte & 0x7F) << (index * 7)
        if byte & 0x80 == 0:
            if index > 0 and result < 1 << (index * 7):
                raise OnboardingError(f"{label} contains a non-minimal varint")
            return result, offset
    raise OnboardingError(f"{label} contains an overflowing varint")


def _load_single_block_dag_cbor_car(
    path: Path, label: str
) -> tuple[str, str, dict[str, Any]]:
    raw = _read_regular_file(path, label, MAX_CAR_BYTES)
    header_length, offset = _read_uvarint(raw, 0, label)
    if header_length < 1 or header_length > MAX_CAR_HEADER_BYTES:
        raise OnboardingError(f"{label} header length is invalid")
    header_end = offset + header_length
    if header_end > len(raw):
        raise OnboardingError(f"{label} header is truncated")
    header, decoded = _decode_cbor_item(raw[offset:header_end], 0, 0)
    if decoded != header_length or not isinstance(header, dict):
        raise OnboardingError(f"{label} header is invalid")
    _require_exact_keys(header, frozenset({"roots", "version"}), f"{label} header")
    roots = header.get("roots")
    if header.get("version") != 1 or not isinstance(roots, list) or len(roots) != 1:
        raise OnboardingError(f"{label} must declare exactly one root")
    root = roots[0]
    if not isinstance(root, CborCid):
        raise OnboardingError(f"{label} root is not a CID")
    root_text = _cid_text(root.raw, codec_prefix=DAG_CBOR_CID_PREFIX, label=f"{label} root")
    section_length, section_offset = _read_uvarint(raw, header_end, label)
    section_end = section_offset + section_length
    if section_length <= len(root.raw) or section_end != len(raw):
        raise OnboardingError(f"{label} must contain exactly one complete root block")
    block_cid = raw[section_offset : section_offset + len(root.raw)]
    block = raw[section_offset + len(root.raw) : section_end]
    if block_cid != root.raw or DAG_CBOR_CID_PREFIX + hashlib.sha256(block).digest() != root.raw:
        raise OnboardingError(f"{label} root block does not match its CID")
    value, decoded = _decode_cbor_item(block, 0, 0)
    if decoded != len(block) or not isinstance(value, dict):
        raise OnboardingError(f"{label} root must be one canonical DAG-CBOR object")
    return root_text, root.raw[4:].hex(), value


def _extract_ecosystem_bindings(
    car_path: Path, expected_ecosystem_cid: str
) -> dict[str, Any]:
    ecosystem_cid, ecosystem_sha256, manifest = _load_single_block_dag_cbor_car(
        car_path, "candidate ecosystem CAR"
    )
    if ecosystem_cid != expected_ecosystem_cid:
        raise OnboardingError("candidate ecosystem CAR does not match the launch-policy CID")
    _require_exact_keys(
        manifest,
        frozenset(
            {
                "schemaVersion",
                "ecosystemId",
                "parentEcosystemCid",
                "repositories",
                "compatibilityPins",
                "toolchainLocks",
                "governanceContractVersion",
                "governanceParameterSetCid",
            }
        ),
        "candidate ecosystem manifest",
    )
    ecosystem_id = manifest.get("ecosystemId")
    if (
        manifest.get("schemaVersion") != 1
        or not isinstance(ecosystem_id, str)
        or not 3 <= len(ecosystem_id) <= 80
        or ecosystem_id[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in ecosystem_id
        )
    ):
        raise OnboardingError("candidate ecosystem manifest identifies a different ecosystem")
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list):
        raise OnboardingError("candidate ecosystem repository list is invalid")
    matches = [item for item in repositories if isinstance(item, dict) and item.get("name") == SOURCE_REPOSITORY]
    if len(matches) != 1:
        raise OnboardingError("candidate ecosystem must contain P2poolBTC exactly once")
    repository = matches[0]
    _require_exact_keys(
        repository,
        frozenset(
            {
                "schemaVersion",
                "name",
                "sourceTreeCid",
                "sourceTreeSha256",
                "gitBundleCid",
                "gitCommitMetadata",
                "dependencyLocks",
                "toolchainLocks",
                "buildInstructions",
                "artifacts",
            }
        ),
        "candidate P2poolBTC repository manifest",
    )
    source_link = repository.get("sourceTreeCid")
    source_sha256 = repository.get("sourceTreeSha256")
    if not isinstance(source_link, CborCid) or not _is_sha256(source_sha256):
        raise OnboardingError("candidate P2poolBTC source binding is invalid")
    source_cid = _cid_text(
        source_link.raw, codec_prefix=DAG_CBOR_CID_PREFIX, label="P2poolBTC source CID"
    )
    if source_link.raw[4:].hex() != source_sha256:
        raise OnboardingError("P2poolBTC source CID and SHA-256 disagree")
    commit = repository.get("gitCommitMetadata")
    if commit is not None and (
        not isinstance(commit, str)
        or len(commit) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise OnboardingError("candidate P2poolBTC Git metadata is invalid")
    artifacts = repository.get("artifacts")
    if not isinstance(artifacts, list):
        raise OnboardingError("candidate P2poolBTC artifact list is invalid")
    artifacts_by_name: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise OnboardingError("candidate P2poolBTC artifact entry is invalid")
        _require_exact_keys(
            artifact, frozenset({"name", "cid", "sha256", "size"}), "candidate artifact"
        )
        name = artifact.get("name")
        cid = artifact.get("cid")
        sha256 = artifact.get("sha256")
        size = artifact.get("size")
        if (
            not isinstance(name, str)
            or not name
            or name in artifacts_by_name
            or not isinstance(cid, CborCid)
            or not _is_sha256(sha256)
            or not _is_positive_int(size)
        ):
            raise OnboardingError("candidate P2poolBTC artifact binding is invalid")
        cid_text = _cid_text(cid.raw, codec_prefix=RAW_CID_PREFIX, label=f"artifact {name} CID")
        if cid.raw[4:].hex() != sha256:
            raise OnboardingError(f"artifact {name} CID and SHA-256 disagree")
        artifacts_by_name[name] = {"cid": cid_text, "sha256": sha256, "size": size}
    missing_artifacts = sorted(set(REQUIRED_RUNTIME_ARTIFACTS) - set(artifacts_by_name))
    if missing_artifacts:
        raise OnboardingError(
            "candidate ecosystem omits required runtime artifacts: " + ", ".join(missing_artifacts)
        )
    return {
        "ecosystem_cid": ecosystem_cid,
        "ecosystem_sha256": ecosystem_sha256,
        "source_cid": source_cid,
        "source_sha256": source_sha256,
        "source_commit": commit,
        "artifacts": {name: artifacts_by_name[name] for name in REQUIRED_RUNTIME_ARTIFACTS},
    }


def _safe_repo_path(repo_root: Path, raw_path: Any, label: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
        raise OnboardingError(f"{label} must be a non-empty repository path")
    relative = Path(raw_path)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise OnboardingError(f"{label} is not a safe repository path")
    root = repo_root.resolve(strict=True)
    candidate = root.joinpath(relative)
    parent = candidate.parent.resolve(strict=True)
    if parent != root and root not in parent.parents:
        raise OnboardingError(f"{label} escapes the repository")
    return candidate


def validate_profile(profile: Mapping[str, Any], repo_root: Path) -> dict[str, Any]:
    _require_exact_keys(
        profile,
        frozenset(
            {
                "schema_version",
                "experiment_id",
                "policy_path",
                "manifest_path",
                "roles",
                "live_success",
            }
        ),
        "onboarding profile",
    )
    if profile.get("schema_version") != PROFILE_SCHEMA:
        raise OnboardingError("unexpected onboarding profile schema")
    if profile.get("experiment_id") != EXPERIMENT_ID:
        raise OnboardingError("unexpected onboarding experiment ID")
    policy_path = _safe_repo_path(repo_root, profile.get("policy_path"), "policy path")
    manifest_path = _safe_repo_path(repo_root, profile.get("manifest_path"), "manifest path")
    roles = profile.get("roles")
    if not isinstance(roles, dict) or frozenset(roles) != frozenset(
        {"observer", "pruned-miner", "archive-operator"}
    ):
        raise OnboardingError("onboarding profile must define the three exact roles")
    for role_name, role in roles.items():
        if not isinstance(role, dict):
            raise OnboardingError(f"role {role_name} must be an object")
        _require_exact_keys(role, ROLE_FIELDS, f"role {role_name}")
        for field in ("live_join", "requires_linux", "requires_systemd", "requires_ssd"):
            if not isinstance(role.get(field), bool):
                raise OnboardingError(f"role {role_name} {field} must be boolean")
        for field in (
            "minimum_cpu_cores",
            "minimum_memory_gib",
            "minimum_free_storage_gib",
        ):
            if not _is_positive_int(role.get(field)):
                raise OnboardingError(f"role {role_name} {field} must be positive")
        groups = role.get("required_command_groups")
        if not isinstance(groups, list) or not groups:
            raise OnboardingError(f"role {role_name} command groups must be non-empty")
        seen_groups: set[tuple[str, ...]] = set()
        for group in groups:
            if (
                not isinstance(group, list)
                or not group
                or any(
                    not isinstance(command, str)
                    or not command
                    or len(command) > 64
                    or "/" in command
                    or "\\" in command
                    for command in group
                )
            ):
                raise OnboardingError(f"role {role_name} has an invalid command group")
            key = tuple(group)
            if key in seen_groups:
                raise OnboardingError(f"role {role_name} has a duplicate command group")
            seen_groups.add(key)
    if roles != EXPECTED_ROLE_REQUIREMENTS:
        raise OnboardingError("onboarding role requirements differ from the reviewed profile")

    live = profile.get("live_success")
    if not isinstance(live, dict):
        raise OnboardingError("live success policy must be an object")
    _require_exact_keys(
        live,
        frozenset(
            {
                "checkpoint_height",
                "checkpoint_hash",
                "rpc_port",
                "minimum_bitcoin_peers",
                "minimum_reachable_gossip_peers",
                "minimum_active_shares",
                "minimum_miner_active_shares",
                "maximum_miner_share_age_seconds",
                "maximum_core_tip_age_seconds",
                "maximum_future_clock_skew_seconds",
                "minimum_snapshot_voters",
                "require_registered_miner",
                "require_verified_snapshot",
                "require_accepted_bitcoin_template",
            }
        ),
        "live success policy",
    )
    if not _is_positive_int(live.get("checkpoint_height")):
        raise OnboardingError("checkpoint height must be positive")
    if not _is_sha256(live.get("checkpoint_hash")):
        raise OnboardingError("checkpoint hash must be lowercase SHA-256 hex")
    for field in (
        "rpc_port",
        "minimum_bitcoin_peers",
        "minimum_reachable_gossip_peers",
        "minimum_active_shares",
        "minimum_miner_active_shares",
        "maximum_miner_share_age_seconds",
        "maximum_core_tip_age_seconds",
        "maximum_future_clock_skew_seconds",
        "minimum_snapshot_voters",
    ):
        if not _is_positive_int(live.get(field)):
            raise OnboardingError(f"{field} must be positive")
    for field in (
        "require_registered_miner",
        "require_verified_snapshot",
        "require_accepted_bitcoin_template",
    ):
        if live.get(field) is not True:
            raise OnboardingError(f"{field} must remain enabled")
    if live != EXPECTED_LIVE_SUCCESS:
        raise OnboardingError("live success requirements differ from the reviewed profile")

    manifest = _read_json(manifest_path, "Experiment 1 manifest")
    policy = _read_json(policy_path, "Experiment 1 launch policy")
    if manifest.get("experiment_id") != EXPERIMENT_ID or policy.get("experiment_id") != EXPERIMENT_ID:
        raise OnboardingError("profile points to a different experiment")
    if manifest.get("activation_id") != policy.get("activation_id"):
        raise OnboardingError("manifest and launch policy activation IDs differ")
    consensus = manifest.get("consensus")
    replay = consensus.get("replay_protection") if isinstance(consensus, dict) else None
    signature_domain = replay.get("signature_domain") if isinstance(replay, dict) else None
    if not isinstance(signature_domain, dict):
        raise OnboardingError("manifest replay-domain checkpoint is missing")
    if (
        signature_domain.get("activation_parent_height") != live.get("checkpoint_height")
        or signature_domain.get("activation_parent_hash") != live.get("checkpoint_hash")
    ):
        raise OnboardingError("onboarding checkpoint does not match the replay-domain manifest")
    if policy.get("fork_manifest_path") != profile.get("manifest_path"):
        raise OnboardingError("launch policy does not bind the onboarding manifest")
    network = manifest.get("network")
    proof_of_work = consensus.get("proof_of_work") if isinstance(consensus, dict) else None
    replay_protection = consensus.get("replay_protection") if isinstance(consensus, dict) else None
    fork_point = manifest.get("fork_point")
    if (
        not isinstance(network, dict)
        or network.get("chain_argument") != "pohw"
        or network.get("rpc_port") != live.get("rpc_port")
        or not isinstance(proof_of_work, dict)
        or not isinstance(replay_protection, dict)
        or not isinstance(fork_point, dict)
    ):
        raise OnboardingError("onboarding Core policy does not match the consensus manifest")
    return {
        "profile": dict(profile),
        "policy_path": policy_path,
        "manifest_path": manifest_path,
        "policy": policy,
        "manifest": manifest,
        "core_expectations": {
            "fork_height": fork_point.get("inherited_tip_height"),
            "fork_hash": fork_point.get("inherited_tip_hash"),
            "first_fork_hash": fork_point.get("first_fork_hash"),
            "inherited_utxo_spending": consensus.get("inherited_utxo_spending_enabled"),
            "replay_protection": replay_protection.get("rule"),
            "replay_marker_activation_height": replay_protection.get("marker_activation_height"),
            "replay_sighash_activation_height": signature_domain.get("activation_height"),
            "replay_sighash_parent_hash": signature_domain.get("activation_parent_hash"),
            "replay_sighash_version_bit": signature_domain.get("transaction_version_bit"),
            "replay_sighash_domain": signature_domain.get("domain"),
            "bootstrap_handoff_hashrate_hps": proof_of_work.get(
                "bootstrap_handoff_hashrate_hps"
            ),
        },
    }


def _sanitized_environment(private_home: Path) -> dict[str, str]:
    allowed = (
        "PATH",
        "RUSTUP_HOME",
        "CARGO_HOME",
        "SYSTEMROOT",
        "WINDIR",
    )
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "CARGO_NET_OFFLINE": "true",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": str(private_home),
            "USERPROFILE": str(private_home),
            "NO_COLOR": "1",
        }
    )
    return environment


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[bytes]:
    if not command or any(not isinstance(item, str) or "\x00" in item for item in command):
        raise OnboardingError("invalid command invocation")
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    reader_errors: list[BaseException] = []

    def terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass

    def read_bounded(stream: Any, destination: bytearray, process: subprocess.Popen[bytes]) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                remaining = MAX_COMMAND_OUTPUT_BYTES + 1 - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(destination) > MAX_COMMAND_OUTPUT_BYTES or len(chunk) > remaining:
                    overflow.set()
                    terminate(process)
                    return
        except (OSError, ValueError) as exc:
            reader_errors.append(exc)
            terminate(process)

    try:
        with tempfile.TemporaryDirectory(prefix="pohw-onboarding-home-") as private_home:
            popen_options: dict[str, Any] = {"start_new_session": os.name == "posix"}
            if pass_fds:
                if os.name != "posix" or any(
                    not isinstance(descriptor, int) or descriptor < 0 for descriptor in pass_fds
                ):
                    raise OnboardingError("invalid inherited executable descriptor")
                popen_options["pass_fds"] = tuple(pass_fds)
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=_sanitized_environment(Path(private_home)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **popen_options,
            )
            if process.stdout is None or process.stderr is None:
                terminate(process)
                raise OnboardingError("required command output pipes are unavailable")
            readers = (
                threading.Thread(
                    target=read_bounded, args=(process.stdout, stdout, process), daemon=True
                ),
                threading.Thread(
                    target=read_bounded, args=(process.stderr, stderr, process), daemon=True
                ),
            )
            for reader in readers:
                reader.start()
            timeout_error: subprocess.TimeoutExpired | None = None
            try:
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                timeout_error = exc
                terminate(process)
                return_code = process.wait(timeout=10)
            for reader in readers:
                reader.join(timeout=10)
            process.stdout.close()
            process.stderr.close()
            if timeout_error is not None:
                raise OnboardingError(f"required command timed out: {command[0]}") from timeout_error
            if any(reader.is_alive() for reader in readers):
                terminate(process)
                raise OnboardingError(f"required command output reader did not stop: {command[0]}")
            if reader_errors:
                raise OnboardingError(f"required command output could not be read: {command[0]}")
            if overflow.is_set():
                raise OnboardingError(f"required command produced excessive output: {command[0]}")
            result = subprocess.CompletedProcess(list(command), return_code, bytes(stdout), bytes(stderr))
    except OSError as exc:
        raise OnboardingError(f"required command could not complete: {command[0]}") from exc
    return result


def _command_succeeded(command: Sequence[str], repo_root: Path) -> bool:
    try:
        return run_command(command, cwd=repo_root).returncode == 0
    except OnboardingError:
        return False


def _command_json(
    command: Sequence[str],
    repo_root: Path,
    label: str,
    *,
    pass_fds: Sequence[int] = (),
) -> dict[str, Any]:
    result = run_command(command, cwd=repo_root, pass_fds=pass_fds)
    if result.returncode != 0:
        raise OnboardingError(f"{label} failed")
    try:
        value = json.loads(result.stdout.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OnboardingError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise OnboardingError(f"{label} JSON root must be an object")
    return value


def _run_attested_command(
    executable: Path,
    label: str,
    expected: Mapping[str, Any],
    arguments: Sequence[str],
    repo_root: Path,
    *,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    with _stage_attested_executable(executable, label, expected) as staged:
        return run_command(
            (staged.command_path, *arguments),
            cwd=repo_root,
            timeout=timeout,
            pass_fds=staged.pass_fds,
        )


def _attested_command_json(
    executable: Path,
    label: str,
    expected: Mapping[str, Any],
    arguments: Sequence[str],
    repo_root: Path,
    output_label: str,
) -> dict[str, Any]:
    with _stage_attested_executable(executable, label, expected) as staged:
        return _command_json(
            (staged.command_path, *arguments),
            repo_root,
            output_label,
            pass_fds=staged.pass_fds,
        )


def _platform_class() -> str:
    system = platform.system().lower()
    return {"linux": "linux", "darwin": "macos", "windows": "windows"}.get(system, "other")


def _memory_gib(repo_root: Path) -> int | None:
    system = _platform_class()
    physical_bytes: int | None = None
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
        if isinstance(page_size, int) and isinstance(page_count, int) and page_size > 0 and page_count > 0:
            physical_bytes = page_size * page_count
    except (AttributeError, OSError, ValueError):
        pass
    if system == "linux" and physical_bytes is None:
        try:
            for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
                if line.startswith("MemTotal:"):
                    kib = int(line.split()[1])
                    physical_bytes = kib * 1024
                    break
        except (OSError, ValueError, IndexError):
            pass
    if system == "macos" and physical_bytes is None:
        try:
            result = run_command(("sysctl", "-n", "hw.memsize"), cwd=repo_root, timeout=10)
            if result.returncode == 0:
                physical_bytes = int(result.stdout.strip())
        except (OnboardingError, ValueError):
            pass
    if system == "windows" and physical_bytes is None:
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                physical_bytes = int(status.total_physical)
        except (AttributeError, OSError):
            pass
    if physical_bytes is None:
        return None
    limits = [physical_bytes]
    if system == "linux":
        for path in (
            Path("/sys/fs/cgroup/memory.max"),
            Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
        ):
            try:
                value = path.read_text(encoding="ascii").strip()
                if value != "max":
                    parsed = int(value)
                    if 0 < parsed < (1 << 60):
                        limits.append(parsed)
            except (OSError, ValueError):
                continue
    return min(limits) // (1024**3)


def _effective_cpu_cores() -> int:
    candidates = [os.cpu_count() or 0]
    try:
        candidates.append(len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        pass
    if _platform_class() == "linux":
        try:
            quota, period = Path("/sys/fs/cgroup/cpu.max").read_text(encoding="ascii").split()
            if quota != "max":
                quota_value = int(quota)
                period_value = int(period)
                if quota_value > 0 and period_value > 0:
                    candidates.append(max(1, quota_value // period_value))
        except (OSError, ValueError):
            try:
                quota_value = int(
                    Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text(encoding="ascii")
                )
                period_value = int(
                    Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text(encoding="ascii")
                )
                if quota_value > 0 and period_value > 0:
                    candidates.append(max(1, quota_value // period_value))
            except (OSError, ValueError):
                pass
    positive = [value for value in candidates if value > 0]
    return min(positive) if positive else 0


def _verified_storage_path(path: Path) -> Path:
    candidate = path.expanduser()
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise OnboardingError("storage path must already exist") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OnboardingError("storage path must be an existing non-symlink directory")
    resolved = candidate.resolve(strict=True)
    # The selected path is a filesystem root, not a data directory owned by the
    # invoking user. Production layouts deliberately put Bitcoin and P2Pool
    # data below it under separate service accounts.
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise OnboardingError("storage path is not readable and traversable")
    try:
        filesystem = os.statvfs(resolved)
    except OSError as exc:
        raise OnboardingError("storage filesystem cannot be inspected") from exc
    read_only_flag = getattr(stat, "ST_RDONLY", 1)
    if filesystem.f_flag & read_only_flag:
        raise OnboardingError("storage filesystem is read-only")
    return resolved


def _linux_ssd(path: Path, repo_root: Path) -> bool | None:
    if _platform_class() != "linux" or shutil.which("findmnt") is None or shutil.which("lsblk") is None:
        return None
    try:
        mount = run_command(
            ("findmnt", "-no", "SOURCE", "--target", str(path)), cwd=repo_root, timeout=10
        )
        if mount.returncode != 0:
            return None
        source = mount.stdout.decode("utf-8", errors="strict").strip()
        if not source.startswith("/dev/") or "\n" in source:
            return None
        rotational = run_command(("lsblk", "-ndo", "ROTA", source), cwd=repo_root, timeout=10)
        if rotational.returncode != 0:
            return None
        values = {line.strip() for line in rotational.stdout.decode("ascii").splitlines() if line.strip()}
        if values == {"0"}:
            return True
        if "1" in values:
            return False
    except (OnboardingError, UnicodeError):
        return None
    return None


def inspect_host(role: Mapping[str, Any], storage_path: Path, repo_root: Path) -> dict[str, Any]:
    try:
        existing_storage = _verified_storage_path(storage_path)
        storage_path_verified = True
    except OnboardingError:
        existing_storage = repo_root
        storage_path_verified = False
    cpu_cores = _effective_cpu_cores()
    memory_gib = _memory_gib(repo_root)
    try:
        free_storage_gib = shutil.disk_usage(existing_storage).free // (1024**3)
    except OSError as exc:
        raise OnboardingError("cannot inspect free storage") from exc
    platform_class = _platform_class()
    systemd_available = (
        platform_class == "linux"
        and Path("/run/systemd/system").is_dir()
        and shutil.which("systemctl") is not None
    )
    ssd_confirmed = _linux_ssd(existing_storage, repo_root)
    missing_groups: list[str] = []
    for group in role["required_command_groups"]:
        if not any(shutil.which(command) is not None for command in group):
            missing_groups.append("|".join(group))
    failed: list[str] = []
    if not storage_path_verified:
        failed.append("storage-path-unavailable")
    if cpu_cores < role["minimum_cpu_cores"]:
        failed.append("insufficient-cpu")
    if memory_gib is None:
        failed.append("memory-unverified")
    elif memory_gib < role["minimum_memory_gib"]:
        failed.append("insufficient-memory")
    if free_storage_gib < role["minimum_free_storage_gib"]:
        failed.append("insufficient-storage")
    if role["requires_linux"] and platform_class != "linux":
        failed.append("linux-required")
    if role["requires_systemd"] and not systemd_available:
        failed.append("systemd-required")
    if role["requires_ssd"] and ssd_confirmed is not True:
        failed.append("ssd-unverified")
    if missing_groups:
        failed.append("commands-missing")
    return {
        "eligible_for_role": not failed,
        "platform_class": platform_class,
        "cpu_cores": cpu_cores,
        "memory_gib": memory_gib,
        "free_storage_gib": free_storage_gib,
        "storage_path_verified": storage_path_verified,
        "ssd_confirmed": ssd_confirmed,
        "systemd_available": systemd_available,
        "missing_command_groups": sorted(set(missing_groups)),
        "failed_checks": sorted(set(failed)),
    }


def _git_source_state(repo_root: Path) -> tuple[str | None, bool]:
    commit_result = run_command(("git", "rev-parse", "--verify", "HEAD"), cwd=repo_root)
    if commit_result.returncode != 0:
        return None, False
    try:
        commit = commit_result.stdout.decode("ascii").strip().lower()
    except UnicodeError:
        return None, False
    if len(commit) != COMMIT_HEX_LENGTH or any(c not in "0123456789abcdef" for c in commit):
        return None, False
    dirty = run_command(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"), cwd=repo_root
    )
    flags = run_command(("git", "ls-files", "-v"), cwd=repo_root)
    ordinary_flags = False
    if flags.returncode == 0:
        try:
            lines = flags.stdout.decode("utf-8", errors="strict").splitlines()
            ordinary_flags = all(line.startswith("H ") for line in lines)
        except UnicodeError:
            ordinary_flags = False
    return commit, dirty.returncode == 0 and not dirty.stdout.strip() and ordinary_flags


def _missing_release_gates(policy: Mapping[str, Any]) -> list[str]:
    readiness = policy.get("public_join_readiness")
    if not isinstance(readiness, dict):
        return ["invalid-public-join-readiness"]
    missing = [field.replace("_", "-") for field in READINESS_BOOLEAN_FIELDS if readiness.get(field) is not True]
    required = readiness.get("required_independent_registry_build_operators")
    verified = readiness.get("verified_independent_registry_build_operators")
    if not _is_positive_int(required) or not _is_nonnegative_int(verified) or verified < required:
        missing.append("independent-registry-build-operators")
    candidate = policy.get("registry_source_candidate")
    if not isinstance(candidate, dict) or candidate.get("deployment_authorized") is not True:
        missing.append("registry-deployment-authorization")
    return sorted(set(missing))


def _static_policy_bindings_verified(
    repo_root: Path, validated: Mapping[str, Any]
) -> bool:
    try:
        policy = validated["policy"]
        manifest = validated["manifest"]
        if (
            policy.get("schema_version") != "pohw-experiment-launch-policy/v1"
            or policy.get("experiment_id") != EXPERIMENT_ID
            or policy.get("activation_id") != manifest.get("activation_id")
            or policy.get("status") not in (BLOCKED_POLICY_STATUS, READY_POLICY_STATUS)
        ):
            return False
        manifest_bytes = _read_regular_file(validated["manifest_path"], "Experiment 1 manifest")
        if policy.get("fork_manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
            return False
        runtime_gates = policy.get("required_runtime_gates")
        if not isinstance(runtime_gates, dict) or frozenset(runtime_gates) != RUNTIME_GATE_FIELDS:
            return False
        if runtime_gates.get("bound_policy_replacement_allowed") is not False:
            return False
        if any(
            runtime_gates.get(field) is not True
            for field in RUNTIME_GATE_FIELDS - {"bound_policy_replacement_allowed"}
        ):
            return False
        if policy.get("identity_admission_scope") != IDENTITY_ADMISSION_SCOPE:
            return False
        readiness = policy.get("public_join_readiness")
        if not isinstance(readiness, dict) or frozenset(readiness) != READINESS_FIELDS:
            return False
        if readiness.get("external_security_review_required") is not True:
            return False
        if any(not isinstance(readiness.get(field), bool) for field in READINESS_BOOLEAN_FIELDS):
            return False
        for field in (
            "required_independent_registry_build_operators",
            "verified_independent_registry_build_operators",
            "matching_registry_builds_observed",
        ):
            if not _is_nonnegative_int(readiness.get(field)):
                return False
        if readiness["required_independent_registry_build_operators"] < 2:
            return False
        candidate_binding = policy.get("registry_source_candidate")
        if not isinstance(candidate_binding, dict):
            return False
        _require_exact_keys(
            candidate_binding,
            frozenset(
                {
                    "path",
                    "sha256",
                    "contract_schema_version",
                    "contract_version",
                    "wasm_sha256",
                    "wasm_cid",
                    "deployment_authorized",
                }
            ),
            "registry source candidate binding",
        )
        candidate_path = _safe_repo_path(
            repo_root, candidate_binding.get("path"), "registry source candidate path"
        )
        candidate_bytes = _read_regular_file(candidate_path, "registry source candidate")
        candidate = json.loads(
            candidate_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
        if (
            not isinstance(candidate, dict)
            or candidate_binding.get("sha256") != hashlib.sha256(candidate_bytes).hexdigest()
        ):
            return False
        artifact = candidate.get("artifact")
        if not isinstance(artifact, dict):
            return False
        if (
            candidate_binding.get("wasm_sha256") != artifact.get("sha256")
            or candidate_binding.get("wasm_cid") != artifact.get("cid")
            or candidate_binding.get("contract_schema_version")
            != candidate.get("contract_schema_version")
            or candidate_binding.get("contract_version") != candidate.get("contract_version")
            or not isinstance(candidate_binding.get("deployment_authorized"), bool)
        ):
            return False
        return True
    except (OnboardingError, UnicodeError, json.JSONDecodeError, OSError, KeyError, TypeError):
        return False


def _verify_canonical_source(
    repo_root: Path,
    policy: Mapping[str, Any],
    *,
    expected_ecosystem_cid: str,
    candidate_ecosystem_car: Path,
    source_car: Path,
    governance_cli: Path,
) -> dict[str, Any]:
    readiness = policy.get("public_join_readiness")
    expected_ecosystem = (
        readiness.get("deployment_readiness_candidate_ecosystem_cid")
        if isinstance(readiness, dict)
        else None
    )
    if not _is_dag_cbor_cid(expected_ecosystem):
        raise OnboardingError("launch policy has no candidate ecosystem CID")
    if not _is_dag_cbor_cid(expected_ecosystem_cid):
        raise OnboardingError("expected ecosystem CID is not a canonical DAG-CBOR CID")
    if expected_ecosystem != expected_ecosystem_cid:
        raise OnboardingError(
            "launch policy candidate differs from the independently selected ecosystem CID"
        )
    source_car_binding = _hash_regular_file(
        source_car, "P2poolBTC source CAR", MAX_CAR_BYTES
    )
    bindings = _extract_ecosystem_bindings(candidate_ecosystem_car, expected_ecosystem)
    ecosystem_verification = _attested_command_json(
        governance_cli,
        "pohw-governance",
        bindings["artifacts"]["pohw-governance"],
        (
            "ecosystem-inspect",
            "--car",
            str(candidate_ecosystem_car),
        ),
        repo_root,
        "candidate ecosystem verification",
    )
    _require_exact_keys(
        ecosystem_verification,
        frozenset(
            {
                "schemaVersion",
                "ecosystemCid",
                "ecosystemSha256",
                "carSha256",
                "manifest",
            }
        ),
        "candidate ecosystem verification output",
    )
    verified_manifest = ecosystem_verification.get("manifest")
    ecosystem_car_sha256, _ = _hash_regular_file(
        candidate_ecosystem_car, "candidate ecosystem CAR", MAX_CAR_BYTES
    )
    if (
        ecosystem_verification.get("schemaVersion") != 1
        or ecosystem_verification.get("ecosystemCid") != expected_ecosystem_cid
        or ecosystem_verification.get("ecosystemSha256") != bindings["ecosystem_sha256"]
        or ecosystem_verification.get("carSha256") != ecosystem_car_sha256
        or not isinstance(verified_manifest, dict)
    ):
        raise OnboardingError("pohw-governance rejected the candidate ecosystem binding")
    verified_repositories = verified_manifest.get("repositories")
    verified_repository = (
        [
            item
            for item in verified_repositories
            if isinstance(item, dict) and item.get("name") == SOURCE_REPOSITORY
        ]
        if isinstance(verified_repositories, list)
        else []
    )
    if len(verified_repository) != 1:
        raise OnboardingError("verified ecosystem does not contain P2poolBTC exactly once")
    if (
        verified_repository[0].get("sourceTreeCid") != bindings["source_cid"]
        or verified_repository[0].get("sourceTreeSha256") != bindings["source_sha256"]
        or verified_repository[0].get("gitCommitMetadata") != bindings["source_commit"]
    ):
        raise OnboardingError("verified ecosystem source binding differs for P2poolBTC")
    verified_artifacts = verified_repository[0].get("artifacts")
    verified_artifacts_by_name = (
        {
            item.get("name"): item
            for item in verified_artifacts
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        if isinstance(verified_artifacts, list)
        else {}
    )
    for name, binding in bindings["artifacts"].items():
        if verified_artifacts_by_name.get(name) != {
            "name": name,
            **binding,
        }:
            raise OnboardingError(f"verified ecosystem artifact differs for {name}")
    verification = _attested_command_json(
        governance_cli,
        "pohw-governance",
        bindings["artifacts"]["pohw-governance"],
        (
            "verify",
            "--car",
            str(source_car),
            "--root",
            str(repo_root),
            "--repository",
            SOURCE_REPOSITORY,
        ),
        repo_root,
        "canonical source-tree verification",
    )
    _require_exact_keys(
        verification,
        frozenset(
            {
                "verified",
                "sourceTreeCid",
                "sourceTreeSha256",
                "repository",
                "files",
                "localTreeMatch",
            }
        ),
        "canonical source verification output",
    )
    if (
        verification.get("verified") is not True
        or verification.get("localTreeMatch") is not True
        or verification.get("repository") != SOURCE_REPOSITORY
        or verification.get("sourceTreeCid") != bindings["source_cid"]
        or verification.get("sourceTreeSha256") != bindings["source_sha256"]
        or not _is_positive_int(verification.get("files"))
    ):
        raise OnboardingError("local source tree does not match the candidate ecosystem")
    if (
        _hash_regular_file(source_car, "P2poolBTC source CAR", MAX_CAR_BYTES)
        != source_car_binding
    ):
        raise OnboardingError("source CAR changed during verification")
    commit, clean = _git_source_state(repo_root)
    commit_matches = bindings["source_commit"] is None or commit == bindings["source_commit"]
    if not clean or not commit_matches:
        raise OnboardingError("Git state does not match the canonical source metadata")
    return {
        **bindings,
        "source_car_sha256": source_car_binding[0],
        "source_commit_matches": commit_matches,
        "governance_cli_verified": True,
    }


def verify_release(
    repo_root: Path,
    validated: Mapping[str, Any],
    *,
    expected_ecosystem_cid: str | None,
    readiness_car: Path | None,
    readiness_evidence_car: Path | None,
    candidate_ecosystem_car: Path | None,
    source_car: Path | None,
    governance_cli: Path | None,
    idena_anchor_policy: Path | None,
    p2pool_node: Path | None,
    idena_rpc_url: str,
    idena_api_key_file: Path | None,
    run_tests: bool,
) -> dict[str, Any]:
    if run_tests:
        raise OnboardingError(
            "onboarding never executes repository tests; use the documented disposable clean-room builder workflow"
        )
    policy = validated["policy"]
    static_bindings_verified = _static_policy_bindings_verified(repo_root, validated)
    source_commit, source_tree_clean = _git_source_state(repo_root)
    source_binding: dict[str, Any] | None = None
    canonical_inputs = (candidate_ecosystem_car, source_car, governance_cli)
    if any(value is not None for value in canonical_inputs) and not all(
        value is not None for value in canonical_inputs
    ):
        raise OnboardingError(
            "candidate ecosystem CAR, source CAR, and governance CLI must be supplied together"
        )
    if all(value is not None for value in canonical_inputs):
        if expected_ecosystem_cid is None:
            raise OnboardingError("canonical source verification requires --expected-ecosystem-cid")
        source_binding = _verify_canonical_source(
            repo_root,
            policy,
            expected_ecosystem_cid=expected_ecosystem_cid,
            candidate_ecosystem_car=candidate_ecosystem_car,  # type: ignore[arg-type]
            source_car=source_car,  # type: ignore[arg-type]
            governance_cli=governance_cli,  # type: ignore[arg-type]
        )
    canonical_source_verified = source_binding is not None
    policy_status = policy.get("status")
    manifest_verified = static_bindings_verified
    launch_policy_verified = static_bindings_verified
    if (
        policy_status == READY_POLICY_STATUS
        and canonical_source_verified
        and manifest_verified
        and launch_policy_verified
    ):
        manifest_command = (
            sys.executable,
            str(repo_root / "scripts" / "pohw-experiment-1-manifest.py"),
            "verify",
            str(validated["manifest_path"]),
            "--repo-root",
            str(repo_root),
        )
        manifest_verified = _command_succeeded(manifest_command, repo_root)
        policy_command = [
            sys.executable,
            str(repo_root / "scripts" / "pohw-experiment-1-launch-policy.py"),
            str(validated["policy_path"]),
            "--repo-root",
            str(repo_root),
        ]
        for option, value in (
            ("--readiness-car", readiness_car),
            ("--readiness-evidence-car", readiness_evidence_car),
            ("--governance-cli", governance_cli),
            (
                "--governance-cli-sha256",
                source_binding["artifacts"]["pohw-governance"]["sha256"],
            ),
            ("--idena-anchor-policy", idena_anchor_policy),
        ):
            if value is not None:
                policy_command.extend((option, str(value)))
        launch_policy_verified = _command_succeeded(policy_command, repo_root)
    focused_tests_passed: bool | None = None
    registry_chain_verified = False
    if (
        policy_status == READY_POLICY_STATUS
        and canonical_source_verified
        and manifest_verified
        and launch_policy_verified
    ):
        if (
            p2pool_node is not None
            and idena_anchor_policy is not None
            and idena_api_key_file is not None
        ):
            result = _run_attested_command(
                p2pool_node,
                "p2pool-node",
                source_binding["artifacts"]["p2pool-node"],  # type: ignore[index]
                (
                    "verify-idena-registry-deployment",
                    "--idena-anchor-policy",
                    str(idena_anchor_policy),
                    "--idena-rpc-url",
                    idena_rpc_url,
                    "--idena-api-key-file",
                    str(idena_api_key_file),
                ),
                repo_root,
                timeout=60,
            )
            registry_chain_verified = (
                result.returncode == 0
                and result.stdout
                == b"Idena registry deployment verified against synchronized local RPC\n"
            )
    final_commit, final_tree_clean = _git_source_state(repo_root)
    source_tree_clean = bool(
        source_tree_clean
        and final_tree_clean
        and source_commit is not None
        and source_commit == final_commit
    )
    source_commit = final_commit
    policy_status = policy.get("status") if launch_policy_verified else "invalid"
    if policy_status not in (BLOCKED_POLICY_STATUS, READY_POLICY_STATUS):
        policy_status = "invalid"
    missing = _missing_release_gates(policy) if launch_policy_verified else ["launch-policy-verification"]
    if policy.get("status") == READY_POLICY_STATUS:
        if expected_ecosystem_cid is None:
            missing.append("expected-ecosystem-cid-required")
        if candidate_ecosystem_car is None:
            missing.append("candidate-ecosystem-car-required")
        if source_car is None:
            missing.append("source-car-required")
        if not canonical_source_verified:
            missing.append("canonical-source-verification")
        if not registry_chain_verified:
            missing.append("registry-chain-verification")
    canonical_source_published = bool(
        launch_policy_verified
        and isinstance(policy.get("public_join_readiness"), dict)
        and policy["public_join_readiness"].get("canonical_source_cid_published") is True
    )
    public_join_ready = bool(
        manifest_verified
        and launch_policy_verified
        and source_tree_clean
        and canonical_source_published
        and canonical_source_verified
        and registry_chain_verified
        and policy_status == READY_POLICY_STATUS
        and not missing
    )
    return {
        "policy_status": policy_status,
        "activation_id": policy.get("activation_id") if _is_sha256(policy.get("activation_id")) else None,
        "manifest_verified": manifest_verified,
        "launch_policy_verified": launch_policy_verified,
        "source_commit": source_commit,
        "source_tree_clean": source_tree_clean,
        "candidate_ecosystem_cid": source_binding["ecosystem_cid"] if source_binding else None,
        "candidate_ecosystem_verified": source_binding is not None,
        "canonical_source_cid": source_binding["source_cid"] if source_binding else None,
        "source_car_sha256": source_binding["source_car_sha256"] if source_binding else None,
        "canonical_source_verified": canonical_source_verified,
        "source_commit_matches": source_binding["source_commit_matches"] if source_binding else None,
        "governance_cli_verified": source_binding["governance_cli_verified"] if source_binding else False,
        "registry_chain_verified": registry_chain_verified,
        "attested_artifacts": source_binding["artifacts"] if source_binding else {},
        "focused_tests_passed": focused_tests_passed,
        "canonical_source_published": canonical_source_published,
        "public_join_ready": public_join_ready,
        "missing_release_gates": sorted(set(missing)),
    }


def _verify_running_executable(
    executable: Path,
    pid: int,
    start_time: int,
    label: str,
    expected: Mapping[str, Any],
) -> None:
    expected_digest = expected.get("sha256")
    expected_size = expected.get("size")
    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in expected_digest)
        or not _is_positive_int(expected_size)
    ):
        raise OnboardingError(f"{label} has an invalid candidate ecosystem binding")
    if _read_proc_start_time(pid) != start_time:
        raise OnboardingError(f"{label} process changed before verification")
    try:
        descriptor = os.open(executable, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        digest = hashlib.sha256()
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size:
                raise OnboardingError(f"{label} does not match the candidate ecosystem artifact")
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    raise OnboardingError(f"{label} exceeds its size limit")
                digest.update(chunk)
            closed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OnboardingError:
        raise
    except OSError as exc:
        raise OnboardingError(f"cannot verify {label}: {exc}") from exc
    if (
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (closed.st_dev, closed.st_ino, closed.st_size, closed.st_mtime_ns)
        or total != expected_size
        or digest.hexdigest() != expected_digest
        or _read_proc_start_time(pid) != start_time
    ):
        raise OnboardingError(f"{label} does not match its running attested process image")


def _validate_bitcoind_arguments(arguments: Sequence[str], bitcoin_datadir: Path) -> None:
    expected = (
        f"-datadir={bitcoin_datadir}",
        "-chain=pohw",
        "-daemon=0",
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
    )
    if tuple(arguments[1:]) != expected:
        raise OnboardingError("Bitcoin Core service arguments do not match the exact reviewed profile")


def _read_proc_network_table(path: Path) -> list[tuple[str, int, str]]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            value = bytearray()
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                value.extend(chunk)
                if len(value) > MAX_JSON_BYTES:
                    raise OnboardingError("Bitcoin Core socket table exceeds its size limit")
        finally:
            os.close(descriptor)
        lines = value.decode("ascii").splitlines()
    except OnboardingError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OnboardingError("Bitcoin Core socket table is unavailable") from exc
    entries: list[tuple[str, int, str]] = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10 or ":" not in fields[1]:
            raise OnboardingError("Bitcoin Core socket table is invalid")
        if fields[3] != "0A":
            continue
        address, port_hex = fields[1].rsplit(":", 1)
        try:
            port = int(port_hex, 16)
        except ValueError as exc:
            raise OnboardingError("Bitcoin Core socket table is invalid") from exc
        entries.append((address, port, fields[9]))
    return entries


def _proc_address(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        raw = bytes.fromhex(address)
    except ValueError as exc:
        raise OnboardingError("Bitcoin Core socket address is invalid") from exc
    if len(raw) == 4:
        return ipaddress.IPv4Address(raw[::-1])
    if len(raw) == 16:
        network_order = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
        return ipaddress.IPv6Address(network_order)
    raise OnboardingError("Bitcoin Core socket address is invalid")


def _verify_local_rpc_listener(pid: int, rpc_port: int) -> None:
    if not isinstance(rpc_port, int) or isinstance(rpc_port, bool) or not 1 <= rpc_port <= 65535:
        raise OnboardingError("Bitcoin Core RPC port is invalid")
    descriptor_root = Path(f"/proc/{pid}/fd")
    try:
        descriptors = list(descriptor_root.iterdir())
        if len(descriptors) > 65_536:
            raise OnboardingError("Bitcoin Core has too many open descriptors")
        socket_inodes = set()
        for descriptor in descriptors:
            target = os.readlink(descriptor)
            if target.startswith("socket:[") and target.endswith("]"):
                inode = target[8:-1]
                if inode.isdigit():
                    socket_inodes.add(inode)
    except OnboardingError:
        raise
    except OSError as exc:
        raise OnboardingError("Bitcoin Core socket descriptors are unavailable") from exc
    listeners = []
    for table in (Path(f"/proc/{pid}/net/tcp"), Path(f"/proc/{pid}/net/tcp6")):
        for address, port, inode in _read_proc_network_table(table):
            if inode in socket_inodes and port == rpc_port:
                listeners.append(_proc_address(address))
    if not listeners or any(not address.is_loopback for address in listeners):
        raise OnboardingError("Bitcoin Core RPC is not bound exclusively to loopback")


def _require_directory_within(root: Path, path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise OnboardingError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OnboardingError(f"{label} must be an existing non-symlink directory")
    if resolved != root and root not in resolved.parents:
        raise OnboardingError(f"{label} is outside the verified storage path")
    return resolved


def _require_regular_file_within(root: Path, path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise OnboardingError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise OnboardingError(f"{label} must be a regular non-symlink file")
    if resolved.parent != root and root not in resolved.parents:
        raise OnboardingError(f"{label} is outside the verified Bitcoin data directory")
    return resolved


def _json_bool(mapping: Mapping[str, Any], key: str) -> bool:
    return mapping.get(key) is True


def _read_proc_cmdline(pid: int) -> tuple[str, ...]:
    path = Path(f"/proc/{pid}/cmdline")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = os.read(descriptor, 65_537)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OnboardingError("Bitcoin Core process arguments are unavailable") from exc
    if not raw or len(raw) > 65_536 or not raw.endswith(b"\0"):
        raise OnboardingError("Bitcoin Core process arguments are invalid")
    try:
        arguments = tuple(item.decode("utf-8") for item in raw[:-1].split(b"\0"))
    except UnicodeError as exc:
        raise OnboardingError("Bitcoin Core process arguments are not UTF-8") from exc
    if not arguments or any(not item or "\n" in item or "\r" in item for item in arguments):
        raise OnboardingError("Bitcoin Core process arguments are invalid")
    return arguments


def _read_proc_start_time(pid: int) -> int:
    path = Path(f"/proc/{pid}/stat")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OnboardingError("Bitcoin Core process identity is unavailable") from exc
    if not raw or len(raw) > 4096 or b"\0" in raw or not raw.endswith(b"\n"):
        raise OnboardingError("Bitcoin Core process identity is invalid")
    # Field 2 is parenthesized and may contain spaces or right parentheses.
    # Fields after its final `) ` begin at field 3; starttime is field 22.
    end = raw.rfind(b") ")
    fields = raw[end + 2 :].split() if end > 0 else []
    if len(fields) <= 19:
        raise OnboardingError("Bitcoin Core process identity is invalid")
    try:
        start_time = int(fields[19])
    except ValueError as exc:
        raise OnboardingError("Bitcoin Core process identity is invalid") from exc
    if start_time <= 0:
        raise OnboardingError("Bitcoin Core process identity is invalid")
    return start_time


def _running_systemd_process(
    service: str, repo_root: Path
) -> tuple[Path, tuple[str, ...], int, int]:
    if service != "bitcoind-pohw-experiment-1.service":
        raise OnboardingError("unexpected Bitcoin Core service name")
    systemctl = Path("/usr/bin/systemctl")
    if not systemctl.is_file():
        raise OnboardingError("trusted systemctl is unavailable")
    result = run_command(
        (
            str(systemctl),
            "show",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            service,
        ),
        cwd=repo_root,
        timeout=20,
    )
    if result.returncode != 0:
        raise OnboardingError("Bitcoin Core systemd service is unavailable")
    try:
        properties: dict[str, str] = {}
        for line in result.stdout.decode("ascii").splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in properties:
                raise ValueError
            properties[key] = value
        if frozenset(properties) != frozenset({"ActiveState", "SubState", "MainPID"}):
            raise ValueError
        if properties["ActiveState"] != "active" or properties["SubState"] != "running":
            raise ValueError
        pid_text = properties["MainPID"]
        if not pid_text.isdigit() or int(pid_text) <= 1:
            raise ValueError
        pid = int(pid_text)
        executable = Path(f"/proc/{pid}/exe")
        executable_metadata = executable.stat()
        if not stat.S_ISREG(executable_metadata.st_mode):
            raise ValueError
    except (UnicodeError, ValueError, OSError) as exc:
        raise OnboardingError("Bitcoin Core systemd service has no verifiable running process") from exc
    return (
        executable,
        _read_proc_cmdline(pid),
        pid,
        _read_proc_start_time(pid),
    )


def _core_profile_matches(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def probe_live(
    args: argparse.Namespace,
    repo_root: Path,
    live_policy: Mapping[str, Any],
    core_expectations: Mapping[str, Any],
    release: Mapping[str, Any],
) -> dict[str, Any]:
    required = {
        "p2pool node": args.p2pool_node,
        "P2Pool data directory": args.p2pool_datadir,
        "snapshot directory": args.snapshot_dir,
        "miner ID": args.miner_id,
        "Bitcoin CLI": args.bitcoin_cli,
        "Bitcoin data directory": args.bitcoin_datadir,
        "Bitcoin cookie file": args.bitcoin_cookie_file,
    }
    if any(value is None or value == "" for value in required.values()):
        raise OnboardingError("live probe requires all node, data, snapshot, miner, and Bitcoin arguments")
    if args.storage_path is None:
        raise OnboardingError("live probe requires the verified storage path")
    storage_root = _verified_storage_path(Path(args.storage_path))
    p2pool_datadir = _require_directory_within(
        storage_root, Path(args.p2pool_datadir), "P2Pool data directory"
    )
    snapshot_dir = _require_directory_within(
        storage_root, Path(args.snapshot_dir), "snapshot directory"
    )
    bitcoin_datadir = _require_directory_within(
        storage_root, Path(args.bitcoin_datadir), "Bitcoin data directory"
    )
    bitcoin_cookie_file = _require_regular_file_within(
        bitcoin_datadir, Path(args.bitcoin_cookie_file), "Bitcoin cookie file"
    )
    artifacts = release.get("attested_artifacts")
    if not isinstance(artifacts, dict) or any(
        not isinstance(artifacts.get(name), dict) for name in REQUIRED_RUNTIME_ARTIFACTS
    ):
        raise OnboardingError("live probe has no verified runtime artifact bindings")
    running_bitcoind, bitcoind_arguments, bitcoind_pid, bitcoind_start_time = _running_systemd_process(
        "bitcoind-pohw-experiment-1.service", repo_root
    )
    _verify_running_executable(
        running_bitcoind,
        bitcoind_pid,
        bitcoind_start_time,
        "running bitcoind",
        artifacts["bitcoind"],
    )
    _validate_bitcoind_arguments(bitcoind_arguments, bitcoin_datadir)
    _verify_local_rpc_listener(bitcoind_pid, live_policy["rpc_port"])
    preflight = _attested_command_json(
        Path(args.p2pool_node),
        "p2pool-node",
        artifacts["p2pool-node"],
        (
            "multinode-preflight",
            "--datadir",
            str(p2pool_datadir),
            "--snapshot-dir",
            str(snapshot_dir),
            "--miner-id",
            str(args.miner_id),
        ),
        repo_root,
        "P2Pool live preflight",
    )
    readiness = preflight.get("readiness")
    local = preflight.get("local")
    replay = local.get("replay") if isinstance(local, dict) else None
    probes = preflight.get("peer_inventory_probe")
    miner_activity = preflight.get("miner_activity")
    if (
        not isinstance(readiness, dict)
        or not isinstance(replay, dict)
        or not isinstance(probes, list)
        or not isinstance(miner_activity, dict)
    ):
        raise OnboardingError("P2Pool live preflight is missing required aggregate fields")
    reachable = sum(
        1 for probe in probes if isinstance(probe, dict) and probe.get("reachable") is True
    )
    active_shares = replay.get("active_share_count")
    if not _is_nonnegative_int(active_shares):
        raise OnboardingError("P2Pool live preflight has an invalid active share count")
    miner_active_shares = miner_activity.get("active_share_count")
    miner_share_time = miner_activity.get("latest_template_created_at_unix")
    if not _is_nonnegative_int(miner_active_shares):
        raise OnboardingError("P2Pool live preflight has an invalid miner share count")
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    miner_share_age: int | None = None
    if _is_nonnegative_int(miner_share_time):
        if miner_share_time <= now + live_policy["maximum_future_clock_skew_seconds"]:
            miner_share_age = max(0, now - miner_share_time)

    snapshot = _attested_command_json(
        Path(args.p2pool_node),
        "p2pool-node",
        artifacts["p2pool-node"],
        (
            "mining-snapshot-evidence",
            "--datadir",
            str(p2pool_datadir),
            "--snapshot-dir",
            str(snapshot_dir),
            "--miner-id",
            str(args.miner_id),
            "--min-snapshot-voters",
            str(live_policy["minimum_snapshot_voters"]),
        ),
        repo_root,
        "Idena mining snapshot evidence",
    )
    snapshot_voters = snapshot.get("distinct_voter_count")
    snapshot_verified = bool(
        snapshot.get("schema_version") == "pohw-mining-snapshot-evidence/v1"
        and snapshot.get("miner_eligible") is True
        and _is_nonnegative_int(snapshot_voters)
        and snapshot_voters >= live_policy["minimum_snapshot_voters"]
    )

    bitcoin_base = [
        f"-datadir={bitcoin_datadir}",
        "-chain=pohw",
        "-rpcconnect=127.0.0.1",
        f"-rpcport={live_policy['rpc_port']}",
        f"-rpccookiefile={bitcoin_cookie_file}",
    ]
    chain_info = _attested_command_json(
        Path(args.bitcoin_cli),
        "bitcoin-cli",
        artifacts["bitcoin-cli"],
        tuple(bitcoin_base + ["getblockchaininfo"]),
        repo_root,
        "Bitcoin Core probe",
    )
    blocks = chain_info.get("blocks")
    headers = chain_info.get("headers")
    progress = chain_info.get("verificationprogress")
    pohw_profile = chain_info.get("pohw_experiment")
    best_block_hash = chain_info.get("bestblockhash")
    profile_verified = isinstance(pohw_profile, dict) and _core_profile_matches(
        pohw_profile, core_expectations
    )
    progress_ready = (
        isinstance(progress, (int, float))
        and not isinstance(progress, bool)
        and 0.999999 <= progress <= 1.0
    )
    network_info = _attested_command_json(
        Path(args.bitcoin_cli),
        "bitcoin-cli",
        artifacts["bitcoin-cli"],
        tuple(bitcoin_base + ["getnetworkinfo"]),
        repo_root,
        "Bitcoin Core network probe",
    )
    bitcoin_peers = network_info.get("connections")
    if not _is_nonnegative_int(bitcoin_peers):
        raise OnboardingError("Bitcoin Core returned an invalid peer count")
    if not isinstance(best_block_hash, str) or len(best_block_hash) != 64:
        raise OnboardingError("Bitcoin Core returned an invalid best block hash")
    tip_header = _attested_command_json(
        Path(args.bitcoin_cli),
        "bitcoin-cli",
        artifacts["bitcoin-cli"],
        tuple(bitcoin_base + ["getblockheader", best_block_hash]),
        repo_root,
        "Bitcoin Core tip header probe",
    )
    tip_time = tip_header.get("time")
    tip_height = tip_header.get("height")
    core_tip_age: int | None = None
    if _is_nonnegative_int(tip_time) and tip_time <= now + live_policy["maximum_future_clock_skew_seconds"]:
        core_tip_age = max(0, now - tip_time)
    core_ready = (
        chain_info.get("chain") == "pohw"
        and _is_nonnegative_int(blocks)
        and _is_nonnegative_int(headers)
        and headers == blocks
        and tip_height == blocks
        and chain_info.get("initialblockdownload") is False
        and progress_ready
        and core_tip_age is not None
        and core_tip_age <= live_policy["maximum_core_tip_age_seconds"]
        and bitcoin_peers >= live_policy["minimum_bitcoin_peers"]
    )
    checkpoint_height = live_policy["checkpoint_height"]
    checkpoint = _run_attested_command(
        Path(args.bitcoin_cli),
        "bitcoin-cli",
        artifacts["bitcoin-cli"],
        tuple(bitcoin_base + ["getblockhash", str(checkpoint_height)]),
        repo_root,
        timeout=30,
    )
    checkpoint_verified = False
    if checkpoint.returncode == 0:
        try:
            checkpoint_verified = (
                checkpoint.stdout.decode("ascii").strip().lower() == live_policy["checkpoint_hash"]
            )
        except UnicodeError:
            checkpoint_verified = False
    final_process = _running_systemd_process("bitcoind-pohw-experiment-1.service", repo_root)
    if final_process != (
        running_bitcoind,
        bitcoind_arguments,
        bitcoind_pid,
        bitcoind_start_time,
    ):
        raise OnboardingError("Bitcoin Core service changed during the live proof")
    _verify_running_executable(
        final_process[0],
        final_process[2],
        final_process[3],
        "running bitcoind",
        artifacts["bitcoind"],
    )
    _verify_local_rpc_listener(final_process[2], live_policy["rpc_port"])
    return {
        "core_ready": core_ready,
        "core_profile_verified": profile_verified,
        "core_local_service_verified": True,
        "checkpoint_verified": checkpoint_verified,
        "core_height": blocks if _is_nonnegative_int(blocks) else 0,
        "core_tip_age_seconds": core_tip_age,
        "bitcoin_peers": bitcoin_peers,
        "registered_miner": _json_bool(readiness, "has_registered_miner"),
        "verified_snapshot": snapshot_verified,
        "snapshot_voters": snapshot_voters if _is_nonnegative_int(snapshot_voters) else 0,
        "reachable_gossip_peers": reachable,
        "accepted_bitcoin_template": _json_bool(
            readiness, "has_accepted_bitcoin_work_template"
        ),
        "active_shares": active_shares,
        "miner_active_shares": miner_active_shares,
        "miner_share_age_seconds": miner_share_age,
        "share_tip_present": _json_bool(readiness, "has_share_tip"),
    }


def _live_succeeded(live: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return bool(
        live.get("core_ready") is True
        and live.get("core_profile_verified") is True
        and live.get("core_local_service_verified") is True
        and live.get("checkpoint_verified") is True
        and live.get("registered_miner") is True
        and live.get("verified_snapshot") is True
        and live.get("accepted_bitcoin_template") is True
        and live.get("share_tip_present") is True
        and _is_nonnegative_int(live.get("reachable_gossip_peers"))
        and live["reachable_gossip_peers"] >= policy["minimum_reachable_gossip_peers"]
        and _is_nonnegative_int(live.get("active_shares"))
        and live["active_shares"] >= policy["minimum_active_shares"]
        and _is_nonnegative_int(live.get("miner_active_shares"))
        and live["miner_active_shares"] >= policy["minimum_miner_active_shares"]
        and _is_nonnegative_int(live.get("miner_share_age_seconds"))
        and live["miner_share_age_seconds"] <= policy["maximum_miner_share_age_seconds"]
        and _is_nonnegative_int(live.get("snapshot_voters"))
        and live["snapshot_voters"] >= policy["minimum_snapshot_voters"]
        and _is_nonnegative_int(live.get("bitcoin_peers"))
        and live["bitcoin_peers"] >= policy["minimum_bitcoin_peers"]
        and _is_nonnegative_int(live.get("core_tip_age_seconds"))
        and live["core_tip_age_seconds"] <= policy["maximum_core_tip_age_seconds"]
    )


def build_receipt(
    *,
    role_name: str,
    role: Mapping[str, Any],
    release: Mapping[str, Any],
    host: Mapping[str, Any],
    live: Mapping[str, Any] | None,
    live_policy: Mapping[str, Any],
) -> dict[str, Any]:
    stages = {stage_id: "pending" for stage_id in STAGE_IDS}
    stages["system-check"] = "passed" if host["eligible_for_role"] else "blocked"
    source_review_ok = bool(
        release["manifest_verified"]
        and release["launch_policy_verified"]
        and release["source_tree_clean"]
        and release.get("focused_tests_passed") is not False
    )
    next_actions: list[str] = []
    if not host["eligible_for_role"]:
        stages["release-verification"] = "blocked" if role["live_join"] else "not-required"
        journey = "host-not-ready"
        stages["identity-registration"] = "blocked" if role["live_join"] else "not-required"
        stages["network-join"] = "blocked" if role["live_join"] else "not-required"
        stages["success-proof"] = "blocked"
        next_actions.extend(host["failed_checks"])
    elif not source_review_ok:
        stages["release-verification"] = "blocked"
        journey = "verification-failed"
        stages["identity-registration"] = "blocked" if role["live_join"] else "not-required"
        stages["network-join"] = "blocked" if role["live_join"] else "not-required"
        stages["success-proof"] = "blocked"
        if not release["source_tree_clean"]:
            next_actions.append("use-clean-exact-source")
        if not release["manifest_verified"]:
            next_actions.append("verify-fork-manifest")
        if not release["launch_policy_verified"]:
            next_actions.append("verify-launch-policy")
        if release["policy_status"] == READY_POLICY_STATUS and not release["canonical_source_verified"]:
            next_actions.append("canonical-source-verification")
        if release.get("focused_tests_passed") is False:
            next_actions.append("pass-focused-tests")
    elif not role["live_join"]:
        stages["release-verification"] = (
            "passed" if release.get("canonical_source_verified") is True else "not-required"
        )
        journey = "review-ready"
        stages["identity-registration"] = "not-required"
        stages["network-join"] = "not-required"
        stages["success-proof"] = "passed"
        next_actions.append("review-experiment-and-report-findings")
    elif not release["public_join_ready"]:
        stages["release-verification"] = "blocked"
        journey = "blocked-public-join"
        stages["identity-registration"] = "blocked"
        stages["network-join"] = "blocked"
        stages["success-proof"] = "blocked"
        next_actions.extend(release["missing_release_gates"])
    elif live is None:
        stages["release-verification"] = "passed"
        journey = "ready-for-identity-registration"
        stages["identity-registration"] = "pending"
        stages["network-join"] = "pending"
        stages["success-proof"] = "pending"
        next_actions.append("complete-local-identity-ownership-registration")
    elif _live_succeeded(live, live_policy):
        stages["release-verification"] = "passed"
        journey = "live-join-verified"
        stages["identity-registration"] = "passed"
        stages["network-join"] = "passed"
        stages["success-proof"] = "passed"
        next_actions.append("keep-redacted-receipt-and-monitor-node")
    else:
        stages["release-verification"] = "passed"
        journey = "live-join-incomplete"
        stages["identity-registration"] = "passed" if live["registered_miner"] else "blocked"
        stages["network-join"] = (
            "passed"
            if live["core_ready"]
            and live["checkpoint_verified"]
            and live["reachable_gossip_peers"] >= live_policy["minimum_reachable_gossip_peers"]
            else "blocked"
        )
        stages["success-proof"] = "blocked"
        checks = {
            "core_ready": "restore-pohw-core-readiness",
            "core_profile_verified": "verify-core-consensus-profile",
            "core_local_service_verified": "verify-local-core-service",
            "checkpoint_verified": "verify-pinned-checkpoint",
            "registered_miner": "complete-identity-registration",
            "verified_snapshot": "install-verified-idena-snapshot",
            "accepted_bitcoin_template": "wait-for-accepted-bitcoin-template",
            "share_tip_present": "wait-for-share-tip",
        }
        for key, action in checks.items():
            if live.get(key) is not True:
                next_actions.append(action)
        if live["reachable_gossip_peers"] < live_policy["minimum_reachable_gossip_peers"]:
            next_actions.append("connect-independent-gossip-peer")
        if live["active_shares"] < live_policy["minimum_active_shares"]:
            next_actions.append("submit-accepted-share")
        if (
            live["miner_active_shares"] < live_policy["minimum_miner_active_shares"]
            or not isinstance(live.get("miner_share_age_seconds"), int)
            or live["miner_share_age_seconds"] > live_policy["maximum_miner_share_age_seconds"]
        ):
            next_actions.append("wait-for-fresh-miner-share")
        if live["bitcoin_peers"] < live_policy["minimum_bitcoin_peers"]:
            next_actions.append("connect-bitcoin-peer")
        if (
            not isinstance(live.get("core_tip_age_seconds"), int)
            or live["core_tip_age_seconds"] > live_policy["maximum_core_tip_age_seconds"]
        ):
            next_actions.append("restore-fresh-core-tip")
    return {
        "schema_version": RECEIPT_SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "experiment_id": EXPERIMENT_ID,
        "role": role_name,
        "journey_status": journey,
        "release": dict(release),
        "host": dict(host),
        "stages": [{"id": stage_id, "status": stages[stage_id]} for stage_id in STAGE_IDS],
        "live": dict(live) if live is not None else None,
        "next_action_codes": sorted(set(next_actions)),
        "privacy": dict(PRIVACY_FLAGS),
    }


def validate_receipt(receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        receipt,
        frozenset(
            {
                "schema_version",
                "generated_at_utc",
                "experiment_id",
                "role",
                "journey_status",
                "release",
                "host",
                "stages",
                "live",
                "next_action_codes",
                "privacy",
            }
        ),
        "onboarding receipt",
    )
    if receipt.get("schema_version") != RECEIPT_SCHEMA or receipt.get("experiment_id") != EXPERIMENT_ID:
        raise OnboardingError("invalid onboarding receipt identity")
    release = receipt.get("release")
    if not isinstance(release, dict):
        raise OnboardingError("receipt release result must be an object")
    _require_exact_keys(
        release,
        frozenset(
            {
                "policy_status",
                "activation_id",
                "manifest_verified",
                "launch_policy_verified",
                "source_commit",
                "source_tree_clean",
                "candidate_ecosystem_cid",
                "candidate_ecosystem_verified",
                "canonical_source_cid",
                "source_car_sha256",
                "canonical_source_verified",
                "source_commit_matches",
                "governance_cli_verified",
                "registry_chain_verified",
                "attested_artifacts",
                "focused_tests_passed",
                "canonical_source_published",
                "public_join_ready",
                "missing_release_gates",
            }
        ),
        "receipt release result",
    )
    if not isinstance(release.get("attested_artifacts"), dict):
        raise OnboardingError("receipt artifact bindings must be an object")
    for field in (
        "manifest_verified",
        "launch_policy_verified",
        "source_tree_clean",
        "candidate_ecosystem_verified",
        "canonical_source_verified",
        "governance_cli_verified",
        "registry_chain_verified",
        "canonical_source_published",
        "public_join_ready",
    ):
        if not isinstance(release.get(field), bool):
            raise OnboardingError(f"receipt release {field} must be boolean")
    if release.get("activation_id") is not None and not _is_sha256(
        release.get("activation_id")
    ):
        raise OnboardingError("receipt activation ID is invalid")
    source_commit = release.get("source_commit")
    if source_commit is not None and (
        not isinstance(source_commit, str)
        or len(source_commit) != COMMIT_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        raise OnboardingError("receipt source commit is invalid")
    if (
        release.get("focused_tests_passed") is not True
        and release.get("focused_tests_passed") is not False
        and release.get("focused_tests_passed") is not None
    ):
        raise OnboardingError("receipt focused-test result is invalid")
    missing_release_gates = release.get("missing_release_gates")
    if (
        not isinstance(missing_release_gates, list)
        or missing_release_gates != sorted(set(missing_release_gates))
        or any(not isinstance(item, str) or not item for item in missing_release_gates)
    ):
        raise OnboardingError("receipt missing release gates are invalid")
    if release.get("canonical_source_verified") is True:
        if (
            not _is_dag_cbor_cid(release.get("candidate_ecosystem_cid"))
            or not _is_dag_cbor_cid(release.get("canonical_source_cid"))
            or not _is_sha256(release.get("source_car_sha256"))
            or release.get("candidate_ecosystem_verified") is not True
            or release.get("source_commit_matches") is not True
            or release.get("governance_cli_verified") is not True
            or frozenset(release["attested_artifacts"]) != frozenset(REQUIRED_RUNTIME_ARTIFACTS)
        ):
            raise OnboardingError("receipt canonical source proof is incomplete")
        for name, artifact in release["attested_artifacts"].items():
            if not isinstance(artifact, dict):
                raise OnboardingError(f"receipt artifact {name} is invalid")
            _require_exact_keys(
                artifact, frozenset({"cid", "sha256", "size"}), f"receipt artifact {name}"
            )
            digest = artifact.get("sha256")
            size = artifact.get("size")
            if (
                not _is_sha256(digest)
                or not _is_positive_int(size)
                or size > MAX_ARTIFACT_BYTES
                or not _is_raw_cid(artifact.get("cid"))
                or artifact["cid"]
                != _cid_text(
                    RAW_CID_PREFIX + bytes.fromhex(digest),
                    codec_prefix=RAW_CID_PREFIX,
                    label=f"receipt artifact {name}",
                )
            ):
                raise OnboardingError(f"receipt artifact {name} binding is invalid")
    elif (
        release.get("candidate_ecosystem_cid") is not None
        or release.get("candidate_ecosystem_verified") is not False
        or release.get("canonical_source_cid") is not None
        or release.get("source_car_sha256") is not None
        or release.get("source_commit_matches") is not None
        or release.get("governance_cli_verified") is not False
        or release["attested_artifacts"] != {}
    ):
        raise OnboardingError("receipt contains an incomplete canonical source claim")
    if release.get("public_join_ready") is True and (
        release.get("policy_status") != READY_POLICY_STATUS
        or release.get("manifest_verified") is not True
        or release.get("launch_policy_verified") is not True
        or release.get("source_tree_clean") is not True
        or release.get("canonical_source_published") is not True
        or release.get("canonical_source_verified") is not True
        or release.get("registry_chain_verified") is not True
        or missing_release_gates
    ):
        raise OnboardingError("receipt public-join claim is inconsistent")
    host = receipt.get("host")
    if not isinstance(host, dict):
        raise OnboardingError("receipt host result must be an object")
    _require_exact_keys(
        host,
        frozenset(
            {
                "eligible_for_role",
                "platform_class",
                "cpu_cores",
                "memory_gib",
                "free_storage_gib",
                "storage_path_verified",
                "ssd_confirmed",
                "systemd_available",
                "missing_command_groups",
                "failed_checks",
            }
        ),
        "receipt host result",
    )
    if (
        not isinstance(host.get("eligible_for_role"), bool)
        or not isinstance(host.get("storage_path_verified"), bool)
        or not isinstance(host.get("systemd_available"), bool)
        or not _is_nonnegative_int(host.get("cpu_cores"))
        or not _is_nonnegative_int(host.get("free_storage_gib"))
        or (
            host.get("memory_gib") is not None
            and not _is_nonnegative_int(host.get("memory_gib"))
        )
        or (
            host.get("ssd_confirmed") is not True
            and host.get("ssd_confirmed") is not False
            and host.get("ssd_confirmed") is not None
        )
    ):
        raise OnboardingError("receipt host metrics are invalid")
    live = receipt.get("live")
    if live is not None:
        if not isinstance(live, dict):
            raise OnboardingError("receipt live result must be an object or null")
        _require_exact_keys(
            live,
            frozenset(
                {
                    "core_ready",
                    "core_profile_verified",
                    "core_local_service_verified",
                    "checkpoint_verified",
                    "core_height",
                    "core_tip_age_seconds",
                    "bitcoin_peers",
                    "registered_miner",
                    "verified_snapshot",
                    "snapshot_voters",
                    "reachable_gossip_peers",
                    "accepted_bitcoin_template",
                    "active_shares",
                    "miner_active_shares",
                    "miner_share_age_seconds",
                    "share_tip_present",
                }
            ),
            "receipt live result",
        )
        for field in (
            "core_ready",
            "core_profile_verified",
            "core_local_service_verified",
            "checkpoint_verified",
            "registered_miner",
            "verified_snapshot",
            "accepted_bitcoin_template",
            "share_tip_present",
        ):
            if not isinstance(live.get(field), bool):
                raise OnboardingError(f"receipt live {field} must be boolean")
        for field in (
            "core_height",
            "bitcoin_peers",
            "snapshot_voters",
            "reachable_gossip_peers",
            "active_shares",
            "miner_active_shares",
        ):
            if not _is_nonnegative_int(live.get(field)):
                raise OnboardingError(f"receipt live {field} must be nonnegative")
        for field in ("core_tip_age_seconds", "miner_share_age_seconds"):
            if live.get(field) is not None and not _is_nonnegative_int(live.get(field)):
                raise OnboardingError(f"receipt live {field} is invalid")
    stages = receipt.get("stages")
    if not isinstance(stages, list) or [stage.get("id") for stage in stages if isinstance(stage, dict)] != list(STAGE_IDS):
        raise OnboardingError("receipt stages are not the exact ordered five-stage journey")
    if receipt.get("privacy") != PRIVACY_FLAGS:
        raise OnboardingError("receipt privacy declaration is invalid")
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    forbidden_keys = (
        "idena_address",
        "miner_id",
        "peer_addr",
        "wallet",
        "cookie",
        "rpc_password",
        "datadir",
        "local_path",
    )
    if any(f'"{key}"' in encoded for key in forbidden_keys):
        raise OnboardingError("receipt contains a forbidden sensitive field")


def _prepare_output_dir(path: Path) -> Path:
    expanded = path.expanduser()
    existing = expanded
    while not existing.exists():
        if existing.parent == existing:
            raise OnboardingError("output directory has no existing ancestor")
        existing = existing.parent
    if existing.is_symlink():
        raise OnboardingError("output directory ancestor must not be a symlink")
    expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = expanded.resolve(strict=True)
    current = resolved
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise OnboardingError("output path contains a non-directory or symlink")
        if current == existing.resolve(strict=True):
            break
        current = current.parent
    os.chmod(resolved, 0o700)
    return resolved


def _atomic_private_write(path: Path, payload: bytes) -> None:
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise OnboardingError("refusing to replace an unsafe output path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def render_html(receipt: Mapping[str, Any]) -> str:
    stage_rows = "".join(
        "<li><strong>{}</strong><span class=\"{}\">{}</span></li>".format(
            html.escape(stage["id"].replace("-", " ").title()),
            html.escape(stage["status"]),
            html.escape(stage["status"].replace("-", " ").title()),
        )
        for stage in receipt["stages"]
    )
    actions = "".join(
        "<li><span>{}</span><code>{}</code></li>".format(
            html.escape(ACTION_LABELS.get(action, action.replace("-", " ").capitalize())),
            html.escape(action),
        )
        for action in receipt["next_action_codes"]
    ) or "<li>None</li>"
    release = receipt["release"]
    release_rows = "".join(
        "<li><strong>{}</strong><code>{}</code></li>".format(
            html.escape(label), html.escape(str(value))
        )
        for label, value in (
            ("Canonical source CID", release.get("canonical_source_cid") or "unavailable"),
            ("Source CAR SHA-256", release.get("source_car_sha256") or "unavailable"),
            ("Git commit metadata", release.get("source_commit") or "unavailable"),
            (
                "Registry chain verification",
                "passed" if release.get("registry_chain_verified") is True else "not verified",
            ),
        )
    )
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>P2poolBTC Experiment 1 onboarding</title>
<style>
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #17211f; background: #f5f7f6; }
body { margin: 0; } main { max-width: 880px; margin: 0 auto; padding: 32px 20px 64px; }
header { border-bottom: 3px solid #087f6b; padding-bottom: 20px; } h1 { font-size: 28px; margin: 0 0 8px; letter-spacing: 0; }
.eyebrow { color: #087f6b; font-weight: 700; text-transform: uppercase; font-size: 12px; } .status { font-size: 18px; font-weight: 700; }
section { margin-top: 28px; } ul { list-style: none; padding: 0; margin: 0; border-top: 1px solid #d6dfdc; }
li { display: flex; justify-content: space-between; gap: 16px; padding: 13px 0; border-bottom: 1px solid #d6dfdc; }
.passed, .not-required { color: #087f6b; } .blocked { color: #b42318; } .pending { color: #8a5a00; }
.note { border-left: 3px solid #d28a00; padding: 12px 14px; background: #fff8e8; } code { overflow-wrap: anywhere; }
@media (max-width: 560px) { li { align-items: flex-start; flex-direction: column; gap: 4px; } }
</style></head><body><main>
<header><div class="eyebrow">Experimental, no-value network</div><h1>Community onboarding receipt</h1>
<div class="status">@@JOURNEY@@</div><p>Role: <strong>@@ROLE@@</strong></p></header>
<section><h2>Five-stage journey</h2><ul>@@STAGES@@</ul></section>
<section><h2>Verified release binding</h2><ul>@@RELEASE@@</ul>
<p>The source CID and CAR digest are authoritative. The Git commit is mirror metadata only.</p></section>
<section><h2>Next actions</h2><ul>@@ACTIONS@@</ul></section>
<section class="note"><strong>Privacy:</strong> this report intentionally excludes identity, miner, peer, wallet, RPC-secret, and local-path data. It is diagnostic evidence, not a release or chain attestation.</section>
</main></body></html>
"""
    return (
        document.replace(
            "@@JOURNEY@@", html.escape(receipt["journey_status"].replace("-", " ").title())
        )
        .replace("@@ROLE@@", html.escape(receipt["role"].replace("-", " ").title()))
        .replace("@@STAGES@@", stage_rows)
        .replace("@@RELEASE@@", release_rows)
        .replace("@@ACTIONS@@", actions)
    )


def render_issue_report(receipt: Mapping[str, Any]) -> str:
    stages = "\n".join(f"- {stage['id']}: `{stage['status']}`" for stage in receipt["stages"])
    actions = "\n".join(f"- `{action}`" for action in receipt["next_action_codes"]) or "- none"
    host = receipt["host"]
    return f"""# Experiment 1 onboarding issue

Do not add identity addresses, miner IDs, peer endpoints, wallet data, RPC credentials, or local paths.

## Redacted status

- Receipt schema: `{receipt['schema_version']}`
- Role: `{receipt['role']}`
- Journey status: `{receipt['journey_status']}`
- Canonical source CID: `{receipt['release']['canonical_source_cid'] or 'unavailable'}`
- Source CAR SHA-256: `{receipt['release']['source_car_sha256'] or 'unavailable'}`
- Git commit metadata: `{receipt['release']['source_commit'] or 'unavailable'}`
- Activation ID: `{receipt['release']['activation_id'] or 'unavailable'}`
- Policy status: `{receipt['release']['policy_status']}`
- Manifest verified: `{str(receipt['release']['manifest_verified']).lower()}`
- Launch policy verified: `{str(receipt['release']['launch_policy_verified']).lower()}`
- Host eligible: `{str(host['eligible_for_role']).lower()}`
- Platform class: `{host['platform_class']}`

## Stages

{stages}

## Next-action codes

{actions}

## What happened?

Describe the expected and observed behavior. Redact all private data before posting.
"""


def write_outputs(receipt: Mapping[str, Any], output_dir: Path) -> dict[str, Path]:
    directory = _prepare_output_dir(output_dir)
    paths = {
        "receipt": directory / "onboarding-receipt.json",
        "report": directory / "onboarding-report.html",
        "issue": directory / "issue-report.md",
    }
    _atomic_private_write(
        paths["receipt"], (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    _atomic_private_write(paths["report"], render_html(receipt).encode("utf-8"))
    _atomic_private_write(paths["issue"], render_issue_report(receipt).encode("utf-8"))
    return paths


def _open_report(path: Path) -> None:
    if sys.platform == "darwin":
        command = ("open", str(path))
    elif os.name == "nt":
        try:
            os.startfile(str(path))  # type: ignore[attr-defined]
            return
        except OSError as exc:
            raise OnboardingError("could not open the local report") from exc
    else:
        command = ("xdg-open", str(path))
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env=_sanitized_environment(Path.home()),
        )
    except OSError as exc:
        raise OnboardingError("could not open the local report") from exc


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    repo_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("observer", "pruned-miner", "archive-operator"), required=True)
    parser.add_argument("--repo-root", type=Path, default=repo_default)
    parser.add_argument(
        "--profile",
        type=Path,
        default=repo_default / "compatibility" / "experiment-1-onboarding-profile.json",
    )
    parser.add_argument("--storage-path", type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.home() / ".pohw-onboarding" / "pohw-experiment-1",
    )
    parser.add_argument(
        "--run-tests",
        action="store_true",
        help="refuse and direct the operator to the disposable clean-room builder workflow",
    )
    parser.add_argument("--json", action="store_true", help="print only the redacted receipt JSON")
    parser.add_argument("--open-report", action="store_true", help="open the generated local static report")
    parser.add_argument("--readiness-car", type=Path)
    parser.add_argument("--readiness-evidence-car", type=Path)
    parser.add_argument(
        "--expected-ecosystem-cid",
        help="canonical EcosystemManifestV1 CID independently read from Idena governance",
    )
    parser.add_argument(
        "--candidate-ecosystem-car",
        type=Path,
        help="DAO-authorized EcosystemManifestV1 CAR bound by readiness evidence",
    )
    parser.add_argument(
        "--source-car",
        type=Path,
        help="canonical P2poolBTC source-tree CAR named by the ecosystem manifest",
    )
    parser.add_argument("--governance-cli", type=Path)
    parser.add_argument("--idena-anchor-policy", type=Path)
    parser.add_argument(
        "--idena-rpc-url",
        default="http://127.0.0.1:9009",
        help="synchronized loopback Idena RPC used to verify the registry deployment",
    )
    parser.add_argument("--idena-api-key-file", type=Path)
    parser.add_argument("--probe-live", action="store_true", help="read-only live proof; policy must already be ready")
    parser.add_argument("--p2pool-node", type=Path)
    parser.add_argument("--p2pool-datadir", type=Path)
    parser.add_argument("--snapshot-dir", type=Path)
    parser.add_argument("--miner-id")
    parser.add_argument("--bitcoin-cli", type=Path)
    parser.add_argument("--bitcoin-datadir", type=Path)
    parser.add_argument("--bitcoin-cookie-file", type=Path)
    return parser.parse_args(argv)


def execute(
    args: argparse.Namespace,
    *,
    host_inspector: Callable[[Mapping[str, Any], Path, Path], dict[str, Any]] = inspect_host,
    release_verifier: Callable[..., dict[str, Any]] = verify_release,
    live_prober: Callable[..., dict[str, Any]] = probe_live,
) -> tuple[dict[str, Any], dict[str, Path], int]:
    repo_root = args.repo_root.resolve(strict=True)
    output_path = args.output_dir.expanduser().resolve(strict=False)
    if output_path == repo_root or repo_root in output_path.parents:
        raise OnboardingError("output directory must remain outside the source checkout")
    profile_path = args.profile
    if not profile_path.is_absolute():
        profile_path = repo_root / profile_path
    canonical_profile = repo_root / "compatibility" / "experiment-1-onboarding-profile.json"
    try:
        if profile_path.resolve(strict=True) != canonical_profile.resolve(strict=True):
            raise OnboardingError("only the repository's canonical Experiment 1 profile is accepted")
    except OSError as exc:
        raise OnboardingError("canonical onboarding profile is unavailable") from exc
    profile = _read_json(profile_path, "onboarding profile")
    validated = validate_profile(profile, repo_root)
    role = profile["roles"][args.role]
    if role["live_join"] and args.storage_path is None:
        raise OnboardingError("live node roles require an explicit existing --storage-path")
    storage_path = args.storage_path or repo_root
    if not storage_path.is_absolute():
        storage_path = repo_root / storage_path
    host = host_inspector(role, storage_path, repo_root)
    release = release_verifier(
        repo_root,
        validated,
        expected_ecosystem_cid=args.expected_ecosystem_cid,
        readiness_car=args.readiness_car,
        readiness_evidence_car=args.readiness_evidence_car,
        candidate_ecosystem_car=args.candidate_ecosystem_car,
        source_car=args.source_car,
        governance_cli=args.governance_cli,
        idena_anchor_policy=args.idena_anchor_policy,
        p2pool_node=args.p2pool_node,
        idena_rpc_url=args.idena_rpc_url,
        idena_api_key_file=args.idena_api_key_file,
        run_tests=args.run_tests,
    )
    live = None
    if args.probe_live:
        if not role["live_join"]:
            raise OnboardingError("observer role cannot run a live mining probe")
        if not host["eligible_for_role"]:
            raise OnboardingError("live probe refused: host does not satisfy the selected role")
        if not release["public_join_ready"]:
            raise OnboardingError("live probe refused: verified policy is not ready for public joining")
        live = live_prober(
            args,
            repo_root,
            profile["live_success"],
            validated["core_expectations"],
            release,
        )
        final_commit, final_clean = _git_source_state(repo_root)
        if not final_clean or final_commit != release["source_commit"]:
            raise OnboardingError("source checkout changed during the live proof")
    receipt = build_receipt(
        role_name=args.role,
        role=role,
        release=release,
        host=host,
        live=live,
        live_policy=profile["live_success"],
    )
    validate_receipt(receipt)
    paths = write_outputs(receipt, args.output_dir)
    if args.open_report:
        _open_report(paths["report"])
    successful = receipt["journey_status"] in (
        "review-ready",
        "ready-for-identity-registration",
        "live-join-verified",
    )
    return receipt, paths, 0 if successful else 2


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        receipt, paths, exit_code = execute(args)
        if args.json:
            print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        else:
            print(f"Experiment 1 onboarding: {receipt['journey_status']}")
            for stage in receipt["stages"]:
                print(f"  {stage['id']}: {stage['status']}")
            if receipt["next_action_codes"]:
                print("Next actions:")
                for action in receipt["next_action_codes"]:
                    print(f"  - {ACTION_LABELS.get(action, action.replace('-', ' ').capitalize())}")
            print(f"Redacted receipt: {paths['receipt']}")
            print(f"Local report: {paths['report']}")
            print(f"Issue template: {paths['issue']}")
        return exit_code
    except (OnboardingError, OSError) as exc:
        print(f"onboarding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
