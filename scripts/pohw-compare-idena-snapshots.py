#!/usr/bin/env python3
"""Verify and compare independent Experiment 2 Idena snapshot captures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "pohw-consensus-identity-snapshot-comparison/v1"
VERIFICATION_SCHEMA = "pohw-consensus-identity-snapshot-verification/v1"
MAX_REPORT_BYTES = 1024 * 1024
EXPECTED_KEYS = {
    "schema_version",
    "status",
    "experiment_id",
    "registry_contract_address",
    "source_input_hash",
    "idena_finalized_height",
    "idena_finalized_timestamp",
    "idena_finalized_block_hash",
    "idena_identity_root",
    "idena_finality_height",
    "idena_finality_block_hash",
    "finality_confirmations",
    "idena_next_validation_timestamp",
    "authorization_root",
    "authorized_identity_count",
}
MATCH_KEYS = tuple(sorted(EXPECTED_KEYS - {"schema_version", "status"}))


class SnapshotComparisonError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SnapshotComparisonError(message)


def duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise SnapshotComparisonError(f"cannot open verifier {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"verifier is not a regular file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            f"verifier changed while hashing: {path}",
        )
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def require_distinct_regular_capture_files(
    input_paths: list[Path], bundle_paths: list[Path]
) -> None:
    seen_paths: set[Path] = set()
    seen_files: set[tuple[int, int]] = set()
    for kind, paths in (("input", input_paths), ("bundle", bundle_paths)):
        for index, path in enumerate(paths):
            require(not path.is_symlink(), f"snapshot {kind} {index} must not be a symlink")
            try:
                resolved = path.resolve(strict=True)
                metadata = os.lstat(path)
            except OSError as exc:
                raise SnapshotComparisonError(
                    f"cannot inspect snapshot {kind} {index}: {exc}"
                ) from exc
            require(
                stat.S_ISREG(metadata.st_mode),
                f"snapshot {kind} {index} must be a regular file",
            )
            require(
                resolved not in seen_paths,
                f"snapshot {kind} {index} repeats a capture path",
            )
            identity = (metadata.st_dev, metadata.st_ino)
            require(
                identity not in seen_files,
                f"snapshot {kind} {index} repeats a capture file",
            )
            seen_paths.add(resolved)
            seen_files.add(identity)


def parse_report(raw: bytes) -> dict[str, Any]:
    require(len(raw) <= MAX_REPORT_BYTES, "snapshot verifier output is too large")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate_safe_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotComparisonError(f"snapshot verifier returned invalid JSON: {exc}") from exc
    require(isinstance(report, dict), "snapshot verifier output must be an object")
    require(set(report) == EXPECTED_KEYS, "snapshot verifier output fields differ")
    require(report["schema_version"] == VERIFICATION_SCHEMA, "snapshot verifier schema differs")
    require(report["status"] == "verified-inactive-input", "snapshot is not a verified inactive input")
    return report


def verify_pair(verifier: Path, input_path: Path, bundle_path: Path) -> tuple[dict[str, Any], str]:
    result = subprocess.run(
        [
            str(verifier),
            "consensus-identity-verify",
            "--input-file",
            str(input_path.absolute()),
            "--bundle-file",
            str(bundle_path.absolute()),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    require(
        result.returncode == 0,
        f"snapshot verification failed for {input_path.name}/{bundle_path.name}",
    )
    return parse_report(result.stdout), hashlib.sha256(result.stdout).hexdigest()


def compare(
    verifier: Path,
    input_paths: list[Path],
    bundle_paths: list[Path],
    minimum: int,
) -> dict[str, Any]:
    require(minimum >= 3, "snapshot assurance requires at least three captures")
    require(len(input_paths) == len(bundle_paths), "input and bundle counts differ")
    require(len(input_paths) >= minimum, f"at least {minimum} snapshot pairs are required")
    require_distinct_regular_capture_files(input_paths, bundle_paths)
    require(not verifier.is_symlink(), "snapshot verifier must not be a symlink")
    verifier = verifier.resolve(strict=True)
    require(os.access(verifier, os.X_OK), "snapshot verifier must be executable")
    verifier_digest = file_sha256(verifier)

    expected: dict[str, Any] | None = None
    verification_digests: list[str] = []
    for input_path, bundle_path in zip(input_paths, bundle_paths):
        report, report_digest = verify_pair(verifier, input_path, bundle_path)
        if expected is None:
            expected = report
        else:
            mismatches = [key for key in MATCH_KEYS if report[key] != expected[key]]
            require(not mismatches, f"snapshot boundaries or roots differ: {', '.join(mismatches)}")
        verification_digests.append(report_digest)

    assert expected is not None
    return {
        "schema_version": SCHEMA,
        "status": "matching-snapshot-boundary-unattributed",
        "experiment_id": expected["experiment_id"],
        "registry_contract_address": expected["registry_contract_address"],
        "source_input_hash": expected["source_input_hash"],
        "idena_finalized_height": expected["idena_finalized_height"],
        "idena_finalized_block_hash": expected["idena_finalized_block_hash"],
        "idena_identity_root": expected["idena_identity_root"],
        "idena_finality_height": expected["idena_finality_height"],
        "idena_finality_block_hash": expected["idena_finality_block_hash"],
        "finality_confirmations": expected["finality_confirmations"],
        "authorization_root": expected["authorization_root"],
        "authorized_identity_count": expected["authorized_identity_count"],
        "verifier_sha256": verifier_digest,
        "matching_capture_count": len(input_paths),
        "minimum_matching_captures": minimum,
        "verification_sha256": sorted(verification_digests),
        "distinct_capture_files_verified": True,
        "identity_rows_assurance": "compatible-rpc-unproven",
        "identity_rows_cryptographically_bound_to_root": False,
        "operator_independence_verified": False,
        "release_authorized": False,
        "next_gate": "replay finalized identity state or add row proofs, then authenticate each capture with a distinct eligible Idena owner",
    }


def write_new(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("ascii")
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    try:
        os.link(temporary, path)
    except FileExistsError as exc:
        raise SnapshotComparisonError("comparison output must be new") from exc
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indexer-bin", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--bundle", type=Path, action="append", required=True)
    parser.add_argument("--minimum-captures", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = compare(
            args.indexer_bin,
            args.input,
            args.bundle,
            args.minimum_captures,
        )
        if args.output:
            write_new(args.output, report)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (OSError, subprocess.SubprocessError, SnapshotComparisonError) as exc:
        print(f"Idena snapshot comparison failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
