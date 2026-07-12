#!/usr/bin/env python3
"""Validate the exact legacy-compatible Idena candidate consumed by PoHW."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "compatibility" / "stack-lock.json"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_LOCK_BYTES = 1024 * 1024
EXPECTED = {
    "release_id": "idena-mainnet-legacy-compat-2026.07.12-rc2",
    "legacy_commit": "938be81dbdeff85f888f4337060a8ebabb12e5b5",
    "node_commit": "4947ddfd41391cca0e51dc2635aaa8a06827a890",
    "gossip_protocol": "/idena/gossip/1.1.0",
    "intermediateGenesisHeaderSha256": "27e696414b955714ba7ed4defe063794c8dcadef28a7e61dd9249b8623571b3c",
    "stateSnapshotSha256": "7cf6f8c334d76a3617cbd5ac3aa5a104a8d337cb6ceb8d6906c62bf7fab8d131",
    "identitySnapshotSha256": "f136ec8939e3f78587a38de517128c7071501e283bac7d12c24ce4be830ff8aa",
}


class CompatibilityError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompatibilityError(message)


def load_json(path: Path) -> Any:
    stat = path.lstat()
    require(stat.st_size <= MAX_LOCK_BYTES, "compatibility lock is unexpectedly large")
    require(path.is_file() and not path.is_symlink(), "compatibility lock must be a regular file")
    try:
        return json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompatibilityError("compatibility lock is not valid UTF-8 JSON") from exc


def verify_lock(lock: Any) -> None:
    require(isinstance(lock, dict), "compatibility lock must be an object")
    require(lock.get("schema") == 1, "unsupported compatibility lock schema")
    require(lock.get("releaseId") == EXPECTED["release_id"], "unexpected release candidate")
    require(lock.get("status") == "candidate", "release status lacks external attestation")

    legacy = lock.get("legacyBaseline", {})
    require(legacy.get("nodeVersion") == "1.1.2", "legacy node version changed")
    require(legacy.get("commit") == EXPECTED["legacy_commit"], "legacy baseline changed")

    invariants = lock.get("chainInvariants", {})
    require(invariants.get("mainnetNetworkId") == 1, "mainnet network ID changed")
    require(
        invariants.get("gossipProtocol") == EXPECTED["gossip_protocol"],
        "gossip protocol changed",
    )
    require(invariants.get("consensusChangesAllowed") is False, "consensus changes were enabled")
    for field in (
        "intermediateGenesisHeaderSha256",
        "stateSnapshotSha256",
        "identitySnapshotSha256",
    ):
        require(invariants.get(field) == EXPECTED[field], f"{field} changed")

    components = [
        component
        for component in lock.get("components", [])
        if isinstance(component, dict) and component.get("name") == "idena-go"
    ]
    require(len(components) == 1, "expected exactly one idena-go component")
    require(
        components[0].get("repository") == "https://github.com/ubiubi18/idena-go.git",
        "unexpected idena-go repository",
    )
    require(components[0].get("commit") == EXPECTED["node_commit"], "node commit changed")
    pin = lock.get("consumerPins", {}).get("P2poolBTC", {}).get("idena-go")
    require(pin == EXPECTED["node_commit"], "PoHW node pin changed")

    gates = set(lock.get("requiredGates", []))
    for gate in (
        "legacy-block-rpc-differential",
        "legacy-state-replay-differential",
        "legacy-modern-p2p-interoperability",
        "secret-scan",
    ):
        require(gate in gates, f"required gate missing: {gate}")


def verify_provenance(path: Path, expected_commit: str) -> None:
    stat = path.lstat()
    require(stat.st_size <= 128, "source provenance file is unexpectedly large")
    require(path.is_file() and not path.is_symlink(), "source provenance must be a regular file")
    try:
        value = path.read_text(encoding="ascii").strip()
    except UnicodeDecodeError as exc:
        raise CompatibilityError("source provenance is not ASCII") from exc
    require(bool(SHA1_RE.fullmatch(value)), "source provenance is not a commit hash")
    require(value == expected_commit, "source provenance does not match the compatibility lock")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--modern-provenance-file", type=Path)
    parser.add_argument("--legacy-provenance-file", type=Path)
    args = parser.parse_args()
    try:
        verify_lock(load_json(args.lock))
        if args.modern_provenance_file:
            verify_provenance(args.modern_provenance_file, EXPECTED["node_commit"])
        if args.legacy_provenance_file:
            verify_provenance(args.legacy_provenance_file, EXPECTED["legacy_commit"])
    except (CompatibilityError, OSError) as exc:
        print(f"Idena compatibility check failed: {exc}", file=sys.stderr)
        return 1
    print("Idena compatibility lock verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
