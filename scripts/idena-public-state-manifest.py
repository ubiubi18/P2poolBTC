#!/usr/bin/env python3
"""Create and validate secret-free Idena public-state transfer manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2
COMPONENTS = ("idenachain.db", "ipfs-badgerds", "snapshots")
METADATA_FILES = ("manifest.json", "READY")
HASH_ALGORITHM = "sha256-tree-v1"
TRANSFER_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
FORBIDDEN_NAMES = {
    "api.key",
    "config",
    "keystore",
    "nodekey",
    "swarm.key",
    "wallet",
}
MANIFEST_KEYS = {
    "schema",
    "createdAt",
    "transferId",
    "sourceHeight",
    "sourceHighest",
    "hashAlgorithm",
    "components",
}
READY_KEYS = {"schema", "transferId", "sourceHeight"}


class ManifestError(ValueError):
    pass


def ensure_plain_directory(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise ManifestError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise ManifestError(f"{label} must be a non-symlink directory: {path}")


def validate_name(path: Path) -> None:
    name = path.name.lower()
    if (
        name in FORBIDDEN_NAMES
        or name.startswith("api.key")
        or "nodekey" in name
        or "secret" in name
        or "wallet" in name
    ):
        raise ManifestError(f"forbidden transfer path: {path}")


def component_stats(root: Path, component: str) -> dict[str, int | str]:
    component_root = root / component
    ensure_plain_directory(component_root, component)
    files = 0
    size = 0
    digest = hashlib.sha256()
    digest.update(b"pohw-idena-public-state-tree-v1\0")
    for current_root, directory_names, file_names in os.walk(
        component_root, topdown=True, followlinks=False
    ):
        current = Path(current_root)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            path = current / name
            validate_name(path)
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise ManifestError(f"non-directory entry in transfer tree: {path}")
        for name in file_names:
            path = current / name
            validate_name(path)
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise ManifestError(f"non-regular file in transfer tree: {path}")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(path, flags)
            except OSError as exc:
                raise ManifestError(f"cannot safely open transfer file: {path}") from exc
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise ManifestError(f"opened transfer path is not a regular file: {path}")
                if opened.st_nlink != 1:
                    raise ManifestError(f"transfer file must have exactly one hard link: {path}")
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise ManifestError(f"transfer file changed while opening: {path}")
                try:
                    relative = path.relative_to(component_root).as_posix().encode("utf-8")
                except UnicodeError as exc:
                    raise ManifestError(f"transfer filename is not valid UTF-8: {path}") from exc
                digest.update(len(relative).to_bytes(8, "big"))
                digest.update(relative)
                digest.update(opened.st_size.to_bytes(8, "big"))
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                after = os.fstat(descriptor)
                if (
                    after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                    or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                ):
                    raise ManifestError(f"transfer file changed while hashing: {path}")
            finally:
                os.close(descriptor)
            files += 1
            size += opened.st_size
    return {"files": files, "bytes": size, "sha256": digest.hexdigest()}


def validate_top_level(root: Path, *, allow_metadata: bool) -> None:
    allowed = set(COMPONENTS)
    if allow_metadata:
        allowed.update(METADATA_FILES)
    actual = {entry.name for entry in root.iterdir()}
    unexpected = sorted(actual - allowed)
    required = set(COMPONENTS)
    if allow_metadata:
        required.update(METADATA_FILES)
    missing = sorted(required - actual)
    if unexpected:
        raise ManifestError("unexpected top-level transfer entries: " + ", ".join(unexpected))
    if missing:
        raise ManifestError("missing transfer components: " + ", ".join(missing))


def validate_transfer_id(transfer_id: Any) -> str:
    if not isinstance(transfer_id, str) or not TRANSFER_ID_PATTERN.fullmatch(transfer_id):
        raise ManifestError("transferId must be 32 lowercase hexadecimal characters")
    return transfer_id


def build_manifest(
    root: Path, transfer_id: str, source_height: int, source_highest: int
) -> dict[str, Any]:
    ensure_plain_directory(root, "transfer root")
    validate_top_level(root, allow_metadata=False)
    validate_transfer_id(transfer_id)
    if source_height < 0 or source_highest < 0:
        raise ManifestError("source heights must be non-negative")
    if source_height > source_highest:
        raise ManifestError("source height cannot exceed source highest block")
    return {
        "schema": SCHEMA_VERSION,
        "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "transferId": transfer_id,
        "sourceHeight": source_height,
        "sourceHighest": source_highest,
        "hashAlgorithm": HASH_ALGORITHM,
        "components": {name: component_stats(root, name) for name in COMPONENTS},
    }


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
        parent_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def load_json_object(path: Path, *, label: str, max_bytes: int) -> dict[str, Any]:
    metadata = path.lstat() if path.exists() or path.is_symlink() else None
    if (
        metadata is None
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ManifestError(f"{label} must be a regular, non-symlink file")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read {label}: {path}") from exc
    if len(raw.encode("utf-8")) > max_bytes:
        raise ManifestError(f"{label} is unexpectedly large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ManifestError(f"{label} root must be an object")
    return payload


def validate_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    ensure_plain_directory(root, "transfer root")
    if manifest_path.parent.resolve() != root.resolve():
        raise ManifestError("manifest must be located directly inside the transfer root")
    validate_top_level(root, allow_metadata=True)
    payload = load_json_object(manifest_path, label="manifest", max_bytes=64 * 1024)
    if set(payload) != MANIFEST_KEYS:
        raise ManifestError("manifest fields do not match the transfer contract")
    if payload.get("schema") != SCHEMA_VERSION:
        raise ManifestError(f"unsupported manifest schema: {payload.get('schema')!r}")
    validate_transfer_id(payload.get("transferId"))
    if payload.get("hashAlgorithm") != HASH_ALGORITHM:
        raise ManifestError(f"unsupported hash algorithm: {payload.get('hashAlgorithm')!r}")
    created_at = payload.get("createdAt")
    if not isinstance(created_at, str) or not created_at or len(created_at) > 64:
        raise ManifestError("createdAt must be a short timestamp string")
    source_height = payload.get("sourceHeight")
    source_highest = payload.get("sourceHighest")
    if not isinstance(source_height, int) or isinstance(source_height, bool) or source_height < 0:
        raise ManifestError("sourceHeight must be a non-negative integer")
    if not isinstance(source_highest, int) or isinstance(source_highest, bool) or source_highest < 0:
        raise ManifestError("sourceHighest must be a non-negative integer")
    if source_height > source_highest:
        raise ManifestError("sourceHeight cannot exceed sourceHighest")
    components = payload.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise ManifestError("manifest components do not match the transfer contract")
    for name in COMPONENTS:
        expected = components.get(name)
        if not isinstance(expected, dict) or set(expected) != {"files", "bytes", "sha256"}:
            raise ManifestError(f"invalid component manifest: {name}")
        if any(
            not isinstance(expected[key], int)
            or isinstance(expected[key], bool)
            or expected[key] < 0
            for key in ("files", "bytes")
        ):
            raise ManifestError(f"invalid component counters: {name}")
        expected_digest = expected.get("sha256")
        if (
            not isinstance(expected_digest, str)
            or len(expected_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_digest)
        ):
            raise ManifestError(f"invalid component digest: {name}")
        actual = component_stats(root, name)
        if actual != expected:
            raise ManifestError(
                f"component counters differ for {name}: expected={expected} actual={actual}"
            )
    ready = load_json_object(root / "READY", label="READY", max_bytes=4096)
    if set(ready) != READY_KEYS:
        raise ManifestError("READY fields do not match the transfer contract")
    if ready.get("schema") != SCHEMA_VERSION:
        raise ManifestError(f"unsupported READY schema: {ready.get('schema')!r}")
    validate_transfer_id(ready.get("transferId"))
    if ready.get("transferId") != payload.get("transferId"):
        raise ManifestError("READY transferId does not match manifest")
    if ready.get("sourceHeight") != payload.get("sourceHeight"):
        raise ManifestError("READY sourceHeight does not match manifest")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--root", type=Path, required=True)
    create.add_argument("--transfer-id", required=True)
    create.add_argument("--source-height", type=int, required=True)
    create.add_argument("--source-highest", type=int, required=True)
    create.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--root", type=Path, required=True)
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--print-source-height", action="store_true")
    validate.add_argument("--print-summary", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        ensure_plain_directory(args.root, "transfer root")
        root = args.root.resolve(strict=True)
        if args.command == "create":
            output = args.output.absolute()
            if output.is_symlink():
                raise ManifestError("output manifest must not be a symlink")
            if output.parent.resolve(strict=True) != root:
                raise ManifestError("output manifest must be directly inside the transfer root")
            payload = build_manifest(
                root, args.transfer_id, args.source_height, args.source_highest
            )
            atomic_write_json(output, payload)
            return 0
        manifest = args.manifest.absolute()
        if manifest.is_symlink():
            raise ManifestError("manifest must not be a symlink")
        payload = validate_manifest(root, manifest)
        if args.print_source_height:
            print(payload["sourceHeight"])
        if args.print_summary:
            total_bytes = sum(
                component["bytes"] for component in payload["components"].values()
            )
            print(payload["sourceHeight"], payload["transferId"], total_bytes)
        return 0
    except (ManifestError, OSError) as exc:
        print(f"Idena public-state manifest error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
