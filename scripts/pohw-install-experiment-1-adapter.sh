#!/usr/bin/env bash
set -euo pipefail

umask 022

SYSTEMCTL_OVERRIDE=${POHW_SYSTEMCTL_BIN-}
SYSTEMCTL_OVERRIDE_SET=${POHW_SYSTEMCTL_BIN+x}
if [[ ${EUID:-0} -eq 0 ]]; then
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  if [[ "$SYSTEMCTL_OVERRIDE_SET" == x && "$SYSTEMCTL_OVERRIDE" != /usr/bin/systemctl ]]; then
    echo "POHW_SYSTEMCTL_BIN cannot override /usr/bin/systemctl during a root install" >&2
    exit 1
  fi
  SYSTEMCTL_BIN=/usr/bin/systemctl
else
  SYSTEMCTL_BIN="${SYSTEMCTL_OVERRIDE:-systemctl}"
fi
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE="target/release/p2pool-node"
DEFAULT_DESTINATION="/usr/local/libexec/p2pool-experiment-1/p2pool-node"
DESTINATION="$DEFAULT_DESTINATION"
BUILD_EVIDENCE=""
EXPECTED_EVIDENCE_SHA256=""
EXPECTED_SOURCE_CID=""
BUILD_PLAN="$REPO_ROOT/compatibility/governance-build-plan-v1.json"
SOURCE_ROOT="$REPO_ROOT"
SERVICES=(pohw-mining-adapter.service pohw-gossip-mesh.service)

usage() {
  cat <<'EOF'
Usage: pohw-install-experiment-1-adapter.sh [options]

Options:
  --binary PATH       Release p2pool-node binary to install.
  --build-evidence FILE
                      Verified rust-workspace build-evidence.json.
  --expected-evidence-sha256 HEX
                      SHA-256 obtained independently for build-evidence.json.
  --expected-source-cid CID
                      Canonical P2poolBTC source CID obtained independently.
  --build-plan FILE   Exact governance build plan used by the evidence.
  --source-root DIR   Canonical P2poolBTC source root used by the build.
  --destination PATH  Exact service binary destination.
  --help              Show this help.

The installer never executes caller-supplied code. It refuses active P2Pool
services, binds the candidate bytes to clean-room source/build evidence,
installs atomically, and retains one .previous rollback copy.
EOF
}

while (($#)); do
  case "$1" in
    --binary)
      [[ $# -ge 2 ]] || { echo "--binary requires a path" >&2; exit 2; }
      SOURCE="$2"
      shift 2
      ;;
    --build-evidence)
      [[ $# -ge 2 ]] || { echo "--build-evidence requires a path" >&2; exit 2; }
      BUILD_EVIDENCE="$2"
      shift 2
      ;;
    --expected-evidence-sha256)
      [[ $# -ge 2 ]] || { echo "--expected-evidence-sha256 requires a value" >&2; exit 2; }
      EXPECTED_EVIDENCE_SHA256="$2"
      shift 2
      ;;
    --expected-source-cid)
      [[ $# -ge 2 ]] || { echo "--expected-source-cid requires a value" >&2; exit 2; }
      EXPECTED_SOURCE_CID="$2"
      shift 2
      ;;
    --build-plan)
      [[ $# -ge 2 ]] || { echo "--build-plan requires a path" >&2; exit 2; }
      BUILD_PLAN="$2"
      shift 2
      ;;
    --source-root)
      [[ $# -ge 2 ]] || { echo "--source-root requires a path" >&2; exit 2; }
      SOURCE_ROOT="$2"
      shift 2
      ;;
    --destination)
      [[ $# -ge 2 ]] || { echo "--destination requires a path" >&2; exit 2; }
      DESTINATION="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$BUILD_EVIDENCE" ]] || {
  echo "--build-evidence is required; privileged installation refuses unbound binaries" >&2
  exit 2
}
[[ "$EXPECTED_EVIDENCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "--expected-evidence-sha256 must be an independently obtained lowercase SHA-256" >&2
  exit 2
}
[[ "$EXPECTED_SOURCE_CID" =~ ^b[a-z2-7]{20,120}$ ]] || {
  echo "--expected-source-cid must be an independently obtained canonical base32 CIDv1" >&2
  exit 2
}
if [[ ${EUID:-0} -eq 0 && "$DESTINATION" != "$DEFAULT_DESTINATION" ]]; then
  echo "root installation is restricted to the service's exact binary destination" >&2
  exit 1
fi
if [[ ${EUID:-0} -eq 0 && ! -x "$SYSTEMCTL_BIN" ]]; then
  echo "trusted systemctl is unavailable: $SYSTEMCTL_BIN" >&2
  exit 1
fi
if [[ -L "$SOURCE" || ! -f "$SOURCE" ]]; then
  echo "Adapter binary must be a regular non-symlink file: $SOURCE" >&2
  exit 1
fi
if [[ ! -x "$SOURCE" ]]; then
  echo "Adapter binary is not executable: $SOURCE" >&2
  exit 1
fi
if [[ -L "$DESTINATION" ]]; then
  echo "Adapter destination must not be a symlink: $DESTINATION" >&2
  exit 1
fi
if [[ -e "$DESTINATION" && ! -f "$DESTINATION" ]]; then
  echo "Adapter destination is not a regular file: $DESTINATION" >&2
  exit 1
fi

# Verify a governance build-evidence package without importing or executing
# anything from the candidate source tree. The evidence package binds the
# exact artifact, dependency lock, source CID, command results, build plan,
# and clean-room properties. Its CID must still be checked through an
# independent channel by the operator; this installer is not a trust oracle.
EXPECTED_SHA256=$(python3 -I - \
  "$SOURCE" "$BUILD_EVIDENCE" "$BUILD_PLAN" "$SOURCE_ROOT" \
  "$EXPECTED_EVIDENCE_SHA256" "$EXPECTED_SOURCE_CID" <<'PY'
import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

MAX_JSON_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CID_RE = re.compile(r"^b[a-z2-7]{20,120}$")

class VerificationError(ValueError):
    pass

def require(value, message):
    if not value:
        raise VerificationError(message)

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value

def read_regular(path, label, maximum=MAX_JSON_BYTES):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), f"{label} must be a regular non-symlink file")
    require(before.st_size <= maximum, f"{label} exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), f"{label} changed before reading")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    require(
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        and len(raw) == opened.st_size,
        f"{label} changed while reading",
    )
    return raw

def load_json(path, label):
    raw = read_regular(path, label)
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} root must be an object")
    return value, raw

def canonical_json(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()

def encode_varint(value):
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)

def raw_cid(digest):
    value = encode_varint(1) + encode_varint(0x55) + encode_varint(0x12) + encode_varint(32) + bytes.fromhex(digest)
    return "b" + base64.b32encode(value).decode().lower().rstrip("=")

def reference(raw):
    digest = hashlib.sha256(raw).hexdigest()
    return {"cid": raw_cid(digest), "sha256": digest, "size": len(raw)}

def verify_reference(actual, raw, label):
    require(isinstance(actual, dict) and actual == reference(raw), f"{label} content reference mismatch")

source = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
plan_path = Path(sys.argv[3])
source_root = Path(sys.argv[4])
expected_evidence_sha256 = sys.argv[5]
expected_source_cid = sys.argv[6]

root_meta = source_root.lstat()
require(stat.S_ISDIR(root_meta.st_mode) and not source_root.is_symlink(), "source root must be a non-symlink directory")
source_root = source_root.resolve(strict=True)
source_resolved = source.resolve(strict=True)
require(source_root in source_resolved.parents, "adapter binary must be inside the declared source root")

evidence, evidence_raw = load_json(evidence_path, "build evidence")
plan, _ = load_json(plan_path, "build plan")
require(
    hashlib.sha256(evidence_raw).hexdigest() == expected_evidence_sha256,
    "build evidence does not match the independently selected SHA-256",
)
require(evidence.get("schemaVersion") == 1, "unsupported build evidence schema")
require(evidence.get("status") == "verified-local-build-evidence", "build evidence is not verified local evidence")
require(evidence.get("target") == "rust-workspace", "build evidence target must be rust-workspace")
require(evidence.get("planId") == plan.get("planId"), "build evidence plan ID mismatch")
require(evidence.get("forkReleaseId") == plan.get("forkReleaseId"), "build evidence fork release mismatch")
verify_reference(evidence.get("buildPlan"), canonical_json(plan), "build plan")

targets = [item for item in plan.get("targets", []) if isinstance(item, dict) and item.get("id") == "rust-workspace"]
require(len(targets) == 1, "build plan must contain one rust-workspace target")
target = targets[0]
declarations = [item for item in target.get("artifacts", []) if isinstance(item, dict) and item.get("name") == "p2pool-node"]
require(len(declarations) == 1, "build plan must declare p2pool-node exactly once")
declaration = declarations[0]
require(
    declaration.get("repository") == "P2poolBTC"
    and declaration.get("kind") == "file"
    and declaration.get("deterministic") is True,
    "p2pool-node must be a deterministic P2poolBTC file artifact",
)
relative_source = source_resolved.relative_to(source_root).as_posix()
require(relative_source == declaration.get("pathHint"), "adapter binary does not match its build-plan path")

artifact_entries = evidence.get("artifacts")
require(isinstance(artifact_entries, list) and all(isinstance(item, dict) for item in artifact_entries), "build evidence artifacts are invalid")
declared_names = [item.get("name") for item in target.get("artifacts", []) if isinstance(item, dict)]
evidence_names = [item.get("name") for item in artifact_entries]
require(len(evidence_names) == len(set(evidence_names)) and set(evidence_names) == set(declared_names), "build evidence artifact set does not match the build plan")
for item in artifact_entries:
    item_sha = item.get("sha256")
    require(SHA256_RE.fullmatch(item_sha or "") is not None and item.get("cid") == raw_cid(item_sha), f"artifact content reference is invalid: {item.get('name')}")
    require(isinstance(item.get("size"), int) and not isinstance(item.get("size"), bool) and item["size"] > 0, f"artifact size is invalid: {item.get('name')}")
artifacts = [item for item in artifact_entries if item.get("name") == "p2pool-node"]
require(len(artifacts) == 1, "build evidence must contain p2pool-node exactly once")
artifact = artifacts[0]
expected_sha = artifact.get("sha256")
expected_size = artifact.get("size")
require(SHA256_RE.fullmatch(expected_sha or "") is not None, "p2pool-node evidence SHA-256 is invalid")
require(isinstance(expected_size, int) and not isinstance(expected_size, bool) and expected_size > 0, "p2pool-node evidence size is invalid")
source_raw = read_regular(source_resolved, "adapter binary", 1024 * 1024 * 1024)
require(len(source_raw) == expected_size and hashlib.sha256(source_raw).hexdigest() == expected_sha, "adapter binary does not match build evidence")

source_cids = evidence.get("sourceCids")
require(isinstance(source_cids, list) and len(source_cids) == 1, "rust build evidence must bind exactly one source repository")
require(source_cids[0].get("repository") == "P2poolBTC" and CID_RE.fullmatch(source_cids[0].get("sourceCid") or "") is not None, "build evidence is missing a valid P2poolBTC source CID")
source_cid = source_cids[0]["sourceCid"]
require(
    source_cid == expected_source_cid,
    "build evidence does not match the independently selected source CID",
)

evidence_dir = evidence_path.resolve(strict=True).parent
source_verification, source_verification_raw = load_json(evidence_dir / "source-verification.json", "source verification")
test_results, test_results_raw = load_json(evidence_dir / "test-results.json", "test results")
environment, environment_raw = load_json(evidence_dir / "build-environment.json", "build environment")
verify_reference(evidence.get("sourceVerification"), source_verification_raw, "source verification")
verify_reference(evidence.get("testResults"), test_results_raw, "test results")
verify_reference(evidence.get("buildEnvironment"), environment_raw, "build environment")

verified_sources = [item for item in source_verification.get("sources", []) if isinstance(item, dict) and item.get("repository") == "P2poolBTC"]
require(len(verified_sources) == 1 and verified_sources[0].get("sourceCid") == source_cid, "source verification does not bind the declared P2poolBTC CID")
require(test_results.get("passed") is True and test_results.get("target") == "rust-workspace", "build tests did not pass for rust-workspace")
require(test_results.get("sourceCids") == {"P2poolBTC": source_cid}, "test results source CID mismatch")
commands = test_results.get("commands")
planned_commands = target.get("commands")
require(isinstance(commands, list) and isinstance(planned_commands, list) and len(commands) == len(planned_commands), "build command evidence count mismatch")
for result, planned in zip(commands, planned_commands):
    require(isinstance(result, dict) and result.get("command") == planned and result.get("exitCode") == 0, "build command evidence does not match the successful allowlisted plan")
require(
    environment.get("cleanRoom") is True
    and environment.get("readOnlySources") is True
    and environment.get("networkDisabledAfterFetch") is True
    and environment.get("dependencyFetchSeparated") is True,
    "build environment is not an isolated clean-room build",
)
verify_reference(environment.get("plan"), canonical_json(plan), "build environment plan")
require(environment.get("sourceVerification") == evidence.get("sourceVerification"), "build environment source verification mismatch")
require(environment.get("toolchains") == plan.get("toolchains"), "build environment toolchain lock mismatch")

plan_locks = [item for item in target.get("dependencyLocks", []) if isinstance(item, dict) and item.get("repository") == "P2poolBTC"]
require(plan_locks, "rust-workspace has no P2poolBTC dependency lock")
evidence_locks = evidence.get("dependencyLocks")
require(isinstance(evidence_locks, list), "build evidence dependency locks are invalid")
for lock in plan_locks:
    lock_path = lock.get("path")
    require(isinstance(lock_path, str) and lock_path and not lock_path.startswith("/") and ".." not in Path(lock_path).parts, "build-plan dependency lock path is unsafe")
    lock_raw = read_regular(source_root / lock_path, f"dependency lock {lock_path}")
    lock_sha = hashlib.sha256(lock_raw).hexdigest()
    require(lock_sha == lock.get("sha256"), f"dependency lock drift: {lock_path}")
    matches = [item for item in evidence_locks if isinstance(item, dict) and item.get("repository") == "P2poolBTC" and item.get("path") == lock_path]
    require(len(matches) == 1 and matches[0].get("sha256") == lock_sha and matches[0].get("cid") == raw_cid(lock_sha) and matches[0].get("size") == len(lock_raw), f"build evidence dependency lock mismatch: {lock_path}")

print(expected_sha)
PY
) || {
  echo "Adapter source/build evidence verification failed" >&2
  exit 1
}

artifact_sha256() {
  python3 -I - "$1" <<'PY'
import hashlib, os, stat, sys
path = sys.argv[1]
metadata = os.lstat(path)
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("installed artifact must be a regular non-symlink file")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    before = os.fstat(descriptor)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
    raise SystemExit("installed artifact changed while hashing")
print(digest.hexdigest())
PY
}

if command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1; then
  for service in "${SERVICES[@]}"; do
    if "$SYSTEMCTL_BIN" is-active --quiet "$service"; then
      echo "Refusing adapter installation while $service is active" >&2
      exit 1
    else
      status=$?
      if [[ $status -ne 3 ]]; then
        echo "Cannot prove that $service is inactive (systemctl status $status)" >&2
        exit 1
      fi
    fi
  done
fi

destination_dir="$(dirname "$DESTINATION")"
if [[ -L "$destination_dir" || ( -e "$destination_dir" && ! -d "$destination_dir" ) ]]; then
  echo "Adapter destination directory is unsafe: $destination_dir" >&2
  exit 1
fi
mkdir -p "$destination_dir"

backup="${DESTINATION}.previous"
temp="$(mktemp "$destination_dir/.p2pool-node.install.XXXXXX")"
backup_temp=""
replaced=false
had_previous=false

rollback() {
  local status=$?
  set +e
  rm -f "$temp"
  [[ -z "$backup_temp" ]] || rm -f "$backup_temp"
  if [[ "$replaced" == true ]]; then
    if [[ "$had_previous" == true && -f "$backup" && ! -L "$backup" ]]; then
      local restore
      restore="$(mktemp "$destination_dir/.p2pool-node.rollback.XXXXXX")"
      install -m 0755 "$backup" "$restore"
      mv -f "$restore" "$DESTINATION"
    else
      rm -f "$DESTINATION"
    fi
  fi
  exit "$status"
}
trap rollback ERR INT TERM

if [[ -f "$DESTINATION" ]]; then
  had_previous=true
  if [[ -L "$backup" || ( -e "$backup" && ! -f "$backup" ) ]]; then
    echo "Adapter rollback destination is unsafe: $backup" >&2
    false
  fi
  backup_temp="$(mktemp "$destination_dir/.p2pool-node.previous.XXXXXX")"
  install -m 0755 "$DESTINATION" "$backup_temp"
  mv -f "$backup_temp" "$backup"
  backup_temp=""
fi

install -m 0755 "$SOURCE" "$temp"
if [[ "$(artifact_sha256 "$temp")" != "$EXPECTED_SHA256" ]]; then
  echo "Temporary adapter install does not match build evidence" >&2
  false
fi
mv -f "$temp" "$DESTINATION"
replaced=true
if [[ "$(artifact_sha256 "$DESTINATION")" != "$EXPECTED_SHA256" ]]; then
  echo "Installed adapter does not match build evidence" >&2
  false
fi

trap - ERR INT TERM
echo "Experiment 1 adapter installed from verified source/build evidence; services remain stopped"
