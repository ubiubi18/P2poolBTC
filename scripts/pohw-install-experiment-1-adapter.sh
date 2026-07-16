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
GOVERNANCE_SOURCE="target/release/pohw-governance"
DEFAULT_RUNTIME_DIR="/usr/local/libexec/p2pool-experiment-1"
DEFAULT_SYSTEMD_DIR="/etc/systemd/system"
DEFAULT_DESTINATION="$DEFAULT_RUNTIME_DIR/p2pool-node"
DEFAULT_GOVERNANCE_DESTINATION="$DEFAULT_RUNTIME_DIR/pohw-governance"
DESTINATION="$DEFAULT_DESTINATION"
INSTALL_ROOT=""
BUILD_EVIDENCE=""
EXPECTED_EVIDENCE_SHA256=""
EXPECTED_SOURCE_CID=""
BUILD_PLAN="$REPO_ROOT/compatibility/governance-build-plan-v1.json"
SOURCE_ROOT="$REPO_ROOT"
SERVICES=(
  bitcoind-pohw-experiment-1.service
  pohw-mining-adapter.service
  pohw-gossip-mesh.service
)

usage() {
  cat <<'EOF'
Usage: pohw-install-experiment-1-adapter.sh [options]

Options:
  --binary PATH       Release p2pool-node binary to install.
  --governance-binary PATH
                      Release pohw-governance evidence verifier to install.
  --build-evidence FILE
                      Verified rust-workspace build-evidence.json.
  --expected-evidence-sha256 HEX
                      SHA-256 obtained independently for build-evidence.json.
  --expected-source-cid CID
                      Canonical P2poolBTC source CID obtained independently.
  --build-plan FILE   Exact governance build plan used by the evidence.
  --source-root DIR   Canonical P2poolBTC source root used by the build.
  --destination PATH  Must equal the fixed service binary destination.
  --install-root DIR  Stage the fixed filesystem layout below DIR (non-root only).
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
    --governance-binary)
      [[ $# -ge 2 ]] || { echo "--governance-binary requires a path" >&2; exit 2; }
      GOVERNANCE_SOURCE="$2"
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
    --install-root)
      [[ $# -ge 2 ]] || { echo "--install-root requires a path" >&2; exit 2; }
      INSTALL_ROOT="$2"
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
if [[ "$DESTINATION" != "$DEFAULT_DESTINATION" ]]; then
  echo "installation is restricted to the service's fixed binary destination" >&2
  exit 1
fi
if [[ ${EUID:-0} -eq 0 && -n "$INSTALL_ROOT" ]]; then
  echo "root installation cannot use a staging root" >&2
  exit 1
fi
if [[ ${EUID:-0} -ne 0 && -z "$INSTALL_ROOT" ]]; then
  echo "non-root installation requires --install-root" >&2
  exit 1
fi
if [[ -n "$INSTALL_ROOT" ]]; then
  if [[ "$INSTALL_ROOT" != /* || "$INSTALL_ROOT" == / || -L "$INSTALL_ROOT" ]]; then
    echo "install root must be an absolute non-symlink staging directory" >&2
    exit 1
  fi
  DESTINATION="$INSTALL_ROOT$DEFAULT_DESTINATION"
  GOVERNANCE_DESTINATION="$INSTALL_ROOT$DEFAULT_GOVERNANCE_DESTINATION"
  RUNTIME_DIR="$INSTALL_ROOT$DEFAULT_RUNTIME_DIR"
  SYSTEMD_DIR="$INSTALL_ROOT$DEFAULT_SYSTEMD_DIR"
else
  GOVERNANCE_DESTINATION="$DEFAULT_GOVERNANCE_DESTINATION"
  RUNTIME_DIR="$DEFAULT_RUNTIME_DIR"
  SYSTEMD_DIR="$DEFAULT_SYSTEMD_DIR"
fi
if ! command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1; then
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
if [[ -L "$GOVERNANCE_SOURCE" || ! -f "$GOVERNANCE_SOURCE" || ! -x "$GOVERNANCE_SOURCE" ]]; then
  echo "Governance verifier must be an executable regular non-symlink file: $GOVERNANCE_SOURCE" >&2
  exit 1
fi
# Verify a governance build-evidence package without importing or executing
# anything from the candidate source tree. The evidence package binds the
# exact artifact, dependency lock, source CID, command results, build plan,
# and clean-room properties. Its CID must still be checked through an
# independent channel by the operator; this installer is not a trust oracle.
EXPECTED_SHA256=$(python3 -I - \
  "$SOURCE" "$GOVERNANCE_SOURCE" "$BUILD_EVIDENCE" "$BUILD_PLAN" "$SOURCE_ROOT" \
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
governance_source = Path(sys.argv[2])
evidence_path = Path(sys.argv[3])
plan_path = Path(sys.argv[4])
source_root = Path(sys.argv[5])
expected_evidence_sha256 = sys.argv[6]
expected_source_cid = sys.argv[7]

root_meta = source_root.lstat()
require(stat.S_ISDIR(root_meta.st_mode) and not source_root.is_symlink(), "source root must be a non-symlink directory")
source_root = source_root.resolve(strict=True)
source_resolved = source.resolve(strict=True)
governance_source_resolved = governance_source.resolve(strict=True)
require(source_root in source_resolved.parents, "adapter binary must be inside the declared source root")
require(source_root in governance_source_resolved.parents, "governance verifier must be inside the declared source root")

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
artifact_entries = evidence.get("artifacts")
require(isinstance(artifact_entries, list) and all(isinstance(item, dict) for item in artifact_entries), "build evidence artifacts are invalid")
declarations = target.get("artifacts")
require(isinstance(declarations, list) and all(isinstance(item, dict) for item in declarations), "build plan artifacts are invalid")
declared_names = [item.get("name") for item in declarations]
evidence_names = [item.get("name") for item in artifact_entries]
require(len(declared_names) == len(set(declared_names)), "build plan artifact names are not unique")
require(len(evidence_names) == len(set(evidence_names)) and set(evidence_names) == set(declared_names), "build evidence artifact set does not match the build plan")
for item in artifact_entries:
    item_sha = item.get("sha256")
    require(SHA256_RE.fullmatch(item_sha or "") is not None and item.get("cid") == raw_cid(item_sha), f"artifact content reference is invalid: {item.get('name')}")
    require(isinstance(item.get("size"), int) and not isinstance(item.get("size"), bool) and item["size"] > 0, f"artifact size is invalid: {item.get('name')}")

declarations_by_name = {item["name"]: item for item in declarations}
evidence_by_name = {item["name"]: item for item in artifact_entries}
runtime_specs = (
    ("p2pool-node", "target/release/p2pool-node", source_resolved, "adapter binary", "builder-platform", "builder-platform", False, 1024 * 1024 * 1024),
    ("pohw-governance", "target/release/pohw-governance", governance_source_resolved, "governance verifier", "builder-platform", "builder-platform", False, 1024 * 1024 * 1024),
    ("pohw-run-mining-adapter.sh", "scripts/pohw-run-mining-adapter.sh", source_root / "scripts/pohw-run-mining-adapter.sh", "mining adapter wrapper", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-run-gossip-mesh.sh", "scripts/pohw-run-gossip-mesh.sh", source_root / "scripts/pohw-run-gossip-mesh.sh", "gossip mesh wrapper", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-health-status.py", "scripts/pohw-health-status.py", source_root / "scripts/pohw-health-status.py", "health status checker", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-experiment-1-launch-policy.py", "scripts/pohw-experiment-1-launch-policy.py", source_root / "scripts/pohw-experiment-1-launch-policy.py", "launch policy verifier", "linux", "any", True, MAX_JSON_BYTES),
    ("experiment-1-full-consensus.json", "compatibility/experiment-1-full-consensus.json", source_root / "compatibility/experiment-1-full-consensus.json", "consensus manifest", "all", "any", True, MAX_JSON_BYTES),
    ("experiment-1-launch-policy.json", "compatibility/experiment-1-launch-policy.json", source_root / "compatibility/experiment-1-launch-policy.json", "launch policy", "all", "any", True, MAX_JSON_BYTES),
    ("experiment-1-miner-registry-candidate.json", "compatibility/experiment-1-miner-registry-candidate.json", source_root / "compatibility/experiment-1-miner-registry-candidate.json", "registry candidate", "all", "any", True, MAX_JSON_BYTES),
    ("bitcoind-pohw-experiment-1.service", "deploy/systemd/bitcoind-pohw-experiment-1.service", source_root / "deploy/systemd/bitcoind-pohw-experiment-1.service", "Bitcoin Core Experiment 1 unit", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-mining-adapter.service", "deploy/systemd/pohw-mining-adapter.service", source_root / "deploy/systemd/pohw-mining-adapter.service", "mining adapter unit", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-gossip-mesh.service", "deploy/systemd/pohw-gossip-mesh.service", source_root / "deploy/systemd/pohw-gossip-mesh.service", "gossip mesh unit", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-mining-adapter-server.conf", "deploy/systemd/pohw-mining-adapter-server.conf", source_root / "deploy/systemd/pohw-mining-adapter-server.conf", "mining adapter server drop-in", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-gossip-mesh-server.conf", "deploy/systemd/pohw-gossip-mesh-server.conf", source_root / "deploy/systemd/pohw-gossip-mesh-server.conf", "gossip mesh server drop-in", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-mining-experiment-1.conf", "deploy/systemd/pohw-mining-experiment-1.conf", source_root / "deploy/systemd/pohw-mining-experiment-1.conf", "mining Experiment 1 gate", "linux", "any", True, MAX_JSON_BYTES),
    ("pohw-gossip-experiment-1.conf", "deploy/systemd/pohw-gossip-experiment-1.conf", source_root / "deploy/systemd/pohw-gossip-experiment-1.conf", "gossip Experiment 1 gate", "linux", "any", True, MAX_JSON_BYTES),
)
verified_sha256s = []
for name, path_hint, local_path, label, platform, architecture, pinned, maximum in runtime_specs:
    require(name in declarations_by_name, f"build plan must declare {name} exactly once")
    declaration = declarations_by_name[name]
    require(
        declaration.get("repository") == "P2poolBTC"
        and declaration.get("kind") == "file"
        and declaration.get("pathHint") == path_hint
        and declaration.get("platform") == platform
        and declaration.get("architecture") == architecture
        and declaration.get("deterministic") is True,
        f"{name} must be the expected deterministic P2poolBTC file artifact",
    )
    if name == "p2pool-node":
        relative_source = source_resolved.relative_to(source_root).as_posix()
        require(relative_source == path_hint, "adapter binary does not match its build-plan path")
    elif name == "pohw-governance":
        relative_source = governance_source_resolved.relative_to(source_root).as_posix()
        require(relative_source == path_hint, "governance verifier does not match its build-plan path")
    raw = read_regular(local_path, label, maximum)
    measured = reference(raw)
    artifact = evidence_by_name[name]
    require(
        artifact.get("repository") == declaration["repository"]
        and artifact.get("kind") == declaration["kind"]
        and artifact.get("deterministic") is True
        and artifact.get("packagedName") == Path(path_hint).name,
        f"build evidence metadata mismatch: {name}",
    )
    if platform != "builder-platform":
        require(artifact.get("platform") == platform, f"build evidence platform mismatch: {name}")
    if architecture != "builder-platform":
        require(artifact.get("architecture") == architecture, f"build evidence architecture mismatch: {name}")
    require(
        artifact.get("cid") == measured["cid"]
        and artifact.get("sha256") == measured["sha256"]
        and artifact.get("size") == measured["size"],
        f"{label} does not match build evidence",
    )
    if pinned:
        require(
            declaration.get("expectedCid") == measured["cid"]
            and declaration.get("expectedSha256") == measured["sha256"]
            and declaration.get("expectedSize") == measured["size"],
            f"{label} does not match the pinned build-plan artifact",
        )
    verified_sha256s.append(measured["sha256"])

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

print(" ".join(verified_sha256s))
PY
) || {
  echo "Adapter runtime source/build evidence verification failed" >&2
  exit 1
}
read -r EXPECTED_SHA256 GOVERNANCE_SHA256 MINING_WRAPPER_SHA256 GOSSIP_WRAPPER_SHA256 \
  HEALTH_SCRIPT_SHA256 LAUNCH_POLICY_SCRIPT_SHA256 CONSENSUS_MANIFEST_SHA256 \
  LAUNCH_POLICY_SHA256 REGISTRY_CANDIDATE_SHA256 BITCOIN_CORE_UNIT_SHA256 \
  MINING_UNIT_SHA256 GOSSIP_UNIT_SHA256 MINING_SERVER_DROPIN_SHA256 \
  GOSSIP_SERVER_DROPIN_SHA256 MINING_EXPERIMENT_DROPIN_SHA256 \
  GOSSIP_EXPERIMENT_DROPIN_SHA256 <<< "$EXPECTED_SHA256"
if [[ -z "${GOSSIP_EXPERIMENT_DROPIN_SHA256:-}" ]]; then
  echo "Adapter runtime source/build evidence verification returned incomplete digests" >&2
  exit 1
fi

DIGEST_TEMP_DIR=${TMPDIR:-/tmp}
if [[ ${EUID:-0} -eq 0 ]]; then
  DIGEST_TEMP_DIR=/tmp
fi
GOVERNANCE_DIGEST_SOURCE=$(mktemp "$DIGEST_TEMP_DIR/pohw-governance.sha256.XXXXXX")
cleanup_governance_digest_source() {
  [[ -z "${GOVERNANCE_DIGEST_SOURCE:-}" ]] || rm -f "$GOVERNANCE_DIGEST_SOURCE"
}
trap cleanup_governance_digest_source EXIT
printf '%s\n' "$GOVERNANCE_SHA256" > "$GOVERNANCE_DIGEST_SOURCE"
chmod 0444 "$GOVERNANCE_DIGEST_SOURCE"
GOVERNANCE_DIGEST_FILE_SHA256=$(python3 -I - "$GOVERNANCE_DIGEST_SOURCE" <<'PY'
import hashlib, pathlib, sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)

verify_installed_artifact() {
  python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import hashlib, os, stat, sys
path = sys.argv[1]
expected_sha256 = sys.argv[2]
expected_mode = int(sys.argv[3], 8)
require_root_owner = sys.argv[4] == "true"
metadata = os.lstat(path)
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("installed artifact must be a regular non-symlink file")
if stat.S_IMODE(metadata.st_mode) != expected_mode:
    raise SystemExit(f"installed artifact mode is not {expected_mode:04o}")
if require_root_owner and (metadata.st_uid != 0 or metadata.st_gid != 0):
    raise SystemExit("installed artifact is not owned by root:root")
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
if digest.hexdigest() != expected_sha256:
    raise SystemExit("installed artifact does not match build evidence")
PY
}

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

MINING_WRAPPER_SOURCE="$SOURCE_ROOT/scripts/pohw-run-mining-adapter.sh"
GOSSIP_WRAPPER_SOURCE="$SOURCE_ROOT/scripts/pohw-run-gossip-mesh.sh"
HEALTH_SCRIPT_SOURCE="$SOURCE_ROOT/scripts/pohw-health-status.py"
LAUNCH_POLICY_SCRIPT_SOURCE="$SOURCE_ROOT/scripts/pohw-experiment-1-launch-policy.py"
CONSENSUS_MANIFEST_SOURCE="$SOURCE_ROOT/compatibility/experiment-1-full-consensus.json"
LAUNCH_POLICY_SOURCE="$SOURCE_ROOT/compatibility/experiment-1-launch-policy.json"
REGISTRY_CANDIDATE_SOURCE="$SOURCE_ROOT/compatibility/experiment-1-miner-registry-candidate.json"
BITCOIN_CORE_UNIT_SOURCE="$SOURCE_ROOT/deploy/systemd/bitcoind-pohw-experiment-1.service"
MINING_UNIT_SOURCE="$SOURCE_ROOT/deploy/systemd/pohw-mining-adapter.service"
GOSSIP_UNIT_SOURCE="$SOURCE_ROOT/deploy/systemd/pohw-gossip-mesh.service"
MINING_SERVER_DROPIN_SOURCE="$SOURCE_ROOT/deploy/systemd/pohw-mining-adapter-server.conf"
GOSSIP_SERVER_DROPIN_SOURCE="$SOURCE_ROOT/deploy/systemd/pohw-gossip-mesh-server.conf"
MINING_EXPERIMENT_DROPIN_SOURCE="$SOURCE_ROOT/deploy/systemd/pohw-mining-experiment-1.conf"
GOSSIP_EXPERIMENT_DROPIN_SOURCE="$SOURCE_ROOT/deploy/systemd/pohw-gossip-experiment-1.conf"
GOVERNANCE_DESTINATION="$RUNTIME_DIR/pohw-governance"
GOVERNANCE_DIGEST_DESTINATION="$RUNTIME_DIR/pohw-governance.sha256"
MINING_WRAPPER_DESTINATION="$RUNTIME_DIR/pohw-run-mining-adapter.sh"
GOSSIP_WRAPPER_DESTINATION="$RUNTIME_DIR/pohw-run-gossip-mesh.sh"
HEALTH_SCRIPT_DESTINATION="$RUNTIME_DIR/pohw-health-status.py"
LAUNCH_POLICY_SCRIPT_DESTINATION="$RUNTIME_DIR/pohw-experiment-1-launch-policy.py"
COMPATIBILITY_DIR="$RUNTIME_DIR/compatibility"
CONSENSUS_MANIFEST_DESTINATION="$COMPATIBILITY_DIR/experiment-1-full-consensus.json"
LAUNCH_POLICY_DESTINATION="$COMPATIBILITY_DIR/experiment-1-launch-policy.json"
REGISTRY_CANDIDATE_DESTINATION="$COMPATIBILITY_DIR/experiment-1-miner-registry-candidate.json"
BITCOIN_CORE_UNIT_DESTINATION="$SYSTEMD_DIR/bitcoind-pohw-experiment-1.service"
MINING_UNIT_DESTINATION="$SYSTEMD_DIR/pohw-mining-adapter.service"
GOSSIP_UNIT_DESTINATION="$SYSTEMD_DIR/pohw-gossip-mesh.service"
MINING_SERVER_DROPIN_DIR="$SYSTEMD_DIR/pohw-mining-adapter.service.d"
GOSSIP_SERVER_DROPIN_DIR="$SYSTEMD_DIR/pohw-gossip-mesh.service.d"
MINING_SERVER_DROPIN_DESTINATION="$MINING_SERVER_DROPIN_DIR/server.conf"
GOSSIP_SERVER_DROPIN_DESTINATION="$GOSSIP_SERVER_DROPIN_DIR/server.conf"
MINING_EXPERIMENT_DROPIN_DESTINATION="$MINING_SERVER_DROPIN_DIR/experiment-1.conf"
GOSSIP_EXPERIMENT_DROPIN_DESTINATION="$GOSSIP_SERVER_DROPIN_DIR/experiment-1.conf"

ARTIFACT_SOURCES=(
  "$SOURCE"
  "$GOVERNANCE_SOURCE"
  "$GOVERNANCE_DIGEST_SOURCE"
  "$MINING_WRAPPER_SOURCE"
  "$GOSSIP_WRAPPER_SOURCE"
  "$HEALTH_SCRIPT_SOURCE"
  "$LAUNCH_POLICY_SCRIPT_SOURCE"
  "$CONSENSUS_MANIFEST_SOURCE"
  "$LAUNCH_POLICY_SOURCE"
  "$REGISTRY_CANDIDATE_SOURCE"
  "$BITCOIN_CORE_UNIT_SOURCE"
  "$MINING_UNIT_SOURCE"
  "$GOSSIP_UNIT_SOURCE"
  "$MINING_SERVER_DROPIN_SOURCE"
  "$GOSSIP_SERVER_DROPIN_SOURCE"
  "$MINING_EXPERIMENT_DROPIN_SOURCE"
  "$GOSSIP_EXPERIMENT_DROPIN_SOURCE"
)
ARTIFACT_DESTINATIONS=(
  "$DESTINATION"
  "$GOVERNANCE_DESTINATION"
  "$GOVERNANCE_DIGEST_DESTINATION"
  "$MINING_WRAPPER_DESTINATION"
  "$GOSSIP_WRAPPER_DESTINATION"
  "$HEALTH_SCRIPT_DESTINATION"
  "$LAUNCH_POLICY_SCRIPT_DESTINATION"
  "$CONSENSUS_MANIFEST_DESTINATION"
  "$LAUNCH_POLICY_DESTINATION"
  "$REGISTRY_CANDIDATE_DESTINATION"
  "$BITCOIN_CORE_UNIT_DESTINATION"
  "$MINING_UNIT_DESTINATION"
  "$GOSSIP_UNIT_DESTINATION"
  "$MINING_SERVER_DROPIN_DESTINATION"
  "$GOSSIP_SERVER_DROPIN_DESTINATION"
  "$MINING_EXPERIMENT_DROPIN_DESTINATION"
  "$GOSSIP_EXPERIMENT_DROPIN_DESTINATION"
)
ARTIFACT_MODES=(0755 0755 0444 0755 0755 0755 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644)
ARTIFACT_SHA256S=(
  "$EXPECTED_SHA256"
  "$GOVERNANCE_SHA256"
  "$GOVERNANCE_DIGEST_FILE_SHA256"
  "$MINING_WRAPPER_SHA256"
  "$GOSSIP_WRAPPER_SHA256"
  "$HEALTH_SCRIPT_SHA256"
  "$LAUNCH_POLICY_SCRIPT_SHA256"
  "$CONSENSUS_MANIFEST_SHA256"
  "$LAUNCH_POLICY_SHA256"
  "$REGISTRY_CANDIDATE_SHA256"
  "$BITCOIN_CORE_UNIT_SHA256"
  "$MINING_UNIT_SHA256"
  "$GOSSIP_UNIT_SHA256"
  "$MINING_SERVER_DROPIN_SHA256"
  "$GOSSIP_SERVER_DROPIN_SHA256"
  "$MINING_EXPERIMENT_DROPIN_SHA256"
  "$GOSSIP_EXPERIMENT_DROPIN_SHA256"
)
ARTIFACT_LABELS=(
  "adapter binary"
  "governance verifier"
  "governance verifier digest"
  "mining adapter wrapper"
  "gossip mesh wrapper"
  "health status checker"
  "launch policy verifier"
  "consensus manifest"
  "launch policy"
  "registry candidate"
  "Bitcoin Core Experiment 1 unit"
  "mining adapter unit"
  "gossip mesh unit"
  "mining adapter server drop-in"
  "gossip mesh server drop-in"
  "mining Experiment 1 gate"
  "gossip Experiment 1 gate"
)

for directory in \
  "$RUNTIME_DIR" \
  "$COMPATIBILITY_DIR" \
  "$SYSTEMD_DIR" \
  "$MINING_SERVER_DROPIN_DIR" \
  "$GOSSIP_SERVER_DROPIN_DIR"; do
  if [[ -L "$directory" || ( -e "$directory" && ! -d "$directory" ) ]]; then
    echo "Adapter destination directory is unsafe: $directory" >&2
    exit 1
  fi
  mkdir -p "$directory"
  if [[ -L "$directory" || ! -d "$directory" ]]; then
    echo "Adapter destination directory could not be created safely: $directory" >&2
    exit 1
  fi
done

for index in "${!ARTIFACT_DESTINATIONS[@]}"; do
  destination=${ARTIFACT_DESTINATIONS[$index]}
  if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
    echo "${ARTIFACT_LABELS[$index]} destination is unsafe: $destination" >&2
    exit 1
  fi
done

backup="${DESTINATION}.previous"
if [[ -L "$backup" || ( -e "$backup" && ! -f "$backup" ) ]]; then
  echo "Adapter rollback destination is unsafe: $backup" >&2
  exit 1
fi

REQUIRE_ROOT_OWNER=false
if [[ ${EUID:-0} -eq 0 ]]; then
  REQUIRE_ROOT_OWNER=true
fi

install_fixed_copy() {
  local mode=$1
  local source_path=$2
  local destination_path=$3
  if [[ "$REQUIRE_ROOT_OWNER" == true ]]; then
    install -o root -g root -m "$mode" "$source_path" "$destination_path"
  else
    install -m "$mode" "$source_path" "$destination_path"
  fi
}

STAGED_PATHS=()
TRANSACTION_BACKUPS=()
EXISTED=()
REPLACED=()
SYSTEMD_REPLACED=false
for index in "${!ARTIFACT_DESTINATIONS[@]}"; do
  STAGED_PATHS[index]=""
  TRANSACTION_BACKUPS[index]=""
  EXISTED[index]=false
  REPLACED[index]=false
done
backup_temp=""

rollback() {
  local status=$?
  local index
  trap - ERR INT TERM
  set +e
  [[ -z "$backup_temp" ]] || rm -f "$backup_temp"
  for index in "${!STAGED_PATHS[@]}"; do
    [[ -z "${STAGED_PATHS[$index]}" ]] || rm -f "${STAGED_PATHS[$index]}"
  done
  for ((index=${#ARTIFACT_DESTINATIONS[@]} - 1; index >= 0; index--)); do
    if [[ "${REPLACED[$index]}" == true ]]; then
      if [[ "${EXISTED[$index]}" == true ]]; then
        mv -f "${TRANSACTION_BACKUPS[$index]}" "${ARTIFACT_DESTINATIONS[$index]}"
        TRANSACTION_BACKUPS[index]=""
      else
        rm -f "${ARTIFACT_DESTINATIONS[$index]}"
      fi
    fi
    [[ -z "${TRANSACTION_BACKUPS[$index]}" ]] || rm -f "${TRANSACTION_BACKUPS[$index]}"
  done
  if [[ "${SYSTEMD_REPLACED:-false}" == true ]]; then
    "$SYSTEMCTL_BIN" daemon-reload >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap rollback ERR INT TERM

for index in "${!ARTIFACT_SOURCES[@]}"; do
  destination_dir=$(dirname "${ARTIFACT_DESTINATIONS[$index]}")
  STAGED_PATHS[index]=$(mktemp "$destination_dir/.${ARTIFACT_LABELS[$index]// /-}.install.XXXXXX")
  staged=${STAGED_PATHS[$index]}
  install_fixed_copy "${ARTIFACT_MODES[$index]}" \
    "${ARTIFACT_SOURCES[$index]}" "$staged"
  verify_installed_artifact "$staged" "${ARTIFACT_SHA256S[$index]}" \
    "${ARTIFACT_MODES[$index]}" "$REQUIRE_ROOT_OWNER"
done

if [[ -f "$DESTINATION" ]]; then
  backup_temp="$(mktemp "$RUNTIME_DIR/.p2pool-node.previous.XXXXXX")"
  install_fixed_copy 0755 "$DESTINATION" "$backup_temp"
  mv -f "$backup_temp" "$backup"
  backup_temp=""
fi

for index in "${!ARTIFACT_DESTINATIONS[@]}"; do
  destination=${ARTIFACT_DESTINATIONS[$index]}
  if [[ -f "$destination" ]]; then
    transaction_backup=$(mktemp "$(dirname "$destination")/.pohw-runtime.rollback.XXXXXX")
    TRANSACTION_BACKUPS[index]=$transaction_backup
    EXISTED[index]=true
    cp -p "$destination" "$transaction_backup"
  fi
  REPLACED[index]=true
  if [[ "$destination" == "$SYSTEMD_DIR/"* ]]; then
    SYSTEMD_REPLACED=true
  fi
  mv -f "${STAGED_PATHS[$index]}" "$destination"
  STAGED_PATHS[index]=""
  verify_installed_artifact "$destination" "${ARTIFACT_SHA256S[$index]}" \
    "${ARTIFACT_MODES[$index]}" "$REQUIRE_ROOT_OWNER"
done

if ! "$SYSTEMCTL_BIN" daemon-reload; then
  echo "systemd daemon-reload failed; restoring the previous runtime files" >&2
  false
fi

trap - ERR INT TERM
for index in "${!TRANSACTION_BACKUPS[@]}"; do
  [[ -z "${TRANSACTION_BACKUPS[$index]}" ]] || rm -f "${TRANSACTION_BACKUPS[$index]}" || true
  TRANSACTION_BACKUPS[index]=""
done

echo "Experiment 1 adapter runtime and units installed from verified source/build evidence; services remain stopped"
