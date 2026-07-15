#!/usr/bin/env bash
set -euo pipefail

ROOT_PATH=/usr/sbin:/usr/bin:/sbin:/bin
BUILD_PATH=${POHW_BUILD_PATH:-/usr/local/bin:/usr/bin:/bin}
PATH=$ROOT_PATH
export PATH

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
MANIFEST="$REPO_ROOT/compatibility/experiment-1-full-consensus.json"
SOURCE_DIR=
BUILD_DIR=
SNAPSHOT_DIR=
JOBS=
INSTALL_ROOT=/usr/local/libexec/pohw-bitcoin-core-v31.1
UNIT_PATH=/etc/systemd/system/bitcoind-pohw-experiment-1.service
SERVICE_NAME=bitcoind-pohw-experiment-1.service
BUILD_USER=${POHW_BUILD_USER:-${SUDO_USER:-bitcoin-pohw}}
USE_VERIFIED_BUILD=0

usage() {
  cat <<'EOF'
Usage: sudo scripts/pohw-install-bitcoin-core-fork.sh \
  --source-dir DIR --build-dir DIR [options]

Create a fresh deterministic build as a non-root account, verify its complete
source/command/test/toolchain evidence, and atomically install bytes without
executing any build artifact as root. The service is not enabled or started.

Options:
  --source-dir DIR
  --build-dir DIR    New or empty scratch build directory
  --snapshot-dir DIR New snapshot destination (default: BUILD_DIR.source-snapshot)
  --build-user USER  Non-root account used for all source/build/test execution
  --build-path PATH  Fixed executable search path for the build account
  --jobs N           Parallel build jobs
  --manifest FILE
  --install-root DIR
  --unit-path FILE
  --service-name NAME
  --use-verified-build
                     Disabled: reusable self-authored evidence cannot prove
                     that commands and tests actually ran
EOF
}

while (($#)); do
  case "$1" in
    --source-dir) SOURCE_DIR=${2:?}; shift 2 ;;
    --build-dir) BUILD_DIR=${2:?}; shift 2 ;;
    --snapshot-dir) SNAPSHOT_DIR=${2:?}; shift 2 ;;
    --build-user) BUILD_USER=${2:?}; shift 2 ;;
    --build-path) BUILD_PATH=${2:?}; shift 2 ;;
    --jobs) JOBS=${2:?}; shift 2 ;;
    --manifest) MANIFEST=${2:?}; shift 2 ;;
    --install-root) INSTALL_ROOT=${2:?}; shift 2 ;;
    --unit-path) UNIT_PATH=${2:?}; shift 2 ;;
    --service-name) SERVICE_NAME=${2:?}; shift 2 ;;
    --use-verified-build) USE_VERIFIED_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n "$SOURCE_DIR" && -n "$BUILD_DIR" ]] || { usage >&2; exit 2; }
[[ "$USE_VERIFIED_BUILD" -eq 0 ]] || {
  echo "--use-verified-build is intentionally disabled; use a new empty build directory" >&2
  exit 1
}
BUILD_UID=$(id -u -- "$BUILD_USER" 2>/dev/null) || {
  echo "build account does not exist: $BUILD_USER" >&2
  exit 1
}
[[ "$BUILD_UID" -ne 0 ]] || {
  echo "build account must not be root" >&2
  exit 1
}
BUILD_HOME=/nonexistent
python3 - "$BUILD_PATH" <<'PY'
import pathlib
import stat
import sys

parts = sys.argv[1].split(":")
if not parts or any(not part or not pathlib.PurePosixPath(part).is_absolute() for part in parts):
    raise SystemExit("--build-path must contain only nonempty absolute directories")
for part in parts:
    path = pathlib.Path(part)
    if path.is_symlink():
        path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise SystemExit(f"build path entry is not a directory: {path}")
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit(f"build path entry must be root-owned and non-writable: {path}")
PY

SOURCE_DIR=$(cd -- "$SOURCE_DIR" && pwd)
BUILD_DIR=$(python3 - "$BUILD_DIR" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
)
SNAPSHOT_DIR=${SNAPSHOT_DIR:-$BUILD_DIR.source-snapshot}
SNAPSHOT_DIR=$(python3 - "$SNAPSHOT_DIR" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
)
[[ -z "$JOBS" || "$JOBS" =~ ^[1-9][0-9]*$ ]] || {
  echo "--jobs must be a positive integer" >&2
  exit 2
}
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9@_.:-]+\.service$ ]] || {
  echo "--service-name must be a systemd service unit name" >&2
  exit 2
}
[[ "$INSTALL_ROOT" = /* && "$INSTALL_ROOT" != / && "$UNIT_PATH" = /* ]] || {
  echo "install paths must be safe absolute paths" >&2
  exit 1
}
python3 - "$INSTALL_ROOT" "$UNIT_PATH" <<'PY'
import pathlib
import sys

for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise SystemExit(f"install path contains a symlink: {candidate}")
        if candidate == candidate.parent:
            break
PY

RUNUSER=/usr/sbin/runuser
[[ -x "$RUNUSER" ]] || {
  echo "required privilege-drop tool is unavailable: $RUNUSER" >&2
  exit 1
}
run_as_build_user() {
  "$RUNUSER" -u "$BUILD_USER" -- /usr/bin/env -i \
    HOME="$BUILD_HOME" USER="$BUILD_USER" LOGNAME="$BUILD_USER" \
    PATH="$BUILD_PATH" LANG=C LC_ALL=C \
    "$@"
}

BUILD_PARENT=$(dirname -- "$BUILD_DIR")
[[ -d "$BUILD_PARENT" && ! -L "$BUILD_PARENT" ]] || {
  echo "build parent must be a real existing directory: $BUILD_PARENT" >&2
  exit 1
}
run_as_build_user /usr/bin/test -r "$SOURCE_DIR" || {
  echo "build account cannot read the source checkout" >&2
  exit 1
}
run_as_build_user /usr/bin/test -w "$BUILD_PARENT" || {
  echo "build account cannot create the build and snapshot directories" >&2
  exit 1
}

verify_exact_patched_source() {
  run_as_build_user "$SCRIPT_DIR/pohw-verify-bitcoin-core-source.sh" \
    --source-dir "$SOURCE_DIR" \
    --manifest "$MANIFEST"
}

verify_exact_patched_source
BUILD_ARGS=(
  --source-dir "$SOURCE_DIR"
  --build-dir "$BUILD_DIR"
  --snapshot-dir "$SNAPSHOT_DIR"
  --manifest "$MANIFEST"
)
if [[ -n "$JOBS" ]]; then
  BUILD_ARGS+=(--jobs "$JOBS")
fi
run_as_build_user "$SCRIPT_DIR/pohw-build-bitcoin-core-fork.sh" "${BUILD_ARGS[@]}"

SNAPSHOT_METADATA="$BUILD_DIR/pohw-source-snapshot.json"
RUN_RECORD="$BUILD_DIR/pohw-build-run.json"
EVIDENCE="$BUILD_DIR/pohw-build-evidence.json"
run_as_build_user python3 "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" verify \
  --manifest "$MANIFEST" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --snapshot-metadata "$SNAPSHOT_METADATA" \
  --build-dir "$BUILD_DIR" \
  --run-record "$RUN_RECORD" \
  --evidence "$EVIDENCE"

PROBE_SOURCE="$REPO_ROOT/scripts/pohw-experiment-1-replay-probe.py"
[[ -f "$PROBE_SOURCE" && ! -L "$PROBE_SOURCE" && -x "$PROBE_SOURCE" ]] || {
  echo "missing executable replay probe: $PROBE_SOURCE" >&2
  exit 1
}
WALLET_ACCEPTANCE_SOURCE="$REPO_ROOT/scripts/pohw-experiment-1-wallet-acceptance.py"
[[ -f "$WALLET_ACCEPTANCE_SOURCE" && ! -L "$WALLET_ACCEPTANCE_SOURCE" && -x "$WALLET_ACCEPTANCE_SOURCE" ]] || {
  echo "missing executable wallet acceptance tool: $WALLET_ACCEPTANCE_SOURCE" >&2
  exit 1
}
if systemctl is-active --quiet -- "$SERVICE_NAME"; then
  echo "refusing to replace binaries while $SERVICE_NAME is active" >&2
  exit 1
fi
[[ ! -e "$INSTALL_ROOT" || -d "$INSTALL_ROOT" ]] || {
  echo "install root is not a directory: $INSTALL_ROOT" >&2
  exit 1
}
INSTALL_PARENT=$(dirname -- "$INSTALL_ROOT")
INSTALL_NAME=$(basename -- "$INSTALL_ROOT")
UNIT_PARENT=$(dirname -- "$UNIT_PATH")
install -d -m 0755 "$INSTALL_PARENT" "$UNIT_PARENT"
STAGING=$(mktemp -d "$INSTALL_PARENT/.${INSTALL_NAME}.new.XXXXXXXX")
chmod 0755 "$STAGING"
BACKUP="$INSTALL_PARENT/.${INSTALL_NAME}.previous.$(date -u +%Y%m%dT%H%M%SZ).$$"
UNIT_STAGING=$(mktemp "$UNIT_PARENT/.${SERVICE_NAME}.new.XXXXXXXX")
UNIT_BACKUP="$UNIT_PARENT/.${SERVICE_NAME}.previous.$(date -u +%Y%m%dT%H%M%SZ).$$"
INSTALL_BACKED_UP=0
NEW_INSTALL_ACTIVE=0
UNIT_BACKED_UP=0
NEW_UNIT_ACTIVE=0

rollback_install() {
  local status=$?
  [[ -z "${STAGING:-}" ]] || rm -rf -- "$STAGING"
  [[ -z "${UNIT_STAGING:-}" ]] || rm -f -- "$UNIT_STAGING"
  if [[ "$status" -ne 0 ]]; then
    if [[ "$NEW_UNIT_ACTIVE" -eq 1 ]]; then
      rm -f -- "$UNIT_PATH"
    fi
    if [[ "$UNIT_BACKED_UP" -eq 1 && -f "$UNIT_BACKUP" ]]; then
      mv -- "$UNIT_BACKUP" "$UNIT_PATH"
    fi
    if [[ "$NEW_INSTALL_ACTIVE" -eq 1 ]]; then
      rm -rf -- "$INSTALL_ROOT"
    fi
    if [[ "$INSTALL_BACKED_UP" -eq 1 && -d "$BACKUP" ]]; then
      mv -- "$BACKUP" "$INSTALL_ROOT"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo "installation failed; restored the previous service state" >&2
  fi
  exit "$status"
}
trap rollback_install EXIT

# Copy each provenance-bound file through one O_NOFOLLOW descriptor and verify
# its digest while copying. This removes the verify-then-open symlink race.
python3 - "$EVIDENCE" "$BUILD_DIR" "$STAGING" "$MANIFEST" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

evidence_path = pathlib.Path(sys.argv[1])
build_dir = pathlib.Path(sys.argv[2])
staging = pathlib.Path(sys.argv[3])
manifest_path = pathlib.Path(sys.argv[4])
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("platform lacks O_NOFOLLOW required for race-safe installation")

def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise SystemExit(f"duplicate evidence key: {key}")
        value[key] = item
    return value

def read_nofollow(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"provenance source is not regular: {path}")
        chunks = []
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise SystemExit(f"provenance source changed while copying: {path}")
        return b"".join(chunks), digest.hexdigest(), before.st_size
    finally:
        os.close(fd)

def write_new(path, payload, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)

evidence_bytes, _, _ = read_nofollow(evidence_path)
evidence = json.loads(evidence_bytes, object_pairs_hook=pairs)
if evidence.get("schema_version") != "pohw-bitcoin-core-build-evidence/v4":
    raise SystemExit("unsupported build evidence schema")
manifest_bytes, manifest_digest, _ = read_nofollow(manifest_path)
if manifest_digest != evidence.get("manifest_sha256"):
    raise SystemExit("manifest changed after build evidence verification")
write_new(staging / "experiment-manifest.json", manifest_bytes, 0o644)

artifact_paths = {
    "bitcoind": "pohw-release/bin/bitcoind",
    "bitcoin-cli": "pohw-release/bin/bitcoin-cli",
}
for name, relative_path in artifact_paths.items():
    source = build_dir / relative_path
    payload, digest, size = read_nofollow(source)
    expected = evidence["artifacts"][name]
    if (
        expected.get("path") != relative_path
        or digest != expected.get("sha256")
        or size != expected.get("size_bytes")
    ):
        raise SystemExit(f"artifact changed after evidence verification: {name}")
    write_new(staging / "bin" / name, payload, 0o755)

write_new(staging / "build-evidence.json", evidence_bytes, 0o644)
bound_files = (
    (
        build_dir / "pohw-build-run.json",
        evidence["build"]["run_record_sha256"],
        staging / "provenance" / "pohw-build-run.json",
    ),
    (
        build_dir / "pohw-source-snapshot.json",
        evidence["build"]["snapshot_metadata_sha256"],
        staging / "provenance" / "pohw-source-snapshot.json",
    ),
    (
        build_dir / "pohw-depends-source.json",
        evidence["build"]["depends"]["source_metadata_sha256"],
        staging / "provenance" / "pohw-depends-source.json",
    ),
    (
        build_dir / "pohw-depends-prefix.json",
        evidence["build"]["depends"]["metadata_sha256"],
        staging / "provenance" / "pohw-depends-prefix.json",
    ),
)
for source, expected_digest, destination in bound_files:
    payload, digest, _ = read_nofollow(source)
    if digest != expected_digest:
        raise SystemExit(f"provenance file changed after verification: {source.name}")
    write_new(destination, payload, 0o644)

for step in evidence["build"]["commands"]:
    source = build_dir / step["log_path"]
    payload, digest, _ = read_nofollow(source)
    if digest != step["output_sha256"]:
        raise SystemExit(f"build log changed after verification: {step['label']}")
    write_new(staging / "provenance" / "logs" / source.name, payload, 0o644)
PY

install -m 0755 "$PROBE_SOURCE" "$STAGING/bin/pohw-experiment-1-replay-probe"
install -m 0755 \
  "$WALLET_ACCEPTANCE_SOURCE" \
  "$STAGING/bin/pohw-experiment-1-wallet-acceptance"
install -m 0644 \
  "$REPO_ROOT/deploy/systemd/bitcoind-pohw-experiment-1.service" \
  "$UNIT_STAGING"

if [[ -d "$INSTALL_ROOT" ]]; then
  mv -- "$INSTALL_ROOT" "$BACKUP"
  INSTALL_BACKED_UP=1
fi
mv -- "$STAGING" "$INSTALL_ROOT"
STAGING=
NEW_INSTALL_ACTIVE=1
if [[ -f "$UNIT_PATH" ]]; then
  mv -- "$UNIT_PATH" "$UNIT_BACKUP"
  UNIT_BACKED_UP=1
fi
mv -- "$UNIT_STAGING" "$UNIT_PATH"
UNIT_STAGING=
NEW_UNIT_ACTIVE=1
systemctl daemon-reload

# Never execute a newly built binary with UID 0. Digest output is sufficient;
# systemd later runs bitcoind under the dedicated bitcoin-pohw account.
sha256sum "$INSTALL_ROOT/bin/bitcoind" "$INSTALL_ROOT/bin/bitcoin-cli"
if [[ -d "$BACKUP" ]]; then
  echo "Previous verified installation retained at: $BACKUP"
fi
if [[ -f "$UNIT_BACKUP" ]]; then
  echo "Previous systemd unit retained at: $UNIT_BACKUP"
fi
echo "Installed but not started. Bootstrap the pinned chainstate, then enable the service explicitly."
