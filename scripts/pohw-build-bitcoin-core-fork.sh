#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
MANIFEST="$REPO_ROOT/compatibility/experiment-1-full-consensus.json"
SOURCE_DIR=
BUILD_DIR=
SNAPSHOT_DIR=
JOBS=

usage() {
  cat <<'EOF'
Usage: scripts/pohw-build-bitcoin-core-fork.sh --source-dir DIR [options]

Build Experiment 1 or the inactive Experiment 2 candidate as an unprivileged
user from a deterministic, read-only snapshot of the exact upstream revision
plus pinned patch series. Every configure, build, and test command is captured
in fail-closed provenance evidence.

Options:
  --source-dir DIR   Bitcoin Core checkout at the pinned commit (required)
  --build-dir DIR    New or empty build directory (default: SOURCE_DIR/build-pohw)
  --snapshot-dir DIR New snapshot destination (default: BUILD_DIR.source-snapshot)
  --manifest FILE    Activation manifest
  --jobs N           Parallel build jobs
EOF
}

while (($#)); do
  case "$1" in
    --source-dir) SOURCE_DIR=${2:?}; shift 2 ;;
    --build-dir) BUILD_DIR=${2:?}; shift 2 ;;
    --snapshot-dir) SNAPSHOT_DIR=${2:?}; shift 2 ;;
    --manifest) MANIFEST=${2:?}; shift 2 ;;
    --jobs) JOBS=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ ${EUID:-$(id -u)} -ne 0 ]] || {
  echo "refusing to configure, build, test, or execute source as root" >&2
  exit 1
}
[[ -n "$SOURCE_DIR" ]] || { usage >&2; exit 2; }
SOURCE_DIR=$(cd -- "$SOURCE_DIR" && pwd)
BUILD_DIR=${BUILD_DIR:-$SOURCE_DIR/build-pohw}
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
[[ "$SNAPSHOT_DIR" != "$BUILD_DIR" ]] || {
  echo "source snapshot and build directory must be different" >&2
  exit 1
}
if [[ "$BUILD_DIR" =~ [[:space:]=] || "$SNAPSHOT_DIR" =~ [[:space:]=] ]]; then
  echo "build and snapshot paths cannot contain whitespace or '='" >&2
  exit 1
fi

if [[ -e "$BUILD_DIR" ]]; then
  [[ -d "$BUILD_DIR" && ! -L "$BUILD_DIR" ]] || {
    echo "build path must be a real directory: $BUILD_DIR" >&2
    exit 1
  }
  [[ -z "$(find "$BUILD_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "build directory must be empty to prevent stale or substituted artifacts" >&2
    exit 1
  }
else
  BUILD_PARENT=$(dirname -- "$BUILD_DIR")
  [[ -d "$BUILD_PARENT" && ! -L "$BUILD_PARENT" ]] || {
    echo "build parent must be a real existing directory: $BUILD_PARENT" >&2
    exit 1
  }
  mkdir -m 0700 -- "$BUILD_DIR"
fi
BUILD_DIR=$(cd -- "$BUILD_DIR" && pwd)
[[ ! -e "$SNAPSHOT_DIR" && ! -L "$SNAPSHOT_DIR" ]] || {
  echo "source snapshot destination must be new: $SNAPSHOT_DIR" >&2
  exit 1
}

SNAPSHOT_METADATA="$BUILD_DIR/pohw-source-snapshot.json"
DEPENDS_SOURCE_METADATA="$BUILD_DIR/pohw-depends-source.json"
DEPENDS_METADATA="$BUILD_DIR/pohw-depends-prefix.json"
RUN_RECORD="$BUILD_DIR/pohw-build-run.json"
EVIDENCE="$BUILD_DIR/pohw-build-evidence.json"

"$SCRIPT_DIR/pohw-verify-bitcoin-core-source.sh" \
  --source-dir "$SOURCE_DIR" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --snapshot-metadata "$SNAPSHOT_METADATA" \
  --manifest "$MANIFEST"

BUILD_PROFILE_INFO=$(python3 - "$MANIFEST" <<'PY'
import json
import sys

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle, object_pairs_hook=pairs)
if manifest.get("schema_version") == "pohw-bitcoin-core-patch-series-lock/v1":
    print("experiment-2", manifest["network"]["candidate_activation_id"], sep="\t")
else:
    print("experiment-1", "-", sep="\t")
PY
)
IFS=$'\t' read -r BUILD_PROFILE POHW2_ACTIVATION_ID <<<"$BUILD_PROFILE_INFO"

resolve_tool() {
  local name=$1
  local located
  located=$(command -v -- "$name") || {
    echo "required build tool is unavailable: $name" >&2
    exit 1
  }
  python3 - "$located" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve(strict=True))
PY
}

PYTHON3=$(resolve_tool python3)
CMAKE=$(resolve_tool cmake)
CTEST=$(resolve_tool ctest)
MAKE=$(resolve_tool make)
resolve_tool ninja >/dev/null
resolve_tool c++ >/dev/null

run_step() {
  local label=$1
  shift
  "$PYTHON3" "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" run-step \
    --snapshot-dir "$SNAPSHOT_DIR" \
    --build-dir "$BUILD_DIR" \
    --run-record "$RUN_RECORD" \
    --label "$label" \
    "$@"
}

# Keep profile-only steps out of the Experiment 1 static step list while still
# recording them through the same fail-closed runner.
run_profile_step() {
  run_step "$@"
}

CMAKE_FLAGS=(
  -DBUILD_GUI=OFF
  -DBUILD_TESTS=ON
  -DBUILD_BENCH=OFF
  -DBUILD_FUZZ_BINARY=OFF
  -DENABLE_IPC=OFF
)
if [[ "$BUILD_PROFILE" == experiment-2 ]]; then
  [[ "$POHW2_ACTIVATION_ID" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Experiment 2 activation ID is invalid" >&2
    exit 1
  }
  CMAKE_FLAGS+=("-DPOHW2_ACTIVATION_ID=$POHW2_ACTIVATION_ID")
fi

DEPENDS_ROOT="$BUILD_DIR/pohw-depends"
DEPENDS_SOURCE="$DEPENDS_ROOT/source"
mkdir -m 0700 -- "$DEPENDS_ROOT"
python3 "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" depends-prepare \
  --source "$SNAPSHOT_DIR/depends" \
  --destination "$DEPENDS_SOURCE" \
  --metadata "$DEPENDS_SOURCE_METADATA"

CONFIG_GUESS="$DEPENDS_SOURCE/config.guess"
CONFIG_SUB="$DEPENDS_SOURCE/config.sub"
[[ -x "$CONFIG_GUESS" && -x "$CONFIG_SUB" ]] || {
  echo "verified source snapshot is missing executable depends host tools" >&2
  exit 1
}
DEPENDS_HOST=$("$CONFIG_SUB" "$("$CONFIG_GUESS")")
[[ "$DEPENDS_HOST" =~ ^[A-Za-z0-9_.+]+-[A-Za-z0-9_.+]+-[A-Za-z0-9_.+-]+$ ]] || {
  echo "depends host triplet is invalid: $DEPENDS_HOST" >&2
  exit 1
}
DEPENDS_PREFIX="$DEPENDS_SOURCE/$DEPENDS_HOST"
DEPENDS_ARGS=(
  -C "$DEPENDS_SOURCE"
  "HOST=$DEPENDS_HOST"
  NO_QT=1
  NO_QR=1
  NO_ZMQ=1
  NO_IPC=1
  NO_USDT=1
)
run_step depends_fetch -- "$MAKE" "${DEPENDS_ARGS[@]}" download-one
run_step depends_build -- "$MAKE" "${DEPENDS_ARGS[@]}" install
[[ -f "$DEPENDS_PREFIX/toolchain.cmake" && ! -L "$DEPENDS_PREFIX/toolchain.cmake" ]] || {
  echo "Bitcoin Core depends did not produce a regular toolchain.cmake" >&2
  exit 1
}
python3 "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" depends-metadata \
  --prefix "$DEPENDS_PREFIX" \
  --metadata "$DEPENDS_METADATA" \
  --host "$DEPENDS_HOST"

PREFIX_MAP_FLAGS="-ffile-prefix-map=$SNAPSHOT_DIR=/pohw/source -ffile-prefix-map=$BUILD_DIR=/pohw/build"
CONFIGURE_ENV=(
  --env "CFLAGS=$PREFIX_MAP_FLAGS"
  --env "CXXFLAGS=$PREFIX_MAP_FLAGS"
)
if [[ "$DEPENDS_HOST" == *-apple-darwin* ]]; then
  CONFIGURE_ENV+=(--env "LDFLAGS=-Wl,-no_uuid")
fi
run_step configure "${CONFIGURE_ENV[@]}" -- \
  "$CMAKE" -S "$SNAPSHOT_DIR" -B "$BUILD_DIR" -G Ninja \
  --toolchain "$DEPENDS_PREFIX/toolchain.cmake" \
  "${CMAKE_FLAGS[@]}"
if [[ -n "$JOBS" ]]; then
  run_step build -- "$CMAKE" --build "$BUILD_DIR" -j "$JOBS"
else
  run_step build -- "$CMAKE" --build "$BUILD_DIR"
fi

TEST_TMPDIR=$(mktemp -d "$BUILD_DIR/.test-tmp.XXXXXXXX")
cleanup_test_tmp() {
  local status=$?
  rm -rf -- "$TEST_TMPDIR"
  exit "$status"
}
trap cleanup_test_tmp EXIT
chmod 0700 "$TEST_TMPDIR"
TEST_BITCOIN="$BUILD_DIR/bin/test_bitcoin"
[[ -x "$TEST_BITCOIN" && ! -L "$TEST_BITCOIN" ]] || {
  echo "build did not produce a regular executable test_bitcoin" >&2
  exit 1
}
TEST_BITCOIN=$(python3 - "$TEST_BITCOIN" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve(strict=True))
PY
)

run_step pow_sanity --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" --run_test=pow_tests/ChainParams_POHW_sanity
run_step block_file_magic --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" --run_test=pow_tests/POHW_inherited_block_file_magic_is_disk_only
run_step bootstrap_marker --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" --run_test=pow_tests/POHW_bootstrap_and_handoff_marker
run_step template_difficulty --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" --run_test=pow_tests/POHW_update_time_refreshes_template_difficulty
run_step replay_marker --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" \
  --run_test=transaction_tests/pohw_inherited_spend_requires_fork_only_replay_marker
run_step replay_domain --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" \
  --run_test=transaction_tests/pohw_replay_sighash_domain_resists_marker_stripping
run_step replay_checkpoint --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" \
  --run_test=transaction_tests/pohw_active_chain_replay_checkpoint_is_fail_closed
run_step replay_version --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" \
  --run_test=transaction_tests/pohw_replay_protected_version_is_network_scoped
run_step script_cache_domain --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" --run_test=txvalidationcache_tests
run_step block_file_reader --env "TMPDIR=$TEST_TMPDIR" -- \
  "$TEST_BITCOIN" --run_test=streams_tests/streams_buffered_file_find_any_byte
if [[ "$BUILD_PROFILE" == experiment-2 ]]; then
  run_profile_step consensus_identity --env "TMPDIR=$TEST_TMPDIR" -- \
    "$TEST_BITCOIN" --run_test=pohw_identity_auth_tests
fi
FUNCTIONAL_RUNNER="$SNAPSHOT_DIR/test/functional/test_runner.py"
FUNCTIONAL_TESTS_DIR="$SNAPSHOT_DIR/test/functional"
FUNCTIONAL_CONFIG="$BUILD_DIR/test/config.ini"
[[ -f "$FUNCTIONAL_RUNNER" ]] || {
  echo "verified source snapshot does not contain the functional test runner" >&2
  exit 1
}
[[ -f "$FUNCTIONAL_TESTS_DIR/feature_pohw_replay.py" ]] || {
  echo "verified source snapshot does not contain the replay functional test" >&2
  exit 1
}
[[ -f "$FUNCTIONAL_CONFIG" && ! -L "$FUNCTIONAL_CONFIG" ]] || {
  echo "build did not produce a regular functional test configuration" >&2
  exit 1
}
run_step replay_functional --env "TMPDIR=$TEST_TMPDIR" -- \
  "$PYTHON3" "$FUNCTIONAL_RUNNER" feature_pohw_replay.py \
  --jobs=1 --tmpdirprefix="$TEST_TMPDIR" \
  --configfile="$FUNCTIONAL_CONFIG" --testsdir="$FUNCTIONAL_TESTS_DIR"
if [[ "$BUILD_PROFILE" == experiment-2 ]]; then
  [[ -f "$FUNCTIONAL_TESTS_DIR/feature_pohw_identity_auth.py" ]] || {
    echo "verified Experiment 2 snapshot lacks the identity authorization functional test" >&2
    exit 1
  }
  run_profile_step consensus_identity_functional --env "TMPDIR=$TEST_TMPDIR" -- \
    "$PYTHON3" "$FUNCTIONAL_RUNNER" feature_pohw_identity_auth.py \
    --jobs=1 --tmpdirprefix="$TEST_TMPDIR" \
    --configfile="$FUNCTIONAL_CONFIG" --testsdir="$FUNCTIONAL_TESTS_DIR"
fi
run_step ctest --env "TMPDIR=$TEST_TMPDIR" -- \
  "$CTEST" --test-dir "$BUILD_DIR" --output-on-failure

RELEASE_DIR="$BUILD_DIR/pohw-release"
[[ ! -e "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] || {
  echo "release artifact directory must be new: $RELEASE_DIR" >&2
  exit 1
}
run_step install -- \
  "$CMAKE" --install "$BUILD_DIR" --prefix "$RELEASE_DIR" --strip

python3 "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" write \
  --manifest "$MANIFEST" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --snapshot-metadata "$SNAPSHOT_METADATA" \
  --build-dir "$BUILD_DIR" \
  --run-record "$RUN_RECORD" \
  --evidence "$EVIDENCE"
python3 "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" verify \
  --manifest "$MANIFEST" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --snapshot-metadata "$SNAPSHOT_METADATA" \
  --build-dir "$BUILD_DIR" \
  --run-record "$RUN_RECORD" \
  --evidence "$EVIDENCE"

python3 - "$EVIDENCE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="ascii") as handle:
    evidence = json.load(handle)
for name in ("bitcoind", "bitcoin-cli", "test_bitcoin"):
    artifact = evidence["artifacts"][name]
    print(f"{artifact['sha256']}  {name}")
PY
