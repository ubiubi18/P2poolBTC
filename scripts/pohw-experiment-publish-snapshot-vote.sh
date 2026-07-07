#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pohw-experiment-publish-snapshot-vote.sh [ENV_FILE] [options]

Publishes a signed SnapshotVote for the latest local verified Idena snapshot.
The vote is appended locally and gossiped to POHW_PEER_ADDRS by default.

Options:
  --snapshot-file PATH          Snapshot JSON to vote for (default: latest in POHW_SNAPSHOT_DIR)
  --output-dir PATH             Output directory for local vote artifacts
  --mining-secret-key-file PATH Override default miner registration mining key
  --node-secret-key-file PATH   Override default gossip node key
  --no-append                   Do not append the signed vote locally
  --no-gossip                   Do not send the signed vote to configured peers
  -h, --help                    Show this help
EOF
}

ENV_FILE="${POHW_EXPERIMENT_ENV:-}"
if [[ $# -gt 0 && "$1" != --* ]]; then
  ENV_FILE="$1"
  shift
fi

SNAPSHOT_FILE=""
OUTPUT_DIR=""
MINING_SECRET_KEY_FILE=""
NODE_SECRET_KEY_FILE=""
APPEND="true"
GOSSIP="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot-file)
      SNAPSHOT_FILE="${2:?missing value for --snapshot-file}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing value for --output-dir}"
      shift 2
      ;;
    --mining-secret-key-file)
      MINING_SECRET_KEY_FILE="${2:?missing value for --mining-secret-key-file}"
      shift 2
      ;;
    --node-secret-key-file)
      NODE_SECRET_KEY_FILE="${2:?missing value for --node-secret-key-file}"
      shift 2
      ;;
    --no-append)
      APPEND="false"
      shift
      ;;
    --no-gossip)
      GOSSIP="false"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_env_file() {
  local file="$1"
  local owner mode unsafe_bits parent parent_mode parent_unsafe_bits current
  if [[ ! -f "$file" ]]; then
    echo "Experiment env file not found: $file" >&2
    exit 1
  fi
  if [[ -L "$file" ]]; then
    echo "Refusing to source symlinked env file: $file" >&2
    exit 1
  fi
  parent="$(dirname "$file")"
  if [[ -L "$parent" ]]; then
    echo "Refusing to source env file from symlinked directory: $parent" >&2
    exit 1
  fi
  if [[ ! -d "$parent" ]]; then
    echo "Env file parent is not a directory: $parent" >&2
    exit 1
  fi
  current="$parent"
  while [[ -n "$current" && "$current" != "/" && "$current" != "." ]]; do
    if [[ -L "$current" ]]; then
      if owner="$(stat -c %u "$current" 2>/dev/null)"; then
        :
      else
        owner="$(stat -f %u "$current")"
      fi
      parent="$(dirname "$current")"
      if parent_mode="$(stat -c %a "$parent" 2>/dev/null)"; then
        :
      else
        parent_mode="$(stat -f %Lp "$parent")"
      fi
      parent_unsafe_bits=$((8#$parent_mode & 022))
      if [[ "$owner" != "0" || "$parent_unsafe_bits" != "0" ]]; then
        echo "Refusing to source env file through symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
  parent="$(dirname "$file")"
  if parent_mode="$(stat -c %a "$parent" 2>/dev/null)"; then
    :
  else
    parent_mode="$(stat -f %Lp "$parent")"
  fi
  parent_unsafe_bits=$((8#$parent_mode & 022))
  if (( parent_unsafe_bits != 0 )); then
    echo "Refusing to source env file from group/world-writable directory: $parent" >&2
    echo "Fix with: chmod go-w $parent" >&2
    exit 1
  fi
  if owner="$(stat -c %u "$file" 2>/dev/null)"; then
    :
  else
    owner="$(stat -f %u "$file")"
  fi
  if [[ "$owner" != "$(id -u)" ]]; then
    echo "Refusing to source env file not owned by the current user: $file" >&2
    exit 1
  fi
  if mode="$(stat -c %a "$file" 2>/dev/null)"; then
    :
  else
    mode="$(stat -f %Lp "$file")"
  fi
  unsafe_bits=$((8#$mode & 022))
  if (( unsafe_bits != 0 )); then
    echo "Refusing to source group/world-writable env file: $file" >&2
    echo "Fix with: chmod 600 $file" >&2
    exit 1
  fi
}

if [[ -n "$ENV_FILE" ]]; then
  validate_env_file "$ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
elif [[ -f ".pohw-experiment.env" ]]; then
  validate_env_file ".pohw-experiment.env"
  set -a
  # shellcheck disable=SC1091
  . ".pohw-experiment.env"
  set +a
fi

if [[ "${POHW_EXPERIMENT_NO_VALUE_ACK:-}" != "I_UNDERSTAND_NO_VALUE" ]]; then
  echo "Set POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE before joining Experiment 0." >&2
  exit 1
fi

WORKDIR="${POHW_WORKDIR:-$(pwd)}"
DATADIR="${POHW_DATADIR:-$WORKDIR/.pohw-p2pool}"
SNAPSHOT_DIR="${POHW_SNAPSHOT_DIR:-$DATADIR/snapshots}"
OUTPUT_ROOT="${POHW_EXPERIMENT_OUTPUT_ROOT:-$WORKDIR/output}"
MINER_ID="${POHW_MINER_ID:-}"
PEER_ADDRS="${POHW_PEER_ADDRS:-}"
OUTPUT_DIR="${OUTPUT_DIR:-$OUTPUT_ROOT/experiment-snapshot-vote-$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ -z "$MINER_ID" ]]; then
  echo "POHW_MINER_ID is required. Run scripts/pohw-experiment-init.sh first." >&2
  exit 1
fi
if [[ ! "$MINER_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "POHW_MINER_ID contains unsupported characters." >&2
  exit 1
fi

if [[ -n "${POHW_P2POOL_NODE_BIN:-}" ]]; then
  P2POOL_CMD=("$POHW_P2POOL_NODE_BIN")
elif [[ -x "$WORKDIR/target/release/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/release/p2pool-node")
elif [[ -x "$WORKDIR/target/debug/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/debug/p2pool-node")
else
  P2POOL_CMD=(cargo run --manifest-path "$WORKDIR/Cargo.toml" -q -p p2pool-node --)
fi

split_words() {
  printf '%s\n' "$1" | tr ',' ' ' | tr '\n' ' '
}

reject_symlink_ancestor() {
  local path="$1"
  local current="$path" owner parent parent_mode parent_unsafe_bits
  while [[ -n "$current" && "$current" != "/" && "$current" != "." ]]; do
    if [[ -L "$current" ]]; then
      if owner="$(stat -c %u "$current" 2>/dev/null)"; then
        :
      else
        owner="$(stat -f %u "$current")"
      fi
      parent="$(dirname "$current")"
      if parent_mode="$(stat -c %a "$parent" 2>/dev/null)"; then
        :
      else
        parent_mode="$(stat -f %Lp "$parent")"
      fi
      parent_unsafe_bits=$((8#$parent_mode & 022))
      if [[ "$owner" != "0" || "$parent_unsafe_bits" != "0" ]]; then
        echo "Refusing to write through symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
}

latest_snapshot_file() {
  python3 - "$SNAPSHOT_DIR" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
snapshot_dir = pathlib.Path(sys.argv[1])
candidates = []
for path in sorted(snapshot_dir.glob("*.json")):
    if path.is_symlink() or not path.is_file():
        continue
    if path.stat().st_size > MAX_JSON_BYTES:
        continue
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    required = ("snapshot_day", "idena_height", "identity_root", "score_root")
    if not all(key in data for key in required):
        continue
    try:
        height = int(data["idena_height"])
    except Exception:
        continue
    candidates.append((str(data["snapshot_day"]), height, path.as_posix()))

if not candidates:
    raise SystemExit(1)

candidates.sort()
print(candidates[-1][2])
PY
}

write_public_view() {
  local input="$1"
  local output="$2"
  if [[ -e "$output" ]]; then
    echo "Refusing to overwrite existing output file: $output" >&2
    exit 1
  fi
  python3 - "$input" "$output" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
if source.stat().st_size > MAX_JSON_BYTES:
    raise SystemExit(f"private snapshot vote output exceeds {MAX_JSON_BYTES} bytes")
data = json.loads(source.read_text(encoding="utf-8"))

PATH_KEYS = {"message_out", "envelope_out", "path"}

def scrub(value):
    if isinstance(value, dict):
        scrubbed = {}
        for key, item in value.items():
            if key in PATH_KEYS and isinstance(item, str):
                scrubbed[key] = "<redacted>"
            else:
                scrubbed[key] = scrub(item)
        return scrubbed
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value

target.write_text(json.dumps(scrub(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

create_output_dir() {
  local dir="$1"
  local parent
  if [[ -L "$dir" ]]; then
    echo "Refusing to write into symlinked output directory: $dir" >&2
    exit 1
  fi
  if [[ -e "$dir" ]]; then
    echo "Refusing to reuse existing output directory: $dir" >&2
    exit 1
  fi
  parent="$(dirname "$dir")"
  if [[ -L "$parent" ]]; then
    echo "Refusing to write into symlinked output parent: $parent" >&2
    exit 1
  fi
  reject_symlink_ancestor "$parent"
  mkdir -p "$parent"
  mkdir "$dir"
}

if [[ -z "$SNAPSHOT_FILE" ]]; then
  if ! SNAPSHOT_FILE="$(latest_snapshot_file)"; then
    echo "No snapshot JSON found in $SNAPSHOT_DIR. Wait for pohw-idena-snapshot.timer or pass --snapshot-file." >&2
    exit 1
  fi
fi
if [[ -L "$SNAPSHOT_FILE" || ! -f "$SNAPSHOT_FILE" || ! -r "$SNAPSHOT_FILE" ]]; then
  echo "Snapshot file must be a readable non-symlink regular file: $SNAPSHOT_FILE" >&2
  exit 1
fi

KEY_DIR="$DATADIR/keys/$MINER_ID"
MINING_SECRET_KEY_FILE="${MINING_SECRET_KEY_FILE:-${POHW_MINING_SECRET_KEY_FILE:-$KEY_DIR/mining.key}}"
NODE_SECRET_KEY_FILE="${NODE_SECRET_KEY_FILE:-${POHW_NODE_SECRET_KEY_FILE:-$KEY_DIR/gossip-node.key}}"
if [[ ! -f "$MINING_SECRET_KEY_FILE" || ! -f "$NODE_SECRET_KEY_FILE" ]]; then
  echo "Miner registration key files are missing. Run scripts/pohw-experiment-register-miner.sh first." >&2
  echo "Expected: $MINING_SECRET_KEY_FILE and $NODE_SECRET_KEY_FILE" >&2
  exit 1
fi

create_output_dir "$OUTPUT_DIR"
raw_out="$OUTPUT_DIR/snapshot-vote-local-private.json"
public_out="$OUTPUT_DIR/snapshot-vote-public.json"
message_out="$OUTPUT_DIR/snapshot-vote-message.json"
envelope_out="$OUTPUT_DIR/snapshot-vote-envelope.json"
for path in "$raw_out" "$public_out" "$message_out" "$envelope_out"; do
  if [[ -e "$path" ]]; then
    echo "Refusing to overwrite existing output file: $path" >&2
    exit 1
  fi
done

args=(
  publish-snapshot-vote
  --datadir "$DATADIR"
  --miner-id "$MINER_ID"
  --snapshot-file "$SNAPSHOT_FILE"
  --mining-secret-key-file "$MINING_SECRET_KEY_FILE"
  --node-secret-key-file "$NODE_SECRET_KEY_FILE"
  --message-out "$message_out"
  --envelope-out "$envelope_out"
)

if [[ "$APPEND" == "true" ]]; then
  args+=(--append)
fi
if [[ "$GOSSIP" == "true" && -n "$PEER_ADDRS" ]]; then
  for peer in $(split_words "$PEER_ADDRS"); do
    [[ -z "$peer" ]] && continue
    args+=(--peer-addr "$peer")
  done
fi

raw_tmp="$(mktemp "$OUTPUT_DIR/.snapshot-vote-local-private.XXXXXX")"
trap 'rm -f "$raw_tmp"' EXIT
"${P2POOL_CMD[@]}" "${args[@]}" > "$raw_tmp"
mv "$raw_tmp" "$raw_out"
trap - EXIT
write_public_view "$raw_out" "$public_out"

cat "$public_out"
echo "Snapshot vote used: $SNAPSHOT_FILE" >&2
echo "Local private snapshot vote output written: snapshot-vote-local-private.json" >&2
echo "Public snapshot vote output written: snapshot-vote-public.json" >&2
echo "Next: run scripts/pohw-experiment-report.sh ${ENV_FILE:-.pohw-experiment.env}" >&2
