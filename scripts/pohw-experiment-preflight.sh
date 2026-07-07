#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-${POHW_EXPERIMENT_ENV:-}}"
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
SNAPSHOT_DIR="${POHW_SNAPSHOT_DIR:-$WORKDIR/snapshots}"
OUTPUT_ROOT="${POHW_EXPERIMENT_OUTPUT_ROOT:-$WORKDIR/output}"
OUTPUT_DIR="$OUTPUT_ROOT/experiment-preflight-$(date -u +%Y%m%dT%H%M%SZ)"
MINER_ID="${POHW_MINER_ID:-}"
PEER_ADDRS="${POHW_PEER_ADDRS:-}"
FORK_ACTIVATION_MANIFEST="${POHW_FORK_ACTIVATION_MANIFEST:-$DATADIR/fork-activation.json}"

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

redact_json_file() {
  local path="$1"
  [[ -s "$path" ]] || return 0
  python3 - "$path" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
path = pathlib.Path(sys.argv[1])

def read_limited_json_file(path):
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON artifact exceeds {MAX_JSON_BYTES} bytes")
    return json.loads(path.read_text(encoding="utf-8"))

try:
    data = read_limited_json_file(path)
except Exception:
    raise SystemExit(0)

PATH_KEYS = {
    "datadir",
    "gossip_envelope_log",
    "path",
    "sharechain_log",
    "snapshot_dir",
    "workdir",
}

def scrub(value):
    if isinstance(value, dict):
        return {
            key: "<redacted>" if key in PATH_KEYS and isinstance(item, str) else scrub(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value

path.write_text(json.dumps(scrub(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
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

ensure_local_dir() {
  local dir="$1"
  local label="$2"
  if [[ -L "$dir" ]]; then
    echo "Refusing to use symlinked $label directory: $dir" >&2
    exit 1
  fi
  if [[ -e "$dir" && ! -d "$dir" ]]; then
    echo "$label path is not a directory: $dir" >&2
    exit 1
  fi
  reject_symlink_ancestor "$dir"
  mkdir -p "$dir"
}

ensure_local_dir "$DATADIR" "datadir"
ensure_local_dir "$SNAPSHOT_DIR" "snapshot"
create_output_dir "$OUTPUT_DIR"

{
  echo "generated_at_utc=$(date -u +%FT%TZ)"
  echo "workdir=<redacted>"
  echo "datadir=<redacted>"
  echo "snapshot_dir=<redacted>"
  echo "miner_id=$MINER_ID"
  echo "fork_chain_name=${POHW_FORK_CHAIN_NAME:-pohw-experiment-0}"
  echo "fork_launch_timestamp_utc=${POHW_FORK_LAUNCH_TIMESTAMP_UTC:-}"
  if [[ -L "$FORK_ACTIVATION_MANIFEST" ]]; then
    echo "Refusing symlinked fork activation manifest: $FORK_ACTIVATION_MANIFEST" >&2
    exit 1
  elif [[ -e "$FORK_ACTIVATION_MANIFEST" && ! -f "$FORK_ACTIVATION_MANIFEST" ]]; then
    echo "Fork activation manifest must be a regular file: $FORK_ACTIVATION_MANIFEST" >&2
    exit 1
  elif [[ -s "$FORK_ACTIVATION_MANIFEST" ]]; then
    reject_symlink_ancestor "$FORK_ACTIVATION_MANIFEST"
    python3 - "$FORK_ACTIVATION_MANIFEST" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
path = pathlib.Path(sys.argv[1])

def read_limited_json_file(path):
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON artifact exceeds {MAX_JSON_BYTES} bytes")
    return json.loads(path.read_text(encoding="utf-8"))

try:
    manifest = read_limited_json_file(path)
except Exception as exc:
    print(f"fork_activation_manifest_parse_error={exc}")
    raise SystemExit(0)

fork_point = manifest.get("fork_point") if isinstance(manifest, dict) else {}
launch_block = manifest.get("launch_block") if isinstance(manifest, dict) else {}
config = manifest.get("config") if isinstance(manifest, dict) else {}
print("fork_activation_manifest_present=true")
print(f"fork_activation_id={manifest.get('activation_id', '')}")
print(f"fork_first_fork_height={fork_point.get('first_fork_height', '')}")
print(f"fork_inherited_tip_hash={fork_point.get('inherited_tip_hash', '')}")
print(f"fork_launch_block_hash={launch_block.get('block_hash', '')}")
print(f"fork_replay_protection_required={manifest.get('replay_protection_required', '')}")
print(f"fork_inherited_utxo_spending_enabled={config.get('inherited_utxo_spending_enabled', '')}")
PY
  else
    echo "fork_activation_manifest_present=false"
  fi
  echo "gossip_bind_addr=${POHW_GOSSIP_BIND_ADDR:-}"
  echo "advertise_addr=${POHW_ADVERTISE_ADDR:-}"
  echo "peer_addrs=$PEER_ADDRS"
  git -C "$WORKDIR" rev-parse --abbrev-ref HEAD 2>/dev/null | sed 's/^/git_branch=/' || true
  git -C "$WORKDIR" rev-parse HEAD 2>/dev/null | sed 's/^/git_commit=/' || true
  if [[ -z "$(git -C "$WORKDIR" status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then
    echo "git_dirty=false"
  else
    echo "git_dirty=true"
  fi
} > "$OUTPUT_DIR/public-env-summary.txt"

if [[ "${POHW_EXPERIMENT_REGISTER_PEERS:-false}" == "true" && -n "$PEER_ADDRS" ]]; then
  for peer in $(split_words "$PEER_ADDRS"); do
    [[ -z "$peer" ]] && continue
    "${P2POOL_CMD[@]}" add-gossip-peer --datadir "$DATADIR" --peer-addr "$peer" \
      > "$OUTPUT_DIR/add-peer-${peer//[^A-Za-z0-9_.-]/_}.json"
    redact_json_file "$OUTPUT_DIR/add-peer-${peer//[^A-Za-z0-9_.-]/_}.json"
  done
fi

"${P2POOL_CMD[@]}" status --datadir "$DATADIR" > "$OUTPUT_DIR/status.json"
redact_json_file "$OUTPUT_DIR/status.json"
"${P2POOL_CMD[@]}" list-gossip-peers --datadir "$DATADIR" > "$OUTPUT_DIR/gossip-peers.json"

preflight_args=(multinode-preflight --datadir "$DATADIR" --snapshot-dir "$SNAPSHOT_DIR")
if [[ -n "$MINER_ID" ]]; then
  preflight_args+=(--miner-id "$MINER_ID")
fi
for peer in $(split_words "$PEER_ADDRS"); do
  [[ -z "$peer" ]] && continue
  preflight_args+=(--peer-addr "$peer")
done
"${P2POOL_CMD[@]}" "${preflight_args[@]}" > "$OUTPUT_DIR/multinode-preflight.json"
redact_json_file "$OUTPUT_DIR/multinode-preflight.json"

python3 - "$OUTPUT_DIR/multinode-preflight.json" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
path = pathlib.Path(sys.argv[1])
if path.stat().st_size > MAX_JSON_BYTES:
    raise SystemExit(f"preflight report JSON exceeds {MAX_JSON_BYTES} bytes")
report = json.loads(path.read_text(encoding="utf-8"))

readiness = report.get("readiness", {})
failed = [key for key, value in readiness.items() if value is not True]
if failed:
    print("Preflight completed with pending items:")
    for key in failed:
        print(f"- {key}")
else:
    print("Preflight ready: all local readiness checks passed.")

peers = report.get("peer_inventory_probe", [])
reachable = sum(1 for peer in peers if isinstance(peer, dict) and peer.get("reachable"))
print(f"Peer probes reachable: {reachable}/{len(peers)}")
PY

echo "Preflight report: $OUTPUT_DIR"
