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
BIND_ADDR="${POHW_GOSSIP_BIND_ADDR:-127.0.0.1:40406}"
SYNC_INTERVAL="${POHW_PEER_SYNC_INTERVAL_SECONDS:-30}"
MAX_PEERS_PER_ROUND="${POHW_MAX_PEERS_PER_ROUND:-32}"
MAX_PARALLEL_PEERS="${POHW_MAX_PARALLEL_PEERS:-4}"
INVENTORY_LIMIT="${POHW_INVENTORY_LIMIT:-256}"
REBROADCAST_LIMIT="${POHW_REBROADCAST_LIMIT:-64}"
PEER_LIST_LIMIT="${POHW_PEER_LIST_LIMIT:-64}"
MAX_CONNECTIONS="${POHW_GOSSIP_MAX_CONNECTIONS:-128}"
MAX_CONNECTIONS_PER_IP="${POHW_GOSSIP_MAX_CONNECTIONS_PER_IP:-16}"
MAX_ENVELOPES_PER_WINDOW="${POHW_MAX_ENVELOPES_PER_WINDOW:-120}"
MAX_READ_REQUESTS_PER_WINDOW="${POHW_MAX_READ_REQUESTS_PER_WINDOW:-600}"
RATE_WINDOW_SECONDS="${POHW_RATE_WINDOW_SECONDS:-60}"

if [[ -n "${POHW_P2POOL_NODE_BIN:-}" ]]; then
  P2POOL_CMD=("$POHW_P2POOL_NODE_BIN")
elif [[ -x "$WORKDIR/target/release/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/release/p2pool-node")
elif [[ -x "$WORKDIR/target/debug/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/debug/p2pool-node")
else
  P2POOL_CMD=(cargo run --manifest-path "$WORKDIR/Cargo.toml" -q -p p2pool-node --)
fi

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

args=(
  run-gossip-mesh
  --datadir "$DATADIR"
  --bind-addr "$BIND_ADDR"
  --peer-sync-interval-seconds "$SYNC_INTERVAL"
  --max-peers-per-round "$MAX_PEERS_PER_ROUND"
  --max-parallel-peers "$MAX_PARALLEL_PEERS"
  --inventory-limit "$INVENTORY_LIMIT"
  --rebroadcast-limit "$REBROADCAST_LIMIT"
  --peer-list-limit "$PEER_LIST_LIMIT"
  --max-connections "$MAX_CONNECTIONS"
  --max-connections-per-ip "$MAX_CONNECTIONS_PER_IP"
  --max-envelopes-per-window "$MAX_ENVELOPES_PER_WINDOW"
  --max-read-requests-per-window "$MAX_READ_REQUESTS_PER_WINDOW"
  --rate-window-seconds "$RATE_WINDOW_SECONDS"
)

if [[ -n "${POHW_ADVERTISE_ADDR:-}" ]]; then
  args+=(--advertise-addr "$POHW_ADVERTISE_ADDR")
fi

if [[ "${POHW_ALLOW_PUBLIC_PEERS:-false}" == "true" ]]; then
  args+=(--allow-public-peers)
fi

if [[ -n "${POHW_PEER_ADDRS:-}" ]]; then
  read -r -a peers <<< "${POHW_PEER_ADDRS//,/ }"
  for peer in "${peers[@]}"; do
    [[ -z "$peer" ]] && continue
    args+=(--peer-addr "$peer")
  done
fi

echo "Starting PoHW gossip mesh on $BIND_ADDR with datadir $DATADIR" >&2
exec "${P2POOL_CMD[@]}" "${args[@]}"
