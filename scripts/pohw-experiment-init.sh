#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pohw-experiment-init.sh --miner-id ID [options]

Creates a local .pohw-experiment.env with safe defaults for Experiment 0.

Options:
  --env-file PATH          Env file to create (default: .pohw-experiment.env)
  --miner-id ID            Stable lowercase participant id, for example alice
  --idena-address ADDRESS  Optional participant Idena address
  --workdir PATH           Repository path (default: current directory)
  --datadir PATH           Local replay datadir (default: WORKDIR/.pohw-p2pool)
  --snapshot-dir PATH      Snapshot directory (default: DATADIR/snapshots)
  --output-root PATH       Preflight/report output root (default: WORKDIR/output)
  --bind-addr ADDR         Gossip bind address (default: 127.0.0.1:40406)
  --advertise-addr ADDR    Optional reachable gossip address to advertise
  --peer-addrs LIST        Comma-separated peer host:port list
  --register-peers         Add peer list during preflight
  --allow-public-peers     Allow public-routable gossip peers
  --force                  Overwrite an existing env file
  -h, --help               Show this help
EOF
}

ENV_FILE=".pohw-experiment.env"
MINER_ID=""
DASHBOARD_IDENA_ADDRESS=""
WORKDIR="$(pwd -P)"
DATADIR=""
SNAPSHOT_DIR=""
OUTPUT_ROOT=""
GOSSIP_BIND_ADDR="127.0.0.1:40406"
ADVERTISE_ADDR=""
PEER_ADDRS=""
REGISTER_PEERS="false"
ALLOW_PUBLIC_PEERS="false"
FORCE="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="${2:?missing value for --env-file}"
      shift 2
      ;;
    --miner-id)
      MINER_ID="${2:?missing value for --miner-id}"
      shift 2
      ;;
    --idena-address)
      DASHBOARD_IDENA_ADDRESS="${2:?missing value for --idena-address}"
      shift 2
      ;;
    --workdir)
      WORKDIR="${2:?missing value for --workdir}"
      shift 2
      ;;
    --datadir)
      DATADIR="${2:?missing value for --datadir}"
      shift 2
      ;;
    --snapshot-dir)
      SNAPSHOT_DIR="${2:?missing value for --snapshot-dir}"
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT="${2:?missing value for --output-root}"
      shift 2
      ;;
    --bind-addr)
      GOSSIP_BIND_ADDR="${2:?missing value for --bind-addr}"
      shift 2
      ;;
    --advertise-addr)
      ADVERTISE_ADDR="${2:?missing value for --advertise-addr}"
      shift 2
      ;;
    --peer-addrs)
      PEER_ADDRS="${2:?missing value for --peer-addrs}"
      shift 2
      ;;
    --register-peers)
      REGISTER_PEERS="true"
      shift
      ;;
    --allow-public-peers)
      ALLOW_PUBLIC_PEERS="true"
      shift
      ;;
    --force)
      FORCE="true"
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

if [[ -z "$MINER_ID" ]]; then
  echo "--miner-id is required. Use a stable lowercase id such as alice or node-01." >&2
  exit 1
fi
if [[ ! "$MINER_ID" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
  echo "--miner-id must be lowercase and contain only a-z, 0-9, dot, underscore, or dash." >&2
  exit 1
fi
if [[ "$DASHBOARD_IDENA_ADDRESS" =~ [[:space:]] ]]; then
  echo "--idena-address must not contain whitespace." >&2
  exit 1
fi
if [[ ! -f "$WORKDIR/Cargo.toml" ]]; then
  echo "--workdir must point to the checked-out p2pool repository: $WORKDIR" >&2
  exit 1
fi
WORKDIR="$(cd "$WORKDIR" && pwd -P)"

DATADIR="${DATADIR:-$WORKDIR/.pohw-p2pool}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-$DATADIR/snapshots}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$WORKDIR/output}"

stat_mode() {
  local path="$1"
  if stat -c %a "$path" >/dev/null 2>&1; then
    stat -c %a "$path"
  else
    stat -f %Lp "$path"
  fi
}

stat_owner() {
  local path="$1"
  if stat -c %u "$path" >/dev/null 2>&1; then
    stat -c %u "$path"
  else
    stat -f %u "$path"
  fi
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

validate_env_destination() {
  local file="$1"
  local parent mode unsafe_bits owner
  parent="$(dirname "$file")"

  if [[ -L "$file" ]]; then
    echo "Refusing to write symlinked env file: $file" >&2
    exit 1
  fi
  if [[ -e "$file" && ! -f "$file" ]]; then
    echo "Refusing to write env file over non-regular path: $file" >&2
    exit 1
  fi
  if [[ -e "$file" && "$FORCE" != "true" ]]; then
    echo "Refusing to overwrite existing env file: $file" >&2
    echo "Re-run with --force if you intentionally want to replace it." >&2
    exit 1
  fi
  if [[ -e "$file" ]]; then
    owner="$(stat_owner "$file")"
    if [[ "$owner" != "$(id -u)" ]]; then
      echo "Refusing to overwrite env file not owned by the current user: $file" >&2
      exit 1
    fi
  fi

  if [[ -L "$parent" ]]; then
    echo "Refusing to write env file in symlinked directory: $parent" >&2
    exit 1
  fi
  reject_symlink_ancestor "$parent"
  if [[ ! -e "$parent" ]]; then
    (umask 077 && mkdir -p "$parent")
  fi
  if [[ ! -d "$parent" ]]; then
    echo "Env file parent is not a directory: $parent" >&2
    exit 1
  fi
  mode="$(stat_mode "$parent")"
  unsafe_bits=$((8#$mode & 022))
  if (( unsafe_bits != 0 )); then
    echo "Refusing to write env file in group/world-writable directory: $parent" >&2
    echo "Fix with: chmod go-w $parent" >&2
    exit 1
  fi
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

reject_newline() {
  local name="$1"
  local value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "$name must not contain newlines." >&2
    exit 1
  fi
}

write_env_line() {
  local name="$1"
  local value="$2"
  reject_newline "$name" "$value"
  printf '%s=%q\n' "$name" "$value"
}

validate_env_destination "$ENV_FILE"
ensure_local_dir "$DATADIR" "datadir"
ensure_local_dir "$SNAPSHOT_DIR" "snapshot"
ensure_local_dir "$OUTPUT_ROOT" "output"
chmod 700 "$DATADIR" "$SNAPSHOT_DIR"
umask 077
tmp_file="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT

{
  echo "# PoHW P2Pool Experiment 0 local config."
  echo "# This file is local-only. Do not share it."
  echo
  write_env_line POHW_EXPERIMENT_NO_VALUE_ACK I_UNDERSTAND_NO_VALUE
  echo
  write_env_line POHW_WORKDIR "$WORKDIR"
  write_env_line POHW_DATADIR "$DATADIR"
  write_env_line POHW_SNAPSHOT_DIR "$SNAPSHOT_DIR"
  write_env_line POHW_EXPERIMENT_OUTPUT_ROOT "$OUTPUT_ROOT"
  echo
  write_env_line POHW_FORK_CHAIN_NAME "pohw-experiment-0"
  write_env_line POHW_FORK_LAUNCH_TIMESTAMP_UTC ""
  write_env_line POHW_FORK_ACTIVATION_MANIFEST "$DATADIR/fork-activation.json"
  write_env_line POHW_FORK_POST_FORK_POW_LIMIT_BITS "207fffff"
  write_env_line POHW_FORK_TARGET_SPACING_SECONDS "600"
  write_env_line POHW_FORK_BOOTSTRAP_HANDOFF_HASHRATE_HPS "1000000000000000"
  write_env_line POHW_FORK_TIMESTAMP_SEARCH_WINDOW_BLOCKS "4096"
  write_env_line POHW_FORK_INHERITED_UTXO_SPENDING_ENABLED "false"
  write_env_line POHW_FORK_ALLOW_NON_MAINNET_RPC "false"
  echo
  write_env_line POHW_MINER_ID "$MINER_ID"
  write_env_line POHW_IDENA_ADDRESS "$DASHBOARD_IDENA_ADDRESS"
  write_env_line POHW_DASHBOARD_IDENA_ADDRESS "$DASHBOARD_IDENA_ADDRESS"
  echo
  write_env_line POHW_GOSSIP_BIND_ADDR "$GOSSIP_BIND_ADDR"
  write_env_line POHW_ADVERTISE_ADDR "$ADVERTISE_ADDR"
  write_env_line POHW_PEER_ADDRS "$PEER_ADDRS"
  write_env_line POHW_ALLOW_PUBLIC_PEERS "$ALLOW_PUBLIC_PEERS"
  write_env_line POHW_EXPERIMENT_REGISTER_PEERS "$REGISTER_PEERS"
  echo
  write_env_line POHW_DASHBOARD_BIND_ADDR "127.0.0.1:40407"
  write_env_line POHW_DASHBOARD_ALLOW_NON_LOOPBACK "false"
  write_env_line POHW_DASHBOARD_API_TOKEN_FILE "/etc/pohw/dashboard-api.token"
  write_env_line POHW_DASHBOARD_ALLOWED_ORIGINS "http://127.0.0.1:5176,http://localhost:5176"
  echo
  write_env_line IDENA_RPC_URL "http://127.0.0.1:9009"
  write_env_line IDENA_API_KEY_FILE "$HOME/.idena/node/datadir/api.key"
  write_env_line BITCOIN_RPC_URL "http://127.0.0.1:8332"
  write_env_line BITCOIN_RPC_COOKIE_FILE "$HOME/.bitcoin/.cookie"
  echo
  write_env_line POHW_P2POOL_NODE_BIN ""
  write_env_line POHW_IDENA_INDEXER_BIN ""
} > "$tmp_file"

mv "$tmp_file" "$ENV_FILE"
trap - EXIT
chmod 600 "$ENV_FILE"

echo "Created $ENV_FILE"
echo "Datadir: $DATADIR"
echo "Snapshot dir: $SNAPSHOT_DIR"
echo "Next: scripts/pohw-experiment-preflight.sh $ENV_FILE"
