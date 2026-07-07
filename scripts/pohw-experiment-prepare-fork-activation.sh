#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pohw-experiment-prepare-fork-activation.sh [ENV_FILE] [options]

Derives the shared fork/testnet activation manifest from local Bitcoin Core.

Options:
  --chain-name NAME              Override POHW_FORK_CHAIN_NAME
  --launch-timestamp-utc TIME    RFC3339 UTC launch time, for example 2026-07-05T00:00:00Z
  --manifest-out PATH            Manifest output path
  --allow-non-mainnet-rpc        Allow regtest/signet/testnet RPC source for local tests
  -h, --help                     Show this help
EOF
}

ENV_FILE="${POHW_EXPERIMENT_ENV:-}"
if [[ $# -gt 0 && "$1" != --* ]]; then
  ENV_FILE="$1"
  shift
fi

CHAIN_NAME=""
LAUNCH_TIMESTAMP_UTC=""
MANIFEST_OUT=""
ALLOW_NON_MAINNET_RPC="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chain-name)
      CHAIN_NAME="${2:?missing value for --chain-name}"
      shift 2
      ;;
    --launch-timestamp-utc)
      LAUNCH_TIMESTAMP_UTC="${2:?missing value for --launch-timestamp-utc}"
      shift 2
      ;;
    --manifest-out)
      MANIFEST_OUT="${2:?missing value for --manifest-out}"
      shift 2
      ;;
    --allow-non-mainnet-rpc)
      ALLOW_NON_MAINNET_RPC="true"
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
  echo "Set POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE before preparing Experiment 0 activation." >&2
  exit 1
fi

WORKDIR="${POHW_WORKDIR:-$(pwd)}"
DATADIR="${POHW_DATADIR:-$WORKDIR/.pohw-p2pool}"
CHAIN_NAME="${CHAIN_NAME:-${POHW_FORK_CHAIN_NAME:-pohw-experiment-0}}"
LAUNCH_TIMESTAMP_UTC="${LAUNCH_TIMESTAMP_UTC:-${POHW_FORK_LAUNCH_TIMESTAMP_UTC:-}}"
MANIFEST_OUT="${MANIFEST_OUT:-${POHW_FORK_ACTIVATION_MANIFEST:-$DATADIR/fork-activation.json}}"
POST_FORK_POW_LIMIT_BITS="${POHW_FORK_POST_FORK_POW_LIMIT_BITS:-207fffff}"
TARGET_SPACING_SECONDS="${POHW_FORK_TARGET_SPACING_SECONDS:-600}"
TIMESTAMP_SEARCH_WINDOW_BLOCKS="${POHW_FORK_TIMESTAMP_SEARCH_WINDOW_BLOCKS:-4096}"

if [[ -z "$LAUNCH_TIMESTAMP_UTC" ]]; then
  echo "Launch timestamp is required. Pass --launch-timestamp-utc or set POHW_FORK_LAUNCH_TIMESTAMP_UTC." >&2
  exit 1
fi
if [[ "$CHAIN_NAME" =~ [[:space:]] || "$LAUNCH_TIMESTAMP_UTC" =~ [[:space:]] ]]; then
  echo "Fork chain name and launch timestamp must not contain whitespace." >&2
  exit 1
fi
MANIFEST_PARENT="$(dirname "$MANIFEST_OUT")"
if [[ -L "$MANIFEST_PARENT" ]]; then
  echo "Refusing to write activation manifest under symlinked directory: $MANIFEST_PARENT" >&2
  exit 1
fi
reject_symlink_ancestor "$MANIFEST_PARENT"
if [[ -e "$MANIFEST_OUT" ]]; then
  echo "Refusing to overwrite existing activation manifest: $MANIFEST_OUT" >&2
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

args=(
  prepare-fork-activation
  --chain-name "$CHAIN_NAME"
  --launch-timestamp-utc "$LAUNCH_TIMESTAMP_UTC"
  --post-fork-pow-limit-bits "$POST_FORK_POW_LIMIT_BITS"
  --target-spacing-seconds "$TARGET_SPACING_SECONDS"
  --timestamp-search-window-blocks "$TIMESTAMP_SEARCH_WINDOW_BLOCKS"
  --rpc-url "${BITCOIN_RPC_URL:-http://127.0.0.1:8332}"
  --manifest-out "$MANIFEST_OUT"
)

if [[ "${POHW_FORK_INHERITED_UTXO_SPENDING_ENABLED:-false}" == "true" ]]; then
  args+=(--inherited-utxo-spending-enabled)
fi
if [[ "$ALLOW_NON_MAINNET_RPC" == "true" || "${POHW_FORK_ALLOW_NON_MAINNET_RPC:-false}" == "true" ]]; then
  args+=(--allow-non-mainnet-rpc)
fi
if [[ "${POHW_BITCOIN_ALLOW_REMOTE_RPC:-false}" == "true" ]]; then
  args+=(--allow-remote-rpc)
fi
if [[ -n "${BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
  args+=(--rpc-cookie-file "$BITCOIN_RPC_COOKIE_FILE")
fi
if [[ -n "${BITCOIN_RPC_USER:-}" ]]; then
  args+=(--rpc-user "$BITCOIN_RPC_USER")
fi
if [[ -n "${BITCOIN_RPC_PASSWORD:-}" ]]; then
  args+=(--rpc-password "$BITCOIN_RPC_PASSWORD")
fi

mkdir -p "$MANIFEST_PARENT"
"${P2POOL_CMD[@]}" "${args[@]}"

echo "Fork activation manifest: $MANIFEST_OUT"
