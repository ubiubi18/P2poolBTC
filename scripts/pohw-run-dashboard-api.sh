#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
BIN="${POHW_P2POOL_NODE_BIN:-$WORKDIR/target/release/p2pool-node}"
DATADIR="${POHW_DATADIR:-/mnt/ssd/pohw-p2pool}"
SNAPSHOT_DIR="${POHW_SNAPSHOT_DIR:-$WORKDIR/snapshots}"
BIND_ADDR="${POHW_DASHBOARD_BIND_ADDR:-127.0.0.1:40407}"
PROBE_TIMEOUT_SECONDS="${POHW_DASHBOARD_PROBE_TIMEOUT_SECONDS:-3}"
TOKEN_FILE="${POHW_DASHBOARD_API_TOKEN_FILE:-}"

if [[ -n "${CREDENTIALS_DIRECTORY:-}" ]]; then
  credential_token_file="$CREDENTIALS_DIRECTORY/dashboard-api.token"
  if [[ -f "$credential_token_file" && ! -L "$credential_token_file" ]]; then
    TOKEN_FILE="$credential_token_file"
  fi
fi

args=(
  serve-dashboard-api
  --datadir "$DATADIR"
  --snapshot-dir "$SNAPSHOT_DIR"
  --bind-addr "$BIND_ADDR"
  --dashboard-probe-timeout-seconds "$PROBE_TIMEOUT_SECONDS"
)

case "${POHW_EXPLORER_PUBLIC:-false}" in
  true)
    args+=(--public-explorer)
    ;;
  false)
    ;;
  *)
    echo "POHW_EXPLORER_PUBLIC must be true or false." >&2
    exit 1
    ;;
esac

if [[ -n "${POHW_EXPLORER_FORK_CHAIN_RPC_ADDR:-}" || -n "${POHW_FORK_ACTIVATION_MANIFEST:-}" ]]; then
  if [[ -z "${POHW_EXPLORER_FORK_CHAIN_RPC_ADDR:-}" || -z "${POHW_FORK_ACTIVATION_MANIFEST:-}" ]]; then
    echo "POHW_EXPLORER_FORK_CHAIN_RPC_ADDR and POHW_FORK_ACTIVATION_MANIFEST must be set together." >&2
    exit 1
  fi
  args+=(
    --explorer-fork-chain-rpc-addr "$POHW_EXPLORER_FORK_CHAIN_RPC_ADDR"
    --explorer-fork-activation-manifest "$POHW_FORK_ACTIVATION_MANIFEST"
  )
fi

if [[ -n "${POHW_EXPLORER_BITCOIN_INDEX_URL:-}" ]]; then
  args+=(--explorer-bitcoin-index-url "$POHW_EXPLORER_BITCOIN_INDEX_URL")
fi

case "${POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX:-false}" in
  true)
    args+=(--explorer-allow-remote-bitcoin-index)
    ;;
  false)
    ;;
  *)
    echo "POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX must be true or false." >&2
    exit 1
    ;;
esac

if [[ "${POHW_DASHBOARD_ALLOW_NON_LOOPBACK:-false}" == "true" ]]; then
  args+=(--allow-non-loopback)
fi

if [[ "${POHW_ALLOW_REMOTE_RPC:-false}" == "true" ]]; then
  args+=(--allow-remote-rpc)
fi

if [[ -n "$TOKEN_FILE" ]]; then
  args+=(--dashboard-api-token-file "$TOKEN_FILE")
fi

if [[ -n "${POHW_DASHBOARD_MINER_ID:-}" ]]; then
  args+=(--dashboard-miner-id "$POHW_DASHBOARD_MINER_ID")
fi

if [[ -n "${POHW_DASHBOARD_CLAIM_OWNER_ID:-}" ]]; then
  args+=(--dashboard-claim-owner-id "$POHW_DASHBOARD_CLAIM_OWNER_ID")
fi

if [[ -n "${POHW_DASHBOARD_IDENA_ADDRESS:-}" ]]; then
  args+=(--dashboard-idena-address "$POHW_DASHBOARD_IDENA_ADDRESS")
fi

if [[ -n "${POHW_DASHBOARD_ALLOWED_ORIGINS:-}" ]]; then
  read -r -a origins <<< "${POHW_DASHBOARD_ALLOWED_ORIGINS//,/ }"
  for origin in "${origins[@]}"; do
    if [[ -n "$origin" ]]; then
      args+=(--dashboard-allowed-origin "$origin")
    fi
  done
fi

if [[ "${POHW_ENABLE_BITCOIN_RPC:-false}" == "true" ]]; then
  args+=(--enable-bitcoin-rpc)
  if [[ -n "${BITCOIN_RPC_URL:-}" ]]; then
    args+=(--bitcoin-rpc-url "$BITCOIN_RPC_URL")
  fi
  if [[ -n "${BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
    args+=(--bitcoin-rpc-cookie-file "$BITCOIN_RPC_COOKIE_FILE")
  fi
fi

if [[ -n "${IDENA_RPC_URL:-}" ]]; then
  args+=(--idena-rpc-url "$IDENA_RPC_URL")
fi

if [[ -n "${IDENA_API_KEY_FILE:-}" ]]; then
  args+=(--idena-api-key-file "$IDENA_API_KEY_FILE")
fi

exec "$BIN" "${args[@]}"
