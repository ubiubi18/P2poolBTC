#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
BIN="${POHW_P2POOL_NODE_BIN:-$WORKDIR/target/release/p2pool-node}"
DATADIR="${POHW_DATADIR:-/mnt/ssd/pohw-p2pool}"
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
ADMIT_PEER_WORK_TEMPLATES="${POHW_ADMIT_PEER_WORK_TEMPLATES:-false}"
GOSSIP_NETWORK_ID="${POHW_GOSSIP_NETWORK_ID:-}"
IDENA_ANCHOR_POLICY="${POHW_IDENA_ANCHOR_POLICY:-}"
REQUIRE_IDENA_ANCHOR_POLICY="${POHW_REQUIRE_IDENA_ANCHOR_POLICY:-false}"
BITCOIN_EXPECTED_CHAIN="${POHW_BITCOIN_EXPECTED_CHAIN:-}"
EXPERIMENT_1_NETWORK_ID="86dfc3ff2736717781cdf007727bfc6bc3ec56a87f27a1d09703885adca434d8"
NORMALIZED_GOSSIP_NETWORK_ID="$(printf '%s' "$GOSSIP_NETWORK_ID" | tr '[:upper:]' '[:lower:]')"

case "$REQUIRE_IDENA_ANCHOR_POLICY" in
  true|false) ;;
  *)
    echo "POHW_REQUIRE_IDENA_ANCHOR_POLICY must be true or false." >&2
    exit 1
    ;;
esac
if [[ ( "$BITCOIN_EXPECTED_CHAIN" == "pohw" \
  || "$NORMALIZED_GOSSIP_NETWORK_ID" == "$EXPERIMENT_1_NETWORK_ID" ) \
  && "$REQUIRE_IDENA_ANCHOR_POLICY" != "true" ]]; then
  echo "POHW_REQUIRE_IDENA_ANCHOR_POLICY=true is mandatory for Experiment 1 gossip." >&2
  exit 1
fi
if [[ "$REQUIRE_IDENA_ANCHOR_POLICY" == "true" && -z "$IDENA_ANCHOR_POLICY" ]]; then
  echo "POHW_IDENA_ANCHOR_POLICY is required by this launch profile." >&2
  exit 1
fi
if [[ "$REQUIRE_IDENA_ANCHOR_POLICY" == "true" && "$ADMIT_PEER_WORK_TEMPLATES" != "true" ]]; then
  echo "POHW_ADMIT_PEER_WORK_TEMPLATES=true is required with mandatory Idena anchor policy." >&2
  exit 1
fi

if [[ -n "$GOSSIP_NETWORK_ID" ]]; then
  if ! [[ "$GOSSIP_NETWORK_ID" =~ ^([0-9a-fA-F]{64})$ ]]; then
    echo "POHW_GOSSIP_NETWORK_ID must be 32 bytes encoded as 64 hex characters." >&2
    exit 1
  fi
  "$BIN" initialize-gossip-network \
    --datadir "$DATADIR" \
    --network-id "$GOSSIP_NETWORK_ID" >/dev/null
fi

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

if [[ "$ADMIT_PEER_WORK_TEMPLATES" == "true" ]]; then
  args+=(--admit-peer-work-templates)
  if [[ -n "${POHW_STRATUM_FORK_CHAIN_RPC_ADDR:-}" || -n "${POHW_FORK_ACTIVATION_MANIFEST:-}" ]]; then
    if [[ -z "${POHW_STRATUM_FORK_CHAIN_RPC_ADDR:-}" || -z "${POHW_FORK_ACTIVATION_MANIFEST:-}" ]]; then
      echo "POHW_STRATUM_FORK_CHAIN_RPC_ADDR and POHW_FORK_ACTIVATION_MANIFEST must be set together." >&2
      exit 1
    fi
    args+=(
      --fork-chain-rpc-addr "$POHW_STRATUM_FORK_CHAIN_RPC_ADDR"
      --fork-chain-activation-manifest "$POHW_FORK_ACTIVATION_MANIFEST"
    )
  else
    export BITCOIN_RPC_URL="${POHW_BITCOIN_RPC_URL:-${BITCOIN_RPC_URL:-http://127.0.0.1:8332}}"
    if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
      export BITCOIN_RPC_COOKIE_FILE="$POHW_BITCOIN_RPC_COOKIE_FILE"
    fi
    if [[ -n "${POHW_EXPECTED_HEADER_MERKLE_ROOT_HEX:-}" ]]; then
      args+=(--expected-header-merkle-root-hex "$POHW_EXPECTED_HEADER_MERKLE_ROOT_HEX")
    fi
    if [[ "${POHW_ALLOW_UNVERIFIED_MERKLE_ROOT:-false}" == "true" ]]; then
      args+=(--allow-unverified-merkle-root)
    fi
    if [[ "${POHW_ALLOW_MUTABLE_TIME:-false}" == "true" ]]; then
      args+=(--allow-mutable-time)
    fi
    if [[ -n "${POHW_MAX_TEMPLATE_TIME_DRIFT_SECONDS:-}" ]]; then
      args+=(--max-template-time-drift-seconds "$POHW_MAX_TEMPLATE_TIME_DRIFT_SECONDS")
    fi
  fi
  if [[ -n "$IDENA_ANCHOR_POLICY" ]]; then
    if [[ -z "${IDENA_API_KEY_FILE:-}" ]]; then
      echo "IDENA_API_KEY_FILE is required when POHW_IDENA_ANCHOR_POLICY is set." >&2
      exit 1
    fi
    args+=(
      --idena-anchor-policy "$IDENA_ANCHOR_POLICY"
      --idena-rpc-url "${IDENA_RPC_URL:-http://127.0.0.1:9009}"
      --idena-api-key-file "$IDENA_API_KEY_FILE"
    )
    if [[ "${POHW_IDENA_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
      args+=(--allow-remote-idena-rpc)
    fi
  fi
elif [[ -n "$IDENA_ANCHOR_POLICY" ]]; then
  echo "POHW_IDENA_ANCHOR_POLICY requires POHW_ADMIT_PEER_WORK_TEMPLATES=true." >&2
  exit 1
fi

if [[ -n "${POHW_PEER_ADDRS:-}" ]]; then
  read -r -a peers <<< "${POHW_PEER_ADDRS//,/ }"
  for peer in "${peers[@]}"; do
    if [[ -n "$peer" ]]; then
      args+=(--peer-addr "$peer")
    fi
  done
fi

exec "$BIN" "${args[@]}"
