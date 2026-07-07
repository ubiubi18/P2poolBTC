#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
BIN="${POHW_P2POOL_NODE_BIN:-$WORKDIR/target/release/p2pool-node}"
DATADIR="${POHW_LOCAL_GOSSIP_DATADIR:-/mnt/ssd/pohw-p2pool/local-gossip-peer}"
BIND_ADDR="${POHW_LOCAL_GOSSIP_BIND_ADDR:-127.0.0.1:40416}"
SYNC_INTERVAL="${POHW_LOCAL_GOSSIP_SYNC_INTERVAL_SECONDS:-10}"
MAX_PEERS_PER_ROUND="${POHW_LOCAL_GOSSIP_MAX_PEERS_PER_ROUND:-8}"
MAX_PARALLEL_PEERS="${POHW_LOCAL_GOSSIP_MAX_PARALLEL_PEERS:-2}"
INVENTORY_LIMIT="${POHW_LOCAL_GOSSIP_INVENTORY_LIMIT:-128}"
REBROADCAST_LIMIT="${POHW_LOCAL_GOSSIP_REBROADCAST_LIMIT:-64}"
PEER_LIST_LIMIT="${POHW_LOCAL_GOSSIP_PEER_LIST_LIMIT:-32}"
MAX_CONNECTIONS="${POHW_LOCAL_GOSSIP_MAX_CONNECTIONS:-32}"
MAX_CONNECTIONS_PER_IP="${POHW_LOCAL_GOSSIP_MAX_CONNECTIONS_PER_IP:-8}"

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
)

if [[ -n "${POHW_LOCAL_GOSSIP_ADVERTISE_ADDR:-}" ]]; then
  args+=(--advertise-addr "$POHW_LOCAL_GOSSIP_ADVERTISE_ADDR")
fi

if [[ "${POHW_LOCAL_GOSSIP_ALLOW_PUBLIC_PEERS:-false}" == "true" ]]; then
  args+=(--allow-public-peers)
fi

if [[ -n "${POHW_LOCAL_GOSSIP_PEER_ADDRS:-}" ]]; then
  read -r -a peers <<< "${POHW_LOCAL_GOSSIP_PEER_ADDRS//,/ }"
  for peer in "${peers[@]}"; do
    if [[ -n "$peer" ]]; then
      args+=(--peer-addr "$peer")
    fi
  done
fi

exec "$BIN" "${args[@]}"
