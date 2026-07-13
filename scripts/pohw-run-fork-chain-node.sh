#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/opt/p2pool}"
BIN="${POHW_P2POOL_NODE_BIN:-$WORKDIR/target/release/p2pool-node}"
DATADIR="${POHW_FORK_CHAIN_DATADIR:-/var/lib/pohw-p2pool/fork-chain}"
MANIFEST="${POHW_FORK_ACTIVATION_MANIFEST:-/var/lib/pohw-p2pool/fork-activation.json}"
RPC_BIND_ADDR="${POHW_FORK_RPC_BIND_ADDR:-127.0.0.1:40408}"
P2P_BIND_ADDR="${POHW_FORK_P2P_BIND_ADDR:-}"
SYNC_INTERVAL_SECONDS="${POHW_FORK_SYNC_INTERVAL_SECONDS:-5}"

if [[ "${POHW_EXPERIMENT_NO_VALUE_ACK:-}" != "I_UNDERSTAND_NO_VALUE" ]]; then
  echo "Set POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE before starting the fork chain." >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "Fork-chain binary is not executable: $BIN" >&2
  exit 1
fi

if [[ ! -f "$MANIFEST" || -L "$MANIFEST" ]]; then
  echo "Fork activation manifest is missing or symlinked: $MANIFEST" >&2
  exit 1
fi

args=(
  run-fork-chain-node
  --datadir "$DATADIR"
  --activation-manifest "$MANIFEST"
  --rpc-bind-addr "$RPC_BIND_ADDR"
  --sync-interval-seconds "$SYNC_INTERVAL_SECONDS"
)

if [[ -n "$P2P_BIND_ADDR" ]]; then
  args+=(--p2p-bind-addr "$P2P_BIND_ADDR")
fi

if [[ "${POHW_FORK_ALLOW_NON_LOOPBACK_P2P:-false}" == "true" ]]; then
  args+=(--allow-non-loopback-fork-p2p)
fi

if [[ -n "${POHW_FORK_PEER_ADDRS:-}" ]]; then
  read -r -a peers <<< "${POHW_FORK_PEER_ADDRS//,/ }"
  for peer in "${peers[@]}"; do
    if [[ -n "$peer" ]]; then
      args+=(--peer-addr "$peer")
    fi
  done
fi

exec "$BIN" "${args[@]}"
