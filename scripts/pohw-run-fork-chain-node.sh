#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/opt/p2pool}"
BIN="${POHW_P2POOL_NODE_BIN:-$WORKDIR/target/release/p2pool-node}"
DATADIR="${POHW_FORK_CHAIN_DATADIR:-/var/lib/pohw-p2pool/fork-chain}"
MANIFEST="${POHW_FORK_ACTIVATION_MANIFEST:-/var/lib/pohw-p2pool/fork-activation.json}"
RPC_BIND_ADDR="${POHW_FORK_RPC_BIND_ADDR:-127.0.0.1:40408}"
P2P_BIND_ADDR="${POHW_FORK_P2P_BIND_ADDR:-}"
SYNC_INTERVAL_SECONDS="${POHW_FORK_SYNC_INTERVAL_SECONDS:-5}"
NETWORK_MODE="${POHW_EXPERIMENT_NETWORK_MODE:-join-existing}"
BOOTSTRAP_FIRST_SEED="${POHW_FORK_BOOTSTRAP_FIRST_SEED:-false}"
EXPERIMENT_0_ACTIVATION_ID="0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e"

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

case "$BOOTSTRAP_FIRST_SEED" in
  true|false)
    ;;
  *)
    echo "POHW_FORK_BOOTSTRAP_FIRST_SEED must be true or false." >&2
    exit 1
    ;;
esac

case "$NETWORK_MODE" in
  join-existing)
    python3 - "$MANIFEST" "$EXPERIMENT_0_ACTIVATION_ID" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
if path.stat().st_size > 64 * 1024:
    raise SystemExit(f"fork activation manifest is too large: {path}")
with path.open(encoding="utf-8") as handle:
    actual = json.load(handle).get("activation_id")
if actual != expected:
    raise SystemExit(
        "refusing noncanonical activation manifest in join-existing mode: "
        f"expected {expected}, got {actual!r}"
    )
PY
    if [[ "$BOOTSTRAP_FIRST_SEED" == "true" ]]; then
      if [[ -n "${POHW_FORK_PEER_ADDRS:-}" ]]; then
        echo "The first-seed exception must be removed once fork peers are configured." >&2
        exit 1
      fi
    elif [[ -z "${POHW_FORK_PEER_ADDRS:-}" ]]; then
      echo "Joining Experiment 0 requires at least one POHW_FORK_PEER_ADDRS entry." >&2
      echo "Only the designated coordinator may set POHW_FORK_BOOTSTRAP_FIRST_SEED=true." >&2
      exit 1
    fi
    ;;
  create-separate)
    if [[ "$BOOTSTRAP_FIRST_SEED" == "true" ]]; then
      echo "POHW_FORK_BOOTSTRAP_FIRST_SEED applies only to the canonical Experiment 0 seed." >&2
      exit 1
    fi
    ;;
  *)
    echo "Invalid POHW_EXPERIMENT_NETWORK_MODE: $NETWORK_MODE" >&2
    exit 1
    ;;
esac

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
