#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
BIN="${POHW_P2POOL_NODE_BIN:-$WORKDIR/target/release/p2pool-node}"
DATADIR="${POHW_DATADIR:-/mnt/ssd/pohw-p2pool}"
BIND_ADDR="${POHW_STRATUM_BIND_ADDR:-127.0.0.1:3333}"
JOB_FILE="${POHW_STRATUM_JOB_FILE:-$DATADIR/mining-job.json}"
BLOCK_CANDIDATE_DIR="${POHW_STRATUM_BLOCK_CANDIDATE_DIR:-$DATADIR/block-candidates}"
SHARE_TARGET="${POHW_STRATUM_SHARE_TARGET:-}"
STRATUM_DIFFICULTY="${POHW_STRATUM_DIFFICULTY:-1}"
EXTRANONCE2_SIZE="${POHW_STRATUM_EXTRANONCE2_SIZE:-4}"
MAX_LINE_BYTES="${POHW_STRATUM_MAX_LINE_BYTES:-16384}"
IDLE_TIMEOUT_SECONDS="${POHW_STRATUM_IDLE_TIMEOUT_SECONDS:-900}"
JOB_REFRESH_INTERVAL_SECONDS="${POHW_STRATUM_JOB_REFRESH_INTERVAL_SECONDS:-5}"

if [[ -z "${POHW_MINER_ID:-}" ]]; then
  echo "POHW_MINER_ID is required before starting the mining adapter." >&2
  exit 1
fi

KEY_DIR="$DATADIR/keys/$POHW_MINER_ID"
MINING_SECRET_KEY_FILE="${POHW_MINING_SECRET_KEY_FILE:-$KEY_DIR/mining.key}"
NODE_SECRET_KEY_FILE="${POHW_NODE_SECRET_KEY_FILE:-$KEY_DIR/gossip-node.key}"

if [[ -z "${POHW_IDENA_SNAPSHOT_ID:-}" ]]; then
  echo "POHW_IDENA_SNAPSHOT_ID is required; publish or select a verified snapshot first." >&2
  exit 1
fi

if [[ -z "${POHW_IDENA_SNAPSHOT_PROOF_ROOT:-}" ]]; then
  echo "POHW_IDENA_SNAPSHOT_PROOF_ROOT is required; publish or select a verified snapshot first." >&2
  exit 1
fi

if [[ "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" == "true" && "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ]]; then
  echo "Use either POHW_STRATUM_BUILD_JOB_FROM_RPC or POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC, not both." >&2
  exit 1
fi

configure_rpc_environment() {
  unset BITCOIN_RPC_USER BITCOIN_RPC_PASSWORD BITCOIN_RPC_COOKIE_FILE
  if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
    export BITCOIN_RPC_COOKIE_FILE="$POHW_BITCOIN_RPC_COOKIE_FILE"
    return
  fi
  if [[ -n "${POHW_BITCOIN_RPC_USER:-}" || -n "${POHW_BITCOIN_RPC_PASSWORD:-}" ]]; then
    if [[ -z "${POHW_BITCOIN_RPC_USER:-}" || -z "${POHW_BITCOIN_RPC_PASSWORD:-}" ]]; then
      echo "POHW_BITCOIN_RPC_USER and POHW_BITCOIN_RPC_PASSWORD must be set together." >&2
      exit 1
    fi
    export BITCOIN_RPC_USER="$POHW_BITCOIN_RPC_USER"
    export BITCOIN_RPC_PASSWORD="$POHW_BITCOIN_RPC_PASSWORD"
  fi
}

if [[ "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" == "true" || "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" || "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" == "true" ]]; then
  configure_rpc_environment
fi

check_health_ready_for_rpc_job() {
  local health_file="${POHW_HEALTH_STATUS_FILE:-$DATADIR/health/status.json}"
  local health_script="${POHW_HEALTH_SCRIPT:-$WORKDIR/scripts/pohw-health-status.py}"
  local max_age_seconds="${POHW_HEALTH_MAX_AGE_SECONDS:-180}"
  if [[ "${POHW_STRATUM_IGNORE_HEALTH:-false}" == "true" || ! -f "$health_file" ]]; then
    return 0
  fi
  if [[ ! -r "$health_script" ]]; then
    echo "PoHW health script is not readable: $health_script" >&2
    exit 1
  fi
  python3 "$health_script" \
    --check-mining-ready \
    --status-file "$health_file" \
    --max-age-seconds "$max_age_seconds"
}

if [[ "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" == "true" || "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ]]; then
  check_health_ready_for_rpc_job
fi

if [[ "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ]]; then
  if [[ -z "${POHW_STRATUM_PAYOUT_SCHEDULE_FILE:-}" ]]; then
    echo "POHW_STRATUM_PAYOUT_SCHEDULE_FILE is required when building a PoHW Stratum job from RPC." >&2
    exit 1
  fi
  if [[ -z "${POHW_STRATUM_POHW_COMMITMENT_FILE:-}" ]]; then
    echo "POHW_STRATUM_POHW_COMMITMENT_FILE is required when building a PoHW Stratum job from RPC." >&2
    exit 1
  fi
  build_args=(
    build-pohw-stratum-job-rpc
    --job-out "$JOB_FILE"
    --replace
    --payout-schedule-file "$POHW_STRATUM_PAYOUT_SCHEDULE_FILE"
    --pohw-commitment-file "$POHW_STRATUM_POHW_COMMITMENT_FILE"
    --extranonce2-size "$EXTRANONCE2_SIZE"
  )
  if [[ -n "${POHW_BITCOIN_RPC_URL:-}" ]]; then
    build_args+=(--rpc-url "$POHW_BITCOIN_RPC_URL")
  fi
  if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
    build_args+=(--rpc-cookie-file "$POHW_BITCOIN_RPC_COOKIE_FILE")
  fi
  if [[ "${POHW_BITCOIN_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
    build_args+=(--allow-remote-rpc)
  fi
  "$BIN" "${build_args[@]}"
elif [[ "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" == "true" ]]; then
  build_args=(
    build-stratum-job-rpc
    --job-out "$JOB_FILE"
    --replace
    --extranonce2-size "$EXTRANONCE2_SIZE"
  )
  if [[ -n "${POHW_BITCOIN_RPC_URL:-}" ]]; then
    build_args+=(--rpc-url "$POHW_BITCOIN_RPC_URL")
  fi
  if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
    build_args+=(--rpc-cookie-file "$POHW_BITCOIN_RPC_COOKIE_FILE")
  fi
  if [[ "${POHW_BITCOIN_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
    build_args+=(--allow-remote-rpc)
  fi
  "$BIN" "${build_args[@]}"
fi

if [[ -f "$JOB_FILE" ]] && grep -Eq '"job_id"[[:space:]]*:[[:space:]]*"experiment-0-example"' "$JOB_FILE"; then
  if [[ "${POHW_ALLOW_EXAMPLE_MINING_JOB:-false}" != "true" ]]; then
    echo "Refusing to start Stratum with the packaged example mining job." >&2
    echo "Provide a locally verified fork/testnet job file, or set POHW_ALLOW_EXAMPLE_MINING_JOB=true for an explicit local dry-run only." >&2
    exit 1
  fi
fi

args=(
  run-mining-adapter
  --datadir "$DATADIR"
  --bind-addr "$BIND_ADDR"
  --miner-id "$POHW_MINER_ID"
  --job-file "$JOB_FILE"
  --idena-snapshot-id "$POHW_IDENA_SNAPSHOT_ID"
  --idena-snapshot-proof-root "$POHW_IDENA_SNAPSHOT_PROOF_ROOT"
  --mining-secret-key-file "$MINING_SECRET_KEY_FILE"
  --node-secret-key-file "$NODE_SECRET_KEY_FILE"
  --stratum-difficulty "$STRATUM_DIFFICULTY"
  --extranonce2-size "$EXTRANONCE2_SIZE"
  --max-stratum-line-bytes "$MAX_LINE_BYTES"
  --stratum-idle-timeout-seconds "$IDLE_TIMEOUT_SECONDS"
)

if [[ -n "$SHARE_TARGET" ]]; then
  args+=(--share-target "$SHARE_TARGET")
fi

if [[ -n "${POHW_STRATUM_PASSWORD_FILE:-}" ]]; then
  args+=(--stratum-password-file "$POHW_STRATUM_PASSWORD_FILE")
fi

if [[ -n "$BLOCK_CANDIDATE_DIR" ]]; then
  args+=(--block-candidate-dir "$BLOCK_CANDIDATE_DIR")
fi

if [[ "${POHW_STRATUM_ALLOW_NON_LOOPBACK:-false}" == "true" ]]; then
  args+=(--allow-non-loopback-stratum)
fi

if [[ "${POHW_ALLOW_EXAMPLE_MINING_JOB:-false}" == "true" ]]; then
  args+=(--allow-example-mining-job)
fi

if [[ "${POHW_STRATUM_APPEND:-true}" != "true" ]]; then
  args+=(--no-append)
fi

if [[ "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" == "true" || "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ]]; then
  args+=(
    --refresh-job-from-rpc
    --job-refresh-interval-seconds "$JOB_REFRESH_INTERVAL_SECONDS"
  )
  if [[ "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ]]; then
    args+=(
      --payout-schedule-file "$POHW_STRATUM_PAYOUT_SCHEDULE_FILE"
      --pohw-commitment-file "$POHW_STRATUM_POHW_COMMITMENT_FILE"
    )
  fi
fi

if [[ "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" == "true" ]]; then
  args+=(--auto-submit-blocks)
fi

if [[ "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" == "true" || "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" || "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" == "true" ]]; then
  if [[ -n "${POHW_BITCOIN_RPC_URL:-}" ]]; then
    args+=(--rpc-url "$POHW_BITCOIN_RPC_URL")
  fi
  if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
    args+=(--rpc-cookie-file "$POHW_BITCOIN_RPC_COOKIE_FILE")
  fi
  if [[ "${POHW_BITCOIN_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
    args+=(--allow-remote-rpc)
  fi
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
