#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
BIN="${POHW_P2POOL_NODE_BIN:-$WORKDIR/target/release/p2pool-node}"
DATADIR="${POHW_DATADIR:-/mnt/ssd/pohw-p2pool}"
BIND_ADDR="${POHW_STRATUM_BIND_ADDR:-127.0.0.1:3333}"
JOB_FILE="${POHW_STRATUM_JOB_FILE:-$DATADIR/mining-job.json}"
BLOCK_CANDIDATE_DIR="${POHW_STRATUM_BLOCK_CANDIDATE_DIR:-$DATADIR/block-candidates}"
PAYOUT_CANDIDATE_DIR="${POHW_PAYOUT_CANDIDATE_DIR:-$DATADIR/payout-candidates}"
SNAPSHOT_DIR="${POHW_SNAPSHOT_DIR:-$DATADIR/snapshots}"
SHARE_TARGET="${POHW_STRATUM_SHARE_TARGET:-}"
STRATUM_DIFFICULTY="${POHW_STRATUM_DIFFICULTY:-1}"
EXTRANONCE2_SIZE="${POHW_STRATUM_EXTRANONCE2_SIZE:-4}"
MAX_LINE_BYTES="${POHW_STRATUM_MAX_LINE_BYTES:-16384}"
IDLE_TIMEOUT_SECONDS="${POHW_STRATUM_IDLE_TIMEOUT_SECONDS:-900}"
JOB_REFRESH_INTERVAL_SECONDS="${POHW_STRATUM_JOB_REFRESH_INTERVAL_SECONDS:-5}"
DYNAMIC_MIN_SNAPSHOT_VOTERS="${POHW_STRATUM_DYNAMIC_MIN_SNAPSHOT_VOTERS:-3}"
BITCOIN_RPC_URL="${POHW_BITCOIN_RPC_URL:-http://127.0.0.1:8332}"
BITCOIN_EXPECTED_CHAIN="${POHW_BITCOIN_EXPECTED_CHAIN:-}"
FORK_CHAIN_RPC_ADDR="${POHW_STRATUM_FORK_CHAIN_RPC_ADDR:-}"
FORK_CHAIN_ACTIVATION_MANIFEST="${POHW_FORK_ACTIVATION_MANIFEST:-}"
GOSSIP_NETWORK_ID="${POHW_GOSSIP_NETWORK_ID:-}"
IDENA_ANCHOR_POLICY="${POHW_IDENA_ANCHOR_POLICY:-}"
REQUIRE_IDENA_ANCHOR_POLICY="${POHW_REQUIRE_IDENA_ANCHOR_POLICY:-false}"
EXPERIMENT_1_NETWORK_ID="9bf5931b2947e42fcfdf019184368c1da103b50caaa1edc28159efd2057a91e8"
NORMALIZED_GOSSIP_NETWORK_ID="$(printf '%s' "$GOSSIP_NETWORK_ID" | tr '[:upper:]' '[:lower:]')"
FORK_CHAIN_MODE=false

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
  echo "POHW_REQUIRE_IDENA_ANCHOR_POLICY=true is mandatory for Experiment 1 mining." >&2
  exit 1
fi
if [[ "$REQUIRE_IDENA_ANCHOR_POLICY" == "true" && -z "$IDENA_ANCHOR_POLICY" ]]; then
  echo "POHW_IDENA_ANCHOR_POLICY is required by this launch profile." >&2
  exit 1
fi

if [[ -n "$FORK_CHAIN_RPC_ADDR" || -n "$FORK_CHAIN_ACTIVATION_MANIFEST" ]]; then
  if [[ -z "$FORK_CHAIN_RPC_ADDR" || -z "$FORK_CHAIN_ACTIVATION_MANIFEST" ]]; then
    echo "POHW_STRATUM_FORK_CHAIN_RPC_ADDR and POHW_FORK_ACTIVATION_MANIFEST must be set together." >&2
    exit 1
  fi
  FORK_CHAIN_MODE=true
fi

if ! [[ "$DYNAMIC_MIN_SNAPSHOT_VOTERS" =~ ^[1-9][0-9]{0,2}$ ]] \
  || (( DYNAMIC_MIN_SNAPSHOT_VOTERS > 512 )); then
  echo "POHW_STRATUM_DYNAMIC_MIN_SNAPSHOT_VOTERS must be an integer between 1 and 512." >&2
  exit 1
fi

case "${POHW_MAINNET_HANDOFF_ACTIVE:-false}" in
  true)
    if [[ "$FORK_CHAIN_MODE" == "true" \
      || "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" != "false" \
      || "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" != "false" \
      || "${POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE:-false}" != "true" \
      || "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" != "true" \
      || "${POHW_STRATUM_ALLOW_MAINNET_SUBMIT:-false}" != "true" ]]; then
      echo "Mainnet handoff mode requires dynamic payout-aware Bitcoin RPC jobs and explicit block submission." >&2
      exit 1
    fi
    ;;
  false)
    ;;
  *)
    echo "POHW_MAINNET_HANDOFF_ACTIVE must be true or false." >&2
    exit 1
    ;;
esac

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

rpc_builder_count=0
for enabled in \
  "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" \
  "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" \
  "${POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE:-false}"; do
  if [[ "$enabled" == "true" ]]; then
    rpc_builder_count=$((rpc_builder_count + 1))
  elif [[ "$enabled" != "false" ]]; then
    echo "Bitcoin RPC job mode flags must be true or false." >&2
    exit 1
  fi
done
if (( rpc_builder_count > 1 )); then
  echo "Enable only one Bitcoin RPC job mode." >&2
  exit 1
fi

if [[ "$FORK_CHAIN_MODE" == "true" \
  && ( "${POHW_STRATUM_BUILD_JOB_FROM_RPC:-false}" == "true" \
    || "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ) ]]; then
  echo "Fork-chain template mode cannot be combined with Bitcoin RPC job builders." >&2
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

if [[ "$FORK_CHAIN_MODE" != "true" && ( "$rpc_builder_count" -gt 0 || "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" == "true" ) ]]; then
  if [[ "$BITCOIN_EXPECTED_CHAIN" != "pohw" && "$BITCOIN_EXPECTED_CHAIN" != "main" ]]; then
    echo "POHW_BITCOIN_EXPECTED_CHAIN must be pohw or main for Bitcoin RPC mining." >&2
    exit 1
  fi
  configure_rpc_environment
fi

if [[ "$FORK_CHAIN_MODE" != "true" && "$BITCOIN_EXPECTED_CHAIN" == "pohw" \
  && ( "$rpc_builder_count" -gt 0 || "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" == "true" ) \
  && -z "$GOSSIP_NETWORK_ID" ]]; then
  echo "POHW_GOSSIP_NETWORK_ID is required for pohw-chain mining." >&2
  exit 1
fi

initialize_gossip_network() {
  if [[ -z "$GOSSIP_NETWORK_ID" ]]; then
    return 0
  fi
  if ! [[ "$GOSSIP_NETWORK_ID" =~ ^([0-9a-fA-F]{64})$ ]]; then
    echo "POHW_GOSSIP_NETWORK_ID must be 32 bytes encoded as 64 hex characters." >&2
    exit 1
  fi
  "$BIN" initialize-gossip-network \
    --datadir "$DATADIR" \
    --network-id "$GOSSIP_NETWORK_ID" >/dev/null
}

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

derive_fork_share_policy() {
  local policy
  if ! policy="$(python3 - "$FORK_CHAIN_ACTIVATION_MANIFEST" <<'PY'
import json
import os
import stat
import sys

path = sys.argv[1]
metadata = os.lstat(path)
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("fork activation manifest must be a regular non-symlink file")
if metadata.st_size > 1024 * 1024:
    raise SystemExit("fork activation manifest exceeds 1 MiB")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
with os.fdopen(fd, "r", encoding="utf-8") as stream:
    manifest = json.load(stream)
bits = manifest.get("config", {}).get("post_fork_pow_limit_bits")
if isinstance(bits, bool) or not isinstance(bits, int) or not 0 <= bits <= 0xFFFFFFFF:
    raise SystemExit("fork activation manifest has invalid post_fork_pow_limit_bits")
exponent = bits >> 24
mantissa = bits & 0x007FFFFF
if bits & 0x00800000 or mantissa == 0:
    raise SystemExit("fork activation manifest has a negative or zero PoW limit")
if exponent <= 3:
    target = mantissa >> (8 * (3 - exponent))
else:
    target = mantissa << (8 * (exponent - 3))
if target <= 0 or target >= 1 << 256:
    raise SystemExit("fork activation manifest PoW limit is outside the uint256 range")
diff_one_target = 0xFFFF << (8 * (0x1D - 3))
print(target.to_bytes(32, "big").hex())
print(format(diff_one_target / target, ".17g"))
PY
  )"; then
    echo "Failed to derive the fork Stratum share policy from the activation manifest." >&2
    exit 1
  fi
  if [[ "$policy" != *$'\n'* ]]; then
    echo "Failed to derive the fork Stratum share policy from the activation manifest." >&2
    exit 1
  fi
  SHARE_TARGET="${policy%%$'\n'*}"
  STRATUM_DIFFICULTY="${policy#*$'\n'}"
  if [[ ! "$SHARE_TARGET" =~ ^[0-9a-f]{64}$ \
    || ! "$STRATUM_DIFFICULTY" =~ ^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$ ]]; then
    echo "Derived fork Stratum share policy has an invalid format." >&2
    exit 1
  fi
}

if [[ "$FORK_CHAIN_MODE" != "true" ]] && (( rpc_builder_count > 0 )); then
  check_health_ready_for_rpc_job
fi

if [[ "$FORK_CHAIN_MODE" == "true" && -z "$SHARE_TARGET" ]]; then
  derive_fork_share_policy
fi

if [[ "${POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE:-false}" == "true" ]]; then
  if [[ -z "${POHW_STRATUM_POHW_COMMITMENT_FILE:-}" ]]; then
    echo "POHW_STRATUM_POHW_COMMITMENT_FILE is required for dynamic PoHW payouts." >&2
    exit 1
  fi
elif [[ "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ]]; then
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
  build_args+=(--rpc-url "$BITCOIN_RPC_URL")
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
  build_args+=(--rpc-url "$BITCOIN_RPC_URL")
  if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
    build_args+=(--rpc-cookie-file "$POHW_BITCOIN_RPC_COOKIE_FILE")
  fi
  if [[ "${POHW_BITCOIN_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
    build_args+=(--allow-remote-rpc)
  fi
  "$BIN" "${build_args[@]}"
fi

if [[ "$FORK_CHAIN_MODE" != "true" && -f "$JOB_FILE" ]] && grep -Eq '"job_id"[[:space:]]*:[[:space:]]*"experiment-0-example"' "$JOB_FILE"; then
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
  --idena-snapshot-id "$POHW_IDENA_SNAPSHOT_ID"
  --idena-snapshot-proof-root "$POHW_IDENA_SNAPSHOT_PROOF_ROOT"
  --mining-secret-key-file "$MINING_SECRET_KEY_FILE"
  --node-secret-key-file "$NODE_SECRET_KEY_FILE"
  --stratum-difficulty "$STRATUM_DIFFICULTY"
  --extranonce2-size "$EXTRANONCE2_SIZE"
  --max-stratum-line-bytes "$MAX_LINE_BYTES"
  --stratum-idle-timeout-seconds "$IDLE_TIMEOUT_SECONDS"
)

if [[ "$FORK_CHAIN_MODE" == "true" ]]; then
  args+=(
    --fork-chain-rpc-addr "$FORK_CHAIN_RPC_ADDR"
    --fork-chain-activation-manifest "$FORK_CHAIN_ACTIVATION_MANIFEST"
    --job-refresh-interval-seconds "$JOB_REFRESH_INTERVAL_SECONDS"
  )
elif [[ "${POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE:-false}" != "true" ]]; then
  args+=(--job-file "$JOB_FILE")
fi

if [[ -n "$SHARE_TARGET" ]]; then
  args+=(--share-target "$SHARE_TARGET")
fi

if [[ -n "${POHW_STRATUM_PASSWORD_FILE:-}" ]]; then
  args+=(--stratum-password-file "$POHW_STRATUM_PASSWORD_FILE")
fi

if [[ -n "$BLOCK_CANDIDATE_DIR" ]]; then
  args+=(--block-candidate-dir "$BLOCK_CANDIDATE_DIR")
fi

if [[ "${POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE:-false}" == "true" ]]; then
  args+=(--payout-candidate-dir "$PAYOUT_CANDIDATE_DIR")
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

if [[ "$FORK_CHAIN_MODE" == "true" ]]; then
  if [[ "${POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE:-false}" == "true" ]]; then
    args+=(
      --derive-pohw-payouts-from-state
      --derive-pohw-min-snapshot-voters "$DYNAMIC_MIN_SNAPSHOT_VOTERS"
      --snapshot-dir "$SNAPSHOT_DIR"
      --pohw-commitment-file "$POHW_STRATUM_POHW_COMMITMENT_FILE"
    )
  elif [[ -n "${POHW_STRATUM_PAYOUT_SCHEDULE_FILE:-}" || -n "${POHW_STRATUM_POHW_COMMITMENT_FILE:-}" ]]; then
    if [[ -z "${POHW_STRATUM_PAYOUT_SCHEDULE_FILE:-}" || -z "${POHW_STRATUM_POHW_COMMITMENT_FILE:-}" ]]; then
      echo "POHW_STRATUM_PAYOUT_SCHEDULE_FILE and POHW_STRATUM_POHW_COMMITMENT_FILE must be set together." >&2
      exit 1
    fi
    args+=(
      --payout-schedule-file "$POHW_STRATUM_PAYOUT_SCHEDULE_FILE"
      --pohw-commitment-file "$POHW_STRATUM_POHW_COMMITMENT_FILE"
    )
  fi
elif (( rpc_builder_count > 0 )); then
  args+=(
    --refresh-job-from-rpc
    --job-refresh-interval-seconds "$JOB_REFRESH_INTERVAL_SECONDS"
  )
  if [[ "${POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE:-false}" == "true" ]]; then
    args+=(
      --derive-pohw-payouts-from-state
      --derive-pohw-min-snapshot-voters "$DYNAMIC_MIN_SNAPSHOT_VOTERS"
      --snapshot-dir "$SNAPSHOT_DIR"
      --pohw-commitment-file "$POHW_STRATUM_POHW_COMMITMENT_FILE"
    )
  elif [[ "${POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC:-false}" == "true" ]]; then
    args+=(
      --payout-schedule-file "$POHW_STRATUM_PAYOUT_SCHEDULE_FILE"
      --pohw-commitment-file "$POHW_STRATUM_POHW_COMMITMENT_FILE"
    )
  fi
fi

if [[ "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" == "true" ]]; then
  args+=(--auto-submit-blocks)
fi

if [[ "$FORK_CHAIN_MODE" != "true" && "${POHW_STRATUM_ALLOW_MAINNET_SUBMIT:-false}" == "true" ]]; then
  args+=(--allow-mainnet-submit)
fi

if [[ "$FORK_CHAIN_MODE" != "true" && ( "$rpc_builder_count" -gt 0 || "${POHW_STRATUM_AUTO_SUBMIT_BLOCKS:-false}" == "true" ) ]]; then
  args+=(--rpc-url "$BITCOIN_RPC_URL" --expected-rpc-chain "$BITCOIN_EXPECTED_CHAIN")
  if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-}" ]]; then
    args+=(--rpc-cookie-file "$POHW_BITCOIN_RPC_COOKIE_FILE")
  fi
  if [[ "${POHW_BITCOIN_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
    args+=(--allow-remote-rpc)
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

if [[ -n "${POHW_PEER_ADDRS:-}" ]]; then
  read -r -a peers <<< "${POHW_PEER_ADDRS//,/ }"
  for peer in "${peers[@]}"; do
    if [[ -n "$peer" ]]; then
      args+=(--peer-addr "$peer")
    fi
  done
fi

initialize_gossip_network
exec "$BIN" "${args[@]}"
