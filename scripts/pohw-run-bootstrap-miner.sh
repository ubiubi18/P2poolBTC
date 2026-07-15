#!/usr/bin/env bash
set -euo pipefail

# This runner is intentionally unsuitable for a Raspberry Pi. It performs one
# bounded loopback-only attempt and lets systemd schedule the next attempt.
if [[ "${POHW_EXPERIMENT_NO_VALUE_ACK:-}" != "I_UNDERSTAND_NO_VALUE" ]]; then
  echo "POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE is required" >&2
  exit 1
fi
if [[ "${POHW_BOOTSTRAP_MINER_ALLOW_HOST:-}" != "I_UNDERSTAND_HETZNER_ONLY" ]]; then
  echo "POHW_BOOTSTRAP_MINER_ALLOW_HOST=I_UNDERSTAND_HETZNER_ONLY is required" >&2
  exit 1
fi
if [[ -r /proc/device-tree/model ]] && grep -aFqi "Raspberry Pi" /proc/device-tree/model; then
  echo "The bounded bootstrap miner refuses to run on Raspberry Pi hardware" >&2
  exit 1
fi

PYTHON_BIN="${POHW_BOOTSTRAP_MINER_PYTHON:-python3}"
BITCOIN_CLI="${POHW_BOOTSTRAP_MINER_BITCOIN_CLI:-/usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli}"
BITCOIN_COOKIE_FILE="${POHW_BOOTSTRAP_MINER_BITCOIN_COOKIE_FILE:-/run/bitcoin-pohw-rpc/.cookie}"
BITCOIN_RPC_PORT="${POHW_BOOTSTRAP_MINER_BITCOIN_RPC_PORT:-40414}"
SMOKE_MINER="${POHW_BOOTSTRAP_MINER_SCRIPT:-/opt/p2pool/scripts/pohw-stratum-smoke-mine.py}"
STRATUM_HOST="${POHW_BOOTSTRAP_MINER_STRATUM_HOST:-127.0.0.1}"
STRATUM_PORT="${POHW_BOOTSTRAP_MINER_STRATUM_PORT:-3333}"
MAX_HASHES="${POHW_BOOTSTRAP_MINER_MAX_HASHES:-100000}"
TIMEOUT_SECONDS="${POHW_BOOTSTRAP_MINER_TIMEOUT_SECONDS:-10}"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
  echo "Configured Python interpreter is unavailable" >&2
  exit 1
}
if [[ -L "$BITCOIN_CLI" || ! -f "$BITCOIN_CLI" || ! -x "$BITCOIN_CLI" ]]; then
  echo "Configured bitcoin-cli must be an executable regular non-symlink file" >&2
  exit 1
fi
if [[ -L "$SMOKE_MINER" || ! -f "$SMOKE_MINER" ]]; then
  echo "Configured smoke miner must be a regular non-symlink file" >&2
  exit 1
fi
if [[ -L "$BITCOIN_COOKIE_FILE" || ! -f "$BITCOIN_COOKIE_FILE" || ! -r "$BITCOIN_COOKIE_FILE" ]]; then
  echo "Configured Bitcoin RPC cookie must be a readable regular non-symlink file" >&2
  exit 1
fi
if ! [[ "$BITCOIN_RPC_PORT" =~ ^[0-9]{1,5}$ ]] || (( BITCOIN_RPC_PORT < 1 || BITCOIN_RPC_PORT > 65535 )); then
  echo "POHW_BOOTSTRAP_MINER_BITCOIN_RPC_PORT must be a valid TCP port" >&2
  exit 1
fi
case "$STRATUM_HOST" in
  127.0.0.1|::1) ;;
  *) echo "Bootstrap mining is restricted to loopback Stratum" >&2; exit 1 ;;
esac
if ! [[ "$STRATUM_PORT" =~ ^[0-9]{1,5}$ ]] || (( STRATUM_PORT < 1 || STRATUM_PORT > 65535 )); then
  echo "POHW_BOOTSTRAP_MINER_STRATUM_PORT must be a valid TCP port" >&2
  exit 1
fi
if ! [[ "$MAX_HASHES" =~ ^[1-9][0-9]{0,6}$ ]] || (( MAX_HASHES > 1000000 )); then
  echo "POHW_BOOTSTRAP_MINER_MAX_HASHES must be between 1 and 1000000" >&2
  exit 1
fi
if ! [[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]?$ ]] || (( TIMEOUT_SECONDS > 30 )); then
  echo "POHW_BOOTSTRAP_MINER_TIMEOUT_SECONDS must be between 1 and 30" >&2
  exit 1
fi

blockchain_info="$($BITCOIN_CLI \
  -noconf \
  -chain=pohw \
  -rpcconnect=127.0.0.1 \
  -rpcport="$BITCOIN_RPC_PORT" \
  -rpccookiefile="$BITCOIN_COOKIE_FILE" \
  getblockchaininfo)"

decision="$(printf '%s' "$blockchain_info" | "$PYTHON_BIN" -I -c '
import json, sys
try:
    value = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit("Bitcoin Core returned invalid JSON")
if not isinstance(value, dict) or value.get("chain") != "pohw":
    raise SystemExit("Bitcoin Core is not on the pohw chain")
if not isinstance(value.get("initialblockdownload"), bool):
    raise SystemExit("Bitcoin Core omitted initialblockdownload")
profile = value.get("pohw_experiment")
if not isinstance(profile, dict):
    raise SystemExit("Bitcoin Core omitted the Experiment 1 profile")
if profile.get("replay_protection") != "inherited-input-requires-fork-only-marker-v2":
    raise SystemExit("Bitcoin Core reports the wrong replay-protection rule")
handoff = profile.get("handoff_active")
if not isinstance(handoff, bool):
    raise SystemExit("Bitcoin Core omitted the bootstrap handoff state")
if value["initialblockdownload"]:
    print("syncing")
elif handoff:
    print("handoff")
else:
    print("bootstrap")
')"

case "$decision" in
  syncing)
    echo "Experiment 1 Core is still syncing; bounded mining skipped"
    exit 0
    ;;
  handoff)
    echo "Experiment 1 bootstrap handoff is active; bounded miner is disabled"
    exit 0
    ;;
  bootstrap) ;;
  *) echo "Unexpected bootstrap-miner decision" >&2; exit 1 ;;
esac

export PYTHONDONTWRITEBYTECODE=1
exec "$PYTHON_BIN" -I "$SMOKE_MINER" \
  --host "$STRATUM_HOST" \
  --port "$STRATUM_PORT" \
  --worker experiment-1-bootstrap \
  --max-hashes "$MAX_HASHES" \
  --timeout-seconds "$TIMEOUT_SECONDS" \
  --allow-no-solution
