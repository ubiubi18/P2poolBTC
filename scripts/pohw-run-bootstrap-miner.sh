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
REPLAY_SIGHASH_PARENT_HEIGHT=958175
REPLAY_SIGHASH_PARENT_HASH=09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6

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

BITCOIN_CLI_ARGS=(
  -noconf \
  -chain=pohw \
  -rpcconnect=127.0.0.1 \
  -rpcport="$BITCOIN_RPC_PORT" \
  -rpccookiefile="$BITCOIN_COOKIE_FILE"
)
blockchain_info="$("$BITCOIN_CLI" "${BITCOIN_CLI_ARGS[@]}" getblockchaininfo)"

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
for field in ("blocks", "headers"):
    field_value = value.get(field)
    if type(field_value) is not int or not 0 <= field_value <= (1 << 31) - 1:
        raise SystemExit(f"Bitcoin Core returned invalid {field}")
if value["blocks"] != value["headers"]:
    raise SystemExit("Bitcoin Core is not at its reported header tip")
profile = value.get("pohw_experiment")
if not isinstance(profile, dict):
    raise SystemExit("Bitcoin Core omitted the Experiment 1 profile")
expected = {
    "fork_height": 958016,
    "fork_hash": "00000000000000000001d0f198da4adf33b597782a36c766685b2f217110cfc8",
    "first_fork_hash": "64d2122b44c111f2f593869ce404117d34c6c830f4390eb70245c11dcc503d01",
    "inherited_utxo_spending": True,
    "replay_protection": "inherited-input-requires-fork-marker-and-signature-domain-v3",
    "replay_marker_activation_height": 958018,
    "replay_sighash_activation_height": 958176,
    "replay_sighash_parent_hash": "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6",
    "replay_sighash_version_bit": 1073741824,
    "replay_sighash_domain": "pohw-experiment-1-full-consensus/replay-sighash-v3",
    "bootstrap_handoff_hashrate_hps": 1000000000000000,
}
for field, expected_value in expected.items():
    if profile.get(field) != expected_value or type(profile.get(field)) is not type(expected_value):
        raise SystemExit(f"Bitcoin Core reports wrong or malformed Experiment 1 field: {field}")
handoff = profile.get("handoff_active")
if not isinstance(handoff, bool):
    raise SystemExit("Bitcoin Core omitted the bootstrap handoff state")
if value["initialblockdownload"]:
    print("syncing")
elif value["blocks"] < 958175:
    print("checkpoint")
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
  checkpoint)
    echo "Experiment 1 Core has not reached the pinned revision-3 checkpoint; bounded mining skipped"
    exit 0
    ;;
  handoff)
    echo "Experiment 1 bootstrap handoff is active; bounded miner is disabled"
    exit 0
    ;;
  bootstrap) ;;
  *) echo "Unexpected bootstrap-miner decision" >&2; exit 1 ;;
esac

checkpoint_hash="$("$BITCOIN_CLI" "${BITCOIN_CLI_ARGS[@]}" \
  getblockhash "$REPLAY_SIGHASH_PARENT_HEIGHT")"
if [[ "$checkpoint_hash" != "$REPLAY_SIGHASH_PARENT_HASH" ]]; then
  echo "Experiment 1 Core reports the wrong revision-3 checkpoint hash" >&2
  exit 1
fi

export PYTHONDONTWRITEBYTECODE=1
exec "$PYTHON_BIN" -I "$SMOKE_MINER" \
  --host "$STRATUM_HOST" \
  --port "$STRATUM_PORT" \
  --worker experiment-1-bootstrap \
  --max-hashes "$MAX_HASHES" \
  --timeout-seconds "$TIMEOUT_SECONDS" \
  --allow-no-solution
