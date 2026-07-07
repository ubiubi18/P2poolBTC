#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${IDENA_RPC_URL:-http://127.0.0.1:9009}"
API_KEY_FILE="${IDENA_API_KEY_FILE:-/mnt/ssd/idena/idena-data/api.key}"
WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
OUT_DIR="${POHW_SNAPSHOT_DIR:-$WORKDIR/snapshots}"
ALLOW_REMOTE_RPC="${POHW_ALLOW_REMOTE_RPC:-false}"
REWARD_INDEXER_SCRIPT="${IDENA_REWARD_INDEXER_SCRIPT:-$WORKDIR/pohw_idena_rpc/idena_reward_indexer.py}"
EXACT_REWARD_SQL_FILE="${IDENA_EXACT_REWARD_SQL_FILE:-$WORKDIR/scripts/pohw-export-idena-indexer-rewards.sql}"

stat_mode() {
  local path="$1"
  if stat -c %a "$path" 2>/dev/null; then
    return 0
  fi
  stat -f %Lp "$path"
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
      parent_mode="$(stat_mode "$parent")"
      parent_unsafe_bits=$((8#$parent_mode & 022))
      if [[ "$owner" != "0" || "$parent_unsafe_bits" != "0" ]]; then
        echo "Refusing to use symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
}

ensure_local_dir() {
  local dir="$1"
  local label="$2"
  local mode unsafe_bits
  if [[ -L "$dir" ]]; then
    echo "Refusing to use symlinked $label directory: $dir" >&2
    exit 1
  fi
  if [[ -e "$dir" && ! -d "$dir" ]]; then
    echo "$label path is not a directory: $dir" >&2
    exit 1
  fi
  reject_symlink_ancestor "$dir"
  if [[ ! -e "$dir" ]]; then
    (umask 077 && mkdir -p "$dir")
  fi
  if [[ ! -d "$dir" ]]; then
    echo "$label path is not a directory: $dir" >&2
    exit 1
  fi
  mode="$(stat_mode "$dir")"
  unsafe_bits=$((8#$mode & 022))
  if (( unsafe_bits != 0 )); then
    echo "Refusing to use group/world-writable $label directory: $dir" >&2
    exit 1
  fi
}

if ! python3 - "$RPC_URL" "$ALLOW_REMOTE_RPC" <<'PY'
import ipaddress
import sys
from urllib.parse import urlparse

raw_url = sys.argv[1]
if not raw_url or len(raw_url) > 2048 or any(ord(ch) < 32 for ch in raw_url):
    print("Idena RPC URL is empty, too long, or contains control characters", file=sys.stderr)
    sys.exit(1)
url = urlparse(raw_url)
allow_remote = sys.argv[2] in {"1", "true", "TRUE", "yes", "YES"}
if url.scheme not in {"http", "https"}:
    print("Idena RPC URL scheme must be http or https", file=sys.stderr)
    sys.exit(1)
if not url.hostname:
    print("Idena RPC URL must include a host", file=sys.stderr)
    sys.exit(1)
if url.username or url.password:
    print("Idena RPC URL must not include userinfo", file=sys.stderr)
    sys.exit(1)
if url.query or url.fragment:
    print("Idena RPC URL must not include query or fragment data", file=sys.stderr)
    sys.exit(1)
host = url.hostname
if host is not None and host.lower() == "localhost":
    sys.exit(0)
try:
    if host is not None and ipaddress.ip_address(host).is_loopback:
        sys.exit(0)
except ValueError:
    pass
if allow_remote:
    sys.exit(0)
print(f"Idena RPC URL must be loopback unless POHW_ALLOW_REMOTE_RPC=true: {raw_url}", file=sys.stderr)
sys.exit(1)
PY
then
  exit 1
fi

if [[ -n "${POHW_IDENA_INDEXER_BIN:-}" ]]; then
  BIN="$POHW_IDENA_INDEXER_BIN"
elif [[ -x "$WORKDIR/target/release/idena-lite-indexer" ]]; then
  BIN="$WORKDIR/target/release/idena-lite-indexer"
else
  BIN="$WORKDIR/target/debug/idena-lite-indexer"
fi

if [[ ! -x "$BIN" ]]; then
  echo "idena-lite-indexer binary not found or not executable: $BIN" >&2
  exit 1
fi

if [[ -L "$API_KEY_FILE" ]]; then
  echo "Idena API key file must not be a symlink: $API_KEY_FILE" >&2
  exit 1
fi

if [[ ! -f "$API_KEY_FILE" || ! -r "$API_KEY_FILE" ]]; then
  echo "Idena API key file must be a readable regular file: $API_KEY_FILE" >&2
  exit 1
fi

api_key_parent="$(dirname "$API_KEY_FILE")"
reject_symlink_ancestor "$api_key_parent"

if ! python3 - "$API_KEY_FILE" <<'PY'
import os
import stat
import sys

path = os.path.abspath(sys.argv[1])
parent = os.path.dirname(path) or "."
try:
    parent_stat = os.lstat(parent)
except OSError as exc:
    print(f"Idena API key parent directory is not readable: {parent}: {exc}", file=sys.stderr)
    sys.exit(1)
if stat.S_ISLNK(parent_stat.st_mode):
    print(f"Idena API key parent directory must not be a symlink: {parent}", file=sys.stderr)
    sys.exit(1)
if not stat.S_ISDIR(parent_stat.st_mode):
    print(f"Idena API key parent path must be a directory: {parent}", file=sys.stderr)
    sys.exit(1)
if parent_stat.st_mode & 0o022:
    print(f"Idena API key parent directory is group/world writable: {parent}", file=sys.stderr)
    sys.exit(1)
PY
then
  exit 1
fi

if mode="$(stat -c '%a' "$API_KEY_FILE" 2>/dev/null || stat -f '%Lp' "$API_KEY_FILE" 2>/dev/null)"; then
  if (( (8#$mode & 077) != 0 )); then
    echo "Idena API key file is too permissive ($mode); run chmod 600 $API_KEY_FILE" >&2
    exit 1
  fi
else
  echo "Could not inspect Idena API key file permissions: $API_KEY_FILE" >&2
  exit 1
fi

api_key="$(tr -d '\r' < "$API_KEY_FILE")"
if [[ -z "$api_key" || "${#api_key}" -gt 512 ]]; then
  echo "Idena API key must be 1-512 bytes" >&2
  exit 1
fi
if printf '%s' "$api_key" | LC_ALL=C grep -q '[[:cntrl:]]'; then
  echo "Idena API key must not contain control characters" >&2
  exit 1
fi
escaped_api_key="${api_key//\\/\\\\}"
escaped_api_key="${escaped_api_key//\"/\\\"}"
sync_request_file="$(mktemp)"
snapshot_tmp_file=""
reward_events_tmp_file=""
trap 'rm -f "$sync_request_file" "$snapshot_tmp_file" "$reward_events_tmp_file"' EXIT
chmod 600 "$sync_request_file"
printf '{"jsonrpc":"2.0","id":1,"method":"bcn_syncing","params":[],"key":"%s"}' \
  "$escaped_api_key" > "$sync_request_file"
if ! sync_json="$(
  curl -fsS \
    --connect-timeout 5 \
    --max-time 15 \
    -H 'Content-Type: application/json' \
    --data-binary "@$sync_request_file" \
    "$RPC_URL"
)"; then
  echo "Idena RPC is unavailable; skipping PoHW snapshot."
  exit 0
fi

if ! sync_state="$(SYNC_JSON="$sync_json" python3 - <<'PY'
import json
import os
import sys

try:
    payload = json.loads(os.environ.get("SYNC_JSON", ""))
except json.JSONDecodeError as exc:
    print(f"invalid JSON: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(payload, dict):
    print("sync response must be a JSON object", file=sys.stderr)
    sys.exit(1)
if payload.get("error"):
    print(f"sync RPC returned error: {payload['error']}", file=sys.stderr)
    sys.exit(1)

result = payload.get("result")
if not isinstance(result, dict):
    print("sync response result must be a JSON object", file=sys.stderr)
    sys.exit(1)

syncing = result.get("syncing")
wrong_time = result.get("wrongTime")
current_block = int(result.get("currentBlock") or 0)
highest_block = int(result.get("highestBlock") or 0)
if not isinstance(syncing, bool):
    print("sync response result.syncing must be boolean", file=sys.stderr)
    sys.exit(1)
if wrong_time is not None and not isinstance(wrong_time, bool):
    print("sync response result.wrongTime must be boolean when present", file=sys.stderr)
    sys.exit(1)

effectively_syncing = syncing and not (highest_block > 0 and current_block >= highest_block)

if wrong_time:
    print("wrong_time")
elif effectively_syncing:
    print("syncing")
else:
    print("ready")
PY
)"; then
  echo "Idena RPC sync response is not usable; skipping PoHW snapshot."
  exit 0
fi

case "$sync_state" in
  syncing)
    echo "Idena is still syncing; skipping PoHW snapshot."
    exit 0
    ;;
  wrong_time)
    echo "Idena node reports wrong local time; skipping PoHW snapshot."
    exit 0
    ;;
  ready)
    ;;
  *)
    echo "Unexpected Idena sync state '$sync_state'; skipping PoHW snapshot."
    exit 0
    ;;
esac

ensure_local_dir "$OUT_DIR" "snapshot output"
snapshot_tmp_file="$(mktemp "$OUT_DIR/.idena-snapshot.XXXXXX")"

indexer_args=(
  snapshot-now
  --rpc-url "$RPC_URL"
  --api-key-file "$API_KEY_FILE"
)

if [[ -n "${IDENA_REWARD_EVENTS_FILE:-}" ]]; then
  indexer_args+=(--reward-events-file "$IDENA_REWARD_EVENTS_FILE")
elif [[ -n "${IDENA_REWARD_LEDGER_DB:-}" ]]; then
  exact_sync_configured=false
  if [[ -n "${IDENA_INDEXER_DATABASE_URL_FILE:-}" || -n "${IDENA_INDEXER_DATABASE_URL:-}" ]]; then
    exact_sync_configured=true
  fi
  if [[ -L "$IDENA_REWARD_LEDGER_DB" ]]; then
    echo "Idena reward ledger DB must not be a symlink: $IDENA_REWARD_LEDGER_DB" >&2
    exit 1
  fi
  ledger_parent="$(dirname "$IDENA_REWARD_LEDGER_DB")"
  reject_symlink_ancestor "$ledger_parent"
  if [[ ! -f "$IDENA_REWARD_LEDGER_DB" || ! -r "$IDENA_REWARD_LEDGER_DB" ]]; then
    if [[ "$exact_sync_configured" == true ]]; then
      ensure_local_dir "$ledger_parent" "Idena reward ledger parent"
    else
      echo "Idena reward ledger DB is not ready; skipping consensus snapshot: $IDENA_REWARD_LEDGER_DB"
      exit 0
    fi
  fi
  if [[ ! -f "$REWARD_INDEXER_SCRIPT" || ! -r "$REWARD_INDEXER_SCRIPT" ]]; then
    echo "Idena reward indexer script must be readable: $REWARD_INDEXER_SCRIPT" >&2
    exit 1
  fi
  if [[ "$exact_sync_configured" == true ]]; then
    exact_sync_args=(
      --db "$IDENA_REWARD_LEDGER_DB"
      sync-official-indexer
      --sql-file "$EXACT_REWARD_SQL_FILE"
    )
    if [[ -n "${IDENA_INDEXER_DATABASE_URL_FILE:-}" ]]; then
      exact_sync_args+=(--database-url-file "$IDENA_INDEXER_DATABASE_URL_FILE")
    fi
    if [[ -n "${IDENA_INDEXER_PSQL_BIN:-}" ]]; then
      exact_sync_args+=(--psql-bin "$IDENA_INDEXER_PSQL_BIN")
    fi
    if [[ -n "${IDENA_INDEXER_EXPORT_TIMEOUT_SECONDS:-}" ]]; then
      exact_sync_args+=(--timeout-seconds "$IDENA_INDEXER_EXPORT_TIMEOUT_SECONDS")
    fi
    if ! python3 "$REWARD_INDEXER_SCRIPT" "${exact_sync_args[@]}"; then
      echo "Official idena-indexer exact reward sync failed; skipping consensus snapshot."
      exit 0
    fi
  fi
  reward_events_tmp_file="$(mktemp "$OUT_DIR/.idena-reward-events.XXXXXX")"
  reward_export_args=(
    --db "$IDENA_REWARD_LEDGER_DB"
    export-replay
  )
  allow_inferred_reward_replay=false
  case "${POHW_ALLOW_INFERRED_REWARD_REPLAY:-}" in
    1|true|TRUE|yes|YES)
      allow_inferred_reward_replay=true
      reward_export_args+=(--allow-inferred)
      ;;
  esac
  if [[ "$allow_inferred_reward_replay" != true ]]; then
    reward_export_args+=(--require-exact)
  fi
  if ! python3 "$REWARD_INDEXER_SCRIPT" \
    "${reward_export_args[@]}" \
    > "$reward_events_tmp_file"; then
    echo "Idena reward ledger cannot produce a consensus-safe replay export; skipping snapshot."
    echo "Use POHW_ALLOW_INFERRED_REWARD_REPLAY=true only for non-consensus development snapshots."
    exit 0
  fi
  indexer_args+=(--reward-events-file "$reward_events_tmp_file")
else
  case "${POHW_ALLOW_EMPTY_REWARD_REPLAY:-}" in
    1|true|TRUE|yes|YES)
      indexer_args+=(--allow-empty-reward-replay)
      ;;
    *)
      echo "Idena reward event replay file is not configured; skipping consensus snapshot."
      echo "Set IDENA_REWARD_EVENTS_FILE, or POHW_ALLOW_EMPTY_REWARD_REPLAY=true for development only."
      exit 0
      ;;
  esac
fi

case "$ALLOW_REMOTE_RPC" in
  1|true|TRUE|yes|YES)
    indexer_args+=(--allow-remote-rpc)
    ;;
esac

"$BIN" "${indexer_args[@]}" > "$snapshot_tmp_file"

snapshot_day="$(date -u +%F)"
height="$(
  grep -m 1 '"idena_height"' "$snapshot_tmp_file" \
    | tr -dc '0-9' \
    || true
)"

final_file="$OUT_DIR/idena-snapshot-$snapshot_day-${height:-unknown}.json"
if [[ -L "$final_file" ]]; then
  echo "Refusing to write snapshot through symlinked output file: $final_file" >&2
  exit 1
fi
if [[ -e "$final_file" ]]; then
  echo "Snapshot output already exists; leaving existing file unchanged: $final_file"
  rm -f "$snapshot_tmp_file"
  snapshot_tmp_file=""
  rm -f "$sync_request_file"
  sync_request_file=""
  trap - EXIT
  exit 0
fi
if ! ln "$snapshot_tmp_file" "$final_file"; then
  echo "Refusing to overwrite existing snapshot output: $final_file" >&2
  exit 1
fi
rm -f "$snapshot_tmp_file"
snapshot_tmp_file=""
rm -f "$sync_request_file"
sync_request_file=""
trap - EXIT

echo "Wrote $final_file"
