#!/usr/bin/env bash
set -euo pipefail

SERVICE="${IDENA_EXPORT_SERVICE:-idena-bootstrap.service}"
DATADIR="${IDENA_EXPORT_DATADIR:-/srv/idena}"
EXPORT_DIR="${IDENA_EXPORT_DIR:-/srv/idena-return-export}"
STATE_DIR="${IDENA_EXPORT_STATE_DIR:-/var/lib/idena-return}"
STATE_FILE="${IDENA_EXPORT_STATE_FILE:-$STATE_DIR/pushed.json}"
READY_SINCE_FILE="${IDENA_EXPORT_READY_SINCE_FILE:-$STATE_DIR/sync-ready.since}"
LOCK_FILE="${IDENA_EXPORT_LOCK_FILE:-/run/lock/idena-public-state-export.lock}"
SOURCE_RECOVERY_FILE="${IDENA_EXPORT_SOURCE_RECOVERY_FILE:-/run/lock/idena-public-state-export.source-active}"
RPC_URL="${IDENA_EXPORT_RPC_URL:-http://127.0.0.1:9009}"
API_KEY_FILE="${IDENA_EXPORT_API_KEY_FILE:-$DATADIR/api.key}"
MANIFEST_TOOL="${IDENA_TRANSFER_MANIFEST_TOOL:-/usr/local/libexec/idena-public-state-manifest.py}"
RETURN_TARGET="${IDENA_RETURN_TARGET:-}"
RETURN_DIR="${IDENA_RETURN_DIR:-current}"
SSH_KEY_FILE="${IDENA_RETURN_SSH_KEY_FILE:-/etc/idena-return/id_ed25519}"
KNOWN_HOSTS_FILE="${IDENA_RETURN_KNOWN_HOSTS_FILE:-/etc/idena-return/known_hosts}"
SSH_PORT="${IDENA_RETURN_SSH_PORT:-2222}"
SYSTEMCTL_BIN="${IDENA_TRANSFER_SYSTEMCTL_BIN:-systemctl}"
PYTHON_BIN="${IDENA_TRANSFER_PYTHON_BIN:-python3}"
RSYNC_BIN="${IDENA_TRANSFER_RSYNC_BIN:-rsync}"
SSH_BIN="${IDENA_TRANSFER_SSH_BIN:-ssh}"
LOCK_HELPER="${IDENA_PRIVATE_LOCK_HELPER:-/usr/local/libexec/idena-private-lock-exec.py}"
MIN_HEIGHT="${IDENA_EXPORT_MIN_HEIGHT:-0}"
MIN_PEERS="${IDENA_EXPORT_MIN_PEERS:-1}"
STABLE_SECONDS="${IDENA_EXPORT_STABLE_SECONDS:-120}"
LOCAL_MIN_FREE_BYTES="${IDENA_EXPORT_MIN_FREE_BYTES:-10737418240}"
RETURN_MIN_FREE_BYTES="${IDENA_RETURN_MIN_FREE_BYTES:-10737418240}"

log() {
  printf '%s idena-public-state-export: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

fail() {
  log "ERROR: $*" >&2
  exit 1
}

safe_directory() {
  local path="$1" label="$2" allow_mount="${3:-false}" resolved
  [[ "$path" == /* ]] || fail "$label must be an absolute path: $path"
  [[ "$path" != "/" ]] || fail "$label must not be /"
  [[ -d "$path" ]] || fail "$label is missing: $path"
  [[ ! -L "$path" ]] || fail "$label must not be a symlink: $path"
  resolved="$(readlink -f -- "$path")"
  [[ "$resolved" == "$path" ]] || fail "$label is not canonical: $path"
  if [[ "$allow_mount" != "true" ]] && mountpoint -q -- "$path"; then
    fail "$label must not be a mount point: $path"
  fi
}

paths_overlap() {
  local first="$1" second="$2"
  [[ "$first" == "$second" || "$first" == "$second/"* || "$second" == "$first/"* ]]
}

require_disjoint() {
  local first="$1" first_label="$2" second="$3" second_label="$4"
  paths_overlap "$first" "$second" \
    && fail "$first_label and $second_label must not overlap: $first / $second"
  return 0
}

clear_directory() {
  safe_directory "$1" "$2" "${3:-false}"
  find "$1" -xdev -mindepth 1 -depth -delete
}

durable_unlink() {
  local path="$1"
  rm -f -- "$path"
  "$PYTHON_BIN" - "$(dirname "$path")" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

atomic_text_file() {
  local path="$1" value="$2"
  "$PYTHON_BIN" - "$path" "$value" <<'PY'
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(sys.argv[2] + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY
}

write_delivery_state() {
  local phase="$1"
  "$PYTHON_BIN" - "$STATE_FILE" "$phase" "$TRANSFER_ID" "$current" <<'PY'
import json
import os
import pathlib
import sys
import tempfile
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
payload = {
    "schema": 2,
    "phase": sys.argv[2],
    "transferId": sys.argv[3],
    "sourceHeight": int(sys.argv[4]),
    "updatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY
}

recover_source() {
  [[ -e "$SOURCE_RECOVERY_FILE" ]] || return 0
  [[ -f "$SOURCE_RECOVERY_FILE" && ! -L "$SOURCE_RECOVERY_FILE" ]] \
    || fail "source recovery marker is not a regular file"
  log "recovering $SERVICE after an interrupted export"
  "$SYSTEMCTL_BIN" start "$SERVICE"
  "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE" \
    || fail "failed to recover $SERVICE"
  durable_unlink "$SOURCE_RECOVERY_FILE"
}

recover_source_on_exit() {
  local rc=$?
  trap - EXIT INT TERM
  if ! recover_source; then
    exit 1
  fi
  exit "$rc"
}

query_sync() {
  "$PYTHON_BIN" - "$RPC_URL" "$API_KEY_FILE" <<'PY'
import json
import pathlib
import sys
import urllib.request

url = sys.argv[1]
key_path = pathlib.Path(sys.argv[2])
if key_path.is_symlink() or not key_path.is_file():
    raise SystemExit("API key file must be a regular, non-symlink file")
key = key_path.read_text(encoding="ascii").strip()
request = urllib.request.Request(
    url,
    data=json.dumps({"method": "bcn_syncing", "params": [], "id": 1, "key": key}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=10) as response:
    payload = json.load(response)
if payload.get("error"):
    raise SystemExit("bcn_syncing RPC failed")
result = payload.get("result")
if not isinstance(result, dict):
    raise SystemExit("bcn_syncing returned an invalid result")
current = int(result["currentBlock"])
highest = int(result["highestBlock"])
syncing = str(bool(result.get("syncing"))).lower()
wrong_time = str(bool(result.get("wrongTime"))).lower()
peer_request = urllib.request.Request(
    url,
    data=json.dumps({"method": "net_peers", "params": [], "id": 2, "key": key}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(peer_request, timeout=10) as response:
    peer_payload = json.load(response)
if peer_payload.get("error") or not isinstance(peer_payload.get("result"), list):
    raise SystemExit("net_peers RPC failed")
print(current, highest, syncing, wrong_time, len(peer_payload["result"]))
PY
}

audit_source_trees() {
  "$PYTHON_BIN" - \
    "$DATADIR/idenachain.db" "$DATADIR/ipfs/badgerds" "${1:-}" <<'PY'
import os
import pathlib
import stat
import sys

for raw_root in sys.argv[1:]:
    if not raw_root:
        continue
    root = pathlib.Path(raw_root)
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit("source public-state root is not a plain directory")
    root_device = metadata.st_dev
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = pathlib.Path(current_root)
        for name in directory_names:
            entry = current / name
            entry_metadata = entry.lstat()
            if (
                stat.S_ISLNK(entry_metadata.st_mode)
                or not stat.S_ISDIR(entry_metadata.st_mode)
                or entry_metadata.st_dev != root_device
            ):
                raise SystemExit("source public-state tree contains an unsafe directory")
        for name in file_names:
            entry = current / name
            entry_metadata = entry.lstat()
            if (
                stat.S_ISLNK(entry_metadata.st_mode)
                or not stat.S_ISREG(entry_metadata.st_mode)
                or entry_metadata.st_dev != root_device
                or entry_metadata.st_nlink != 1
            ):
                raise SystemExit("source public-state tree contains an unsafe file")
PY
}

directory_bytes() {
  du -sb -- "$1" | awk '{print $1}'
}

available_bytes() {
  df -B1 --output=avail -- "$1" | awk 'NR == 2 {print $1}'
}

[[ "$(id -u)" == "0" ]] || fail "run this exporter as root"
[[ -x "$LOCK_HELPER" && ! -L "$LOCK_HELPER" ]] || fail "private lock helper is missing or symlinked"
if [[ "${IDENA_PRIVATE_LOCK_HELD:-}" != "$LOCK_FILE" ]]; then
  script_path="$(readlink -f -- "$0")"
  [[ -f "$script_path" && ! -L "$script_path" ]] || fail "exporter path is not a regular file"
  exec "$LOCK_HELPER" "$LOCK_FILE" "$script_path" "$@"
fi
if [[ "${1:-}" == "--recover-source" && "$#" == "1" ]]; then
  recover_source
  exit 0
fi
[[ "$#" == "0" ]] || fail "unsupported arguments"
[[ -n "$RETURN_TARGET" ]] || fail "IDENA_RETURN_TARGET is required"
[[ "$RETURN_TARGET" =~ ^[a-z_][a-z0-9_-]{0,31}@[a-zA-Z0-9_.:-]+$ ]] \
  || fail "IDENA_RETURN_TARGET has an invalid format"
[[ "$RETURN_DIR" == "current" ]] || fail "IDENA_RETURN_DIR must be exactly current"
[[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] || fail "IDENA_RETURN_SSH_PORT must be numeric"
(( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) || fail "invalid SSH port"
for value_name in \
  MIN_HEIGHT MIN_PEERS STABLE_SECONDS LOCAL_MIN_FREE_BYTES RETURN_MIN_FREE_BYTES; do
  value="${!value_name}"
  [[ "$value" =~ ^[0-9]+$ ]] || fail "$value_name must be an unsigned integer"
done
(( STABLE_SECONDS >= 60 && STABLE_SECONDS <= 3600 )) || fail "STABLE_SECONDS is out of range"
(( LOCAL_MIN_FREE_BYTES >= 1073741824 )) || fail "local free-space reserve must be at least 1 GiB"
(( RETURN_MIN_FREE_BYTES >= 1073741824 )) || fail "return free-space reserve must be at least 1 GiB"
[[ -x "$MANIFEST_TOOL" ]] || fail "manifest tool is not executable: $MANIFEST_TOOL"
[[ -f "$SSH_KEY_FILE" && ! -L "$SSH_KEY_FILE" ]] || fail "return SSH key is missing or symlinked"
[[ "$(stat -c %a "$SSH_KEY_FILE")" == "600" ]] || fail "return SSH key must have mode 600"
[[ -f "$KNOWN_HOSTS_FILE" && ! -L "$KNOWN_HOSTS_FILE" ]] \
  || fail "known-hosts file is missing or symlinked"
case "$SSH_KEY_FILE$KNOWN_HOSTS_FILE" in
  *[[:space:]]*) fail "SSH key and known-hosts paths must not contain whitespace" ;;
esac

for path in "$EXPORT_DIR" "$STATE_DIR"; do
  [[ "$path" == /* && "$path" != "/" && "$path" != "/run" ]] \
    || fail "managed directory is unsafe: $path"
done
install -d -o root -g root -m 0700 "$EXPORT_DIR" "$STATE_DIR"
safe_directory "$DATADIR" "Idena datadir" true
safe_directory "$EXPORT_DIR" "export directory" true
safe_directory "$STATE_DIR" "export state directory" true
require_disjoint "$DATADIR" "Idena datadir" "$EXPORT_DIR" "export directory"
require_disjoint "$DATADIR" "Idena datadir" "$STATE_DIR" "export state directory"
require_disjoint "$EXPORT_DIR" "export directory" "$STATE_DIR" "export state directory"
[[ "$(dirname "$STATE_FILE")" == "$STATE_DIR" ]] || fail "state file must be directly inside the state directory"
[[ "$(dirname "$READY_SINCE_FILE")" == "$STATE_DIR" ]] \
  || fail "sync gate state must be directly inside the state directory"
for runtime_path in "$LOCK_FILE" "$SOURCE_RECOVERY_FILE"; do
  [[ "$runtime_path" == /run/lock/* && "$(dirname "$runtime_path")" == "/run/lock" ]] \
    || fail "runtime state path must be directly inside /run/lock: $runtime_path"
done

recover_source
if [[ -L "$STATE_FILE" ]]; then
  fail "delivery state must not be a symlink"
elif [[ -e "$STATE_FILE" ]]; then
  log "a delivery decision already exists in $STATE_FILE; inspect it before any intentional retry"
  exit 0
fi

read -r current highest syncing wrong_time peers < <(query_sync)
if [[ "$syncing" != "false" \
  || "$wrong_time" != "false" \
  || "$current" -lt "$highest" \
  || "$current" -lt "$MIN_HEIGHT" \
  || "$peers" -lt "$MIN_PEERS" ]]; then
  durable_unlink "$READY_SINCE_FILE"
  log "waiting for sync: current=$current highest=$highest minimum=$MIN_HEIGHT syncing=$syncing wrongTime=$wrong_time peers=$peers"
  exit 0
fi

now="$(date +%s)"
ready_since=""
if [[ -f "$READY_SINCE_FILE" && ! -L "$READY_SINCE_FILE" ]]; then
  ready_since="$(cat "$READY_SINCE_FILE")"
fi
if [[ ! "$ready_since" =~ ^[0-9]+$ || "$ready_since" -gt "$now" ]]; then
  atomic_text_file "$READY_SINCE_FILE" "$now"
  log "sync gate first passed at height $current; waiting ${STABLE_SECONDS}s for stability"
  exit 0
fi
if (( now - ready_since < STABLE_SECONDS )); then
  log "sync gate remains healthy; waiting $((STABLE_SECONDS - (now - ready_since)))s"
  exit 0
fi

for path in \
  "$DATADIR/idenachain.db" \
  "$DATADIR/ipfs" \
  "$DATADIR/ipfs/badgerds" \
  "$DATADIR/keystore"; do
  [[ -d "$path" && ! -L "$path" ]] || fail "required directory is missing or symlinked: $path"
done
for path in \
  "$DATADIR/keystore/nodekey" \
  "$DATADIR/api.key" \
  "$DATADIR/ipfs/config" \
  "$DATADIR/ipfs/swarm.key"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "required local key file is missing or symlinked: $path"
done

required_bytes="$(( $(directory_bytes "$DATADIR/idenachain.db") + $(directory_bytes "$DATADIR/ipfs/badgerds") ))"
if [[ -d "$DATADIR/snapshots" && ! -L "$DATADIR/snapshots" ]]; then
  required_bytes="$(( required_bytes + $(directory_bytes "$DATADIR/snapshots") ))"
fi
local_available="$(available_bytes "$EXPORT_DIR")"
local_reclaimable="$(directory_bytes "$EXPORT_DIR")"
[[ "$required_bytes" =~ ^[0-9]+$ && "$local_available" =~ ^[0-9]+$ && "$local_reclaimable" =~ ^[0-9]+$ ]] \
  || fail "could not determine local capacity"
(( local_available + local_reclaimable >= required_bytes + LOCAL_MIN_FREE_BYTES )) \
  || fail "insufficient local capacity for a safe export"

ssh_options=(
  -i "$SSH_KEY_FILE"
  -p "$SSH_PORT"
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$KNOWN_HOSTS_FILE"
)
remote_available="$($SSH_BIN "${ssh_options[@]}" "$RETURN_TARGET" idena-return-capacity)"
[[ "$remote_available" =~ ^[0-9]+$ ]] || fail "destination returned an invalid capacity response"
(( remote_available >= required_bytes + RETURN_MIN_FREE_BYTES )) \
  || fail "destination lacks capacity for the transfer and required reserve"

TRANSFER_ID="$($PYTHON_BIN -c 'import secrets; print(secrets.token_hex(16))')"
[[ "$TRANSFER_ID" =~ ^[0-9a-f]{32}$ ]] || fail "failed to create a transfer identifier"

if "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE"; then
  atomic_text_file "$SOURCE_RECOVERY_FILE" "$SERVICE"
else
  fail "$SERVICE became inactive before export"
fi
trap recover_source_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$SYSTEMCTL_BIN" stop "$SERVICE"

snapshot_source=""
if [[ -d "$DATADIR/snapshots" && ! -L "$DATADIR/snapshots" ]]; then
  snapshot_source="$DATADIR/snapshots"
fi
audit_source_trees "$snapshot_source"

clear_directory "$EXPORT_DIR" "export directory" true
cp -a --no-preserve=ownership --reflink=auto \
  "$DATADIR/idenachain.db" "$EXPORT_DIR/idenachain.db"
cp -a --no-preserve=ownership --reflink=auto \
  "$DATADIR/ipfs/badgerds" "$EXPORT_DIR/ipfs-badgerds"
if [[ -d "$DATADIR/snapshots" && ! -L "$DATADIR/snapshots" ]]; then
  cp -a --no-preserve=ownership --reflink=auto \
    "$DATADIR/snapshots" "$EXPORT_DIR/snapshots"
else
  install -d -o root -g root -m 0700 "$EXPORT_DIR/snapshots"
fi
find "$EXPORT_DIR" -xdev -type d -exec chmod 0700 {} +
find "$EXPORT_DIR" -xdev -type f -exec chmod 0600 {} +
"$MANIFEST_TOOL" create \
  --root "$EXPORT_DIR" \
  --transfer-id "$TRANSFER_ID" \
  --source-height "$current" \
  --source-highest "$highest" \
  --output "$EXPORT_DIR/manifest.json"

recover_source
trap - EXIT INT TERM

ssh_command="$SSH_BIN -i $SSH_KEY_FILE -p $SSH_PORT -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN_HOSTS_FILE"
RSYNC_RSH="$ssh_command" "$RSYNC_BIN" -a --delete --partial --delay-updates --stats \
  "$EXPORT_DIR/" "$RETURN_TARGET:$RETURN_DIR/"

ready_file="$(mktemp "$STATE_DIR/READY.XXXXXX")"
trap 'rm -f "$ready_file"' EXIT
"$PYTHON_BIN" - "$ready_file" "$TRANSFER_ID" "$current" <<'PY'
import json
import os
import sys

path = sys.argv[1]
payload = {"schema": 2, "sourceHeight": int(sys.argv[3]), "transferId": sys.argv[2]}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(path, 0o600)
PY

# From this point onward automatic retries are intentionally blocked. A crash may
# have delivered READY, so only an operator may reconcile and retry this transfer.
write_delivery_state "ready-intent"
RSYNC_RSH="$ssh_command" "$RSYNC_BIN" -a --partial \
  "$ready_file" "$RETURN_TARGET:$RETURN_DIR/READY"
write_delivery_state "ready-sent"
rm -f "$ready_file"
trap - EXIT
durable_unlink "$READY_SINCE_FILE"
log "pushed synchronized public state at height $current (transfer $TRANSFER_ID)"
