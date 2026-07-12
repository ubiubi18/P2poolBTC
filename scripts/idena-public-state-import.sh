#!/usr/bin/env bash
set -euo pipefail

SERVICE="${IDENA_IMPORT_SERVICE:-idena.service}"
DATADIR="${IDENA_IMPORT_DATADIR:-/var/lib/idena}"
INBOX_ROOT="${IDENA_IMPORT_INBOX_ROOT:-/var/lib/idena-return-inbox}"
INBOX="${IDENA_IMPORT_INBOX:-$INBOX_ROOT/current}"
BACKUP_ROOT="${IDENA_IMPORT_BACKUP_ROOT:-/var/lib/idena-return-backup}"
BACKUP="${IDENA_IMPORT_BACKUP:-$BACKUP_ROOT/current}"
FAILED_ROOT="${IDENA_IMPORT_FAILED_ROOT:-/var/lib/idena-return-failed}"
STATE_DIR="${IDENA_IMPORT_STATE_DIR:-/var/lib/idena-return-state}"
TRANSACTION_FILE="${IDENA_IMPORT_TRANSACTION_FILE:-$STATE_DIR/in-progress.json}"
COMPLETED_FILE="${IDENA_IMPORT_COMPLETED_FILE:-$STATE_DIR/completed.json}"
LOCK_FILE="${IDENA_IMPORT_LOCK_FILE:-/run/lock/idena-public-state-import.lock}"
TRANSFER_LOCK_FILE="${IDENA_TRANSFER_LOCK_FILE:-/run/lock/idena-return-transfer.lock}"
TRANSFER_GROUP="${IDENA_TRANSFER_GROUP:-idena-return}"
RPC_URL="${IDENA_IMPORT_RPC_URL:-http://127.0.0.1:9009}"
API_KEY_FILE="${IDENA_IMPORT_API_KEY_FILE:-$DATADIR/api.key}"
RPC_TIMEOUT_SECONDS="${IDENA_IMPORT_RPC_TIMEOUT_SECONDS:-900}"
LOCK_TIMEOUT_SECONDS="${IDENA_IMPORT_LOCK_TIMEOUT_SECONDS:-900}"
MIN_FREE_BYTES="${IDENA_IMPORT_MIN_FREE_BYTES:-10737418240}"
MANIFEST_TOOL="${IDENA_TRANSFER_MANIFEST_TOOL:-/usr/local/libexec/idena-public-state-manifest.py}"
SYSTEMCTL_BIN="${IDENA_TRANSFER_SYSTEMCTL_BIN:-systemctl}"
PYTHON_BIN="${IDENA_TRANSFER_PYTHON_BIN:-python3}"
FLOCK_BIN="${IDENA_TRANSFER_FLOCK_BIN:-flock}"
LOCK_HELPER="${IDENA_PRIVATE_LOCK_HELPER:-/usr/local/libexec/idena-private-lock-exec.py}"

log() {
  printf '%s idena-public-state-import: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
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
  safe_directory "$1" "$2"
  find "$1" -xdev -mindepth 1 -depth -delete
}

fsync_directory() {
  "$PYTHON_BIN" - "$1" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

durable_unlink() {
  local path="$1"
  rm -f -- "$path"
  fsync_directory "$(dirname "$path")"
}

key_digest() {
  sha256sum \
    "$DATADIR/keystore/nodekey" \
    "$DATADIR/api.key" \
    "$DATADIR/ipfs/config" \
    "$DATADIR/ipfs/swarm.key"
}

available_bytes() {
  df -B1 --output=avail -- "$1" | awk 'NR == 2 {print $1}'
}

write_transaction() {
  local phase="$1" validated_height="${2:-}"
  "$PYTHON_BIN" - \
    "$TRANSACTION_FILE" "$phase" "$TRANSFER_ID" "$SOURCE_HEIGHT" "$TRANSFER_BYTES" \
    "$SERVICE_WAS_ACTIVE" "$SNAPSHOTS_WERE_PRESENT" "$validated_height" <<'PY'
import json
import os
import pathlib
import sys
import tempfile
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
validated_height = None if not sys.argv[8] else int(sys.argv[8])
payload = {
    "schema": 1,
    "phase": sys.argv[2],
    "transferId": sys.argv[3],
    "sourceHeight": int(sys.argv[4]),
    "transferBytes": int(sys.argv[5]),
    "serviceWasActive": sys.argv[6] == "true",
    "snapshotsWerePresent": sys.argv[7] == "true",
    "validatedHeight": validated_height,
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

load_transaction() {
  local fields
  fields="$($PYTHON_BIN - "$TRANSACTION_FILE" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    raise SystemExit("transaction journal must be a regular, non-symlink file")
raw = path.read_text(encoding="utf-8")
if len(raw.encode("utf-8")) > 16384:
    raise SystemExit("transaction journal is unexpectedly large")
payload = json.loads(raw)
expected = {
    "schema", "phase", "transferId", "sourceHeight", "transferBytes",
    "serviceWasActive", "snapshotsWerePresent", "validatedHeight", "updatedAt",
}
if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema") != 1:
    raise SystemExit("transaction journal does not match the contract")
phase = payload.get("phase")
if phase not in {"prepared", "swapping", "running", "committed"}:
    raise SystemExit("transaction journal has an invalid phase")
transfer_id = payload.get("transferId")
if not isinstance(transfer_id, str) or not re.fullmatch(r"[0-9a-f]{32}", transfer_id):
    raise SystemExit("transaction journal has an invalid transfer ID")
for name in ("sourceHeight", "transferBytes"):
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SystemExit(f"transaction journal has an invalid {name}")
for name in ("serviceWasActive", "snapshotsWerePresent"):
    if not isinstance(payload.get(name), bool):
        raise SystemExit(f"transaction journal has an invalid {name}")
validated = payload.get("validatedHeight")
if phase == "committed":
    if not isinstance(validated, int) or isinstance(validated, bool) or validated < payload["sourceHeight"]:
        raise SystemExit("committed transaction has an invalid validated height")
elif validated is not None:
    raise SystemExit("uncommitted transaction contains a validated height")
print(
    phase,
    transfer_id,
    payload["sourceHeight"],
    payload["transferBytes"],
    str(payload["serviceWasActive"]).lower(),
    str(payload["snapshotsWerePresent"]).lower(),
    "none" if validated is None else validated,
)
PY
)" || fail "could not load the import transaction journal"
  read -r TRANSACTION_PHASE TRANSFER_ID SOURCE_HEIGHT TRANSFER_BYTES \
    SERVICE_WAS_ACTIVE SNAPSHOTS_WERE_PRESENT VALIDATED_HEIGHT <<<"$fields"
  [[ "$TRANSACTION_PHASE" =~ ^(prepared|swapping|running|committed)$ ]] \
    || fail "transaction parser returned an invalid phase"
  [[ "$TRANSFER_ID" =~ ^[0-9a-f]{32}$ ]] || fail "transaction parser returned an invalid transfer ID"
}

transaction_phase() {
  [[ -f "$TRANSACTION_FILE" && ! -L "$TRANSACTION_FILE" ]] || return 1
  "$PYTHON_BIN" - "$TRANSACTION_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
print(payload.get("phase", ""))
PY
}

write_completed_state() {
  "$PYTHON_BIN" - \
    "$COMPLETED_FILE" "$TRANSFER_ID" "$SOURCE_HEIGHT" "$VALIDATED_HEIGHT" <<'PY'
import json
import os
import pathlib
import sys
import tempfile
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
payload = {
    "schema": 2,
    "completedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "transferId": sys.argv[2],
    "sourceHeight": int(sys.argv[3]),
    "validatedHeight": int(sys.argv[4]),
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

wait_for_imported_height() {
  "$PYTHON_BIN" - "$RPC_URL" "$API_KEY_FILE" "$SOURCE_HEIGHT" "$RPC_TIMEOUT_SECONDS" <<'PY'
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

url = sys.argv[1]
key_path = pathlib.Path(sys.argv[2])
minimum_height = int(sys.argv[3])
timeout = int(sys.argv[4])
deadline = time.monotonic() + timeout
last_error = "RPC not ready"
while time.monotonic() < deadline:
    try:
        key = key_path.read_text(encoding="ascii").strip()
        request = urllib.request.Request(
            url,
            data=json.dumps({"method": "bcn_syncing", "params": [], "id": 1, "key": key}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.load(response)
        if payload.get("error"):
            last_error = "bcn_syncing RPC failed"
        else:
            result = payload.get("result")
            current = int(result["currentBlock"])
            if bool(result.get("wrongTime")):
                raise SystemExit("imported node reports wrongTime=true")
            if current >= minimum_height:
                print(current)
                raise SystemExit(0)
            last_error = f"current height {current} is below imported height {minimum_height}"
    except (OSError, KeyError, TypeError, ValueError, urllib.error.URLError) as exc:
        last_error = type(exc).__name__
    time.sleep(5)
raise SystemExit(f"Idena RPC validation timed out: {last_error}")
PY
}

failed_directory() {
  printf '%s/transfer-%s' "$FAILED_ROOT" "$TRANSFER_ID"
}

move_current_to_failed() {
  local current_path="$1" failed_path="$2"
  [[ -e "$current_path" ]] || return 0
  [[ ! -e "$failed_path" ]] || fail "rollback target already exists: $failed_path"
  install -d -o root -g root -m 0700 "$(dirname "$failed_path")"
  mv -- "$current_path" "$failed_path"
}

restore_component() {
  local backup_path="$1" current_path="$2" failed_path="$3"
  [[ -e "$backup_path" ]] || return 0
  move_current_to_failed "$current_path" "$failed_path"
  install -d -o root -g root -m 0700 "$(dirname "$current_path")"
  mv -- "$backup_path" "$current_path"
}

quarantine_inbox() {
  local failed="$1" entry name target
  [[ -d "$INBOX" && ! -L "$INBOX" ]] || return 0
  install -d -o root -g root -m 0700 "$failed/inbox"
  while IFS= read -r -d '' entry; do
    name="$(basename "$entry")"
    target="$failed/inbox/$name"
    [[ ! -e "$target" ]] || target="$failed/inbox/$name.recovered.$(date +%s).$$"
    mv -- "$entry" "$target"
  done < <(find "$INBOX" -xdev -mindepth 1 -maxdepth 1 -print0)
}

perform_rollback() {
  local failed
  failed="$(failed_directory)"
  log "restoring the original Pi public state for transfer $TRANSFER_ID"
  "$SYSTEMCTL_BIN" stop "$SERVICE"
  install -d -o root -g root -m 0700 "$failed/imported-state"
  restore_component \
    "$BACKUP/idenachain.db" "$DATADIR/idenachain.db" "$failed/imported-state/idenachain.db"
  restore_component \
    "$BACKUP/ipfs-badgerds" "$DATADIR/ipfs/badgerds" "$failed/imported-state/ipfs-badgerds"
  if [[ "$SNAPSHOTS_WERE_PRESENT" == "true" ]]; then
    restore_component \
      "$BACKUP/snapshots" "$DATADIR/snapshots" "$failed/imported-state/snapshots"
  elif [[ ! -e "$BACKUP/snapshots" ]]; then
    move_current_to_failed "$DATADIR/snapshots" "$failed/imported-state/snapshots"
  fi
  quarantine_inbox "$failed"
  fsync_directory "$DATADIR"
  fsync_directory "$DATADIR/ipfs"
  fsync_directory "$BACKUP"
  fsync_directory "$INBOX"
  if [[ "$SERVICE_WAS_ACTIVE" == "true" ]]; then
    "$SYSTEMCTL_BIN" start "$SERVICE"
    "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE" || fail "failed to restart $SERVICE after rollback"
  fi
}

finalize_success() {
  write_completed_state
  clear_directory "$BACKUP" "rollback directory"
  clear_directory "$INBOX" "completed return inbox"
  fsync_directory "$BACKUP"
  fsync_directory "$INBOX"
  durable_unlink "$TRANSACTION_FILE"
  log "imported public state at height $SOURCE_HEIGHT; validated height $VALIDATED_HEIGHT (transfer $TRANSFER_ID)"
}

recover_existing_transaction() {
  RECOVERY_ONLY=false
  [[ -e "$TRANSACTION_FILE" ]] || return 0
  load_transaction
  case "$TRANSACTION_PHASE" in
    prepared)
      log "recovering an interrupted pre-swap import for transfer $TRANSFER_ID"
      if [[ "$SERVICE_WAS_ACTIVE" == "true" ]]; then
        "$SYSTEMCTL_BIN" start "$SERVICE"
        "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE" || fail "failed to restart $SERVICE"
      fi
      durable_unlink "$TRANSACTION_FILE"
      ;;
    swapping|running)
      perform_rollback
      durable_unlink "$TRANSACTION_FILE"
      log "rolled back interrupted transfer $TRANSFER_ID"
      RECOVERY_ONLY=true
      ;;
    committed)
      log "finalizing previously validated transfer $TRANSFER_ID"
      finalize_success
      RECOVERY_ONLY=true
      ;;
  esac
}

failure_handler() {
  local rc=$? phase="" failed
  trap - EXIT INT TERM
  (( rc != 0 )) || return 0
  set +e
  phase="$(transaction_phase 2>/dev/null)"
  if [[ "$phase" == "committed" ]]; then
    log "finalization was interrupted; the committed journal is retained for automatic recovery"
    exit "$rc"
  fi
  if [[ "$phase" == "swapping" || "$phase" == "running" ]]; then
    if perform_rollback; then
      durable_unlink "$TRANSACTION_FILE"
    else
      log "ERROR: rollback was interrupted; the transaction journal is retained" >&2
    fi
  else
    if [[ "${SERVICE_STOPPED:-false}" == "true" && "${SERVICE_WAS_ACTIVE:-false}" == "true" ]]; then
      "$SYSTEMCTL_BIN" start "$SERVICE" || true
    fi
    if [[ "${CAN_QUARANTINE:-false}" == "true" ]]; then
      if [[ -n "${TRANSFER_ID:-}" ]]; then
        failed="$(failed_directory)"
      else
        failed="$FAILED_ROOT/rejected-$(date -u +%Y%m%dT%H%M%SZ)-$$"
      fi
      quarantine_inbox "$failed" || true
    fi
    [[ -e "$TRANSACTION_FILE" ]] && durable_unlink "$TRANSACTION_FILE"
  fi
  exit "$rc"
}

[[ "$(id -u)" == "0" ]] || fail "run this importer as root"
[[ -x "$LOCK_HELPER" && ! -L "$LOCK_HELPER" ]] || fail "private lock helper is missing or symlinked"
if [[ "${IDENA_PRIVATE_LOCK_HELD:-}" != "$LOCK_FILE" ]]; then
  script_path="$(readlink -f -- "$0")"
  [[ -f "$script_path" && ! -L "$script_path" ]] || fail "importer path is not a regular file"
  exec "$LOCK_HELPER" "$LOCK_FILE" "$script_path" "$@"
fi
for value_name in RPC_TIMEOUT_SECONDS LOCK_TIMEOUT_SECONDS MIN_FREE_BYTES; do
  value="${!value_name}"
  [[ "$value" =~ ^[0-9]+$ ]] || fail "$value_name must be an unsigned integer"
done
(( RPC_TIMEOUT_SECONDS >= 30 && RPC_TIMEOUT_SECONDS <= 3600 )) || fail "RPC timeout is out of range"
(( LOCK_TIMEOUT_SECONDS >= 60 && LOCK_TIMEOUT_SECONDS <= 86400 )) || fail "lock timeout is out of range"
(( MIN_FREE_BYTES >= 1073741824 )) || fail "free-space reserve must be at least 1 GiB"
[[ -x "$MANIFEST_TOOL" ]] || fail "manifest tool is not executable: $MANIFEST_TOOL"

for path in "$INBOX_ROOT" "$BACKUP_ROOT" "$FAILED_ROOT" "$STATE_DIR"; do
  [[ "$path" == /* && "$path" != "/" && "$path" != "/run" ]] \
    || fail "managed directory is unsafe: $path"
done
install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$FAILED_ROOT" "$STATE_DIR"
[[ -d "$INBOX_ROOT" ]] || fail "return inbox root is missing: $INBOX_ROOT"
[[ -d "$INBOX" ]] || fail "return inbox is missing: $INBOX"
if [[ ! -e "$BACKUP" ]]; then
  install -d -o root -g root -m 0700 "$BACKUP"
fi

safe_directory "$DATADIR" "Idena datadir" true
safe_directory "$INBOX_ROOT" "return inbox root" true
safe_directory "$INBOX" "return inbox"
safe_directory "$BACKUP_ROOT" "rollback root" true
safe_directory "$BACKUP" "rollback directory"
safe_directory "$FAILED_ROOT" "failed-transfer root" true
safe_directory "$STATE_DIR" "import state directory" true
[[ ! -L "$TRANSACTION_FILE" ]] || fail "transaction journal must not be a symlink"
[[ ! -L "$COMPLETED_FILE" ]] || fail "completion state must not be a symlink"
[[ "$(dirname "$INBOX")" == "$INBOX_ROOT" ]] || fail "return inbox must be a direct child of its root"
[[ "$(dirname "$BACKUP")" == "$BACKUP_ROOT" ]] || fail "rollback directory must be a direct child of its root"
[[ "$(dirname "$TRANSACTION_FILE")" == "$STATE_DIR" ]] \
  || fail "transaction journal must be directly inside the state directory"
[[ "$(dirname "$COMPLETED_FILE")" == "$STATE_DIR" ]] \
  || fail "completion state must be directly inside the state directory"

managed_paths=("$DATADIR" "$INBOX_ROOT" "$BACKUP_ROOT" "$FAILED_ROOT" "$STATE_DIR")
managed_labels=("Idena datadir" "return inbox" "rollback root" "failed-transfer root" "import state")
for ((first = 0; first < ${#managed_paths[@]}; first++)); do
  for ((second = first + 1; second < ${#managed_paths[@]}; second++)); do
    require_disjoint \
      "${managed_paths[$first]}" "${managed_labels[$first]}" \
      "${managed_paths[$second]}" "${managed_labels[$second]}"
  done
done

device="$(stat -c %d "$DATADIR")"
for path in "$INBOX" "$BACKUP" "$FAILED_ROOT" "$STATE_DIR"; do
  [[ "$(stat -c %d "$path")" == "$device" ]] \
    || fail "all import, rollback, failure, and journal paths must share one filesystem"
done

[[ "$LOCK_FILE" == /run/lock/* && "$(dirname "$LOCK_FILE")" == "/run/lock" ]] \
  || fail "import lock must be directly inside /run/lock"
[[ "$TRANSFER_LOCK_FILE" == /run/lock/* && "$(dirname "$TRANSFER_LOCK_FILE")" == "/run/lock" ]] \
  || fail "transfer lock must be directly inside /run/lock"
[[ -f "$TRANSFER_LOCK_FILE" && ! -L "$TRANSFER_LOCK_FILE" ]] \
  || fail "shared transfer lock is missing or symlinked"
group_entry="$(getent group "$TRANSFER_GROUP" || true)"
transfer_gid="$(printf '%s\n' "$group_entry" | cut -d: -f3)"
[[ "$transfer_gid" =~ ^[0-9]+$ ]] || fail "transfer group does not exist: $TRANSFER_GROUP"
[[ "$(stat -c %u "$TRANSFER_LOCK_FILE")" == "0" \
  && "$(stat -c %g "$TRANSFER_LOCK_FILE")" == "$transfer_gid" \
  && "$(stat -c %a "$TRANSFER_LOCK_FILE")" == "660" \
  && "$(stat -c %h "$TRANSFER_LOCK_FILE")" == "1" ]] \
  || fail "shared transfer lock must be root:$TRANSFER_GROUP mode 0660"

exec 8<>"$TRANSFER_LOCK_FILE"
if ! "$FLOCK_BIN" -w "$LOCK_TIMEOUT_SECONDS" 8; then
  fail "timed out waiting for the destination transfer lock"
fi

recover_existing_transaction
[[ "$RECOVERY_ONLY" == "false" ]] || exit 0
[[ -e "$INBOX/READY" ]] || {
  log "no completed transfer marker or recovery journal is present"
  exit 0
}
CAN_QUARANTINE=true
trap failure_handler EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for path in \
  "$DATADIR/keystore/nodekey" \
  "$DATADIR/api.key" \
  "$DATADIR/ipfs/config" \
  "$DATADIR/ipfs/swarm.key"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "required Pi key file is missing or symlinked: $path"
done
for path in "$DATADIR/idenachain.db" "$DATADIR/ipfs/badgerds"; do
  [[ -d "$path" && ! -L "$path" ]] || fail "required Pi public-state directory is missing or symlinked: $path"
done

summary="$($MANIFEST_TOOL validate \
  --root "$INBOX" \
  --manifest "$INBOX/manifest.json" \
  --print-summary)"
[[ "$summary" =~ ^([0-9]+)\ ([0-9a-f]{32})\ ([0-9]+)$ ]] \
  || fail "manifest returned an invalid validation summary"
SOURCE_HEIGHT="${BASH_REMATCH[1]}"
TRANSFER_ID="${BASH_REMATCH[2]}"
TRANSFER_BYTES="${BASH_REMATCH[3]}"

free_bytes="$(available_bytes "$DATADIR")"
[[ "$free_bytes" =~ ^[0-9]+$ ]] || fail "could not determine destination capacity"
(( free_bytes >= MIN_FREE_BYTES )) || fail "destination free-space reserve is exhausted"

before_digest="$(key_digest)"
service_user="$($SYSTEMCTL_BIN show "$SERVICE" -p User --value)"
service_group="$($SYSTEMCTL_BIN show "$SERVICE" -p Group --value)"
service_user="${service_user:-root}"
service_group="${service_group:-$(id -gn "$service_user")}"
id "$service_user" >/dev/null 2>&1 || fail "Idena service user does not exist: $service_user"
getent group "$service_group" >/dev/null || fail "Idena service group does not exist: $service_group"

SERVICE_WAS_ACTIVE=false
if "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE"; then
  SERVICE_WAS_ACTIVE=true
fi
SNAPSHOTS_WERE_PRESENT=false
if [[ -d "$DATADIR/snapshots" && ! -L "$DATADIR/snapshots" ]]; then
  SNAPSHOTS_WERE_PRESENT=true
elif [[ -e "$DATADIR/snapshots" ]]; then
  fail "existing snapshots path is not a plain directory"
fi
clear_directory "$BACKUP" "rollback directory"
write_transaction "prepared"

"$SYSTEMCTL_BIN" stop "$SERVICE"
SERVICE_STOPPED=true
write_transaction "swapping"
mv "$DATADIR/idenachain.db" "$BACKUP/idenachain.db"
mv "$DATADIR/ipfs/badgerds" "$BACKUP/ipfs-badgerds"
if [[ "$SNAPSHOTS_WERE_PRESENT" == "true" ]]; then
  mv "$DATADIR/snapshots" "$BACKUP/snapshots"
fi
mv "$INBOX/idenachain.db" "$DATADIR/idenachain.db"
mv "$INBOX/ipfs-badgerds" "$DATADIR/ipfs/badgerds"
mv "$INBOX/snapshots" "$DATADIR/snapshots"
chown -R -h "$service_user:$service_group" \
  "$DATADIR/idenachain.db" "$DATADIR/ipfs/badgerds" "$DATADIR/snapshots"
fsync_directory "$DATADIR"
fsync_directory "$DATADIR/ipfs"
fsync_directory "$BACKUP"
fsync_directory "$INBOX"

after_digest="$(key_digest)"
[[ "$before_digest" == "$after_digest" ]] || fail "Pi key hashes changed during public-state import"
write_transaction "running"
"$SYSTEMCTL_BIN" start "$SERVICE"
SERVICE_STOPPED=false
VALIDATED_HEIGHT="$(wait_for_imported_height)"
[[ "$VALIDATED_HEIGHT" =~ ^[0-9]+$ && "$VALIDATED_HEIGHT" -ge "$SOURCE_HEIGHT" ]] \
  || fail "RPC validation returned an invalid height"
write_transaction "committed" "$VALIDATED_HEIGHT"
finalize_success
trap - EXIT INT TERM
