#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="${POHW_NETWORK_WATCHDOG_STATE_DIR:-/var/lib/pohw/network-watchdog}"
TARGETS="${POHW_NETWORK_WATCHDOG_TARGETS:-}"
PING_TIMEOUT_SECONDS="${POHW_NETWORK_WATCHDOG_PING_TIMEOUT_SECONDS:-2}"
RESTART_THRESHOLD="${POHW_NETWORK_WATCHDOG_RESTART_THRESHOLD:-3}"
REBOOT_THRESHOLD="${POHW_NETWORK_WATCHDOG_REBOOT_THRESHOLD:-8}"
RESTART_SERVICES="${POHW_NETWORK_WATCHDOG_RESTART_SERVICES:-NetworkManager.service systemd-networkd.service dhcpcd.service wpa_supplicant.service}"
DRY_RUN="${POHW_NETWORK_WATCHDOG_DRY_RUN:-false}"
PING_BIN="${POHW_NETWORK_WATCHDOG_PING_BIN:-ping}"
IP_BIN="${POHW_NETWORK_WATCHDOG_IP_BIN:-ip}"
SYSTEMCTL_BIN="${POHW_NETWORK_WATCHDOG_SYSTEMCTL_BIN:-systemctl}"
LOCK_STALE_SECONDS="${POHW_NETWORK_WATCHDOG_LOCK_STALE_SECONDS:-300}"

FAILURE_COUNT_FILE="$STATE_DIR/failure-count"
RESTART_MARKER_FILE="$STATE_DIR/network-restart-attempted"
STATUS_FILE="$STATE_DIR/status.json"
LOCK_DIR="$STATE_DIR/lock"

stat_mode() {
  local path="$1"
  if stat -c %a "$path" 2>/dev/null; then
    return 0
  fi
  stat -f %Lp "$path"
}

stat_mtime_epoch() {
  local path="$1"
  if stat -c %Y "$path" 2>/dev/null; then
    return 0
  fi
  stat -f %m "$path"
}

reject_symlink_ancestor() {
  local path="$1"
  local current="$path" owner parent parent_mode parent_unsafe_bits
  current="$(cd "$(dirname "$path")" 2>/dev/null && pwd -P)/$(basename "$path")" || current="$path"
  while [[ -n "$current" && "$current" != "/" && "$current" != "." ]]; do
    if [[ -L "$current" ]]; then
      if owner="$(stat -c %u "$current" 2>/dev/null)"; then
        :
      else
        owner="$(stat -f %u "$current")"
      fi
      parent="$(dirname "$current")"
      if parent_mode="$(stat_mode "$parent")"; then
        :
      else
        echo "Could not inspect parent mode for symlinked path: $current" >&2
        exit 1
      fi
      parent_unsafe_bits=$((8#$parent_mode & 022))
      if [[ "$owner" != "0" || "$parent_unsafe_bits" != "0" ]]; then
        echo "Refusing symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
}

ensure_private_dir() {
  local dir="$1"
  if [[ -L "$dir" ]]; then
    echo "Refusing symlinked network-watchdog directory: $dir" >&2
    exit 1
  fi
  reject_symlink_ancestor "$(dirname "$dir")"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir"
  fi
  chmod 700 "$dir"
}

acquire_lock() {
  local lock_dir="$1" stale_seconds="$2" pid_file started_file mtime now age pid
  if ! is_unsigned_int "$stale_seconds"; then
    echo "POHW_NETWORK_WATCHDOG_LOCK_STALE_SECONDS must be an unsigned integer." >&2
    exit 1
  fi
  if mkdir "$lock_dir" 2>/dev/null; then
    pid_file="$lock_dir/pid"
    started_file="$lock_dir/started-at"
    printf '%s\n' "$$" > "$pid_file"
    date -u +%Y%m%dT%H%M%SZ > "$started_file"
    chmod 600 "$pid_file" "$started_file"
    trap 'rm -f "$LOCK_DIR/pid" "$LOCK_DIR/started-at"; rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT
    return 0
  fi
  if [[ -L "$lock_dir" ]]; then
    echo "Refusing symlinked network watchdog lock directory: $lock_dir" >&2
    exit 1
  fi
  if [[ ! -d "$lock_dir" ]]; then
    echo "PoHW network watchdog lock path exists but is not a directory: $lock_dir" >&2
    exit 1
  fi
  pid_file="$lock_dir/pid"
  if [[ -f "$pid_file" ]]; then
    pid="$(tr -cd '0-9' < "$pid_file" || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "PoHW network watchdog is already running: $lock_dir pid=$pid"
      exit 0
    fi
    echo "Removing stale PoHW network watchdog lock with dead pid: $lock_dir pid=${pid:-unknown}"
    rm -f "$lock_dir/pid" "$lock_dir/started-at"
    if rmdir "$lock_dir" 2>/dev/null; then
      acquire_lock "$lock_dir" "$stale_seconds"
      return 0
    fi
    echo "PoHW network watchdog lock is stale but not empty; leaving it in place: $lock_dir" >&2
    exit 0
  fi
  if ! mtime="$(stat_mtime_epoch "$lock_dir")"; then
    echo "Could not inspect network watchdog lock age; assuming it is active: $lock_dir"
    exit 0
  fi
  now="$(date +%s)"
  age=$((now - mtime))
  if (( age >= stale_seconds )); then
    echo "Removing stale PoHW network watchdog lock without pid: $lock_dir age=${age}s"
    if rmdir "$lock_dir" 2>/dev/null; then
      acquire_lock "$lock_dir" "$stale_seconds"
      return 0
    fi
    echo "PoHW network watchdog lock is stale but not empty; leaving it in place: $lock_dir" >&2
    exit 0
  fi
  echo "PoHW network watchdog is already running: $lock_dir age=${age}s"
  exit 0
}

is_unsigned_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES)
      return 0
      ;;
  esac
  return 1
}

resolve_targets() {
  local raw target
  if [[ -n "$TARGETS" ]]; then
    for raw in ${TARGETS//,/ }; do
      target="${raw#"${raw%%[![:space:]]*}"}"
      target="${target%"${target##*[![:space:]]}"}"
      if [[ -n "$target" ]]; then
        printf '%s\n' "$target"
      fi
    done
    return 0
  fi
  if command -v "$IP_BIN" >/dev/null 2>&1; then
    "$IP_BIN" route show default 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "via") print $(i+1)}' | sort -u
  fi
}

read_failure_count() {
  if [[ -f "$FAILURE_COUNT_FILE" ]]; then
    local count
    count="$(tr -cd '0-9' < "$FAILURE_COUNT_FILE" || true)"
    if [[ -n "$count" ]]; then
      printf '%s\n' "$count"
      return 0
    fi
  fi
  printf '0\n'
}

write_status() {
  local status="$1"
  local failure_count="$2"
  local detail="$3"
  shift 3
  python3 - "$STATUS_FILE" "$status" "$failure_count" "$detail" "$@" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
status = sys.argv[2]
failure_count = int(sys.argv[3])
detail = sys.argv[4]
targets = sys.argv[5:]
payload = {
    "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "status": status,
    "failureCount": failure_count,
    "detail": detail,
    "targets": targets,
}
tmp = path.with_name(f".{path.name}.tmp")
tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
tmp.chmod(0o600)
tmp.replace(path)
PY
}

restart_network_services() {
  local service restarted=0
  for service in $RESTART_SERVICES; do
    if "$SYSTEMCTL_BIN" is-active --quiet "$service" 2>/dev/null; then
      echo "Restarting active network service: $service"
      if is_truthy "$DRY_RUN"; then
        echo "Dry-run: would run $SYSTEMCTL_BIN try-restart $service"
      else
        "$SYSTEMCTL_BIN" try-restart "$service"
      fi
      restarted=1
    fi
  done
  if (( restarted == 0 )); then
    echo "No active network manager service found to restart."
  fi
}

request_reboot() {
  echo "Requesting reboot after $1 consecutive failed network checks."
  if is_truthy "$DRY_RUN"; then
    echo "Dry-run: would run $SYSTEMCTL_BIN reboot"
  else
    "$SYSTEMCTL_BIN" reboot
  fi
}

handle_failed_check() {
  local waiting_status="$1"
  local failure_detail="$2"
  shift 2
  local failure_count

  failure_count="$(read_failure_count)"
  failure_count=$((failure_count + 1))
  printf '%s\n' "$failure_count" > "$FAILURE_COUNT_FILE"
  chmod 600 "$FAILURE_COUNT_FILE"

  if (( failure_count >= REBOOT_THRESHOLD )); then
    write_status "reboot_requested" "$failure_count" "$failure_detail Reboot threshold reached." "$@"
    request_reboot "$failure_count"
    return
  fi

  if (( failure_count >= RESTART_THRESHOLD )); then
    if [[ ! -e "$RESTART_MARKER_FILE" ]]; then
      write_status "network_restart_requested" "$failure_count" "$failure_detail Restarting active network services once for this failure streak." "$@"
      restart_network_services
      date -u +%Y%m%dT%H%M%SZ > "$RESTART_MARKER_FILE"
      chmod 600 "$RESTART_MARKER_FILE"
      return
    fi
    write_status "waiting_after_network_restart" "$failure_count" "$failure_detail Network services were already restarted for this failure streak." "$@"
    echo "Network watchdog still failing after restart attempt: $failure_count/$REBOOT_THRESHOLD."
    return
  fi

  write_status "$waiting_status" "$failure_count" "$failure_detail Below recovery threshold." "$@"
  echo "Network watchdog failed $failure_count/$REBOOT_THRESHOLD checks."
}

if ! is_unsigned_int "$PING_TIMEOUT_SECONDS" || ! is_unsigned_int "$RESTART_THRESHOLD" || ! is_unsigned_int "$REBOOT_THRESHOLD"; then
  echo "Watchdog thresholds and timeout must be unsigned integers." >&2
  exit 1
fi
if (( PING_TIMEOUT_SECONDS < 1 || RESTART_THRESHOLD < 1 || REBOOT_THRESHOLD < RESTART_THRESHOLD )); then
  echo "Invalid watchdog thresholds: timeout=$PING_TIMEOUT_SECONDS restart=$RESTART_THRESHOLD reboot=$REBOOT_THRESHOLD" >&2
  exit 1
fi

ensure_private_dir "$STATE_DIR"
acquire_lock "$LOCK_DIR" "$LOCK_STALE_SECONDS"

targets=()
while IFS= read -r target; do
  if [[ -n "$target" ]]; then
    targets+=("$target")
  fi
done < <(resolve_targets)
if (( ${#targets[@]} == 0 )); then
  echo "No network watchdog targets found."
  handle_failed_check "no_targets" "No gateway or configured watchdog target was found."
  exit 0
fi

for target in "${targets[@]}"; do
  if "$PING_BIN" -c 1 -W "$PING_TIMEOUT_SECONDS" "$target" >/dev/null 2>&1; then
    printf '0\n' > "$FAILURE_COUNT_FILE"
    chmod 600 "$FAILURE_COUNT_FILE"
    rm -f "$RESTART_MARKER_FILE"
    write_status "ok" 0 "Network target responded: $target" "${targets[@]}"
    echo "Network watchdog OK: $target responded."
    exit 0
  fi
done

handle_failed_check "waiting" "All watchdog targets failed." "${targets[@]}"
