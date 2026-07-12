#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${POHW_RUNTIME_DIR:-/opt/p2pool}"
STATE_DIR="${POHW_STATE_DIR:-/var/lib/pohw-p2pool}"
RESTART_SERVICES=0

UNITS=(
  idena-bootstrap.service
  idena-original-relay.service
)
SOURCES=(
  "$ROOT_DIR/deploy/systemd/idena-hetzner-modern.service"
  "$ROOT_DIR/deploy/systemd/idena-hetzner-legacy-relay.service"
)
USERS=(
  idena-modern
  idena-relay
)
DATADIRS=(
  /srv/idena
  /srv/idena-original-relay
)
CONFIGS=(
  /etc/idena-modern/config.json
  /etc/idena-relay/config.json
)
BINARIES=(
  /usr/local/libexec/idena-node-compat-v5
  /usr/local/libexec/idena-node-1.1.2
)

usage() {
  cat <<EOF
Usage: sudo $0 [--restart]

Install the isolated Hetzner Idena units transactionally. By default, running
services are not restarted. --restart restarts only services that were already
active and rolls back both units if either service fails its health check.
EOF
}

case "${1:-}" in
  "") ;;
  --restart) RESTART_SERVICES=1 ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

fail() {
  echo "$*" >&2
  return 1
}

require_metadata() {
  local path=$1
  local expected_owner=$2
  local expected_group=$3
  local expected_mode=$4
  local expected_kind=$5
  local actual_owner actual_group actual_mode

  [[ ! -L "$path" ]] || fail "Refusing symlinked path: $path"
  case "$expected_kind" in
    directory) [[ -d "$path" ]] || fail "Required directory is missing: $path" ;;
    file) [[ -f "$path" ]] || fail "Required file is missing: $path" ;;
    executable) [[ -f "$path" && -x "$path" ]] || fail "Required executable is missing: $path" ;;
    *) fail "Unknown metadata kind: $expected_kind" ;;
  esac

  actual_owner="$(stat -c %U -- "$path")"
  actual_group="$(stat -c %G -- "$path")"
  actual_mode="$(stat -c %a -- "$path")"
  [[ "$actual_owner" == "$expected_owner" ]] \
    || fail "$path must be owned by $expected_owner"
  [[ "$actual_group" == "$expected_group" ]] \
    || fail "$path must have group $expected_group"
  [[ "$actual_mode" == "$expected_mode" ]] \
    || fail "$path must have mode $expected_mode"
}

validate_config() {
  local config=$1
  local datadir=$2
  python3 - "$config" "$datadir" <<'PY'
import json
import sys

config_path, expected_datadir = sys.argv[1:]
with open(config_path, encoding="utf-8") as handle:
    config = json.load(handle)

if config.get("DataDir") not in (None, expected_datadir):
    raise SystemExit(f"{config_path}: DataDir does not match its isolated runtime")
if config.get("RPC", {}).get("HTTPHost") not in ("127.0.0.1", "::1", "localhost"):
    raise SystemExit(f"{config_path}: RPC must be bound to loopback")
PY
}

if [[ "$(id -u)" != "0" ]]; then
  fail "Run as root, for example: sudo $0"
  exit 1
fi
if [[ "$ROOT_DIR" != "$RUNTIME_DIR" ]]; then
  fail "Run this installer from the protected runtime checkout at $RUNTIME_DIR"
  exit 1
fi
for path in "$ROOT_DIR" "$RUNTIME_DIR" "$STATE_DIR"; do
  if [[ -L "$path" ]]; then
    fail "Refusing symlinked deployment path: $path"
    exit 1
  fi
done

unsafe_runtime_entry="$(
  find "$RUNTIME_DIR" -xdev \( -type l -o ! -uid 0 -o -perm /022 \) -print -quit
)"
if [[ -n "$unsafe_runtime_entry" ]]; then
  fail "Runtime checkout contains a symlink, non-root owner, or writable entry: $unsafe_runtime_entry"
  exit 1
fi

for index in "${!UNITS[@]}"; do
  user="${USERS[$index]}"
  datadir="${DATADIRS[$index]}"
  config="${CONFIGS[$index]}"
  binary="${BINARIES[$index]}"

  getent passwd "$user" >/dev/null || fail "Required system user is missing: $user"
  require_metadata "$datadir" "$user" "$user" 700 directory
  require_metadata "$(dirname "$config")" root "$user" 750 directory
  require_metadata "$config" root "$user" 640 file
  require_metadata "$binary" root root 755 executable
  validate_config "$config" "$datadir"
done

mountpoint -q /srv/idena || fail "/srv/idena must be a dedicated mount point"
[[ "$(cat /srv/idena/ipfs/version)" == "18" ]] \
  || fail "Modern Idena IPFS repository must be at version 18"
runuser -u idena-modern -- test ! -x /srv/idena-original-relay \
  || fail "idena-modern can traverse the relay data directory"
runuser -u idena-relay -- test ! -x /srv/idena \
  || fail "idena-relay can traverse the modern data directory"

install -d -m 0755 -o root -g root "$STATE_DIR"
install -d -m 0700 -o root -g root "$STATE_DIR/hetzner-runtime-backup"

TXN_DIR="$(mktemp -d /run/pohw-hetzner-idena.XXXXXX)"
STAGE_DIR="$TXN_DIR/stage"
BACKUP_DIR="$TXN_DIR/backup"
install -d -m 0700 -o root -g root "$STAGE_DIR" "$BACKUP_DIR"

MUTATED=0
declare -a ACTIVE_BEFORE=()
for index in "${!UNITS[@]}"; do
  if systemctl is-active --quiet "${UNITS[$index]}"; then
    ACTIVE_BEFORE[index]=1
  else
    ACTIVE_BEFORE[index]=0
  fi
done

rollback_transaction() {
  local rc=${1:-1}
  trap - ERR INT TERM
  if [[ "$MUTATED" == "1" ]]; then
    for unit in "${UNITS[@]}"; do
      rm -f "/etc/systemd/system/$unit"
      rm -rf "/etc/systemd/system/$unit.d"
      if [[ -e "$BACKUP_DIR/$unit" || -L "$BACKUP_DIR/$unit" ]]; then
        cp -a "$BACKUP_DIR/$unit" "/etc/systemd/system/$unit"
      fi
      if [[ -d "$BACKUP_DIR/$unit.d" ]]; then
        cp -a "$BACKUP_DIR/$unit.d" "/etc/systemd/system/$unit.d"
      fi
    done
    systemctl daemon-reload || true
    if [[ "$RESTART_SERVICES" == "1" ]]; then
      for index in "${!UNITS[@]}"; do
        if [[ "${ACTIVE_BEFORE[index]}" == "1" ]]; then
          systemctl restart "${UNITS[$index]}" || true
        fi
      done
    fi
  fi
  rm -rf "$TXN_DIR"
  exit "$rc"
}
trap 'rollback_transaction $?' ERR
trap 'rollback_transaction 130' INT
trap 'rollback_transaction 143' TERM

STAGED_UNITS=()
for index in "${!UNITS[@]}"; do
  unit="${UNITS[$index]}"
  source="${SOURCES[$index]}"
  [[ -f "$source" && ! -L "$source" ]] \
    || fail "Unit source is not a regular file: $source"
  install -m 0644 -o root -g root "$source" "$STAGE_DIR/$unit"
  STAGED_UNITS+=("$STAGE_DIR/$unit")
done
systemd-analyze verify "${STAGED_UNITS[@]}"

for unit in "${UNITS[@]}"; do
  target="/etc/systemd/system/$unit"
  persistent_backup="$STATE_DIR/hetzner-runtime-backup/$unit"
  if [[ -e "$target" || -L "$target" ]]; then
    cp -a "$target" "$BACKUP_DIR/$unit"
    if [[ ! -e "$persistent_backup" ]]; then
      cp -a "$target" "$persistent_backup"
    fi
  fi
  if [[ -d "$target.d" ]]; then
    cp -a "$target.d" "$BACKUP_DIR/$unit.d"
    if [[ ! -e "$persistent_backup.d" ]]; then
      cp -a "$target.d" "$persistent_backup.d"
    fi
  fi
done

MUTATED=1
for index in "${!UNITS[@]}"; do
  unit="${UNITS[$index]}"
  install -m 0644 -o root -g root "$STAGE_DIR/$unit" "/etc/systemd/system/$unit"
  rm -rf "/etc/systemd/system/$unit.d"
done
systemctl daemon-reload
systemd-analyze verify "${UNITS[@]}"

if [[ "$RESTART_SERVICES" == "1" ]]; then
  for index in "${!UNITS[@]}"; do
    unit="${UNITS[$index]}"
    if [[ "${ACTIVE_BEFORE[index]}" == "1" ]]; then
      systemctl restart "$unit"
      systemctl is-active --quiet "$unit"
    fi
  done
  sleep 5
fi

for index in "${!UNITS[@]}"; do
  unit="${UNITS[$index]}"
  expected_user="${USERS[$index]}"
  [[ "$(systemctl show "$unit" --property=User --value)" == "$expected_user" ]] \
    || fail "$unit does not use its isolated system user"
  [[ "$(systemctl show "$unit" --property=FragmentPath --value)" == "/etc/systemd/system/$unit" ]] \
    || fail "$unit is not using the installed unit"
  if [[ "$RESTART_SERVICES" == "1" && "${ACTIVE_BEFORE[index]}" == "1" ]]; then
    systemctl is-active --quiet "$unit"
  fi
done

MUTATED=0
trap - ERR INT TERM
rm -rf "$TXN_DIR"

if [[ "$RESTART_SERVICES" == "1" ]]; then
  echo "Isolated Hetzner Idena units installed and active services restarted."
else
  echo "Isolated Hetzner Idena units installed; no service was restarted or enabled."
fi
