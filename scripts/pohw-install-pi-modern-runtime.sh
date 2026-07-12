#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${POHW_RUNTIME_DIR:-/opt/p2pool}"
STATE_DIR="${POHW_STATE_DIR:-/var/lib/pohw-p2pool}"
MODERN_IDENA_BIN="${IDENA_MODERN_BIN:-/usr/local/libexec/idena-node-modern}"
IDENA_DATADIR="${IDENA_DATADIR:-/var/lib/idena}"

UNITS=(
  idena.service
  idena-reward-indexer.service
  idena-session-recorder.service
  pohw-idena-snapshot.service
  pohw-health-status.service
)
SOURCES=(
  "$ROOT_DIR/deploy/systemd/idena-modern-sdcard.service"
  "$ROOT_DIR/deploy/systemd/idena-reward-indexer-sdcard.service"
  "$ROOT_DIR/deploy/systemd/idena-session-recorder-sdcard.service"
  "$ROOT_DIR/deploy/systemd/pohw-idena-snapshot-sdcard.service"
  "$ROOT_DIR/deploy/systemd/pohw-health-status-sdcard.service"
)
LEGACY_DROPINS=(
  /etc/systemd/system/idena.service.d/20-restart.conf
  /etc/systemd/system/idena.service.d/30-hardening.conf
  /etc/systemd/system/idena.service.d/40-extra-hardening.conf
  /etc/systemd/system/idena.service.d/50-sdcard.conf
  /etc/systemd/system/idena.service.d/60-sdcard-modern.conf
  /etc/systemd/system/idena-reward-indexer.service.d/60-sdcard-modern.conf
  /etc/systemd/system/idena-session-recorder.service.d/60-sdcard-modern.conf
  /etc/systemd/system/pohw-idena-snapshot.service.d/60-sdcard-modern.conf
  /etc/systemd/system/pohw-health-status.service.d/50-bitcoin-wd.conf
  /etc/systemd/system/pohw-health-status.service.d/60-sdcard-modern.conf
)

if [[ "$(id -u)" != "0" ]]; then
  echo "Run as root, for example: sudo $0" >&2
  exit 1
fi

for path in "$ROOT_DIR" "$RUNTIME_DIR" "$STATE_DIR" "$IDENA_DATADIR"; do
  if [[ -L "$path" ]]; then
    echo "Refusing symlinked deployment path: $path" >&2
    exit 1
  fi
done

if [[ "$ROOT_DIR" != "$RUNTIME_DIR" ]]; then
  echo "Run this installer from the protected runtime checkout at $RUNTIME_DIR" >&2
  exit 1
fi
unsafe_runtime_entry="$(
  find "$RUNTIME_DIR" -xdev \( -type l -o ! -uid 0 -o -perm /022 \) -print -quit
)"
if [[ -n "$unsafe_runtime_entry" ]]; then
  echo "Runtime checkout contains a symlink, non-root owner, or writable entry: $unsafe_runtime_entry" >&2
  exit 1
fi
if [[ ! -x "$MODERN_IDENA_BIN" ]]; then
  echo "Modern Idena binary is missing or not executable: $MODERN_IDENA_BIN" >&2
  exit 1
fi
if [[ "$(cat "$IDENA_DATADIR/ipfs/version")" != "18" ]]; then
  echo "Idena IPFS repository must be migrated to version 18 before installing runtime overrides." >&2
  exit 1
fi

install -d -m 0755 -o root -g root "$STATE_DIR"
install -d -m 0750 -o ubuntu -g ubuntu \
  "$STATE_DIR/health" \
  "$STATE_DIR/rewards" \
  "$STATE_DIR/rewards/rolling" \
  "$STATE_DIR/idena-session-recorder" \
  "$STATE_DIR/snapshots"
install -d -m 0700 -o root -g root "$STATE_DIR/runtime-backup"

TXN_DIR="$(mktemp -d /run/pohw-modern-runtime.XXXXXX)"
STAGE_DIR="$TXN_DIR/stage"
BACKUP_DIR="$TXN_DIR/backup"
install -d -m 0700 -o root -g root "$STAGE_DIR" "$BACKUP_DIR"

MUTATED=0
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
  if [[ ! -f "$source" || -L "$source" ]]; then
    echo "Unit source is not a regular file: $source" >&2
    false
  fi
  install -m 0644 -o root -g root "$source" "$STAGE_DIR/$unit"
  STAGED_UNITS+=("$STAGE_DIR/$unit")
done

# Verify the complete replacement set before changing live systemd state.
systemd-analyze verify "${STAGED_UNITS[@]}"

for unit in "${UNITS[@]}"; do
  target="/etc/systemd/system/$unit"
  persistent_backup="$STATE_DIR/runtime-backup/$unit"
  if [[ -e "$target" || -L "$target" ]]; then
    cp -a "$target" "$BACKUP_DIR/$unit"
    if [[ ! -f "$persistent_backup" ]]; then
      install -m 0600 -o root -g root "$target" "$persistent_backup"
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
for unit in "${UNITS[@]}"; do
  install -m 0644 -o root -g root "$STAGE_DIR/$unit" "/etc/systemd/system/$unit"
done

# List-valued mount dependencies from legacy units cannot be reliably removed
# by a later drop-in. Remove only known obsolete overrides after preserving
# each original base unit above.
rm -f "${LEGACY_DROPINS[@]}"

for unit in "${UNITS[@]}"; do
  unsafe_dropin="$(
    find "/etc/systemd/system/$unit.d" -maxdepth 1 \
      \( -type l -o \( -type f \( ! -uid 0 -o -perm /022 \) \) \) \
      -print -quit 2>/dev/null || true
  )"
  if [[ -n "$unsafe_dropin" ]]; then
    echo "$unit has an unsafe non-root, writable, or symlinked drop-in: $unsafe_dropin" >&2
    false
  fi
done

systemctl daemon-reload
systemd-analyze verify "${UNITS[@]}"

for unit in "${UNITS[@]}"; do
  if systemctl show "$unit" --property=RequiresMountsFor --value \
    | grep -Eq 'mnt-(ssd|bitcoin)|home-ubuntu'; then
    echo "$unit still depends on a legacy runtime path." >&2
    false
  fi
done

MUTATED=0
trap - ERR INT TERM
rm -rf "$TXN_DIR"

cat <<EOF
Modern Pi runtime overrides installed.

No disabled service was enabled automatically. Validate first:
  systemctl restart idena.service
  systemctl start pohw-health-status.service
  journalctl -u idena.service -n 100 --no-pager
EOF
