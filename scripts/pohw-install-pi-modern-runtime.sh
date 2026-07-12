#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${POHW_RUNTIME_DIR:-/opt/p2pool}"
STATE_DIR="${POHW_STATE_DIR:-/var/lib/pohw-p2pool}"
MODERN_IDENA_BIN="${IDENA_MODERN_BIN:-/usr/local/libexec/idena-node-modern}"
IDENA_DATADIR="${IDENA_DATADIR:-/var/lib/idena}"

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
if [[ "$(stat -c %u "$RUNTIME_DIR")" != "0" ]]; then
  echo "Runtime checkout must be root-owned: $RUNTIME_DIR" >&2
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

install_dropin() {
  local unit=$1 source=$2
  local target="/etc/systemd/system/${unit}.d"
  install -d -m 0755 -o root -g root "$target"
  install -m 0644 -o root -g root "$source" "$target/60-sdcard-modern.conf"
}

install_full_unit() {
  local unit=$1 source=$2
  local target="/etc/systemd/system/$unit"
  local backup="$STATE_DIR/runtime-backup/$unit"

  if [[ -f "$target" && ! -f "$backup" ]]; then
    install -m 0600 -o root -g root "$target" "$backup"
  fi
  install -m 0644 -o root -g root "$source" "$target"
}

install_dropin idena.service "$ROOT_DIR/deploy/systemd/idena-modern-sdcard.conf"
install_dropin idena-reward-indexer.service "$ROOT_DIR/deploy/systemd/idena-reward-indexer-sdcard.conf"
install_dropin idena-session-recorder.service "$ROOT_DIR/deploy/systemd/idena-session-recorder-sdcard.conf"
install_dropin pohw-idena-snapshot.service "$ROOT_DIR/deploy/systemd/pohw-idena-snapshot-sdcard.conf"
install_full_unit pohw-health-status.service "$ROOT_DIR/deploy/systemd/pohw-health-status-sdcard.service"

# RequiresMountsFor dependencies from the legacy SSD drop-ins cannot be
# reliably removed by a later drop-in. Remove only the two known obsolete
# overrides after preserving the original base unit above.
rm -f \
  /etc/systemd/system/pohw-health-status.service.d/50-bitcoin-wd.conf \
  /etc/systemd/system/pohw-health-status.service.d/60-sdcard-modern.conf

systemctl daemon-reload
systemd-analyze verify \
  idena.service \
  idena-reward-indexer.service \
  idena-session-recorder.service \
  pohw-idena-snapshot.service \
  pohw-health-status.service

if systemctl show pohw-health-status.service --property=RequiresMountsFor --value \
  | grep -Eq 'mnt-(ssd|bitcoin)'; then
  echo "Health service still depends on a legacy SSD mount." >&2
  exit 1
fi

cat <<EOF
Modern Pi runtime overrides installed.

No disabled service was enabled automatically. Validate first:
  systemctl restart idena.service
  systemctl start pohw-health-status.service
  journalctl -u idena.service -n 100 --no-pager
EOF
