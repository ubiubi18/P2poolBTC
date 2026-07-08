#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
DATADIR="${POHW_DATADIR:-/mnt/ssd/pohw-p2pool}"
NETWORK_WATCHDOG_DIR="${POHW_NETWORK_WATCHDOG_STATE_DIR:-$DATADIR/network-watchdog}"

if [[ "$(id -u)" != "0" ]]; then
  echo "Run as root, for example: sudo $0" >&2
  exit 1
fi

if [[ ! -d "$WORKDIR" ]]; then
  echo "PoHW workdir does not exist: $WORKDIR" >&2
  exit 1
fi

install -d -m 700 -o root -g root "$NETWORK_WATCHDOG_DIR"
install -d -m 755 /etc/systemd/system /etc/systemd/system.conf.d
install -m 644 "$WORKDIR/deploy/systemd/pohw-network-watchdog.service" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-network-watchdog.timer" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/system.conf.d/10-pohw-watchdog.conf" /etc/systemd/system.conf.d/

systemctl daemon-reload
systemctl enable --now pohw-network-watchdog.timer

cat <<EOF
PoHW self-recovery installed.

Network watchdog:
  systemctl status pohw-network-watchdog.timer
  journalctl -u pohw-network-watchdog.service -n 50 --no-pager
  status file: $NETWORK_WATCHDOG_DIR/status.json

Hardware watchdog:
  config: /etc/systemd/system.conf.d/10-pohw-watchdog.conf
  active after the next reboot, or after: sudo systemctl daemon-reexec
EOF
