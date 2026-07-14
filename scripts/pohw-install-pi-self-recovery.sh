#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/opt/p2pool}"
NETWORK_WATCHDOG_DIR="/var/lib/pohw/network-watchdog"
BITCOIN_PRESSURE_DIR="/var/lib/pohw/bitcoin-pressure"
IDENA_PRIORITY_DIR="/var/lib/pohw/idena-priority"
IDENA_WORKERS_DIR="/var/lib/pohw/idena-workers"
RUNTIME_DIR="/usr/local/libexec/pohw"
CONFIG_DIR="/etc/pohw"
CONFIG_FILE="$CONFIG_DIR/p2pool.env"
ENABLE_IDENA_PRIORITY_GUARD="${POHW_INSTALL_ENABLE_IDENA_PRIORITY_GUARD:-false}"
ENABLE_BITCOIN_PRESSURE_GUARD="${POHW_INSTALL_ENABLE_BITCOIN_PRESSURE_GUARD:-false}"
ENABLE_IDENA_WORKERS_WATCHER="${POHW_INSTALL_ENABLE_IDENA_WORKERS_WATCHER:-false}"

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
  esac
  return 1
}

if [[ "$(id -u)" != "0" ]]; then
  echo "Run as root, for example: sudo $0" >&2
  exit 1
fi

if [[ ! -d "$WORKDIR" ]]; then
  echo "PoHW workdir does not exist: $WORKDIR" >&2
  exit 1
fi

for source in \
  "$WORKDIR/scripts/pohw-network-watchdog.sh" \
  "$WORKDIR/scripts/pohw-bitcoin-pressure-guard.py" \
  "$WORKDIR/scripts/pohw-idena-priority-guard.py" \
  "$WORKDIR/scripts/pohw-idena-workers-if-synced.py" \
  "$WORKDIR/pohw_idena_rpc/__init__.py" \
  "$WORKDIR/pohw_idena_rpc/idena_rpc_client_minimal.py"; do
  if [[ -L "$source" || ! -f "$source" ]]; then
    echo "Required runtime source is not a regular non-symlink file: $source" >&2
    exit 1
  fi
done

unsafe_runtime_entry="$(
  find "$WORKDIR" -xdev \( -type l -o ! -uid 0 -o -perm /022 \) -print -quit
)"
if [[ -n "$unsafe_runtime_entry" ]]; then
  echo "Privileged runtime checkout contains a symlink, non-root owner, or writable entry: $unsafe_runtime_entry" >&2
  exit 1
fi

for privileged_dir in \
  /usr/local \
  /usr/local/libexec \
  "$RUNTIME_DIR" \
  "$RUNTIME_DIR/pohw_idena_rpc" \
  /var/lib \
  /var/lib/pohw \
  "$NETWORK_WATCHDOG_DIR" \
  "$BITCOIN_PRESSURE_DIR" \
  "$IDENA_PRIORITY_DIR" \
  "$IDENA_WORKERS_DIR" \
  "$CONFIG_DIR"; do
  if [[ -L "$privileged_dir" ]]; then
    echo "Refusing symlinked privileged directory: $privileged_dir" >&2
    exit 1
  fi
done

install -d -m 755 -o root -g root "$CONFIG_DIR"

if [[ -L "$CONFIG_FILE" ]]; then
  echo "Refusing symlinked PoHW environment file: $CONFIG_FILE" >&2
  exit 1
fi
if [[ -e "$CONFIG_FILE" ]]; then
  chown root:root "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
fi

install -d -m 700 -o root -g root /var/lib/pohw
install -d -m 700 -o root -g root "$NETWORK_WATCHDOG_DIR"
install -d -m 700 -o root -g root "$BITCOIN_PRESSURE_DIR"
install -d -m 700 -o root -g root "$IDENA_PRIORITY_DIR"
install -d -m 700 -o root -g root "$IDENA_WORKERS_DIR"
install -d -m 755 -o root -g root /usr/local/libexec
install -d -m 755 -o root -g root "$RUNTIME_DIR" "$RUNTIME_DIR/pohw_idena_rpc"
install -m 755 -o root -g root "$WORKDIR/scripts/pohw-network-watchdog.sh" "$RUNTIME_DIR/"
install -m 755 -o root -g root "$WORKDIR/scripts/pohw-bitcoin-pressure-guard.py" "$RUNTIME_DIR/"
install -m 755 -o root -g root "$WORKDIR/scripts/pohw-idena-priority-guard.py" "$RUNTIME_DIR/"
install -m 755 -o root -g root "$WORKDIR/scripts/pohw-idena-workers-if-synced.py" "$RUNTIME_DIR/"
install -m 644 -o root -g root "$WORKDIR/pohw_idena_rpc/__init__.py" "$RUNTIME_DIR/pohw_idena_rpc/"
install -m 644 -o root -g root "$WORKDIR/pohw_idena_rpc/idena_rpc_client_minimal.py" "$RUNTIME_DIR/pohw_idena_rpc/"
install -d -m 755 /etc/systemd/system /etc/systemd/system.conf.d
install -m 644 "$WORKDIR/deploy/systemd/pohw-network-watchdog.service" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-network-watchdog.timer" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-idena-priority-guard.service" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-idena-priority-guard.timer" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-bitcoin-pressure-guard.service" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-bitcoin-pressure-guard.timer" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-idena-workers-if-synced.service" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/pohw-idena-workers-if-synced.timer" /etc/systemd/system/
install -m 644 "$WORKDIR/deploy/systemd/system.conf.d/10-pohw-watchdog.conf" /etc/systemd/system.conf.d/

systemctl daemon-reload
systemctl enable --now pohw-network-watchdog.timer

idena_guard_note="installed; existing enablement left unchanged (explicit opt-in required to enable)"
if is_truthy "$ENABLE_IDENA_PRIORITY_GUARD"; then
  systemctl enable --now pohw-idena-priority-guard.timer
  idena_guard_note="enabled by POHW_INSTALL_ENABLE_IDENA_PRIORITY_GUARD"
fi

pressure_guard_note="installed; existing enablement left unchanged (explicit opt-in required to enable)"
if is_truthy "$ENABLE_BITCOIN_PRESSURE_GUARD"; then
  systemctl enable --now pohw-bitcoin-pressure-guard.timer
  pressure_guard_note="enabled by POHW_INSTALL_ENABLE_BITCOIN_PRESSURE_GUARD"
fi

idena_workers_note="installed; existing enablement left unchanged (explicit opt-in required to enable)"
if is_truthy "$ENABLE_IDENA_WORKERS_WATCHER"; then
  systemctl enable --now pohw-idena-workers-if-synced.timer
  idena_workers_note="enabled by POHW_INSTALL_ENABLE_IDENA_WORKERS_WATCHER"
fi

cat <<EOF
PoHW self-recovery installed.

Privileged runtime:
  $RUNTIME_DIR (root-owned; services do not execute the writable checkout)

Network watchdog:
  systemctl status pohw-network-watchdog.timer
  journalctl -u pohw-network-watchdog.service -n 50 --no-pager
  status file: $NETWORK_WATCHDOG_DIR/status.json

Bitcoin pressure guard:
  install state: $pressure_guard_note
  systemctl status pohw-bitcoin-pressure-guard.timer
  journalctl -u pohw-bitcoin-pressure-guard.service -n 50 --no-pager
  status file: $BITCOIN_PRESSURE_DIR/status.json

Idena priority guard:
  install state: $idena_guard_note
  systemctl status pohw-idena-priority-guard.timer
  journalctl -u pohw-idena-priority-guard.service -n 50 --no-pager
  status file: $IDENA_PRIORITY_DIR/status.json

Idena worker watcher:
  install state: $idena_workers_note
  systemctl status pohw-idena-workers-if-synced.timer
  journalctl -u pohw-idena-workers-if-synced.service -n 50 --no-pager
  status file: $IDENA_WORKERS_DIR/status.json

Hardware watchdog:
  config: /etc/systemd/system.conf.d/10-pohw-watchdog.conf
  active after the next reboot, or after: sudo systemctl daemon-reexec
EOF
