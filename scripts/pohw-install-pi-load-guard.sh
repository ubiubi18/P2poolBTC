#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [[ "$(id -u)" != "0" ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

for source in \
  "$ROOT_DIR/deploy/systemd/idena-pi-resource.conf" \
  "$ROOT_DIR/deploy/systemd/bitcoind-mainnet-remote-only.conf" \
  "$ROOT_DIR/deploy/systemd/pohw-pi-observer-only.conf" \
  "$ROOT_DIR/deploy/systemd/pohw-zram.service" \
  "$ROOT_DIR/scripts/pohw-zram.sh"
do
  if [[ ! -f "$source" || -L "$source" ]]; then
    echo "Required load-guard source is missing or symlinked: $source" >&2
    exit 1
  fi
done

install -D -m 0644 \
  "$ROOT_DIR/deploy/systemd/idena-pi-resource.conf" \
  /etc/systemd/system/idena.service.d/30-pi-resource.conf
install -D -m 0644 \
  "$ROOT_DIR/deploy/systemd/bitcoind-mainnet-remote-only.conf" \
  /etc/systemd/system/bitcoind-mainnet.service.d/30-remote-only.conf
install -D -m 0644 \
  "$ROOT_DIR/deploy/systemd/pohw-zram.service" \
  /etc/systemd/system/pohw-zram.service
install -D -m 0755 "$ROOT_DIR/scripts/pohw-zram.sh" /usr/local/libexec/pohw-zram

mkdir -p /etc/pohw
rm -f /etc/pohw/enable-local-bitcoin
rm -f \
  /etc/pohw/enable-experiment-0-fork \
  /etc/pohw/enable-experiment-0-mining \
  /etc/pohw/enable-experiment-1-mining \
  /etc/pohw/enable-pi-local-pohw-runtime

observer_only_units=(
  bitcoind-mainnet.service
  bitcoind-pohw-experiment-1.service
  pohw-fork-chain-node.service
  pohw-gossip-mesh.service
  pohw-mining-adapter.service
)
systemctl disable --now "${observer_only_units[@]}" >/dev/null 2>&1 || true
for unit in "${observer_only_units[@]}"; do
  install -D -m 0644 \
    "$ROOT_DIR/deploy/systemd/pohw-pi-observer-only.conf" \
    "/etc/systemd/system/${unit}.d/90-pi-observer-only.conf"
done
systemctl disable --now \
  pohw-auto-bootstrap.timer \
  pohw-bitcoin-pressure-guard.timer \
  pohw-idena-priority-guard.timer >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now pohw-zram.service

if systemctl is-active --quiet idena.service; then
  systemctl set-property --runtime idena.service \
    CPUQuota=250% \
    CPUWeight=80 \
    IOWeight=50 \
    MemoryHigh=2300M \
    MemoryMax=3000M \
    MemorySwapMax=768M \
    TasksMax=512
  idena_pid="$(systemctl show --property=MainPID --value idena.service)"
  if [[ "$idena_pid" =~ ^[1-9][0-9]*$ ]]; then
    renice 5 --pid "$idena_pid" >/dev/null
  fi
fi

echo "Pi load guard installed."
echo "Pi observer-only mode is active; local Bitcoin, fork, gossip, and mining units are gated."
echo "Use Hetzner for Experiment 1 and create no local-runtime marker without a capacity review."
