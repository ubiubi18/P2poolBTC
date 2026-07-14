#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FORK_UNIT="pohw-fork-chain-node.service"
MINING_UNIT="pohw-mining-adapter.service"
FORK_MARKER="/etc/pohw/enable-experiment-0-fork"
MINING_MARKER="/etc/pohw/enable-experiment-0-mining"

if [[ "$(id -u)" != "0" ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

for source in \
  "$ROOT_DIR/deploy/systemd/pohw-fork-chain-manual-approval.conf" \
  "$ROOT_DIR/deploy/systemd/pohw-mining-manual-approval.conf"
do
  if [[ ! -f "$source" || -L "$source" ]]; then
    echo "Required launch-gate source is missing or symlinked: $source" >&2
    exit 1
  fi
done

systemctl disable --now "$MINING_UNIT" "$FORK_UNIT" >/dev/null 2>&1 || true

install -d -m 0755 /etc/pohw \
  "/etc/systemd/system/$FORK_UNIT.d" \
  "/etc/systemd/system/$MINING_UNIT.d"
install -m 0644 \
  "$ROOT_DIR/deploy/systemd/pohw-fork-chain-manual-approval.conf" \
  "/etc/systemd/system/$FORK_UNIT.d/10-manual-approval.conf"
install -m 0644 \
  "$ROOT_DIR/deploy/systemd/pohw-mining-manual-approval.conf" \
  "/etc/systemd/system/$MINING_UNIT.d/10-manual-approval.conf"

rm -f "$FORK_MARKER" "$MINING_MARKER"
systemctl daemon-reload
systemctl reset-failed "$FORK_UNIT" "$MINING_UNIT" >/dev/null 2>&1 || true

# Exercise both start paths. Missing conditions must leave both units inactive.
systemctl start "$FORK_UNIT" "$MINING_UNIT"
for unit in "$FORK_UNIT" "$MINING_UNIT"; do
  if systemctl is-active --quiet "$unit"; then
    echo "Launch gate failed closed: $unit became active." >&2
    systemctl stop "$MINING_UNIT" "$FORK_UNIT" >/dev/null 2>&1 || true
    exit 1
  fi
done

echo "Experiment 0 launch gate installed and verified."
echo "Fork and mining approval markers are absent; both services remain stopped."
