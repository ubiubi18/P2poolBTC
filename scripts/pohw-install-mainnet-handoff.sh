#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ENABLE=false
P2POOL_BIN="$ROOT_DIR/target/release/p2pool-node"
RUNTIME_DIR=/usr/local/libexec/pohw

usage() {
  cat <<'EOF'
Usage: sudo scripts/pohw-install-mainnet-handoff.sh [--enable] [--p2pool-bin PATH]

Installs the one-way 20-participant fork-to-mainnet controller. --enable starts
the timer; the controller still stays disarmed until /etc/pohw/p2pool.env has
both POHW_MAINNET_HANDOFF_ENABLED=true and the documented acknowledgement.
The default p2pool-node source is target/release/p2pool-node.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable)
      ENABLE=true
      shift
      ;;
    --p2pool-bin)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--p2pool-bin requires a path." >&2
        exit 2
      fi
      P2POOL_BIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$(id -u)" != "0" ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

required=(
  "$ROOT_DIR/scripts/pohw-mainnet-handoff.py"
  "$ROOT_DIR/deploy/systemd/pohw-mainnet-handoff.service"
  "$ROOT_DIR/deploy/systemd/pohw-mainnet-handoff.timer"
  "$ROOT_DIR/deploy/systemd/pohw-mining-mainnet-handoff.conf"
  "$ROOT_DIR/deploy/systemd/pohw-fork-mainnet-handoff.conf"
)
for source in "${required[@]}"; do
  if [[ ! -f "$source" || -L "$source" ]]; then
    echo "Required handoff file is missing or symlinked: $source" >&2
    exit 1
  fi
done
if [[ ! -f "$P2POOL_BIN" || -L "$P2POOL_BIN" || ! -x "$P2POOL_BIN" ]]; then
  echo "Release p2pool-node is missing, symlinked, or not executable: $P2POOL_BIN" >&2
  echo "Build it with: cargo build --release -p p2pool-node" >&2
  exit 1
fi

install -d -m 0755 -o root -g root "$RUNTIME_DIR"
install -m 0755 -o root -g root "$ROOT_DIR/scripts/pohw-mainnet-handoff.py" \
  "$RUNTIME_DIR/pohw-mainnet-handoff.py"
install -m 0755 -o root -g root "$P2POOL_BIN" \
  "$RUNTIME_DIR/p2pool-node-mainnet-handoff"
install -d -m 0700 /var/lib/pohw-p2pool/mainnet-handoff
install -d -m 0755 /etc/systemd/system/pohw-mining-adapter.service.d
install -d -m 0755 /etc/systemd/system/pohw-fork-chain-node.service.d
install -m 0644 "$ROOT_DIR/deploy/systemd/pohw-mainnet-handoff.service" \
  /etc/systemd/system/pohw-mainnet-handoff.service
install -m 0644 "$ROOT_DIR/deploy/systemd/pohw-mainnet-handoff.timer" \
  /etc/systemd/system/pohw-mainnet-handoff.timer
install -m 0644 "$ROOT_DIR/deploy/systemd/pohw-mining-mainnet-handoff.conf" \
  /etc/systemd/system/pohw-mining-adapter.service.d/20-mainnet-handoff.conf
install -m 0644 "$ROOT_DIR/deploy/systemd/pohw-fork-mainnet-handoff.conf" \
  /etc/systemd/system/pohw-fork-chain-node.service.d/20-mainnet-handoff.conf

systemctl daemon-reload
if [[ "$ENABLE" == "true" ]]; then
  systemctl enable --now pohw-mainnet-handoff.timer
  echo "Mainnet handoff timer installed and enabled."
else
  systemctl disable --now pohw-mainnet-handoff.timer >/dev/null 2>&1 || true
  echo "Mainnet handoff controller installed but timer remains disabled."
fi

echo "The canonical trigger is fixed at 20 distinct active Idena identities."
