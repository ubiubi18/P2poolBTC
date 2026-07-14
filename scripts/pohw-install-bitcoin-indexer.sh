#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${POHW_BITCOIN_INDEX_ENV_FILE:-/etc/pohw/bitcoin-indexer.env}"
SOURCE_BINARY="${POHW_ELECTRS_SOURCE_BINARY:-$ROOT_DIR/.build/electrs/target/release/electrs}"
DEST_BINARY="/usr/local/libexec/pohw/electrs"
SERVICE_USER="pohw-bitcoin-index"
UNIT="pohw-bitcoin-indexer.service"
ACTIVATE=0

usage() {
  cat <<EOF
Usage: sudo $0 [--activate] [--binary PATH]

Install the pinned host-only Bitcoin history indexer. Build it first as an
unprivileged user with scripts/pohw-build-bitcoin-indexer.sh. --activate starts
the multi-hour initial index after installing the hardened service.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --activate) ACTIVATE=1; shift ;;
    --binary)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      SOURCE_BINARY=$2
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

fail() { echo "$*" >&2; exit 1; }
[[ "$(id -u)" == "0" ]] || fail "Run as root, for example: sudo $0"
[[ "$ROOT_DIR" == "/opt/p2pool" ]] || fail "Run from the protected runtime checkout at /opt/p2pool"
[[ -f "$SOURCE_BINARY" && -x "$SOURCE_BINARY" && ! -L "$SOURCE_BINARY" ]] \
  || fail "Built electrs binary is missing, non-executable, or symlinked: $SOURCE_BINARY"
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || fail "Missing real environment file: $ENV_FILE"
[[ "$(stat -c %U -- "$ENV_FILE")" == "root" ]] || fail "$ENV_FILE must be root-owned"
env_mode="$(stat -c %a -- "$ENV_FILE")"
(( (8#$env_mode & 8#022) == 0 )) || fail "$ENV_FILE must not be group/world writable"
python3 - "$ENV_FILE" <<'PY'
import re
import sys
from pathlib import Path

allowed = {
    "POHW_ELECTRS_BIN",
    "POHW_BITCOIN_INDEX_DB_DIR",
    "POHW_BITCOIN_INDEX_DAEMON_DIR",
    "POHW_BITCOIN_INDEX_BLOCKS_DIR",
    "POHW_BITCOIN_INDEX_DAEMON_RPC_ADDR",
    "POHW_BITCOIN_INDEX_ELECTRUM_ADDR",
    "POHW_BITCOIN_INDEX_HTTP_ADDR",
    "POHW_BITCOIN_INDEX_MONITORING_ADDR",
}
assignment = re.compile(r"^([A-Z][A-Z0-9_]*)=([^\s\"']+)$")
seen = set()
for number, raw in enumerate(Path(sys.argv[1]).read_text(encoding="utf-8").splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    match = assignment.fullmatch(line)
    if not match or match.group(1) not in allowed or match.group(1) in seen:
        raise SystemExit(f"invalid Bitcoin indexer environment line {number}")
    seen.add(match.group(1))
PY
getent group bitcoin >/dev/null || fail "Required bitcoin group is missing"

if ! getent passwd "$SERVICE_USER" >/dev/null; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin "$SERVICE_USER"
fi
usermod -a -G bitcoin "$SERVICE_USER"
account="$(getent passwd "$SERVICE_USER")"
[[ "$(cut -d: -f6 <<< "$account")" == "/nonexistent" ]] || fail "$SERVICE_USER has an unexpected home"
[[ "$(cut -d: -f7 <<< "$account")" == "/usr/sbin/nologin" ]] || fail "$SERVICE_USER has an unexpected shell"

env_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE"
}
DB_DIR="$(env_value POHW_BITCOIN_INDEX_DB_DIR)"
DAEMON_DIR="$(env_value POHW_BITCOIN_INDEX_DAEMON_DIR)"
[[ -n "$DB_DIR" && -n "$DAEMON_DIR" ]] \
  || fail "Bitcoin indexer environment is missing required paths"
[[ "$DB_DIR" == /srv/bitcoin/* && "$DAEMON_DIR" == /srv/bitcoin/* ]] \
  || fail "Indexer data paths must stay under /srv/bitcoin"
[[ -d "$DAEMON_DIR" && ! -L "$DAEMON_DIR" && "$(realpath -e -- "$DAEMON_DIR")" == "$DAEMON_DIR" ]] \
  || fail "Bitcoin source path is missing, symlinked, or non-canonical: $DAEMON_DIR"
if [[ -e "$DB_DIR" ]]; then
  [[ -d "$DB_DIR" && ! -L "$DB_DIR" && "$(realpath -e -- "$DB_DIR")" == "$DB_DIR" ]] \
    || fail "Indexer database path is not a real canonical directory: $DB_DIR"
else
  install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DB_DIR"
fi
chown "$SERVICE_USER:$SERVICE_USER" "$DB_DIR"
chmod 0700 "$DB_DIR"
available_kib="$(df -Pk "$DB_DIR" | awk 'NR == 2 {print $4}')"
(( available_kib >= 2 * 1024 * 1024 * 1024 )) \
  || fail "Indexer volume needs at least 2 TiB free for the initial light-mode index and compaction"
runuser -u "$SERVICE_USER" -- test -r "$DAEMON_DIR/.cookie" \
  || fail "$SERVICE_USER cannot read the Bitcoin RPC cookie through the bitcoin group; set rpccookieperms=group in Bitcoin Core and restart it"
runuser -u "$SERVICE_USER" -- test -w "$DB_DIR" \
  || fail "$SERVICE_USER cannot write the index database"

install -d -m 0755 -o root -g root /usr/local/libexec/pohw
install -m 0755 -o root -g root "$SOURCE_BINARY" "$DEST_BINARY.new"
"$DEST_BINARY.new" --version >/dev/null
mv -f "$DEST_BINARY.new" "$DEST_BINARY"

source_unit="$ROOT_DIR/deploy/systemd/$UNIT"
[[ -f "$source_unit" && ! -L "$source_unit" ]] || fail "Missing service unit: $source_unit"
stage="$(mktemp /run/pohw-bitcoin-indexer.XXXXXX.service)"
backup=""
cleanup() { rm -f "$stage"; }
trap cleanup EXIT
install -m 0644 -o root -g root "$source_unit" "$stage"
systemd-analyze verify "$stage"
if [[ -e "/etc/systemd/system/$UNIT" ]]; then
  backup="$(mktemp /run/pohw-bitcoin-indexer-backup.XXXXXX.service)"
  cp -a "/etc/systemd/system/$UNIT" "$backup"
fi

rollback_unit() {
  systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
  if [[ -n "$backup" ]]; then
    cp -a "$backup" "/etc/systemd/system/$UNIT"
  else
    rm -f "/etc/systemd/system/$UNIT"
  fi
  systemctl daemon-reload
}

install -m 0644 -o root -g root "$stage" "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemd-analyze verify "$UNIT"

if [[ "$ACTIVATE" == "1" ]]; then
  if ! systemctl enable --now "$UNIT"; then
    rollback_unit
    fail "Indexer failed to activate; previous unit restored"
  fi
  sleep 5
  if ! systemctl is-active --quiet "$UNIT"; then
    journalctl -u "$UNIT" -n 20 --no-pager >&2 || true
    rollback_unit
    fail "Indexer did not remain active; previous unit restored"
  fi
  echo "Bitcoin history indexer is active; initial indexing continues in the background."
else
  echo "Bitcoin history indexer installed but not started."
fi
rm -f "$backup"
