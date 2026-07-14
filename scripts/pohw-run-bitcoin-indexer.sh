#!/usr/bin/env bash
set -euo pipefail

BIN="${POHW_ELECTRS_BIN:-/usr/local/libexec/pohw/electrs}"
DB_DIR="${POHW_BITCOIN_INDEX_DB_DIR:-/srv/bitcoin/esplora-index}"
DAEMON_DIR="${POHW_BITCOIN_INDEX_DAEMON_DIR:-/srv/bitcoin/mainnet}"
DAEMON_RPC_ADDR="${POHW_BITCOIN_INDEX_DAEMON_RPC_ADDR:-127.0.0.1:8332}"
ELECTRUM_ADDR="${POHW_BITCOIN_INDEX_ELECTRUM_ADDR:-127.0.0.1:50001}"
HTTP_ADDR="${POHW_BITCOIN_INDEX_HTTP_ADDR:-127.0.0.1:3002}"
MONITORING_ADDR="${POHW_BITCOIN_INDEX_MONITORING_ADDR:-127.0.0.1:4225}"

[[ -x "$BIN" && ! -L "$BIN" ]] || { echo "Electrs binary is missing or symlinked: $BIN" >&2; exit 1; }
for path in "$DB_DIR" "$DAEMON_DIR"; do
  [[ -d "$path" && ! -L "$path" ]] || { echo "Required real directory is missing: $path" >&2; exit 1; }
done
[[ -f "$DAEMON_DIR/.cookie" && ! -L "$DAEMON_DIR/.cookie" ]] || {
  echo "Bitcoin RPC cookie file is missing or symlinked." >&2
  exit 1
}

python3 - "$DAEMON_RPC_ADDR" "$ELECTRUM_ADDR" "$HTTP_ADDR" "$MONITORING_ADDR" <<'PY'
import ipaddress
import sys

for endpoint in sys.argv[1:]:
    host, separator, port = endpoint.rpartition(":")
    if not separator or not port.isdigit() or not (1 <= int(port) <= 65535):
        raise SystemExit(f"invalid loopback endpoint: {endpoint}")
    address = ipaddress.ip_address(host.strip("[]"))
    if not address.is_loopback:
        raise SystemExit(f"indexer endpoint must stay on loopback: {endpoint}")
PY

exec "$BIN" \
  --network mainnet \
  --jsonrpc-import \
  --lightmode \
  --db-dir "$DB_DIR" \
  --daemon-dir "$DAEMON_DIR" \
  --daemon-rpc-addr "$DAEMON_RPC_ADDR" \
  --electrum-rpc-addr "$ELECTRUM_ADDR" \
  --http-addr "$HTTP_ADDR" \
  --monitoring-addr "$MONITORING_ADDR" \
  --timestamp
