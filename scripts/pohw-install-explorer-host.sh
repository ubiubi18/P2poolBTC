#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${POHW_RUNTIME_DIR:-/opt/p2pool}"
STATE_DIR="${POHW_STATE_DIR:-/var/lib/pohw-p2pool}"
ENV_FILE="${POHW_ENV_FILE:-/etc/pohw/explorer.env}"
ACTIVATE=0
UI_USER="pohw-explorer-ui"

UNITS=(pohw-dashboard-api.service pohw-dashboard-ui.service)
SOURCES=(
  "$ROOT_DIR/deploy/systemd/pohw-dashboard-api-host.service"
  "$ROOT_DIR/deploy/systemd/pohw-dashboard-ui-host.service"
)

usage() {
  cat <<EOF
Usage: sudo $0 [--activate]

Install the dedicated-host dashboard/explorer units transactionally. The
default only installs unit files. --activate enables both services, verifies
the loopback API/UI health endpoints, and restores prior units on failure.

Build first:
  cargo build --release
  corepack pnpm@11.11.0 --dir ui/pohw-dashboard build
EOF
}

case "${1:-}" in
  "") ;;
  --activate) ACTIVATE=1 ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
[[ $# -le 1 ]] || { usage >&2; exit 2; }

fail() {
  echo "$*" >&2
  return 1
}

require_regular_file() {
  local path=$1
  [[ -f "$path" && ! -L "$path" ]] || fail "Required regular file is missing: $path"
}

require_root_runtime_file() {
  local path=$1
  require_regular_file "$path"
  [[ "$(stat -c %U:%G -- "$path")" == "root:root" ]] \
    || fail "Runtime file must be root-owned: $path"
  local mode
  mode="$(stat -c %a -- "$path")"
  (( (8#$mode & 8#022) == 0 )) || fail "Runtime file must not be group/world writable: $path"
}

require_root_runtime_directory() {
  local path=$1
  [[ -d "$path" && ! -L "$path" ]] || fail "Required runtime directory is missing: $path"
  [[ "$(stat -c %U:%G -- "$path")" == "root:root" ]] \
    || fail "Runtime directory must be root-owned: $path"
  local mode
  mode="$(stat -c %a -- "$path")"
  (( (8#$mode & 8#022) == 0 )) || fail "Runtime directory must not be group/world writable: $path"
}

env_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE"
}

validate_explorer_environment() {
  python3 - "$ENV_FILE" <<'PY'
import re
import sys
from pathlib import Path

allowed = {
    "POHW_WORKDIR",
    "POHW_DATADIR",
    "POHW_SNAPSHOT_DIR",
    "POHW_FORK_ACTIVATION_MANIFEST",
    "POHW_EXPLORER_FORK_CHAIN_RPC_ADDR",
    "POHW_EXPLORER_POHW_CORE_MANIFEST",
    "POHW_EXPLORER_FORK_ADDRESS_INDEX",
    "POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_BLOCKS",
    "POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_TRANSACTIONS",
    "POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_OUTPUTS",
    "POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_ADDRESSES",
    "POHW_ENABLE_BITCOIN_RPC",
    "BITCOIN_RPC_URL",
    "BITCOIN_RPC_COOKIE_FILE",
    "POHW_EXPLORER_BITCOIN_INDEX_URL",
    "POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX",
    "POHW_DASHBOARD_BIND_ADDR",
    "POHW_DASHBOARD_ALLOW_NON_LOOPBACK",
    "POHW_DASHBOARD_API_TOKEN_FILE",
    "POHW_DASHBOARD_ALLOWED_ORIGINS",
    "POHW_EXPLORER_PUBLIC",
    "POHW_DASHBOARD_UI_DIR",
    "POHW_DASHBOARD_UI_DIST_DIR",
    "POHW_DASHBOARD_UI_BIND_HOST",
    "POHW_DASHBOARD_UI_PORT",
    "POHW_DASHBOARD_UI_API_URL",
    "POHW_EXPLORER_UI_API_BASE",
    "POHW_DASHBOARD_UI_DEFAULT_VIEW",
    "POHW_DASHBOARD_UI_PARTICIPANT_ENABLED",
    "POHW_DASHBOARD_UI_CACHE_DIR",
}
assignment = re.compile(r"^([A-Z][A-Z0-9_]*)=([^\s\"']+)$")
seen = set()
for number, raw_line in enumerate(Path(sys.argv[1]).read_text(encoding="utf-8").splitlines(), 1):
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    match = assignment.fullmatch(line)
    if not match:
        raise SystemExit(f"explorer environment line {number} is not a simple assignment")
    key = match.group(1)
    if key not in allowed:
        raise SystemExit(f"explorer environment contains forbidden key: {key}")
    if key in seen:
        raise SystemExit(f"explorer environment contains duplicate key: {key}")
    seen.add(key)
PY
}

validate_loopback_endpoint() {
  local label=$1
  local value=$2
  python3 - "$label" "$value" <<'PY'
import ipaddress
import sys

label, endpoint = sys.argv[1:]
host, separator, port = endpoint.rpartition(":")
if not separator or not port.isdigit() or not (1 <= int(port) <= 65535):
    raise SystemExit(f"{label} must be host:port")
host = host.strip("[]")
try:
    address = ipaddress.ip_address(host)
except ValueError as exc:
    raise SystemExit(f"{label} must use a literal loopback address") from exc
if not address.is_loopback:
    raise SystemExit(f"{label} must stay on loopback")
PY
}

validate_bitcoin_index_url() {
  local label=$1
  local value=$2
  local allow_remote=$3
  python3 - "$label" "$value" "$allow_remote" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit

label, raw, allow_remote = sys.argv[1:]
url = urlsplit(raw)
if not url.hostname or url.username or url.password:
    raise SystemExit(f"{label} must be a credential-free URL")
if url.query or url.fragment:
    raise SystemExit(f"{label} must not contain a query or fragment")
try:
    port = url.port
except ValueError as exc:
    raise SystemExit(f"{label} has an invalid port") from exc
if url.scheme == "http":
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError as exc:
        raise SystemExit(f"{label} HTTP mode must use a literal loopback address") from exc
    if not address.is_loopback or port is None or not (1 <= port <= 65535):
        raise SystemExit(f"{label} HTTP mode must stay on loopback and include a port")
elif url.scheme == "https":
    if allow_remote != "true":
        raise SystemExit(f"{label} remote HTTPS mode requires explicit opt-in")
    if url.hostname.lower() == "localhost":
        raise SystemExit(f"{label} remote HTTPS mode must not use localhost")
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise SystemExit(f"{label} remote HTTPS mode must use a public address")
else:
    raise SystemExit(f"{label} must use loopback HTTP or opted-in HTTPS")
PY
}

loopback_http_origin() {
  local endpoint=$1
  python3 - "$endpoint" <<'PY'
import ipaddress
import sys

host, _, port = sys.argv[1].rpartition(":")
address = ipaddress.ip_address(host.strip("[]"))
formatted_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
print(f"http://{formatted_host}:{port}")
PY
}

if [[ "$(id -u)" != "0" ]]; then
  fail "Run as root, for example: sudo $0"
  exit 1
fi
[[ "$ROOT_DIR" == "$RUNTIME_DIR" ]] \
  || fail "Run this installer from the protected runtime checkout at $RUNTIME_DIR"
[[ ! -L "$ROOT_DIR" && ! -L "$STATE_DIR" && ! -L "$ENV_FILE" ]] \
  || fail "Refusing symlinked runtime, state, or environment path"
for runtime_directory in \
  "$RUNTIME_DIR" \
  "$RUNTIME_DIR/scripts" \
  "$RUNTIME_DIR/target" \
  "$RUNTIME_DIR/target/release" \
  "$RUNTIME_DIR/compatibility" \
  "$RUNTIME_DIR/ui" \
  "$RUNTIME_DIR/ui/pohw-dashboard" \
  "$RUNTIME_DIR/ui/pohw-dashboard/dist"; do
  require_root_runtime_directory "$runtime_directory"
done
getent passwd pohw >/dev/null || fail "Required service user is missing: pohw"
if ! getent passwd "$UI_USER" >/dev/null; then
  getent group "$UI_USER" >/dev/null \
    && fail "Refusing existing group without matching $UI_USER account"
  useradd --system --user-group --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin "$UI_USER"
fi
ui_account="$(getent passwd "$UI_USER")"
[[ "$(cut -d: -f6 <<< "$ui_account")" == "/nonexistent" ]] \
  || fail "$UI_USER must use /nonexistent as its home"
[[ "$(cut -d: -f7 <<< "$ui_account")" == "/usr/sbin/nologin" ]] \
  || fail "$UI_USER must use /usr/sbin/nologin"

require_root_runtime_file "$RUNTIME_DIR/target/release/p2pool-node"
require_root_runtime_file "$RUNTIME_DIR/scripts/pohw-run-dashboard-api.sh"
require_root_runtime_file "$RUNTIME_DIR/scripts/pohw-run-dashboard-ui.sh"
require_root_runtime_file "$RUNTIME_DIR/scripts/pohw-dashboard-ui-server.py"
require_root_runtime_file "$RUNTIME_DIR/ui/pohw-dashboard/dist/index.html"
require_regular_file "$ENV_FILE"
[[ "$(stat -c %U -- "$ENV_FILE")" == "root" ]] || fail "$ENV_FILE must be root-owned"
env_mode="$(stat -c %a -- "$ENV_FILE")"
(( (8#$env_mode & 8#077) == 0 )) || fail "$ENV_FILE must not be accessible by group or others"
validate_explorer_environment

api_bind="$(env_value POHW_DASHBOARD_BIND_ADDR)"
fork_rpc="$(env_value POHW_EXPLORER_FORK_CHAIN_RPC_ADDR)"
fork_manifest="$(env_value POHW_FORK_ACTIVATION_MANIFEST)"
core_manifest="$(env_value POHW_EXPLORER_POHW_CORE_MANIFEST)"
fork_address_index="$(env_value POHW_EXPLORER_FORK_ADDRESS_INDEX)"
fork_address_index_max_blocks="$(env_value POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_BLOCKS)"
fork_address_index_max_transactions="$(env_value POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_TRANSACTIONS)"
fork_address_index_max_outputs="$(env_value POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_OUTPUTS)"
fork_address_index_max_addresses="$(env_value POHW_EXPLORER_FORK_ADDRESS_INDEX_MAX_ADDRESSES)"
enable_bitcoin_rpc="$(env_value POHW_ENABLE_BITCOIN_RPC)"
bitcoin_rpc_url="$(env_value BITCOIN_RPC_URL)"
bitcoin_rpc_cookie="$(env_value BITCOIN_RPC_COOKIE_FILE)"
bitcoin_index_url="$(env_value POHW_EXPLORER_BITCOIN_INDEX_URL)"
allow_remote_bitcoin_index="$(env_value POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX)"
allow_remote_bitcoin_index="${allow_remote_bitcoin_index:-false}"
ui_host="$(env_value POHW_DASHBOARD_UI_BIND_HOST)"
ui_port="$(env_value POHW_DASHBOARD_UI_PORT)"
datadir="$(env_value POHW_DATADIR)"
snapshot_dir="$(env_value POHW_SNAPSHOT_DIR)"
[[ -n "$api_bind" ]] || fail "POHW_DASHBOARD_BIND_ADDR is missing from $ENV_FILE"
[[ -z "$fork_rpc" && -z "$fork_manifest" ]] \
  || fail "Dedicated-host installation no longer accepts the retired Experiment 0 fork RPC"
[[ "$core_manifest" == "$RUNTIME_DIR/compatibility/experiment-1-full-consensus.json" ]] \
  || fail "POHW_EXPLORER_POHW_CORE_MANIFEST must select the protected Experiment 1 manifest"
[[ "$fork_address_index" == "true" ]] \
  || fail "POHW_EXPLORER_FORK_ADDRESS_INDEX must be true on the dedicated explorer host"
for value in \
  "$fork_address_index_max_blocks" \
  "$fork_address_index_max_transactions" \
  "$fork_address_index_max_outputs" \
  "$fork_address_index_max_addresses"; do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] \
    || fail "Fork address-index limits must be positive decimal integers"
done
[[ "$enable_bitcoin_rpc" == "true" ]] \
  || fail "POHW_ENABLE_BITCOIN_RPC must be true for the Experiment 1 explorer"
[[ "$bitcoin_rpc_url" == "http://127.0.0.1:40414" ]] \
  || fail "BITCOIN_RPC_URL must select the dedicated loopback Experiment 1 Core RPC"
[[ "$bitcoin_rpc_cookie" == "/run/bitcoin-pohw-rpc/.cookie" ]] \
  || fail "BITCOIN_RPC_COOKIE_FILE must select the dedicated Experiment 1 cookie"
[[ -n "$bitcoin_index_url" ]] || fail "POHW_EXPLORER_BITCOIN_INDEX_URL is missing from $ENV_FILE"
[[ -n "$ui_host" ]] || fail "POHW_DASHBOARD_UI_BIND_HOST is missing from $ENV_FILE"
[[ -n "$ui_port" ]] || fail "POHW_DASHBOARD_UI_PORT is missing from $ENV_FILE"
[[ -n "$datadir" ]] || fail "POHW_DATADIR is missing from $ENV_FILE"
[[ -n "$snapshot_dir" ]] || fail "POHW_SNAPSHOT_DIR is missing from $ENV_FILE"
validate_loopback_endpoint POHW_DASHBOARD_BIND_ADDR "$api_bind"
validate_bitcoin_index_url BITCOIN_RPC_URL "$bitcoin_rpc_url" false
case "$allow_remote_bitcoin_index" in
  true|false) ;;
  *) fail "POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX must be true or false" ;;
esac
validate_bitcoin_index_url \
  POHW_EXPLORER_BITCOIN_INDEX_URL "$bitcoin_index_url" "$allow_remote_bitcoin_index"
validate_loopback_endpoint POHW_DASHBOARD_UI_BIND "${ui_host}:${ui_port}"
[[ "$(env_value POHW_EXPLORER_PUBLIC)" == "true" ]] \
  || fail "Dedicated-host profile requires POHW_EXPLORER_PUBLIC=true"
require_root_runtime_file "$core_manifest"
require_regular_file "$bitcoin_rpc_cookie"
[[ "$(stat -c %U:%G -- "$bitcoin_rpc_cookie")" == "bitcoin-pohw:bitcoin-pohw-rpc" ]] \
  || fail "Experiment 1 RPC cookie has an unexpected owner or group"
[[ "$(stat -c %a -- "$bitcoin_rpc_cookie")" == "640" ]] \
  || fail "Experiment 1 RPC cookie must use mode 0640"
api_origin="$(loopback_http_origin "$api_bind")"
ui_origin="$(loopback_http_origin "${ui_host}:${ui_port}")"

if [[ -e "$STATE_DIR" ]]; then
  [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || fail "State path must be a real directory: $STATE_DIR"
  state_mode="$(stat -c %a -- "$STATE_DIR")"
  (( (8#$state_mode & 8#022) == 0 )) || fail "$STATE_DIR must not be group/world writable"
else
  install -d -m 0755 -o root -g root "$STATE_DIR"
fi

for path in "$datadir" "$snapshot_dir"; do
  case "$path" in
    "$STATE_DIR"/*)
      if [[ ! -e "$path" ]]; then
        install -d -m 0700 -o pohw -g pohw "$path"
      fi
      ;;
    /srv/sharechain|/srv/sharechain/*) ;;
    *) fail "Explorer data paths must stay under $STATE_DIR or /srv/sharechain" ;;
  esac
  [[ -d "$path" && ! -L "$path" ]] || fail "Explorer data directory is missing or symlinked: $path"
  [[ "$(realpath -e -- "$path")" == "$path" ]] \
    || fail "Explorer data directory has a symlinked or non-canonical ancestor: $path"
  runuser -u pohw -- test -r "$path" \
    || fail "pohw cannot read explorer data directory: $path"
done
runuser -u pohw -- test -w "$datadir" \
  || fail "pohw cannot maintain the sharechain replay index in $datadir"

install -d -m 0755 -o root -g root /etc/pohw
install -d -m 0700 -o "$UI_USER" -g "$UI_USER" "$STATE_DIR/dashboard-ui-cache"
token_file="$(env_value POHW_DASHBOARD_API_TOKEN_FILE)"
[[ -n "$token_file" ]] || fail "POHW_DASHBOARD_API_TOKEN_FILE is missing from $ENV_FILE"
if [[ ! -e "$token_file" ]]; then
  umask 0077
  openssl rand -hex 32 > "$token_file"
fi
require_regular_file "$token_file"
chown root:root "$token_file"
chmod 0600 "$token_file"

txn_dir="$(mktemp -d /run/pohw-explorer-install.XXXXXX)"
stage_dir="$txn_dir/stage"
backup_dir="$txn_dir/backup"
install -d -m 0700 -o root -g root "$stage_dir" "$backup_dir"

declare -a ACTIVE_BEFORE=()
for index in "${!UNITS[@]}"; do
  unit="${UNITS[$index]}"
  source="${SOURCES[$index]}"
  require_regular_file "$source"
  install -m 0644 -o root -g root "$source" "$stage_dir/$unit"
  if systemctl is-active --quiet "$unit"; then
    ACTIVE_BEFORE[index]=1
  else
    ACTIVE_BEFORE[index]=0
  fi
done
systemd-analyze verify "$stage_dir/${UNITS[0]}" "$stage_dir/${UNITS[1]}"

mutated=0
rollback() {
  local rc=${1:-1}
  trap - ERR INT TERM
  if [[ "$mutated" == "1" ]]; then
    for unit in "${UNITS[@]}"; do
      rm -f "/etc/systemd/system/$unit"
      if [[ -e "$backup_dir/$unit" ]]; then
        cp -a "$backup_dir/$unit" "/etc/systemd/system/$unit"
      fi
    done
    systemctl daemon-reload || true
    for index in "${!UNITS[@]}"; do
      if [[ "${ACTIVE_BEFORE[$index]}" == "1" ]]; then
        systemctl restart "${UNITS[$index]}" || true
      else
        systemctl disable --now "${UNITS[$index]}" >/dev/null 2>&1 || true
      fi
    done
  fi
  rm -rf "$txn_dir"
  exit "$rc"
}
trap 'rollback $?' ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM

backup_root="$STATE_DIR/explorer-unit-backup"
install -d -m 0700 -o root -g root "$backup_root"
for unit in "${UNITS[@]}"; do
  if [[ -e "/etc/systemd/system/$unit" ]]; then
    cp -a "/etc/systemd/system/$unit" "$backup_dir/$unit"
    if [[ ! -e "$backup_root/$unit" ]]; then
      cp -a "/etc/systemd/system/$unit" "$backup_root/$unit"
    fi
  fi
done

mutated=1
for unit in "${UNITS[@]}"; do
  install -m 0644 -o root -g root "$stage_dir/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemd-analyze verify "${UNITS[@]}"

if [[ "$ACTIVATE" == "1" ]]; then
  systemctl enable --now pohw-dashboard-api.service pohw-dashboard-ui.service
  systemctl restart pohw-dashboard-api.service pohw-dashboard-ui.service
  sleep 3
  systemctl is-active --quiet pohw-dashboard-api.service
  systemctl is-active --quiet pohw-dashboard-ui.service
  curl --fail --silent --show-error --max-time 5 \
    "${api_origin}/api/v1/overview" >/dev/null
  curl --fail --silent --show-error --max-time 5 \
    "${ui_origin}/" >/dev/null
fi

mutated=0
trap - ERR INT TERM
rm -rf "$txn_dir"

if [[ "$ACTIVATE" == "1" ]]; then
  echo "PoHW explorer installed, activated, and loopback smoke-tested."
else
  echo "PoHW explorer units installed but not activated. Run again with --activate after review."
fi
