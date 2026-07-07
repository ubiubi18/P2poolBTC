#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${IDENA_WEB_DIR:-${ROOT_DIR}/../idena-go/idena-web}"
STATE_DIR="${ROOT_DIR}/tmp/idena-web-pi"

PI_HOST="${PI_HOST:-pohw-pi}"
REMOTE_RPC_HOST="${REMOTE_RPC_HOST:-127.0.0.1}"
REMOTE_RPC_PORT="${REMOTE_RPC_PORT:-9009}"
LOCAL_TUNNEL_PORT="${LOCAL_TUNNEL_PORT:-19010}"
LOCAL_PROXY_PORT="${LOCAL_PROXY_PORT:-19009}"
WEB_PORT="${WEB_PORT:-3030}"

API_KEY_FILE="${IDENA_API_KEY_FILE:-${STATE_DIR}/idena-pi-api.key}"
TUNNEL_LOG="${STATE_DIR}/ssh-tunnel.log"
PROXY_LOG="${STATE_DIR}/rpc-proxy.log"
WEB_LOG="${STATE_DIR}/idena-web.log"
LEGACY_LAUNCH_DOMAIN="gui/$(id -u)"
TUNNEL_LABEL="com.pohw.idena-web-pi.tunnel"
PROXY_LABEL="com.pohw.idena-web-pi.rpc-proxy"
WEB_LABEL="com.pohw.idena-web-pi.web"
TUNNEL_PLIST="${STATE_DIR}/${TUNNEL_LABEL}.plist"
PROXY_PLIST="${STATE_DIR}/${PROXY_LABEL}.plist"
WEB_PLIST="${STATE_DIR}/${WEB_LABEL}.plist"
TUNNEL_SCREEN="pohw-idena-pi-tunnel"
PROXY_SCREEN="pohw-idena-pi-proxy"
WEB_SCREEN="pohw-idena-web"

usage() {
  cat <<USAGE
Usage: $0 [start|stop|status]

Starts a local app.idena.io-style web app on http://127.0.0.1:${WEB_PORT}
and connects it to the Pi's private Idena RPC through a loopback-only proxy.

Override PI_HOST for your SSH host alias and IDENA_WEB_DIR for the local
idena-web checkout. Runtime API keys are written only under ${STATE_DIR}.
USAGE
}

ensure_dirs() {
  mkdir -p "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"
}

port_listening() {
  local port="$1"
  lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
}

screen_running() {
  local name="$1"
  screen -ls 2>/dev/null | grep -Eq "[.]${name}[[:space:]]"
}

stop_legacy_agent() {
  local label="$1"
  local plist="$2"
  launchctl bootout "${LEGACY_LAUNCH_DOMAIN}/${label}" >/dev/null 2>&1 || true
  launchctl bootout "${LEGACY_LAUNCH_DOMAIN}" "${plist}" >/dev/null 2>&1 || true
}

stop_screen() {
  local name="$1"
  if screen_running "${name}"; then
    screen -S "${name}" -X quit >/dev/null 2>&1 || true
  fi
}

kill_listener() {
  local port="$1"
  local pids
  pids="$(lsof -tiTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "${pids}" ]]; then
    # shellcheck disable=SC2086
    kill ${pids} 2>/dev/null || true
  fi
}

fetch_api_key() {
  umask 077
  local tmp="${API_KEY_FILE}.tmp"
  ssh -o BatchMode=yes "${PI_HOST}" "cat /mnt/ssd/idena/idena-data/api.key" >"${tmp}"
  mv "${tmp}" "${API_KEY_FILE}"
  chmod 600 "${API_KEY_FILE}"
}

start_tunnel() {
  if port_listening "${LOCAL_TUNNEL_PORT}"; then
    return
  fi
  stop_screen "${TUNNEL_SCREEN}"
  screen -dmS "${TUNNEL_SCREEN}" /bin/bash -lc "exec ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o RequestTTY=no -o StdinNull=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L '127.0.0.1:${LOCAL_TUNNEL_PORT}:${REMOTE_RPC_HOST}:${REMOTE_RPC_PORT}' '${PI_HOST}' >>'${TUNNEL_LOG}' 2>&1"
  sleep 1
  if ! port_listening "${LOCAL_TUNNEL_PORT}"; then
    echo "SSH tunnel did not start. See ${TUNNEL_LOG}" >&2
    return 1
  fi
}

start_proxy() {
  if port_listening "${LOCAL_PROXY_PORT}"; then
    return
  fi
  stop_screen "${PROXY_SCREEN}"
  screen -dmS "${PROXY_SCREEN}" /bin/bash -lc "exec env IDENA_API_KEY_FILE='${API_KEY_FILE}' IDENA_RPC_UPSTREAM='http://127.0.0.1:${LOCAL_TUNNEL_PORT}/' IDENA_RPC_ALLOWED_ORIGINS='http://127.0.0.1:${WEB_PORT},http://localhost:${WEB_PORT}' /usr/bin/python3 '${ROOT_DIR}/scripts/idena-rpc-loopback-proxy.py' --host 127.0.0.1 --port '${LOCAL_PROXY_PORT}' >>'${PROXY_LOG}' 2>&1"
  sleep 1
  if ! port_listening "${LOCAL_PROXY_PORT}"; then
    echo "RPC proxy did not start. See ${PROXY_LOG}" >&2
    return 1
  fi
}

start_web() {
  if port_listening "${WEB_PORT}"; then
    return
  fi
  if [[ ! -d "${WEB_DIR}" ]]; then
    echo "Idena web app directory not found: ${WEB_DIR}" >&2
    return 1
  fi
  if [[ ! -x "${WEB_DIR}/node_modules/.bin/next" ]]; then
    echo "Missing ${WEB_DIR}/node_modules/.bin/next. Run npm install in ${WEB_DIR}." >&2
    return 1
  fi
  stop_screen "${WEB_SCREEN}"
  screen -dmS "${WEB_SCREEN}" /bin/bash -lc "cd '${WEB_DIR}' && exec env HOST=127.0.0.1 PORT='${WEB_PORT}' NODE_OPTIONS='${NODE_OPTIONS:---openssl-legacy-provider}' NEXT_PUBLIC_DEFAULT_NODE_URL='http://127.0.0.1:${LOCAL_PROXY_PORT}' NEXT_PUBLIC_DEFAULT_NODE_KEY='pohw-local' NEXT_PUBLIC_DEFAULT_NODE_MANUAL='true' ./node_modules/.bin/next dev -H 127.0.0.1 -p '${WEB_PORT}' >>'${WEB_LOG}' 2>&1"
  for _ in {1..30}; do
    if curl -fsS "http://127.0.0.1:${WEB_PORT}/" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "Idena web app did not become ready. See ${WEB_LOG}" >&2
  return 1
}

probe_proxy() {
  curl -fsS \
    --connect-timeout 2 \
    --max-time 8 \
    -H "Origin: http://127.0.0.1:${WEB_PORT}" \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","id":1,"method":"bcn_syncing","params":[],"key":"pohw-local"}' \
    "http://127.0.0.1:${LOCAL_PROXY_PORT}/" >/dev/null
}

start_all() {
  ensure_dirs
  fetch_api_key
  start_tunnel
  start_proxy
  probe_proxy
  start_web
  cat <<STATUS
Idena web access is ready.
Web app:       http://127.0.0.1:${WEB_PORT}
RPC proxy:     http://127.0.0.1:${LOCAL_PROXY_PORT}
SSH tunnel:    127.0.0.1:${LOCAL_TUNNEL_PORT} -> ${PI_HOST}:${REMOTE_RPC_PORT}
Logs:          ${STATE_DIR}
STATUS
}

stop_all() {
  stop_screen "${WEB_SCREEN}"
  stop_screen "${PROXY_SCREEN}"
  stop_screen "${TUNNEL_SCREEN}"
  kill_listener "${WEB_PORT}"
  kill_listener "${LOCAL_PROXY_PORT}"
  kill_listener "${LOCAL_TUNNEL_PORT}"
  stop_legacy_agent "${WEB_LABEL}" "${WEB_PLIST}"
  stop_legacy_agent "${PROXY_LABEL}" "${PROXY_PLIST}"
  stop_legacy_agent "${TUNNEL_LABEL}" "${TUNNEL_PLIST}"
  sleep 1
}

status_all() {
  ensure_dirs
  printf "web_app_port_%s=" "${WEB_PORT}"
  port_listening "${WEB_PORT}" && echo "listening" || echo "closed"
  printf "rpc_proxy_port_%s=" "${LOCAL_PROXY_PORT}"
  port_listening "${LOCAL_PROXY_PORT}" && echo "listening" || echo "closed"
  printf "ssh_tunnel_port_%s=" "${LOCAL_TUNNEL_PORT}"
  port_listening "${LOCAL_TUNNEL_PORT}" && echo "listening" || echo "closed"
  [[ -f "${API_KEY_FILE}" ]] && echo "api_key_file=present" || echo "api_key_file=missing"
  printf "screens="
  screen -ls 2>/dev/null | grep -E "(${TUNNEL_SCREEN}|${PROXY_SCREEN}|${WEB_SCREEN})" | tr '\n' ';' || true
  echo
}

case "${1:-start}" in
  start) start_all ;;
  stop) stop_all ;;
  status) status_all ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
