#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
DATADIR="${POHW_DATADIR:-/mnt/ssd/pohw-p2pool}"
UI_DIR="${POHW_DASHBOARD_UI_DIR:-$WORKDIR/ui/pohw-dashboard}"
DIST_DIR="${POHW_DASHBOARD_UI_DIST_DIR:-$UI_DIR/dist}"
BIND_HOST="${POHW_DASHBOARD_UI_BIND_HOST:-127.0.0.1}"
PORT="${POHW_DASHBOARD_UI_PORT:-5176}"
API_URL="${POHW_DASHBOARD_UI_API_URL:-http://127.0.0.1:40407/dashboard.json}"
EXPLORER_API_BASE="${POHW_EXPLORER_UI_API_BASE:-http://127.0.0.1:40407/api/v1}"
DEFAULT_VIEW="${POHW_DASHBOARD_UI_DEFAULT_VIEW:-dashboard}"
PARTICIPANT_DASHBOARD="${POHW_DASHBOARD_UI_PARTICIPANT_ENABLED:-true}"
TOKEN_FILE="${POHW_DASHBOARD_API_TOKEN_FILE:-}"
CACHE_DIR="${POHW_DASHBOARD_UI_CACHE_DIR:-$DATADIR/dashboard-ui-cache}"
PYTHON_BIN="${POHW_DASHBOARD_UI_PYTHON_BIN:-python3}"
HTTP_SERVER_BIN="${POHW_DASHBOARD_UI_HTTP_SERVER_BIN:-$PYTHON_BIN}"
PROXY_SERVER_BIN="${POHW_DASHBOARD_UI_PROXY_SERVER_BIN:-$PYTHON_BIN}"
PROXY_SERVER="${POHW_DASHBOARD_UI_PROXY_SERVER:-$WORKDIR/scripts/pohw-dashboard-ui-server.py}"
PROXY_API_ORIGIN="${POHW_DASHBOARD_UI_PROXY_API_ORIGIN:-http://127.0.0.1:40407}"
NON_LOOPBACK_BIND=false

if [[ -n "${CREDENTIALS_DIRECTORY:-}" ]]; then
  credential_token_file="$CREDENTIALS_DIRECTORY/dashboard-api.token"
  if [[ -f "$credential_token_file" && ! -L "$credential_token_file" ]]; then
    TOKEN_FILE="$credential_token_file"
  fi
fi

case "$BIND_HOST" in
  127.*|localhost|::1)
    ;;
  *)
    NON_LOOPBACK_BIND=true
    if [[ "${POHW_DASHBOARD_UI_ALLOW_NON_LOOPBACK:-false}" != "true" ]]; then
      echo "Refusing to bind dashboard UI to non-loopback host $BIND_HOST." >&2
      echo "Use SSH port forwarding, or set POHW_DASHBOARD_UI_ALLOW_NON_LOOPBACK=true only on a trusted/firewalled network." >&2
      exit 1
    fi
    ;;
esac

if [[ "$NON_LOOPBACK_BIND" == "true" && "$PARTICIPANT_DASHBOARD" == "true" ]]; then
  echo "Refusing a non-loopback participant dashboard because its authenticated proxy exposes private dashboard data." >&2
  echo "Keep the participant UI on loopback and use SSH forwarding, or disable participant mode for a public explorer." >&2
  exit 1
fi

if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "POHW_DASHBOARD_UI_PORT must be a TCP port from 1 to 65535." >&2
  exit 1
fi

case "$DEFAULT_VIEW" in
  dashboard|explorer)
    ;;
  *)
    echo "POHW_DASHBOARD_UI_DEFAULT_VIEW must be dashboard or explorer." >&2
    exit 1
    ;;
esac

case "$PARTICIPANT_DASHBOARD" in
  true|false)
    ;;
  *)
    echo "POHW_DASHBOARD_UI_PARTICIPANT_ENABLED must be true or false." >&2
    exit 1
    ;;
esac

if [[ ! -d "$UI_DIR" ]]; then
  echo "Dashboard UI directory does not exist: $UI_DIR" >&2
  exit 1
fi

if [[ ! -f "$DIST_DIR/index.html" ]]; then
  echo "Dashboard UI build is missing at $DIST_DIR." >&2
  echo "Run: cd $UI_DIR && npm install && npm run build" >&2
  exit 1
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python is required to serve the static dashboard UI: $PYTHON_BIN" >&2
  exit 1
fi

if ! command -v "$HTTP_SERVER_BIN" >/dev/null 2>&1; then
  echo "Dashboard UI HTTP server command is missing: $HTTP_SERVER_BIN" >&2
  exit 1
fi

token_available=false
if [[ "$PARTICIPANT_DASHBOARD" == "true" && -n "$TOKEN_FILE" ]]; then
  if [[ ! -f "$TOKEN_FILE" || -L "$TOKEN_FILE" ]]; then
    echo "Dashboard API token file must be a regular file: $TOKEN_FILE" >&2
    exit 1
  fi
  token_size="$(wc -c < "$TOKEN_FILE" | tr -d ' ')"
  if [[ ! "$token_size" =~ ^[0-9]+$ ]] || (( token_size == 0 || token_size > 4096 )); then
    echo "Dashboard API token file has an unsafe size: $TOKEN_FILE" >&2
    exit 1
  fi
  token_available=true
fi

mkdir -p "$CACHE_DIR"

json_escape() {
  "$PYTHON_BIN" -c 'import json, sys; print(json.dumps(sys.stdin.read()))'
}

if [[ "$PARTICIPANT_DASHBOARD" == "true" ]]; then
  if [[ "$token_available" != "true" ]]; then
    echo "Participant dashboard requires a dashboard API token credential." >&2
    exit 1
  fi
  if [[ ! -f "$PROXY_SERVER" || -L "$PROXY_SERVER" ]]; then
    echo "Dashboard same-origin proxy is missing or symlinked: $PROXY_SERVER" >&2
    exit 1
  fi
  API_URL="/dashboard.json"
  EXPLORER_API_BASE="/api/v1"
fi

api_url_json="$(printf '%s' "$API_URL" | json_escape)"
explorer_api_base_json="$(printf '%s' "$EXPLORER_API_BASE" | json_escape)"
default_view_json="$(printf '%s' "$DEFAULT_VIEW" | json_escape)"
token_json="$(printf '%s' "" | json_escape)"
demo_json="$(printf '%s' "${POHW_DASHBOARD_UI_DEMO:-}" | json_escape)"

www_dir="$CACHE_DIR/www"
next_www_dir="$CACHE_DIR/www.next.$$"
rm -rf "$next_www_dir"
mkdir -p "$next_www_dir"
cp -R "$DIST_DIR/." "$next_www_dir/"
cat > "$next_www_dir/pohw-dashboard-config.js" <<CONFIG
window.__POHW_DASHBOARD_CONFIG__ = {
  apiUrl: $api_url_json,
  explorerApiBase: $explorer_api_base_json,
  defaultView: $default_view_json,
  participantDashboard: $PARTICIPANT_DASHBOARD,
  apiToken: $token_json,
  demo: $demo_json
};
CONFIG
chmod 600 "$next_www_dir/pohw-dashboard-config.js"
"$PYTHON_BIN" - "$next_www_dir/index.html" <<'PY'
from pathlib import Path
import sys

index = Path(sys.argv[1])
html = index.read_text(encoding="utf-8")
tag = '    <script src="/pohw-dashboard-config.js"></script>\n'
if tag not in html:
    marker = '<script type="module"'
    if marker in html:
        html = html.replace(marker, tag + marker, 1)
    elif "</body>" in html:
        html = html.replace("</body>", tag + "  </body>", 1)
    else:
        raise SystemExit("Dashboard UI index.html has no script marker or closing body tag")
index.write_text(html, encoding="utf-8")
PY
rm -rf "$www_dir"
mv "$next_www_dir" "$www_dir"

cd "$www_dir"
if [[ "$PARTICIPANT_DASHBOARD" == "true" ]]; then
  exec "$PROXY_SERVER_BIN" "$PROXY_SERVER" \
    --root "$www_dir" \
    --bind-host "$BIND_HOST" \
    --port "$PORT" \
    --api-origin "$PROXY_API_ORIGIN" \
    --token-file "$TOKEN_FILE"
fi
exec "$HTTP_SERVER_BIN" -m http.server "$PORT" --bind "$BIND_HOST"
