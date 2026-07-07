#!/usr/bin/env bash
set -euo pipefail

SSH_TARGET="${1:-${POHW_PI_SSH_TARGET:-pohw-pi}}"
LOCAL_UI_PORT="${POHW_LOCAL_DASHBOARD_UI_PORT:-5176}"
REMOTE_UI_PORT="${POHW_REMOTE_DASHBOARD_UI_PORT:-5176}"
LOCAL_API_PORT="${POHW_LOCAL_DASHBOARD_API_PORT:-40407}"
REMOTE_API_PORT="${POHW_REMOTE_DASHBOARD_API_PORT:-40407}"

for port in "$LOCAL_UI_PORT" "$REMOTE_UI_PORT" "$LOCAL_API_PORT" "$REMOTE_API_PORT"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "Invalid TCP port: $port" >&2
    exit 1
  fi
done

echo "Opening PoHW dashboard tunnel to $SSH_TARGET"
echo "UI:  http://127.0.0.1:$LOCAL_UI_PORT/ -> Pi 127.0.0.1:$REMOTE_UI_PORT"
echo "API: http://127.0.0.1:$LOCAL_API_PORT/dashboard.json -> Pi 127.0.0.1:$REMOTE_API_PORT"
echo "Keep this process running while using the dashboard."

exec ssh \
  -N \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=20 \
  -o ServerAliveCountMax=3 \
  -L "127.0.0.1:$LOCAL_UI_PORT:127.0.0.1:$REMOTE_UI_PORT" \
  -L "127.0.0.1:$LOCAL_API_PORT:127.0.0.1:$REMOTE_API_PORT" \
  "$SSH_TARGET"
